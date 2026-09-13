import { readFile, readdir } from 'node:fs/promises'
import { dirname, relative, resolve } from 'node:path'
import type {
  ActionableChangeEvent,
  AffectedDependency,
  ImpactEvidence,
  RepositoryImpact,
} from '@automated-api/contracts'
import { intersects, validRange } from 'semver'
import { goPackageDeclarationUsages } from './go-package-usage.js'

const EXCLUDED_DIRECTORIES = new Set([
  '.git', '.hg', '.idea', '.vscode', 'build', 'coverage', 'dist', 'node_modules',
  'target', 'vendor', '.venv', 'venv', '__pycache__',
])
const MAX_SOURCE_BYTES = 2 * 1024 * 1024

interface NativeLanguageConfiguration {
  language: 'rust' | 'go'
  ecosystem: 'cargo' | 'gomod'
  manifestName: 'Cargo.toml' | 'go.mod'
  sourceExtension: '.rs' | '.go'
}

const RUST: NativeLanguageConfiguration = {
  language: 'rust', ecosystem: 'cargo', manifestName: 'Cargo.toml', sourceExtension: '.rs',
}
const GO: NativeLanguageConfiguration = {
  language: 'go', ecosystem: 'gomod', manifestName: 'go.mod', sourceExtension: '.go',
}

export interface AnalyzeNativeRepositoryInput {
  rootDir: string
  baseSha: string
  changeEvent: ActionableChangeEvent
}

export function analyzeRustRepository(input: AnalyzeNativeRepositoryInput): Promise<RepositoryImpact> {
  return analyzeNativeRepository(input, RUST)
}

export function analyzeGoRepository(input: AnalyzeNativeRepositoryInput): Promise<RepositoryImpact> {
  return analyzeNativeRepository(input, GO)
}

async function analyzeNativeRepository(
  input: AnalyzeNativeRepositoryInput,
  configuration: NativeLanguageConfiguration,
): Promise<RepositoryImpact> {
  const dependencies = input.changeEvent.impactScope === 'api'
    ? []
    : input.changeEvent.affectedDependencies.filter(
      dependency => dependency.ecosystem === configuration.ecosystem,
    )
  const apiHosts = input.changeEvent.impactScope === 'sdk'
    ? []
    : [...new Set(input.changeEvent.affectedApiHosts.map(host => host.toLowerCase()))]
  if (dependencies.length === 0 && apiHosts.length === 0) {
    return impact(input, 'blocked', [], [
      `change event has no ${configuration.ecosystem} dependency or API host metadata for ${configuration.language} analysis`,
    ])
  }

  const root = resolve(input.rootDir)
  const paths = await repositoryPaths(root)
  const manifests = paths.filter(path => path.name === configuration.manifestName)
  const manifestContents = new Map(await Promise.all(manifests.map(async manifest => [
    manifest.path,
    await readFile(manifest.path, 'utf8'),
  ] as const)))
  const activeDependencies = new Map<string, AffectedDependency>()
  const rustImportRoots = new Map<string, Set<string>>()
  const cargoWorkspaceDependencies = configuration.language === 'rust'
    ? new Map(manifests.flatMap(manifest => {
        const content = manifestContents.get(manifest.path)!
        return rustDependencies(content)
          .filter(declaration => declaration.version !== 'workspace')
          .map(declaration => [declaration.declarationName, declaration] as const)
      }))
    : new Map<string, ReturnType<typeof rustDependencies>[number]>()
  const evidence: ImpactEvidence[] = []
  for (const manifest of manifests) {
    const content = manifestContents.get(manifest.path)!
    if (configuration.language === 'go') {
      const replaced = dependencies.filter(dependency => goModuleIsReplaced(content, dependency.name))
      if (replaced.length > 0) {
        return impact(input, 'blocked', [], [
          `affected Go module replacement must be reviewed manually: ${replaced.map(item => item.name).join(', ')}`,
        ])
      }
    }
    const declarations = configuration.language === 'rust'
      ? rustDependencies(content)
      : goDependencies(content)
    for (const declaration of declarations) {
      const workspaceDependency = declaration.version === 'workspace'
        ? cargoWorkspaceDependencies.get(declaration.declarationName)
        : undefined
      const packageName = workspaceDependency?.packageName ?? declaration.packageName
      const dependency = dependencies.find(target => target.name === packageName)
      const declaredVersion = declaration.version === 'workspace'
        ? workspaceDependency?.version ?? declaration.version
        : declaration.version
      if (dependency === undefined || !versionMayBeAffected(
        declaredVersion,
        dependency.oldVersionRange ?? input.changeEvent.oldVersion,
        configuration.language,
      )) continue
      activeDependencies.set(dependency.name, dependency)
      if (configuration.language === 'rust') {
        const roots = rustImportRoots.get(dependency.name) ?? new Set<string>()
        roots.add(declaration.declarationName.replaceAll('-', '_'))
        rustImportRoots.set(dependency.name, roots)
      }
      const workspace = relative(root, dirname(manifest.path)).replaceAll('\\', '/')
      evidence.push({
        kind: configuration.language === 'rust' ? 'rust_dependency' : 'go_dependency',
        operation: 'package_usage',
        location: location(root, manifest.path, content, declaration.offset),
        detail: `${configuration.ecosystem} dependency ${JSON.stringify(dependency.name)} at ${JSON.stringify(declaredVersion)} is affected`,
        deterministicRecipeSupported: false,
        language: configuration.language,
        ecosystem: configuration.ecosystem,
        ...(workspace === '' || workspace === '.' ? {} : { workspace }),
      })
    }
  }

  for (const source of paths.filter(path => path.extension === configuration.sourceExtension)) {
    if (source.size > MAX_SOURCE_BYTES) continue
    const content = await readFile(source.path, 'utf8')
    if (configuration.language === 'go' && input.changeEvent.verificationStatus === 'verified') {
      const packageMigrations = [...activeDependencies.values()].filter(dependency =>
        dependency.oldVersionRange !== undefined && dependency.newVersion !== undefined
        && input.changeEvent.operations.some(operation => operation.operation === 'package migration'
          && operation.oldSymbol === `${dependency.name}@${dependency.oldVersionRange}`
          && operation.newSymbol === `${dependency.name}@${dependency.newVersion}`))
      for (const usage of goPackageDeclarationUsages(content, packageMigrations.map(dependency => dependency.name))) {
        evidence.push({ kind: 'go_call', operation: 'package migration',
          location: { path: relative(root, source.path).replaceAll('\\', '/'), line: usage.start, endLine: usage.end, column: 1 },
          detail: `Go parser located affected ${JSON.stringify(usage.module)} package usage in declaration ${JSON.stringify(usage.declaration)}`,
          deterministicRecipeSupported: false, language: 'go', ecosystem: 'gomod',
        })
      }
    }
    const imports = configuration.language === 'rust'
      ? rustImports(content, activeDependencies, rustImportRoots)
      : goImports(content, activeDependencies)
    for (const imported of imports) {
      evidence.push({
        kind: configuration.language === 'rust' ? 'rust_import' : 'go_import',
        operation: 'package_usage',
        location: location(root, source.path, content, imported.offset),
        detail: `import from affected ${configuration.ecosystem} package ${JSON.stringify(imported.name)}`,
        deterministicRecipeSupported: false,
        language: configuration.language,
        ecosystem: configuration.ecosystem,
      })
    }
    const oldSymbols = new Set(input.changeEvent.operations.flatMap(operation =>
      operation.oldSymbol === undefined ? [] : [operation.oldSymbol]))
    if (imports.length > 0) {
      for (const symbol of oldSymbols) {
        const expression = legacySymbolExpression(symbol)
        for (const match of content.matchAll(expression)) {
          const endOffset = configuration.language === 'rust'
            ? balancedExpressionEndOffset(content, match.index)
            : match.index
          evidence.push({
            kind: configuration.language === 'rust' ? 'rust_call' : 'go_call',
            operation: symbol,
            location: location(root, source.path, content, match.index, endOffset),
            detail: `affected ${configuration.language} source references legacy symbol ${JSON.stringify(symbol)}`,
            deterministicRecipeSupported: false,
            language: configuration.language,
            ecosystem: configuration.ecosystem,
          })
        }
      }
    }
    for (const host of apiHosts) {
      const hostSuffix = host.replace(/^\*\./u, '')
      const expression = new RegExp(`https?://(?:[A-Za-z0-9-]+\\.)*${escapeRegex(hostSuffix)}(?=[/:?#"'\\s]|$)`, 'giu')
      for (const match of content.matchAll(expression)) {
        evidence.push({
          kind: configuration.language === 'rust' ? 'rust_raw_endpoint' : 'go_raw_endpoint',
          operation: 'api_host_usage',
          location: location(root, source.path, content, match.index),
          detail: `${configuration.language} source uses affected API host ${JSON.stringify(host)}`,
          deterministicRecipeSupported: false,
          language: configuration.language,
        })
      }
    }
  }

  const unique = deduplicate(evidence)
  if (unique.length === 0) {
    return impact(input, 'not_affected', [], [
      `no ${configuration.language} dependency, import, symbol, or API URL matched ${[
        ...dependencies.map(dependency => dependency.name), ...apiHosts,
      ].join(', ')}`,
    ])
  }
  return impact(input, 'affected_manual', unique, [
    `affected ${configuration.language} usage was found and is routed to the bounded Harness until an exact reviewed recipe matches`,
  ])
}

interface RepositoryPath {
  path: string
  name: string
  extension: string
  size: number
}

async function repositoryPaths(root: string): Promise<RepositoryPath[]> {
  const paths: RepositoryPath[] = []
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue
      const path = resolve(directory, entry.name)
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) await visit(path)
      } else if (entry.isFile()) {
        const extension = entry.name.endsWith('.rs') ? '.rs' : entry.name.endsWith('.go') ? '.go' : ''
        if (extension !== '' || entry.name === 'Cargo.toml' || entry.name === 'go.mod') {
          paths.push({
            path, name: entry.name, extension,
            size: Buffer.byteLength(await readFile(path)),
          })
        }
      }
    }
  }
  await visit(root)
  return paths.sort((left, right) => left.path.localeCompare(right.path))
}

function rustDependencies(content: string): Array<{
  declarationName: string
  packageName: string
  version: string
  offset: number
}> {
  const output: Array<{
    declarationName: string
    packageName: string
    version: string
    offset: number
  }> = []
  let dependencySection = false
  let offset = 0
  for (const raw of content.split(/(?<=\n)/u)) {
    const line = raw.replace(/\r?\n$/u, '')
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/u)?.[1]
    if (section !== undefined) dependencySection = /(?:^|\.)dependencies$/u.test(section)
    if (dependencySection && !line.trimStart().startsWith('#')) {
      const assignment = line.match(/^\s*(?:(["'])([^"']+)\1|([A-Za-z0-9_-]+))\s*=\s*(.*)$/u)
      const declarationName = assignment?.[2] ?? assignment?.[3]
      const value = assignment?.[4]
      const directVersion = value?.match(/^["']([^"']+)["']/u)?.[1]
      const inline = value?.match(/^\{([^}]*)\}/u)?.[1]
      const version = directVersion ?? inline?.match(/\bversion\s*=\s*["']([^"']+)["']/u)?.[1]
      const packageName = inline?.match(/\bpackage\s*=\s*["']([^"']+)["']/u)?.[1] ?? declarationName
      if (declarationName !== undefined && packageName !== undefined && version !== undefined) {
        output.push({
          declarationName, packageName, version,
          offset: offset + line.indexOf(declarationName),
        })
      } else {
        const inheritedBody = inline
        const inheritedPackage = inheritedBody?.match(/\bpackage\s*=\s*["']([^"']+)["']/u)?.[1]
        if (declarationName !== undefined) {
          if (/\bworkspace\s*=\s*true\b/u.test(inheritedBody ?? '')) {
            output.push({
              declarationName,
              packageName: inheritedPackage ?? declarationName,
              version: 'workspace',
              offset: offset + line.indexOf(declarationName),
            })
          }
        }
      }
    }
    offset += raw.length
  }
  return output
}

function goDependencies(content: string): Array<{
  declarationName: string
  packageName: string
  version: string
  offset: number
}> {
  const output: Array<{
    declarationName: string
    packageName: string
    version: string
    offset: number
  }> = []
  let requireBlock = false
  let offset = 0
  for (const raw of content.split(/(?<=\n)/u)) {
    const line = raw.replace(/\r?\n$/u, '')
    if (/^\s*require\s*\(\s*$/u.test(line)) requireBlock = true
    else if (requireBlock && /^\s*\)\s*$/u.test(line)) requireBlock = false
    else {
      const match = requireBlock
        ? line.match(/^\s*([^\s/][^\s]*)\s+(v[^\s]+)(?:\s+\/\/.*)?$/u)
        : line.match(/^\s*require\s+([^\s]+)\s+(v[^\s]+)(?:\s+\/\/.*)?$/u)
      if (match?.[1] !== undefined && match[2] !== undefined) {
        output.push({
          declarationName: match[1], packageName: match[1], version: match[2],
          offset: offset + line.indexOf(match[1]),
        })
      }
    }
    offset += raw.length
  }
  return output
}

function goModuleIsReplaced(content: string, moduleName: string): boolean {
  const escaped = escapeRegex(moduleName)
  return new RegExp(`^\\s*replace\\s+${escaped}(?:\\s+v[^\\s]+)?\\s+=>`, 'mu').test(content)
    || new RegExp(`^\\s*${escaped}(?:\\s+v[^\\s]+)?\\s+=>`, 'mu').test(replaceBlock(content))
}

function replaceBlock(content: string): string {
  const blocks = [...content.matchAll(/^\s*replace\s*\(\s*$([\s\S]*?)^\s*\)\s*$/gmu)]
  return blocks.map(match => match[1] ?? '').join('\n')
}

function rustImports(
  content: string,
  dependencies: ReadonlyMap<string, AffectedDependency>,
  declarationRoots: ReadonlyMap<string, ReadonlySet<string>>,
): Array<{ name: string; offset: number }> {
  const output: Array<{ name: string; offset: number }> = []
  for (const dependency of dependencies.values()) {
    const roots = new Set([
      ...(dependency.importNames.length > 0
        ? dependency.importNames
        : [dependency.name.replaceAll('-', '_')]),
      ...(declarationRoots.get(dependency.name) ?? []),
    ])
    for (const root of roots) {
      const expression = new RegExp(`(?:^|\\n)\\s*(?:pub\\s+)?(?:use|extern\\s+crate)\\s+(?:::)?${escapeRegex(root)}(?:\\b|::)`, 'gu')
      for (const match of content.matchAll(expression)) output.push({ name: dependency.name, offset: match.index })
    }
  }
  return output
}

function goImports(
  content: string,
  dependencies: ReadonlyMap<string, AffectedDependency>,
): Array<{ name: string; offset: number }> {
  const output: Array<{ name: string; offset: number }> = []
  for (const dependency of dependencies.values()) {
    const roots = dependency.importNames.length > 0 ? dependency.importNames : [dependency.name]
    for (const root of roots) {
      const expression = new RegExp(`["']${escapeRegex(root)}(?:/[^"']*)?["']`, 'gu')
      for (const match of content.matchAll(expression)) output.push({ name: dependency.name, offset: match.index })
    }
  }
  return output
}

function versionMayBeAffected(declared: string, affected: string, _language: 'rust' | 'go'): boolean {
  const declaredRange = validRange(declared.replace(/v(?=\d)/gu, ''), { loose: true, includePrerelease: true })
  const affectedRange = validRange(
    affected.replace(/^==?\s*/u, '').replace(/v(?=\d)/gu, ''),
    { loose: true, includePrerelease: true },
  )
  return declaredRange === null || affectedRange === null
    || intersects(declaredRange, affectedRange, { loose: true, includePrerelease: true })
}

function location(root: string, path: string, content: string, offset = 0, endOffset = offset) {
  const lines = content.slice(0, Math.max(0, offset)).split(/\r?\n/u)
  const endLine = content.slice(0, Math.max(offset, endOffset)).split(/\r?\n/u).length
  return {
    path: relative(root, path).replaceAll('\\', '/'),
    line: lines.length,
    ...(endLine > lines.length ? { endLine } : {}),
    column: (lines.at(-1)?.length ?? 0) + 1,
  }
}

function balancedExpressionEndOffset(content: string, start: number): number {
  const opening = content.slice(start).search(/[({\[]/u)
  if (opening === -1) return start
  const first = start + opening
  const pairs: Record<string, string> = { '(': ')', '{': '}', '[': ']' }
  const stack: string[] = []
  let quoted = false
  let escaped = false
  let lineComment = false
  let blockCommentDepth = 0
  for (let index = first; index < content.length; index += 1) {
    const character = content[index]!
    const next = content[index + 1]
    if (lineComment) {
      if (character === '\n') lineComment = false
      continue
    }
    if (blockCommentDepth > 0) {
      if (character === '/' && next === '*') { blockCommentDepth += 1; index += 1 }
      else if (character === '*' && next === '/') { blockCommentDepth -= 1; index += 1 }
      continue
    }
    if (quoted) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') quoted = false
      continue
    }
    if (character === '"') { quoted = true; continue }
    if (character === '/' && next === '/') { lineComment = true; index += 1; continue }
    if (character === '/' && next === '*') { blockCommentDepth = 1; index += 1; continue }
    const close = pairs[character]
    if (close !== undefined) stack.push(close)
    else if (stack.at(-1) === character) {
      stack.pop()
      if (stack.length === 0) return index + 1
    }
  }
  return start
}

function deduplicate(evidence: ImpactEvidence[]): ImpactEvidence[] {
  const seen = new Set<string>()
  return evidence.filter(item => {
    const key = [item.kind, item.operation, item.location?.path, item.location?.line, item.location?.column].join(':')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function impact(
  input: Pick<AnalyzeNativeRepositoryInput, 'baseSha' | 'changeEvent'>,
  outcome: RepositoryImpact['outcome'],
  evidence: ImpactEvidence[],
  reasons: string[],
): RepositoryImpact {
  return {
    schemaVersion: '1.0', changeEventId: input.changeEvent.id, baseSha: input.baseSha,
    outcome, evidence, reasons,
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}

function legacySymbolExpression(symbol: string): RegExp {
  const leadingBoundary = /^[\p{L}\p{N}_]/u.test(symbol) ? '\\b' : ''
  const trailingBoundary = /[\p{L}\p{N}_]$/u.test(symbol) ? '\\b' : ''
  return new RegExp(`${leadingBoundary}${escapeRegex(symbol)}${trailingBoundary}`, 'gu')
}
