import { readFile, readdir } from 'node:fs/promises'
import { dirname, extname, relative, resolve } from 'node:path'
import type {
  ActionableChangeEvent,
  AffectedDependency,
  ImpactEvidence,
  RepositoryImpact,
  RepositoryLanguage,
} from '@automated-api/contracts'

const EXCLUDED_DIRECTORIES = new Set([
  '.git', '.idea', '.vscode', 'build', 'cmake-build-debug', 'cmake-build-release',
  'dist', 'node_modules', 'out', 'target', 'vendor', 'vcpkg_installed',
])
const CPP_SOURCE_EXTENSIONS = new Set([
  '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp',
  '.inl', '.inc', '.ixx', '.cppm',
])
const C_SOURCE_EXTENSIONS = new Set(['.c', '.h'])
const ALL_SOURCE_EXTENSIONS = new Set([...CPP_SOURCE_EXTENSIONS, ...C_SOURCE_EXTENSIONS])
const MAX_SOURCE_BYTES = 2 * 1024 * 1024

export interface AnalyzeCppRepositoryInput {
  rootDir: string
  baseSha: string
  changeEvent: ActionableChangeEvent
}

export async function analyzeCppRepository(input: AnalyzeCppRepositoryInput): Promise<RepositoryImpact> {
  return analyzeVcpkgRepository(input, 'cpp')
}

export async function analyzeCRepository(input: AnalyzeCppRepositoryInput): Promise<RepositoryImpact> {
  return analyzeVcpkgRepository(input, 'c')
}

async function analyzeVcpkgRepository(
  input: AnalyzeCppRepositoryInput,
  language: Extract<RepositoryLanguage, 'c' | 'cpp'>,
): Promise<RepositoryImpact> {
  const label = language === 'c' ? 'C' : 'C++'
  const dependencies = input.changeEvent.impactScope === 'api' ? []
    : input.changeEvent.affectedDependencies.filter(item => item.ecosystem === 'vcpkg')
  const apiHosts = input.changeEvent.impactScope === 'sdk' ? []
    : [...new Set(input.changeEvent.affectedApiHosts.map(host => host.toLowerCase()))]
  if (dependencies.length === 0 && apiHosts.length === 0) {
    return result(input, 'blocked', [], [
      `change event has no vcpkg dependency or API host metadata for ${label} analysis`,
    ])
  }

  const root = resolve(input.rootDir)
  const paths = await repositoryPaths(root)
  const manifestScopes: Array<{
    directory: string
    active: Map<string, AffectedDependency>
  }> = []
  const evidence: ImpactEvidence[] = []
  for (const manifest of paths.filter(path => /(?:^|[/\\])vcpkg\.json$/u.test(path))) {
    const content = await readFile(manifest, 'utf8')
    const parsed = parseVcpkgManifest(content, manifest)
    const active = new Map<string, AffectedDependency>()
    manifestScopes.push({ directory: dirname(manifest), active })
    let hasDirectAffectedDependency = false
    for (const declaration of parsed.dependencies) {
      const dependency = dependencies.find(item => normalize(item.name) === normalize(declaration.name))
      if (dependency === undefined) continue
      const declared = parsed.overrides.get(normalize(declaration.name)) ?? declaration.version
      if (declared === undefined || !versionMayBeAffected(
        declared,
        dependency.oldVersionRange ?? input.changeEvent.oldVersion,
      )) continue
      active.set(normalize(dependency.name), dependency)
      hasDirectAffectedDependency = true
      const offset = content.indexOf(JSON.stringify(declaration.name))
      const workspace = relative(root, dirname(manifest)).replaceAll('\\', '/')
      evidence.push({
        kind: language === 'c' ? 'c_dependency' : 'cpp_dependency', operation: 'package_usage',
        location: location(root, manifest, content, Math.max(0, offset)),
        detail: `vcpkg dependency ${JSON.stringify(dependency.name)} at ${JSON.stringify(declared)} is affected`,
        deterministicRecipeSupported: false,
        language, ecosystem: 'vcpkg',
        ...(workspace === '' || workspace === '.' ? {} : { workspace }),
      })
    }
    // A vcpkg override can pin a transitive ABI companion without listing it
    // as a direct dependency. Once this manifest is in scope through a direct
    // affected package, retain every affected override so the migration and
    // certification layers cannot silently validate a different graph.
    if (hasDirectAffectedDependency) {
      for (const dependency of dependencies) {
        if (active.has(normalize(dependency.name))) continue
        const declared = parsed.overrides.get(normalize(dependency.name))
        if (declared === undefined || !versionMayBeAffected(
          declared, dependency.oldVersionRange ?? input.changeEvent.oldVersion,
        )) continue
        active.set(normalize(dependency.name), dependency)
        const offset = content.indexOf(JSON.stringify(dependency.name))
        const workspace = relative(root, dirname(manifest)).replaceAll('\\', '/')
        evidence.push({
          kind: language === 'c' ? 'c_dependency' : 'cpp_dependency', operation: 'package_usage',
          location: location(root, manifest, content, Math.max(0, offset)),
          detail: `vcpkg transitive override ${JSON.stringify(dependency.name)} at ${JSON.stringify(declared)} is affected`,
          deterministicRecipeSupported: false, language, ecosystem: 'vcpkg',
          ...(workspace === '' || workspace === '.' ? {} : { workspace }),
        })
      }
    }
  }

  const oldSymbols = new Set(input.changeEvent.operations.flatMap(operation =>
    operation.oldSymbol === undefined ? [] : [operation.oldSymbol]))
  const legacyBuildSymbols = new Set(input.changeEvent.operations.flatMap(operation => {
    const buildSystem = operation.details['buildSystem']
    if (typeof buildSystem !== 'object' || buildSystem === null) return []
    const patterns = (buildSystem as Record<string, unknown>)['legacyPatterns']
    return Array.isArray(patterns)
      ? patterns.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : []
  }))
  for (const path of paths.filter(path => isSourceForLanguage(path, language) || isCmakeConfiguration(path))) {
    const bytes = await readFile(path)
    if (bytes.byteLength > MAX_SOURCE_BYTES) continue
    const content = bytes.toString('utf8')
    const scope = nearestManifestScope(path, manifestScopes)
    const buildConfiguration = isCmakeConfiguration(path)
    const importedDependencies = [...(scope?.active.values() ?? [])].filter(dependency => dependency.importNames.some(importName =>
      includeOrNamespaceExpression(importName).test(content)))
    const manifestScopedSymbols = new Set(
      (scope?.active.size ?? 0) === 0 || buildConfiguration
        ? []
        : [...oldSymbols].filter(symbol =>
            isQualifiedCppSymbol(symbol) && oldSymbolExpression(symbol).test(content)),
    )
    for (const dependency of importedDependencies) {
      const importName = dependency.importNames.find(name => includeOrNamespaceExpression(name).test(content))!
      const match = includeOrNamespaceExpression(importName).exec(content)
      evidence.push({
        kind: language === 'c' ? 'c_import' : 'cpp_import', operation: 'package_usage',
        location: location(root, path, content, match?.index ?? 0),
        detail: `${label} source references affected vcpkg package ${JSON.stringify(dependency.name)} through ${JSON.stringify(importName)}`,
        deterministicRecipeSupported: false, language, ecosystem: 'vcpkg',
      })
    }
    if (importedDependencies.length > 0
      || manifestScopedSymbols.size > 0
      || (buildConfiguration && (scope?.active.size ?? 0) > 0)) {
      const symbols = buildConfiguration
        ? new Set([...oldSymbols, ...legacyBuildSymbols])
        : importedDependencies.length > 0 ? oldSymbols : manifestScopedSymbols
      for (const symbol of symbols) {
        const expression = oldSymbolExpression(symbol)
        for (const match of content.matchAll(expression)) {
          evidence.push({
            kind: buildConfiguration
              ? (language === 'c' ? 'c_dependency' : 'cpp_dependency')
              : (language === 'c' ? 'c_call' : 'cpp_call'),
            operation: symbol,
            location: location(root, path, content, match.index),
            detail: buildConfiguration
              ? `affected ${label} build configuration references legacy SDK symbol ${JSON.stringify(symbol)}`
              : `affected ${label} source references legacy symbol ${JSON.stringify(symbol)}`,
            deterministicRecipeSupported: false, language, ecosystem: 'vcpkg',
          })
        }
      }
    }
    for (const host of apiHosts) {
      const suffix = host.replace(/^\*\./u, '')
      const expression = new RegExp(`https?://(?:[A-Za-z0-9-]+\\.)*${escapeRegex(suffix)}(?=[/:?#\"'\\s]|$)`, 'giu')
      for (const match of content.matchAll(expression)) {
        evidence.push({
          kind: language === 'c' ? 'c_raw_endpoint' : 'cpp_raw_endpoint', operation: 'api_host_usage',
          location: location(root, path, content, match.index),
          detail: `${label} source uses affected API host ${JSON.stringify(host)}`,
          deterministicRecipeSupported: false, language,
        })
      }
    }
  }

  const unique = deduplicate(evidence)
  if (unique.length === 0) return result(input, 'not_affected', [], [
    `no ${label} dependency, include, symbol, or API URL matched ${[
      ...dependencies.map(item => item.name), ...apiHosts,
    ].join(', ')}`,
  ])
  return result(input, 'affected_manual', unique, [
    `affected ${label} usage was found and is routed to the bounded Harness until an exact reviewed recipe matches`,
  ])
}

function isQualifiedCppSymbol(symbol: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+$/u.test(symbol)
}

function oldSymbolExpression(symbol: string): RegExp {
  // A verified namespace operation authorizes qualified descendants, but not
  // identifiers that merely contain the same text as a prefix or suffix.
  return new RegExp(`(?<![A-Za-z0-9_])${escapeRegex(symbol)}(?![A-Za-z0-9_])`, 'gu')
}

function nearestManifestScope<T extends { directory: string }>(path: string, scopes: T[]): T | undefined {
  return scopes
    .filter(scope => {
      const candidate = relative(scope.directory, path)
      return candidate !== '..' && !candidate.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
    })
    .sort((left, right) => right.directory.length - left.directory.length)[0]
}

interface VcpkgDeclaration { name: string; version?: string }

export function parseVcpkgManifest(content: string, path = 'vcpkg.json'): {
  dependencies: VcpkgDeclaration[]
  overrides: Map<string, string>
  baseline?: string
} {
  let value: unknown
  try {
    value = JSON.parse(content)
  } catch {
    throw new Error(`invalid vcpkg.json while checking affected dependencies: ${path}`)
  }
  if (typeof value !== 'object' || value === null) throw new Error(`vcpkg.json must contain an object: ${path}`)
  const record = value as Record<string, unknown>
  const dependencies = Array.isArray(record['dependencies']) ? record['dependencies'].flatMap(item => {
    if (typeof item === 'string') return [{ name: item }]
    if (typeof item !== 'object' || item === null || typeof (item as Record<string, unknown>)['name'] !== 'string') return []
    const dependency = item as Record<string, unknown>
    const version = typeof dependency['version>='] === 'string' ? dependency['version>='] : undefined
    return [{ name: dependency['name'] as string, ...(version === undefined ? {} : { version }) }]
  }) : []
  const overrides = new Map<string, string>()
  if (Array.isArray(record['overrides'])) {
    for (const item of record['overrides']) {
      if (typeof item !== 'object' || item === null) continue
      const override = item as Record<string, unknown>
      const name = typeof override['name'] === 'string' ? override['name'] : undefined
      const version = ['version', 'version-semver', 'version-string'].map(key => override[key])
        .find(candidate => typeof candidate === 'string')
      const portVersion = Number.isSafeInteger(override['port-version']) && Number(override['port-version']) > 0
        ? `#${String(override['port-version'])}` : ''
      if (name !== undefined && typeof version === 'string') overrides.set(normalize(name), `${version}${portVersion}`)
    }
  }
  const configuration = typeof record['vcpkg-configuration'] === 'object' && record['vcpkg-configuration'] !== null
    ? record['vcpkg-configuration'] as Record<string, unknown> : undefined
  const baseline = typeof record['builtin-baseline'] === 'string' ? record['builtin-baseline']
    : typeof configuration?.['default-registry'] === 'object' && configuration['default-registry'] !== null
      && typeof (configuration['default-registry'] as Record<string, unknown>)['baseline'] === 'string'
      ? (configuration['default-registry'] as Record<string, string>)['baseline'] : undefined
  return { dependencies, overrides, ...(baseline === undefined ? {} : { baseline }) }
}

function versionMayBeAffected(declared: string, affected: string): boolean {
  const normalizeVersion = (value: string) => value.trim().replace(/^v/u, '').replace(/#\d+$/u, '')
  const actual = normalizeVersion(declared)
  const range = normalizeVersion(affected)
  if (actual === range) return true
  const major = /^(\d+)/u.exec(actual)?.[1]
  const affectedMajor = /^(?:[~^<>= ]*)(\d+)/u.exec(range)?.[1]
  return major !== undefined && affectedMajor !== undefined && major === affectedMajor
}

async function repositoryPaths(root: string): Promise<string[]> {
  const output: string[] = []
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue
      const path = resolve(directory, entry.name)
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) await visit(path)
      } else if (entry.isFile() && (entry.name === 'vcpkg.json'
        || isCmakeConfiguration(path)
        || ALL_SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase()))) {
        output.push(path)
      }
    }
  }
  await visit(root)
  return output.sort()
}

function includeOrNamespaceExpression(name: string): RegExp {
  return new RegExp(`^\\s*#\\s*include\\s*[<\"]${escapeRegex(name)}(?:[/."]|>)|\\b${escapeRegex(name)}::`, 'mu')
}

function location(root: string, path: string, content: string, offset: number) {
  const before = content.slice(0, offset)
  const lines = before.split(/\r?\n/u)
  return {
    path: relative(root, path).replaceAll('\\', '/'),
    line: lines.length,
    column: (lines.at(-1)?.length ?? 0) + 1,
  }
}

function isSourceForLanguage(path: string, language: Extract<RepositoryLanguage, 'c' | 'cpp'>): boolean {
  const extension = extname(path)
  if (extension === '.C') return language === 'cpp'
  return (language === 'c' ? C_SOURCE_EXTENSIONS : CPP_SOURCE_EXTENSIONS).has(extension.toLowerCase())
}

function isCmakeConfiguration(path: string): boolean {
  return /(?:^|[/\\])CMakeLists\.txt$/u.test(path) || extname(path).toLowerCase() === '.cmake'
}

function result(
  input: AnalyzeCppRepositoryInput,
  outcome: RepositoryImpact['outcome'],
  evidence: ImpactEvidence[],
  reasons: string[],
): RepositoryImpact {
  return {
    schemaVersion: '1.0', changeEventId: input.changeEvent.id,
    baseSha: input.baseSha, outcome, evidence, reasons,
  }
}

function deduplicate(evidence: ImpactEvidence[]): ImpactEvidence[] {
  const seen = new Set<string>()
  return evidence.filter(item => {
    const key = `${item.kind}:${item.operation}:${item.location?.path ?? ''}:${item.location?.line ?? 0}:${item.location?.column ?? 0}`
    return seen.has(key) ? false : (seen.add(key), true)
  })
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/_+/gu, '-')
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}
