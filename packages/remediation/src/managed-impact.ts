import { readFile, readdir } from 'node:fs/promises'
import { dirname, extname, relative, resolve } from 'node:path'
import { hasSwiftResponseTypeOverride, reviewedSwiftResponseChange, swiftResponseContentAccesses } from './swift-response-access.js'
import type {
  ActionableChangeEvent,
  AffectedDependency,
  ImpactEvidence,
  PackageEcosystem,
  RepositoryImpact,
  RepositoryLanguage,
} from '@automated-api/contracts'
import { jvmDescriptorMethodName, jvmDescriptorSourceCalls } from './jvm-source-methods.js'
import { isReviewedRubyRedisMigration, rubyRedisOwnershipEvidence } from './ruby-redis-ownership.js'

const EXCLUDED_DIRECTORIES = new Set([
  '.git', '.gradle', '.idea', '.swiftpm', '.build', '.dart_tool', '.bundle', '.venv', '.vscode',
  'bin', 'build', 'coverage', 'dist', 'node_modules', 'obj', 'target', 'vendor',
])
const MAX_SOURCE_BYTES = 2 * 1024 * 1024

interface ManagedLanguageConfiguration {
  language: Extract<RepositoryLanguage, 'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure'>
  ecosystem: Extract<PackageEcosystem, 'maven' | 'nuget' | 'composer' | 'gem' | 'swiftpm' | 'pub' | 'hex'>
  sourceExtensions: readonly string[]
  manifestNames: readonly RegExp[]
}

const CONFIGURATIONS: Readonly<Record<ManagedLanguageConfiguration['language'], ManagedLanguageConfiguration>> = {
  java: configuration('java', 'maven', ['.java'], [/^pom\.xml$/u, /^build\.gradle(?:\.kts)?$/u, /^gradle\.lockfile$/u]),
  kotlin: configuration('kotlin', 'maven', ['.kt', '.kts'], [/^pom\.xml$/u, /^build\.gradle(?:\.kts)?$/u, /^gradle\.lockfile$/u]),
  scala: configuration('scala', 'maven', ['.scala'], [/^build\.sbt$/u]),
  csharp: configuration('csharp', 'nuget', ['.cs'], [/\.csproj$/u, /^Directory\.Packages\.props$/u]),
  php: configuration('php', 'composer', ['.php'], [/^composer\.json$/u]),
  ruby: configuration('ruby', 'gem', ['.rb'], [/^Gemfile$/u, /\.gemspec$/u]),
  swift: configuration('swift', 'swiftpm', ['.swift'], [/^Package\.swift$/u]),
  dart: configuration('dart', 'pub', ['.dart'], [/^pubspec\.yaml$/u]),
  elixir: configuration('elixir', 'hex', ['.ex', '.exs'], [/^mix\.exs$/u, /^mix\.lock$/u]),
  clojure: configuration('clojure', 'maven', ['.clj', '.cljc', '.cljs'], [/^deps\.edn$/u, /^project\.clj$/u]),
}

export interface AnalyzeManagedRepositoryInput {
  rootDir: string
  baseSha: string
  changeEvent: ActionableChangeEvent
}

export function analyzeManagedRepository(
  input: AnalyzeManagedRepositoryInput,
  language: ManagedLanguageConfiguration['language'],
): Promise<RepositoryImpact> {
  return analyze(input, CONFIGURATIONS[language])
}

async function analyze(
  input: AnalyzeManagedRepositoryInput,
  config: ManagedLanguageConfiguration,
): Promise<RepositoryImpact> {
  const dependencies = input.changeEvent.impactScope === 'api' ? []
    : input.changeEvent.affectedDependencies.filter(item => item.ecosystem === config.ecosystem)
  const apiHosts = input.changeEvent.impactScope === 'sdk' ? []
    : [...new Set(input.changeEvent.affectedApiHosts.map(host => host.toLowerCase()))]
  if (dependencies.length === 0 && apiHosts.length === 0) {
    return result(input, 'blocked', [], [
      `change event has no ${config.ecosystem} dependency or API host metadata for ${config.language} analysis`,
    ])
  }

  const root = resolve(input.rootDir)
  const paths = await repositoryPaths(root, config)
  const manifests = paths.filter(item => config.manifestNames.some(pattern => pattern.test(item.name)))
  const manifestDocuments: ManifestDocument[] = await Promise.all(manifests.map(async manifest => ({
    ...manifest,
    content: await readFile(manifest.path, 'utf8'),
  })))
  const mavenModels = config.ecosystem === 'maven'
    ? new Map(manifestDocuments
      .filter(manifest => manifest.name === 'pom.xml')
      .map(manifest => [manifest.path, mavenModel(manifest)]))
    : new Map<string, MavenModel>()
  const active = new Map<string, AffectedDependency>()
  const evidence: ImpactEvidence[] = []
  for (const manifest of manifestDocuments) {
    for (const declaration of manifest.name === 'pom.xml'
      ? resolvedMavenDependencies(manifest.path, mavenModels)
      : dependencyDeclarations(manifest.content, manifest.name, config.ecosystem)) {
      const dependency = dependencies.find(candidate => normalizedName(candidate.name, config.ecosystem)
        === normalizedName(declaration.name, config.ecosystem))
      if (dependency === undefined || !versionMayBeAffected(
        declaration.version,
        dependency.oldVersionRange ?? input.changeEvent.oldVersion,
      )) continue
      active.set(dependency.name, dependency)
      const workspace = relative(root, dirname(manifest.path)).replaceAll('\\', '/')
      evidence.push({
        kind: 'dependency', operation: 'package_usage',
        location: location(root, manifest.path, manifest.content, declaration.offset),
        detail: `${config.ecosystem} dependency ${JSON.stringify(dependency.name)} at ${JSON.stringify(declaration.version)} is affected`,
        deterministicRecipeSupported: false,
        language: config.language, ecosystem: config.ecosystem,
        ...(workspace === '' || workspace === '.' ? {} : { workspace }),
      })
    }
  }

  const legacyOperations = input.changeEvent.operations.filter(operation => operation.oldSymbol !== undefined)
  const localRedisRequireShadow = config.language === 'ruby' && paths.some(source =>
    ['redis.rb', 'lib/redis.rb'].includes(relative(root, source.path).replaceAll('\\', '/')))
  const swiftResponseChange = config.language === 'swift' && active.has('OpenAI') && reviewedSwiftResponseChange(input.changeEvent)
  const swiftTypeOverride = swiftResponseChange && (await Promise.all(paths.filter(item => item.extension === '.swift')
    .map(async source => source.size > MAX_SOURCE_BYTES || hasSwiftResponseTypeOverride(await readFile(source.path, 'utf8'))))).some(Boolean)
  for (const source of paths.filter(item => config.sourceExtensions.includes(item.extension))) {
    if (source.size > MAX_SOURCE_BYTES) continue
    const content = await readFile(source.path, 'utf8')
    if (config.language === 'ruby' && active.has('redis') && isReviewedRubyRedisMigration(input.changeEvent)) {
      if (!localRedisRequireShadow) evidence.push(...rubyRedisOwnershipEvidence(content, relative(root, source.path).replaceAll('\\', '/'), input.changeEvent))
      // This constructor-option event does not authorize editing every file
      // importing Redis. Keep unresolved/shadowed sources out of the Harness.
      continue
    }
    if (swiftResponseChange) {
      if (!swiftTypeOverride) for (const access of swiftResponseContentAccesses(content)) {
        evidence.push({ kind: 'sdk_call', operation: input.changeEvent.operations[0]!.oldSymbol!,
          location: location(root, source.path, content, access.offset),
          detail: 'Exact archived OpenAI.chats response ownership: Choice.message now exposes optional String content directly; remove only the old content string accessor and preserve the fallback.',
          deterministicRecipeSupported: false, language: 'swift', ecosystem: 'swiftpm' })
      }
      // A declaration type change does not authorize unrelated import lines or
      // same-named content fields. Only owned response accesses establish scope.
      continue
    }
    const imports = matchingImports(content, active, config)
    for (const imported of imports) {
      evidence.push({
        kind: 'sdk_import', operation: 'package_usage',
        location: location(root, source.path, content, imported.offset),
        detail: `import from affected ${config.ecosystem} package ${JSON.stringify(imported.name)}`,
        deterministicRecipeSupported: false,
        language: config.language, ecosystem: config.ecosystem,
      })
    }
    for (const operation of legacyOperations) {
      const symbol = operation.oldSymbol!
      const descriptor = jvmDescriptorMethodName(symbol, config.language)
      const offsets = descriptor === undefined
        ? (imports.length ? [...content.matchAll(legacySymbolExpression(symbol))].map(match => match.index) : [])
        : jvmDescriptorSourceCalls({ content, symbol, operation: operation.operation,
          language: config.language, importRoots: [...active.values()].flatMap(dependency => dependency.importNames),
          changeEvent: input.changeEvent })
      for (const offset of offsets) {
        if (isCommentOccurrence(content, offset, config.language)) continue
        evidence.push({
          kind: 'sdk_call', operation: symbol,
          location: location(root, source.path, content, offset),
          detail: `affected ${config.language} source references legacy symbol ${JSON.stringify(symbol)}`,
          deterministicRecipeSupported: false,
          language: config.language, ecosystem: config.ecosystem,
        })
      }
    }
    for (const host of apiHosts) {
      const suffix = host.replace(/^\*\./u, '')
      const expression = new RegExp(`https?://(?:[A-Za-z0-9-]+\\.)*${escapeRegex(suffix)}(?=[/:?#"'\\s]|$)`, 'giu')
      for (const match of content.matchAll(expression)) {
        evidence.push({
          kind: 'raw_rest_endpoint', operation: 'api_host_usage',
          location: location(root, source.path, content, match.index),
          detail: `${config.language} source uses affected API host ${JSON.stringify(host)}`,
          deterministicRecipeSupported: false, language: config.language,
        })
      }
    }
  }

  const unique = deduplicate(evidence)
  if (unique.length === 0) return result(input, 'not_affected', [], [
    `no ${config.language} dependency, import, symbol, or API URL matched ${[
      ...dependencies.map(item => item.name), ...apiHosts,
    ].join(', ')}`,
  ])
  return result(input, 'affected_manual', unique, [
    `affected ${config.language} usage was found and is routed to the bounded Harness until an exact reviewed recipe matches`,
  ])
}

function isCommentOccurrence(
  content: string,
  offset: number,
  language: ManagedLanguageConfiguration['language'],
): boolean {
  const before = content.slice(0, offset)
  const linePrefix = before.slice(before.lastIndexOf('\n') + 1).trimStart()
  if (linePrefix.startsWith('//')) return true
  if ((language === 'php' || language === 'ruby') && linePrefix.startsWith('#')) return true
  return before.lastIndexOf('/*') > before.lastIndexOf('*/')
}

function configuration(
  language: ManagedLanguageConfiguration['language'],
  ecosystem: ManagedLanguageConfiguration['ecosystem'],
  sourceExtensions: readonly string[],
  manifestNames: readonly RegExp[],
): ManagedLanguageConfiguration {
  return { language, ecosystem, sourceExtensions, manifestNames }
}

interface RepositoryPath { path: string; name: string; extension: string; size: number }

interface ManifestDocument extends RepositoryPath { content: string }

interface MavenModel {
  path: string
  properties: ReadonlyMap<string, string>
  parentRelativePath?: string
  projectVersion?: string
  parentVersion?: string
  managedDependencies: ReadonlyMap<string, string>
  importedBoms: ReadonlyArray<{ name: string; version: string }>
  dependencies: ReadonlyArray<{ name: string; version?: string; offset: number }>
}

async function repositoryPaths(root: string, config: ManagedLanguageConfiguration): Promise<RepositoryPath[]> {
  const paths: RepositoryPath[] = []
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true })
    const mixProject = config.language === 'elixir'
      && entries.some(entry => entry.isFile() && entry.name === 'mix.exs')
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const path = resolve(directory, entry.name)
      if (entry.isDirectory()) {
        if (mixProject && (entry.name === 'deps' || entry.name === '_build')) continue
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) await visit(path)
      } else if (entry.isFile()) {
        const extension = extname(entry.name)
        if (config.sourceExtensions.includes(extension)
          || config.manifestNames.some(pattern => pattern.test(entry.name))) {
          const content = await readFile(path)
          paths.push({ path, name: entry.name, extension, size: content.byteLength })
        }
      }
    }
  }
  await visit(root)
  return paths.sort((left, right) => left.path.localeCompare(right.path))
}

function dependencyDeclarations(
  content: string,
  manifestName: string,
  ecosystem: ManagedLanguageConfiguration['ecosystem'],
): Array<{ name: string; version: string; offset: number }> {
  if (ecosystem === 'maven') return manifestName === 'pom.xml'
    ? xmlDependencies(content)
    : manifestName === 'build.sbt'
      ? sbtDependencies(content)
    : manifestName === 'gradle.lockfile'
      ? gradleLockDependencies(content)
      : manifestName === 'deps.edn'
        ? depsEdnDependencies(content)
        : manifestName === 'project.clj'
          ? leinDependencies(content)
          : gradleDependencies(content)
  if (ecosystem === 'nuget') return xmlPackageReferences(content)
  if (ecosystem === 'composer') return jsonDependencies(content)
  if (ecosystem === 'gem') return gemDependencies(content)
  if (ecosystem === 'swiftpm') return swiftDependencies(content)
  if (ecosystem === 'hex') return manifestName === 'mix.lock'
    ? mixLockDependencies(content)
    : mixDependencies(content)
  return pubDependencies(content)
}

function xmlDependencies(content: string) {
  const output: Array<{ name: string; version: string; offset: number }> = []
  for (const match of content.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency>/giu)) {
    const body = match[1] ?? ''
    const group = body.match(/<groupId>\s*([^<]+?)\s*<\/groupId>/iu)?.[1]
    const artifact = body.match(/<artifactId>\s*([^<]+?)\s*<\/artifactId>/iu)?.[1]
    const version = body.match(/<version>\s*([^<]+?)\s*<\/version>/iu)?.[1]
    if (group && artifact && version) output.push({
      name: `${group}:${artifact}`,
      version,
      offset: match.index,
    })
  }
  return output
}

function mavenModel(document: ManifestDocument): MavenModel {
  const parentMatch = document.content.match(/<parent\b[^>]*>([\s\S]*?)<\/parent>/iu)
  const parent = parentMatch?.[1] ?? ''
  const managementRanges = [...document.content.matchAll(/<dependencyManagement\b[^>]*>[\s\S]*?<\/dependencyManagement>/giu)]
    .map(match => [match.index, match.index + match[0].length] as const)
  const dependencies: Array<{ name: string; version?: string; offset: number }> = []
  const managedDependencies = new Map<string, string>()
  const importedBoms: Array<{ name: string; version: string }> = []
  for (const match of document.content.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency>/giu)) {
    const body = match[1] ?? ''
    const group = xmlValue(body, 'groupId')
    const artifact = xmlValue(body, 'artifactId')
    if (!group || !artifact) continue
    const version = xmlValue(body, 'version')
    const dependency = {
      name: `${group}:${artifact}`,
      ...(version === undefined ? {} : { version }),
      offset: match.index,
    }
    const managed = managementRanges.some(([start, end]) => match.index >= start && match.index < end)
    if (managed && dependency.version !== undefined) {
      managedDependencies.set(dependency.name, dependency.version)
      if (xmlValue(body, 'type') === 'pom' && xmlValue(body, 'scope') === 'import') {
        importedBoms.push({ name: dependency.name, version: dependency.version })
      }
    }
    else if (!managed) dependencies.push(dependency)
  }
  const relativePathMatch = parent.match(/<relativePath\b[^>]*>([\s\S]*?)<\/relativePath>/iu)
  const relativePath = relativePathMatch?.[1]?.trim()
  const parentResolutionDisabled = /<relativePath\s*\/\s*>/iu.test(parent)
    || (relativePathMatch !== null && relativePath === '')
  const projectVersion = mavenProjectVersion(document.content)
  const parentVersion = xmlValue(parent, 'version')
  return {
    path: document.path,
    properties: mavenProperties(document.content),
    ...(parentMatch === null || parentResolutionDisabled ? {} : { parentRelativePath: relativePath || '../pom.xml' }),
    ...(projectVersion === undefined ? {} : { projectVersion }),
    ...(parentVersion === undefined ? {} : { parentVersion }),
    managedDependencies,
    importedBoms,
    dependencies,
  }
}

function resolvedMavenDependencies(
  path: string,
  models: ReadonlyMap<string, MavenModel>,
): Array<{ name: string; version: string; offset: number }> {
  const model = models.get(path)
  if (model === undefined) return []
  const properties = effectiveMavenProperties(model, models, new Set())
  const managed = effectiveMavenManagement(model, models, new Set())
  return model.dependencies.flatMap(dependency => {
    const rawVersion = dependency.version
      ?? managed.get(dependency.name)
      ?? sameFamilyBomVersion(dependency.name, model, models, properties)
    const version = rawVersion === undefined ? undefined : resolveMavenValue(rawVersion, properties)
    return version === undefined || !/\d/u.test(version)
      ? []
      : [{ name: dependency.name, version, offset: dependency.offset }]
  })
}

function sameFamilyBomVersion(
  dependencyName: string,
  model: MavenModel,
  models: ReadonlyMap<string, MavenModel>,
  properties: ReadonlyMap<string, string>,
): string | undefined {
  const [group, artifact] = dependencyName.split(':')
  if (!group || !artifact) return undefined
  const candidates = effectiveImportedBoms(model, models, new Set())
    .filter(candidate => {
      const [bomGroup, bomArtifact] = candidate.name.split(':')
      const family = bomArtifact?.replace(/-bom$/u, '')
      return bomGroup === group && family !== undefined && family !== bomArtifact
        && artifact.startsWith(`${family}-`)
    })
    .map(candidate => resolveMavenValue(candidate.version, properties))
    .filter((version): version is string => version !== undefined)
  return candidates.length === 1 ? candidates[0] : undefined
}

function effectiveImportedBoms(
  model: MavenModel,
  models: ReadonlyMap<string, MavenModel>,
  visiting: Set<string>,
): Array<{ name: string; version: string }> {
  if (visiting.has(model.path)) return []
  visiting.add(model.path)
  const parent = localMavenParent(model, models)
  const boms = parent === undefined ? [] : effectiveImportedBoms(parent, models, visiting)
  boms.push(...model.importedBoms)
  visiting.delete(model.path)
  return boms
}

function effectiveMavenProperties(
  model: MavenModel,
  models: ReadonlyMap<string, MavenModel>,
  visiting: Set<string>,
): Map<string, string> {
  if (visiting.has(model.path)) return new Map()
  visiting.add(model.path)
  const parent = localMavenParent(model, models)
  const properties = parent === undefined
    ? new Map<string, string>()
    : effectiveMavenProperties(parent, models, visiting)
  for (const [name, value] of model.properties) properties.set(name, value)
  const parentVersion = model.parentVersion === undefined
    ? undefined
    : resolveMavenValue(model.parentVersion, properties)
  const projectVersion = model.projectVersion === undefined
    ? parentVersion
    : resolveMavenValue(model.projectVersion, properties)
  if (parentVersion !== undefined) {
    properties.set('parent.version', parentVersion)
    properties.set('project.parent.version', parentVersion)
  }
  if (projectVersion !== undefined) {
    properties.set('version', projectVersion)
    properties.set('pom.version', projectVersion)
    properties.set('project.version', projectVersion)
  }
  visiting.delete(model.path)
  return properties
}

function effectiveMavenManagement(
  model: MavenModel,
  models: ReadonlyMap<string, MavenModel>,
  visiting: Set<string>,
): Map<string, string> {
  if (visiting.has(model.path)) return new Map()
  visiting.add(model.path)
  const parent = localMavenParent(model, models)
  const managed = parent === undefined
    ? new Map<string, string>()
    : effectiveMavenManagement(parent, models, visiting)
  const properties = effectiveMavenProperties(model, models, new Set())
  for (const [name, rawVersion] of model.managedDependencies) {
    const version = resolveMavenValue(rawVersion, properties)
    if (version !== undefined) managed.set(name, version)
  }
  visiting.delete(model.path)
  return managed
}

function localMavenParent(model: MavenModel, models: ReadonlyMap<string, MavenModel>): MavenModel | undefined {
  return model.parentRelativePath === undefined
    ? undefined
    : models.get(resolve(dirname(model.path), model.parentRelativePath))
}

function mavenProperties(content: string): Map<string, string> {
  const body = content.match(/<properties\b[^>]*>([\s\S]*?)<\/properties>/iu)?.[1] ?? ''
  const properties = new Map<string, string>()
  for (const match of body.matchAll(/<([A-Za-z_][\w.-]*)\b[^>]*>\s*([^<]+?)\s*<\/\1>/gu)) {
    if (match[1] && match[2]) properties.set(match[1], match[2])
  }
  return properties
}

function mavenProjectVersion(content: string): string | undefined {
  const project = content
    .replace(/<parent\b[^>]*>[\s\S]*?<\/parent>/giu, '')
    .replace(/<properties\b[^>]*>[\s\S]*?<\/properties>/giu, '')
    .replace(/<dependencyManagement\b[^>]*>[\s\S]*?<\/dependencyManagement>/giu, '')
    .replace(/<dependencies\b[^>]*>[\s\S]*?<\/dependencies>/giu, '')
    .replace(/<build\b[^>]*>[\s\S]*?<\/build>/giu, '')
    .replace(/<profiles\b[^>]*>[\s\S]*?<\/profiles>/giu, '')
  return xmlValue(project, 'version')
}

function resolveMavenValue(value: string, properties: ReadonlyMap<string, string>): string | undefined {
  let resolved = value.trim()
  for (let attempt = 0; attempt < 10 && /\$\{[^}]+\}/u.test(resolved); attempt += 1) {
    let missing = false
    resolved = resolved.replace(/\$\{([^}]+)\}/gu, (_match, name: string) => {
      const replacement = properties.get(name)
      if (replacement === undefined) missing = true
      return replacement ?? ''
    })
    if (missing) return undefined
  }
  return /\$\{[^}]+\}/u.test(resolved) || resolved.length === 0 ? undefined : resolved
}

function xmlValue(content: string, tag: string): string | undefined {
  return content.match(new RegExp(`<${tag}\\b[^>]*>\\s*([^<]+?)\\s*</${tag}>`, 'iu'))?.[1]?.trim()
}

function gradleDependencies(content: string) {
  return [...content.matchAll(/(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*(?:\(\s*)?["']([^:"']+):([^:"']+):([^"']+)["']/gu)]
    .flatMap(match => match[1] && match[2] && match[3]
      ? [{ name: `${match[1]}:${match[2]}`, version: match[3], offset: match.index }]
      : [])
}

function sbtDependencies(content: string) {
  return [...content.matchAll(/["']([^"']+)["']\s*%%?\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']/gu)]
    .flatMap(match => match[1] && match[2] && match[3]
      ? [{ name: `${match[1]}:${match[2]}`, version: match[3], offset: match.index }]
      : [])
}

function gradleLockDependencies(content: string) {
  return [...content.matchAll(/^([^:\s=]+):([^:\s=]+):([^=\s]+)=/gmu)]
    .flatMap(match => match[1] && match[2] && match[3]
      ? [{ name: `${match[1]}:${match[2]}`, version: match[3], offset: match.index }]
      : [])
}

function depsEdnDependencies(content: string) {
  return [...content.matchAll(/(?:^|[\s{])([\w.-]+\/[\w.-]+)\s+\{[^{}]*:mvn\/version\s+["']([^"']+)["'][^{}]*\}/gu)]
    .flatMap(match => match[1] && match[2]
      ? [{ name: match[1].replace('/', ':'), version: match[2], offset: match.index }]
      : [])
}

function leinDependencies(content: string) {
  return [...content.matchAll(/\[([\w.-]+\/[\w.-]+)\s+["']([^"']+)["'][^\]]*\]/gu)]
    .flatMap(match => match[1] && match[2]
      ? [{ name: match[1].replace('/', ':'), version: match[2], offset: match.index }]
      : [])
}

function xmlPackageReferences(content: string) {
  return [...content.matchAll(/<PackageReference\b[^>]*(?:Include|Update)=["']([^"']+)["'][^>]*(?:Version=["']([^"']+)["']|>\s*<Version>\s*([^<]+)<\/Version>)/giu)]
    .flatMap(match => match[1] && (match[2] || match[3])
      ? [{ name: match[1], version: (match[2] ?? match[3])!, offset: match.index }]
      : [])
}

function jsonDependencies(content: string) {
  try {
    const value = JSON.parse(content) as { require?: Record<string, unknown>; 'require-dev'?: Record<string, unknown> }
    return Object.entries({ ...value.require, ...value['require-dev'] }).flatMap(([name, version]) =>
      typeof version === 'string' ? [{ name, version, offset: Math.max(0, content.indexOf(JSON.stringify(name))) }] : [])
  } catch { return [] }
}

function gemDependencies(content: string) {
  return [...content.matchAll(/(?:^|\n)\s*(?:[A-Za-z_]\w*\.)?(?:gem|add_(?:runtime_)?dependency)\s*\(?\s*["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/gu)]
    .flatMap(match => match[1]
      ? [{ name: match[1], version: match[2] ?? '*', offset: match.index }]
      : [])
}

function swiftDependencies(content: string) {
  return [...content.matchAll(/\.package\s*\(\s*(?:name:\s*["']([^"']+)["']\s*,\s*)?url:\s*["']([^"']+)["'][\s\S]*?(?:from:\s*["']([^"']+)["']|exact:\s*["']([^"']+)["']|\.upToNextMajor\s*\(\s*from:\s*["']([^"']+)["'])/gu)]
    .map(match => ({
      name: match[1] ?? swiftPackageName(match[2]!),
      version: match[3] ?? match[4] ?? match[5] ?? '*', offset: match.index,
    }))
}

function pubDependencies(content: string) {
  const output: Array<{ name: string; version: string; offset: number }> = []
  let dependencies = false
  let offset = 0
  for (const raw of content.split(/(?<=\n)/u)) {
    const line = raw.replace(/\r?\n$/u, '')
    if (/^(?:dependencies|dev_dependencies):\s*$/u.test(line)) dependencies = true
    else if (/^[A-Za-z_][\w-]*:\s*$/u.test(line)) dependencies = false
    else if (dependencies) {
      const match = line.match(/^\s{2}([A-Za-z_][\w-]*):\s*([^#\s][^#]*)?/u)
      if (match?.[1] && match[2]) output.push({ name: match[1], version: match[2].trim(), offset: offset + line.indexOf(match[1]) })
    }
    offset += raw.length
  }
  return output
}

function mixDependencies(content: string) {
  return [...content.matchAll(/\{\s*:([a-zA-Z_][\w!?]*)\s*,\s*["']([^"']+)["']/gu)]
    .flatMap(match => match[1] && match[2]
      ? [{ name: match[1], version: match[2], offset: match.index }]
      : [])
}

function mixLockDependencies(content: string) {
  return [...content.matchAll(/^\s*["']([^"']+)["']:\s*\{:hex,\s*:[a-zA-Z_][\w!?]*,\s*["']([^"']+)["']/gmu)]
    .flatMap(match => match[1] && match[2]
      ? [{ name: match[1], version: match[2], offset: match.index }]
      : [])
}

function matchingImports(
  content: string,
  dependencies: ReadonlyMap<string, AffectedDependency>,
  config: ManagedLanguageConfiguration,
): Array<{ name: string; offset: number }> {
  const output: Array<{ name: string; offset: number }> = []
  for (const dependency of dependencies.values()) {
    const roots = dependency.importNames.length > 0 ? dependency.importNames : defaultImportNames(dependency.name, config)
    for (const root of roots) {
      const patterns = importPatterns(root, config.language)
      for (const expression of patterns) {
        for (const match of content.matchAll(expression)) output.push({ name: dependency.name, offset: match.index })
      }
    }
  }
  return output
}

function importPatterns(root: string, language: ManagedLanguageConfiguration['language']): RegExp[] {
  const escaped = escapeRegex(root)
  if (language === 'java' || language === 'kotlin' || language === 'scala') return [new RegExp(`(?:^|\\n)\\s*import\\s+${escaped}(?:\\.|\\b)`, 'gu')]
  if (language === 'csharp') return [new RegExp(`(?:^|\\n)\\s*(?:global\\s+)?using\\s+${escaped}(?:\\.|\\s*;)`, 'gu')]
  if (language === 'php') return [new RegExp(`\\b(?:use|require(?:_once)?|include(?:_once)?)\\s+[^;\\n]*${escaped}`, 'giu')]
  if (language === 'ruby') return [new RegExp(`(?:^|\\n)\\s*require(?:_relative)?\\s*\\(?["']${escaped}(?:/[^"']*)?["']`, 'gu')]
  if (language === 'swift') return [new RegExp(`(?:^|\\n)\\s*import\\s+${escaped}\\b`, 'gu')]
  if (language === 'dart') return [new RegExp(`(?:^|\\n)\\s*(?:import|export)\\s+["']package:${escaped}(?:/[^"']*)?["']`, 'gu')]
  if (language === 'elixir') return [
    new RegExp(`(?:^|\\n)\\s*(?:alias|import|require|use)\\s+${escaped}(?:\\.|\\b)`, 'gu'),
    new RegExp(`\\b${escaped}(?:\\.|\\b)`, 'gu'),
  ]
  if (language === 'clojure') return [
    new RegExp(`(?:\\[|['\x60])${escaped}(?=[\\s\\]:])`, 'gu'),
    new RegExp(`\\b${escaped}\\/[-!?+*A-Za-z0-9_]+`, 'gu'),
  ]
  return [new RegExp(`(?:^|\\n)\\s*import\\s+["']package:${escaped}(?:/[^"']*)?["']`, 'gu')]
}

function defaultImportNames(name: string, config: ManagedLanguageConfiguration): string[] {
  if (config.ecosystem === 'maven') return [name.split(':').at(-1)!.replaceAll('-', '.')]
  if (config.ecosystem === 'nuget') return [name]
  if (config.ecosystem === 'composer') return [name.split('/').at(-1)!]
  if (config.ecosystem === 'swiftpm') return [name]
  if (config.ecosystem === 'hex') return [name.split('_').map(part => part[0]?.toUpperCase() + part.slice(1)).join('')]
  return [name.replaceAll('-', '_')]
}

function normalizedName(name: string, ecosystem: ManagedLanguageConfiguration['ecosystem']): string {
  if (ecosystem === 'nuget' || ecosystem === 'hex') return name.toLowerCase()
  if (ecosystem === 'maven') return name.replace('/', ':')
  return name
}

function versionMayBeAffected(declared: string, affected: string): boolean {
  const exactDeclared = declared.match(/\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?/u)?.[0]
  const exactAffected = affected.match(/\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?/u)?.[0]
  if (!exactDeclared || !exactAffected) return true
  return exactDeclared.split('.')[0] === exactAffected.split('.')[0]
}

function swiftPackageName(url: string): string {
  return url.split('/').at(-1)!.replace(/\.git$/u, '')
}

function location(root: string, path: string, content: string, offset = 0) {
  const lines = content.slice(0, Math.max(0, offset)).split(/\r?\n/u)
  return {
    path: relative(root, path).replaceAll('\\', '/'),
    line: lines.length,
    column: (lines.at(-1)?.length ?? 0) + 1,
  }
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

function result(
  input: Pick<AnalyzeManagedRepositoryInput, 'baseSha' | 'changeEvent'>,
  outcome: RepositoryImpact['outcome'],
  evidence: ImpactEvidence[],
  reasons: string[],
): RepositoryImpact {
  return { schemaVersion: '1.0', changeEventId: input.changeEvent.id, baseSha: input.baseSha, outcome, evidence, reasons }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}

function legacySymbolExpression(symbol: string): RegExp {
  const leadingBoundary = /^[\p{L}\p{N}_]/u.test(symbol) ? '\\b' : ''
  const trailingBoundary = /[\p{L}\p{N}_]$/u.test(symbol) ? '\\b' : ''
  return new RegExp(`${leadingBoundary}${escapeRegex(symbol)}${trailingBoundary}`, 'gu')
}
