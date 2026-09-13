import { createReadStream } from 'node:fs'
import { readFile, readdir, stat } from 'node:fs/promises'
import { dirname, relative, resolve, sep } from 'node:path'
import type {
  ActionableChangeEvent,
  ImpactEvidence,
  RepositoryImpact,
} from '@automated-api/contracts'
import {
  Node,
  Project,
  SyntaxKind,
  type CallExpression,
  type ClassDeclaration,
  type GetAccessorDeclaration,
  type NewExpression,
  type SourceFile,
} from 'ts-morph'
import {
  declaredMajor,
  inspectReviewedRecipeSource,
  matchesLegacyPackageVersion,
  reviewedRecipeForEvent,
  type ReviewedProviderRecipe,
} from './provider-recipes.js'
import { analyzePythonRepository } from './python-impact.js'
import { analyzeGoRepository, analyzeRustRepository } from './native-impact.js'
import { analyzeManagedRepository } from './managed-impact.js'
import { analyzeCRepository, analyzeCppRepository } from './cpp-impact.js'
import {
  FIRECRAWL_DETERMINISTIC_METHOD_MIGRATIONS,
  FIRECRAWL_V1_V2_RECIPE_ID,
} from './recipe.js'
import { intersects, validRange } from 'semver'

const LEGACY_PACKAGE = '@mendable/firecrawl-js'

const METHOD_MIGRATIONS = new Map<string, string>([
  ['scrapeUrl', 'scrape'],
  ['crawlUrl', 'crawl'],
  ['mapUrl', 'map'],
  ['asyncCrawlUrl', 'startCrawl'],
  ['checkCrawlStatus', 'getCrawlStatus'],
  ['checkCrawlErrors', 'getCrawlErrors'],
  ['batchScrapeUrls', 'batchScrape'],
  ['asyncBatchScrapeUrls', 'startBatchScrape'],
  ['checkBatchScrapeStatus', 'getBatchScrapeStatus'],
  ['checkBatchScrapeErrors', 'getBatchScrapeErrors'],
  ['asyncExtract', 'startExtract'],
  ['crawlUrlAndWatch', 'watcher'],
  ['batchScrapeUrlsAndWatch', 'watcher'],
])

const MANUAL_METHOD_MIGRATIONS = new Set([
  'crawlUrlAndWatch',
  'batchScrapeUrlsAndWatch',
])

const RAW_ENDPOINT = /https:\/\/api\.firecrawl\.dev\/v1\/(scrape|crawl)(?:[/?#]|$)/u

/**
 * `@mendable/firecrawl-js` is an alias of `firecrawl`, not a v1-only package:
 * both are published in lockstep and both ship v2 from 4.x onward. Presence of
 * the scoped name therefore proves nothing on its own — only a range that can
 * still resolve below 4.0.0 indicates actual v1 usage. Without this check every
 * already-migrated repository on the scoped name draws a false-positive PR.
 */
const FIRST_V2_MAJOR = 4
const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx'])
const MAX_RELEVANT_SOURCE_FILES = 500
const MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
const SKIPPED_SOURCE_DIRECTORIES = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo', '.cache',
  'vendor', 'public', 'static', 'storybook-static',
])

export function rangeCanResolveToV1(range: string): boolean {
  const majors = [...range.matchAll(/(\d+)\s*\.\s*\d+/gu)].map(match => Number(match[1]))
  if (majors.length === 0) return true // unparseable (git url, "latest", "*") — treat as unknown
  return majors.some(major => major < FIRST_V2_MAJOR)
}

export interface AnalyzeRepositoryInput {
  rootDir: string
  runtimeRootDir?: string
  baseSha: string
  changeEvent: ActionableChangeEvent
}

/**
 * Routes the fixture-proven Firecrawl migration to its precise analyzer and
 * gives every other provider a conservative package/import impact check.
 * Generic matches are always manual until a provider-specific recipe exists.
 */
export async function analyzeRepository(
  input: AnalyzeRepositoryInput,
): Promise<RepositoryImpact> {
  const languages = new Set(input.changeEvent.affectedLanguages)
  const hasExplicitLanguages = languages.size > 0
  const hasNpmDependency = input.changeEvent.affectedDependencies.some(
    dependency => dependency.ecosystem === 'npm',
  )
  const hasPypiDependency = input.changeEvent.affectedDependencies.some(
    dependency => dependency.ecosystem === 'pypi',
  )
  const hasCargoDependency = input.changeEvent.affectedDependencies.some(
    dependency => dependency.ecosystem === 'cargo',
  )
  const hasGoDependency = input.changeEvent.affectedDependencies.some(
    dependency => dependency.ecosystem === 'gomod',
  )
  const managedEcosystems = new Set(input.changeEvent.affectedDependencies.map(({ ecosystem }) => ecosystem))
  const hasVcpkgDependency = input.changeEvent.affectedDependencies.some(
    dependency => dependency.ecosystem === 'vcpkg',
  )
  // `affectedPackages` is the pre-ecosystem ActionableChangeEvent field and therefore
  // means npm for backwards compatibility. A Node SDK event must not become
  // blocked merely because the customer repository also contains Python.
  const hasLegacyNpmPackage = input.changeEvent.affectedPackages.length > 0
  const hasAnyDependency = hasNpmDependency || hasPypiDependency
    || hasCargoDependency || hasGoDependency || hasLegacyNpmPackage
    || hasVcpkgDependency
    || ['maven', 'nuget', 'composer', 'gem', 'swiftpm', 'pub', 'hex'].some(item => managedEcosystems.has(item as never))
  const hasKnownNodeRecipe = input.changeEvent.recipeIds.includes(FIRECRAWL_V1_V2_RECIPE_ID)
    || reviewedRecipeForEvent(input.changeEvent) !== undefined
  const analyzeNode = hasExplicitLanguages
    ? languages.has('javascript') || languages.has('typescript')
    : hasNpmDependency || hasLegacyNpmPackage || hasKnownNodeRecipe || !hasAnyDependency
      || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
  const analyzePython = hasExplicitLanguages
    ? languages.has('python')
    : hasPypiDependency || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
  const analyzeRust = hasExplicitLanguages
    ? languages.has('rust')
    : hasCargoDependency || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
  const analyzeGo = hasExplicitLanguages
    ? languages.has('go')
    : hasGoDependency || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
  const analyzeCpp = hasExplicitLanguages
    ? languages.has('cpp')
    : hasVcpkgDependency || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
  const analyzeC = hasExplicitLanguages
    ? languages.has('c')
    : false
  const managedLanguages = [
    ['java', 'maven'], ['kotlin', 'maven'], ['scala', 'maven'], ['csharp', 'nuget'], ['php', 'composer'],
    ['ruby', 'gem'], ['swift', 'swiftpm'], ['dart', 'pub'], ['elixir', 'hex'],
    ['clojure', 'maven'],
  ] as const
  const [node, python, rust, go, c, cpp, ...managed] = await Promise.all([
    analyzeNode
      ? analyzeNodeRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target JavaScript or TypeScript',
      ])),
    analyzePython
      ? analyzePythonRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target Python',
      ])),
    analyzeRust
      ? analyzeRustRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target Rust',
      ])),
    analyzeGo
      ? analyzeGoRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target Go',
      ])),
    analyzeC
      ? analyzeCRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target C',
      ])),
    analyzeCpp
      ? analyzeCppRepository(input)
      : Promise.resolve(impact(input, 'not_affected', [], [
        'event metadata does not target C++',
      ])),
    ...managedLanguages.map(([language, ecosystem]) => {
      const selected = hasExplicitLanguages
        ? languages.has(language)
        : managedEcosystems.has(ecosystem) || (!hasAnyDependency && input.changeEvent.affectedApiHosts.length > 0)
      return selected
        ? analyzeManagedRepository(input, language)
        : Promise.resolve(impact(input, 'not_affected', [], [
          `event metadata does not target ${language}`,
        ]))
    }),
  ])
  return mergeLanguageImpacts(input, [
    ['JavaScript/TypeScript', node], ['Python', python], ['Rust', rust], ['Go', go], ['C', c], ['C++', cpp],
    ...managedLanguages.map(([language], index) => [language, managed[index]!] as [string, RepositoryImpact]),
  ])
}

async function analyzeNodeRepository(
  input: AnalyzeRepositoryInput,
): Promise<RepositoryImpact> {
  if (input.changeEvent.provider.toLowerCase() === 'firecrawl'
    && input.changeEvent.recipeIds.includes(FIRECRAWL_V1_V2_RECIPE_ID)) {
    return analyzeFirecrawlRepository(input)
  }
  const recipe = reviewedRecipeForEvent(input.changeEvent)
  if (recipe !== undefined) return analyzeReviewedProviderRecipe(input, recipe)
  return analyzeGenericPackageImpact(input)
}

function mergeLanguageImpacts(
  input: AnalyzeRepositoryInput,
  results: Array<[string, RepositoryImpact]>,
): RepositoryImpact {
  const evidence = deduplicateEvidence(results.flatMap(([, result]) => result.evidence))
  const outcomes = results.map(([, result]) => result.outcome)
  const outcome: RepositoryImpact['outcome'] = outcomes.includes('affected_manual')
    ? 'affected_manual'
    : outcomes.includes('affected_draftable')
      ? 'affected_draftable'
      : outcomes.every(item => item === 'blocked' || item === 'not_affected')
        && outcomes.includes('blocked')
        ? 'blocked'
        : 'not_affected'
  return impact(
    input,
    outcome,
    evidence,
    results.flatMap(([language, result]) => result.reasons.map(reason => `${language}: ${reason}`)),
  )
}

interface PackageManifest {
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  engines?: { node?: string }
}

async function analyzeReviewedProviderRecipe(
  input: AnalyzeRepositoryInput,
  recipe: ReviewedProviderRecipe,
): Promise<RepositoryImpact> {
  const rootDir = resolve(input.rootDir)
  const manifest = await readManifest(rootDir)
  const runtimeManifest = input.runtimeRootDir === undefined
    ? manifest
    : await readManifest(resolve(input.runtimeRootDir))
  const evidence: ImpactEvidence[] = []
  for (const rule of recipe.packages) {
    const version = dependencyVersion(manifest, rule.from)
    if (version === undefined || !matchesLegacyPackageVersion(version, rule)) continue
    evidence.push({
      kind: 'dependency',
      operation: 'package_migration',
      detail: `${rule.from}@${version} requires ${rule.to}@${rule.targetVersion}`,
      deterministicRecipeSupported: true,
    })
  }

  const sourceSelection = await selectRelevantSourceFiles(rootDir, [
    ...recipe.packages.flatMap(rule => [rule.from, rule.to]),
    ...Object.keys(recipe.addedPackages ?? {}),
    ...(recipe.addedPackageAnchors ?? []),
    ...input.changeEvent.operations.flatMap(operation => [
      ...(operation.oldSymbol === undefined ? [] : [operation.oldSymbol]),
      ...(operation.newSymbol === undefined ? [] : [operation.newSymbol]),
    ]),
  ])
  if (sourceSelection.truncated) evidence.push(truncatedSourceEvidence())
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: { allowJs: true, checkJs: false, skipLibCheck: true },
  })
  project.addSourceFilesAtPaths(sourceSelection.paths)
  const sourceFiles = project.getSourceFiles()
  for (const sourceFile of sourceFiles) {
    for (const usage of inspectReviewedRecipeSource(sourceFile, recipe)) {
      evidence.push({
        kind: usage.supported ? 'sdk_call' : 'dynamic_usage',
        operation: usage.operation,
        location: locationFor(sourceFile, usage.position, rootDir, usage.operation),
        detail: usage.detail,
        deterministicRecipeSupported: usage.supported,
      })
    }
  }
  if (evidence.some(item => item.location !== undefined && !item.deterministicRecipeSupported)) {
    const packages = new Set(recipe.packages.flatMap(rule => [rule.from, rule.to]))
    for (const sourceFile of sourceFiles) {
      inspectGenericOldSymbols(sourceFile, rootDir, packages, input.changeEvent, evidence)
    }
  }

  if (evidence.length === 0) {
    return impact(input, 'not_affected', [], [`no usage matched reviewed recipe ${recipe.id}`])
  }
  if (recipe.minimumNodeMajor !== undefined && !supportsNodeMajor(runtimeManifest, recipe.minimumNodeMajor)) {
    evidence.push({
      kind: 'dynamic_usage',
      operation: 'runtime_requirement',
      detail: `recipe ${recipe.id} requires package.json engines.node >=${recipe.minimumNodeMajor}`,
      deterministicRecipeSupported: false,
    })
  }
  const uniqueEvidence = deduplicateEvidence(evidence)
  const unsupported = uniqueEvidence.some(item => !item.deterministicRecipeSupported)
  return impact(
    input,
    unsupported ? 'affected_manual' : 'affected_draftable',
    uniqueEvidence,
    unsupported
      ? [`recipe ${recipe.id} found usage outside its reviewed safe subset`]
      : [`all affected usage is covered by reviewed recipe ${recipe.id}`],
  )
}

export async function analyzeFirecrawlRepository(
  input: AnalyzeRepositoryInput,
): Promise<RepositoryImpact> {
  const rootDir = resolve(input.rootDir)
  if (input.changeEvent.provider.toLowerCase() !== 'firecrawl') {
    return impact(input, 'blocked', [], ['unsupported provider for the Firecrawl MVP analyzer'])
  }

  const evidence: ImpactEvidence[] = []
  const manifest = await readManifest(rootDir)
  const legacyVersion = dependencyVersion(manifest, LEGACY_PACKAGE)
  // The scoped name only implies v1 when its declared range can still resolve
  // below 4.0.0. A manifest pinning it at ^4.x is already on v2 under an alias,
  // so neither the dependency nor its imports are evidence of v1 usage.
  const scopedNameImpliesV1 = legacyVersion === undefined || rangeCanResolveToV1(legacyVersion)
  if (legacyVersion !== undefined && scopedNameImpliesV1) {
    evidence.push({
      kind: 'dependency',
      operation: 'package_migration',
      detail: `${LEGACY_PACKAGE}@${legacyVersion} requires migration to ${LEGACY_PACKAGE}@4.34.0`,
      deterministicRecipeSupported: true,
    })
  }

  const sourceSelection = await selectRelevantSourceFiles(rootDir, [
    LEGACY_PACKAGE,
    ...METHOD_MIGRATIONS.keys(),
    'api.firecrawl.dev/v1',
  ])
  if (sourceSelection.truncated) evidence.push(truncatedSourceEvidence())
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      skipLibCheck: true,
    },
  })
  project.addSourceFilesAtPaths(sourceSelection.paths)

  // Build the client context across the whole project before inspecting calls.
  // A per-file context misses the common layout where one module constructs and
  // exports the client and another module calls methods on it — the
  // wrapped/internal client scenario docs/mvp_plan.md requires us to detect.
  const context = projectClientContext(project.getSourceFiles())

  for (const sourceFile of project.getSourceFiles()) {
    if (scopedNameImpliesV1) inspectImports(sourceFile, rootDir, evidence)
    inspectCalls(sourceFile, rootDir, evidence, context)
    inspectReflectiveLegacySymbols(sourceFile, rootDir, evidence, input.changeEvent)
    if (legacyVersion !== undefined && scopedNameImpliesV1) {
      inspectUnlocatedLegacySymbols(sourceFile, rootDir, evidence, input.changeEvent, context)
    }
    inspectRawEndpoints(sourceFile, rootDir, evidence)
  }

  const uniqueEvidence = deduplicateEvidence(evidence)
  const hasManual = uniqueEvidence.some(item => !item.deterministicRecipeSupported)
  const hasAffected = uniqueEvidence.length > 0
  const outcome = hasManual
    ? 'affected_manual'
    : hasAffected
      ? 'affected_draftable'
      : 'not_affected'

  const reasons = outcome === 'not_affected'
    ? ['no Firecrawl v1 dependency, method call, or raw v1 endpoint was found']
    : outcome === 'affected_manual'
      ? ['affected usage was found, but at least one dynamic or ambiguous call requires review']
      : ['all detected Firecrawl v1 usages are covered by the deterministic MVP recipe']

  return impact(input, outcome, uniqueEvidence, reasons)
}

async function analyzeGenericPackageImpact(
  input: AnalyzeRepositoryInput,
): Promise<RepositoryImpact> {
  const includeSdk = input.changeEvent.impactScope !== 'api'
  const includeApi = input.changeEvent.impactScope !== 'sdk'
  const dependencyTargets = new Map((includeSdk ? input.changeEvent.affectedDependencies : [])
    .filter(({ ecosystem }) => ecosystem === 'npm')
    .map(dependency => [dependency.name, dependency]))
  const packages = [...new Set([
    ...(includeSdk ? input.changeEvent.affectedPackages : []),
    ...dependencyTargets.keys(),
  ])]
  const apiHosts = includeApi
    ? [...new Set(input.changeEvent.affectedApiHosts.map(host => host.toLowerCase()))]
    : []
  if (packages.length === 0 && apiHosts.length === 0) {
    return impact(input, 'blocked', [], [
      'change event has no affected package or API host metadata for generic impact analysis',
    ])
  }

  const rootDir = resolve(input.rootDir)
  const manifests = await readManifests(rootDir)
  const evidence: ImpactEvidence[] = []
  const activePackages = new Set<string>()
  for (const packageName of packages) {
    const declarations = manifests.flatMap(({ manifest, path: manifestPath }) => {
      const version = dependencyVersion(manifest, packageName)
      return version === undefined ? [] : [{ version, manifestPath }]
    })
    const targetRange = dependencyTargets.get(packageName)?.oldVersionRange
    if (declarations.length > 0 && declarations.every(({ version }) => targetRange !== undefined
      ? !npmRangesMayIntersect(version, targetRange)
      : !declaredVersionCanMatchChange(version, input.changeEvent.oldVersion))) continue
    activePackages.add(packageName)
    for (const { version, manifestPath } of declarations) {
      evidence.push({
        kind: 'dependency',
        operation: 'package_usage',
        detail: `${packageName}@${version} is affected by ${input.changeEvent.id}`,
        deterministicRecipeSupported: false,
        ...(dirname(manifestPath) === '.' ? {} : { workspace: dirname(manifestPath) }),
      })
    }
  }

  const sourceSelection = await selectRelevantSourceFiles(rootDir, [
    ...packages.flatMap(genericPackageNeedles),
    ...apiHosts.flatMap(host => host.split('*').filter(part => part.length >= 4)),
  ])
  if (sourceSelection.truncated) evidence.push(truncatedSourceEvidence())
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: { allowJs: true, checkJs: false, skipLibCheck: true },
  })
  project.addSourceFilesAtPaths(sourceSelection.paths)

  const packageSet = activePackages
  for (const sourceFile of project.getSourceFiles()) {
    for (const declaration of sourceFile.getImportDeclarations()) {
      const packageName = matchingPackage(
        declaration.getModuleSpecifierValue(),
        packageSet,
      )
      if (packageName === undefined) continue
      evidence.push({
        kind: 'sdk_import',
        operation: 'package_usage',
        location: syntaxLocationFor(declaration, rootDir),
        detail: `import from affected package ${JSON.stringify(packageName)}`,
        deterministicRecipeSupported: false,
      })
      inspectAffectedImportCalls(declaration, sourceFile, rootDir, packageName, evidence)
    }

    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (call.getExpression().getText() !== 'require') continue
      const firstArgument = call.getArguments()[0]
      if (!Node.isStringLiteral(firstArgument)) continue
      const packageName = matchingPackage(firstArgument.getLiteralText(), packageSet)
      if (packageName === undefined) continue
      evidence.push({
        kind: 'sdk_import',
        operation: 'package_usage',
        location: syntaxLocationFor(call, rootDir),
        detail: `require of affected package ${JSON.stringify(packageName)}`,
        deterministicRecipeSupported: false,
      })
    }
    inspectGenericOldSymbols(sourceFile, rootDir, packageSet, input.changeEvent, evidence)

    for (const literal of endpointBearingLiterals(sourceFile)) {
      const host = affectedHostInLiteral(literal.text, apiHosts)
      if (host === undefined) continue
      evidence.push({
        kind: 'raw_rest_endpoint',
        operation: 'api_host_usage',
        location: locationFor(sourceFile, literal.start, rootDir),
        detail: `request URL uses affected API host ${JSON.stringify(host)}`,
        deterministicRecipeSupported: false,
      })
    }
  }

  const uniqueEvidence = deduplicateEvidence(evidence)
  if (uniqueEvidence.length === 0) {
    return impact(input, 'not_affected', [], [
      `no dependency, import, or API URL matched ${[...packages, ...apiHosts].join(', ')}`,
    ])
  }
  return impact(input, 'affected_manual', uniqueEvidence, [
    'affected package or API usage was found, but no reviewed deterministic recipe exists for this provider',
  ])
}

/** Unknown git/file/workspace aliases fail conservatively to "may intersect". */
export function npmRangesMayIntersect(declared: string, affected: string): boolean {
  const declaredRange = validRange(declared, { loose: true, includePrerelease: true })
  const affectedRange = validRange(affected, { loose: true, includePrerelease: true })
  if (declaredRange === null || affectedRange === null) return true
  return intersects(declaredRange, affectedRange, { loose: true, includePrerelease: true })
}

function affectedHostInLiteral(
  text: string,
  patterns: readonly string[],
): string | undefined {
  for (const match of text.matchAll(/https?:\/\/([a-z0-9.-]+)/giu)) {
    const host = match[1]?.toLowerCase()
    if (host !== undefined && patterns.some(pattern => hostMatchesPattern(host, pattern))) {
      return host
    }
  }
  return undefined
}

function hostMatchesPattern(host: string, pattern: string): boolean {
  if (!pattern.includes('*')) return host === pattern
  if (pattern.startsWith('*.')) {
    const suffixLabels = pattern.split('.').slice(1)
    const hostLabels = host.split('.')
    const offset = hostLabels.length - suffixLabels.length
    if (offset < 1) return false
    return suffixLabels.every((label, index) => hostLabelMatches(hostLabels[offset + index]!, label))
  }
  const labels = pattern.split('.')
  const hostLabels = host.split('.')
  if (labels.length !== hostLabels.length) return false
  return labels.every((label, index) => hostLabelMatches(hostLabels[index]!, label))
}

function inspectGenericOldSymbols(
  sourceFile: SourceFile,
  rootDir: string,
  packageSet: ReadonlySet<string>,
  changeEvent: ActionableChangeEvent,
  evidence: ImpactEvidence[],
): void {
  const importsAffectedPackage = sourceFile.getImportDeclarations().some(declaration =>
    matchingPackage(declaration.getModuleSpecifierValue(), packageSet) !== undefined,
  )
  if (!importsAffectedPackage) return
  const oldSymbols = new Set(changeEvent.operations.flatMap(operation =>
    operation.oldSymbol === undefined ? [] : [operation.oldSymbol],
  ))
  if (oldSymbols.size === 0) return
  for (const identifier of sourceFile.getDescendantsOfKind(SyntaxKind.Identifier)) {
    const symbol = identifier.getText()
    if (!oldSymbols.has(symbol)) continue
    evidence.push({
      kind: 'dynamic_usage',
      operation: symbol,
      location: locationFor(sourceFile, identifier.getStart(), rootDir, symbol),
      detail: `affected package source contains legacy symbol ${JSON.stringify(symbol)}`,
      deterministicRecipeSupported: false,
    })
  }
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    const symbol = expression.getText()
    if (!oldSymbols.has(symbol)) continue
    evidence.push({
      kind: 'dynamic_usage',
      operation: symbol,
      location: locationFor(sourceFile, expression.getStart(), rootDir, symbol),
      detail: `affected package source contains legacy symbol ${JSON.stringify(symbol)}`,
      deterministicRecipeSupported: false,
    })
  }
}

function declaredVersionCanMatchChange(declared: string, oldVersion: string): boolean {
  const declaredPackageMajor = declaredMajor(declared)
  const changedFromMajor = declaredMajor(oldVersion)
  // Keep unknown ranges conservative. Only a clear major mismatch is enough
  // to rule a repository out and suppress its imports/calls for this event.
  return declaredPackageMajor === undefined
    || changedFromMajor === undefined
    || declaredPackageMajor === changedFromMajor
}

function inspectAffectedImportCalls(
  declaration: ReturnType<SourceFile['getImportDeclarations']>[number],
  sourceFile: SourceFile,
  rootDir: string,
  packageName: string,
  evidence: ImpactEvidence[],
): void {
  const bindings = [
    declaration.getDefaultImport(),
    declaration.getNamespaceImport(),
    ...declaration.getNamedImports().map(named => named.getAliasNode() ?? named.getNameNode()),
  ].filter(Node.isIdentifier)

  const pending: Node[] = bindings.flatMap(binding => binding.findReferencesAsNodes())
  const visited = new Set<Node>()
  const enqueueReferences = (name: Node | undefined) => {
    if (Node.isIdentifier(name)) pending.push(...name.findReferencesAsNodes())
  }
  for (let index = 0; index < pending.length; index += 1) {
    const reference = pending[index]!
    if (visited.has(reference) || reference.getSourceFile().isDeclarationFile()) continue
    visited.add(reference)
    if (reference.getFirstAncestorByKind(SyntaxKind.ImportDeclaration) !== undefined) continue
    const usage = sdkReferenceSyntax(reference)
    if (Node.isCallExpression(usage) || Node.isNewExpression(usage)) {
      addGenericSdkCallEvidence(rootDir, packageName, usage, evidence)
      // A returned client can be used immediately: getClient().scrape(...).
      if (usage !== reference) pending.push(usage)
    } else {
      evidence.push({
        kind: 'dynamic_usage',
        operation: reference.getText(),
        location: syntaxLocationFor(usage, rootDir),
        detail: `reference bound to affected package ${JSON.stringify(packageName)}`,
        deterministicRecipeSupported: false,
      })
    }
    enqueueReferences(assignedVariableDeclaration(usage)?.getNameNode())

    // Follow explicit SDK type annotations, not names or inferred any types.
    const owner = usage.getParent()
    if (Node.isTypeReference(usage) && (
      Node.isPropertySignature(owner) || Node.isPropertyDeclaration(owner)
      || Node.isParameterDeclaration(owner) || Node.isVariableDeclaration(owner)
    ) && owner.getTypeNode() === usage) enqueueReferences(owner.getNameNode())

    const returned = valueWrapper(usage).getParent()
    if (Node.isReturnStatement(returned)) {
      const callable = returned.getFirstAncestor(node =>
        Node.isFunctionDeclaration(node) || Node.isFunctionExpression(node)
        || Node.isArrowFunction(node) || Node.isMethodDeclaration(node)
        || Node.isGetAccessorDeclaration(node))
      if (Node.isFunctionDeclaration(callable) || Node.isMethodDeclaration(callable)) {
        enqueueReferences(callable.getNameNode())
      } else if (Node.isFunctionExpression(callable) || Node.isArrowFunction(callable)) {
        enqueueReferences(assignedVariableDeclaration(callable)?.getNameNode())
      } else if (Node.isGetAccessorDeclaration(callable)) {
        pending.push(...unambiguousSdkGetterReferences(callable, returned))
      }
    }
  }
}

function unambiguousSdkGetterReferences(getter: GetAccessorDeclaration, returned: Node): Node[] {
  const owner = getter.getParent()
  const name = getter.getNameNode()
  const body = getter.getBody()
  const statements = Node.isBlock(body) ? body.getStatements() : undefined
  // Only a direct, unconditional SDK return proves the getter's value. Mixed
  // returns, nested callbacks, setters and inherited members remain manual.
  if (!Node.isClassDeclaration(owner) || owner.getExtends() !== undefined || owner.getDerivedClasses().length > 0
    || !Node.isIdentifier(name)
    || getter.getSetAccessor() !== undefined || statements?.length !== 1 || statements[0] !== returned) return []
  if (owner.getConstructors().some(constructor => constructor.getDescendantsOfKind(SyntaxKind.ReturnStatement)
    .some(statement => statement.getExpression() !== undefined && statement.getFirstAncestor(node =>
      Node.isConstructorDeclaration(node) || Node.isFunctionDeclaration(node) || Node.isFunctionExpression(node)
      || Node.isArrowFunction(node) || Node.isMethodDeclaration(node)) === constructor))) return []
  const references = name.findReferencesAsNodes()
  if (references.some(isAssignedReference)) return []
  return references.filter(reference => {
    if (!reference.getSymbol()?.getDeclarations().includes(getter)) return false
    const access = reference.getParent()
    if (!Node.isPropertyAccessExpression(access) || access.getNameNode() !== reference) return false
    const receiver = access.getExpression()
    // Exact class identity is required, not a same-named or structurally
    // compatible getter on another class, a subclass, an interface or any.
    const type = receiver.getType()
    if (type.isUnion() || type.isIntersection() || !type.getSymbol()?.getDeclarations().includes(owner)) return false
    return isConstructedGetterReceiver(receiver, owner, new Set())
  })
}

function isConstructedGetterReceiver(receiver: Node, owner: ClassDeclaration, seen: Set<Node>): boolean {
  if (seen.has(receiver) || seen.size >= 100) return false
  seen.add(receiver)
  if (Node.isThisExpression(receiver)) {
    return receiver.getFirstAncestor(node => Node.isClassDeclaration(node) || Node.isClassExpression(node)
      || Node.isFunctionDeclaration(node) || Node.isFunctionExpression(node)) === owner
  }
  if (Node.isNewExpression(receiver)) {
    let symbol = receiver.getExpression().getSymbol()
    if (symbol?.isAlias()) symbol = symbol.getAliasedSymbol()
    return symbol?.getDeclarations().includes(owner) === true
  }
  if (Node.isParenthesizedExpression(receiver)) return isConstructedGetterReceiver(receiver.getExpression(), owner, seen)
  // TypeScript is structural: a declared class type, a type assertion, a
  // constructor parameter or an implementing class is not instance provenance.
  if (!Node.isIdentifier(receiver) || receiver.findReferencesAsNodes().some(isAssignedReference)) return false
  const declarations = receiver.getSymbol()?.getDeclarations()
  if (declarations?.length !== 1 || !Node.isVariableDeclaration(declarations[0])) return false
  const initializer = declarations[0].getInitializer()
  return initializer !== undefined && isConstructedGetterReceiver(initializer, owner, seen)
}

function isAssignedReference(reference: Node): boolean {
  const access = reference.getParent()
  const expression = Node.isPropertyAccessExpression(access) && access.getNameNode() === reference ? access : reference
  const assignment = expression.getFirstAncestor(node => Node.isBinaryExpression(node)
    && node.getOperatorToken().getKind() >= SyntaxKind.FirstAssignment
    && node.getOperatorToken().getKind() <= SyntaxKind.LastAssignment
    && node.getLeft().getStart() <= expression.getStart() && node.getLeft().getEnd() >= expression.getEnd())
  if (assignment !== undefined) return true
  const parent = expression.getParent()
  if (Node.isPrefixUnaryExpression(parent) || Node.isPostfixUnaryExpression(parent)) {
    return parent.getOperatorToken() === SyntaxKind.PlusPlusToken || parent.getOperatorToken() === SyntaxKind.MinusMinusToken
  }
  return (Node.isForOfStatement(parent) || Node.isForInStatement(parent)) && parent.getInitializer() === expression
}

function sdkReferenceSyntax(reference: Node): Node {
  const parent = reference.getParent()
  if (Node.isTypeReference(parent)) return parent
  let expression = Node.isPropertyAccessExpression(parent) && parent.getNameNode() === reference
    ? parent : reference
  const invocation = invocationUsingReference(expression)
  if (invocation !== undefined) return invocation
  while (true) {
    const next = expression.getParent()
    if ((Node.isPropertyAccessExpression(next) || Node.isElementAccessExpression(next))
      && next.getExpression() === expression) expression = next
    else return expression
  }
}

function invocationUsingReference(reference: Node): CallExpression | NewExpression | undefined {
  let expression = reference
  while (true) {
    const parent = expression.getParent()
    if (
      (Node.isPropertyAccessExpression(parent) || Node.isElementAccessExpression(parent))
      && parent.getExpression() === expression
    ) {
      expression = parent
      continue
    }
    if (
      (Node.isCallExpression(parent) || Node.isNewExpression(parent))
      && parent.getExpression() === expression
    ) return parent
    return undefined
  }
}

function valueWrapper(value: Node): Node {
  let current = value
  while (true) {
    const parent = current.getParent()
    if (
      Node.isAwaitExpression(parent)
      || Node.isParenthesizedExpression(parent)
      || Node.isAsExpression(parent)
    ) {
      current = parent
      continue
    }
    return current
  }
}

function assignedVariableDeclaration(value: Node) {
  const current = valueWrapper(value)
  const parent = current.getParent()
  return Node.isVariableDeclaration(parent) && parent.getInitializer() === current ? parent : undefined
}

function assignedSdkResultDeclaration(invocation: CallExpression | NewExpression) {
  const direct = assignedVariableDeclaration(invocation)
  if (direct !== undefined) return direct
  const wrappedInvocation = valueWrapper(invocation)
  const callback = wrappedInvocation.getParent()
  if (!Node.isArrowFunction(callback) || callback.getBody() !== wrappedInvocation) return undefined
  const wrapperCall = callback.getParent()
  if (!Node.isCallExpression(wrapperCall) || !wrapperCall.getArguments().includes(callback)) return undefined
  return assignedVariableDeclaration(wrapperCall)
}

function addGenericSdkCallEvidence(
  rootDir: string,
  packageName: string,
  invocation: CallExpression | NewExpression,
  evidence: ImpactEvidence[],
): void {
  evidence.push({
    kind: 'sdk_call',
    operation: invocation.getExpression().getText(),
    location: syntaxLocationFor(invocation, rootDir),
    detail: `call using affected package ${JSON.stringify(packageName)}`,
    deterministicRecipeSupported: false,
  })
  addInvocationResultEvidence(rootDir, packageName, invocation, evidence)
}

function addInvocationResultEvidence(
  rootDir: string,
  packageName: string,
  invocation: CallExpression | NewExpression,
  evidence: ImpactEvidence[],
): void {
  const declaration = assignedSdkResultDeclaration(invocation)
  addVariableResultEvidence(rootDir, packageName, declaration, evidence, new Set())
}

function addVariableResultEvidence(
  rootDir: string,
  packageName: string,
  declaration: ReturnType<typeof assignedVariableDeclaration>,
  evidence: ImpactEvidence[],
  visited: Set<string>,
): void {
  const variableName = declaration?.getNameNode()
  if (!Node.isIdentifier(variableName)) return
  const identity = `${variableName.getSourceFile().getFilePath()}:${variableName.getStart()}`
  if (visited.has(identity)) return
  visited.add(identity)
  for (const reference of variableName.findReferencesAsNodes()) {
    evidence.push({
      kind: 'sdk_call',
      operation: `${variableName.getText()}.result_usage`,
      location: syntaxLocationFor(sdkReferenceSyntax(reference), rootDir),
      detail: `result from affected package ${JSON.stringify(packageName)} is used here`,
      deterministicRecipeSupported: false,
    })
    addVariableResultEvidence(
      rootDir,
      packageName,
      assignedVariableDeclaration(reference),
      evidence,
      visited,
    )
  }
}

function hostLabelMatches(hostLabel: string, patternLabel: string): boolean {
  if (patternLabel === '*') return true
  if (!patternLabel.includes('*')) return hostLabel === patternLabel
  const expression = patternLabel
    .split('*')
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'))
    .join('[a-z0-9-]*')
  return new RegExp(`^${expression}$`, 'u').test(hostLabel)
}

function matchingPackage(
  moduleSpecifier: string,
  packages: ReadonlySet<string>,
): string | undefined {
  return [...packages].find(
    (packageName) =>
      moduleSpecifier === packageName || moduleSpecifier.startsWith(`${packageName}/`),
  )
}

function inspectImports(
  sourceFile: SourceFile,
  rootDir: string,
  evidence: ImpactEvidence[],
): void {
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== LEGACY_PACKAGE) continue
    evidence.push({
      kind: 'sdk_import',
      operation: 'package_migration',
      location: locationFor(sourceFile, declaration.getStart(), rootDir),
      detail: `legacy Firecrawl SDK import ${JSON.stringify(LEGACY_PACKAGE)}`,
      deterministicRecipeSupported: true,
    })
    const namespaceImport = declaration.getNamespaceImport()
    if (namespaceImport !== undefined) {
      evidence.push({
        kind: 'dynamic_usage',
        operation: 'namespace_import',
        location: locationFor(sourceFile, namespaceImport.getStart(), rootDir),
        detail: 'legacy Firecrawl namespace import is outside the verified deterministic recipe',
        deterministicRecipeSupported: false,
      })
    }
    for (const namedImport of declaration.getNamedImports()) {
      if (namedImport.getName() === 'FirecrawlApp') continue
      evidence.push({
        kind: 'dynamic_usage',
        operation: namedImport.getName(),
        location: locationFor(sourceFile, namedImport.getStart(), rootDir, namedImport.getName()),
        detail: `legacy Firecrawl named import ${JSON.stringify(namedImport.getName())} requires v2 surface review`,
        deterministicRecipeSupported: false,
      })
    }
  }

  for (const declaration of sourceFile.getVariableDeclarations()) {
    const initializer = declaration.getInitializer()
    if (!Node.isCallExpression(initializer)) continue
    if (initializer.getExpression().getText() !== 'require') continue
    const firstArgument = initializer.getArguments()[0]
    if (!Node.isStringLiteral(firstArgument) || firstArgument.getLiteralText() !== LEGACY_PACKAGE) continue
    evidence.push({
      kind: 'sdk_import',
      operation: 'package_migration',
      location: locationFor(sourceFile, declaration.getStart(), rootDir, declaration.getName()),
      detail: `legacy CommonJS Firecrawl SDK import ${JSON.stringify(LEGACY_PACKAGE)}`,
      deterministicRecipeSupported: true,
    })
  }
}

function inspectCalls(
  sourceFile: SourceFile,
  rootDir: string,
  evidence: ImpactEvidence[],
  context: LegacyClientContext,
): void {
  if (context.classNames.size === 0) return

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (Node.isPropertyAccessExpression(expression)) {
      if (!isLegacyReceiver(expression.getExpression(), context)) continue
      const oldMethod = expression.getName()
      const newMethod = METHOD_MIGRATIONS.get(oldMethod)
      if (newMethod === undefined) continue
      const recipeCoversMethod = FIRECRAWL_DETERMINISTIC_METHOD_MIGRATIONS.get(oldMethod) === newMethod
      const optionsAreSafe = recipeCoversMethod && !MANUAL_METHOD_MIGRATIONS.has(oldMethod)
        && callOptionsAreDeterministic(call)
      evidence.push({
        kind: 'sdk_call',
        operation: oldMethod,
        location: locationFor(sourceFile, expression.getStart(), rootDir, oldMethod),
        detail: optionsAreSafe
          ? `${oldMethod} can be renamed to ${newMethod}`
          : recipeCoversMethod
            ? `${oldMethod} uses non-literal options that may require v2 option mapping`
            : `${oldMethod} is outside the verified deterministic Firecrawl recipe`,
        deterministicRecipeSupported: optionsAreSafe,
      })
      continue
    }

    if (Node.isElementAccessExpression(expression)) {
      if (!isLegacyReceiver(expression.getExpression(), context)) continue
      const argument = expression.getArgumentExpression()
      if (argument === undefined || !Node.isStringLiteral(argument)) {
        evidence.push({
          kind: 'dynamic_usage',
          operation: 'dynamic_sdk_method',
          location: locationFor(sourceFile, expression.getStart(), rootDir),
          detail: 'dynamic Firecrawl SDK method selection cannot be migrated safely',
          deterministicRecipeSupported: false,
        })
      }
    }
  }
}

function inspectReflectiveLegacySymbols(
  sourceFile: SourceFile,
  rootDir: string,
  evidence: ImpactEvidence[],
  changeEvent: ActionableChangeEvent,
): void {
  const oldSymbols = legacyFirecrawlSymbols(changeEvent)
  if (oldSymbols.size === 0) return
  for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
    const symbol = literal.getLiteralText()
    if (!oldSymbols.has(symbol)) continue
    evidence.push({
      kind: 'dynamic_usage',
      operation: symbol,
      location: locationFor(sourceFile, literal.getStart(), rootDir, symbol),
      detail: `legacy Firecrawl method ${JSON.stringify(symbol)} is referenced reflectively`,
      deterministicRecipeSupported: false,
    })
  }
}

function inspectUnlocatedLegacySymbols(
  sourceFile: SourceFile,
  rootDir: string,
  evidence: ImpactEvidence[],
  changeEvent: ActionableChangeEvent,
  context: LegacyClientContext,
): void {
  const oldSymbols = legacyFirecrawlSymbols(changeEvent)
  if (oldSymbols.size === 0) return
  const path = relative(rootDir, sourceFile.getFilePath()).split(sep).join('/')
  for (const identifier of sourceFile.getDescendantsOfKind(SyntaxKind.Identifier)) {
    const symbol = identifier.getText()
    if (!oldSymbols.has(symbol)) continue
    const parent = identifier.getParent()
    if (Node.isPropertyAssignment(parent)
      && parent.getNameNode() === identifier
      && Node.isObjectLiteralExpression(parent.getParent())) continue
    if (Node.isMethodDeclaration(parent)
      && parent.getNameNode() === identifier
      && Node.isObjectLiteralExpression(parent.getParent())) continue
    if (Node.isPropertyAccessExpression(parent) && parent.getNameNode() === identifier) {
      const call = parent.getParent()
      if (Node.isCallExpression(call) && call.getExpression() === parent) {
        if (isLegacyReceiver(parent.getExpression(), context)) continue
        if (isDefinitelyLocalObject(parent.getExpression(), sourceFile)) continue
      }
    }
    const location = locationFor(sourceFile, identifier.getStart(), rootDir, symbol)
    const alreadyLocated = evidence.some(item =>
      item.operation === symbol
      && item.location?.path === path
      && item.location.line === location?.line
      && item.location.column === location?.column,
    )
    if (alreadyLocated) continue
    evidence.push({
      kind: 'dynamic_usage',
      operation: symbol,
      location,
      detail: `legacy Firecrawl symbol ${JSON.stringify(symbol)} appears outside a recognized deterministic call`,
      deterministicRecipeSupported: false,
    })
  }
}

function legacyFirecrawlSymbols(changeEvent: ActionableChangeEvent): Set<string> {
  return new Set([
    ...METHOD_MIGRATIONS.keys(),
    ...changeEvent.operations.flatMap(operation =>
      operation.oldSymbol === undefined ? [] : [operation.oldSymbol]),
  ])
}

function isDefinitelyLocalObject(receiver: Node, sourceFile: SourceFile): boolean {
  if (!Node.isIdentifier(receiver)) return false
  const declarations = sourceFile.getVariableDeclarations().filter(
    declaration => declaration.getName() === receiver.getText(),
  )
  return declarations.length > 0 && declarations.every(
    declaration => Node.isObjectLiteralExpression(declaration.getInitializer()),
  )
}

interface LegacyClientContext {
  classNames: Set<string>
  receiverNames: Set<string>
}

/** Unions the per-file contexts so wrappers and call sites can live apart. */
function projectClientContext(sourceFiles: SourceFile[]): LegacyClientContext {
  const classNames = new Set<string>()
  const receiverNames = new Set<string>()
  for (const sourceFile of sourceFiles) {
    const local = legacyClientContext(sourceFile)
    for (const name of local.classNames) classNames.add(name)
    for (const name of local.receiverNames) receiverNames.add(name)
  }
  return { classNames, receiverNames }
}

function legacyClientContext(sourceFile: SourceFile): LegacyClientContext {
  const classNames = new Set<string>()
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== LEGACY_PACKAGE) continue
    const defaultImport = declaration.getDefaultImport()
    if (defaultImport !== undefined) classNames.add(defaultImport.getText())
    for (const namedImport of declaration.getNamedImports()) {
      classNames.add(namedImport.getAliasNode()?.getText() ?? namedImport.getName())
    }
  }

  for (const declaration of sourceFile.getVariableDeclarations()) {
    const initializer = declaration.getInitializer()
    if (!Node.isCallExpression(initializer) || initializer.getExpression().getText() !== 'require') continue
    const firstArgument = initializer.getArguments()[0]
    if (!Node.isStringLiteral(firstArgument) || firstArgument.getLiteralText() !== LEGACY_PACKAGE) continue
    classNames.add(declaration.getName())
  }

  const receiverNames = new Set<string>()
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    if (!classNames.has(expression.getExpression().getText())) continue
    const parent = expression.getParent()
    if (Node.isVariableDeclaration(parent) || Node.isPropertyDeclaration(parent)) {
      receiverNames.add(parent.getName())
    }
  }
  return { classNames, receiverNames }
}

function isLegacyReceiver(
  receiver: Node,
  context: LegacyClientContext,
): boolean {
  if (Node.isNewExpression(receiver)) {
    return context.classNames.has(receiver.getExpression().getText())
  }
  if (Node.isIdentifier(receiver)) return context.receiverNames.has(receiver.getText())
  if (Node.isPropertyAccessExpression(receiver)) return context.receiverNames.has(receiver.getName())
  return false
}

function inspectRawEndpoints(
  sourceFile: SourceFile,
  rootDir: string,
  evidence: ImpactEvidence[],
): void {
  // Scan template literals as well as plain strings: `${BASE}/v1/scrape` and
  // backtick-quoted URLs are ordinary style, and a StringLiteral-only scan
  // silently reports such repositories as not_affected.
  for (const literal of endpointBearingLiterals(sourceFile)) {
    const match = RAW_ENDPOINT.exec(literal.text)
    if (match === null) continue
    const operation = match[1] ?? 'unknown'
    evidence.push({
      kind: 'raw_rest_endpoint',
      operation,
      location: locationFor(sourceFile, literal.start, rootDir),
      detail: `literal v1 ${operation} endpoint can be migrated to /v2/${operation}`,
      deterministicRecipeSupported: true,
    })
  }
}

/** String, no-substitution template, and template-span text with positions. */
export function endpointBearingLiterals(
  sourceFile: SourceFile,
): Array<{ text: string; start: number }> {
  const results: Array<{ text: string; start: number }> = []
  for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
    results.push({ text: literal.getLiteralText(), start: literal.getStart() })
  }
  for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
    results.push({ text: literal.getLiteralText(), start: literal.getStart() })
  }
  for (const template of sourceFile.getDescendantsOfKind(SyntaxKind.TemplateExpression)) {
    // Each chunk is matched independently; an interpolation cannot contain the
    // path segment we key on, so per-chunk matching is sufficient here.
    results.push({ text: template.getHead().getLiteralText(), start: template.getStart() })
    for (const span of template.getTemplateSpans()) {
      results.push({ text: span.getLiteral().getLiteralText(), start: template.getStart() })
    }
  }
  return results
}

function callOptionsAreDeterministic(call: CallExpression): boolean {
  const options = call.getArguments()[1]
  if (options === undefined) return true
  if (!Node.isObjectLiteralExpression(options)) return false

  for (const property of options.getProperties()) {
    if (Node.isSpreadAssignment(property)) return false
    if (Node.isShorthandPropertyAssignment(property)) return false
    if (!Node.isPropertyAssignment(property)) continue
    const name = property.getName()
    const initializer = property.getInitializer()
    if (initializer === undefined) return false
    if (name === 'ignoreSitemap' && !Node.isTrueLiteral(initializer) && !Node.isFalseLiteral(initializer)) {
      return false
    }
    if ((name === 'allowBackwardCrawling' || name === 'parsePDF')
      && !Node.isTrueLiteral(initializer) && !Node.isFalseLiteral(initializer)) return false
    if (name === 'formats') {
      if (!Node.isArrayLiteralExpression(initializer)) return false
      if (initializer.getElements().some(element => Node.isStringLiteral(element) && element.getLiteralText() === 'extract')) {
        return false
      }
    }
  }
  return true
}

function syntaxLocationFor(node: Node, rootDir: string): ImpactEvidence['location'] {
  return {
    ...locationFor(node.getSourceFile(), node.getStart(), rootDir)!,
    endLine: node.getSourceFile().getLineAndColumnAtPos(node.getEnd()).line,
  }
}

function locationFor(
  sourceFile: SourceFile,
  position: number,
  rootDir: string,
  symbol?: string,
): ImpactEvidence['location'] {
  const lineAndColumn = sourceFile.getLineAndColumnAtPos(position)
  return {
    path: relative(rootDir, sourceFile.getFilePath()).split(sep).join('/'),
    line: lineAndColumn.line,
    column: lineAndColumn.column,
    ...(symbol === undefined ? {} : { symbol }),
  }
}

function impact(
  input: AnalyzeRepositoryInput,
  outcome: RepositoryImpact['outcome'],
  evidence: ImpactEvidence[],
  reasons: string[],
): RepositoryImpact {
  return {
    schemaVersion: '1.0',
    changeEventId: input.changeEvent.id,
    baseSha: input.baseSha,
    outcome,
    evidence,
    reasons,
  }
}

function deduplicateEvidence(evidence: ImpactEvidence[]): ImpactEvidence[] {
  const seen = new Set<string>()
  return evidence.filter((item) => {
    const key = [
      item.kind,
      item.operation,
      item.location?.path ?? '',
      item.location?.line ?? 0,
      item.location?.column ?? 0,
    ].join(':')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

interface RelevantSourceSelection {
  paths: string[]
  truncated: boolean
}

/**
 * Prefilters large repositories before ts-morph builds ASTs. Generic impact
 * analysis only inspects direct package imports and literal API hosts, so an
 * unrelated source file cannot contribute evidence. Oversized files and a
 * candidate overflow fail conservatively to manual review instead of risking
 * either an out-of-memory crash or a false not_affected result.
 */
async function selectRelevantSourceFiles(
  rootDir: string,
  rawNeedles: readonly string[],
): Promise<RelevantSourceSelection> {
  const needles = [...new Set(rawNeedles.map(value => value.trim()).filter(value => value.length > 0))]
  const paths: string[] = []
  let truncated = false

  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue
      const absolute = resolve(directory, entry.name)
      if (entry.isDirectory()) {
        if (!SKIPPED_SOURCE_DIRECTORIES.has(entry.name)) await visit(absolute)
        continue
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(extension(entry.name))) continue
      const metadata = await stat(absolute)
      if (metadata.size > MAX_SOURCE_FILE_BYTES) {
        // Oversized generated/bundled files are only relevant when they contain
        // one of the exact package/host anchors. Treating every large JS file as
        // relevant makes an unrelated repository manual for short package names
        // such as `ai`. Stream the bytes so this check stays memory-bounded.
        if (await fileContainsAnyNeedle(absolute, needles)) truncated = true
        continue
      }
      const content = await readFile(absolute, 'utf8')
      if (!needles.some(needle => content.includes(needle))) continue
      if (paths.length >= MAX_RELEVANT_SOURCE_FILES) {
        truncated = true
        continue
      }
      paths.push(absolute)
    }
  }

  await visit(rootDir)
  return { paths, truncated }
}

function genericPackageNeedles(packageName: string): string[] {
  return [
    `'${packageName}'`, `"${packageName}"`,
    `'${packageName}/`, `"${packageName}/`,
  ]
}

async function fileContainsAnyNeedle(path: string, needles: readonly string[]): Promise<boolean> {
  if (needles.length === 0) return false
  const overlap = Math.max(...needles.map(needle => needle.length)) - 1
  let carry = ''
  const stream = createReadStream(path, { encoding: 'utf8', highWaterMark: 64 * 1024 })
  for await (const chunk of stream) {
    const text = carry + chunk
    if (needles.some(needle => text.includes(needle))) {
      stream.destroy()
      return true
    }
    carry = overlap > 0 ? text.slice(-overlap) : ''
  }
  return false
}

function extension(path: string): string {
  const index = path.lastIndexOf('.')
  return index < 0 ? '' : path.slice(index).toLowerCase()
}

function truncatedSourceEvidence(): ImpactEvidence {
  return {
    kind: 'dynamic_usage',
    operation: 'repository_scan_limit',
    detail: 'relevant source exceeded the bounded AST scan; manual review is required',
    deterministicRecipeSupported: false,
  }
}

async function readManifest(rootDir: string): Promise<PackageManifest> {
  try {
    return JSON.parse(await readFile(resolve(rootDir, 'package.json'), 'utf8')) as PackageManifest
  } catch (error) {
    if (isMissingFile(error)) return {}
    throw error
  }
}

interface LocatedManifest {
  path: string
  manifest: PackageManifest
}

const SKIPPED_MANIFEST_DIRECTORIES = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo', '.cache',
])

/** Finds package manifests in nested npm/pnpm/Yarn workspaces without following symlinks. */
async function readManifests(rootDir: string): Promise<LocatedManifest[]> {
  const located: LocatedManifest[] = []
  async function visit(directory: string, relativeDirectory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        if (SKIPPED_MANIFEST_DIRECTORIES.has(entry.name)) continue
        const childRelative = relativeDirectory === '.' ? entry.name : `${relativeDirectory}/${entry.name}`
        await visit(resolve(directory, entry.name), childRelative)
        continue
      }
      if (!entry.isFile() || entry.name !== 'package.json') continue
      const manifestPath = relativeDirectory === '.' ? 'package.json' : `${relativeDirectory}/package.json`
      try {
        located.push({
          path: manifestPath,
          manifest: JSON.parse(await readFile(resolve(rootDir, manifestPath), 'utf8')) as PackageManifest,
        })
      } catch (error) {
        if (!isMissingFile(error)) throw error
      }
    }
  }
  await visit(rootDir, '.')
  return located
}

function dependencyVersion(manifest: PackageManifest, name: string): string | undefined {
  return manifest.dependencies?.[name]
    ?? manifest.devDependencies?.[name]
    ?? manifest.optionalDependencies?.[name]
    ?? manifest.peerDependencies?.[name]
}

function supportsNodeMajor(manifest: PackageManifest, minimum: number): boolean {
  const range = manifest.engines?.node
  if (range === undefined) return false
  const explicitMajors = [...range.matchAll(/(?<![\d.])(\d+)(?:\.\d+|\.x|$)/gu)]
    .map(match => Number(match[1]))
  if (explicitMajors.length === 0) return false
  // The smallest explicitly declared line is the repository's runtime floor.
  // Requiring it to meet the recipe avoids silently raising Node for customers.
  return Math.min(...explicitMajors) >= minimum
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT'
}
