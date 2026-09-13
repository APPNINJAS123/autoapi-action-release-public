import { access, lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { basename, dirname, relative, resolve } from 'node:path'
import type { CommandSpec, MigrationJob } from '@automated-api/contracts'
import { MigrationJobSchema } from '@automated-api/contracts'
import { isMap, isScalar, parseDocument } from 'yaml'
import { updatePythonProjectDependency } from './pythonDependencyManifest.js'
import { pythonUvReleaseAgePolicy } from './pythonUvPolicy.js'
import { readJvmMetadata, reviewedJvmToolchain, type ReviewedJvmContext, type ReviewedJvmToolchainReceipt } from './reviewedJvmToolchain.js'
import { migrateReviewedKotlinPom, readReviewedKotlinPom, reviewedKotlinMavenArguments } from './reviewedKotlinConsumer.js'
import {
  applyFirecrawlV1ToV2DependencyUpdate,
  applyReviewedProviderDependencyUpdate,
  assertPathAllowed,
  declaredMajor,
  FIRECRAWL_TARGET_PACKAGE_VERSION,
  FIRECRAWL_V1_V2_RECIPE_ID,
  normalizeRepositoryPath,
  resolveExistingPathInsideRepository,
  reviewedRecipeDependencies,
  parseVcpkgManifest,
} from '@automated-api/remediation'

export interface MigrationDependency {
  name: string
  version: string
}

export type SupportedPackageManager = 'npm' | 'pnpm' | 'yarn' | 'pip' | 'uv' | 'python' | 'cargo' | 'go'
  | 'maven' | 'gradle' | 'sbt' | 'dotnet' | 'composer' | 'bundler' | 'swift' | 'dart' | 'mix'
  | 'clojure' | 'leiningen' | 'vcpkg' | 'none'
export type PackageManagerVariant = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'python-pip' | 'python-uv'
  | 'python-stdlib' | 'rust-cargo' | 'go-modules' | 'jvm-maven' | 'jvm-gradle' | 'scala-sbt' | 'dotnet-nuget'
  | 'php-composer' | 'ruby-bundler' | 'swift-package' | 'dart-pub' | 'elixir-mix'
  | 'clojure-tools-deps' | 'clojure-leiningen' | 'c-vcpkg' | 'cpp-vcpkg' | 'analysis-only'

export interface PackageManagerPlan {
  name: SupportedPackageManager
  version: string
  spec: string
  variant: PackageManagerVariant
  lockfile: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock' | 'requirements.txt' | 'uv.lock' | 'Cargo.lock' | 'go.sum'
    | 'pom.xml' | 'gradle.lockfile' | 'build.sbt' | 'packages.lock.json' | 'composer.lock' | 'Gemfile.lock' | 'Package.resolved' | 'pubspec.lock' | 'mix.lock'
    | 'deps.edn' | 'project.clj' | '.'
  language?: 'python' | 'rust' | 'go' | 'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure' | 'c' | 'cpp'
  /** Exact language runtime selected by a repository-owned version file. */
  runtimeVersion?: string
  reviewedJvmToolchain?: ReviewedJvmToolchainReceipt
  scalaVersion?: string
  coursierVersion?: string
  pythonVersion?: string
  /** The repository's minor-line requirement when the Action resolved it to an exact patch. */
  pythonVersionRequirement?: string
  /** Exact Erlang/OTP runtime paired with the repository-owned Elixir pin. */
  erlangVersion?: string
  /** Immutable Hex and Rebar installers certified for the Elixir/OTP pair. */
  hexVersion?: string
  hexArchiveUrl?: string
  hexArchiveSha512?: string
  rebar3Version?: string
  rebar3ArchiveUrl?: string
  rebar3ArchiveSha512?: string
  /** Wrapper executable relative to the selected package-manager directory. */
  wrapperExecutable?: string
}

const PACKAGE_MANAGER_PATTERN = /^(npm|pnpm|yarn)@(\d+\.\d+\.\d+)(?:\+sha(?:224|256|384|512)\.[a-f0-9]+)?$/iu
const NATIVE_PACKAGE_MANAGER_PATTERN = /^(cargo|go)@(\d+\.\d+\.\d+)$/iu
const MANAGED_PACKAGE_MANAGER_PATTERN = /^(maven|gradle|sbt|dotnet|composer|bundler|swift|dart|mix|clojure|leiningen)@(\d+\.\d+\.\d+(?:\.\d+)?)$/iu
const VCPKG_PACKAGE_MANAGER_PATTERN = /^vcpkg@([a-f0-9]{40})$/iu
const EXACT_VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)$/u
const MINOR_VERSION_PATTERN = /^(\d+)\.(\d+)$/u
export const CERTIFIED_PYTHON_UV_EXECUTABLE = '/opt/dependency-cache/uv-tool/bin/uv'

const CERTIFIABLE_VERSION_POLICY = {
  npm: { minimumMajor: 9, maximumMajor: 12 },
  pnpm: { minimumMajor: 8, maximumMajor: 12 },
  yarnBerry: { minimumMajor: 3, maximumMajor: 4 },
  python: { major: 3, minimumMinor: 10, maximumMinor: 14 },
  uv: { major: 0, minimumMinor: 5, maximumMinor: 12 },
  rust: { major: 1, minimumMinor: 75, maximumMinor: 99 },
  go: { major: 1, minimumMinor: 21, maximumMinor: 26 },
} as const

/**
 * This is deliberately a small exact-version matrix. Adding an entry requires
 * the real networked-prefetch plus --network none regression test in
 * scripts/test-package-manager-containers.mjs to pass for that exact version.
 */
export const TESTED_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [
  { name: 'npm', version: '10.9.8', spec: 'npm@10.9.8', variant: 'npm', lockfile: 'package-lock.json' },
  { name: 'npm', version: '11.13.0', spec: 'npm@11.13.0', variant: 'npm', lockfile: 'package-lock.json' },
  { name: 'pnpm', version: '10.15.0', spec: 'pnpm@10.15.0', variant: 'pnpm', lockfile: 'pnpm-lock.yaml' },
  { name: 'pnpm', version: '10.23.0', spec: 'pnpm@10.23.0', variant: 'pnpm', lockfile: 'pnpm-lock.yaml' },
  { name: 'pnpm', version: '11.22.0', spec: 'pnpm@11.22.0', variant: 'pnpm', lockfile: 'pnpm-lock.yaml' },
  { name: 'yarn', version: '1.22.22', spec: 'yarn@1.22.22', variant: 'yarn-classic', lockfile: 'yarn.lock' },
  { name: 'yarn', version: '4.6.0', spec: 'yarn@4.6.0', variant: 'yarn-berry', lockfile: 'yarn.lock' },
] as const

export const TESTED_PYTHON_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [
  {
    name: 'pip', version: '25.0.1', spec: 'pip@25.0.1', variant: 'python-pip',
    lockfile: 'requirements.txt', language: 'python', pythonVersion: '3.12.11',
  },
  {
    name: 'uv', version: '0.12.5', spec: 'uv@0.12.5', variant: 'python-uv',
    lockfile: 'uv.lock', language: 'python', pythonVersion: '3.12.11',
  },
] as const

export const PYTHON_STDLIB_PLAN: PackageManagerPlan = {
  name: 'python',
  version: '3.12.11',
  spec: 'python@3.12.11',
  variant: 'python-stdlib',
  lockfile: '.',
  language: 'python',
  pythonVersion: '3.12.11',
}

export const TESTED_RUST_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [{
  name: 'cargo', version: '1.96.1', spec: 'cargo@1.96.1', variant: 'rust-cargo',
  lockfile: 'Cargo.lock', language: 'rust',
}] as const

export const TESTED_GO_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [{
  name: 'go', version: '1.26.5', spec: 'go@1.26.5', variant: 'go-modules',
  lockfile: 'go.sum', language: 'go',
}] as const

export const TESTED_MANAGED_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [
  { name: 'maven', version: '3.9.11', spec: 'maven@3.9.11', variant: 'jvm-maven', lockfile: 'pom.xml', language: 'java' },
  { name: 'gradle', version: '8.14.4', spec: 'gradle@8.14.4', variant: 'jvm-gradle', lockfile: 'gradle.lockfile', language: 'java' },
  {
    name: 'sbt', version: '1.10.1', spec: 'sbt@1.10.1', variant: 'scala-sbt',
    lockfile: 'build.sbt', language: 'scala', runtimeVersion: '17.0.12',
    scalaVersion: '2.13.14', coursierVersion: '2.1.24',
  },
  { name: 'dotnet', version: '9.0.304', spec: 'dotnet@9.0.304', variant: 'dotnet-nuget', lockfile: 'packages.lock.json', language: 'csharp' },
  { name: 'composer', version: '2.8.10', spec: 'composer@2.8.10', variant: 'php-composer', lockfile: 'composer.lock', language: 'php' },
  { name: 'bundler', version: '2.6.9', spec: 'bundler@2.6.9', variant: 'ruby-bundler', lockfile: 'Gemfile.lock', language: 'ruby' },
  { name: 'swift', version: '6.2.0', spec: 'swift@6.2.0', variant: 'swift-package', lockfile: 'Package.resolved', language: 'swift' },
  { name: 'dart', version: '3.9.0', spec: 'dart@3.9.0', variant: 'dart-pub', lockfile: 'pubspec.lock', language: 'dart' },
  {
    name: 'mix', version: '1.19.4', spec: 'mix@1.19.4', variant: 'elixir-mix',
    lockfile: 'mix.lock', language: 'elixir', runtimeVersion: '1.19.4', erlangVersion: '27.3.4.6',
    hexVersion: '2.5.1',
    hexArchiveUrl: 'https://builds.hex.pm/installs/1.19.0/hex-2.5.1-otp-27.ez',
    hexArchiveSha512: '283898a61ea969cb9be4bdbee022bb15784a74945ba9f81cfff9c42472dcdde3f72955e9610461c3aa53874cd229f96ae75b00fed8e775c8e5f2266e4c0f0e23',
    rebar3Version: '3.24.0',
    rebar3ArchiveUrl: 'https://builds.hex.pm/installs/1.18.3/rebar3-3.24.0-otp-27',
    rebar3ArchiveSha512: '158473850233093e6a1417e9779919cb6768402ea967db510d926bc5e74361377e9176014e827c622098e0dbf96b505677addc4bd4817ce2b9b4f4bc8121768b',
  },
  { name: 'clojure', version: '1.12.0.1530', spec: 'clojure@1.12.0.1530', variant: 'clojure-tools-deps', lockfile: 'deps.edn', language: 'clojure', runtimeVersion: '1.12.0' },
  { name: 'leiningen', version: '2.11.2', spec: 'leiningen@2.11.2', variant: 'clojure-leiningen', lockfile: 'project.clj', language: 'clojure', runtimeVersion: '1.12.0' },
] as const

export const TESTED_VCPKG_PACKAGE_MANAGERS: readonly PackageManagerPlan[] = [{
  name: 'vcpkg',
  version: 'cea592f4772491abdb7c483387a59ea89889f4be',
  spec: 'vcpkg@cea592f4772491abdb7c483387a59ea89889f4be',
  variant: 'cpp-vcpkg',
  lockfile: '.',
  language: 'cpp',
}, {
  name: 'vcpkg',
  version: '1004d5d0f80ac648514e3e6ce8e033f44b45e246',
  spec: 'vcpkg@1004d5d0f80ac648514e3e6ce8e033f44b45e246',
  variant: 'c-vcpkg',
  lockfile: '.',
  language: 'c',
}] as const

export const ANALYSIS_ONLY_PLAN: PackageManagerPlan = {
  name: 'none',
  version: '1.0.0',
  spec: 'none@1.0.0',
  variant: 'analysis-only',
  lockfile: '.',
}

const MANIFEST_SCAN_EXCLUDED = new Set([
  '.git', '.hg', '.venv', 'venv', 'node_modules', 'dist', 'build', '.build', 'coverage',
  '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'vendor',
])

/**
 * Converts a verified migration job into a code-owned, exact dependency plan.
 * No customer files are read here, and provider/model text cannot introduce an
 * arbitrary package name or floating version into the networked fetch stage.
 */
export function migrationDependencies(jobInput: MigrationJob): MigrationDependency[] {
  const job = MigrationJobSchema.parse(jobInput)
  const event = job.changeEvent
  const python = safePythonDependencyMigration(event)
  if (python !== undefined) return [{ name: python.name, version: python.newVersion }]
  const native = safeNativeDependencyMigration(event)
  if (native !== undefined) return [{ name: native.name, version: native.newVersion }]
  const cpp = safeCppDependencyMigrations(event)
  if (cpp.length > 0) return cpp.map(item => ({ name: item.name, version: item.newVersion }))
  const managed = safeManagedDependencyMigrations(event)
  if (managed.length > 0) return managed.map(item => ({ name: item.name, version: item.newVersion }))
  const isFirecrawlV1ToV2 = !isPythonOnly(event) && isFirecrawlMigration(event)
  const isSentryV7ToV8 = isSentryMigration(event)

  if (isFirecrawlV1ToV2) {
    return [{ name: '@mendable/firecrawl-js', version: FIRECRAWL_TARGET_PACKAGE_VERSION }]
  }
  if (isSentryV7ToV8) return [{ name: '@sentry/core', version: '8.0.0' }]
  const reviewed = reviewedRecipeDependencies(event)
  if (reviewed.length > 0) return reviewed
  const generic = safeGenericDependencyMigration(event)
  return generic === undefined ? [] : [generic]
}

export async function selectPreparationPackageManager(
  rootDir: string,
  jobInput: MigrationJob,
): Promise<PackageManagerPlan> {
  const job = MigrationJobSchema.parse(jobInput)
  await readReviewedKotlinPom(rootDir, job, 'baseline')
  const workingDir = await resolveExistingPathInsideRepository(
    rootDir,
    job.repository.workingDirectory,
  )
  const packageManagerDir = await resolveExistingPathInsideRepository(
    rootDir,
    job.repository.packageManagerDirectory ?? job.repository.workingDirectory,
  )
  const languages = job.changeEvent.affectedLanguages
  const preferredLanguage = languages.length === 1 ? languages[0] : undefined
  const pythonDependencyChange = safePythonDependencyMigration(job.changeEvent) !== undefined
    || job.changeEvent.affectedDependencies.some(dependency =>
      dependency.ecosystem === 'pypi'
        && (dependency.oldVersionRange !== undefined || dependency.newVersion !== undefined),
    )
  if (preferredLanguage === 'python' && !pythonDependencyChange) {
    return detectPythonRuntimePlan(packageManagerDir)
  }
  const nativeDependencyChange = job.changeEvent.affectedDependencies.some(dependency =>
    (dependency.ecosystem === 'cargo' || dependency.ecosystem === 'gomod')
      && (dependency.oldVersionRange !== undefined || dependency.newVersion !== undefined),
  )
  if ((preferredLanguage === 'rust' || preferredLanguage === 'go') && !nativeDependencyChange) {
    return detectNativePackageManager(packageManagerDir, preferredLanguage)
  }
  if (!(await repositoryDeclaresAffectedDependency(workingDir, job))) {
    return { ...ANALYSIS_ONLY_PLAN }
  }
  return detectPackageManager(
    packageManagerDir,
    job.repository.packageManager ?? preferredLanguage,
    { reviewedJvmContext: { job, repositoryRoot: rootDir } },
  )
}

async function repositoryDeclaresAffectedDependency(
  rootDir: string,
  job: MigrationJob,
): Promise<boolean> {
  const npmNames = new Set([
    ...job.changeEvent.affectedPackages,
    ...job.changeEvent.affectedDependencies
      .filter(dependency => dependency.ecosystem === 'npm')
      .map(dependency => dependency.name),
  ])
  const pypiNames = new Set(job.changeEvent.affectedDependencies
    .filter(dependency => dependency.ecosystem === 'pypi')
    .map(dependency => normalizePythonDistribution(dependency.name)))
  const cargoNames = new Set(job.changeEvent.affectedDependencies
    .filter(dependency => dependency.ecosystem === 'cargo')
    .map(dependency => dependency.name))
  const goNames = new Set(job.changeEvent.affectedDependencies
    .filter(dependency => dependency.ecosystem === 'gomod')
    .map(dependency => dependency.name))
  const vcpkgNames = new Set(job.changeEvent.affectedDependencies
    .filter(dependency => dependency.ecosystem === 'vcpkg')
    .map(dependency => dependency.name.toLowerCase()))
  const managedNames = new Map(['maven', 'nuget', 'composer', 'gem', 'swiftpm', 'pub', 'hex'].map(ecosystem => [
    ecosystem,
    new Set(job.changeEvent.affectedDependencies.filter(item => item.ecosystem === ecosystem).map(item => item.name.toLowerCase())),
  ]))
  if (npmNames.size === 0 && pypiNames.size === 0 && cargoNames.size === 0 && goNames.size === 0 && vcpkgNames.size === 0
    && [...managedNames.values()].every(names => names.size === 0)) return false

  for (const path of await repositoryManifestPaths(resolve(rootDir))) {
    const name = basename(path)
    const content = await readFile(path, 'utf8')
    if (name === 'package.json' && npmNames.size > 0) {
      let manifest: unknown
      try {
        manifest = JSON.parse(content)
      } catch {
        throw new Error(`invalid package.json while checking affected dependencies: ${path}`)
      }
      if (typeof manifest === 'object' && manifest !== null) {
        for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
          const dependencies = (manifest as Record<string, unknown>)[field]
          if (typeof dependencies === 'object' && dependencies !== null
            && Object.keys(dependencies).some(dependency => npmNames.has(dependency))) return true
        }
      }
    }
    if (pypiNames.size > 0 && (name === 'pyproject.toml' || /^requirements(?:[-_.].*)?\.txt$/iu.test(name))) {
      const normalized = content.toLowerCase().replace(/[._-]+/gu, '-')
      if ([...pypiNames].some(dependency => new RegExp(`(^|[^a-z0-9])${escapeRegex(dependency)}([^a-z0-9]|$)`, 'mu').test(normalized))) {
        return true
      }
    }
    if (name === 'Cargo.toml' && cargoNames.size > 0) {
      if (cargoDependencyDeclarations(content).some(declaration =>
        cargoNames.has(declaration.packageName))) return true
    }
    if (name === 'go.mod' && goNames.size > 0) {
      if ([...goNames].some(dependency => new RegExp(
        `^\\s*(?:require\\s+)?${escapeRegex(dependency)}\\s+v`, 'mu',
      ).test(content))) return true
    }
    if (name === 'vcpkg.json' && vcpkgNames.size > 0) {
      const manifest = parseVcpkgManifest(content, path)
      if (manifest.dependencies.some(dependency => vcpkgNames.has(dependency.name.toLowerCase()))) return true
    }
    for (const [ecosystem, names] of managedNames) {
      if (names.size > 0 && manifestBelongsToEcosystem(name, ecosystem)
        && [...names].some(dependency => managedManifestDeclaresDependency(name, content, ecosystem, dependency))) return true
    }
  }
  return false
}

async function repositoryManifestPaths(root: string): Promise<string[]> {
  const paths: string[] = []
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    const path = resolve(root, entry.name)
    if (entry.isDirectory() && !MANIFEST_SCAN_EXCLUDED.has(entry.name)) {
      paths.push(...await repositoryManifestPaths(path))
    } else if (entry.isFile() && (
      entry.name === 'package.json'
      || entry.name === 'pyproject.toml'
      || /^requirements(?:[-_.].*)?\.txt$/iu.test(entry.name)
      || entry.name === 'Cargo.toml'
      || entry.name === 'go.mod'
      || entry.name === 'pom.xml'
      || /^build\.gradle(?:\.kts)?$/u.test(entry.name)
      || entry.name === 'build.sbt'
      || entry.name.endsWith('.csproj')
      || entry.name === 'Directory.Packages.props'
      || entry.name === 'composer.json'
      || entry.name === 'Gemfile'
      || entry.name.endsWith('.gemspec')
      || entry.name === 'Package.swift'
      || entry.name === 'pubspec.yaml'
      || entry.name === 'mix.exs'
      || entry.name === 'deps.edn'
      || entry.name === 'project.clj'
      || entry.name === 'vcpkg.json'
    )) {
      paths.push(path)
    }
  }
  return paths.sort()
}

function manifestBelongsToEcosystem(name: string, ecosystem: string): boolean {
  if (ecosystem === 'maven') return name === 'pom.xml' || /^build\.gradle(?:\.kts)?$/u.test(name)
    || name === 'build.sbt' || name === 'deps.edn' || name === 'project.clj'
  if (ecosystem === 'nuget') return name.endsWith('.csproj') || name === 'Directory.Packages.props'
  if (ecosystem === 'composer') return name === 'composer.json'
  if (ecosystem === 'gem') return name === 'Gemfile' || name.endsWith('.gemspec')
  if (ecosystem === 'swiftpm') return name === 'Package.swift'
  if (ecosystem === 'hex') return name === 'mix.exs'
  return ecosystem === 'pub' && name === 'pubspec.yaml'
}

function managedManifestDeclaresDependency(
  filename: string,
  content: string,
  ecosystem: string,
  dependency: string,
): boolean {
  const normalized = dependency.toLowerCase()
  if (ecosystem === 'maven') {
    const [groupId, artifactId] = normalized.split(':')
    if (!groupId || !artifactId) return false
    if (filename === 'build.sbt') {
      return new RegExp(
        `["']${escapeRegex(groupId)}["']\\s*%%?\\s*["']${escapeRegex(artifactId)}["']`, 'iu',
      ).test(content)
    }
    if (filename === 'deps.edn') {
      return new RegExp(`(?:^|[\\s{])${escapeRegex(groupId)}/${escapeRegex(artifactId)}\\s+\\{[^{}]*:mvn/version\\s+["']`, 'u').test(content)
    }
    if (filename === 'project.clj') {
      return new RegExp(`\\[${escapeRegex(groupId)}/${escapeRegex(artifactId)}\\s+["']`, 'u').test(content)
    }
    if (/^build\.gradle(?:\.kts)?$/u.test(filename)) {
      if (new RegExp(`["']${escapeRegex(normalized)}(?:[:"'])`, 'iu').test(content)) return true
      const separator = '\\s*(?::|=)\\s*'
      const group = `group${separator}["']${escapeRegex(groupId)}["']`
      const name = `name${separator}["']${escapeRegex(artifactId)}["']`
      return new RegExp(`(?:${group}[^)\\n]{0,500}${name}|${name}[^)\\n]{0,500}${group})`, 'iu').test(content)
    }
    return [...content.matchAll(/<dependency\b[^>]*>([\s\S]*?)<\/dependency>/giu)].some(match => {
      const block = match[1] ?? ''
      const group = block.match(/<groupId>\s*([^<]+?)\s*<\/groupId>/iu)?.[1]?.trim().toLowerCase()
      const artifact = block.match(/<artifactId>\s*([^<]+?)\s*<\/artifactId>/iu)?.[1]?.trim().toLowerCase()
      return group === groupId && artifact === artifactId
    })
  }
  if (ecosystem === 'nuget') {
    return new RegExp(`<(?:PackageReference|PackageVersion)\\b[^>]*(?:Include|Update)\\s*=\\s*["']${escapeRegex(normalized)}["']`, 'iu').test(content)
  }
  if (ecosystem === 'composer') {
    try {
      const manifest = JSON.parse(content) as Record<string, unknown>
      return ['require', 'require-dev'].some(field => {
        const dependencies = manifest[field]
        return typeof dependencies === 'object' && dependencies !== null
          && Object.keys(dependencies).some(name => name.toLowerCase() === normalized)
      })
    } catch {
      throw new Error('invalid composer.json while checking affected dependencies')
    }
  }
  if (ecosystem === 'gem') {
    return new RegExp(`^\\s*(?:[A-Za-z_]\\w*\\.)?(?:gem|add_dependency|add_runtime_dependency|add_development_dependency)\\s*\\(?\\s*["']${escapeRegex(normalized)}["']`, 'imu').test(content)
  }
  if (ecosystem === 'swiftpm') {
    const aliases = new Set([normalized, normalized.split('/').at(-1) ?? normalized])
    return [...aliases].some(name => new RegExp(`(?:name\\s*:\\s*)?["']${escapeRegex(name)}["']|/\\s*${escapeRegex(name)}(?:\\.git)?["']`, 'iu').test(content))
  }
  if (ecosystem === 'hex') {
    return new RegExp(`\\{\\s*:${escapeRegex(normalized)}\\s*,`, 'iu').test(content)
  }
  return ecosystem === 'pub'
    && new RegExp(`^\\s{2,}${escapeRegex(normalized)}\\s*:`, 'imu').test(content)
}

function normalizePythonDistribution(value: string): string {
  return value.toLowerCase().replace(/[._-]+/gu, '-')
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}

export async function applyHarnessDependencyManifest(
  rootDir: string,
  jobInput: MigrationJob,
): Promise<boolean> {
  const job = MigrationJobSchema.parse(jobInput)
  const reviewedKotlin = await migrateReviewedKotlinPom(rootDir, job)
  if (reviewedKotlin !== undefined) return reviewedKotlin
  const python = safePythonDependencyMigration(job.changeEvent)
  if (python !== undefined) return migrateExactPythonDependency(rootDir, python, job)
  if (isPythonOnly(job.changeEvent)) return false
  if (isRustOnly(job.changeEvent)) {
    if (safeNativeDependencyMigration(job.changeEvent) === undefined) return false
    return migrateCargoDependency(rootDir, job.changeEvent)
  }
  if (isGoOnly(job.changeEvent)) {
    if (safeNativeDependencyMigration(job.changeEvent) === undefined) return false
    return migrateGoDependency(rootDir, job.changeEvent)
  }
  if (isCOrCppOnly(job.changeEvent)) {
    const dependencies = safeCppDependencyMigrations(job.changeEvent)
    if (dependencies.length === 0) return false
    return migrateVcpkgDependencies(rootDir, dependencies)
  }
  const managed = safeManagedDependencyMigrations(job.changeEvent)
  if (managed.length > 0) {
    const changed = await migrateManagedDependencies(rootDir, managed)
    if (changed) {
      for (const dependency of managed) await adoptPrefetchedManagedLockfile(rootDir, dependency)
    }
    return changed
  }
  if (isFirecrawlMigration(job.changeEvent)) {
    return applyFirecrawlV1ToV2DependencyUpdate(rootDir)
  }
  if (isSentryMigration(job.changeEvent)) {
    return migrateExactDependency(rootDir, '@sentry/core', '7.120.4', '8.0.0')
  }
  if (await applyReviewedProviderDependencyUpdate(rootDir, job.changeEvent)) return true
  const generic = safeGenericDependencyMigration(job.changeEvent)
  if (generic === undefined) return false
  return migrateDependencyMajor(
    rootDir,
    generic.name,
    job.changeEvent.oldVersion,
    generic.version,
  )
}

function isPythonOnly(event: MigrationJob['changeEvent']): boolean {
  return event.affectedLanguages.length === 1 && event.affectedLanguages[0] === 'python'
}

function isRustOnly(event: MigrationJob['changeEvent']): boolean {
  return event.affectedLanguages.length === 1 && event.affectedLanguages[0] === 'rust'
}

function isGoOnly(event: MigrationJob['changeEvent']): boolean {
  return event.affectedLanguages.length === 1 && event.affectedLanguages[0] === 'go'
}

function isCOrCppOnly(event: MigrationJob['changeEvent']): boolean {
  return event.affectedLanguages.length === 1
    && (event.affectedLanguages[0] === 'c' || event.affectedLanguages[0] === 'cpp')
}

/**
 * Applies only the reviewed dependency edit to a disposable repository copy.
 * The networked Action stage uses this copy to resolve future lockfile
 * metadata without exposing the real checkout to a network-enabled mutation.
 */
export async function prepareDependencyResolution(
  repositoryRoot: string,
  jobInput: MigrationJob,
): Promise<boolean> {
  const job = MigrationJobSchema.parse(jobInput)
  // Hashed pip requirements are updated only later inside the network-disabled
  // proposal container, where the downloaded wheel hash is available. Legacy
  // uv also prefetches its target from the separate code-owned manifest, but
  // needs a disposable copy of the complete migrated project graph so a later
  // offline non-frozen lock refresh has registry metadata for unchanged
  // dependencies. The current baseline uses its separate certified archive.
  if (isPythonOnly(job.changeEvent)) {
    const packageManager = await selectPreparationPackageManager(repositoryRoot, job)
    if (packageManager.variant !== 'python-uv'
      || packageManager.version === TESTED_PYTHON_PACKAGE_MANAGERS[1]!.version) return false
  }
  const workingDir = await resolveExistingPathInsideRepository(
    repositoryRoot,
    job.repository.workingDirectory,
  )
  return applyHarnessDependencyManifest(workingDir, job)
}

/** Names whose reviewed Ruby declarations actually change in this repository. */
export async function rubyDependencyResolutionTargets(
  repositoryRoot: string,
  jobInput: MigrationJob,
): Promise<string[]> {
  const job = MigrationJobSchema.parse(jobInput)
  const dependencies = safeManagedDependencyMigrations(job.changeEvent)
  if (dependencies.length === 0 || dependencies.some(dependency =>
    dependency.ecosystem !== 'gem' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/u.test(dependency.name))) return []
  const rootDir = await resolveExistingPathInsideRepository(repositoryRoot, job.repository.workingDirectory)
  const changed = new Set<string>()
  for (const path of await repositoryManifestPaths(rootDir)) {
    const name = basename(path)
    if (!manifestBelongsToEcosystem(name, 'gem')) continue
    const content = await readFile(path, 'utf8')
    for (const dependency of dependencies) {
      if (updateManagedManifest(content, name, dependency) !== content) changed.add(dependency.name)
    }
  }
  // Match the all-or-nothing manifest writer; never broaden a partial plan.
  return changed.size === dependencies.length ? [...changed].sort() : []
}

/** Composer package names whose reviewed declarations actually change in this repository. */
export async function composerDependencyResolutionTargets(
  repositoryRoot: string,
  jobInput: MigrationJob,
): Promise<string[]> {
  const job = MigrationJobSchema.parse(jobInput)
  const dependencies = safeManagedDependencyMigrations(job.changeEvent)
  if (dependencies.length === 0 || dependencies.some(dependency =>
    dependency.ecosystem !== 'composer'
      || !/^[a-z0-9][a-z0-9_.-]*\/[a-z0-9][a-z0-9_.-]*$/u.test(dependency.name))) return []
  const rootDir = await resolveExistingPathInsideRepository(repositoryRoot, job.repository.workingDirectory)
  const changed = new Set<string>()
  for (const path of await repositoryManifestPaths(rootDir)) {
    const name = basename(path)
    if (!manifestBelongsToEcosystem(name, 'composer')) continue
    const content = await readFile(path, 'utf8')
    for (const dependency of dependencies) {
      if (updateManagedManifest(content, name, dependency) !== content) changed.add(dependency.name)
    }
  }
  // Match the all-or-nothing manifest writer; never broaden a partial plan.
  return changed.size === dependencies.length ? [...changed].sort() : []
}

export async function detectPackageManager(
  rootDir: string,
  configuredPackageManagerOrLanguage?: string,
  options: { allowPythonStdlibOnly?: boolean; reviewedJvmContext?: ReviewedJvmContext } = {},
): Promise<PackageManagerPlan> {
  const preferredLanguage = isRepositoryLanguage(configuredPackageManagerOrLanguage)
    ? configuredPackageManagerOrLanguage
    : undefined
  const configuredPackageManager = preferredLanguage === undefined
    ? configuredPackageManagerOrLanguage
    : undefined
  const configuredPython = configuredPackageManager !== undefined
    && /^(?:pip|uv|python)@/iu.test(configuredPackageManager)
  const configuredRust = configuredPackageManager !== undefined
    && /^cargo@/iu.test(configuredPackageManager)
  const configuredGo = configuredPackageManager !== undefined
    && /^go@/iu.test(configuredPackageManager)
  const configuredVcpkg = configuredPackageManager !== undefined
    && VCPKG_PACKAGE_MANAGER_PATTERN.test(configuredPackageManager)
  const configuredManaged = configuredPackageManager !== undefined
    && MANAGED_PACKAGE_MANAGER_PATTERN.test(configuredPackageManager)
  if (preferredLanguage === 'rust' || configuredRust) {
    return detectNativePackageManager(rootDir, 'rust', configuredPackageManager)
  }
  if (preferredLanguage === 'go' || configuredGo) {
    return detectNativePackageManager(rootDir, 'go', configuredPackageManager)
  }
  if (preferredLanguage === 'c' || preferredLanguage === 'cpp' || configuredVcpkg) {
    return detectVcpkgPackageManager(
      rootDir,
      preferredLanguage === 'c' || preferredLanguage === 'cpp' ? preferredLanguage : undefined,
      configuredPackageManager,
    )
  }
  if (preferredLanguage === 'python' || configuredPython) {
    if (options.allowPythonStdlibOnly === true) return { ...PYTHON_STDLIB_PLAN }
    const detected = await detectPythonPackageManager(rootDir)
    if (configuredPackageManager !== undefined && configuredPackageManager !== detected.spec) {
      throw new Error('configured Python packageManager does not match repository lock metadata')
    }
    return detected
  }
  if (isManagedRepositoryLanguage(preferredLanguage) || configuredManaged) {
    return detectManagedPackageManager(
      rootDir,
      isManagedRepositoryLanguage(preferredLanguage) ? preferredLanguage : undefined,
      configuredPackageManager,
      options.reviewedJvmContext,
    )
  }
  if (!(await pathExists(resolve(rootDir, 'package.json')))) {
    const candidates = [
      await pathExists(resolve(rootDir, 'pyproject.toml'))
        || await pathExists(resolve(rootDir, 'requirements.txt'))
        || await pathExists(resolve(rootDir, 'uv.lock')) ? 'python' : undefined,
      await pathExists(resolve(rootDir, 'Cargo.toml')) ? 'rust' : undefined,
      await pathExists(resolve(rootDir, 'go.mod')) ? 'go' : undefined,
      await pathExists(resolve(rootDir, 'build.sbt')) ? 'scala' : undefined,
      await pathExists(resolve(rootDir, 'pom.xml')) || await pathExists(resolve(rootDir, 'build.gradle'))
        || await pathExists(resolve(rootDir, 'build.gradle.kts')) ? 'java' : undefined,
      (await topLevelHasExtension(rootDir, '.csproj')) ? 'csharp' : undefined,
      await pathExists(resolve(rootDir, 'composer.json')) ? 'php' : undefined,
      await pathExists(resolve(rootDir, 'Gemfile')) ? 'ruby' : undefined,
      await pathExists(resolve(rootDir, 'Package.swift')) ? 'swift' : undefined,
      await pathExists(resolve(rootDir, 'pubspec.yaml')) ? 'dart' : undefined,
      await pathExists(resolve(rootDir, 'mix.exs')) ? 'elixir' : undefined,
      await pathExists(resolve(rootDir, 'deps.edn')) || await pathExists(resolve(rootDir, 'project.clj')) ? 'clojure' : undefined,
      await pathExists(resolve(rootDir, 'vcpkg.json')) ? 'cpp' : undefined,
    ].filter((value): value is 'python' | 'rust' | 'go' | 'java' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure' | 'cpp' => value !== undefined)
    if (candidates.length !== 1) {
      throw new Error('repository target must select one language when multiple or no supported manifests are present')
    }
    if (candidates[0] === 'rust') return detectNativePackageManager(rootDir, 'rust')
    if (candidates[0] === 'go') return detectNativePackageManager(rootDir, 'go')
    if (candidates[0] === 'cpp') return detectVcpkgPackageManager(rootDir, 'cpp')
    if (isManagedRepositoryLanguage(candidates[0])) return detectManagedPackageManager(rootDir, candidates[0], undefined, options.reviewedJvmContext)
    if (options.allowPythonStdlibOnly === true) return { ...PYTHON_STDLIB_PLAN }
    return detectPythonPackageManager(rootDir)
  }
  const manifest = JSON.parse(await readFile(resolve(rootDir, 'package.json'), 'utf8')) as unknown
  if (typeof manifest !== 'object' || manifest === null) {
    throw new Error('package.json must contain an object')
  }
  const declaredPackageManager = 'packageManager' in manifest ? manifest.packageManager : undefined
  if (
    declaredPackageManager !== undefined
    && configuredPackageManager !== undefined
    && declaredPackageManager !== configuredPackageManager
  ) {
    throw new Error('configured packageManager does not match package.json')
  }
  const lockfiles = await presentLockfiles(rootDir)
  const packageManager = declaredPackageManager ?? configuredPackageManager
    ?? (lockfiles.length === 1 && lockfiles[0] === 'package-lock.json' ? 'npm@10.9.8' : undefined)
  if (packageManager === undefined) {
    throw new Error('package.json or repository target must declare an exact packageManager unless package-lock.json selects certified npm')
  }
  if (typeof packageManager !== 'string') {
    throw new Error('packageManager must be an exact string such as npm@10.9.8')
  }
  const match = packageManager.match(PACKAGE_MANAGER_PATTERN)
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new Error('packageManager must use an exact name@major.minor.patch version')
  }
  const name = match[1].toLowerCase() as SupportedPackageManager
  const version = match[2]
  const bootstrap = TESTED_PACKAGE_MANAGERS.find(
    candidate => candidate.name === name && candidate.version === version,
  )
  const supported = bootstrap ?? certifiableNodePackageManager(name, version, packageManager)
  if (lockfiles.length !== 1) {
    throw new Error(
      lockfiles.length === 0
        ? 'exactly one npm, pnpm, or Yarn lockfile is required'
        : `multiple package-manager lockfiles found: ${lockfiles.join(', ')}`,
    )
  }
  if (lockfiles[0] !== supported.lockfile) {
    throw new Error(`packageManager ${name}@${version} does not match ${lockfiles[0]}`)
  }
  await assertSafeNodePackageManagerConfiguration(rootDir, supported.variant)

  return {
    ...supported,
    // Preserve an optional Corepack integrity suffix after validating the
    // allowlisted name and exact semantic version.
    spec: packageManager,
  }
}

async function detectPythonPackageManager(rootDir: string): Promise<PackageManagerPlan> {
  const pythonVersion = await detectedPythonVersion(rootDir)
  const requirement = await pythonVersionRequirement(rootDir)
  const hasUv = await pathExists(resolve(rootDir, 'uv.lock'))
  const hasRequirements = await pathExists(resolve(rootDir, 'requirements.txt'))
  if (hasUv && hasRequirements) throw new Error('multiple Python package-manager lockfiles found: uv.lock, requirements.txt')
  if (hasUv) {
    const pyproject = await readFile(resolve(rootDir, 'pyproject.toml'), 'utf8')
    const match = pyproject.match(/^\s*required-version\s*=\s*["']==([0-9]+\.[0-9]+\.[0-9]+)["']\s*$/mu)
    const hasDeclaration = /^\s*required-version\s*=/mu.test(pyproject)
    if (hasDeclaration && match?.[1] === undefined) {
      throw new Error('uv required-version, when declared, must select one exact version')
    }
    // uv.lock does not record the uv executable that created it. Repositories
    // may therefore omit required-version; use the platform-owned exact
    // baseline in that case, then prove the repository's frozen graph both
    // online and with networking disabled. Never guess past an explicit range.
    const uvVersion = match?.[1] ?? TESTED_PYTHON_PACKAGE_MANAGERS[1]!.version
    assertCertifiableMinorVersion('uv', uvVersion, CERTIFIABLE_VERSION_POLICY.uv)
    return {
      name: 'uv', version: uvVersion, spec: `uv@${uvVersion}`, variant: 'python-uv',
      lockfile: 'uv.lock', language: 'python', pythonVersion,
      ...(requirement === undefined ? {} : { pythonVersionRequirement: requirement }),
    }
  }
  if (!hasRequirements) {
    throw new Error('Python repositories require exactly one supported requirements.txt or uv.lock')
  }
  await assertHashLockedRequirements(resolve(rootDir, 'requirements.txt'))
  return {
    ...(TESTED_PYTHON_PACKAGE_MANAGERS[0] as PackageManagerPlan),
    pythonVersion,
    ...(requirement === undefined ? {} : { pythonVersionRequirement: requirement }),
  }
}

async function detectPythonRuntimePlan(rootDir: string): Promise<PackageManagerPlan> {
  const pythonVersion = await detectedPythonVersion(rootDir)
  const requirement = await pythonVersionRequirement(rootDir)
  return {
    name: 'python', version: pythonVersion, spec: `python@${pythonVersion}`,
    variant: 'python-stdlib', lockfile: '.', language: 'python', pythonVersion,
    ...(requirement === undefined ? {} : { pythonVersionRequirement: requirement }),
  }
}

async function detectedPythonVersion(rootDir: string): Promise<string> {
  const requirement = await declaredPythonRuntimeRequirement(rootDir)
  assertCertifiableRuntimeRequirement('Python', requirement, CERTIFIABLE_VERSION_POLICY.python)
  const resolved = process.env['AUTOMATED_API_RESOLVED_PYTHON_VERSION']?.trim()
  if (resolved === undefined || resolved === '') return requirement
  assertCertifiableMinorVersion('Python', resolved, CERTIFIABLE_VERSION_POLICY.python)
  if (!runtimeRequirementAllows(requirement, resolved)) {
    throw new Error(`resolved Python ${resolved} does not satisfy repository requirement ${requirement}`)
  }
  return resolved
}

async function pythonVersionRequirement(rootDir: string): Promise<string | undefined> {
  const requirement = await declaredPythonRuntimeRequirement(rootDir)
  return MINOR_VERSION_PATTERN.test(requirement) ? requirement : undefined
}

async function declaredPythonRuntimeRequirement(rootDir: string): Promise<string> {
  const versionPath = resolve(rootDir, '.python-version')
  if (await pathExists(versionPath)) return (await readFile(versionPath, 'utf8')).trim()

  const projectPath = resolve(rootDir, 'pyproject.toml')
  if (!(await pathExists(projectPath))) {
    throw new Error('Python repositories require .python-version or an exact pyproject.toml requires-python')
  }
  const project = await readFile(projectPath, 'utf8')
  const declarations = [...project.matchAll(/^\s*requires-python\s*=\s*["']([^"']+)["']\s*$/gmu)]
  if (declarations.length !== 1) {
    throw new Error('pyproject.toml must declare exactly one requires-python when .python-version is absent')
  }
  const requirement = declarations[0]?.[1]?.match(/^==([0-9]+\.[0-9]+(?:\.[0-9]+)?)$/u)?.[1]
  if (requirement === undefined) {
    throw new Error('pyproject.toml requires-python must select one exact Python version when .python-version is absent')
  }
  return requirement
}

async function assertHashLockedRequirements(path: string): Promise<void> {
  const content = await readFile(path, 'utf8')
  const logicalLines = content.replace(/\\\r?\n/gu, ' ').split(/\r?\n/u)
    .map(line => line.replace(/\s+#.*$/u, '').trim())
    .filter(Boolean)
  for (const line of logicalLines) {
    if (line.startsWith('-') || line.includes('://') || line.includes(' @ ')) {
      throw new Error('pip requirements must not use indexes, includes, URLs, editable, or VCS dependencies')
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?==[^\s;]+(?:\s*;[^#]+)?\s+--hash=sha256:[a-f0-9]{64}(?:\s+--hash=sha256:[a-f0-9]{64})*$/iu.test(line)) {
      throw new Error('pip requirements must use exact versions and SHA-256 hashes for offline installation')
    }
  }
}

export async function writeDependencyManifest(
  jobPath: string,
  manifestPath: string,
  packageManager: PackageManagerPlan,
  repositoryManagerRoot?: string,
): Promise<void> {
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(jobPath), 'utf8')))
  if (job.repository.pythonEnvironment !== undefined
    && (packageManager.variant !== 'python-uv' || packageManager.version !== '0.12.5')) {
    throw new Error('explicit Python environment selection requires the certified uv 0.12.5 route')
  }
  const dependencies = Object.fromEntries(
    migrationDependencies(job).map(item => [item.name, item.version]),
  )
  if (packageManager.language === 'python') {
    const explicitlyVersioned = job.changeEvent.affectedDependencies
      .filter(item => item.ecosystem === 'pypi' && item.newVersion !== undefined)
      .map(item => [item.name, item.newVersion!] as const)
    const pythonDependencies = Object.entries(
      explicitlyVersioned.length > 0 ? Object.fromEntries(explicitlyVersioned) : dependencies,
    )
      .map(([name, version]) => `${name}==${version}`)
      .sort()
    if (packageManager.variant === 'python-stdlib') {
      await writeFile(resolve(manifestPath), '', 'utf8')
      return
    }
    if (packageManager.variant === 'python-uv') {
      const releaseAgePolicy = repositoryManagerRoot === undefined
        ? [] : await pythonUvReleaseAgePolicy(repositoryManagerRoot)
      await writeFile(resolve(manifestPath), [
        '[project]',
        'name = "automated-api-dependency-prefetch"',
        'version = "0.0.0"',
        `requires-python = "==${packageManager.pythonVersion}"`,
        `dependencies = ${JSON.stringify(pythonDependencies)}`,
        '',
        '[tool.uv]',
        `required-version = "==${packageManager.version}"`,
        ...releaseAgePolicy,
        '',
      ].join('\n'), 'utf8')
      return
    }
    await writeFile(resolve(manifestPath), `${pythonDependencies.join('\n')}${pythonDependencies.length ? '\n' : ''}`, 'utf8')
    return
  }
  if (packageManager.language === 'rust') {
    const rustDependencies = job.changeEvent.affectedDependencies
      .filter(item => item.ecosystem === 'cargo' && item.newVersion !== undefined)
      .sort((left, right) => left.name.localeCompare(right.name))
    await writeFile(resolve(manifestPath), [
      '[package]',
      'name = "automated-api-dependency-prefetch"',
      'version = "0.0.0"',
      'edition = "2021"',
      '',
      '[dependencies]',
      ...rustDependencies.map(item => `${JSON.stringify(item.name)} = "=${item.newVersion}"`),
      '',
    ].join('\n'), 'utf8')
    return
  }
  if (packageManager.language === 'go') {
    const goDependencies = job.changeEvent.affectedDependencies
      .filter(item => item.ecosystem === 'gomod' && item.newVersion !== undefined)
      .sort((left, right) => left.name.localeCompare(right.name))
    await writeFile(resolve(manifestPath), [
      'module automated-api.invalid/dependency-prefetch',
      '',
      `go ${packageManager.version}`,
      '',
      'require (',
      ...goDependencies.map(item => `\t${item.name} ${item.newVersion!.startsWith('v') ? item.newVersion : `v${item.newVersion}`}`),
      ')',
      '',
    ].join('\n'), 'utf8')
    return
  }
  if (packageManager.language === 'c' || packageManager.language === 'cpp') {
    const label = packageManager.language === 'c' ? 'C' : 'C++'
    const migrations = safeCppDependencyMigrations(job.changeEvent)
    if (migrations.length === 0) throw new Error(`${label} dependency prefetch requires verified exact vcpkg migrations`)
    if (repositoryManagerRoot === undefined) throw new Error(`${label} dependency prefetch requires the repository manager root`)
    const customer = JSON.parse(await readFile(resolve(repositoryManagerRoot, 'vcpkg.json'), 'utf8')) as Record<string, unknown>
    const overrides = Array.isArray(customer['overrides'])
      ? structuredClone(customer['overrides']) as unknown[]
      : []
    for (const migration of migrations) {
      const override = overrides.find(item => typeof item === 'object' && item !== null
        && String((item as Record<string, unknown>)['name']).toLowerCase() === migration.name.toLowerCase()) as Record<string, unknown> | undefined
      if (override === undefined) throw new Error(`${label} dependency projection requires an exact override for ${migration.name}`)
      const selected = ['version', 'version-semver', 'version-string'].map(key => override[key]).find(value => typeof value === 'string')
      if (typeof selected !== 'string' || selected.replace(/#\d+$/u, '') !== migration.oldVersion) {
        throw new Error(`${label} dependency projection override mismatch for ${migration.name}`)
      }
      override['version'] = migration.newVersion
      delete override['version-semver']; delete override['version-string']; delete override['port-version']
    }
    await writeFile(resolve(manifestPath), `${JSON.stringify({
      name: 'automated-api-dependency-prefetch',
      'version-string': '0.0.0',
      dependencies: migrations.map(item => item.name).sort(),
      overrides,
      'builtin-baseline': packageManager.version,
    }, null, 2)}\n`, 'utf8')
    return
  }
  if (isManagedRepositoryLanguage(packageManager.language)) {
    const managed = safeManagedDependencyMigrations(job.changeEvent)
    const dependencies = managed.map(item => ({ name: item.name, version: item.newVersion }))
    const dependency = dependencies.length === 1 ? dependencies[0] : undefined
    if (packageManager.variant === 'jvm-maven') {
      const [group, artifact] = dependency?.name.split(':') ?? []
      await writeFile(resolve(manifestPath), [
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>',
        '<groupId>invalid.autoapi</groupId><artifactId>dependency-prefetch</artifactId><version>0.0.0</version>',
        ...(group && artifact ? [`<dependencies><dependency><groupId>${group}</groupId><artifactId>${artifact}</artifactId><version>${dependency!.version}</version></dependency></dependencies>`] : []),
        '</project>', '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'jvm-gradle') {
      await writeFile(resolve(manifestPath), [
        'plugins { java }', 'repositories { mavenCentral() }', 'dependencyLocking { lockAllConfigurations() }',
        ...(dependency ? [`dependencies { implementation(${JSON.stringify(`${dependency.name}:${dependency.version}`)}) }`] : []), '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'scala-sbt') {
      const [group, artifact] = dependency?.name.split(':') ?? []
      await writeFile(resolve(manifestPath), [
        `ThisBuild / scalaVersion := ${JSON.stringify(packageManager.scalaVersion)}`,
        'resolvers += Resolver.mavenCentral',
        ...(group && artifact ? [`libraryDependencies += ${JSON.stringify(group)} % ${JSON.stringify(artifact)} % ${JSON.stringify(dependency!.version)}`] : []),
        '',
      ].join('\n'), 'utf8')
      const project = resolve(dirname(manifestPath), 'project')
      await mkdir(project, { recursive: true })
      await writeFile(resolve(project, 'build.properties'), `sbt.version=${packageManager.version}\n`, 'utf8')
      return
    }
    if (packageManager.variant === 'dotnet-nuget') {
      await writeFile(resolve(manifestPath), [
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net9.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile><RestoreLockedMode>true</RestoreLockedMode></PropertyGroup>',
        ...(dependencies.length > 0 ? [
          '<ItemGroup>',
          ...dependencies.map(item => `<PackageReference Include="${item.name}" Version="${item.version}" />`),
          '</ItemGroup>',
        ] : []),
        '</Project>', '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'php-composer') {
      await writeFile(resolve(manifestPath), `${JSON.stringify({ name: 'autoapi/dependency-prefetch', require: dependency ? { [dependency.name]: dependency.version } : {} }, null, 2)}\n`, 'utf8'); return
    }
    if (packageManager.variant === 'ruby-bundler') {
      await writeFile(resolve(manifestPath), `source "https://rubygems.org"\n${dependency ? `gem ${JSON.stringify(dependency.name)}, ${JSON.stringify(`=${dependency.version}`)}\n` : ''}`, 'utf8'); return
    }
    if (packageManager.variant === 'swift-package') {
      await writeFile(resolve(manifestPath), [
        '// swift-tools-version: 6.2', 'import PackageDescription',
        'let package = Package(name: "DependencyPrefetch", dependencies: [], targets: [])', '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'elixir-mix') {
      await writeFile(resolve(manifestPath), [
        'defmodule AutoApi.DependencyPrefetch.MixProject do',
        '  use Mix.Project',
        `  def project, do: [app: :autoapi_dependency_prefetch, version: "0.0.0", elixir: "== ${packageManager.runtimeVersion}", deps: deps()]`,
        '  def application, do: [extra_applications: [:logger]]',
        `  defp deps, do: [${dependency ? `{:${dependency.name}, "== ${dependency.version}"}` : ''}]`,
        'end', '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'clojure-tools-deps') {
      const [group, artifact] = dependency?.name.split(':') ?? []
      const coordinate = group && artifact ? `${group}/${artifact}` : undefined
      await writeFile(resolve(manifestPath), [
        '{:deps',
        ` {${coordinate ? `${coordinate} {:mvn/version ${JSON.stringify(dependency!.version)}}` : ''}}`,
        ' :mvn/repos {"clojars" {:url "https://repo.clojars.org/"}}}',
        '',
      ].join('\n'), 'utf8'); return
    }
    if (packageManager.variant === 'clojure-leiningen') {
      const coordinate = dependency?.name.replace(':', '/')
      await writeFile(resolve(manifestPath), [
        '(defproject automated-api-dependency-prefetch "0.0.0"',
        `  :dependencies [${coordinate ? `[${coordinate} ${JSON.stringify(dependency!.version)}]` : ''}]`,
        '  :repositories [["clojars" {:url "https://repo.clojars.org/"}]])',
        '',
      ].join('\n'), 'utf8'); return
    }
    await writeFile(resolve(manifestPath), [
      'name: automated_api_dependency_prefetch', 'environment:', "  sdk: '>=3.9.0 <4.0.0'", 'dependencies:',
      ...(dependency ? [`  ${dependency.name}: ${dependency.version}`] : []), '',
    ].join('\n'), 'utf8'); return
  }
  if (packageManager.variant === 'analysis-only') {
    await writeFile(resolve(manifestPath), `${JSON.stringify({
      name: 'automated-api-analysis-only',
      private: true,
      version: '0.0.0',
    }, null, 2)}\n`, 'utf8')
    return
  }
  await writeFile(resolve(manifestPath), `${JSON.stringify({
    name: 'automated-api-dependency-prefetch',
    private: true,
    version: '0.0.0',
    packageManager: packageManager.spec,
    dependencies,
  }, null, 2)}\n`, 'utf8')
}

export async function writeDependencyManifestDirectory(
  jobPath: string,
  directory: string,
  packageManager: PackageManagerPlan,
  repositoryManagerRoot?: string,
): Promise<string> {
  await mkdir(resolve(directory), { recursive: true })
  const name = packageManager.variant === 'python-uv'
    ? 'pyproject.toml'
    : packageManager.language === 'python' ? 'requirements.txt'
      : packageManager.language === 'rust' ? 'Cargo.toml'
        : packageManager.language === 'go' ? 'go.mod'
          : packageManager.language === 'c' || packageManager.language === 'cpp' ? 'vcpkg.json'
          : packageManager.variant === 'jvm-maven' ? 'pom.xml'
            : packageManager.variant === 'jvm-gradle' ? 'build.gradle.kts'
              : packageManager.variant === 'scala-sbt' ? 'build.sbt'
              : packageManager.variant === 'dotnet-nuget' ? 'DependencyPrefetch.csproj'
                : packageManager.variant === 'php-composer' ? 'composer.json'
                  : packageManager.variant === 'ruby-bundler' ? 'Gemfile'
                    : packageManager.variant === 'swift-package' ? 'Package.swift'
                    : packageManager.variant === 'dart-pub' ? 'pubspec.yaml'
                      : packageManager.variant === 'elixir-mix' ? 'mix.exs'
                        : packageManager.variant === 'clojure-tools-deps' ? 'deps.edn'
                          : packageManager.variant === 'clojure-leiningen' ? 'project.clj'
          : 'package.json'
  await writeDependencyManifest(jobPath, resolve(directory, name), packageManager, repositoryManagerRoot)
  if (packageManager.language === 'rust') {
    await mkdir(resolve(directory, 'src'), { recursive: true })
    await writeFile(resolve(directory, 'src/lib.rs'), '', 'utf8')
  }
  return name
}

/**
 * Returns the one exact-manager offline lockfile-refresh command for the
 * checked-out repository. The Action has already prefetched that exact
 * manager and its dependencies before the proposal container loses network.
 */
export async function dependencySynchronizationCommand(
  rootDir: string,
  configuredPackageManagerOrLanguage?: string,
  exactDependency?: MigrationDependency,
  reviewedJvmContext?: ReviewedJvmContext,
): Promise<CommandSpec | undefined> {
  const preferredLanguage = isRepositoryLanguage(configuredPackageManagerOrLanguage)
    ? configuredPackageManagerOrLanguage
    : undefined
  const configuredPython = configuredPackageManagerOrLanguage !== undefined
    && /^(?:pip|uv|python)@/iu.test(configuredPackageManagerOrLanguage)
  const configuredRust = configuredPackageManagerOrLanguage !== undefined
    && /^cargo@/iu.test(configuredPackageManagerOrLanguage)
  const configuredGo = configuredPackageManagerOrLanguage !== undefined
    && /^go@/iu.test(configuredPackageManagerOrLanguage)
  const configuredVcpkg = configuredPackageManagerOrLanguage !== undefined
    && VCPKG_PACKAGE_MANAGER_PATTERN.test(configuredPackageManagerOrLanguage)
  const configuredManaged = configuredPackageManagerOrLanguage !== undefined
    && MANAGED_PACKAGE_MANAGER_PATTERN.test(configuredPackageManagerOrLanguage)
  if (preferredLanguage === 'rust' || configuredRust) {
    await detectPackageManager(rootDir, configuredPackageManagerOrLanguage)
    return {
      executable: 'cargo',
      // Update only the reviewed package. `cargo metadata` resolves the new
      // manifest but does not persist Cargo.lock, while an unscoped
      // `cargo update` could move unrelated customer dependencies.
      args: exactDependency === undefined
        ? ['metadata', '--offline', '--format-version', '1', '--no-deps']
        : ['update', '--offline', '--package', exactDependency.name, '--precise', exactDependency.version],
      timeoutMs: 5 * 60 * 1000,
    }
  }
  if (preferredLanguage === 'go' || configuredGo) {
    await detectPackageManager(rootDir, configuredPackageManagerOrLanguage)
    return {
      executable: 'go',
      args: ['mod', 'tidy'],
      timeoutMs: 5 * 60 * 1000,
    }
  }
  if (preferredLanguage === 'c' || preferredLanguage === 'cpp' || configuredVcpkg) {
    await detectPackageManager(rootDir, configuredPackageManagerOrLanguage)
    return {
      executable: process.env['AUTOMATED_API_VCPKG'] ?? '/opt/dependency-cache/vcpkg/vcpkg',
      args: vcpkgOfflineInstallArguments(),
      timeoutMs: 15 * 60 * 1000,
    }
  }
  if (isManagedRepositoryLanguage(preferredLanguage) || configuredManaged) {
    const manager = await detectPackageManager(rootDir, configuredPackageManagerOrLanguage,
      reviewedJvmContext === undefined ? {} : { reviewedJvmContext })
    const executable = manager.wrapperExecutable ?? (process.platform === 'win32'
      ? manager.variant === 'jvm-maven' ? 'mvnw.cmd' : manager.variant === 'jvm-gradle' ? 'gradlew.bat' : managedExecutable(manager.variant)
      : manager.variant === 'jvm-maven' ? './mvnw' : manager.variant === 'jvm-gradle' ? './gradlew' : managedExecutable(manager.variant))
    const args: Partial<Record<PackageManagerVariant, string[]>> = {
      'jvm-maven': ['-o', ...await reviewedKotlinMavenArguments(rootDir, reviewedJvmContext), '-DskipTests', 'dependency:go-offline'],
      'jvm-gradle': [
        '--offline', '-Pkotlin.compiler.execution.strategy=in-process', '--init-script',
        '/opt/autoapi-runtime/gradle-dependency-prefetch.init.gradle',
        ...(exactDependency === undefined ? [] : [
          `-PautomatedApiForceModule=${exactDependency.name}`,
          `-PautomatedApiForceVersion=${exactDependency.version}`,
        ]),
        '--write-locks', ...gradlePrefetchDependencyTasks(),
      ],
      'scala-sbt': ['launch', '--mode', 'offline', `sbt:${manager.version}`, '--', 'update'],
      'dotnet-nuget': [
        'restore', '--force-evaluate', '--ignore-failed-sources',
        '-p:EnableWindowsTargeting=true',
      ],
      'php-composer': exactDependency === undefined
        ? ['install', '--no-interaction', '--no-plugins', '--no-scripts']
        : process.env['AUTOMATED_API_RESOLVED_LOCKFILE']
          ? ['install', '--no-interaction', '--no-plugins', '--no-scripts']
          : ['update', exactDependency.name, '--with-dependencies', '--minimal-changes', '--no-interaction', '--no-plugins', '--no-scripts'],
      'ruby-bundler': exactDependency === undefined
        ? [`_${manager.version}_`, 'install', '--local']
        : [`_${manager.version}_`, 'update', exactDependency.name, '--local'],
      'swift-package': ['package', '--only-use-versions-from-resolved-file', 'resolve'],
      'dart-pub': ['pub', 'get', '--offline'],
      'elixir-mix': ['deps.get', '--only', 'test'],
      'clojure-tools-deps': ['-Soffline', '-P'],
      'clojure-leiningen': ['-o', 'deps'],
    }
    return { executable, args: args[manager.variant] ?? [], timeoutMs: 10 * 60 * 1000 }
  }
  const pythonRepository = preferredLanguage === 'python'
    || configuredPython
    || !(await pathExists(resolve(rootDir, 'package.json')))
  if (pythonRepository) {
    const packageManager = await detectPackageManager(rootDir, configuredPackageManagerOrLanguage)
    if (packageManager.variant === 'python-pip') {
      const wheelCache = process.env['AUTOMATED_API_PYTHON_WHEEL_CACHE']
        ?? '/opt/dependency-cache/python-wheels'
      const siteDirectory = process.env['AUTOMATED_API_PYTHON_SITE_DIRECTORY']
        ?? '/opt/dependency-cache/python-site'
      return {
        executable: process.env['AUTOMATED_API_PYTHON'] ?? 'python',
        args: [
          '-m', 'pip', '--isolated', 'install', '--no-user', '--no-index', '--find-links', wheelCache,
          '--only-binary=:all:', '--disable-pip-version-check', '--upgrade',
          '--target', siteDirectory,
          '-r', 'requirements.txt',
        ],
        timeoutMs: 5 * 60 * 1000,
      }
    }
    if (process.env['AUTOMATED_API_PYTHON_CERTIFIED_CACHE']) {
      return {
        executable: process.env['AUTOMATED_API_PYTHON'] ?? 'python',
        args: ['-I', '/opt/automated-api/scripts/lib/python-certified-environment.py', 'sync',
          process.env['AUTOMATED_API_PYTHON_CERTIFIED_CACHE'],
          CERTIFIED_PYTHON_UV_EXECUTABLE],
        timeoutMs: 5 * 60 * 1000,
      }
    }
    return {
      executable: 'uv',
      args: [
        // Skip every local workspace member. `--no-install-project` excludes
        // only the root and would still ask uv to build editable siblings,
        // executing customer build backends or failing under --no-build.
        'sync', '--offline', '--no-install-workspace', '--no-build',
        '--python', packageManager.pythonVersion!,
      ],
      timeoutMs: 5 * 60 * 1000,
    }
  }
  const lockfiles = await presentLockfiles(rootDir)
  // Credentialless unit fixtures without dependency state can still exercise
  // source-only recipes. The hosted Action rejects this before execution.
  if (lockfiles.length === 0) return undefined
  const packageManager = await detectPackageManager(rootDir, configuredPackageManagerOrLanguage)
  switch (packageManager.variant) {
    case 'npm':
      return {
        executable: 'node',
        args: [
          '/opt/dependency-cache/npm-manager/node_modules/npm/bin/npm-cli.js',
          'install', '--offline', '--include=dev', '--ignore-scripts', '--no-audit', '--no-fund',
        ],
        timeoutMs: 5 * 60 * 1000,
      }
    case 'pnpm':
      return {
        executable: 'corepack',
        // Docker's --network none is the security boundary. pnpm --offline
        // rejects some Git-hosted tarballs even after a networked install has
        // populated the content-addressable store; --prefer-offline reuses
        // that store and still fails closed if any real fetch is attempted.
        args: ['pnpm', 'install', '--prefer-offline', '--prod=false', '--no-frozen-lockfile', '--ignore-scripts'],
        timeoutMs: 5 * 60 * 1000,
      }
    case 'yarn-classic':
      return {
        executable: 'corepack',
        args: [
          'yarn', 'install', '--offline', '--production=false', '--ignore-scripts',
          '--cache-folder', '/opt/dependency-cache/yarn-classic',
        ],
        timeoutMs: 5 * 60 * 1000,
      }
    case 'yarn-berry':
      return {
        executable: 'corepack',
        // The containing proposal container has --network none and
        // YARN_ENABLE_NETWORK=0. --immutable cannot be used here because the
        // reviewed migration intentionally changes package.json and its lock.
        args: ['yarn', 'install', '--mode=skip-build'],
        timeoutMs: 5 * 60 * 1000,
      }
  }
}

function gradlePrefetchDependencyTasks(): string[] {
  const projects = process.env['AUTOAPI_GRADLE_PREFETCH_PROJECTS']?.trim()
  if (projects === undefined || projects === '' || projects === '*') {
    return ['autoApiPrefetchDependencies']
  }
  return projects.split(',').map(project => {
    const normalized = project.trim().replace(/:+$/u, '')
    return normalized === ''
      ? ':autoApiPrefetchDependencies'
      : `${normalized}:autoApiPrefetchDependencies`
  })
}

function vcpkgOfflineInstallArguments(): string[] {
  return [
    'install', '--x-manifest-root=/opt/dependency-source',
    '--x-install-root=/opt/dependency-cache/vcpkg-prefetch-installed',
    '--downloads-root=/opt/dependency-cache/vcpkg-downloads',
    '--x-buildtrees-root=/opt/dependency-cache/vcpkg-buildtrees',
    '--binarysource=clear;files,/opt/dependency-cache/vcpkg-binary,read',
  ]
}

export async function dependencyLockfileVerificationCommand(
  rootDir: string,
  configuredPackageManager?: string,
  reviewedJvmContext?: ReviewedJvmContext,
): Promise<CommandSpec | undefined> {
  if ((configuredPackageManager !== undefined && (configuredPackageManager === 'c' || configuredPackageManager === 'cpp'
    || VCPKG_PACKAGE_MANAGER_PATTERN.test(configuredPackageManager)))
    || await pathExists(resolve(rootDir, 'vcpkg.json'))) {
    await detectPackageManager(rootDir, configuredPackageManager ?? 'cpp')
    return {
      executable: process.env['AUTOMATED_API_VCPKG'] ?? '/opt/dependency-cache/vcpkg/vcpkg',
      args: [...vcpkgOfflineInstallArguments(), '--dry-run'],
      timeoutMs: 15 * 60 * 1000,
    }
  }
  const managedLanguage = isManagedRepositoryLanguage(configuredPackageManager)
    ? configuredPackageManager
    : await managedLanguageForSpec(rootDir, configuredPackageManager)
  if (managedLanguage || await hasManagedManifest(rootDir)) {
    const manager = await detectPackageManager(rootDir, configuredPackageManager ?? managedLanguage,
      reviewedJvmContext === undefined ? {} : { reviewedJvmContext })
    const executable = manager.wrapperExecutable ?? (process.platform === 'win32'
      ? manager.variant === 'jvm-maven' ? 'mvnw.cmd' : manager.variant === 'jvm-gradle' ? 'gradlew.bat' : managedExecutable(manager.variant)
      : manager.variant === 'jvm-maven' ? './mvnw' : manager.variant === 'jvm-gradle' ? './gradlew' : managedExecutable(manager.variant))
    const args: Partial<Record<PackageManagerVariant, string[]>> = {
      'jvm-maven': ['-o', ...await reviewedKotlinMavenArguments(rootDir, reviewedJvmContext), '-DskipTests', 'dependency:go-offline'],
      'jvm-gradle': [
        '--offline', '-Pkotlin.compiler.execution.strategy=in-process', '--init-script',
        '/opt/autoapi-runtime/gradle-dependency-prefetch.init.gradle',
        ...gradlePrefetchDependencyTasks(),
      ],
      'scala-sbt': ['launch', '--mode', 'offline', `sbt:${manager.version}`, '--', 'update'],
      'dotnet-nuget': [
        'restore', '--locked-mode', '--ignore-failed-sources',
        '-p:EnableWindowsTargeting=true',
      ],
      'php-composer': ['install', '--dry-run', '--no-interaction', '--no-plugins', '--no-scripts'],
      'ruby-bundler': [`_${manager.version}_`, 'check'],
      'swift-package': ['package', '--only-use-versions-from-resolved-file', 'show-dependencies'],
      'dart-pub': ['pub', 'get', '--offline'],
      'elixir-mix': ['deps.get', '--only', 'test'],
      'clojure-tools-deps': ['-Soffline', '-P'],
      'clojure-leiningen': ['-o', 'deps'],
    }
    return { executable, args: args[manager.variant] ?? [], timeoutMs: 10 * 60 * 1000 }
  }
  if ((configuredPackageManager !== undefined && /^cargo@/iu.test(configuredPackageManager))
    || await pathExists(resolve(rootDir, 'Cargo.toml'))) {
    await detectPackageManager(rootDir, configuredPackageManager ?? 'rust')
    return {
      executable: 'cargo', args: ['metadata', '--frozen', '--format-version', '1', '--no-deps'],
      timeoutMs: 5 * 60 * 1000,
    }
  }
  if ((configuredPackageManager !== undefined && /^go@/iu.test(configuredPackageManager))
    || await pathExists(resolve(rootDir, 'go.mod'))) {
    await detectPackageManager(rootDir, configuredPackageManager ?? 'go')
    return {
      executable: 'go', args: ['mod', 'verify'], timeoutMs: 5 * 60 * 1000,
    }
  }
  if (
    (configuredPackageManager !== undefined && /^(?:pip|uv|python)@/iu.test(configuredPackageManager))
    || !(await pathExists(resolve(rootDir, 'package.json')))
  ) return undefined
  const packageManager = await detectPackageManager(rootDir, configuredPackageManager)
  if (packageManager.variant !== 'pnpm') return undefined
  return {
    executable: 'corepack',
    args: ['pnpm', 'install', '--prefer-offline', '--prod=false', '--frozen-lockfile', '--ignore-scripts'],
    timeoutMs: 5 * 60 * 1000,
  }
}

function isRepositoryLanguage(value: string | undefined): value is 'javascript' | 'typescript' | 'python' | 'rust' | 'go' | 'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure' | 'c' | 'cpp' {
  return value === 'javascript' || value === 'typescript' || value === 'python'
    || value === 'rust' || value === 'go' || value === 'java' || value === 'kotlin' || value === 'scala'
    || value === 'csharp' || value === 'php' || value === 'ruby' || value === 'swift' || value === 'dart' || value === 'elixir' || value === 'clojure'
    || value === 'c' || value === 'cpp'
}

function managedExecutable(variant: PackageManagerVariant): string {
  if (variant === 'scala-sbt') return 'cs'
  if (variant === 'dotnet-nuget') return 'dotnet'
  if (variant === 'php-composer') return 'composer'
  if (variant === 'ruby-bundler') return 'bundle'
  if (variant === 'swift-package') return 'swift'
  if (variant === 'dart-pub') return 'dart'
  if (variant === 'elixir-mix') return 'mix'
  if (variant === 'clojure-tools-deps') return 'clojure'
  if (variant === 'clojure-leiningen') return 'lein'
  throw new Error(`no managed executable for ${variant}`)
}

async function hasManagedManifest(rootDir: string): Promise<boolean> {
  return await pathExists(resolve(rootDir, 'pom.xml')) || await pathExists(resolve(rootDir, 'build.gradle'))
    || await pathExists(resolve(rootDir, 'build.gradle.kts')) || await pathExists(resolve(rootDir, 'build.sbt'))
    || await topLevelHasExtension(rootDir, '.csproj')
    || await pathExists(resolve(rootDir, 'composer.json')) || await pathExists(resolve(rootDir, 'Gemfile'))
    || await pathExists(resolve(rootDir, 'Package.swift')) || await pathExists(resolve(rootDir, 'pubspec.yaml'))
    || await pathExists(resolve(rootDir, 'mix.exs'))
    || await pathExists(resolve(rootDir, 'deps.edn')) || await pathExists(resolve(rootDir, 'project.clj'))
}

interface SafeManagedDependencyMigration {
  ecosystem: 'maven' | 'nuget' | 'composer' | 'gem' | 'swiftpm' | 'pub' | 'hex'
  name: string
  oldVersion: string
  newVersion: string
}

function safeManagedDependencyMigrations(event: MigrationJob['changeEvent']): SafeManagedDependencyMigration[] {
  if (!['verified', 'probable'].includes(event.verificationStatus)
    || event.affectedLanguages.length !== 1 || !isManagedRepositoryLanguage(event.affectedLanguages[0])
    || event.affectedDependencies.length === 0) return []
  const exactVersion = /^\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?$/u
  if (event.affectedDependencies.length === 1) {
    if (!exactVersion.test(event.oldVersion) || !exactVersion.test(event.newVersion)) return []
    const dependency = event.affectedDependencies[0]!
    if (!['maven', 'nuget', 'composer', 'gem', 'swiftpm', 'pub', 'hex'].includes(dependency.ecosystem)) return []
    if (dependency.newVersion !== undefined && dependency.newVersion !== event.newVersion) return []
    return [{
      ecosystem: dependency.ecosystem as SafeManagedDependencyMigration['ecosystem'],
      name: dependency.name, oldVersion: event.oldVersion, newVersion: event.newVersion,
    }]
  }
  if (event.affectedLanguages[0] !== 'csharp') return []
  const names = new Set<string>()
  const migrations: SafeManagedDependencyMigration[] = []
  for (const dependency of event.affectedDependencies) {
    const normalizedName = dependency.name.toLowerCase()
    if (dependency.ecosystem !== 'nuget'
      || dependency.oldVersionRange === undefined || !exactVersion.test(dependency.oldVersionRange)
      || dependency.newVersion === undefined || !exactVersion.test(dependency.newVersion)
      || dependency.newArtifactSha256 === undefined
      || !event.evidence.some(item => item.contentHash === dependency.newArtifactSha256)
      || names.has(normalizedName)) return []
    names.add(normalizedName)
    migrations.push({
      ecosystem: 'nuget', name: dependency.name,
      oldVersion: dependency.oldVersionRange, newVersion: dependency.newVersion,
    })
  }
  return migrations
}

function isManagedRepositoryLanguage(value: string | undefined): value is 'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure' {
  return value === 'java' || value === 'kotlin' || value === 'scala' || value === 'csharp' || value === 'php'
    || value === 'ruby' || value === 'swift' || value === 'dart' || value === 'elixir' || value === 'clojure'
}

async function presentLockfiles(
  rootDir: string,
): Promise<Array<PackageManagerPlan['lockfile']>> {
  const lockfiles: Array<PackageManagerPlan['lockfile']> = [
    'package-lock.json',
    'pnpm-lock.yaml',
    'yarn.lock',
  ]
  const present: Array<PackageManagerPlan['lockfile']> = []
  for (const lockfile of lockfiles) {
    try {
      await access(resolve(rootDir, lockfile))
      present.push(lockfile)
    } catch (error) {
      if (!isMissingPath(error)) throw error
    }
  }
  return present
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch (error) {
    if (isMissingPath(error)) return false
    throw error
  }
}

async function topLevelHasExtension(rootDir: string, extension: string): Promise<boolean> {
  return (await readdir(rootDir, { withFileTypes: true })).some(entry => entry.isFile() && entry.name.endsWith(extension))
}

async function repositoryContainsExtension(rootDir: string, extension: string): Promise<boolean> {
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    if (entry.isFile() && entry.name.endsWith(extension)) return true
    if (entry.isDirectory() && !MANIFEST_SCAN_EXCLUDED.has(entry.name)
      && await repositoryContainsExtension(resolve(rootDir, entry.name), extension)) return true
  }
  return false
}

function isFirecrawlMigration(event: MigrationJob['changeEvent']): boolean {
  return event.provider === 'firecrawl'
    && event.oldVersion.toLowerCase() === 'v1'
    && event.newVersion.toLowerCase() === 'v2'
    && (
      event.recipeIds.includes(FIRECRAWL_V1_V2_RECIPE_ID)
      || event.operations.some(operation =>
        operation.oldSymbol === 'scrapeUrl'
        || operation.oldSymbol === 'crawlUrl'
        || operation.kind === 'endpoint_version_changed',
      )
    )
}

function isSentryMigration(event: MigrationJob['changeEvent']): boolean {
  return event.provider === 'sentry'
    && event.oldVersion === '7.120.4'
    && event.newVersion === '8.0.0'
    && event.affectedPackages.length === 1
    && event.affectedPackages[0] === '@sentry/core'
}

function safeGenericDependencyMigration(
  event: MigrationJob['changeEvent'],
): MigrationDependency | undefined {
  const npmDependencies = event.affectedDependencies.filter(dependency => dependency.ecosystem === 'npm')
  const explicitDependency = npmDependencies.length === 1 ? npmDependencies[0] : undefined
  if (explicitDependency === undefined) {
    if (event.verificationStatus !== 'verified'
      || event.affectedPackages.length !== 1
      || event.recipeIds.length > 0
      || declaredMajor(event.oldVersion) === undefined
      || !/^\d+\.\d+\.\d+$/u.test(event.newVersion)) return undefined
    return { name: event.affectedPackages[0]!, version: event.newVersion }
  }
  const legacyPackageMatches = event.affectedPackages.length === 0
    || (event.affectedPackages.length === 1 && event.affectedPackages[0] === explicitDependency.name)
  const oldVersionRange = explicitDependency.oldVersionRange ?? (
    event.affectedPackages.length === 1 ? event.oldVersion : undefined
  )
  const newVersion = explicitDependency.newVersion ?? (
    event.affectedPackages.length === 1 ? event.newVersion : undefined
  )
  if (
    event.verificationStatus !== 'verified'
    || !legacyPackageMatches
    || event.recipeIds.length > 0
    || oldVersionRange === undefined
    || declaredMajor(oldVersionRange) === undefined
    || newVersion === undefined
    || !/^\d+\.\d+\.\d+$/u.test(newVersion)
  ) return undefined
  return { name: explicitDependency.name, version: newVersion }
}

interface SafePythonDependencyMigration {
  name: string
  oldVersion: string
  newVersion: string
}

interface SafeNativeDependencyMigration {
  ecosystem: 'cargo' | 'gomod'
  name: string
  oldVersion: string
  newVersion: string
}

function safeNativeDependencyMigration(
  event: MigrationJob['changeEvent'],
): SafeNativeDependencyMigration | undefined {
  if (!['verified', 'probable'].includes(event.verificationStatus)
    || event.affectedLanguages.length !== 1
    || !isRustOnly(event) && !isGoOnly(event)
    || event.affectedDependencies.length !== 1) return undefined
  const dependency = event.affectedDependencies[0]!
  const ecosystem = isRustOnly(event) ? 'cargo' : 'gomod'
  const versionPattern = ecosystem === 'cargo'
    ? /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/u
    : /^v\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/u
  if (dependency.ecosystem !== ecosystem
    || !versionPattern.test(event.oldVersion)
    || !versionPattern.test(event.newVersion)
    || dependency.newVersion !== event.newVersion) return undefined
  return {
    ecosystem,
    name: dependency.name,
    oldVersion: event.oldVersion,
    newVersion: event.newVersion,
  }
}

function safePythonDependencyMigration(
  event: MigrationJob['changeEvent'],
): SafePythonDependencyMigration | undefined {
  if (!isPythonOnly(event)
    || !['verified', 'probable'].includes(event.verificationStatus)
    || event.affectedDependencies.length !== 1
    || !/^\d+\.\d+\.\d+$/u.test(event.oldVersion)
    || !/^\d+\.\d+\.\d+$/u.test(event.newVersion)) return undefined
  const dependency = event.affectedDependencies[0]!
  if (dependency.ecosystem !== 'pypi') return undefined
  if (dependency.oldVersionRange !== undefined
    && dependency.oldVersionRange !== event.oldVersion
    && dependency.oldVersionRange !== `==${event.oldVersion}`) return undefined
  if (dependency.newVersion !== undefined && dependency.newVersion !== event.newVersion) return undefined
  return { name: dependency.name, oldVersion: event.oldVersion, newVersion: event.newVersion }
}

async function migrateExactPythonDependency(
  rootDir: string,
  dependency: SafePythonDependencyMigration,
  job: MigrationJob,
): Promise<boolean> {
  const configured = job.policy.allowedManifestPaths
  if (configured === undefined || configured.length === 0) {
    throw new Error('Python Harness dependency migration requires explicit allowed manifest paths')
  }
  const workingDirectory = normalizeRepositoryPath(job.repository.workingDirectory ?? '.')
  const workingPrefix = workingDirectory === '.' ? '' : `${workingDirectory}/`
  const allowedFromWorkingDirectory = new Set(configured.flatMap((configuredPath) => {
    const repositoryPath = assertPathAllowed(configuredPath, job.policy)
    if (workingPrefix === '') return [repositoryPath]
    return repositoryPath.startsWith(workingPrefix)
      ? [repositoryPath.slice(workingPrefix.length)]
      : []
  }))
  const resolvedRoot = resolve(rootDir)
  const allowedUvLockPaths = new Set([...allowedFromWorkingDirectory]
    .filter(path => basename(path) === 'uv.lock')
    .map(path => resolve(resolvedRoot, ...path.split('/'))))
  const paths = (await repositoryManifestPaths(resolvedRoot)).filter((path) => {
    const localPath = relative(resolvedRoot, path).replaceAll('\\', '/')
    return allowedFromWorkingDirectory.has(localPath)
  })
  const updates: Array<{ path: string; content: string }> = []
  for (const path of paths) {
    const name = basename(path)
    const content = await readFile(path, 'utf8')
    if (/^requirements(?:[-_.].*)?\.txt$/iu.test(name)) {
      const updated = await updateExactHashedRequirement(content, dependency)
      if (updated !== content) updates.push({ path, content: updated })
    } else if (name === 'pyproject.toml') {
      const updated = await updatePythonProjectDependency(
        content, dependency, path, rootDir, allowedUvLockPaths,
      )
      if (updated !== content) updates.push({ path, content: updated })
    }
  }
  if (updates.length === 0) return false
  if (updates.length !== 1) {
    throw new Error('Python Harness dependency migration requires exactly one unambiguous manifest pin')
  }
  await writeFile(updates[0]!.path, updates[0]!.content, 'utf8')
  return true
}

async function updateExactHashedRequirement(
  content: string,
  dependency: SafePythonDependencyMigration,
): Promise<string> {
  const escapedName = pythonDistributionPattern(dependency.name)
  const pattern = new RegExp(
    `^(\\s*${escapedName}(?:\\[[^\\]]+\\])?==)${escapeRegex(dependency.oldVersion)}(.*)$`,
    'iu',
  )
  const lines = content.split(/(?<=\n)/u)
  const matches = lines.filter(line => pattern.test(line.replace(/\r?\n$/u, '')))
  if (matches.length === 0) return content
  if (matches.length !== 1 || !/--hash=sha256:[a-f0-9]{64}/iu.test(matches[0]!)) {
    throw new Error('Python Harness dependency migration requires one exact hash-locked requirement')
  }
  const targetHash = await targetWheelSha256(dependency.name, dependency.newVersion)
  return lines.map((line) => {
    const newline = line.endsWith('\n') ? '\n' : ''
    const value = newline === '' ? line : line.slice(0, -1).replace(/\r$/u, '')
    if (!pattern.test(value)) return line
    const versionUpdated = value.replace(pattern, `$1${dependency.newVersion}$2`)
    const withoutHashes = versionUpdated.replace(/\s+--hash=sha256:[a-f0-9]{64}/giu, '')
    const comment = withoutHashes.match(/\s+#/u)?.index
    const requirement = comment === undefined ? withoutHashes : withoutHashes.slice(0, comment)
    const suffix = comment === undefined ? '' : withoutHashes.slice(comment)
    return `${requirement.trimEnd()} --hash=sha256:${targetHash}${suffix}${newline}`
  }).join('')
}

function pythonDistributionPattern(value: string): string {
  return normalizePythonDistribution(value)
    .split('-')
    .map(escapeRegex)
    .join('[._-]+')
}

async function targetWheelSha256(name: string, version: string): Promise<string> {
  const directory = process.env['AUTOMATED_API_PYTHON_WHEEL_CACHE']
    ?? '/opt/dependency-cache/python-wheels'
  const prefix = `${normalizePythonDistribution(name).replaceAll('-', '_')}-${version}-`
  const candidates = (await readdir(directory))
    .filter(file => file.toLowerCase().startsWith(prefix.toLowerCase()) && file.endsWith('.whl'))
  if (candidates.length !== 1) {
    throw new Error('Python Harness dependency migration requires exactly one prefetched target wheel')
  }
  return createHash('sha256').update(await readFile(resolve(directory, candidates[0]!))).digest('hex')
}

async function migrateDependencyMajor(
  rootDir: string,
  name: string,
  oldVersion: string,
  newVersion: string,
): Promise<boolean> {
  const oldMajor = declaredMajor(oldVersion)
  if (oldMajor === undefined) return false
  const path = resolve(rootDir, 'package.json')
  const manifest = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[field]
    if (typeof dependencies !== 'object' || dependencies === null || Array.isArray(dependencies)) continue
    const values = dependencies as Record<string, unknown>
    const declared = values[name]
    if (typeof declared !== 'string' || declaredMajor(declared) !== oldMajor) continue
    values[name] = newVersion
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    return true
  }
  return false
}

async function migrateExactDependency(
  rootDir: string,
  name: string,
  oldVersion: string,
  newVersion: string,
): Promise<boolean> {
  const path = resolve(rootDir, 'package.json')
  const manifest = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[field]
    if (typeof dependencies !== 'object' || dependencies === null || Array.isArray(dependencies)) continue
    const values = dependencies as Record<string, unknown>
    if (values[name] !== oldVersion) continue
    values[name] = newVersion
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    return true
  }
  return false
}

async function detectNativePackageManager(
  rootDir: string,
  language: 'rust' | 'go',
  configuredPackageManager?: string,
): Promise<PackageManagerPlan> {
  const bootstrap = language === 'rust'
    ? TESTED_RUST_PACKAGE_MANAGERS[0]!
    : TESTED_GO_PACKAGE_MANAGERS[0]!
  const manifest = language === 'rust' ? 'Cargo.toml' : 'go.mod'
  if (!(await pathExists(resolve(rootDir, manifest)))) {
    throw new Error(`${language} repositories require ${manifest}`)
  }
  if (!(await pathExists(resolve(rootDir, bootstrap.lockfile)))) {
    throw new Error(`${language} repositories require ${bootstrap.lockfile}`)
  }
  const declared = configuredPackageManager ?? await declaredNativeToolchain(rootDir, language)
  const match = declared?.match(NATIVE_PACKAGE_MANAGER_PATTERN)
  if (match?.[1] !== bootstrap.name || match[2] === undefined) {
    throw new Error(`${language} repositories must select an exact ${bootstrap.name}@major.minor.patch toolchain`)
  }
  assertCertifiableMinorVersion(
    language,
    match[2],
    language === 'rust' ? CERTIFIABLE_VERSION_POLICY.rust : CERTIFIABLE_VERSION_POLICY.go,
  )
  return {
    name: bootstrap.name,
    version: match[2],
    spec: `${bootstrap.name}@${match[2]}`,
    variant: bootstrap.variant,
    lockfile: bootstrap.lockfile,
    language,
  }
}

interface SafeCppDependencyMigration {
  ecosystem: 'vcpkg'
  name: string
  oldVersion: string
  newVersion: string
  newArtifactSha256: string
}

function safeCppDependencyMigrations(
  event: MigrationJob['changeEvent'],
): SafeCppDependencyMigration[] {
  if (event.verificationStatus !== 'verified'
    || !isCOrCppOnly(event)
    || !/^\d+\.\d+\.\d+$/u.test(event.oldVersion)
    || !/^\d+\.\d+\.\d+$/u.test(event.newVersion)
    || event.affectedDependencies.length === 0) return []
  const primary = event.affectedDependencies[0]
  if (primary?.ecosystem !== 'vcpkg'
    || primary.oldVersionRange?.replace(/#\d+$/u, '') !== event.oldVersion
    || primary.newVersion !== event.newVersion) return []
  const names = new Set<string>()
  const migrations: SafeCppDependencyMigration[] = []
  for (const dependency of event.affectedDependencies) {
    const oldVersion = dependency.oldVersionRange?.replace(/#\d+$/u, '')
    const newVersion = dependency.newVersion
    const normalized = dependency.name.toLowerCase()
    if (dependency.ecosystem !== 'vcpkg' || oldVersion === undefined || newVersion === undefined
      || !/^\d+\.\d+\.\d+$/u.test(oldVersion) || !/^\d+\.\d+\.\d+$/u.test(newVersion)
      || names.has(normalized) || dependency.newArtifactSha256 === undefined
      || !event.evidence.some(item => item.contentHash === dependency.newArtifactSha256)) return []
    names.add(normalized)
    migrations.push({ ecosystem: 'vcpkg', name: dependency.name, oldVersion, newVersion,
      newArtifactSha256: dependency.newArtifactSha256 })
  }
  return migrations
}

async function detectVcpkgPackageManager(
  rootDir: string,
  language: 'c' | 'cpp' | undefined,
  configuredPackageManager?: string,
): Promise<PackageManagerPlan> {
  const path = resolve(rootDir, 'vcpkg.json')
  const label = language === 'c' ? 'C' : language === 'cpp' ? 'C++' : 'C/C++'
  if (!(await pathExists(path))) throw new Error(`${label} vcpkg repositories require vcpkg.json`)
  const content = await readFile(path, 'utf8')
  const parsed = parseVcpkgManifest(content, path)
  const manifest = JSON.parse(content) as Record<string, unknown>
  const embeddedConfiguration = recordValue(manifest['vcpkg-configuration'])
  const configurationPath = resolve(rootDir, 'vcpkg-configuration.json')
  const fileConfiguration = await readVcpkgConfiguration(configurationPath)
  if (embeddedConfiguration !== undefined && fileConfiguration !== undefined) {
    throw new Error(`${label} certification requires one vcpkg registry configuration source`)
  }
  const configuration = embeddedConfiguration ?? fileConfiguration
  assertBuiltinVcpkgRegistry(configuration)
  const configuredBaseline = recordValue(configuration?.['default-registry'])?.['baseline']
  const baseline = parsed.baseline ?? (typeof configuredBaseline === 'string' ? configuredBaseline : undefined)
  if (baseline === undefined || !/^[a-f0-9]{40}$/u.test(baseline)) {
    throw new Error('vcpkg.json must pin one lowercase 40-character builtin baseline')
  }
  const plan = TESTED_VCPKG_PACKAGE_MANAGERS.find(candidate => candidate.version === baseline
    && (language === undefined || candidate.language === language))
  if (plan === undefined) throw new Error(`vcpkg baseline ${baseline} has not passed offline certification`)
  if (configuredPackageManager !== undefined && configuredPackageManager !== plan.spec) {
    throw new Error('configured packageManager does not match repository vcpkg baseline')
  }
  return { ...plan }
}

async function readVcpkgConfiguration(path: string): Promise<Record<string, unknown> | undefined> {
  if (!(await pathExists(path))) return undefined
  let value: unknown
  try {
    value = JSON.parse(await readFile(path, 'utf8'))
  } catch {
    throw new Error('invalid vcpkg-configuration.json while selecting the certified toolchain')
  }
  const configuration = recordValue(value)
  if (configuration === undefined) throw new Error('vcpkg-configuration.json must contain an object')
  return configuration
}

function assertBuiltinVcpkgRegistry(configuration: Record<string, unknown> | undefined): void {
  const registries = configuration?.['registries']
  if (registries !== undefined) {
    if (!Array.isArray(registries)) throw new Error('vcpkg registries configuration must be an array')
    if (registries.length > 0) {
      throw new Error('C++ certification does not execute repository-defined vcpkg registries')
    }
  }
  const configuredDefault = configuration?.['default-registry']
  if (configuredDefault !== undefined) {
    const defaultRegistry = recordValue(configuredDefault)
    if (defaultRegistry === undefined || defaultRegistry['kind'] !== 'builtin') {
      throw new Error('C++ certification requires the builtin vcpkg registry')
    }
  }
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

async function detectManagedPackageManager(
  rootDir: string,
  preferredLanguage?: 'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure',
  configuredPackageManager?: string,
  reviewedJvmContext?: ReviewedJvmContext,
): Promise<PackageManagerPlan> {
  const inferred = preferredLanguage ?? await managedLanguageForSpec(rootDir, configuredPackageManager)
  if (!inferred) throw new Error('managed repository requires an explicit supported language or package manager')
  let name: Extract<SupportedPackageManager, 'maven' | 'gradle' | 'sbt' | 'dotnet' | 'composer' | 'bundler' | 'swift' | 'dart' | 'mix' | 'clojure' | 'leiningen'>
  let version: string | undefined
  let lockfile: PackageManagerPlan['lockfile']
  let variant: PackageManagerVariant
  let runtimeVersion: string | undefined
  let scalaVersion: string | undefined
  let coursierVersion: string | undefined
  let wrapperExecutable: string | undefined
  let reviewedJvm: ReviewedJvmToolchainReceipt | undefined
  if (inferred === 'clojure') {
    const toolsDeps = await pathExists(resolve(rootDir, 'deps.edn'))
    const lein = await pathExists(resolve(rootDir, 'project.clj'))
    const configuredName = configuredPackageManager?.match(MANAGED_PACKAGE_MANAGER_PATTERN)?.[1]?.toLowerCase()
    if (!toolsDeps && !lein) throw new Error('Clojure repositories require deps.edn or project.clj')
    if (toolsDeps && lein && configuredName !== 'clojure' && configuredName !== 'leiningen') {
      throw new Error('Clojure repositories with deps.edn and project.clj must select clojure or leiningen explicitly')
    }
    const useLein = configuredName === 'leiningen' || (!toolsDeps && lein)
    const baseline = TESTED_MANAGED_PACKAGE_MANAGERS.find(plan => plan.variant === (useLein ? 'clojure-leiningen' : 'clojure-tools-deps'))!
    name = baseline.name as 'clojure' | 'leiningen'
    variant = baseline.variant
    lockfile = baseline.lockfile
    const versionFile = resolve(rootDir, useLein ? '.lein-version' : '.clojure-cli-version')
    version = await pathExists(versionFile) ? (await readFile(versionFile, 'utf8')).trim() : baseline.version
    const runtimeFile = resolve(rootDir, '.clojure-version')
    runtimeVersion = await pathExists(runtimeFile)
      ? (await readFile(runtimeFile, 'utf8')).trim()
      : await declaredClojureRuntime(rootDir, useLein ? 'project.clj' : 'deps.edn') ?? baseline.runtimeVersion
  } else if (inferred === 'scala') {
    name = 'sbt'; variant = 'scala-sbt'; lockfile = 'build.sbt'
    const properties = await readFile(resolve(rootDir, 'project/build.properties'), 'utf8')
    version = properties.match(/^sbt\.version\s*=\s*(\d+\.\d+\.\d+)\s*$/mu)?.[1]
    const build = await readFile(resolve(rootDir, 'build.sbt'), 'utf8')
    scalaVersion = build.match(/(?:ThisBuild\s*\/\s*)?scalaVersion\s*:?=\s*["'](\d+\.\d+\.\d+)["']/u)?.[1]
    const javaVersion = await readJvmMetadata(rootDir, '.java-version')
    if (javaVersion === undefined) reviewedJvm = await reviewedJvmToolchain(rootDir, reviewedJvmContext)
    runtimeVersion = javaVersion === undefined ? reviewedJvm!.javaVersion : javaVersion.trim()
    coursierVersion = TESTED_MANAGED_PACKAGE_MANAGERS.find(plan => plan.variant === 'scala-sbt')!.coursierVersion
    if (!scalaVersion) throw new Error('Scala repositories must pin an exact scalaVersion in build.sbt')
  } else if (inferred === 'java' || inferred === 'kotlin') {
    const wrapper = await findJvmWrapper(rootDir, configuredPackageManager)
    const wrapperRoot = wrapper?.root ?? rootDir
    wrapperExecutable = wrapperExecutableForManagedRoot(rootDir, wrapper)
    const gradle = wrapper?.variant === 'jvm-gradle'
    const javaVersion = await readJvmMetadata(wrapperRoot, '.java-version')
    if (javaVersion !== undefined) {
      runtimeVersion = javaVersion.trim()
    } else if (gradle) {
      const daemonProperties = await readFile(resolve(wrapperRoot, 'gradle/gradle-daemon-jvm.properties'), 'utf8')
      runtimeVersion = daemonProperties.match(/^toolchainVersion=(\d+(?:\.\d+\.\d+)?)$/mu)?.[1]
    } else {
      reviewedJvm = await reviewedJvmToolchain(rootDir, reviewedJvmContext)
      runtimeVersion = reviewedJvm.javaVersion
    }
    if (gradle) {
      name = 'gradle'; variant = 'jvm-gradle'; lockfile = 'gradle.lockfile'
      const properties = await readFile(resolve(wrapperRoot, 'gradle/wrapper/gradle-wrapper.properties'), 'utf8')
      version = properties.match(/distributionUrl=.*gradle-(\d+\.\d+\.\d+)-/u)?.[1]
      if (!/^distributionSha256Sum=[a-f0-9]{64}$/mu.test(properties)) throw new Error('Gradle wrapper requires distributionSha256Sum')
    } else {
      name = 'maven'; variant = 'jvm-maven'; lockfile = 'pom.xml'
      const properties = await readJvmMetadata(wrapperRoot, '.mvn/wrapper/maven-wrapper.properties')
      if (properties === undefined) {
        reviewedJvm ??= await reviewedJvmToolchain(rootDir, reviewedJvmContext)
        if (reviewedJvm.wrapper === undefined || !reviewedJvm.managerSpec.startsWith('maven@')) {
          throw new Error('Missing Maven wrapper metadata has no reviewed wrapper authority')
        }
        version = reviewedJvm.managerSpec.slice('maven@'.length)
      } else {
        version = properties.match(/distributionUrl=.*apache-maven-(\d+\.\d+\.\d+)-bin/u)?.[1]
        if (!/^distributionSha256Sum=[a-f0-9]{64}$/mu.test(properties)) throw new Error('Maven wrapper requires distributionSha256Sum')
      }
    }
  } else if (inferred === 'csharp') {
    name = 'dotnet'; variant = 'dotnet-nuget'; lockfile = 'packages.lock.json'
    const global = JSON.parse(await readFile(resolve(rootDir, 'global.json'), 'utf8')) as { sdk?: { version?: unknown; rollForward?: unknown } }
    version = typeof global.sdk?.version === 'string' ? global.sdk.version : undefined
    runtimeVersion = version
    if (global.sdk?.rollForward !== 'disable') throw new Error('global.json must set sdk.rollForward to disable')
  } else if (inferred === 'php') {
    name = 'composer'; variant = 'php-composer'; lockfile = 'composer.lock'
    version = (await readFile(resolve(rootDir, '.composer-version'), 'utf8')).trim()
    runtimeVersion = (await readFile(resolve(rootDir, '.php-version'), 'utf8')).trim()
  } else if (inferred === 'ruby') {
    name = 'bundler'; variant = 'ruby-bundler'; lockfile = 'Gemfile.lock'
    const lock = await readFile(resolve(rootDir, 'Gemfile.lock'), 'utf8')
    version = lock.match(/\nBUNDLED WITH\n\s+(\d+\.\d+\.\d+)\s*$/u)?.[1]
    runtimeVersion = (await readFile(resolve(rootDir, '.ruby-version'), 'utf8')).trim()
  } else if (inferred === 'swift') {
    name = 'swift'; variant = 'swift-package'; lockfile = 'Package.resolved'
    const versionFile = resolve(rootDir, '.swift-version')
    // An absent optional version file may use the explicitly selected certified
    // runtime; a present file remains authoritative and must pass the checks below.
    const versionMarker = await lstat(versionFile).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error
      return undefined
    })
    if (versionMarker !== undefined && !versionMarker.isFile()) {
      throw new Error('Swift version marker must be a regular file, not a symlink or directory')
    }
    version = versionMarker !== undefined
      ? (await readFile(versionFile, 'utf8')).trim()
      : TESTED_MANAGED_PACKAGE_MANAGERS.find(plan => plan.variant === 'swift-package'
        && plan.spec === configuredPackageManager)?.version
    runtimeVersion = version
  } else if (inferred === 'dart') {
    name = 'dart'; variant = 'dart-pub'; lockfile = 'pubspec.lock'
    const versionFile = resolve(rootDir, '.dart-version')
    version = await pathExists(versionFile)
      ? (await readFile(versionFile, 'utf8')).trim()
      : configuredPackageManager?.match(MANAGED_PACKAGE_MANAGER_PATTERN)?.[2]
    runtimeVersion = version
  } else {
    name = 'mix'; variant = 'elixir-mix'; lockfile = 'mix.lock'
    const toolVersions = await readFile(resolve(rootDir, '.tool-versions'), 'utf8')
    const elixir = toolVersions.match(/^elixir\s+(\d+\.\d+\.\d+)(?:-otp-(\d+))?\s*$/mu)
    const erlang = toolVersions.match(/^erlang\s+(\d+\.\d+\.\d+(?:\.\d+)?)\s*$/mu)
    version = elixir?.[1]
    runtimeVersion = version
    const otpMajor = erlang?.[1]?.split('.')[0]
    if (!erlang?.[1] || !elixir?.[2] || elixir[2] !== otpMajor) {
      throw new Error('Elixir .tool-versions must pin matching exact elixir-otp and erlang runtimes')
    }
    if (!/^\d+\.\d+\.\d+(?:\.\d+)?$/u.test(erlang[1])) {
      throw new Error('Elixir .tool-versions must pin an exact Erlang runtime')
    }
    const erlangVersion = erlang[1]
    const certified = TESTED_MANAGED_PACKAGE_MANAGERS.find(plan => plan.variant === 'elixir-mix'
      && plan.version === version && plan.erlangVersion === erlangVersion)
    if (certified === undefined) {
      throw new Error(`unsupported certified Elixir/OTP runtime ${version}/${erlangVersion}`)
    }
    if ([
      certified.hexVersion, certified.hexArchiveUrl, certified.hexArchiveSha512,
      certified.rebar3Version, certified.rebar3ArchiveUrl, certified.rebar3ArchiveSha512,
    ].some(value => value === undefined || value === '')) {
      throw new Error('certified Elixir runtime is missing immutable Hex or Rebar3 metadata')
    }
    if (!(await pathExists(resolve(rootDir, lockfile)))) throw new Error(`${name} repositories require ${lockfile}`)
    if (!version || !EXACT_VERSION_PATTERN.test(version)) throw new Error('mix repository must pin an exact major.minor.patch toolchain')
    if (configuredPackageManager !== undefined && configuredPackageManager !== `${name}@${version}`) {
      throw new Error(`configured packageManager does not match repository ${name} toolchain`)
    }
    return {
      name, version, spec: `${name}@${version}`, variant, lockfile, language: inferred,
      runtimeVersion: version, erlangVersion,
      hexVersion: certified.hexVersion!,
      hexArchiveUrl: certified.hexArchiveUrl!,
      hexArchiveSha512: certified.hexArchiveSha512!,
      rebar3Version: certified.rebar3Version!,
      rebar3ArchiveUrl: certified.rebar3ArchiveUrl!,
      rebar3ArchiveSha512: certified.rebar3ArchiveSha512!,
    }
  }
  const exactManagerVersion = inferred === 'clojure' ? /^\d+\.\d+\.\d+(?:\.\d+)?$/u : EXACT_VERSION_PATTERN
  if (!version || !exactManagerVersion.test(version)) throw new Error(`${name} repository must select an exact toolchain version`)
  const pinnedJvmMajor = (inferred === 'java' || inferred === 'kotlin') && /^\d+$/u.test(runtimeVersion ?? '')
  if (!runtimeVersion || (!EXACT_VERSION_PATTERN.test(runtimeVersion) && !pinnedJvmMajor)) {
    throw new Error(`${inferred} repository must pin an exact major.minor.patch language runtime`)
  }
  if (configuredPackageManager !== undefined && configuredPackageManager !== `${name}@${version}`) {
    throw new Error(`configured packageManager does not match repository ${name} toolchain`)
  }
  if (variant === 'dotnet-nuget') {
    const lockfiles = await repositoryFilesNamed(resolve(rootDir), 'packages.lock.json')
    if (lockfiles.length === 0) throw new Error('dotnet repositories require packages.lock.json')
    const rootLockfile = resolve(rootDir, 'packages.lock.json')
    lockfile = lockfiles.length === 1 && lockfiles[0] === rootLockfile ? 'packages.lock.json' : '.'
  } else if (!(await pathExists(resolve(rootDir, lockfile)))) {
    throw new Error(`${name} repositories require ${lockfile}`)
  }
  if (variant === 'jvm-gradle') await assertGradleDependencyLocking(rootDir)
  if (variant === 'dotnet-nuget') await assertNugetLockedMode(rootDir)
  return {
    name, version, spec: `${name}@${version}`, variant, lockfile, language: inferred, runtimeVersion,
    ...(wrapperExecutable === undefined ? {} : { wrapperExecutable }),
    ...(scalaVersion === undefined ? {} : { scalaVersion }),
    ...(coursierVersion === undefined ? {} : { coursierVersion }),
    ...(reviewedJvm === undefined ? {} : { reviewedJvmToolchain: reviewedJvm }),
  }
}

interface JvmWrapper {
  root: string
  variant: 'jvm-maven' | 'jvm-gradle'
  executable: string
}

async function findJvmWrapper(
  rootDir: string,
  configuredPackageManager?: string,
): Promise<JvmWrapper | undefined> {
  const configuredName = configuredPackageManager?.match(MANAGED_PACKAGE_MANAGER_PATTERN)?.[1]?.toLowerCase()
  let current = resolve(rootDir)
  while (true) {
    const mavenExecutable = process.platform === 'win32' ? 'mvnw.cmd' : 'mvnw'
    const gradleExecutable = process.platform === 'win32' ? 'gradlew.bat' : 'gradlew'
    const hasMaven = await pathExists(resolve(current, mavenExecutable))
      || await pathExists(resolve(current, '.mvn/wrapper/maven-wrapper.properties'))
    const hasGradle = await pathExists(resolve(current, gradleExecutable))
      || await pathExists(resolve(current, 'gradle/wrapper/gradle-wrapper.properties'))
    if (configuredName === 'maven' && hasMaven) {
      return { root: current, variant: 'jvm-maven', executable: mavenExecutable }
    }
    if (configuredName === 'gradle' && hasGradle) {
      return { root: current, variant: 'jvm-gradle', executable: gradleExecutable }
    }
    if (configuredName === undefined) {
      if (hasGradle) return { root: current, variant: 'jvm-gradle', executable: gradleExecutable }
      if (hasMaven) return { root: current, variant: 'jvm-maven', executable: mavenExecutable }
    }
    const parent = dirname(current)
    if (await pathExists(resolve(current, '.git')) || parent === current) return undefined
    current = parent
  }
}

function wrapperExecutableForManagedRoot(
  rootDir: string,
  wrapper: JvmWrapper | undefined,
): string | undefined {
  if (wrapper === undefined) return undefined
  const executable = relative(resolve(rootDir), resolve(wrapper.root, wrapper.executable)).replaceAll('\\', '/')
  return executable.startsWith('.') ? executable : `./${executable}`
}

async function declaredClojureRuntime(rootDir: string, manifest: 'deps.edn' | 'project.clj'): Promise<string | undefined> {
  const content = await readFile(resolve(rootDir, manifest), 'utf8')
  return manifest === 'deps.edn'
    ? content.match(/org\.clojure\/clojure\s+\{[^{}]*:mvn\/version\s+["'](\d+\.\d+\.\d+)["']/u)?.[1]
    : content.match(/\[org\.clojure\/clojure\s+["'](\d+\.\d+\.\d+)["']/u)?.[1]
}

async function managedLanguageForSpec(
  rootDir: string,
  spec: string | undefined,
): Promise<'java' | 'kotlin' | 'scala' | 'csharp' | 'php' | 'ruby' | 'swift' | 'dart' | 'elixir' | 'clojure' | undefined> {
  const name = spec?.match(MANAGED_PACKAGE_MANAGER_PATTERN)?.[1]?.toLowerCase()
  if (name === 'maven' || name === 'gradle') {
    return await repositoryContainsExtension(rootDir, '.kt') ? 'kotlin' : 'java'
  }
  if (name === 'sbt') return 'scala'
  if (name === 'dotnet') return 'csharp'
  if (name === 'composer') return 'php'
  if (name === 'bundler') return 'ruby'
  if (name === 'swift') return 'swift'
  if (name === 'dart') return 'dart'
  if (name === 'mix') return 'elixir'
  if (name === 'clojure' || name === 'leiningen') return 'clojure'
  return undefined
}

async function assertGradleDependencyLocking(rootDir: string): Promise<void> {
  const buildLogic = await gradleBuildLogicPaths(rootDir)
  const locksAllConfigurations = (await Promise.all(buildLogic.map(file => readFile(file, 'utf8'))))
    .some(content => /(?:project\.)?dependencyLocking\s*\{/u.test(content)
      && /lockAllConfigurations\s*\(/u.test(content))
  if (!locksAllConfigurations) {
    throw new Error('Gradle repositories must lock all configurations')
  }
}

async function gradleBuildLogicPaths(rootDir: string): Promise<string[]> {
  const paths: string[] = []
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    const path = resolve(rootDir, entry.name)
    if (entry.isDirectory() && !MANIFEST_SCAN_EXCLUDED.has(entry.name)) {
      paths.push(...await gradleBuildLogicPaths(path))
    } else if (entry.isFile() && (entry.name.endsWith('.gradle') || entry.name.endsWith('.gradle.kts'))) {
      paths.push(path)
    }
  }
  return paths.sort()
}

async function assertNugetLockedMode(rootDir: string): Promise<void> {
  const repositoryRoot = resolve(rootDir)
  const lockfiles = await repositoryFilesNamed(repositoryRoot, 'packages.lock.json')
  for (const lockfile of lockfiles) {
    const projectDirectory = dirname(lockfile)
    const projects = (await readdir(projectDirectory, { withFileTypes: true }))
      .filter(entry => entry.isFile() && entry.name.endsWith('.csproj'))
      .map(entry => resolve(projectDirectory, entry.name))
    if (projects.length === 0) {
      throw new Error('each NuGet packages.lock.json must be adjacent to a .csproj')
    }
    const inheritedProperties = await nearestDirectoryBuildProps(repositoryRoot, projectDirectory)
    for (const project of projects) {
      const projectContent = await readFile(project, 'utf8')
      const effectiveContent = `${inheritedProperties}\n${projectContent}`
      if (!nugetPropertyEnabled(effectiveContent, 'RestorePackagesWithLockFile')) {
        throw new Error('NuGet projects with packages.lock.json must enable RestorePackagesWithLockFile')
      }
      // The Action's original install/certification and the final verification
      // command both pass --locked-mode explicitly. Requiring the duplicate
      // MSBuild property would reject genuine repositories that already commit
      // their locks. An explicit false, conditional, or malformed declaration
      // remains an opt-out rather than silently becoming fallback authority.
      const lockedModeMarkers = effectiveContent.match(/<RestoreLockedMode\b/giu) ?? []
      const lockedModeDeclarations = [...effectiveContent.matchAll(/<RestoreLockedMode\b([^>]*)>([\s\S]*?)<\/RestoreLockedMode\s*>/giu)]
      if (lockedModeMarkers.length !== lockedModeDeclarations.length
        || lockedModeDeclarations.some(match => match[1]!.trim() !== '' || match[2]!.trim().toLowerCase() !== 'true')) {
        throw new Error('NuGet projects must not disable or obscure RestoreLockedMode')
      }
    }
  }
}

async function nearestDirectoryBuildProps(repositoryRoot: string, projectDirectory: string): Promise<string> {
  let current = resolve(projectDirectory)
  while (current.startsWith(repositoryRoot)) {
    const props = resolve(current, 'Directory.Build.props')
    if (await pathExists(props)) return readFile(props, 'utf8')
    if (current === repositoryRoot) break
    const parent = dirname(current)
    if (parent === current) break
    current = parent
  }
  return ''
}

function nugetPropertyEnabled(content: string, property: string): boolean {
  const values = [...content.matchAll(new RegExp(`<${property}>\\s*(true|false)\\s*<\\/${property}>`, 'giu'))]
  return values.at(-1)?.[1]?.toLowerCase() === 'true'
}

function certifiableNodePackageManager(
  name: SupportedPackageManager,
  version: string,
  spec: string,
): PackageManagerPlan {
  const parsed = parseExactVersion(version)
  if (name === 'npm' || name === 'pnpm') {
    const policy = CERTIFIABLE_VERSION_POLICY[name]
    if (parsed.major < policy.minimumMajor || parsed.major > policy.maximumMajor) {
      throw new Error(`${name}@${version} is outside the certifiable major-version policy`)
    }
    return {
      name, version, spec,
      variant: name,
      lockfile: name === 'npm' ? 'package-lock.json' : 'pnpm-lock.yaml',
    }
  }
  if (name === 'yarn') {
    if (parsed.major === 1 && parsed.minor === 22) {
      return { name, version, spec, variant: 'yarn-classic', lockfile: 'yarn.lock' }
    }
    const policy = CERTIFIABLE_VERSION_POLICY.yarnBerry
    if (parsed.major >= policy.minimumMajor && parsed.major <= policy.maximumMajor) {
      return { name, version, spec, variant: 'yarn-berry', lockfile: 'yarn.lock' }
    }
  }
  throw new Error(`${name}@${version} is outside the certifiable major-version policy`)
}

function assertCertifiableMinorVersion(
  label: string,
  version: string,
  policy: { major: number; minimumMinor: number; maximumMinor: number },
): void {
  const parsed = parseExactVersion(version)
  if (
    parsed.major !== policy.major
    || parsed.minor < policy.minimumMinor
    || parsed.minor > policy.maximumMinor
  ) {
    throw new Error(`${label} ${version} is outside the certifiable runtime policy`)
  }
}

function assertCertifiableRuntimeRequirement(
  label: string,
  version: string,
  policy: { major: number; minimumMinor: number; maximumMinor: number },
): void {
  const match = version.match(MINOR_VERSION_PATTERN) ?? version.match(EXACT_VERSION_PATTERN)
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new Error(`toolchain version ${version} must be major.minor or exact major.minor.patch`)
  }
  const major = Number(match[1])
  const minor = Number(match[2])
  if (major !== policy.major || minor < policy.minimumMinor || minor > policy.maximumMinor) {
    throw new Error(`${label} ${version} is outside the certifiable runtime policy`)
  }
}

function runtimeRequirementAllows(requirement: string, resolved: string): boolean {
  if (EXACT_VERSION_PATTERN.test(requirement)) return requirement === resolved
  const requested = requirement.match(MINOR_VERSION_PATTERN)
  const actual = resolved.match(EXACT_VERSION_PATTERN)
  return requested?.[1] === actual?.[1] && requested?.[2] === actual?.[2]
}

function parseExactVersion(version: string): { major: number; minor: number; patch: number } {
  const match = version.match(EXACT_VERSION_PATTERN)
  if (match?.[1] === undefined || match[2] === undefined || match[3] === undefined) {
    throw new Error(`toolchain version ${version} must be exact major.minor.patch`)
  }
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) }
}

async function declaredNativeToolchain(
  rootDir: string,
  language: 'rust' | 'go',
): Promise<string | undefined> {
  if (language === 'rust') {
    const plain = resolve(rootDir, 'rust-toolchain')
    if (await pathExists(plain)) return `cargo@${(await readFile(plain, 'utf8')).trim()}`
    const toml = resolve(rootDir, 'rust-toolchain.toml')
    if (!(await pathExists(toml))) return undefined
    const match = (await readFile(toml, 'utf8')).match(/^\s*channel\s*=\s*["']([^"']+)["']/mu)
    return match?.[1] === undefined ? undefined : `cargo@${match[1]}`
  }
  const content = await readFile(resolve(rootDir, 'go.mod'), 'utf8')
  const toolchain = content.match(/^\s*toolchain\s+go(\d+\.\d+\.\d+)\s*$/mu)?.[1]
  const directive = content.match(/^\s*go\s+(\d+\.\d+\.\d+)\s*$/mu)?.[1]
  const version = toolchain ?? directive
  return version === undefined ? undefined : `go@${version}`
}

async function migrateCargoDependency(
  rootDir: string,
  event: MigrationJob['changeEvent'],
): Promise<boolean> {
  const targets = event.affectedDependencies.filter(dependency =>
    dependency.ecosystem === 'cargo' && dependency.newVersion !== undefined)
  if (targets.length !== 1) return false
  const target = targets[0]!
  const updates: Array<{ path: string; content: string }> = []
  for (const path of (await repositoryManifestPaths(resolve(rootDir)))
    .filter(candidate => basename(candidate) === 'Cargo.toml')) {
    const content = await readFile(path, 'utf8')
    const next = updateCargoDependencyVersion(content, target.name, target.newVersion!)
    if (next !== content) updates.push({ path, content: next })
  }
  if (updates.length === 0) return false
  await Promise.all(updates.map(update => writeFile(update.path, update.content, 'utf8')))
  return true
}

async function migrateGoDependency(
  rootDir: string,
  event: MigrationJob['changeEvent'],
): Promise<boolean> {
  const targets = event.affectedDependencies.filter(dependency =>
    dependency.ecosystem === 'gomod' && dependency.newVersion !== undefined)
  if (targets.length !== 1) return false
  const target = targets[0]!
  const path = resolve(rootDir, 'go.mod')
  const content = await readFile(path, 'utf8')
  if (goModuleIsReplaced(content, target.name)) return false
  const newVersion = target.newVersion!
  const version = newVersion.startsWith('v') ? newVersion : `v${newVersion}`
  const expression = new RegExp(
    `(^\\s*(?:require\\s+)?${escapeRegex(target.name)}\\s+)v[^\\s]+`, 'mu',
  )
  if (!expression.test(content)) return false
  const next = content.replace(expression, `$1${version}`)
  if (next === content) return false
  await writeFile(path, next, 'utf8')
  return true
}

async function migrateVcpkgDependencies(
  rootDir: string,
  dependencies: readonly SafeCppDependencyMigration[],
): Promise<boolean> {
  const updates: Array<{ path: string; content: string }> = []
  for (const path of (await repositoryManifestPaths(resolve(rootDir)))
    .filter(candidate => basename(candidate) === 'vcpkg.json')) {
    const content = await readFile(path, 'utf8')
    const manifest = JSON.parse(content) as Record<string, unknown>
    if (!Array.isArray(manifest['dependencies'])) continue
    const declarations = manifest['dependencies']
    const overrides = Array.isArray(manifest['overrides']) ? manifest['overrides'] : []
    const direct = new Set(declarations.flatMap(item => typeof item === 'string' ? [item.toLowerCase()]
      : typeof item === 'object' && item !== null && typeof (item as Record<string, unknown>)['name'] === 'string'
        ? [String((item as Record<string, unknown>)['name']).toLowerCase()] : []))
    const primary = dependencies.find(item => direct.has(item.name.toLowerCase()))
    if (primary === undefined) continue
    let valid = true
    for (const dependency of dependencies) {
      const override = overrides.find(item => typeof item === 'object' && item !== null
        && String((item as Record<string, unknown>)['name']).toLowerCase() === dependency.name.toLowerCase()) as Record<string, unknown> | undefined
      const overrideVersion = override === undefined ? undefined
        : ['version', 'version-semver', 'version-string'].map(key => override[key]).find(value => typeof value === 'string')
      if (typeof overrideVersion !== 'string' || overrideVersion.replace(/#\d+$/u, '') !== dependency.oldVersion) {
        valid = false; break
      }
    }
    if (!valid) continue
    const next = updateVcpkgOverrideVersions(content, dependencies)
    if (next !== content) updates.push({ path, content: next })
  }
  if (updates.length === 0) return false
  await Promise.all(updates.map(update => writeFile(update.path, update.content, 'utf8')))
  return true
}

function updateVcpkgOverrideVersions(
  content: string,
  dependencies: readonly SafeCppDependencyMigration[],
): string {
  const ranges = topLevelJsonArrayObjectRanges(content, 'overrides')
  const replacements: Array<{ start: number; end: number; content: string }> = []
  for (const dependency of dependencies) {
    const matches = ranges.filter(range => {
      const value = JSON.parse(content.slice(range.start, range.end)) as Record<string, unknown>
      return typeof value['name'] === 'string' && value['name'].toLowerCase() === dependency.name.toLowerCase()
    })
    if (matches.length !== 1) throw new Error(`vcpkg override ${dependency.name} must occur exactly once`)
    const range = matches[0]!
    let object = content.slice(range.start, range.end)
    const version = /"(?:version|version-semver|version-string)"(\s*:\s*)"(?:\\.|[^"\\])*"/gu
    const versionMatches = [...object.matchAll(version)]
    if (versionMatches.length !== 1) throw new Error(`vcpkg override ${dependency.name} must have exactly one version field`)
    object = object.replace(version, `"version"$1${JSON.stringify(dependency.newVersion)}`)
    object = removeFlatJsonNumberProperty(object, 'port-version')
    replacements.push({ ...range, content: object })
  }
  return replacements.sort((left, right) => right.start - left.start)
    .reduce((result, replacement) => `${result.slice(0, replacement.start)}${replacement.content}${result.slice(replacement.end)}`, content)
}

function topLevelJsonArrayObjectRanges(
  content: string,
  property: string,
): Array<{ start: number; end: number }> {
  let depth = 0
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index]
    if (character === '"') {
      const end = jsonStringEnd(content, index)
      if (depth === 1 && JSON.parse(content.slice(index, end)) === property) {
        let cursor = end
        while (/\s/u.test(content[cursor] ?? '')) cursor += 1
        if (content[cursor] !== ':') { index = end - 1; continue }
        cursor += 1
        while (/\s/u.test(content[cursor] ?? '')) cursor += 1
        if (content[cursor] !== '[') throw new Error(`vcpkg ${property} must be an array`)
        return jsonArrayObjectRanges(content, cursor)
      }
      index = end - 1
    } else if (character === '{' || character === '[') depth += 1
    else if (character === '}' || character === ']') depth -= 1
  }
  throw new Error(`vcpkg manifest must contain ${property}`)
}

function jsonArrayObjectRanges(content: string, arrayStart: number): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = []
  let depth = 0
  let objectStart: number | undefined
  for (let index = arrayStart; index < content.length; index += 1) {
    const character = content[index]
    if (character === '"') index = jsonStringEnd(content, index) - 1
    else if (character === '[' || character === '{') {
      depth += 1
      if (character === '{' && depth === 2) objectStart = index
    } else if (character === ']' || character === '}') {
      if (character === '}' && depth === 2 && objectStart !== undefined) {
        ranges.push({ start: objectStart, end: index + 1 })
        objectStart = undefined
      }
      depth -= 1
      if (depth === 0) return ranges
    }
  }
  throw new Error('unterminated vcpkg overrides array')
}

function jsonStringEnd(content: string, start: number): number {
  let escaped = false
  for (let index = start + 1; index < content.length; index += 1) {
    if (!escaped && content[index] === '"') return index + 1
    if (!escaped && content[index] === '\\') escaped = true
    else escaped = false
  }
  throw new Error('unterminated JSON string in vcpkg manifest')
}

function removeFlatJsonNumberProperty(content: string, property: string): string {
  const expression = new RegExp(`"${escapeRegex(property)}"\\s*:\\s*-?\\d+(?:\\.\\d+)?`, 'u')
  const match = expression.exec(content)
  if (match === null) return content
  let start = match.index
  let end = match.index + match[0].length
  let cursor = end
  while (/\s/u.test(content[cursor] ?? '')) cursor += 1
  if (content[cursor] === ',') {
    end = cursor + 1
  } else {
    cursor = start - 1
    while (cursor >= 0 && /\s/u.test(content[cursor] ?? '')) cursor -= 1
    if (content[cursor] !== ',') throw new Error(`vcpkg ${property} field cannot be removed safely`)
    start = cursor
  }
  return `${content.slice(0, start)}${content.slice(end)}`
}

async function migrateManagedDependencies(
  rootDir: string,
  dependencies: readonly SafeManagedDependencyMigration[],
): Promise<boolean> {
  const manifests = await Promise.all((await repositoryManifestPaths(resolve(rootDir))).map(async path => {
    const content = await readFile(path, 'utf8')
    return { path, name: basename(path), original: content, content }
  }))
  const changedDependencies = new Set<string>()
  for (const dependency of dependencies) {
    for (const manifest of manifests) {
      if (!manifestBelongsToEcosystem(manifest.name, dependency.ecosystem)) continue
      const next = updateManagedManifest(manifest.content, manifest.name, dependency)
      if (next !== manifest.content) {
        manifest.content = next
        changedDependencies.add(dependency.name.toLowerCase())
      }
    }
  }
  if (changedDependencies.size !== dependencies.length) {
    if (dependencies.length !== 1
      || !await managedDynamicDependencyRequiresLockRefresh(rootDir, dependencies[0]!)) return false
    return true
  }
  const updates = manifests
    .filter(manifest => manifest.content !== manifest.original)
    .map(manifest => ({ path: manifest.path, content: manifest.content }))
  await Promise.all(updates.map(update => writeFile(update.path, update.content, 'utf8')))
  return true
}

async function managedDynamicDependencyRequiresLockRefresh(
  rootDir: string,
  dependency: SafeManagedDependencyMigration,
): Promise<boolean> {
  if (dependency.ecosystem !== 'maven') return false
  const [group, artifact] = dependency.name.split(':')
  if (!group || !artifact) return false
  let dynamicDeclaration = false
  let lockedOldVersion = false
  for (const path of await repositoryManifestPaths(resolve(rootDir))) {
    const name = basename(path)
    if (/^build\.gradle(?:\.kts)?$/u.test(name)) {
      const content = await readFile(path, 'utf8')
      const coordinates = new RegExp(
        `${escapeRegex(group)}:${escapeRegex(artifact)}:(?:\\+|\\d+\\.\\+|latest\\.(?:release|integration))`,
        'u',
      )
      const mapNotation = new RegExp(
        `group\\s*[:=]\\s*["']${escapeRegex(group)}["'][\\s\\S]{0,200}?name\\s*[:=]\\s*["']${escapeRegex(artifact)}["'][\\s\\S]{0,200}?version\\s*[:=]\\s*["'](?:\\+|\\d+\\.\\+|latest\\.(?:release|integration))["']`,
        'u',
      )
      dynamicDeclaration = dynamicDeclaration || coordinates.test(content) || mapNotation.test(content)
    }
  }
  for (const path of await repositoryFilesNamed(resolve(rootDir), 'gradle.lockfile')) {
    const content = await readFile(path, 'utf8')
    lockedOldVersion = lockedOldVersion
      || content.includes(`${dependency.name}:${dependency.oldVersion}=`)
  }
  return dynamicDeclaration && lockedOldVersion
}

async function repositoryFilesNamed(rootDir: string, filename: string): Promise<string[]> {
  const paths: string[] = []
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    const path = resolve(rootDir, entry.name)
    if (entry.isDirectory() && !MANIFEST_SCAN_EXCLUDED.has(entry.name)) {
      paths.push(...await repositoryFilesNamed(path, filename))
    } else if (entry.isFile() && entry.name === filename) {
      paths.push(path)
    }
  }
  return paths.sort()
}

async function adoptPrefetchedManagedLockfile(
  rootDir: string,
  dependency: SafeManagedDependencyMigration,
): Promise<void> {
  const candidatePath = process.env['AUTOMATED_API_RESOLVED_LOCKFILE']?.trim()
  if (candidatePath === undefined || candidatePath === '') return
  const content = await readFile(resolve(candidatePath), 'utf8')
  if (dependency.ecosystem === 'hex') {
    const escaped = escapeRegex(dependency.name)
    const entries = [...content.matchAll(new RegExp(
      `^[ \\t]*["']${escaped}["']:\\s*\\{:hex,\\s*:${escaped},\\s*["']([^"']+)["']`, 'gimu',
    ))]
    if (entries.length !== 1 || entries[0]?.[1] !== dependency.newVersion) {
      throw new Error('prefetched Mix lockfile does not contain the reviewed dependency version')
    }
    await writeFile(resolve(rootDir, 'mix.lock'), content, 'utf8')
    return
  }
  if (dependency.ecosystem === 'swiftpm') {
    const value = JSON.parse(content) as { pins?: Array<{ identity?: unknown; state?: { version?: unknown } }> }
    const identity = dependency.name.toLowerCase()
    const pins = (value.pins ?? []).filter(pin => pin.identity === identity)
    if (pins.length !== 1 || pins[0]?.state?.version !== dependency.newVersion) {
      throw new Error('prefetched SwiftPM lockfile does not contain the reviewed dependency version')
    }
    await writeFile(resolve(rootDir, 'Package.resolved'), content, 'utf8')
    return
  }
  if (dependency.ecosystem !== 'composer') {
    throw new Error(`prefetched lockfile is not supported for ${dependency.ecosystem}`)
  }
  let lock: { packages?: Array<{ name?: unknown; version?: unknown }>; 'packages-dev'?: Array<{ name?: unknown; version?: unknown }> }
  try {
    lock = JSON.parse(content) as typeof lock
  } catch {
    throw new Error('prefetched Composer lockfile is invalid JSON')
  }
  const packages = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])]
  const selected = packages.filter(item => item.name === dependency.name)
  if (selected.length !== 1 || typeof selected[0]?.version !== 'string'
    || selected[0].version.replace(/^v/u, '') !== dependency.newVersion.replace(/^v/u, '')) {
    throw new Error('prefetched Composer lockfile does not contain the reviewed dependency version')
  }
  await writeFile(resolve(rootDir, 'composer.lock'), content, 'utf8')
}

function updateManagedManifest(
  content: string,
  manifestName: string,
  dependency: SafeManagedDependencyMigration,
): string {
  const oldVersion = escapeRegex(dependency.oldVersion)
  if (dependency.ecosystem === 'maven') {
    const [group, artifact] = dependency.name.split(':')
    if (!group || !artifact) return content
    if (manifestName === 'deps.edn') {
      const coordinate = new RegExp(`(${escapeRegex(group)}/${escapeRegex(artifact)}\\s+\\{[^{}]*:mvn/version\\s+["'])${oldVersion}(["'][^{}]*\\})`, 'gu')
      return content.replace(coordinate, `$1${dependency.newVersion}$2`)
    }
    if (manifestName === 'project.clj') {
      const coordinate = new RegExp(`(\\[${escapeRegex(group)}/${escapeRegex(artifact)}\\s+["'])${oldVersion}(["'][^\\]]*\\])`, 'gu')
      return content.replace(coordinate, `$1${dependency.newVersion}$2`)
    }
    if (manifestName === 'pom.xml') {
      const block = new RegExp(`(<dependency\\b[^>]*>[\\s\\S]*?<groupId>\\s*${escapeRegex(group)}\\s*</groupId>[\\s\\S]*?<artifactId>\\s*${escapeRegex(artifact)}\\s*</artifactId>[\\s\\S]*?<version>\\s*)${oldVersion}(\\s*</version>[\\s\\S]*?</dependency>)`, 'gu')
      return content.replace(block, `$1${dependency.newVersion}$2`)
    }
    if (manifestName === 'build.sbt') {
      const declaration = new RegExp(
        `(["']${escapeRegex(group)}["']\\s*%%?\\s*["']${escapeRegex(artifact)}["']\\s*%\\s*["'])${oldVersion}(["'])`,
        'gu',
      )
      return content.replace(declaration, `$1${dependency.newVersion}$2`)
    }
    const coordinate = new RegExp(`(["']${escapeRegex(group)}:${escapeRegex(artifact)}:)${oldVersion}(["'])`, 'gu')
    return content.replace(coordinate, `$1${dependency.newVersion}$2`)
  }
  if (dependency.ecosystem === 'nuget') {
    const escaped = escapeRegex(dependency.name)
    const attribute = new RegExp(`(<PackageReference\\b[^>]*(?:Include|Update)=["']${escaped}["'][^>]*Version=["'])${oldVersion}(["'])`, 'giu')
    const element = new RegExp(`(<PackageReference\\b[^>]*(?:Include|Update)=["']${escaped}["'][^>]*>[\\s\\S]*?<Version>\\s*)${oldVersion}(\\s*</Version>)`, 'giu')
    return content.replace(attribute, `$1${dependency.newVersion}$2`).replace(element, `$1${dependency.newVersion}$2`)
  }
  if (dependency.ecosystem === 'composer') {
    const value = JSON.parse(content) as Record<string, unknown>
    const replacements: Array<{ start: number; end: number }> = []
    const rootStart = content.search(/\S/u)
    if (rootStart < 0 || content[rootStart] !== '{') {
      throw new Error('composer.json root must be an object')
    }
    const root = { start: rootStart, end: jsonObjectEnd(content, rootStart) }
    for (const field of ['require', 'require-dev']) {
      const dependencies = value[field]
      if (typeof dependencies !== 'object' || dependencies === null || Array.isArray(dependencies)) continue
      const versions = dependencies as Record<string, unknown>
      const declared = versions[dependency.name]
      if (typeof declared !== 'string' || !declared.includes(dependency.oldVersion)) continue
      const sections = directJsonPropertyValueRanges(content, root, field)
      if (sections.length !== 1 || content[sections[0]!.start] !== '{') {
        throw new Error(`composer.json ${field} cannot be updated safely`)
      }
      const section = { start: sections[0]!.start, end: jsonObjectEnd(content, sections[0]!.start) }
      const declarations = directJsonPropertyValueRanges(content, section, dependency.name)
      if (declarations.length !== 1
        || content[declarations[0]!.start] !== '"'
        || JSON.parse(content.slice(declarations[0]!.start, declarations[0]!.end)) !== declared) {
        throw new Error(`composer.json dependency ${dependency.name} cannot be updated safely`)
      }
      replacements.push(declarations[0]!)
    }
    return replacements.sort((left, right) => right.start - left.start).reduce(
      (updated, range) => `${updated.slice(0, range.start)}${JSON.stringify(dependency.newVersion)}${updated.slice(range.end)}`,
      content,
    )
  }
  if (dependency.ecosystem === 'gem') {
    const escaped = escapeRegex(dependency.name)
    return content.replace(
      new RegExp(`((?:[A-Za-z_]\\w*\\.)?(?:gem|add_(?:runtime_|development_)?dependency)\\s*\\(?\\s*["']${escaped}["']\\s*,\\s*["'])([^"']+)(["'])`, 'gu'),
      (match, prefix: string, requirement: string, suffix: string) => {
        if (!rubyRequirementAllowsVersion(requirement, dependency.oldVersion)) return match
        const nextRequirement = requirement.replace(/\d+(?:\.\d+){0,3}/u, dependency.newVersion)
        return `${prefix}${nextRequirement}${suffix}`
      },
    )
  }
  if (dependency.ecosystem === 'swiftpm') {
    return content.replace(
      new RegExp(`(\\.package\\s*\\([\\s\\S]*?(?:name:\\s*["']${escapeRegex(dependency.name)}["'][\\s\\S]*?)?(?:from|exact):\\s*["'])${oldVersion}(["'])`, 'gu'),
      `$1${dependency.newVersion}$2`,
    )
  }
  if (dependency.ecosystem === 'hex') {
    const escaped = escapeRegex(dependency.name)
    return content.replace(
      new RegExp(`(\\{\\s*:${escaped}\\s*,\\s*["'])([^"']+)(["'])`, 'giu'),
      (match, prefix: string, requirement: string, suffix: string) => {
        if (!requirement.includes(dependency.oldVersion)) return match
        return `${prefix}${requirement.replace(dependency.oldVersion, dependency.newVersion)}${suffix}`
      },
    )
  }
  if (dependency.ecosystem === 'pub') {
    const document = parseDocument(content)
    if (document.errors.length > 0 || !isMap(document.contents)) return content
    const reviewedVersion = new RegExp(
      `(?:^|[\\^<>= \\t])${oldVersion}(?=$|[ \\t])`,
      'u',
    )
    const ranges: Array<readonly [number, number]> = []
    for (const field of ['dependencies', 'dev_dependencies']) {
      const section = document.contents.get(field, true)
      if (!isMap(section)) continue
      const requirement = section.get(dependency.name, true)
      if (!isScalar(requirement) || typeof requirement.value !== 'string'
        || requirement.anchor !== undefined || requirement.range == null
        || !reviewedVersion.test(requirement.value)) continue
      const [start, end] = requirement.range
      if (/[\r\n]/u.test(content.slice(start, end))) continue
      ranges.push([start, end])
    }
    for (const [start, end] of ranges.sort((left, right) => right[0] - left[0])) {
      content = `${content.slice(0, start)}${dependency.newVersion}${content.slice(end)}`
    }
    return content
  }
  return content.replace(
    new RegExp(`(^\\s{2}${escapeRegex(dependency.name)}:\\s*[^#\\n]*?)${oldVersion}([^#\\n]*)$`, 'gmu'),
    `$1${dependency.newVersion}$2`,
  )
}

function directJsonPropertyValueRanges(
  content: string,
  object: { start: number; end: number },
  property: string,
): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = []
  let depth = 0
  for (let index = object.start; index < object.end; index += 1) {
    const character = content[index]
    if (character === '"') {
      const end = jsonStringEnd(content, index)
      if (depth === 1 && JSON.parse(content.slice(index, end)) === property) {
        let cursor = end
        while (/\s/u.test(content[cursor] ?? '')) cursor += 1
        if (content[cursor] === ':') {
          cursor += 1
          while (/\s/u.test(content[cursor] ?? '')) cursor += 1
          if (content[cursor] === '"') {
            ranges.push({ start: cursor, end: jsonStringEnd(content, cursor) })
          } else if (content[cursor] === '{') {
            ranges.push({ start: cursor, end: jsonObjectEnd(content, cursor) })
          }
        }
      }
      index = end - 1
      continue
    }
    if (character === '{') depth += 1
    else if (character === '}') depth -= 1
  }
  return ranges
}

function jsonObjectEnd(content: string, start: number): number {
  if (content[start] !== '{') throw new Error('JSON object must start with an opening brace')
  let depth = 0
  for (let index = start; index < content.length; index += 1) {
    const character = content[index]
    if (character === '"') {
      index = jsonStringEnd(content, index) - 1
      continue
    }
    if (character === '{') depth += 1
    else if (character === '}' && --depth === 0) return index + 1
  }
  throw new Error('unterminated JSON object in composer manifest')
}

function rubyRequirementAllowsVersion(requirement: string, version: string): boolean {
  const requested = numericVersionParts(version)
  if (requested === undefined) return false
  const pessimistic = requirement.match(/^\s*~>\s*(\d+(?:\.\d+){0,3})\s*$/u)?.[1]
  if (pessimistic !== undefined) {
    const lower = numericVersionParts(pessimistic)!
    const upper = [...lower]
    const incrementAt = upper.length === 1 ? 0 : upper.length - 2
    upper[incrementAt] = (upper[incrementAt] ?? 0) + 1
    for (let index = incrementAt + 1; index < upper.length; index += 1) upper[index] = 0
    return compareNumericVersions(requested, lower) >= 0 && compareNumericVersions(requested, upper) < 0
  }
  const exact = requirement.match(/^\s*=?\s*(\d+(?:\.\d+){0,3})\s*$/u)?.[1]
  return exact !== undefined && compareNumericVersions(requested, numericVersionParts(exact)!) === 0
}

function numericVersionParts(version: string): number[] | undefined {
  if (!/^\d+(?:\.\d+){0,3}$/u.test(version)) return undefined
  return version.split('.').map(Number)
}

function compareNumericVersions(left: number[], right: number[]): number {
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0)
    if (difference !== 0) return difference
  }
  return 0
}

interface CargoDependencyDeclaration {
  declarationName: string
  packageName: string
  version?: string
}

function cargoDependencyDeclarations(content: string): CargoDependencyDeclaration[] {
  const declarations: CargoDependencyDeclaration[] = []
  let dependencySection = false
  for (const line of content.split(/\r?\n/u)) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/u)?.[1]
    if (section !== undefined) {
      dependencySection = /(?:^|\.)dependencies$/u.test(section)
      continue
    }
    if (!dependencySection || line.trimStart().startsWith('#')) continue
    const assignment = line.match(/^\s*(?:(["'])([^"']+)\1|([A-Za-z0-9_-]+))\s*=\s*(.*)$/u)
    const declarationName = assignment?.[2] ?? assignment?.[3]
    if (declarationName === undefined) continue
    const value = assignment?.[4]
    const inline = value?.match(/^\{([^}]*)\}/u)?.[1]
    const version = value?.match(/^["']([^"']+)["']/u)?.[1]
      ?? inline?.match(/\bversion\s*=\s*["']([^"']+)["']/u)?.[1]
    declarations.push({
      declarationName,
      packageName: inline?.match(/\bpackage\s*=\s*["']([^"']+)["']/u)?.[1] ?? declarationName,
      ...(version === undefined ? {} : { version }),
    })
  }
  return declarations
}

function updateCargoDependencyVersion(content: string, packageName: string, newVersion: string): string {
  let dependencySection = false
  return content.split(/(?<=\n)/u).map(raw => {
    const line = raw.replace(/\r?\n$/u, '')
    const ending = raw.endsWith('\r\n') ? '\r\n' : raw.endsWith('\n') ? '\n' : ''
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/u)?.[1]
    if (section !== undefined) {
      dependencySection = /(?:^|\.)dependencies$/u.test(section)
      return raw
    }
    if (!dependencySection || line.trimStart().startsWith('#')) return raw
    const match = line.match(/^(\s*)((?:["'][^"']+["'])|(?:[A-Za-z0-9_-]+))(\s*=\s*)(["'])([^"']+)(["'])(.*)$/u)
    const directName = match?.[2]?.replace(/^["']|["']$/gu, '')
    if (match !== null && directName === packageName) {
      return `${match[1]}${match[2]}${match[3]}${match[4]}${newVersion}${match[6]}${match[7]}${ending}`
    }
    const inline = line.match(/^(\s*)((?:["'][^"']+["'])|(?:[A-Za-z0-9_-]+))(\s*=\s*\{)([^}]*)(\})(.*)$/u)
    if (inline === null) return raw
    const declaredPackage = inline[4]!.match(/\bpackage\s*=\s*["']([^"']+)["']/u)?.[1]
      ?? inline[2]!.replace(/^["']|["']$/gu, '')
    if (declaredPackage !== packageName || !/\bversion\s*=\s*["'][^"']+["']/u.test(inline[4]!)) return raw
    const body = inline[4]!.replace(
      /(\bversion\s*=\s*["'])[^"']+(["'])/u,
      `$1${newVersion}$2`,
    )
    return `${inline[1]}${inline[2]}${inline[3]}${body}${inline[5]}${inline[6]}${ending}`
  }).join('')
}

function goModuleIsReplaced(content: string, moduleName: string): boolean {
  const escaped = escapeRegex(moduleName)
  if (new RegExp(`^\\s*replace\\s+${escaped}(?:\\s+v[^\\s]+)?\\s+=>`, 'mu').test(content)) return true
  for (const block of content.matchAll(/^\s*replace\s*\(\s*$([\s\S]*?)^\s*\)\s*$/gmu)) {
    if (new RegExp(`^\\s*${escaped}(?:\\s+v[^\\s]+)?\\s+=>`, 'mu').test(block[1] ?? '')) return true
  }
  return false
}

async function assertSafeYarnBerryConfiguration(rootDir: string): Promise<void> {
  let configuration = ''
  try {
    configuration = await readFile(resolve(rootDir, '.yarnrc.yml'), 'utf8')
  } catch (error) {
    if (!isMissingPath(error)) throw error
  }
  if (/^\s*(?:yarnPath|plugins|npmRegistryServer|npmScopes|unsafeHttpWhitelist)\s*:/imu.test(configuration)) {
    throw new Error('Yarn Berry custom binaries, plugins, and registries are not supported')
  }
  try {
    await access(resolve(rootDir, '.yarn/plugins'))
    throw new Error('Yarn Berry repository plugins are not supported')
  } catch (error) {
    if (error instanceof Error && error.message.includes('repository plugins')) throw error
    if (!isMissingPath(error)) throw error
  }
}

async function assertSafeNodePackageManagerConfiguration(
  rootDir: string,
  variant: PackageManagerPlan['variant'],
): Promise<void> {
  if (variant === 'yarn-berry') {
    await assertSafeYarnBerryConfiguration(rootDir)
    if (await pathExists(resolve(rootDir, 'yarn.config.cjs'))) {
      throw new Error('Yarn Berry executable constraints are not supported')
    }
    return
  }
  if (variant === 'yarn-classic') {
    let configuration = ''
    try {
      configuration = await readFile(resolve(rootDir, '.yarnrc'), 'utf8')
    } catch (error) {
      if (!isMissingPath(error)) throw error
    }
    if (/^\s*(?:yarn-path|registry|proxy|https-proxy)\s+/imu.test(configuration)) {
      throw new Error('Yarn Classic custom binaries, registries, and proxies are not supported')
    }
    return
  }
  if (variant !== 'pnpm') return
  for (const filename of ['.pnpmfile.cjs', '.pnpmfile.mjs']) {
    if (await pathExists(resolve(rootDir, filename))) {
      throw new Error('pnpm repository hooks are not supported')
    }
  }
  let workspace = ''
  try {
    workspace = await readFile(resolve(rootDir, 'pnpm-workspace.yaml'), 'utf8')
  } catch (error) {
    if (!isMissingPath(error)) throw error
  }
  if (/^\s*(?:configDependencies|pnpmfile|registries)\s*:/imu.test(workspace)) {
    throw new Error('pnpm executable configuration and custom registries are not supported')
  }
}

function isMissingPath(error: unknown): boolean {
  return typeof error === 'object'
    && error !== null
    && 'code' in error
    && error.code === 'ENOENT'
}
