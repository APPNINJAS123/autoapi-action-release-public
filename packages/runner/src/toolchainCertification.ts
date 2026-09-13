import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { lstat, readFile, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import {
  MigrationJobSchema,
  ToolchainCertificationSchema,
  type ToolchainCertification,
} from '@automated-api/contracts'
import { parseVcpkgManifest, resolveExistingPathInsideRepository } from '@automated-api/remediation'
import { detectPackageManager, type PackageManagerPlan } from './dependencies.js'
import { certifyNugetLockGraph } from './nugetLockGraph.js'
import { assertReviewedJvmCertification } from './reviewedJvmToolchain.js'
import { readReviewedKotlinPom } from './reviewedKotlinConsumer.js'

export async function createToolchainCertification(input: {
  jobPath: string
  repositoryPath: string
  outputPath: string
  expectedManager: PackageManagerPlan
  runnerImageId: string
  runtimeImages: string[]
  managerExecutionVerified?: boolean
  lockfileBeforeHash?: string
  vcpkgResolvedManifestPath?: string
  vcpkgProjectionManifestPath?: string
  pythonEnvironmentReceiptPath?: string
  now?: Date
}): Promise<ToolchainCertification> {
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(input.jobPath), 'utf8')))
  // Certification belongs to the unchanged old graph, never the disposable
  // target graph or a modified compiler/test/classpath configuration.
  await readReviewedKotlinPom(input.repositoryPath, job, 'baseline')
  const managerRoot = await resolveExistingPathInsideRepository(
    resolve(input.repositoryPath),
    job.repository.packageManagerDirectory ?? job.repository.workingDirectory,
  )
  const detected = input.expectedManager.variant === 'analysis-only'
    ? input.expectedManager
    : await detectPackageManager(
        managerRoot,
        job.repository.packageManager ?? (job.changeEvent.affectedLanguages.length === 1
          ? job.changeEvent.affectedLanguages[0]
          : undefined),
        { allowPythonStdlibOnly: input.expectedManager.variant === 'python-stdlib',
          reviewedJvmContext: { job, repositoryRoot: input.repositoryPath } },
      )
  assertSameManager(detected, input.expectedManager)
  const lockfile = detected.lockfile === '.' ? undefined : await lockEvidence(
    managerRoot,
    detected.lockfile,
    input.lockfileBeforeHash,
  )
  const elixirTools = detected.variant === 'elixir-mix'
    ? certifyElixirTools(detected)
    : undefined
  const vcpkgResolution = detected.variant === 'c-vcpkg' || detected.variant === 'cpp-vcpkg'
    ? await vcpkgManifestEvidence(
        managerRoot,
        input.vcpkgResolvedManifestPath,
        input.vcpkgProjectionManifestPath,
      )
    : undefined
  const manager: ToolchainCertification['manager'] = detected.name === 'vcpkg'
    ? {
        name: 'vcpkg',
        version: detected.version,
        spec: detected.spec,
        variant: detected.variant as 'c-vcpkg' | 'cpp-vcpkg',
      }
    : {
        name: detected.name as Exclude<ToolchainCertification['manager']['name'], 'vcpkg'>,
        version: detected.version,
        spec: detected.spec,
        variant: detected.variant as Exclude<ToolchainCertification['manager']['variant'], 'c-vcpkg' | 'cpp-vcpkg'>,
      }
  const unsigned = {
    schemaVersion: '1.0' as const,
    jobId: job.id,
    baseSha: job.baseSha,
    manager,
    runtime: runtimeVersions(detected, managerRoot, input.managerExecutionVerified === true),
    ...(detected.pythonVersionRequirement === undefined ? {} : {
      runtimeRequirements: { python: detected.pythonVersionRequirement },
    }),
    ...(elixirTools === undefined ? {} : { elixirTools }),
    ...(lockfile === undefined ? {} : { lockfile }),
    ...(detected.variant === 'dotnet-nuget' ? {
      nugetLockGraphHash: await certifyNugetLockGraph(input.repositoryPath, job),
    } : {}),
    ...(detected.reviewedJvmToolchain === undefined ? {} : { reviewedJvmToolchain: detected.reviewedJvmToolchain }),
    ...(vcpkgResolution === undefined ? {} : { vcpkgResolution }),
    ...(input.pythonEnvironmentReceiptPath === undefined ? {} : {
      pythonEnvironmentReceiptHash: await certifyPythonEnvironmentReceipt(input.pythonEnvironmentReceiptPath, {
        jobId: job.id, baseSha: job.baseSha, runnerImageId: input.runnerImageId,
        pythonVersion: detected.pythonVersion, variant: detected.variant,
        lockHash: lockfile?.beforeHash,
        manifestHash: sha256(await readFile(resolve(managerRoot, 'pyproject.toml'))),
        selection: job.repository.pythonEnvironment,
      }),
    }),
    runnerImageId: input.runnerImageId,
    runtimeImages: input.runtimeImages,
    lifecycleScriptsDisabled: true as const,
    networkDisabledVerification: true as const,
    certifiedAt: (input.now ?? new Date()).toISOString(),
  }
  const certification = ToolchainCertificationSchema.parse({
    ...unsigned,
    certificationKey: toolchainCertificationKey(unsigned),
  })
  await writeFile(resolve(input.outputPath), `${JSON.stringify(certification, null, 2)}\n`, 'utf8')
  return certification
}

export async function certifyPythonEnvironmentReceipt(path: string, expected: {
  jobId: string; baseSha: string; runnerImageId: string; pythonVersion: string | undefined;
  variant: string; lockHash: string | undefined; manifestHash: string;
  selection?: { extras: string[]; noDev: boolean } | undefined;
}): Promise<string> {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 8 * 1024 * 1024) {
    throw new Error('Python certification requires a bounded regular receipt')
  }
  const bytes = await readFile(path)
  const receipt = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>
  const args = [
    ...(expected.selection?.noDev ? ['--no-dev'] : []),
    ...[...new Set(expected.selection?.extras ?? [])].sort().flatMap(extra => ['--extra', extra]),
  ]
  if (expected.variant !== 'python-uv' || receipt['schemaVersion'] !== 2
    || receipt['sealedOutput'] !== true
    || receipt['jobId'] !== expected.jobId || receipt['baseSha'] !== expected.baseSha
    || receipt['runnerImageId'] !== expected.runnerImageId || receipt['pythonVersion'] !== expected.pythonVersion
    || receipt['lockSha256'] !== expected.lockHash || receipt['manifestSha256'] !== expected.manifestHash
    || JSON.stringify(receipt['selectionArgs']) !== JSON.stringify(args)) {
    throw new Error('Python environment receipt does not match the certified job, runtime, manifests or selection')
  }
  return sha256(bytes)
}

export async function readToolchainCertification(
  path: string,
): Promise<ToolchainCertification> {
  return verifyToolchainCertificationIdentity(
    ToolchainCertificationSchema.parse(JSON.parse(await readFile(resolve(path), 'utf8'))),
  )
}

export function verifyToolchainCertificationIdentity(
  input: ToolchainCertification,
): ToolchainCertification {
  const certification = ToolchainCertificationSchema.parse(input)
  if (certification.certificationKey !== toolchainCertificationKey(certification)) {
    throw new Error('toolchain certification identity mismatch')
  }
  if (certification.manager.variant === 'dotnet-nuget' && certification.nugetLockGraphHash === undefined) {
    throw new Error('Current dotnet execution requires an immutable NuGet lock graph certificate')
  }
  assertReviewedJvmCertification(certification)
  return certification
}

export function toolchainCertificationKey(
  input: Omit<ToolchainCertification, 'certificationKey'>,
): string {
  // This is an attestation identity, not a reusable capability-cache key.
  // Bind every artifact-specific fact so a second Action invocation cannot
  // overwrite or be confused with evidence produced for another job, commit,
  // lockfile, or instant.
  // Defensive runtime omission matters because a schema-parsed certificate is
  // structurally assignable here even though the TypeScript signature omits
  // the key. Never make the digest recursively depend on itself.
  const { certificationKey: _certificationKey, ...unsigned } = input as ToolchainCertification
  return sha256(canonicalize(unsigned))
}

function assertSameManager(actual: PackageManagerPlan, expected: PackageManagerPlan): void {
  for (const key of ['name', 'version', 'spec', 'variant', 'lockfile'] as const) {
    if (actual[key] !== expected[key]) throw new Error(`toolchain certification manager ${key} mismatch`)
  }
  if (actual.pythonVersion !== expected.pythonVersion) {
    const requirement = actual.pythonVersionRequirement
    if (requirement === undefined || expected.pythonVersion === undefined
      || !expected.pythonVersion.startsWith(`${requirement}.`)) {
      throw new Error('toolchain certification Python runtime mismatch')
    }
  }
  if (actual.runtimeVersion !== expected.runtimeVersion) {
    throw new Error('toolchain certification language runtime mismatch')
  }
  if (actual.scalaVersion !== expected.scalaVersion) {
    throw new Error('toolchain certification Scala runtime mismatch')
  }
  if (actual.coursierVersion !== expected.coursierVersion) {
    throw new Error('toolchain certification Coursier runtime mismatch')
  }
  for (const key of [
    'erlangVersion',
    'hexVersion', 'hexArchiveUrl', 'hexArchiveSha512',
    'rebar3Version', 'rebar3ArchiveUrl', 'rebar3ArchiveSha512',
  ] as const) {
    if (actual[key] !== expected[key]) {
      throw new Error(`toolchain certification Elixir ${key} mismatch`)
    }
  }
}

async function lockEvidence(
  root: string,
  path: string,
  expectedBeforeHash: string | undefined,
): Promise<{ path: string; beforeHash: string; afterHash: string }> {
  if (expectedBeforeHash === undefined || !/^[a-f0-9]{64}$/u.test(expectedBeforeHash)) {
    throw new Error('toolchain certification requires the pre-install lockfile hash')
  }
  const afterHash = sha256(await readFile(resolve(root, path)))
  return { path, beforeHash: expectedBeforeHash, afterHash }
}

function runtimeVersions(
  manager: PackageManagerPlan,
  managerRoot: string,
  managerExecutionVerified: boolean,
): ToolchainCertification['runtime'] {
  const clojure = manager.language === 'clojure' && !managerExecutionVerified
    ? clojureRuntimeVersions(manager, managerRoot)
    : {}
  return {
    node: process.version.replace(/^v/u, ''),
    ...(manager.language === 'python' ? { python: commandVersion(
      process.env['AUTOMATED_API_PYTHON'] ?? 'python', ['--version'], /Python\s+(\d+\.\d+\.\d+)/u,
    ) } : {}),
    ...(manager.language === 'rust' ? {
      rust: commandVersion('rustc', ['--version'], /^rustc\s+(\d+\.\d+\.\d+)/u),
      cargo: commandVersion('cargo', ['--version'], /^cargo\s+(\d+\.\d+\.\d+)/u),
    } : {}),
    ...(manager.language === 'go' ? {
      go: commandVersion('go', ['version'], /\bgo(\d+\.\d+\.\d+)\b/u),
    } : {}),
    ...(manager.language === 'java' || manager.language === 'kotlin' ? {
      java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)/u),
      ...(manager.variant === 'jvm-maven' ? { maven: managerExecutionVerified ? manager.version : commandVersion(
        manager.wrapperExecutable ?? './mvnw', ['--version'], /Apache Maven (\d+\.\d+\.\d+)/u,
        undefined, 10_000, managerRoot,
      ) } : {}),
      ...(manager.variant === 'jvm-gradle' ? { gradle: managerExecutionVerified ? manager.version : commandVersion(
        manager.wrapperExecutable ?? './gradlew', ['--version'], /Gradle (\d+\.\d+\.\d+)/u,
        undefined, 10_000, managerRoot,
      ) } : {}),
    } : {}),
    ...(manager.language === 'scala' ? {
      java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)/u),
      scala: manager.scalaVersion!,
      sbt: managerExecutionVerified ? manager.version : commandVersion('cs', ['launch', '--mode', 'offline', `sbt:${manager.version}`, '--', 'show sbtVersion'], /(\d+\.\d+\.\d+)/u, undefined, 30_000),
      coursier: managerExecutionVerified ? manager.coursierVersion! : commandVersion('cs', ['version'], /(\d+\.\d+\.\d+)/u),
    } : {}),
    ...(manager.language === 'csharp' ? { dotnet: commandVersion('dotnet', ['--version'], /^(\d+\.\d+\.\d+)/u) } : {}),
    ...(manager.language === 'php' ? {
      php: commandVersion('php', ['--version'], /^PHP (\d+\.\d+\.\d+)/u),
      composer: managerExecutionVerified ? manager.version : commandVersion('composer', ['--version'], /Composer version (\d+\.\d+\.\d+)/u),
    } : {}),
    ...(manager.language === 'ruby' ? {
      ruby: commandVersion('ruby', ['--version'], /^ruby (\d+\.\d+\.\d+)/u),
      bundler: managerExecutionVerified ? manager.version : commandVersion('bundle', ['--version'], /Bundler version (\d+\.\d+\.\d+)/u),
    } : {}),
    ...(manager.language === 'swift' ? { swift: commandVersion(
      'swift', ['--version'], /Swift version (\d+\.\d+(?:\.\d+)?)/u, manager.runtimeVersion,
    ) } : {}),
    ...(manager.language === 'dart' ? { dart: commandVersion('dart', ['--version'], /Dart SDK version: (\d+\.\d+\.\d+)/u) } : {}),
    ...(manager.language === 'elixir' ? managerExecutionVerified ? {
      elixir: manager.runtimeVersion!, mix: manager.version,
      hex: manager.hexVersion!, rebar3: manager.rebar3Version!,
    } : elixirRuntimeVersions(manager) : {}),
    ...(manager.language === 'clojure' && managerExecutionVerified ? {
      java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)"/u, undefined, 10_000, managerRoot),
      clojure: manager.runtimeVersion!,
      ...(manager.variant === 'clojure-leiningen' ? { leiningen: manager.version } : {}),
    } : clojure),
    ...(manager.language === 'cpp' ? {
      cxx: commandVersion(
        process.env['AUTOMATED_API_CXX'] ?? 'c++',
        ['--version'],
        /(?:clang version|(?:g\+\+|c\+\+)[^\n]*?)\s(\d+\.\d+\.\d+)/u,
      ),
      cmake: commandVersion(
        process.env['AUTOMATED_API_CMAKE'] ?? 'cmake',
        ['--version'],
        /cmake version (\d+\.\d+\.\d+)/u,
      ),
      vcpkg: certifiedVcpkgCommit(manager),
    } : {}),
    ...(manager.language === 'c' ? {
      cc: commandVersion(
        process.env['AUTOMATED_API_CC'] ?? 'cc',
        ['--version'],
        /\b(\d+\.\d+\.\d+)\b/u,
      ),
      cmake: commandVersion(
        process.env['AUTOMATED_API_CMAKE'] ?? 'cmake',
        ['--version'],
        /cmake version (\d+\.\d+\.\d+)/u,
      ),
      vcpkg: certifiedVcpkgCommit(manager),
    } : {}),
  }
}

export function certifiedVcpkgCommit(
  manager: PackageManagerPlan,
  markerPath = process.env['AUTOMATED_API_VCPKG_COMMIT_FILE']
    ?? '/opt/dependency-cache/vcpkg/.autoapi-vcpkg-commit',
): string {
  if (manager.name !== 'vcpkg' || (manager.variant !== 'c-vcpkg' && manager.variant !== 'cpp-vcpkg')) {
    throw new Error('vcpkg runtime identity requires the C or C++ vcpkg manager')
  }
  let commit: string
  try {
    commit = readFileSync(resolve(markerPath), 'utf8').trim()
  } catch {
    throw new Error('toolchain certification could not verify the vcpkg commit marker')
  }
  if (!/^[a-f0-9]{40}$/u.test(commit) || commit !== manager.version) {
    throw new Error('toolchain certification vcpkg commit mismatch')
  }
  return commit
}

function clojureRuntimeVersions(
  manager: PackageManagerPlan,
  managerRoot: string,
): Pick<ToolchainCertification['runtime'], 'java' | 'clojure' | 'leiningen'> {
  const java = commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)"/u, undefined, 10_000, managerRoot)
  if (manager.variant === 'clojure-tools-deps') {
    const cli = commandVersion('clojure', ['-Sdescribe'], /:version\s+"(\d+\.\d+\.\d+\.\d+)"/u, undefined, 10_000, managerRoot)
    if (cli !== manager.version) throw new Error('toolchain certification Clojure CLI version mismatch')
    const clojure = commandVersion(
      'clojure', ['-Srepro', '-M', '-e', '(print (clojure-version))'], /^(\d+\.\d+\.\d+)$/u,
      undefined, 10_000, managerRoot,
    )
    if (clojure !== manager.runtimeVersion) throw new Error('toolchain certification Clojure runtime mismatch')
    return { java, clojure }
  }
  const leiningen = commandVersion('lein', ['version'], /Leiningen (\d+\.\d+\.\d+)/u, undefined, 10_000, tmpdir())
  if (leiningen !== manager.version) throw new Error('toolchain certification Leiningen version mismatch')
  const clojure = commandVersion(
    'lein', [
      '-o', 'update-in', ':prep-tasks', 'empty', '--',
      'trampoline', 'run', '-m', 'clojure.main', '-e', '(print (clojure-version))',
    ],
    /(?:^|\r?\n)(\d+\.\d+\.\d+)\s*$/u, undefined, 120_000, managerRoot,
  )
  if (clojure !== manager.runtimeVersion) throw new Error('toolchain certification Clojure runtime mismatch')
  return { java, clojure, leiningen }
}

function elixirRuntimeVersions(
  manager: PackageManagerPlan,
): { elixir: string; mix: string; hex: string; rebar3: string } {
  const tools = requiredElixirToolPlan(manager)
  const elixir = commandVersion(
    process.env['AUTOMATED_API_ELIXIR'] ?? 'elixir', ['--version'], /Elixir\s+(\d+\.\d+\.\d+)/u,
  )
  const mix = commandVersion(
    process.env['AUTOMATED_API_MIX'] ?? 'mix', ['--version'], /Mix\s+(\d+\.\d+\.\d+)/u,
  )
  const hex = commandVersion('mix', ['hex.info'], /^Hex:\s+(\d+\.\d+\.\d+)$/mu)
  const rebar3 = commandVersion(elixirRebar3Path(manager), ['version'], /\brebar3?\s+(\d+\.\d+\.\d+)\b/iu)
  if (elixir !== manager.runtimeVersion) {
    throw new Error(`toolchain certification Elixir runtime mismatch: expected ${manager.runtimeVersion}, found ${elixir}`)
  }
  if (mix !== manager.version) {
    throw new Error(`toolchain certification Mix runtime mismatch: expected ${manager.version}, found ${mix}`)
  }
  if (hex !== tools.hexVersion) {
    throw new Error(`toolchain certification Hex runtime mismatch: expected ${tools.hexVersion}, found ${hex}`)
  }
  if (rebar3 !== tools.rebar3Version) {
    throw new Error(`toolchain certification Rebar3 runtime mismatch: expected ${tools.rebar3Version}, found ${rebar3}`)
  }
  return { elixir, mix, hex, rebar3 }
}

async function vcpkgManifestEvidence(
  managerRoot: string,
  resolvedManifestPath: string | undefined,
  projectionManifestPath: string | undefined,
): Promise<NonNullable<ToolchainCertification['vcpkgResolution']>> {
  if (resolvedManifestPath === undefined || projectionManifestPath === undefined) {
    throw new Error('C/C++ toolchain certification requires resolved and projection vcpkg manifests')
  }
  const before = await readFile(resolve(managerRoot, 'vcpkg.json'))
  const after = await readFile(resolve(resolvedManifestPath))
  const projection = await readFile(resolve(projectionManifestPath))
  const resolved = parseVcpkgManifest(after.toString('utf8'), resolvedManifestPath)
  const projected = parseVcpkgManifest(projection.toString('utf8'), projectionManifestPath)
  if (resolved.baseline !== projected.baseline
    || resolved.overrides.size !== projected.overrides.size
    || [...resolved.overrides].some(([name, version]) => projected.overrides.get(name) !== version)) {
    throw new Error('C/C++ vcpkg projection does not match the resolved customer dependency graph')
  }
  return {
    manifestPath: 'vcpkg.json',
    beforeHash: sha256(before),
    afterHash: sha256(after),
    projectionHash: sha256(projection),
  }
}

function certifyElixirTools(manager: PackageManagerPlan): NonNullable<ToolchainCertification['elixirTools']> {
  const tools = requiredElixirToolPlan(manager)
  const proofPath = process.env['AUTOMATED_API_ELIXIR_TOOL_PROOF']
    ?? '/opt/dependency-cache/elixir-tools/verified-tools'
  let proof: string[]
  try {
    proof = readFileSync(proofPath, 'utf8').trimEnd().split('\n')
  } catch {
    throw new Error('toolchain certification could not read the Elixir tool proof')
  }
  const expected = [
    tools.hexVersion, tools.hexArchiveUrl, tools.hexArchiveSha512,
    tools.rebar3Version, tools.rebar3ArchiveUrl, tools.rebar3ArchiveSha512,
  ]
  if (proof.length !== expected.length || proof.some((value, index) => value !== expected[index])) {
    throw new Error('toolchain certification Elixir tool proof mismatch')
  }
  return {
    hex: {
      version: tools.hexVersion,
      url: tools.hexArchiveUrl,
      sha512: tools.hexArchiveSha512,
    },
    rebar3: {
      version: tools.rebar3Version,
      url: tools.rebar3ArchiveUrl,
      sha512: tools.rebar3ArchiveSha512,
    },
  }
}

function requiredElixirToolPlan(manager: PackageManagerPlan): Required<Pick<
  PackageManagerPlan,
  'hexVersion' | 'hexArchiveUrl' | 'hexArchiveSha512'
    | 'rebar3Version' | 'rebar3ArchiveUrl' | 'rebar3ArchiveSha512'
>> {
  const values = {
    hexVersion: manager.hexVersion,
    hexArchiveUrl: manager.hexArchiveUrl,
    hexArchiveSha512: manager.hexArchiveSha512,
    rebar3Version: manager.rebar3Version,
    rebar3ArchiveUrl: manager.rebar3ArchiveUrl,
    rebar3ArchiveSha512: manager.rebar3ArchiveSha512,
  }
  if (Object.values(values).some(value => value === undefined || value === '')) {
    throw new Error('toolchain certification requires exact Hex and Rebar3 artifacts')
  }
  return {
    hexVersion: values.hexVersion!,
    hexArchiveUrl: values.hexArchiveUrl!,
    hexArchiveSha512: values.hexArchiveSha512!,
    rebar3Version: values.rebar3Version!,
    rebar3ArchiveUrl: values.rebar3ArchiveUrl!,
    rebar3ArchiveSha512: values.rebar3ArchiveSha512!,
  }
}

function elixirRebar3Path(manager: PackageManagerPlan): string {
  const configured = process.env['AUTOMATED_API_REBAR3']?.trim()
  if (configured) return configured
  const mixHome = process.env['MIX_HOME']?.trim()
  if (!mixHome || !manager.runtimeVersion || !manager.erlangVersion) {
    throw new Error('toolchain certification cannot resolve the local Rebar3 path')
  }
  const [major, minor] = manager.runtimeVersion.split('.')
  const otpMajor = manager.erlangVersion.split('.')[0]
  return resolve(mixHome, 'elixir', `${major}-${minor}-otp-${otpMajor}`, 'rebar3')
}

function commandVersion(
  command: string,
  args: string[],
  pattern: RegExp,
  expected?: string,
  timeoutMs = 10_000,
  cwd?: string,
): string {
  const result = spawnSync(command, args, {
    encoding: 'utf8', timeout: timeoutMs,
    ...(cwd === undefined ? {} : { cwd }),
    env: certificationCommandEnvironment(),
  })
  const match = `${result.stdout}${result.stderr}`.match(pattern)
  if (result.status !== 0 || match?.[1] === undefined) {
    throw new Error(`toolchain certification could not verify ${command}`)
  }
  const version = match[1]
  if (expected !== undefined && version.split('.').length === 2 && expected.startsWith(`${version}.`)) return expected
  return version
}

export function certificationCommandEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: process.env['PATH'],
    HOME: process.env['HOME'],
    RUSTUP_TOOLCHAIN: process.env['RUSTUP_TOOLCHAIN'],
    RUSTUP_HOME: process.env['RUSTUP_HOME'],
    CARGO_HOME: process.env['CARGO_HOME'],
    GOROOT: process.env['GOROOT'],
    JAVA_HOME: process.env['JAVA_HOME'],
    MAVEN_USER_HOME: process.env['MAVEN_USER_HOME'],
    MAVEN_OPTS: process.env['MAVEN_OPTS'],
    // Only the Action's container-local, job-owned Maven cache may survive
    // this allowlist. Never forward an arbitrary host runner temporary path.
    ...(process.env['RUNNER_TEMP'] === '/opt/dependency-cache/maven-wrapper'
      ? { RUNNER_TEMP: '/opt/dependency-cache/maven-wrapper' } : {}),
    GRADLE_USER_HOME: process.env['GRADLE_USER_HOME'],
    COURSIER_CACHE: process.env['COURSIER_CACHE'],
    SBT_OPTS: process.env['SBT_OPTS'],
    DOTNET_ROOT: process.env['DOTNET_ROOT'],
    NUGET_PACKAGES: process.env['NUGET_PACKAGES'],
    COMPOSER_HOME: process.env['COMPOSER_HOME'],
    COMPOSER_CACHE_DIR: process.env['COMPOSER_CACHE_DIR'],
    GEM_HOME: process.env['GEM_HOME'],
    BUNDLE_PATH: process.env['BUNDLE_PATH'],
    PUB_CACHE: process.env['PUB_CACHE'],
    MIX_HOME: process.env['MIX_HOME'],
    HEX_HOME: process.env['HEX_HOME'],
    MIX_ENV: process.env['MIX_ENV'],
    HEX_OFFLINE: process.env['HEX_OFFLINE'],
    CLJ_CONFIG: process.env['CLJ_CONFIG'],
    LEIN_HOME: process.env['LEIN_HOME'],
    LEIN_JVM_OPTS: process.env['LEIN_JVM_OPTS'],
    AUTOMATED_API_VCPKG: process.env['AUTOMATED_API_VCPKG'],
  }
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex')
}
