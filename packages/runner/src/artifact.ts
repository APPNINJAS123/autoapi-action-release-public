import { readFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import type {
  FileChange,
  MigrationJob,
  ProposalArtifact,
  RepositoryImpact,
  RepositoryPolicy,
  ValidationCommandResult,
} from '@automated-api/contracts'
import { ProposalArtifactSchema } from '@automated-api/contracts'
import { assertPathAllowed, resolveExistingPathInsideRepository, sha256 } from '@automated-api/remediation'
import { detectPackageManager, type PackageManagerPlan } from './dependencies.js'
import { git } from './git.js'
import { readToolchainCertification } from './toolchainCertification.js'

interface BuildArtifactInput {
  rootDir: string
  job: MigrationJob
  impact: RepositoryImpact
  validation: ValidationCommandResult[]
  intendedFiles?: FileChange[]
  recipeId?: string
  model?: ProposalArtifact['model']
  now?: Date
  ttlMs?: number
}

export async function buildProposalArtifact(input: BuildArtifactInput): Promise<{
  artifact: ProposalArtifact
  patch: Buffer
}> {
  const intendedFiles = input.intendedFiles
  const intendedPaths = intendedFiles?.map(file => file.path)
  const patch = await git(input.rootDir, [
    'diff', '--binary', '--no-ext-diff', input.job.baseSha, '--', ...(intendedPaths ?? []),
  ])
  if (patch.length > input.job.policy.maxPatchBytes) {
    throw new Error('patch exceeds repository policy')
  }
  const files = await collectFileChanges(
    input.rootDir,
    input.job,
    intendedPaths === undefined ? undefined : new Set(intendedPaths),
  )
  if (intendedFiles !== undefined && !sameFileStates(intendedFiles, files)) {
    throw new Error('validation mutated an intended proposal file')
  }
  if (files.length > input.job.policy.maxChangedFiles) {
    throw new Error('changed file count exceeds repository policy')
  }

  const now = input.now ?? new Date()
  const toolchainCertification = await certificationFromEnvironment(input.job)
  if (toolchainCertification?.manager.variant === 'c-vcpkg' || toolchainCertification?.manager.variant === 'cpp-vcpkg') {
    const directory = input.job.repository.packageManagerDirectory ?? input.job.repository.workingDirectory ?? '.'
    const manifestPath = [directory === '.' ? '' : directory, toolchainCertification.vcpkgResolution!.manifestPath]
      .filter(Boolean).join('/')
    const manifest = files.find(file => file.path === manifestPath)
    if (manifest === undefined
      || manifest.beforeHash !== toolchainCertification.vcpkgResolution!.beforeHash
      || manifest.afterHash !== toolchainCertification.vcpkgResolution!.afterHash) {
      throw new Error('C/C++ proposal manifest does not match certified vcpkg resolution')
    }
  }
  const scalaToolVersions = toolchainCertification === undefined
    && input.job.changeEvent.affectedLanguages.includes('scala')
    ? await uncertifiedScalaToolVersions(input.rootDir, input.job)
    : undefined
  const withoutManifestHash = {
    schemaVersion: '1.0' as const,
    jobId: input.job.id,
    changeEventId: input.job.changeEvent.id,
    changeEventProvenanceHash: input.job.changeEvent.provenanceHash,
    authority: input.job.changeEvent.verificationStatus,
    baseSha: input.job.baseSha,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + (input.ttlMs ?? 24 * 60 * 60 * 1000)).toISOString(),
    impact: input.impact,
    ...(input.recipeId === undefined ? {} : { recipeId: input.recipeId }),
    ...(input.model === undefined ? {} : { model: input.model }),
    toolVersions: {
      runner: '0.1.0',
      node: process.version,
      typescript: '5.7.3',
      tsMorph: '25.0.1',
      ...(toolchainCertification === undefined ? {
        ...(input.job.changeEvent.affectedLanguages.includes('python')
        ? { python: pythonVersion() }
        : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('rust')
        ? { rust: commandVersion('rustc', ['--version'], /^rustc\s+(\d+\.\d+\.\d+)/u) }
        : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('rust')
        ? { cargo: commandVersion('cargo', ['--version'], /^cargo\s+(\d+\.\d+\.\d+)/u) }
        : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('go')
        ? { go: commandVersion('go', ['version'], /\bgo(\d+\.\d+\.\d+)\b/u) }
        : {}),
      ...(input.job.changeEvent.affectedLanguages.some(language => language === 'java' || language === 'kotlin')
        ? {
            java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)/u),
            ...(commandAvailable('mvn') ? { maven: commandVersion('mvn', ['--version'], /Apache Maven (\d+\.\d+\.\d+)/u) } : {}),
            ...(commandAvailable('gradle') ? { gradle: commandVersion('gradle', ['--version'], /Gradle (\d+\.\d+\.\d+)/u) } : {}),
          }
        : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('scala')
        ? scalaToolVersions
        : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('csharp')
        ? { dotnet: commandVersion('dotnet', ['--version'], /^(\d+\.\d+\.\d+)/u) } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('php')
        ? { php: commandVersion('php', ['--version'], /^PHP (\d+\.\d+\.\d+)/u), composer: commandVersion('composer', ['--version'], /Composer version (\d+\.\d+\.\d+)/u) } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('ruby')
        ? { ruby: commandVersion('ruby', ['--version'], /^ruby (\d+\.\d+\.\d+)/u), bundler: commandVersion('bundle', ['--version'], /Bundler version (\d+\.\d+\.\d+)/u) } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('swift')
        ? { swift: commandVersion('swift', ['--version'], /Swift version (\d+\.\d+\.\d+)/u) } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('dart')
        ? { dart: commandVersion('dart', ['--version'], /Dart SDK version: (\d+\.\d+\.\d+)/u) } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('clojure')
        ? {
            java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)/u),
            clojure: commandVersion('clojure', ['-Srepro', '-M', '-e', '(print (clojure-version))'], /^(\d+\.\d+\.\d+)$/u),
            ...(commandAvailable('lein') ? { leiningen: commandVersion('lein', ['version'], /Leiningen (\d+\.\d+\.\d+)/u) } : {}),
          } : {}),
      ...(input.job.changeEvent.affectedLanguages.includes('c') || input.job.changeEvent.affectedLanguages.includes('cpp')
        ? {
            ...(input.job.changeEvent.affectedLanguages.includes('c')
              ? { cc: commandVersion(process.env['AUTOMATED_API_CC'] ?? 'cc', ['--version'], /\b(\d+\.\d+\.\d+)\b/u) }
              : { cxx: commandVersion(process.env['AUTOMATED_API_CXX'] ?? 'c++', ['--version'], /(?:clang version|(?:g\+\+|c\+\+)[^\n]*?)\s(\d+\.\d+\.\d+)/u) }),
            cmake: commandVersion(process.env['AUTOMATED_API_CMAKE'] ?? 'cmake', ['--version'], /cmake version (\d+\.\d+\.\d+)/u),
          } : {}),
      } : toolchainCertification.runtime),
    },
    ...(toolchainCertification === undefined ? {} : { toolchainCertification }),
    files,
    validation: input.validation,
    patchHash: sha256(patch),
  }
  const artifact = ProposalArtifactSchema.parse({
    ...withoutManifestHash,
    manifestHash: sha256(canonicalize(withoutManifestHash)),
  })
  return { artifact, patch }
}

async function uncertifiedScalaToolVersions(
  rootDir: string,
  job: MigrationJob,
): Promise<{ java: string; scala: string; sbt: string; coursier: string }> {
  const managerRoot = await resolveExistingPathInsideRepository(
    rootDir,
    job.repository.packageManagerDirectory ?? job.repository.workingDirectory,
  )
  const manager = await detectPackageManager(managerRoot, 'scala', {
    reviewedJvmContext: { job, repositoryRoot: rootDir },
  })
  const plan = scalaArtifactRuntimePlan(manager)
  return {
    java: commandVersion('java', ['-version'], /version "(\d+\.\d+\.\d+)/u),
    scala: plan.scala,
    sbt: commandVersion('cs', plan.sbtArgs, /(\d+\.\d+\.\d+)/u, 30_000),
    coursier: commandVersion('cs', ['version'], /(\d+\.\d+\.\d+)/u),
  }
}

export function scalaArtifactRuntimePlan(manager: PackageManagerPlan): {
  scala: string
  sbtArgs: string[]
} {
  if (manager.variant !== 'scala-sbt' || manager.scalaVersion === undefined) {
    throw new Error('Scala artifact provenance requires an exact sbt and scalaVersion plan')
  }
  return {
    scala: manager.scalaVersion,
    sbtArgs: ['launch', '--mode', 'offline', `sbt:${manager.version}`, '--', 'show sbtVersion'],
  }
}

async function certificationFromEnvironment(
  job: MigrationJob,
): Promise<ProposalArtifact['toolchainCertification']> {
  const path = process.env['AUTOMATED_API_TOOLCHAIN_CERTIFICATE']?.trim()
  if (path === undefined || path === '') return undefined
  const certification = await readToolchainCertification(path)
  if (certification.jobId !== job.id || certification.baseSha !== job.baseSha) {
    throw new Error('toolchain certification does not match the migration job')
  }
  return certification
}

export async function captureProposalFiles(
  rootDir: string,
  job: MigrationJob,
): Promise<FileChange[]> {
  return collectFileChanges(rootDir, job)
}

function sameFileStates(before: FileChange[], after: FileChange[]): boolean {
  const state = (files: FileChange[]) => files.map(file => ({
    path: file.path,
    operation: file.operation,
    mode: file.mode,
    beforeHash: file.beforeHash,
    afterHash: file.afterHash,
  }))
  return canonicalize(state(before)) === canonicalize(state(after))
}

function pythonVersion(): string {
  const executable = process.env['AUTOMATED_API_PYTHON'] ?? 'python3'
  const result = spawnSync(executable, ['--version'], {
    encoding: 'utf8', timeout: 10_000,
    env: { PATH: process.env['PATH'], PYTHONNOUSERSITE: '1' },
  })
  if (result.status !== 0) throw new Error('Python runtime version could not be recorded')
  const match = `${result.stdout}${result.stderr}`.match(/Python\s+(\d+\.\d+\.\d+)/u)
  if (match?.[1] === undefined) throw new Error('Python runtime returned an invalid version')
  return match[1]
}

function commandAvailable(command: string): boolean {
  return spawnSync(command, ['--version'], { encoding: 'utf8', timeout: 5_000, env: { PATH: process.env['PATH'] } }).status === 0
}

function commandVersion(executable: string, args: string[], pattern: RegExp, timeoutMs = 10_000): string {
  const result = spawnSync(executable, args, {
    encoding: 'utf8', timeout: timeoutMs,
    env: {
      PATH: process.env['PATH'],
      HOME: process.env['HOME'],
      JAVA_HOME: process.env['JAVA_HOME'],
      COURSIER_CACHE: process.env['COURSIER_CACHE'],
      SBT_OPTS: process.env['SBT_OPTS'],
      CARGO_HOME: process.env['CARGO_HOME'],
      RUSTUP_HOME: process.env['RUSTUP_HOME'],
      RUSTUP_TOOLCHAIN: process.env['RUSTUP_TOOLCHAIN'],
    },
  })
  if (result.status !== 0) throw new Error(`${executable} runtime version could not be recorded`)
  const match = `${result.stdout}${result.stderr}`.match(pattern)
  if (match?.[1] === undefined) throw new Error(`${executable} runtime returned an invalid version`)
  return match[1]
}

/**
 * Order-independent JSON serialization for the manifest hash.
 *
 * The hash is computed here over a freshly-built object but re-computed in
 * verifyProposalArtifact over a zod-parsed one, and zod rebuilds objects in
 * schema declaration order at every nesting level. Plain JSON.stringify would
 * make the integrity check depend on incidental key ordering, so reordering a
 * schema field or adding a `.default()` would break every artifact.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(',')}}`
}

async function collectFileChanges(
  rootDir: string,
  job: MigrationJob,
  includedPaths?: Set<string>,
): Promise<FileChange[]> {
  const output = await git(rootDir, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
  const entries = output.toString('utf8').split('\0').filter(Boolean)
  const changes: FileChange[] = []
  for (const entry of entries) {
    const status = entry.slice(0, 2)
    if (status.includes('R') || status.includes('C')) {
      throw new Error('renamed and copied files are outside the MVP artifact contract')
    }
    const rawPath = entry.slice(3)
    if (includedPaths !== undefined && !includedPaths.has(rawPath)) continue
    const path = assertPathAllowed(rawPath, job.policy)
    const deleted = status.includes('D')
    const added = status === '??' || status.includes('A')
    let before: Buffer | undefined
    let mode: FileChange['mode'] = '100644'
    if (!added) {
      before = await git(rootDir, ['show', `${job.baseSha}:${path}`])
      const treeEntry = (await git(rootDir, ['ls-tree', job.baseSha, '--', path])).toString('utf8').trim()
      if (treeEntry.startsWith('100755 ')) mode = '100755'
    }
    if (deleted) {
      changes.push({
        path,
        operation: 'delete',
        mode,
        ...(before === undefined ? {} : { beforeHash: sha256(before) }),
      })
      continue
    }
    const content = await readFile(await resolveExistingPathInsideRepository(rootDir, path))
    changes.push({
      path,
      operation: added ? 'add' : 'modify',
      mode,
      ...(before === undefined ? {} : { beforeHash: sha256(before) }),
      afterHash: sha256(content),
      contentBase64: content.toString('base64'),
    })
  }
  return changes.sort((left, right) => left.path.localeCompare(right.path))
}

export function verifyProposalArtifact(
  artifact: ProposalArtifact,
  patch: Buffer,
  expectedBaseSha: string,
  now = new Date(),
): void {
  ProposalArtifactSchema.parse(artifact)
  if (artifact.baseSha !== expectedBaseSha) throw new Error('artifact base SHA is stale')
  if (new Date(artifact.expiresAt).getTime() <= now.getTime()) throw new Error('artifact has expired')
  if (artifact.patchHash !== sha256(patch)) throw new Error('artifact patch hash mismatch')
  const { manifestHash, ...withoutManifestHash } = artifact
  if (manifestHash !== sha256(canonicalize(withoutManifestHash))) {
    throw new Error('artifact manifest hash mismatch')
  }
  for (const file of artifact.files) {
    if (file.operation === 'delete') continue
    const content = Buffer.from(file.contentBase64 ?? '', 'base64')
    if (file.afterHash !== sha256(content)) throw new Error(`artifact file hash mismatch for ${file.path}`)
  }
}

export function verifyArtifactAgainstPolicy(
  artifact: ProposalArtifact,
  patch: Buffer,
  policy: RepositoryPolicy,
): void {
  if (artifact.files.length > policy.maxChangedFiles) {
    throw new Error('artifact changed file count exceeds repository policy')
  }
  if (patch.length > policy.maxPatchBytes) {
    throw new Error('artifact patch exceeds repository policy')
  }
  for (const file of artifact.files) assertPathAllowed(file.path, policy)
}
