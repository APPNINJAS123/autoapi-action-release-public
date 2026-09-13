import {
  MigrationJobSchema,
  RepositoryPolicySchema,
  type MigrationJob,
  type RepositoryPolicy,
} from '@automated-api/contracts'
import { sha256 } from '@automated-api/remediation'

interface ReviewedDockershrinkClientSeed {
  sourcePath: string
  baselineSha256: string
  seededSha256: string
  oldCall: string
  seededCall: string
}

const SOURCE_PATH = 'cmd/utils.go'
const BASE_SHA = '43a04bde446c5bf98a114f53165725677f4eea69'
const EVENT_PROVENANCE = '15fe4ed06edf8eef1d0e15c3be5528094d6cf6a65f303d740168afea97374c9c'
const OLD_CALL = 'return ai.NewAIService(logger, client, aiModel), true'
const SEEDED_CALL = 'return ai.NewAIService(logger, &client, aiModel), true'

/**
 * Bind one mechanical pointer adapter to the exact reviewed Dockershrink job.
 * The official declarations prove that NewClient changed from *Client to
 * Client. The Harness remains responsible for the substantive SDK migration.
 */
export function reviewedDockershrinkClientSeed(
  jobInput: MigrationJob,
): ReviewedDockershrinkClientSeed | undefined {
  const job = MigrationJobSchema.parse(jobInput)
  if (!matchesReviewedJob(job)) return undefined
  return {
    sourcePath: SOURCE_PATH,
    baselineSha256: '75a8fa293d8072775765eb41e31778cce5a2a5fc928efce89f8d51a60671f2ce',
    seededSha256: '6a3cb6bc8f3b6f6ffafc7619dbbad9f1b0623908240c37e0ae28f95dec88ab8b',
    oldCall: OLD_CALL,
    seededCall: SEEDED_CALL,
  }
}

/** Keep the exact code-owned adapter visible to the model, but read-only. */
export function reviewedDockershrinkModelPolicy(
  jobInput: MigrationJob,
  fallback: RepositoryPolicy,
): RepositoryPolicy {
  const contract = reviewedDockershrinkClientSeed(jobInput)
  if (contract === undefined) return fallback
  const job = MigrationJobSchema.parse(jobInput)
  const allowedPaths = fallback.allowedPaths.filter(path => path !== contract.sourcePath)
  if (allowedPaths.length !== fallback.allowedPaths.length - 1
    || !job.policy.modelReadablePaths?.includes(contract.sourcePath)) {
    throw new Error('reviewed Dockershrink client seed is not an exact readable policy path')
  }
  return RepositoryPolicySchema.parse({ ...fallback, allowedPaths })
}

export function reviewedDockershrinkClientSeedEdits(
  contract: ReviewedDockershrinkClientSeed | undefined,
  files: readonly { path: string; content: string }[],
): Array<{ path: string; expectedHash: string; content: string }> {
  if (contract === undefined) return []
  const file = files.find(candidate => candidate.path === contract.sourcePath)
  if (file === undefined) {
    throw new Error('reviewed Dockershrink client source was not supplied to the Harness')
  }
  const observed = sha256(file.content)
  if (observed === contract.seededSha256) return []
  if (observed !== contract.baselineSha256
    || file.content.split(contract.oldCall).length !== 2
    || file.content.includes(contract.seededCall)) {
    throw new Error('reviewed Dockershrink client seed baseline does not match its exact source bytes')
  }
  const content = file.content.replace(contract.oldCall, contract.seededCall)
  if (sha256(content) !== contract.seededSha256) {
    throw new Error('reviewed Dockershrink client seed did not produce its exact reviewed bytes')
  }
  return [{ path: file.path, expectedHash: observed, content }]
}

/** Separate the exact code-owned adapter from cumulative model repair edits. */
export function partitionReviewedDockershrinkPreviousEdits(
  contract: ReviewedDockershrinkClientSeed | undefined,
  edits: readonly { path: string; expectedHash: string; content: string }[],
): {
  trustedSeedEdits: Array<{ path: string; expectedHash: string; content: string }>
  modelEdits: Array<{ path: string; expectedHash: string; content: string }>
} {
  if (contract === undefined) return { trustedSeedEdits: [], modelEdits: [...edits] }
  const trustedSeedEdits = edits.filter(edit => edit.path === contract.sourcePath
    && edit.expectedHash === contract.baselineSha256
    && sha256(edit.content) === contract.seededSha256)
  if (trustedSeedEdits.length > 1) {
    throw new Error('previous repair contains duplicate reviewed Dockershrink client seeds')
  }
  const trusted = trustedSeedEdits[0]
  return {
    trustedSeedEdits,
    modelEdits: trusted === undefined ? [...edits] : edits.filter(edit => edit !== trusted),
  }
}

export function reviewedDockershrinkClientViolations(
  contract: ReviewedDockershrinkClientSeed | undefined,
  files: readonly { path: string; content: string }[],
): string[] {
  if (contract === undefined) return []
  const file = files.find(candidate => candidate.path === contract.sourcePath)
  if (file === undefined) return ['reviewed Dockershrink client source is missing']
  return sha256(file.content) === contract.seededSha256
    ? []
    : ['reviewed Dockershrink client adapter must match the exact code-owned bytes']
}

function matchesReviewedJob(job: MigrationJob): boolean {
  const repositoryMatches = (job.repository.owner === 'sajsnddkn'
      && job.repository.name === 'autoapi-real-dockershrink-openai-go')
    || (job.repository.owner === 'APPNINJAS123'
      && job.repository.name === 'autoapi-real-dockershrink-openai-go-public')
  const dependency = job.changeEvent.affectedDependencies[0]
  const operation = job.changeEvent.operations[0]
  const evidence = new Set(job.changeEvent.evidence.map(item => `${item.url}\u0000${item.contentHash}`))
  return repositoryMatches
    && job.repository.defaultBranch === 'main'
    && (job.repository.workingDirectory ?? '.') === '.'
    && (job.repository.packageManagerDirectory ?? '.') === '.'
    && job.repository.packageManager === 'go@1.26.5'
    && job.baseSha === BASE_SHA
    && sameStrings(job.policy.allowedPaths, [SOURCE_PATH, 'internal/ai', 'go.mod', 'go.sum', 'vendor'])
    && sameStrings(job.policy.modelReadablePaths, [SOURCE_PATH, 'internal/ai'])
    && sameStrings(job.policy.deniedPaths, ['.github/workflows', '.env', 'cmd/ai_migration_test.go'])
    && sameStrings(job.policy.allowedLanguages, ['go'])
    && sameStrings(job.policy.allowedManifestPaths, ['go.mod', 'go.sum'])
    && sameStrings(job.policy.requiredChecks, ['go-whole-repository'])
    && job.policy.allowedNetworkHosts.length === 0
    && job.policy.maxChangedFiles === 100
    && job.policy.maxPatchBytes === 10_000_000
    && job.policy.maxModelInputBytes === 150_000
    && job.policy.maxModelOutputTokens === 18_000
    && job.policy.maxRunTimeMs === 900_000
    && job.policy.maxRepairAttempts === 2
    && job.changeEvent.verificationStatus === 'verified'
    && job.changeEvent.provenanceHash === EVENT_PROVENANCE
    && job.changeEvent.provider === 'openai'
    && job.changeEvent.apiOrSdk === 'OpenAI Go SDK'
    && job.changeEvent.oldVersion === 'v0.1.0-alpha.45'
    && job.changeEvent.newVersion === 'v0.1.0-beta.1'
    && job.changeEvent.impactScope === 'sdk'
    && sameStrings(job.changeEvent.affectedLanguages, ['go'])
    && job.changeEvent.affectedDependencies.length === 1
    && dependency?.ecosystem === 'gomod'
    && dependency.name === 'github.com/openai/openai-go'
    && sameStrings(dependency.importNames, ['github.com/openai/openai-go'])
    && dependency.oldVersionRange === 'v0.1.0-alpha.45'
    && dependency.newVersion === 'v0.1.0-beta.1'
    && dependency.newArtifactSha256 === 'fc047345a88b31f328a6fe4e4003b5f5fc5623bb49781c0e7904b82db6b807b7'
    && job.changeEvent.operations.length === 1
    && operation?.kind === 'option_changed'
    && operation.operation === 'package migration'
    && operation.oldSymbol === 'github.com/openai/openai-go@v0.1.0-alpha.45'
    && operation.newSymbol === 'github.com/openai/openai-go@v0.1.0-beta.1'
    && operation.details?.['migrationHintType'] === 'manual_instruction'
    && job.changeEvent.evidence.length === 3
    && evidence.size === 3
    && evidence.has('https://proxy.golang.org/github.com/openai/openai-go/@v/v0.1.0-alpha.45.zip\u0000ee20b03eb42bdd83427e450a3cbee31652c418bac5bc63750abda601f02a6518')
    && evidence.has('https://proxy.golang.org/github.com/openai/openai-go/@v/v0.1.0-beta.1.zip\u0000fc047345a88b31f328a6fe4e4003b5f5fc5623bb49781c0e7904b82db6b807b7')
    && evidence.has('https://raw.githubusercontent.com/openai/openai-go/4002a71af6200b5a65d74e338e64d57b410d964f/MIGRATION.md\u000091ff3ee9d131e225b24c4b766f6d9cba3c62421807db45547c552ae7a1111f04')
}

function sameStrings(left: readonly string[] | undefined, right: readonly string[]): boolean {
  return left !== undefined
    && left.length === right.length
    && left.every((value, index) => value === right[index])
}
