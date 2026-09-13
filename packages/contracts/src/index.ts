import { z } from 'zod'

export const SCHEMA_VERSION = '1.0' as const
export const MAX_HARNESS_JOB_RUNTIME_MS = 10 * 60 * 1000
export const MAX_HARNESS_VALIDATION_RESERVE_MS = 3 * 60 * 1000

export function boundedHarnessJobRuntimeMs(maxRunTimeMs: number): number {
  if (!Number.isSafeInteger(maxRunTimeMs) || maxRunTimeMs <= 0) {
    throw new Error('Harness job runtime must be a positive integer')
  }
  return Math.min(maxRunTimeMs, MAX_HARNESS_JOB_RUNTIME_MS)
}

export function harnessJobDeadlineAt(
  maxRunTimeMs: number,
  nowMs = Date.now(),
): string {
  return new Date(nowMs + boundedHarnessJobRuntimeMs(maxRunTimeMs)).toISOString()
}

export function harnessValidationReserveMs(maxRunTimeMs: number): number {
  const effectiveRuntimeMs = boundedHarnessJobRuntimeMs(maxRunTimeMs)
  return Math.min(
    Math.floor(effectiveRuntimeMs * 0.3),
    MAX_HARNESS_VALIDATION_RESERVE_MS,
  )
}

export function harnessModelDeadlineAtMs(
  jobDeadlineAtMs: number,
  maxRunTimeMs: number,
): number {
  if (!Number.isFinite(jobDeadlineAtMs)) throw new Error('Harness job deadline must be finite')
  return jobDeadlineAtMs - harnessValidationReserveMs(maxRunTimeMs)
}

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u, 'expected a lowercase SHA-256 hash')
const GitShaSchema = z.string().regex(/^[a-f0-9]{40}$/u, 'expected a full Git SHA')
const DiagnosticCountSchema = z.number().int().min(0).max(10_000_000)
export const OfficialBackfillReasonCodeSchema = z.enum([
  'verified', 'rights_blocked', 'package_identity_blocked', 'review_rejected', 'contradictory_evidence',
  'missing_review_evidence', 'review_not_confirmed', 'category_mismatch', 'invalid_review_citations',
  'missing_sdk_citation', 'missing_documentation_citation', 'unresolved_candidate_evidence',
  'no_breaking_finding', 'no_migration_documentation', 'untrusted_evidence', 'other_withheld_reason',
])
const OfficialBackfillDecisionDiagnosticSchema = z.object({
  candidateHash: Sha256Schema,
  reviewEligible: z.boolean(),
  effectiveReviewDecision: z.enum(['confirmed', 'suspected', 'rejected', 'needs_human']),
  missingEvidenceCount: DiagnosticCountSchema,
  contradictionCount: DiagnosticCountSchema,
  verificationStatus: z.enum(['verified', 'probable', 'uncertain', 'blocked']),
  reasonCodes: z.array(OfficialBackfillReasonCodeSchema).max(20),
}).strict()
const OfficialBackfillSourceHashesSchema = z.array(z.object({
  role: z.enum(['old_sdk', 'new_sdk', 'old_documentation', 'new_documentation']),
  sha256: Sha256Schema,
}).strict()).max(8).superRefine((entries, context) => {
  const seen = new Set<string>()
  for (const [index, entry] of entries.entries()) {
    const key = `${entry.role}:${entry.sha256}`
    if (seen.has(key)) {
      context.addIssue({ code: 'custom', message: 'duplicate source role/hash receipt', path: [index] })
    }
    seen.add(key)
  }
})
const OfficialBackfillTransitionDiagnosticSchema = z.object({
  transitionHash: Sha256Schema,
  status: z.enum(['verified', 'withheld']),
  publishedEvents: DiagnosticCountSchema,
  sdkFindings: DiagnosticCountSchema.optional(),
  documentationFindings: DiagnosticCountSchema.optional(),
  reviewedCandidates: DiagnosticCountSchema.optional(),
  verifiedCandidates: DiagnosticCountSchema.optional(),
  withheldReasonCodes: z.array(OfficialBackfillReasonCodeSchema).max(20),
  sourceHashes: OfficialBackfillSourceHashesSchema,
  decisions: z.array(OfficialBackfillDecisionDiagnosticSchema).max(100),
  omittedDecisions: DiagnosticCountSchema,
}).strict()
export const OfficialBackfillDiagnosticsSchema = z.object({
  schemaVersion: z.literal('official-backfill-diagnostics-v1'),
  productAcceptance: z.literal(false),
  selectorHash: Sha256Schema,
  stage: z.enum(['backfill_started', 'backfill_failed', 'backfill_complete', 'persisted_event_reuse',
    'event_export_failed', 'event_exported']),
  transitions: z.array(OfficialBackfillTransitionDiagnosticSchema).max(100),
  omittedTransitions: DiagnosticCountSchema,
}).strict()
export type OfficialBackfillDiagnostics = z.infer<typeof OfficialBackfillDiagnosticsSchema>
const RelativePathSchema = z.string().min(1).refine(
  value => !value.startsWith('/')
    && !value.startsWith('\\')
    && !/^[a-zA-Z]:[\\/]/u.test(value)
    && !value.split(/[\\/]/u).includes('..'),
  'expected a workspace-relative path without parent traversal',
)
const RepositoryDirectorySchema = RelativePathSchema.refine(
  value => /^[A-Za-z0-9._ /-]+$/u.test(value.replaceAll('\\', '/')),
  'expected a repository directory without control characters',
)
const PackageManagerSpecSchema = z.union([
  z.string().regex(
    /^(?:(?:npm|pnpm|yarn|pip|uv|python|cargo|go|maven|gradle|sbt|dotnet|composer|bundler|swift|dart|mix|leiningen)@\d+\.\d+\.\d+|clojure@\d+\.\d+\.\d+(?:\.\d+)?)(?:\+sha(?:224|256|384|512)\.[a-f0-9]+)?$/iu,
    'expected an exact supported package-manager or language-runtime version',
  ),
  z.string().regex(
    /^vcpkg@[a-f0-9]{40}$/u,
    'expected vcpkg at one canonical lowercase Git commit',
  ),
])

export const PackageEcosystemSchema = z.enum([
  'npm', 'pypi', 'cargo', 'gomod', 'maven', 'nuget', 'composer', 'gem', 'swiftpm', 'pub', 'hex', 'vcpkg',
])
export const RepositoryLanguageSchema = z.enum([
  'javascript', 'typescript', 'python', 'rust', 'go',
  'java', 'kotlin', 'scala', 'csharp', 'php', 'ruby', 'swift', 'dart', 'elixir', 'clojure', 'c', 'cpp',
])
export const ChangeImpactScopeSchema = z.enum(['sdk', 'api', 'sdk_and_api'])
export const ChangeAuthoritySchema = z.enum(['verified', 'probable', 'uncertain', 'blocked'])

export const AffectedDependencySchema = z.object({
  ecosystem: PackageEcosystemSchema,
  name: z.string().min(1),
  importNames: z.array(z.string().min(1)).default([]),
  oldVersionRange: z.string().min(1).optional(),
  newVersion: z.string().min(1).optional(),
  newArtifactSha256: Sha256Schema.optional(),
})

export const EvidenceReferenceSchema = z.object({
  url: z.string().url(),
  contentHash: Sha256Schema,
  title: z.string().min(1).optional(),
  excerpt: z.object({
    kind: z.literal('sdk_declarations'),
    text: z.string().min(1).max(24_000),
    sha256: Sha256Schema,
    partial: z.literal(true),
  }).strict().optional(),
})

export const ChangeOperationSchema = z.object({
  kind: z.enum([
    'method_renamed',
    'parameter_renamed',
    'parameter_removed',
    'option_changed',
    'endpoint_version_changed',
  ]),
  operation: z.string().min(1),
  oldSymbol: z.string().min(1).optional(),
  newSymbol: z.string().min(1).optional(),
  details: z.record(z.string(), z.unknown()).default({}),
})

export const ChangeEventSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  id: z.string().min(1),
  provider: z.string().min(1),
  apiOrSdk: z.string().min(1),
  affectedPackages: z.array(z.string().min(1)).default([]),
  // Ecosystem-qualified targets prevent a same-named npm and PyPI package from
  // selecting each other's analyzers or recipes. Legacy affectedPackages rows
  // remain valid and are interpreted as npm by compatibility helpers.
  affectedDependencies: z.array(AffectedDependencySchema).default([]),
  affectedLanguages: z.array(RepositoryLanguageSchema).default([]),
  affectedApiHosts: z.array(z.string().min(1)).default([]),
  // SDK/package histories and raw HTTP API contracts are separate impact
  // domains. Legacy events default to both, while every newly produced event
  // declares its scope explicitly so a package release cannot match unrelated
  // raw REST calls merely because both belong to the same provider.
  impactScope: ChangeImpactScopeSchema.default('sdk_and_api'),
  oldVersion: z.string().min(1),
  newVersion: z.string().min(1),
  verificationStatus: z.literal('verified'),
  verifiedAt: z.string().datetime(),
  // Required by docs/mvp_plan.md §4: the ChangeEvent contract must carry
  // "affected symbols, recipes, confidence, and provenance hashes". This was
  // missing from the original contract; added during Part A/Part B
  // reconciliation so Person A's verification confidence survives the
  // handoff instead of being silently dropped at the publish boundary.
  confidence: z.number().min(0).max(1),
  operations: z.array(ChangeOperationSchema).min(1),
  evidence: z.array(EvidenceReferenceSchema).min(1),
  provenanceHash: Sha256Schema,
  recipeIds: z.array(z.string().min(1)).default([]),
})

// Probable events deliberately use a separate wire contract. They can
// authorize a bounded sandbox investigation, but never inherit the trust or
// publication authority of a verified ChangeEvent.
export const ProbableChangeEventSchema = ChangeEventSchema.omit({
  verificationStatus: true,
  verifiedAt: true,
}).extend({
  verificationStatus: z.literal('probable'),
  classifiedAt: z.string().datetime(),
  reasonCodes: z.array(z.string().min(1)).min(1),
})

export const ActionableChangeEventSchema = z.union([
  ChangeEventSchema,
  ProbableChangeEventSchema,
])

export const SourceLocationSchema = z.object({
  path: RelativePathSchema,
  line: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  column: z.number().int().positive(),
  symbol: z.string().min(1).optional(),
}).refine(location => location.endLine === undefined || location.endLine >= location.line, {
  message: 'endLine must not precede line',
  path: ['endLine'],
})

export const ImpactEvidenceSchema = z.object({
  kind: z.enum([
    'sdk_import',
    'sdk_call',
    'raw_rest_endpoint',
    'dynamic_usage',
    'dependency',
    'python_import',
    'python_call',
    'python_dependency',
    'python_raw_endpoint',
    'rust_import',
    'rust_call',
    'rust_dependency',
    'rust_raw_endpoint',
    'go_import',
    'go_call',
    'go_dependency',
    'go_raw_endpoint',
    'c_import',
    'c_call',
    'c_dependency',
    'c_raw_endpoint',
    'cpp_import',
    'cpp_call',
    'cpp_dependency',
    'cpp_raw_endpoint',
  ]),
  operation: z.string().min(1),
  location: SourceLocationSchema.optional(),
  detail: z.string().min(1),
  deterministicRecipeSupported: z.boolean(),
  language: RepositoryLanguageSchema.optional(),
  ecosystem: PackageEcosystemSchema.optional(),
  workspace: RelativePathSchema.optional(),
})

export const RepositoryImpactSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  changeEventId: z.string().min(1),
  baseSha: GitShaSchema,
  outcome: z.enum(['not_affected', 'affected_manual', 'affected_draftable', 'blocked']),
  evidence: z.array(ImpactEvidenceSchema),
  reasons: z.array(z.string().min(1)),
})

export const CommandSpecSchema = z.object({
  executable: z.string().min(1),
  args: z.array(z.string()).default([]),
  timeoutMs: z.number().int().positive().max(30 * 60 * 1000),
})

export const RepositoryPolicySchema = z.object({
  allowedPaths: z.array(RelativePathSchema).min(1),
  modelReadablePaths: z.array(RelativePathSchema).min(1).optional(),
  deniedPaths: z.array(RelativePathSchema).default(['.github/workflows']),
  validationCommands: z.array(CommandSpecSchema).max(10),
  allowedNetworkHosts: z.array(z.string().min(1)).default([]),
  maxChangedFiles: z.number().int().positive().max(100),
  maxPatchBytes: z.number().int().positive().max(10 * 1024 * 1024),
  maxModelInputBytes: z.number().int().positive().max(2 * 1024 * 1024),
  maxModelOutputTokens: z.number().int().positive().max(100_000),
  maxRunTimeMs: z.number().int().positive().max(60 * 60 * 1000),
  maxRepairAttempts: z.number().int().min(1).max(2).default(1),
  requiredChecks: z.array(z.string().min(1)).default([]),
  allowedLanguages: z.array(RepositoryLanguageSchema).optional(),
  allowedManifestPaths: z.array(RelativePathSchema).optional(),
  probableChanges: z.object({
    // Probable changes may publish only labelled, preflight-tested PRs that are
    // ready for maintainer review. They never receive merge authority, and
    // repositories can still opt out explicitly. `allowDraftPr` is retained as
    // the wire-compatible name for this publication permission.
    enabled: z.boolean().default(true),
    allowHarness: z.boolean().default(true),
    allowDraftPr: z.boolean().default(true),
    maxChangedFiles: z.number().int().positive().max(25).default(10),
    maxPatchBytes: z.number().int().positive().max(1024 * 1024).default(500_000),
  }).default({}),
})

export const HarnessRepairEditBoundarySchema = z.object({
  path: RelativePathSchema,
  expectedHash: Sha256Schema,
  ranges: z.array(z.object({
    start: z.number().int().positive(),
    end: z.number().int().positive(),
  }).refine(range => range.end >= range.start, 'end must not precede start')).max(10_000),
})

export const ValidatedHarnessEditScopeSchema = z.object({
  schemaVersion: z.literal('validated-harness-edit-scope-v1'),
  jobId: z.string().min(1),
  baseSha: GitShaSchema,
  changeEventId: z.string().min(1),
  repairAttempt: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  files: z.array(HarnessRepairEditBoundarySchema).min(1).max(100),
})

export const MigrationJobSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  id: z.string().min(1),
  // Absolute budget shared by dispatch, Harness execution, dependency
  // bootstrap, offline validation, and repair. Optional only so persisted
  // pre-deadline records remain parseable; executors reject a missing value.
  deadlineAt: z.string().datetime().optional(),
  tenantId: z.string().min(1),
  installationId: z.number().int().positive(),
  repository: z.object({
    owner: z.string().min(1),
    name: z.string().min(1),
    defaultBranch: z.string().min(1),
    workingDirectory: RepositoryDirectorySchema.default('.'),
    packageManagerDirectory: RepositoryDirectorySchema.optional(),
    packageManager: PackageManagerSpecSchema.optional(),
    pythonEnvironment: z.object({
      extras: z.array(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u)).max(20).default([]),
      noDev: z.boolean().default(false),
    }).strict().optional(),
  }),
  baseSha: GitShaSchema,
  changeEvent: ActionableChangeEventSchema,
  policy: RepositoryPolicySchema,
  repairAttempt: z.union([z.literal(0), z.literal(1), z.literal(2)]).default(0),
  repairContext: z.object({
    parentJobId: z.string().min(1),
    failedChecks: z.array(z.string().min(1)).max(100),
    // Deterministic impact recomputed by the production Action after the
    // target dependencies were installed. Repair must retain these exact
    // usage locations instead of falling back to a dependency-light scan.
    validatedImpact: RepositoryImpactSchema.optional(),
    validatedEditScope: ValidatedHarnessEditScopeSchema.optional(),
    diagnostics: z.array(z.string().min(1).max(4_000)).max(10).optional(),
    validationContext: z.array(z.object({
      path: RelativePathSchema,
      content: z.string().max(8_000),
    })).max(3).optional(),
    previousEdits: z.array(z.object({
      path: RelativePathSchema,
      expectedHash: Sha256Schema,
      content: z.string(),
    })).max(100).optional(),
  }).optional(),
})

const BaseNormalizationCommitSchema = z.object({
  sha: GitShaSchema,
  summary: z.string().min(1),
})

export const BaseNormalizationSchema = z.preprocess((input) => {
  // Keep normalized cases written before the discriminator parseable while
  // making newly-authored identity and snapshot-import records explicit.
  if (typeof input !== 'object' || input === null || 'kind' in input) return input
  const commits = 'commits' in input ? input.commits : undefined
  if (!Array.isArray(commits)) return input
  return { ...input, kind: commits.length === 0 ? 'identity' : 'commit_chain' }
}, z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('identity'),
    fromSha: GitShaSchema,
    commits: z.tuple([]),
  }),
  z.object({
    kind: z.literal('commit_chain'),
    fromSha: GitShaSchema,
    commits: z.array(BaseNormalizationCommitSchema).min(1),
  }),
  z.object({
    kind: z.literal('snapshot_import'),
    sourceSha: GitShaSchema,
    commits: z.array(BaseNormalizationCommitSchema).min(1),
  }),
]))

export const RealRepositoryCaseSchema = z.object({
  id: z.string().min(1),
  eventPath: RelativePathSchema,
  baseSha: GitShaSchema,
  baseNormalization: BaseNormalizationSchema,
  upstream: z.union([
    z.string().url(),
    z.object({ repository: z.string().min(1), sha: GitShaSchema }).passthrough(),
  ]),
  repository: MigrationJobSchema.shape.repository,
  policy: RepositoryPolicySchema,
}).superRefine((value, context) => {
  const normalization = value.baseNormalization
  const upstreamSha = typeof value.upstream === 'string'
    ? value.upstream.match(/\/tree\/([a-f0-9]{40})(?:\/|$)/u)?.[1]
    : value.upstream.sha
  if (normalization.kind === 'identity' && normalization.fromSha !== value.baseSha) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'fromSha'],
      message: 'identity normalization must start at baseSha',
    })
  }
  if (normalization.kind === 'identity' && upstreamSha !== undefined && upstreamSha !== value.baseSha) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'fromSha'],
      message: 'identity normalization must match the selected upstream SHA',
    })
  }
  if (normalization.kind !== 'identity' && normalization.commits.at(-1)?.sha !== value.baseSha) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'commits'],
      message: 'normalization commits must end at baseSha',
    })
  }
  if (normalization.kind === 'commit_chain'
    && normalization.commits.some(commit => commit.sha === normalization.fromSha)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'commits'],
      message: 'commit-chain normalization must list only commits after fromSha',
    })
  }
  if (normalization.kind === 'commit_chain'
    && upstreamSha !== undefined && normalization.fromSha !== upstreamSha) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'fromSha'],
      message: 'commit-chain normalization must start at the selected upstream SHA',
    })
  }
  const commitShas = normalization.commits.map(commit => commit.sha)
  if (new Set(commitShas).size !== commitShas.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['baseNormalization', 'commits'],
      message: 'normalization commits must be unique',
    })
  }
  if (normalization.kind === 'snapshot_import') {
    if (upstreamSha !== undefined && normalization.sourceSha !== upstreamSha) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['baseNormalization', 'sourceSha'],
        message: 'snapshot import must identify the selected upstream SHA',
      })
    }
  }
})

export const HarnessRequestSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  jobId: z.string().min(1),
  baseSha: GitShaSchema,
  impact: RepositoryImpactSchema,
  repairAttempt: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  authority: z.enum(['verified', 'probable']).default('verified'),
  unresolvedFiles: z.array(z.object({
    path: RelativePathSchema,
    expectedHash: Sha256Schema,
    content: z.string(),
  })).min(1).max(100),
  // Runner-derived exact windows after applying hash-validated prior edits.
  // These replace stale original-file windows; they are never model output.
  repairEditBoundaries: z.array(HarnessRepairEditBoundarySchema).max(100).optional(),
  // Verified code-owned source edits applied virtually before the model sees
  // a file. Dependency manifests remain excluded and are updated separately
  // by the deterministic package manager in the offline runner.
  seedEdits: z.array(z.object({
    path: RelativePathSchema,
    expectedHash: Sha256Schema,
    content: z.string(),
  })).max(100).optional(),
  previousAttempt: z.object({
    edits: z.array(z.object({
      path: RelativePathSchema,
      expectedHash: Sha256Schema,
      content: z.string(),
    })).max(100),
    failedChecks: z.array(z.string().min(1)).max(100),
    diagnostics: z.array(z.string().min(1).max(4_000)).max(10).optional(),
    validationContext: z.array(z.object({
      path: RelativePathSchema,
      content: z.string().max(8_000),
    })).max(3).optional(),
  }).optional(),
})

export const HarnessResultSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  jobId: z.string().min(1),
  baseSha: GitShaSchema,
  repairAttempt: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  edits: z.array(z.object({
    path: RelativePathSchema,
    expectedHash: Sha256Schema,
    content: z.string(),
  })).max(100),
  summary: z.string().min(1),
  confidence: z.number().min(0).max(1),
  // Explicit source compatibility conclusions, hash-bound by the executor.
  // Absence of source edits alone is never an affirmative compatibility review.
  readOnlyCompatibility: z.array(z.object({
    path: RelativePathSchema,
    expectedHash: Sha256Schema,
    verdict: z.enum(['compatible', 'changes_required', 'uncertain']),
  })).max(100).refine(entries => new Set(entries.map(entry => entry.path)).size === entries.length,
    'read-only compatibility paths must be unique').optional(),
  provider: z.string().min(1).default('deepseek'),
  model: z.string().min(1),
  finishReason: z.string().min(1),
  // Optional only for persisted pre-release-identity results. Credentialed
  // production acceptance requires this exact worker build identity.
  workerReleaseSha: GitShaSchema.optional(),
})

export const PreflightValidationFailureSchema = z.object({
  status: z.literal('validation_failed'),
  impact: RepositoryImpactSchema,
  validatedEditScope: ValidatedHarnessEditScopeSchema.optional(),
  failureKind: z.enum(['code', 'infrastructure']).optional(),
  failedChecks: z.array(z.string().min(1).max(500)).min(1).max(100),
  diagnostics: z.array(z.string().min(1).max(4_000)).max(10).optional(),
  validationContext: z.array(z.object({
    path: RelativePathSchema,
    content: z.string().max(8_000),
  })).max(3).optional(),
})

export const ExecutionFailureSchema = z.object({
  status: z.literal('execution_failed'),
  failureCode: z.literal('github_actions_step_failed'),
  failureKind: z.literal('infrastructure').optional(),
  failureReason: z.enum(['timeout', 'process_failure']).optional(),
  stage: z.enum(['prepare_dependencies', 'workflow']).optional(),
  phase: z.enum([
    'job_fetch',
    'proposal',
    'harness_wait',
    'harness_validation',
    'artifact_selection',
    'artifact_upload',
    'callback_delivery',
    'workflow',
  ]),
  runId: z.string().regex(/^\d+$/u).max(100),
  runAttempt: z.number().int().positive().max(100),
}).strict()

export const RoutingRouteSchema = z.enum([
  'deterministic',
  'harness',
  'manual',
  'blocked',
  'failed',
])

export const FileChangeSchema = z.object({
  path: RelativePathSchema,
  operation: z.enum(['add', 'modify', 'delete']),
  mode: z.enum(['100644', '100755']).default('100644'),
  beforeHash: Sha256Schema.optional(),
  afterHash: Sha256Schema.optional(),
  contentBase64: z.string().optional(),
}).superRefine((value, context) => {
  if (value.operation === 'delete' && value.contentBase64 !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'deleted files cannot contain content' })
  }
  if (value.operation !== 'delete' && value.contentBase64 === undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'added or modified files require content' })
  }
})

export const ValidationCommandResultSchema = z.object({
  command: CommandSpecSchema,
  exitCode: z.number().int().nullable(),
  timedOut: z.boolean(),
  durationMs: z.number().int().nonnegative(),
  stdoutHash: Sha256Schema,
  stderrHash: Sha256Schema,
})

const SemanticToolchainManagerSchema = z.object({
  name: z.enum([
    'npm', 'pnpm', 'yarn', 'pip', 'uv', 'python', 'cargo', 'go',
    'maven', 'gradle', 'sbt', 'dotnet', 'composer', 'bundler', 'swift', 'dart',
    'mix', 'clojure', 'leiningen', 'none',
  ]),
  version: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/u),
  spec: z.string().min(3).max(200),
  variant: z.enum([
    'npm', 'pnpm', 'yarn-classic', 'yarn-berry', 'python-pip', 'python-uv',
    'python-stdlib', 'rust-cargo', 'go-modules', 'jvm-maven', 'jvm-gradle', 'scala-sbt',
    'dotnet-nuget', 'php-composer', 'ruby-bundler', 'swift-package', 'dart-pub', 'elixir-mix',
    'clojure-tools-deps', 'clojure-leiningen',
    'analysis-only',
  ]),
})

const SemanticToolchainVariantPolicy = Object.freeze({
  npm: { name: 'npm', runtime: ['node'], managerRuntime: undefined, lockfile: true },
  pnpm: { name: 'pnpm', runtime: ['node'], managerRuntime: undefined, lockfile: true },
  'yarn-classic': { name: 'yarn', runtime: ['node'], managerRuntime: undefined, lockfile: true },
  'yarn-berry': { name: 'yarn', runtime: ['node'], managerRuntime: undefined, lockfile: true },
  'python-pip': { name: 'pip', runtime: ['node', 'python'], managerRuntime: undefined, lockfile: true },
  'python-uv': { name: 'uv', runtime: ['node', 'python'], managerRuntime: undefined, lockfile: true },
  'python-stdlib': { name: 'python', runtime: ['node', 'python'], managerRuntime: 'python', lockfile: false },
  'rust-cargo': { name: 'cargo', runtime: ['node', 'rust', 'cargo'], managerRuntime: 'cargo', lockfile: true },
  'go-modules': { name: 'go', runtime: ['node', 'go'], managerRuntime: 'go', lockfile: true },
  'jvm-maven': { name: 'maven', runtime: ['node', 'java', 'maven'], managerRuntime: 'maven', lockfile: true },
  'jvm-gradle': { name: 'gradle', runtime: ['node', 'java', 'gradle'], managerRuntime: 'gradle', lockfile: true },
  'scala-sbt': { name: 'sbt', runtime: ['node', 'java', 'scala', 'sbt', 'coursier'], managerRuntime: 'sbt', lockfile: true },
  // A single-project NuGet repository has the ordinary lock receipt. A
  // solution-wide repository deliberately records lockfile "." and instead
  // requires the complete sorted NuGet graph receipt at current verification.
  'dotnet-nuget': { name: 'dotnet', runtime: ['node', 'dotnet'], managerRuntime: 'dotnet', lockfile: 'optional' },
  'php-composer': { name: 'composer', runtime: ['node', 'php', 'composer'], managerRuntime: 'composer', lockfile: true },
  'ruby-bundler': { name: 'bundler', runtime: ['node', 'ruby', 'bundler'], managerRuntime: 'bundler', lockfile: true },
  'swift-package': { name: 'swift', runtime: ['node', 'swift'], managerRuntime: 'swift', lockfile: true },
  'dart-pub': { name: 'dart', runtime: ['node', 'dart'], managerRuntime: 'dart', lockfile: true },
  'elixir-mix': { name: 'mix', runtime: ['node', 'elixir', 'mix', 'hex', 'rebar3'], managerRuntime: 'mix', lockfile: true },
  'clojure-tools-deps': { name: 'clojure', runtime: ['node', 'java', 'clojure'], managerRuntime: undefined, lockfile: true },
  'clojure-leiningen': { name: 'leiningen', runtime: ['node', 'java', 'clojure', 'leiningen'], managerRuntime: 'leiningen', lockfile: true },
  'analysis-only': { name: 'none', runtime: ['node'], managerRuntime: undefined, lockfile: false },
} as const)

const VcpkgToolchainManagerSchema = z.object({
  name: z.literal('vcpkg'),
  version: GitShaSchema,
  spec: z.string().regex(/^vcpkg@[a-f0-9]{40}$/u),
  variant: z.enum(['c-vcpkg', 'cpp-vcpkg']),
}).refine(value => value.spec === `vcpkg@${value.version}`, {
  message: 'vcpkg spec must identify the certified Git commit',
  path: ['spec'],
})

const ElixirToolArtifactSchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+$/u),
  url: z.string().url().regex(/^https:\/\/builds\.hex\.pm\/installs\//u),
  sha512: z.string().regex(/^[a-f0-9]{128}$/u),
})

export const ToolchainCertificationSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  jobId: z.string().min(1),
  baseSha: GitShaSchema,
  manager: z.union([SemanticToolchainManagerSchema, VcpkgToolchainManagerSchema]),
  runtime: z.object({
    node: z.string().regex(/^\d+\.\d+\.\d+$/u),
    python: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    rust: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    cargo: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    go: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    java: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    maven: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    gradle: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    scala: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    sbt: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    coursier: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    dotnet: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    php: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    composer: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    ruby: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    bundler: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    swift: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    dart: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    elixir: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    mix: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    hex: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    rebar3: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    clojure: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/u).optional(),
    leiningen: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    cc: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    cxx: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    cmake: z.string().regex(/^\d+\.\d+\.\d+$/u).optional(),
    vcpkg: GitShaSchema.optional(),
  }),
  // Records a repository-owned compatibility line separately from the exact,
  // immutable runtime selected for this job. For example, `.python-version`
  // may request 3.13 while `runtime.python` certifies 3.13.11.
  runtimeRequirements: z.object({
    python: z.string().regex(/^\d+\.\d+$/u).optional(),
  }).optional(),
  elixirTools: z.object({
    hex: ElixirToolArtifactSchema,
    rebar3: ElixirToolArtifactSchema,
  }).optional(),
  lockfile: z.object({
    path: RelativePathSchema,
    beforeHash: Sha256Schema,
    afterHash: Sha256Schema,
  }).optional(),
  vcpkgResolution: z.object({
    manifestPath: RelativePathSchema,
    beforeHash: Sha256Schema,
    afterHash: Sha256Schema,
    projectionHash: Sha256Schema,
  }).optional(),
  pythonEnvironmentReceiptHash: Sha256Schema.optional(),
  // Hash of the complete NuGet lock inventory checked against immutable base
  // blobs before the runner receives any model edits.
  nugetLockGraphHash: Sha256Schema.optional(),
  reviewedJvmToolchain: z.object({
    policyVersion: z.literal('reviewed-jvm-toolchain-v1'),
    repositoryBinding: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u),
    managerSpec: z.string().regex(/^(?:maven|sbt)@\d+\.\d+\.\d+$/u),
    javaVersion: z.string().regex(/^\d+\.\d+\.\d+$/u),
    workflowPath: RelativePathSchema,
    workflowSha256: Sha256Schema,
    wrapper: z.object({
      path: RelativePathSchema,
      sha256: Sha256Schema,
      archiveUrl: z.string().url().startsWith('https://'),
      archiveSha512: z.string().regex(/^[a-f0-9]{128}$/u),
    }).optional(),
  }).optional(),
  runnerImageId: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  runtimeImages: z.array(z.string().regex(/^[a-z0-9./_-]+(?::[a-zA-Z0-9._-]+)?@sha256:[a-f0-9]{64}$/u)).min(1).max(12),
  lifecycleScriptsDisabled: z.literal(true),
  networkDisabledVerification: z.literal(true),
  certifiedAt: z.string().datetime(),
  certificationKey: Sha256Schema,
}).superRefine((value, context) => {
  const runtimeKeys = Object.entries(value.runtime)
    .filter(([, version]) => version !== undefined)
    .map(([tool]) => tool)
    .sort()
  if (value.manager.name === 'vcpkg') {
    const expectedRuntime = ['node', value.manager.variant === 'c-vcpkg' ? 'cc' : 'cxx', 'cmake', 'vcpkg'].sort()
    if (JSON.stringify(runtimeKeys) !== JSON.stringify(expectedRuntime)
      || value.runtime.vcpkg !== value.manager.version) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['runtime'], message: 'vcpkg runtime does not match its certified variant and commit' })
    }
    if (value.lockfile !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['lockfile'], message: 'vcpkg uses its resolved manifest receipt instead of a lockfile receipt' })
    }
  } else {
    const policy = SemanticToolchainVariantPolicy[value.manager.variant]
    const plainSpec = `${value.manager.name}@${value.manager.version}`
    const integritySuffix = value.manager.spec.slice(plainSpec.length)
    const allowsIntegrity = value.manager.spec.startsWith(plainSpec)
      && ['npm', 'pnpm', 'yarn'].includes(value.manager.name)
      && /^\+sha(?:224|256|384|512)\.[a-f0-9]+$/u.test(integritySuffix)
    if (value.manager.name !== policy.name
      || (value.manager.spec !== plainSpec && !allowsIntegrity)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['manager'], message: 'toolchain manager name, spec, version, and variant do not match' })
    }
    if (JSON.stringify(runtimeKeys) !== JSON.stringify([...policy.runtime].sort())) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['runtime'], message: 'toolchain runtime inventory does not match its manager variant' })
    }
    if (policy.managerRuntime !== undefined
      && value.runtime[policy.managerRuntime] !== value.manager.version) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['runtime', policy.managerRuntime], message: 'package-manager runtime does not match its certified version' })
    }
    if (policy.lockfile !== 'optional' && policy.lockfile !== (value.lockfile !== undefined)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['lockfile'], message: 'toolchain lockfile receipt does not match its manager variant' })
    }
  }
  if (value.runtimeRequirements !== undefined
    && ((!value.manager.variant.startsWith('python-'))
      || value.runtimeRequirements.python === undefined
      || value.runtime.python?.startsWith(`${value.runtimeRequirements.python}.`) !== true)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['runtimeRequirements'], message: 'runtime compatibility requirement does not match the certified Python runtime' })
  }
  if (value.nugetLockGraphHash !== undefined && value.manager.variant !== 'dotnet-nuget') {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['nugetLockGraphHash'], message: 'NuGet lock graph receipts require dotnet certification' })
  }
  if (value.reviewedJvmToolchain !== undefined
    && ((!['jvm-maven', 'scala-sbt'].includes(value.manager.variant))
      || value.reviewedJvmToolchain.managerSpec !== value.manager.spec
      || value.reviewedJvmToolchain.javaVersion !== value.runtime.java
      || !value.reviewedJvmToolchain.repositoryBinding.endsWith(`@${value.baseSha}`))) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['reviewedJvmToolchain'], message: 'Reviewed JVM metadata does not match the certified runtime, manager, or base' })
  }
  const requiresPythonEnvironmentReceipt = value.manager.variant === 'python-uv'
    && value.manager.version === '0.12.5'
  if ((value.pythonEnvironmentReceiptHash !== undefined) !== requiresPythonEnvironmentReceipt) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['pythonEnvironmentReceiptHash'],
      message: 'Python environment receipt does not match the certified uv execution route',
    })
  }
  if (value.lockfile !== undefined && value.lockfile.beforeHash !== value.lockfile.afterHash) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'certification lockfile changed' })
  }
  if ((value.manager.variant === 'c-vcpkg' || value.manager.variant === 'cpp-vcpkg') && value.vcpkgResolution === undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['vcpkgResolution'], message: 'C/C++ certificates require exact customer and projection manifest evidence' })
  }
  if (value.manager.variant !== 'c-vcpkg' && value.manager.variant !== 'cpp-vcpkg' && value.vcpkgResolution !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['vcpkgResolution'], message: 'vcpkg resolution evidence is only valid for C/C++ certificates' })
  }
  if (value.manager.variant === 'elixir-mix'
    && (value.elixirTools === undefined || value.runtime.hex === undefined || value.runtime.rebar3 === undefined)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['elixirTools'],
      message: 'Elixir certificates require verified Hex and Rebar3 runtimes and immutable artifacts',
    })
  }
  if (value.manager.variant !== 'elixir-mix' && value.elixirTools !== undefined) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['elixirTools'],
      message: 'Elixir tools are only valid for Mix certificates',
    })
  }
  if (value.elixirTools !== undefined
    && (value.runtime.hex !== value.elixirTools.hex.version
      || value.runtime.rebar3 !== value.elixirTools.rebar3.version
      || value.runtime.elixir !== value.manager.version)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['elixirTools'],
      message: 'Elixir tool artifact versions must match the verified runtimes',
    })
  }
})

export const ProposalArtifactSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  jobId: z.string().min(1),
  changeEventId: z.string().min(1),
  changeEventProvenanceHash: Sha256Schema,
  authority: z.enum(['verified', 'probable']).default('verified'),
  baseSha: GitShaSchema,
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  impact: RepositoryImpactSchema,
  recipeId: z.string().min(1).optional(),
  model: z.object({
    provider: z.string().min(1),
    model: z.string().min(1),
    confidence: z.number().min(0).max(1),
    finishReason: z.string().min(1).optional(),
  }).optional(),
  toolVersions: z.object({
    runner: z.string().min(1),
    node: z.string().min(1),
    typescript: z.string().min(1),
    tsMorph: z.string().min(1),
    python: z.string().min(1).optional(),
    rust: z.string().min(1).optional(),
    cargo: z.string().min(1).optional(),
    go: z.string().min(1).optional(),
    java: z.string().min(1).optional(),
    maven: z.string().min(1).optional(),
    gradle: z.string().min(1).optional(),
    scala: z.string().min(1).optional(),
    sbt: z.string().min(1).optional(),
    coursier: z.string().min(1).optional(),
    dotnet: z.string().min(1).optional(),
    php: z.string().min(1).optional(),
    composer: z.string().min(1).optional(),
    ruby: z.string().min(1).optional(),
    bundler: z.string().min(1).optional(),
    swift: z.string().min(1).optional(),
    dart: z.string().min(1).optional(),
    elixir: z.string().min(1).optional(),
    mix: z.string().min(1).optional(),
    clojure: z.string().min(1).optional(),
    leiningen: z.string().min(1).optional(),
    cc: z.string().min(1).optional(),
    cxx: z.string().min(1).optional(),
    cmake: z.string().min(1).optional(),
    vcpkg: z.string().min(1).optional(),
  }),
  toolchainCertification: ToolchainCertificationSchema.optional(),
  files: z.array(FileChangeSchema),
  validation: z.array(ValidationCommandResultSchema),
  patchHash: Sha256Schema,
  manifestHash: Sha256Schema,
})

export const ValidationRunSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  deliveryId: z.string().min(1),
  repository: z.string().min(3),
  pullRequestNumber: z.number().int().positive(),
  expectedHeadSha: GitShaSchema,
  observedHeadSha: GitShaSchema,
  // `blocked` = the repository declared no required checks, so there is no CI
  // signal to judge. Deliberately distinct from `failed` per docs/mvp_plan.md,
  // which reserves `blocked` for a missing test signal.
  status: z.enum(['pending', 'passed', 'failed', 'stale', 'blocked']),
  requiredChecks: z.array(z.object({
    name: z.string().min(1),
    status: z.enum(['queued', 'in_progress', 'completed']),
    conclusion: z.string().nullable(),
    id: z.number().int().positive().optional(),
    detailsUrl: z.string().url().optional(),
    checkSuiteId: z.number().int().positive().optional(),
    workflowRunId: z.number().int().positive().optional(),
  })),
  repairAttempt: z.number().int().min(0).max(2),
  observedAt: z.string().datetime(),
})

const FullFlowRequiredCheckSchema = z.object({
  name: z.string().min(1),
  status: z.literal('completed'),
  conclusion: z.literal('success'),
  id: z.number().int().positive(),
  detailsUrl: z.string().url(),
  checkSuiteId: z.number().int().positive().optional(),
  workflowRunId: z.number().int().positive(),
}).strict().superRefine((value, context) => {
  if (!value.detailsUrl.includes(`/actions/runs/${value.workflowRunId}/`)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['detailsUrl'],
      message: 'check details URL must identify its workflow run',
    })
  }
})

const IndependentFullFlowAuditSchema = z.object({
  source: z.literal('github_api_post_run'),
  observedAt: z.string().datetime(),
  repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
  pullRequestNumber: z.number().int().positive(),
  author: z.string().min(1),
  state: z.literal('open'),
  isDraft: z.literal(false),
  mergeStateStatus: z.literal('CLEAN'),
  headSha: GitShaSchema,
  files: z.array(z.object({
    path: z.string().min(1),
    status: z.literal('modified'),
    additions: z.number().int().nonnegative(),
    deletions: z.number().int().nonnegative(),
    blobSha: GitShaSchema,
  }).strict()).min(1),
  assertions: z.array(z.string().min(1)).min(1),
  result: z.literal('passed'),
}).strict()

export const ExternalRepositoryFullFlowProofSchema = z.object({
  schemaVersion: z.literal('external-repository-full-flow-proof-v1'),
  generatedAt: z.string().datetime(),
  product: z.object({
    commitSha: GitShaSchema,
    actionSha256: Sha256Schema,
  }).strict(),
  caseId: z.string().min(1),
  externalRepository: z.object({
    repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
    baseSha: GitShaSchema,
    upstream: z.union([
      z.string().url(),
      z.object({ repository: z.string().min(1), sha: GitShaSchema }).strict(),
    ]),
  }).strict(),
  changeEvent: z.object({
    id: z.string().min(1),
    provenanceHash: Sha256Schema,
    source: z.literal('part_a_export'),
    evidence: z.array(z.object({
      url: z.string().url(),
      contentHash: Sha256Schema,
    }).strict()).min(1),
  }).strict(),
  execution: z.object({
    route: z.enum(['deterministic', 'harness_required']),
    repairAttempt: z.number().int().min(0).max(2).optional(),
    modelSelection: z.object({
      initialModel: z.enum(['deepseek/deepseek-v4-flash', 'deepseek/deepseek-v4-flash-0731']),
      repairModel: z.enum(['deepseek/deepseek-v4-flash', 'deepseek/deepseek-v4-flash-0731', 'deepseek/deepseek-v4.1-flash']),
    }).strict().optional(),
    model: z.object({
      provider: z.string().min(1),
      model: z.string().min(1),
    }).strict().optional(),
  }).strict(),
  localProposal: z.object({
    status: z.literal('proposed'),
    artifactBaseSha: GitShaSchema,
    changeEventId: z.string().min(1),
    changeEventProvenanceHash: Sha256Schema,
    patchHash: Sha256Schema,
    manifestHash: Sha256Schema,
    validation: z.array(ValidationCommandResultSchema).min(1),
  }).strict(),
  publication: z.object({
    number: z.number().int().positive(),
    url: z.string().url(),
    branch: z.string().min(1),
    headSha: GitShaSchema,
    state: z.literal('open'),
    isDraft: z.literal(false),
    replayReused: z.literal(true),
  }).strict(),
  hostedCi: z.object({
    // Historical v1 proofs remain readable; current acceptance generation
    // independently requires this code-owned workflow-content receipt.
    reviewedWorkflow: z.object({
      checkoutPolicy: z.literal('exact-head-v1'),
      baseSha: GitShaSchema,
      headSha: GitShaSchema,
      workflowFile: z.string().regex(/^[A-Za-z0-9_.-]+\.ya?ml$/u),
      workflowMode: z.literal('100644'),
      workflowBlobSha: GitShaSchema,
      workflowSha256: Sha256Schema,
      requiredCheck: z.string().min(1),
      workflowRunId: z.number().int().positive(),
      workflowJobId: z.number().int().positive(),
      checkoutAssertionStep: z.string().min(1).max(200),
      checkoutAssertionPassed: z.literal(true),
    }).strict().optional(),
    status: z.literal('passed'),
    exactHeadMatched: z.literal(true),
    expectedHeadSha: GitShaSchema,
    observedHeadSha: GitShaSchema,
    requiredChecks: z.array(FullFlowRequiredCheckSchema).min(1),
    workflowRuns: z.array(z.object({
      id: z.number().int().positive(),
      url: z.string().url(),
    }).strict()).min(1),
    observedAt: z.string().datetime(),
  }).strict(),
  independentAudit: IndependentFullFlowAuditSchema.optional(),
}).strict().superRefine((value, context) => {
  const issue = (path: Array<string | number>, message: string): void => {
    context.addIssue({ code: z.ZodIssueCode.custom, path, message })
  }
  if (value.localProposal.artifactBaseSha !== value.externalRepository.baseSha) {
    issue(['localProposal', 'artifactBaseSha'], 'local proposal must use the certified external base')
  }
  if (value.localProposal.changeEventId !== value.changeEvent.id) {
    issue(['localProposal', 'changeEventId'], 'local proposal must identify the persisted Part A event')
  }
  if (value.localProposal.changeEventProvenanceHash !== value.changeEvent.provenanceHash) {
    issue(['localProposal', 'changeEventProvenanceHash'], 'local proposal must bind the Part A provenance hash')
  }
  if (value.localProposal.validation.some(result => result.exitCode !== 0 || result.timedOut)) {
    issue(['localProposal', 'validation'], 'every local validation command must complete successfully')
  }
  if (value.publication.headSha !== value.hostedCi.expectedHeadSha
    || value.publication.headSha !== value.hostedCi.observedHeadSha) {
    issue(['hostedCi'], 'hosted CI must pass at the published exact head')
  }
  const selection = value.execution.modelSelection
  if (selection !== undefined && value.execution.repairAttempt === undefined) {
    issue(['execution', 'repairAttempt'], 'configured model selection must record the actual job repair attempt')
  }
  const allowedModels = selection === undefined
    ? ['deepseek/deepseek-v4-flash', 'deepseek/deepseek-v4-flash-0731']
    : value.execution.repairAttempt === 0 ? [selection.initialModel, selection.repairModel] : [selection.repairModel]
  const observedModels = value.execution.model?.model.split(',') ?? []
  if (value.execution.route === 'harness_required'
    && (value.execution.model?.provider !== 'openrouter'
      || observedModels.length === 0
      || (selection === undefined && observedModels.length !== 1)
      || new Set(observedModels).size !== observedModels.length
      || observedModels.some(model => !allowedModels.includes(model)))) {
    issue(['execution', 'model'], 'Harness proof must identify the configured DeepSeek V4 model for its attempt through OpenRouter')
  }
  const workflowIds = new Set(value.hostedCi.workflowRuns.map(run => run.id))
  const receipt = value.hostedCi.reviewedWorkflow
  if (receipt !== undefined) {
    const check = value.hostedCi.requiredChecks[0]
    const expectedDetails = `https://github.com/${value.externalRepository.repository}/actions/runs/${receipt.workflowRunId}/job/${receipt.workflowJobId}`
    if (receipt.baseSha !== value.externalRepository.baseSha || receipt.headSha !== value.publication.headSha
      || value.hostedCi.requiredChecks.length !== 1 || check?.name !== receipt.requiredCheck
      || check.workflowRunId !== receipt.workflowRunId || check.detailsUrl !== expectedDetails) {
      issue(['hostedCi', 'reviewedWorkflow'], 'reviewed workflow receipt must identify the exact base, published head, and successful required job')
    }
  }
  for (const [index, check] of value.hostedCi.requiredChecks.entries()) {
    if (!workflowIds.has(check.workflowRunId)) {
      issue(['hostedCi', 'requiredChecks', index, 'workflowRunId'], 'required check must reference a recorded workflow run')
    }
  }
  const expectedWorkflowPrefix = `https://github.com/${value.externalRepository.repository}/actions/runs/`
  for (const [index, run] of value.hostedCi.workflowRuns.entries()) {
    if (run.url !== `${expectedWorkflowPrefix}${run.id}`) {
      issue(['hostedCi', 'workflowRuns', index, 'url'], 'workflow URL must match the external repository and run ID')
    }
  }
  if (value.independentAudit !== undefined) {
    if (value.independentAudit.repository !== value.externalRepository.repository) {
      issue(['independentAudit', 'repository'], 'independent audit must identify the external repository')
    }
    if (value.independentAudit.pullRequestNumber !== value.publication.number) {
      issue(['independentAudit', 'pullRequestNumber'], 'independent audit must identify the published pull request')
    }
    if (value.independentAudit.headSha !== value.publication.headSha) {
      issue(['independentAudit', 'headSha'], 'independent audit must inspect the published exact head')
    }
  }
})

export const OutcomeRecordSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  id: z.string().min(1),
  tenantId: z.string().min(1),
  runId: z.string().min(1),
  jobId: z.string().min(1),
  provider: z.string().min(1),
  changeEventId: z.string().min(1).optional(),
  changeSignalId: z.string().min(1).optional(),
  repository: z.string().min(3),
  baseSha: GitShaSchema,
  headSha: GitShaSchema.optional(),
  pullRequestNumber: z.number().int().positive().optional(),
  outcome: z.enum([
    'not_affected',
    'affected_manual',
    'draft_opened',
    'ci_pending',
    'ci_passed',
    'ci_failed',
    'stale_head',
    'merged',
    'rejected',
    'human_corrected',
  ]),
  changedFiles: z.array(RelativePathSchema).max(100).default([]),
  failureCategory: z.enum([
    'required_check_failed',
    'required_check_missing',
    'stale_head',
    'policy',
    'unsupported',
  ]).optional(),
  repairAttempt: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  resolution: z.string().min(1).max(500),
  observedAt: z.string().datetime(),
  rights: z.object({
    allowedToTrain: z.literal(false).default(false),
    allowedToRedistribute: z.literal(false).default(false),
    allowedToSell: z.literal(false).default(false),
    allowedToAggregate: z.boolean().default(false),
  }).default({}),
}).strict().superRefine((record, context) => {
  if (Number(record.changeEventId !== undefined) + Number(record.changeSignalId !== undefined) !== 1) {
    context.addIssue({
      code: 'custom',
      message: 'exactly one verified change event or probable change signal is required',
      path: ['changeEventId'],
    })
  }
})

export const HarnessLearningRecordSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  id: z.string().min(1),
  tenantId: z.string().min(1),
  repository: z.string().min(3),
  jobId: z.string().min(1),
  pullRequestNumber: z.number().int().positive(),
  provider: z.string().min(1),
  changeEventId: z.string().min(1),
  commitSha: GitShaSchema,
  changedFiles: z.array(RelativePathSchema).max(100).default([]),
  changeSummary: z.string().min(1).max(500),
  failureSummary: z.string().min(1).max(500),
  resolution: z.string().min(1).max(500),
  apiChanged: z.string().min(1).max(500),
  validationSource: z.literal('exact_head_ci'),
  observedAt: z.string().datetime(),
  rights: z.object({
    allowedToTrain: z.literal(false).default(false),
    allowedToRedistribute: z.literal(false).default(false),
    allowedToSell: z.literal(false).default(false),
  }).default({}),
}).strict()

// This is the only projection supplied to Harness. Customer identity, repository,
// commit SHA, paths, patches, prompts, and CI output stay in the private record.
export const HarnessLessonSchema = HarnessLearningRecordSchema.pick({
  provider: true,
  changeEventId: true,
  changeSummary: true,
  failureSummary: true,
  resolution: true,
  apiChanged: true,
  observedAt: true,
}).strict()

export type ChangeEvent = z.infer<typeof ChangeEventSchema>
export type ProbableChangeEvent = z.infer<typeof ProbableChangeEventSchema>
export type ActionableChangeEvent = z.infer<typeof ActionableChangeEventSchema>
export type ChangeAuthority = z.infer<typeof ChangeAuthoritySchema>
export type ChangeOperation = z.infer<typeof ChangeOperationSchema>
export type AffectedDependency = z.infer<typeof AffectedDependencySchema>
export type ChangeImpactScope = z.infer<typeof ChangeImpactScopeSchema>
export type PackageEcosystem = z.infer<typeof PackageEcosystemSchema>
export type RepositoryLanguage = z.infer<typeof RepositoryLanguageSchema>
export type CommandSpec = z.infer<typeof CommandSpecSchema>
export type FileChange = z.infer<typeof FileChangeSchema>
export type ImpactEvidence = z.infer<typeof ImpactEvidenceSchema>
export type HarnessRequest = z.infer<typeof HarnessRequestSchema>
export type HarnessRepairEditBoundary = z.infer<typeof HarnessRepairEditBoundarySchema>
export type ValidatedHarnessEditScope = z.infer<typeof ValidatedHarnessEditScopeSchema>
export type HarnessResult = z.infer<typeof HarnessResultSchema>
export type HarnessLearningRecord = z.infer<typeof HarnessLearningRecordSchema>
export type HarnessLesson = z.infer<typeof HarnessLessonSchema>
export type PreflightValidationFailure = z.infer<typeof PreflightValidationFailureSchema>
export type ExecutionFailure = z.infer<typeof ExecutionFailureSchema>
export type MigrationJob = z.infer<typeof MigrationJobSchema>
export type RealRepositoryCase = z.infer<typeof RealRepositoryCaseSchema>
export type OutcomeRecord = z.infer<typeof OutcomeRecordSchema>
export type ProposalArtifact = z.infer<typeof ProposalArtifactSchema>
export type RepositoryImpact = z.infer<typeof RepositoryImpactSchema>
export type RepositoryPolicy = z.infer<typeof RepositoryPolicySchema>
export type RoutingRoute = z.infer<typeof RoutingRouteSchema>
export type ValidationCommandResult = z.infer<typeof ValidationCommandResultSchema>
export type ToolchainCertification = z.infer<typeof ToolchainCertificationSchema>
export type ValidationRun = z.infer<typeof ValidationRunSchema>
export type ExternalRepositoryFullFlowProof = z.infer<typeof ExternalRepositoryFullFlowProofSchema>
