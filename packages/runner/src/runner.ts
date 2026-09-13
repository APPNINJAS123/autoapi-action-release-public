import { access, readFile, writeFile } from 'node:fs/promises'
import { relative, resolve } from 'node:path'
import {
  HarnessResultSchema,
  MigrationJobSchema,
  harnessModelDeadlineAtMs,
  type ActionableChangeEvent,
  type HarnessRequest,
  type HarnessResult,
  type ImpactEvidence,
  type MigrationJob,
  type PreflightValidationFailure,
  type ProposalArtifact,
  type RepositoryImpact,
  type RepositoryPolicy,
  type ValidatedHarnessEditScope,
} from '@automated-api/contracts'
import {
  analyzeRepository,
  applyFirecrawlV1ToV2Recipe,
  applyFirecrawlPythonV1ToV2Recipe,
  FIRECRAWL_V1_V2_RECIPE_ID,
  FIRECRAWL_PYTHON_V1_V2_RECIPE_ID,
  applyReviewedProviderRecipe,
  applyProposedEdits,
  assertPathAllowed,
  normalizeRepositoryPath,
  resolveExistingPathInsideRepository,
  sha256,
  validateProposedEdits,
  bindHarnessRepairEditBoundaries,
  createHarnessRepairEditBoundaries,
  captureHarnessValidatedEditBoundaries,
  preserveHarnessAffectedUsageWindows,
  jvmDescriptorMethodName,
  reviewedSwiftResponseChange,
  swiftResponseContentAccesses,
  type SwiftResponseContentAccess,
  type MigrationExecutor,
  type MigrationExecutorResult,
  type ProposedEdit,
} from '@automated-api/remediation'
import { buildProposalArtifact, captureProposalFiles } from './artifact.js'
import {
  applyHarnessDependencyManifest,
  CERTIFIED_PYTHON_UV_EXECUTABLE,
  detectPackageManager,
  migrationDependencies,
} from './dependencies.js'
import { verifyFixedHead } from './git.js'
import { assertMaterializedRepositoryInputs } from './repositoryMaterialization.js'
import {
  hasBlockingSyntaxFailure,
  hasPolicyBackedOfflineGradleVerification,
  normalizeChangedNativeSources,
  policyBackedOfflineGradleVerificationIndex,
  runValidationCommands,
  synchronizeDependencies,
  synchronizeGradleDependencyWithPolicyValidation,
  validateChangedSourceSyntax,
  verifySynchronizedDependencyLockfile,
  type ExecutedValidationResult,
} from './process.js'

import { minimizePnpmLockfileChange } from './pnpmLockfileScope.js'
import {
  bindReviewedRepositoryChangeEvent,
  reviewedDdTraceGradleLockMigration,
  reviewedDdTraceModelPolicy,
  reviewedSymfonyPredisImportSeed,
} from './repositoryEventBindings.js'
import { scanTextForSecrets } from './secrets.js'
import {
  certifiedDartRepairUsageWindows,
  isReviewedDartPackageMigration,
  resolvedDartOwnership,
} from './dartOwnership.js'
import { findIncompletePythonResponseContracts } from './pythonResponseContract.js'
import {
  prepareReviewedDdTraceJavaHelper,
  partitionReviewedJavaHelperPreviousEdits,
  reviewedJavaHelperEvidence,
  reviewedJavaHelperSeedEdits,
  reviewedJavaHelperViolations,
} from './reviewedJavaHelper.js'
import { applyReviewedEmbabelKotlinRecipe } from './reviewedKotlinConsumer.js'
import {
  partitionReviewedDockershrinkPreviousEdits,
  reviewedDockershrinkClientSeed,
  reviewedDockershrinkClientSeedEdits,
  reviewedDockershrinkClientViolations,
  reviewedDockershrinkModelPolicy,
} from './reviewedDockershrinkClient.js'

const MAX_VALIDATION_CONTEXT_CHARACTERS = 8_000

export type ProposalRunnerResult =
  | { status: 'not_affected' | 'manual' | 'blocked'; impact: RepositoryImpact }
  | { status: 'harness_required'; impact: RepositoryImpact; request: HarnessRequest }
  | PreflightValidationFailure
  | { status: 'proposed'; impact: RepositoryImpact; artifact: ProposalArtifact; patch: Buffer }

export class ProposalRunner {
  constructor(
    private readonly executor?: MigrationExecutor,
    private readonly harnessNetworkHost = 'api.deepseek.com',
  ) {}

  async run(
    jobInput: MigrationJob,
    rootDir: string,
    harnessResultInput?: HarnessResult,
  ): Promise<ProposalRunnerResult> {
    const parsedJob = MigrationJobSchema.parse(jobInput)
    if (parsedJob.changeEvent.verificationStatus === 'probable'
      && !parsedJob.policy.probableChanges.enabled) {
      return {
        status: 'manual',
        impact: {
          schemaVersion: '1.0', changeEventId: parsedJob.changeEvent.id,
          baseSha: parsedJob.baseSha, outcome: 'affected_manual', evidence: [],
          reasons: ['probable change investigation is not enabled by repository policy'],
        },
      }
    }
    const restrictedJob = restrictProbableJob(parsedJob)
    const reviewedGradleLockMigration = reviewedDdTraceGradleLockMigration(restrictedJob)
    const reviewedDockershrinkClient = reviewedDockershrinkClientSeed(restrictedJob)
    const modelPolicy = reviewedDockershrinkModelPolicy(
      restrictedJob,
      reviewedDdTraceModelPolicy(restrictedJob),
    )
    const job = bindReviewedRepositoryChangeEvent(restrictedJob)
    const commandBudget = job.deadlineAt === undefined
      ? undefined
      : { deadlineAtMs: Date.parse(job.deadlineAt) }
    await verifyFixedHead(rootDir, job.baseSha)
    await assertMaterializedRepositoryInputs(job, rootDir)
    const reviewedJavaHelper = await prepareReviewedDdTraceJavaHelper(restrictedJob, rootDir)
    const workingDir = await resolveExistingPathInsideRepository(
      rootDir,
      job.repository.workingDirectory,
    )
    const packageManagerDir = await resolveExistingPathInsideRepository(
      rootDir,
      job.repository.packageManagerDirectory ?? job.repository.workingDirectory,
    )
    const workspaceImpact = await analyzeRepository({
      rootDir: workingDir,
      runtimeRootDir: packageManagerDir,
      baseSha: job.baseSha,
      changeEvent: job.changeEvent,
    })
    const currentImpact = prefixImpactPaths(workspaceImpact, job.repository.workingDirectory)
    if (isReviewedDartPackageMigration(job)) {
      // A package-version literal or a commented import is not SDK ownership.
      // The certified resolver replaces generic Dart source authority entirely.
      currentImpact.evidence = currentImpact.evidence.filter(item => item.kind === 'dependency')
    }
    currentImpact.evidence.push(...await resolvedDartOwnership(job, rootDir))
    const impact = repairImpact(job, currentImpact)
    const priorScope = job.repairContext?.validatedEditScope
    if (priorScope !== undefined && (priorScope.jobId !== job.repairContext!.parentJobId
      || priorScope.baseSha !== job.baseSha || priorScope.changeEventId !== job.changeEvent.id
      || priorScope.repairAttempt !== job.repairAttempt - 1)) {
      throw new Error('validated repair scope does not match its parent migration job')
    }

    let recipeId: string | undefined
    let dependencyManifestChanged = false
    let changedPaths: string[] = []
    let model: ProposalArtifact['model'] | undefined
    let reviewedGradleLockSeed: ProposedEdit | undefined
    let validatedEditScope: ValidatedHarnessEditScope | undefined
    const reviewedKotlinRecipe = impact.outcome === 'affected_manual'
      && job.repairContext === undefined
      ? await applyReviewedEmbabelKotlinRecipe(rootDir, job)
      : undefined
    if (reviewedKotlinRecipe !== undefined) {
      recipeId = reviewedKotlinRecipe.recipeId
      changedPaths = reviewedKotlinRecipe.changedFiles
      dependencyManifestChanged = reviewedKotlinRecipe.changedFiles.some(path => isDependencyManifest(path))
    } else if (impact.outcome === 'affected_draftable' && job.repairContext === undefined) {
      const result = job.changeEvent.recipeIds.includes(FIRECRAWL_PYTHON_V1_V2_RECIPE_ID)
        ? await applyFirecrawlPythonV1ToV2Recipe(workingDir, workspaceImpact, job.changeEvent)
        : job.changeEvent.provider.toLowerCase() === 'firecrawl'
          ? await applyFirecrawlV1ToV2Recipe(workingDir, workspaceImpact)
          : await applyReviewedProviderRecipe(workingDir, workspaceImpact, job.changeEvent)
      recipeId = result.recipeId
      changedPaths = prefixRepositoryPaths(result.changedFiles, job.repository.workingDirectory)
      dependencyManifestChanged = result.changedFiles.some(path => isDependencyManifest(path))
    } else if (impact.outcome === 'affected_manual' || job.repairContext !== undefined) {
      if (job.changeEvent.verificationStatus === 'probable'
        && !job.policy.probableChanges.allowHarness) {
        return {
          status: 'manual',
          impact: { ...impact, reasons: [...impact.reasons, 'probable Harness investigation is disabled by repository policy'] },
        }
      }
      const missingVerifiedOperations = missingVerifiedHarnessOperations(job.changeEvent, impact)
      if (missingVerifiedOperations.length > 0) {
        return {
          status: 'blocked',
          impact: {
            ...impact,
            outcome: 'blocked',
            reasons: [
              ...impact.reasons,
              `verified ChangeEvent does not authorize migrations for: ${missingVerifiedOperations.join(', ')}`,
            ],
          },
        }
      }
      const migrationRequirements = await captureHarnessMigrationRequirements(
        rootDir,
        impact,
        job.changeEvent,
      )
      const hasCodeOwnedDependencyMigration = migrationDependencies(job).length > 0
      const firecrawlHybridSeedEnabled = isVerifiedFirecrawlHybrid(job.changeEvent)
      const instructionSeedEnabled = verifiedInstructionMethodMappings(job.changeEvent).size > 0
      const repositoryImportSeed = reviewedSymfonyPredisImportSeed(job)
      const codeOwnedSeedEnabled = firecrawlHybridSeedEnabled
        || instructionSeedEnabled
        || repositoryImportSeed !== undefined
        || reviewedJavaHelper !== undefined
        || reviewedDockershrinkClient !== undefined
      const partitionedPreviousEdits = partitionReviewedJavaHelperPreviousEdits(
        reviewedJavaHelper,
        job.repairContext?.previousEdits ?? [],
      )
      const partitionedDockershrinkEdits = partitionReviewedDockershrinkPreviousEdits(
        reviewedDockershrinkClient,
        partitionedPreviousEdits.modelEdits,
      )
      const previousModelEdits = partitionedDockershrinkEdits.modelEdits.filter(edit =>
        !hasCodeOwnedDependencyMigration || !isDependencyManifest(edit.path))
      const loaded = await loadUnresolvedFiles(
        rootDir,
        impact,
        job.policy,
        previousModelEdits,
        job.repairContext?.validationContext ?? [],
        hasCodeOwnedDependencyMigration,
        codeOwnedSeedEnabled,
        priorScope?.files,
        certifiedDartRepairUsageWindows(job),
      )
      const candidateFiles = loaded.files.filter(file => !hasCodeOwnedDependencyMigration || !isDependencyManifest(file.path))
      const readableFiles = candidateFiles.filter(file => scanTextForSecrets(file.content).length === 0)
      const withheldSecretFiles = candidateFiles.length - readableFiles.length
      const seedEdits = reviewedJavaHelper !== undefined
        ? reviewedJavaHelperSeedEdits(reviewedJavaHelper, readableFiles)
        : reviewedDockershrinkClient !== undefined
          ? reviewedDockershrinkClientSeedEdits(reviewedDockershrinkClient, readableFiles)
        : firecrawlHybridSeedEnabled
          ? verifiedFirecrawlHarnessSeedEdits(readableFiles, impact, job.changeEvent)
          : repositoryImportSeed !== undefined
            ? reviewedSymfonyPredisImportSeedEdits(job, readableFiles)
            : instructionSeedEnabled
              ? verifiedInstructionHarnessSeedEdits(readableFiles, impact, job.changeEvent)
              : []
      const unresolvedFiles = overlaySeedEdits(readableFiles, seedEdits)
      if (candidateFiles.length > 0 && unresolvedFiles.length === 0) {
        return {
          status: 'blocked',
          impact: {
            ...impact,
            outcome: 'blocked',
            reasons: ['secret scanner blocked hosted model inference'],
          },
        }
      }
      // A bounded analyzer can deliberately fail closed without identifying a
      // model-readable source location (for example, an oversized or
      // candidate-overflow repository scan). Do not manufacture an invalid
      // empty Harness request: there is no customer source the model is
      // authorized to inspect or edit. Keep the finding manual for a human.
      if (unresolvedFiles.length === 0) {
        return {
          status: 'manual',
          impact: {
            ...impact,
            reasons: [...impact.reasons, 'no policy-approved source files were available for Harness review'],
          },
        }
      }
      const modelPaths = new Set(unresolvedFiles.map(file => file.path))
      const repairEditBoundaries = loaded.repairEditBoundaries.filter(boundary =>
        modelPaths.has(boundary.path) && matchesPolicyPath(boundary.path, modelPolicy.allowedPaths))
      const missingRequiredMigrationPaths = [...new Set(
        migrationRequirements
          .map(requirement => requirement.path)
          .filter(path => !modelPaths.has(path)),
      )]
      // Completeness is checked against every evidence-backed old-symbol
      // occurrence after the model returns. Do not spend a Harness attempt
      // when policy, secret filtering, or bounded source selection withheld a
      // file that the same delivery would later require the model to migrate.
      if (missingRequiredMigrationPaths.length > 0) {
        return {
          status: 'blocked',
          impact: {
            ...impact,
            outcome: 'blocked',
            reasons: [
              ...impact.reasons,
              `${missingRequiredMigrationPaths.length} completeness-required source file(s) were not available to the Harness`,
            ],
          },
        }
      }
      const baseHarnessImpact: RepositoryImpact = impact.outcome === 'affected_manual'
        ? impact
        : {
            ...impact,
            outcome: 'affected_manual',
            reasons: [...impact.reasons, 'failed CI requires the single policy-approved Harness repair'],
          }
      const harnessImpact = bindHarnessRepairEditBoundaries({
        ...baseHarnessImpact,
        reasons: withheldSecretFiles === 0
          ? baseHarnessImpact.reasons
          : [...baseHarnessImpact.reasons, `${withheldSecretFiles} source files were withheld by the secret scanner`],
        evidence: [
          ...baseHarnessImpact.evidence.filter(item =>
            item.location === undefined || modelPaths.has(item.location.path)),
          ...reviewedJavaHelperEvidence(reviewedJavaHelper, unresolvedFiles),
        ],
      }, unresolvedFiles, repairEditBoundaries)
      if (harnessResultInput === undefined && this.executor === undefined) {
        return {
          status: 'harness_required',
          impact,
          request: {
            schemaVersion: '1.0',
            jobId: job.id,
            baseSha: job.baseSha,
            impact: harnessImpact,
            repairAttempt: job.repairAttempt,
            authority: job.changeEvent.verificationStatus,
            unresolvedFiles: unresolvedFiles.map(file => ({
              ...file,
              expectedHash: sha256(file.content),
            })),
            ...(repairEditBoundaries.length === 0 ? {} : { repairEditBoundaries }),
            ...(seedEdits.length === 0 ? {} : { seedEdits }),
            ...(job.repairContext === undefined ? {} : {
              previousAttempt: {
                edits: previousModelEdits,
                failedChecks: job.repairContext.failedChecks,
                ...(job.repairContext.diagnostics === undefined ? {} : {
                  diagnostics: job.repairContext.diagnostics,
                }),
                ...(job.repairContext.validationContext === undefined ? {} : {
                  validationContext: job.repairContext.validationContext,
                }),
              },
            }),
          },
        }
      }
      const result = harnessResultInput === undefined
        ? await this.executor!.execute({
            jobId: job.id,
            rootDir,
            changeEvent: job.changeEvent,
            impact: harnessImpact,
            policy: { ...modelPolicy, allowedNetworkHosts: [this.harnessNetworkHost] },
            unresolvedFiles,
            ...(repairEditBoundaries.length === 0 ? {} : { repairEditBoundaries }),
            ...(repositoryImportSeed === undefined ? {} : {
              trustedTextMigrations: Object.entries(repositoryImportSeed.requiredSnippetsByPath)
                .map(([path, requiredSnippets]) => ({
                  path,
                  requiredSnippets: [...requiredSnippets],
                  forbiddenSnippets: [...repositoryImportSeed.forbiddenSnippets],
                })),
            }),
            repairAttempt: job.repairAttempt,
            ...(job.deadlineAt === undefined ? {} : {
              deadlineAtMs: harnessModelDeadlineAtMs(
                Date.parse(job.deadlineAt),
                job.policy.maxRunTimeMs,
              ),
            }),
            ...(job.repairContext === undefined ? {} : {
              previousAttempt: {
                edits: previousModelEdits,
                failedChecks: job.repairContext.failedChecks,
                ...(job.repairContext.diagnostics === undefined ? {} : {
                  diagnostics: job.repairContext.diagnostics,
                }),
                ...(job.repairContext.validationContext === undefined ? {} : {
                  validationContext: job.repairContext.validationContext,
                }),
              },
            }),
          })
        : validateHarnessResult(harnessResultInput, job, modelPolicy, harnessImpact, unresolvedFiles)
      const reviewedFiles = unresolvedFiles.map(file => ({ path: file.path, expectedHash: sha256(file.content) }))
      if (!acceptsReadOnlyCompatibility(modelPolicy, reviewedFiles, result.readOnlyCompatibility)) {
        return { status: 'manual', impact: { ...impact, reasons: [...impact.reasons,
          'Harness did not affirm compatibility for every exact read-only source; automatic publication was withheld'] } }
      }
      if (hasCodeOwnedDependencyMigration && result.edits.some(edit => isDependencyManifest(edit.path))) {
        return {
          status: 'manual',
          impact: {
            ...impact,
            reasons: [
              ...impact.reasons,
              'Harness attempted to edit a dependency manifest owned by the deterministic dependency updater',
            ],
          },
        }
      }
      const manifestOnlyResultAllowed = permitsManifestOnlyHarnessResult(
        job.changeEvent.verificationStatus,
        impact.evidence,
        migrationRequirements.length,
        hasCodeOwnedDependencyMigration,
        { policy: modelPolicy, reviewedFiles,
          compatibility: result.readOnlyCompatibility },
      )
      if (result.edits.length === 0 && previousModelEdits.length === 0
        && seedEdits.length === 0 && !manifestOnlyResultAllowed) {
        return {
          status: 'manual',
          impact: {
            ...impact,
            reasons: [
              ...impact.reasons,
              'Harness found no applicable bounded edit; automatic publication was withheld',
            ],
          },
        }
      }
      // Preserve the scope granted to this accepted model result, including
      // current compiler diagnostics, before formatters or customer commands
      // can mutate the checkout. The next job replays model/seed edits only.
      const validatedBoundaries = captureHarnessValidatedEditBoundaries(
        harnessImpact, unresolvedFiles, result.edits,
        [...previousModelEdits, ...result.edits].map(edit => edit.path),
        job.repairContext?.diagnostics,
      )
      if (validatedBoundaries.length > 0) validatedEditScope = {
        schemaVersion: 'validated-harness-edit-scope-v1', jobId: job.id,
        baseSha: job.baseSha, changeEventId: job.changeEvent.id,
        repairAttempt: job.repairAttempt, files: validatedBoundaries,
      }
      const proposedSources = unresolvedFiles.map(file => ({
        path: file.path,
        content: result.edits.find(edit => edit.path === file.path)?.content ?? file.content,
      }))
      const reviewedRepositoryViolations = [
        ...reviewedSymfonyPredisMigrationViolations(job, proposedSources),
        ...reviewedJavaHelperViolations(reviewedJavaHelper, proposedSources),
        ...reviewedDockershrinkClientViolations(reviewedDockershrinkClient, proposedSources),
      ]
      if (reviewedRepositoryViolations.length > 0) {
        return {
          status: 'validation_failed',
          impact,
          ...(validatedEditScope === undefined ? {} : { validatedEditScope }),
          failedChecks: ['automated-api reviewed-repository-contract'],
          diagnostics: reviewedRepositoryViolations.slice(0, 10),
        }
      }
      reviewedGradleLockSeed = reviewedGradleLockMigration === undefined
        ? undefined
        : await reviewedGradleLockSeedEdit(rootDir, reviewedGradleLockMigration)
      if (previousModelEdits.length > 0) {
        await applyProposedEdits(rootDir, previousModelEdits, modelPolicy)
      }
      if (seedEdits.length > 0) {
        await applyProposedEdits(rootDir, seedEdits, job.policy)
      }
      if (reviewedGradleLockSeed !== undefined) {
        await applyProposedEdits(rootDir, [reviewedGradleLockSeed], job.policy)
      }
      dependencyManifestChanged = await applyHarnessDependencyManifest(workingDir, job)
      dependencyManifestChanged = dependencyManifestChanged || result.edits.some(edit =>
        isDependencyManifest(edit.path))
      // The reviewed dd-trace event uses a dynamic declaration, so its complete
      // resolver-derived lock migration is owned by this deterministic seed.
      dependencyManifestChanged = dependencyManifestChanged || reviewedGradleLockSeed !== undefined
      changedPaths = [...new Set([
        ...previousModelEdits.map(edit => edit.path),
        ...seedEdits.map(edit => edit.path),
        ...(reviewedGradleLockSeed === undefined ? [] : [reviewedGradleLockSeed.path]),
        ...result.edits.map(edit => edit.path),
      ])]
      await applyProposedEdits(rootDir, result.edits, modelPolicy)
      const incompleteMigrations = await findIncompleteHarnessMigrations(
        rootDir,
        migrationRequirements,
      )
      const incompleteResponseContracts = await findIncompletePythonResponseContracts(
        rootDir,
        [...changedPaths, ...impact.evidence.flatMap(item => item.location === undefined
          ? [] : [item.location.path])],
        job.changeEvent,
      )
      if (incompleteMigrations.length > 0 || incompleteResponseContracts.length > 0) {
        return {
          status: 'validation_failed',
          impact,
          ...(validatedEditScope === undefined ? {} : { validatedEditScope }),
          failedChecks: [
            ...(incompleteMigrations.length > 0
              ? ['automated-api required-migration-completeness']
              : []),
            ...(incompleteResponseContracts.length > 0
              ? ['automated-api typed-response-completeness']
              : []),
          ],
          diagnostics: [...incompleteMigrations, ...incompleteResponseContracts].slice(0, 10),
        }
      }
      model = modelEvidence(result)
    } else {
      return {
        status: impact.outcome === 'not_affected'
          ? 'not_affected'
          : impact.outcome === 'blocked'
            ? 'blocked'
            : 'manual',
        impact,
      }
    }

    const preferredLanguage = job.changeEvent.affectedLanguages.length === 1
      ? job.changeEvent.affectedLanguages[0]
      : undefined
    if ((preferredLanguage === 'c' || preferredLanguage === 'cpp') && job.policy.validationCommands.length === 0) {
      const label = preferredLanguage === 'c' ? 'C' : 'C++'
      return {
        status: 'validation_failed',
        impact,
        ...(validatedEditScope === undefined ? {} : { validatedEditScope }),
        failureKind: 'infrastructure',
        failedChecks: [`automated-api ${label} repository validation command required`],
        diagnostics: [
          `${label} proposals require at least one repository-owned compile or test command; dependency resolution alone cannot validate compiler flags and generated headers`,
        ],
      }
    }
    const lockfileVerifiablePackageManager = preferredLanguage === 'rust'
      || preferredLanguage === 'go'
      || preferredLanguage === 'c'
      || preferredLanguage === 'cpp'
      || /^(?:java|kotlin|scala|csharp|php|ruby|swift|dart|elixir|clojure)$/u.test(preferredLanguage ?? '')
      || /^(?:cargo|go|maven|gradle|sbt|dotnet|composer|bundler|swift|dart|mix|clojure|leiningen)@/iu.test(job.repository.packageManager ?? '')
      || /^vcpkg@/iu.test(job.repository.packageManager ?? '')
    const formattingNormalization = await normalizeChangedNativeSources(rootDir, changedPaths, commandBudget)
    const syntaxValidation = await validateChangedSourceSyntax(
      rootDir,
      changedPaths,
      job.repository.packageManager ?? preferredLanguage,
      commandBudget,
    )
    // Formatting is part of the final gate, but it must not hide compiler diagnostics
    // from the single bounded repair attempt.
    const syntaxFailed = hasBlockingSyntaxFailure([
      ...formattingNormalization,
      ...syntaxValidation,
    ])
    const pnpmLockfilePath = resolve(packageManagerDir, 'pnpm-lock.yaml')
    let pnpmLockfileBefore: string | undefined
    if (!syntaxFailed && dependencyManifestChanged && await pathExists(pnpmLockfilePath)) {
      const packageManager = await detectPackageManager(
        packageManagerDir,
        job.repository.packageManager ?? preferredLanguage,
        { reviewedJvmContext: { job, repositoryRoot: rootDir } },
      )
      if (packageManager.variant === 'pnpm') {
        pnpmLockfileBefore = await readFile(pnpmLockfilePath, 'utf8')
      }
    }
    const exactMigrationDependencies = migrationDependencies(job)
    const combinedGradleValidationIndex = !syntaxFailed
      && dependencyManifestChanged
      && exactMigrationDependencies.length === 1
      ? policyBackedOfflineGradleVerificationIndex(
          job.repository.packageManager,
          job.policy.validationCommands,
        )
      : -1
    const dependencyValidation = reviewedGradleLockMigration !== undefined
      ? []
      : !syntaxFailed && dependencyManifestChanged
      ? combinedGradleValidationIndex === -1
        ? await synchronizeDependencies(
            packageManagerDir,
            job.repository.packageManager ?? preferredLanguage,
            exactMigrationDependencies,
            commandBudget,
            { job, repositoryRoot: rootDir },
          )
        : await synchronizeGradleDependencyWithPolicyValidation(
            packageManagerDir,
            job.repository.packageManager!,
            exactMigrationDependencies[0]!,
            job.policy.validationCommands[combinedGradleValidationIndex]!,
            commandBudget,
          )
      : []
    const remainingPolicyValidationCommands = combinedGradleValidationIndex === -1
      ? job.policy.validationCommands
      : job.policy.validationCommands.filter((_command, index) => index !== combinedGradleValidationIndex)
    let dependencyInstallFailed = syntaxFailed || dependencyValidation.some(
      result => result.timedOut || result.exitCode !== 0,
    )
    if (!dependencyInstallFailed && reviewedGradleLockMigration !== undefined) {
      await assertReviewedGradleLockHash(
        rootDir,
        reviewedGradleLockMigration.lockPath,
        reviewedGradleLockMigration.resolvedLockSha256,
        'resolved',
      )
    }
    if (!dependencyInstallFailed && pnpmLockfileBefore !== undefined) {
      const importer = relative(packageManagerDir, workingDir).replaceAll('\\', '/') || '.'
      let minimized: string
      try {
        minimized = minimizePnpmLockfileChange(
          pnpmLockfileBefore,
          await readFile(pnpmLockfilePath, 'utf8'),
          importer,
          migrationDependencies(job).map(dependency => dependency.name),
        )
      } catch (error) {
        return {
          status: 'validation_failed',
          impact,
          ...(validatedEditScope === undefined ? {} : { validatedEditScope }),
          failedChecks: ['automated-api pnpm-lockfile-scope'],
          diagnostics: [
            error instanceof Error ? error.message : 'pnpm lockfile scope validation failed',
          ],
        }
      }
      await writeFile(pnpmLockfilePath, minimized, 'utf8')
      dependencyValidation.push(...await verifySynchronizedDependencyLockfile(
        packageManagerDir,
        job.repository.packageManager,
        commandBudget,
        { job, repositoryRoot: rootDir },
      ))
      dependencyInstallFailed = dependencyValidation.some(
        result => result.timedOut || result.exitCode !== 0,
      )
    } else if (!dependencyInstallFailed && dependencyManifestChanged && lockfileVerifiablePackageManager
      && reviewedGradleLockMigration === undefined) {
      // A required offline Gradle test resolves the synchronized lock state again
      // without the exact-version force used by synchronization. Avoid repeating
      // the same expensive Gradle configuration with a standalone prefetch first.
      if (!hasPolicyBackedOfflineGradleVerification(
        job.repository.packageManager,
        job.policy.validationCommands,
      )) {
        dependencyValidation.push(...await verifySynchronizedDependencyLockfile(
          packageManagerDir,
          job.repository.packageManager,
          commandBudget,
          { job, repositoryRoot: rootDir },
        ))
      }
      dependencyInstallFailed = dependencyValidation.some(
        result => result.timedOut || result.exitCode !== 0,
      )
    }
    // Freeze the authorized proposal before running customer validation.
    // Builds and compilers may create caches or generated files; those files
    // are useful to the check but must never acquire PR-writing authority.
    const intendedFiles = dependencyInstallFailed
      ? []
      : await captureProposalFiles(rootDir, job)
    const validation = dependencyInstallFailed
      ? [...formattingNormalization, ...syntaxValidation, ...dependencyValidation]
      : [
          ...formattingNormalization,
          ...syntaxValidation,
          ...dependencyValidation,
          ...await runValidationCommands(workingDir, remainingPolicyValidationCommands, commandBudget,
            preferredLanguage === 'python' || /^(?:uv|pip)@/iu.test(job.repository.packageManager ?? '')
              ? { repositoryRoot: rootDir, packageManagerDirectory: packageManagerDir }
              : undefined),
        ]
    const failedChecks = validation
      .filter(result => result.timedOut || result.exitCode !== 0)
      .map(result => [result.command.executable, ...result.command.args].join(' ').slice(0, 500))
    if (failedChecks.length > 0) {
      const trustedDependencyResults = new Set(dependencyValidation)
      const failureKind = validation.some(result =>
        isInfrastructureValidationFailure(result, trustedDependencyResults.has(result)))
        ? 'infrastructure' as const
        : 'code' as const
      const diagnostics = validation
        .filter(result => result.timedOut || result.exitCode !== 0)
        .flatMap(result => result.diagnostic === undefined ? [] : [result.diagnostic])
        .slice(0, 10)
      const validationContext = await loadValidationContext(rootDir, diagnostics, job.policy)
      return {
        status: 'validation_failed',
        impact,
        ...(validatedEditScope === undefined ? {} : { validatedEditScope }),
        failureKind,
        failedChecks,
        ...(diagnostics.length === 0 ? {} : { diagnostics }),
        ...(validationContext.length === 0 ? {} : { validationContext }),
      }
    }
    const { artifact, patch } = await buildProposalArtifact({
      rootDir,
      job,
      impact,
      validation: validation.map(({ diagnostic: _diagnostic, ...result }) => result),
      intendedFiles,
      ...(recipeId === undefined ? {} : { recipeId }),
      ...(model === undefined ? {} : { model }),
    })
    return { status: 'proposed', impact, artifact, patch }
  }
}

export async function assertReviewedGradleLockHash(
  repositoryRoot: string,
  lockPath: string,
  expectedHash: string,
  phase: 'baseline' | 'resolved',
): Promise<void> {
  const path = await resolveExistingPathInsideRepository(repositoryRoot, lockPath)
  const actualHash = sha256(await readFile(path))
  if (actualHash !== expectedHash) {
    throw new Error(`reviewed Gradle ${phase} lock does not match its resolver-derived whole-file hash`)
  }
}

export async function reviewedGradleLockSeedEdit(
  repositoryRoot: string,
  plan: {
    lockPath: string
    baselineLockSha256: string
    resolvedLockSha256: string
    lockReplacements: readonly { old: string; replacement: string }[]
  },
): Promise<ProposedEdit> {
  const path = await resolveExistingPathInsideRepository(repositoryRoot, plan.lockPath)
  const content = await readFile(path, 'utf8')
  if (sha256(content) !== plan.baselineLockSha256) {
    throw new Error('reviewed Gradle baseline lock does not match its resolver-derived whole-file hash')
  }
  let resolved = content
  for (const replacement of plan.lockReplacements) {
    const unexpectedNewLine = replacement.replacement.split('\n')
      .some(line => content.includes(line))
    if (content.split(replacement.old).length !== 2 || unexpectedNewLine) {
      throw new Error('reviewed Gradle lock replacement does not match the exact resolver baseline')
    }
    resolved = resolved.replace(replacement.old, replacement.replacement)
  }
  if (sha256(resolved) !== plan.resolvedLockSha256) {
    throw new Error('reviewed Gradle resolved lock does not match its resolver-derived whole-file hash')
  }
  return {
    path: plan.lockPath,
    expectedHash: plan.baselineLockSha256,
    content: resolved,
  }
}

export function isInfrastructureValidationFailure(
  result: ExecutedValidationResult,
  trustedDependencyCommand = false,
): boolean {
  if (result.timedOut) return true
  const mavenExecutable = result.command.executable.replaceAll('\\', '/')
  const runsOfflineMavenWrapper = (mavenExecutable === 'mvnw' || mavenExecutable.endsWith('/mvnw'))
    && result.command.args.some(argument => argument === '-o' || argument === '--offline')
  if (runsOfflineMavenWrapper
    && /Cannot access [^\n]+ in offline mode and the artifact [^\n]+ has not been downloaded from it before/u
      .test(result.diagnostic ?? '')) {
    return true
  }
  // Exit 86 is emitted only by our helper before model-controlled lock/manifest
  // validation, for an absent or corrupt sealed certification input. Command
  // text alone is not authority: a policy command may append an identical
  // suffix or print uv's cache diagnostic verbatim.
  const certifiedPythonSync = result.command.executable === '/usr/local/bin/python'
    && result.command.args.join('\0') === [
      '-I',
      '/opt/automated-api/scripts/lib/python-certified-environment.py',
      'sync',
      '/opt/python-certified-cache',
      CERTIFIED_PYTHON_UV_EXECUTABLE,
    ].join('\0')
  if (trustedDependencyCommand && certifiedPythonSync && result.exitCode === 86) {
    return true
  }
  const forcedIncludeIndex = result.command.args.indexOf('-include')
  const forcedHeader = forcedIncludeIndex === -1
    ? undefined
    : result.command.args[forcedIncludeIndex + 1]
  if (forcedHeader === undefined) return false
  const readsCertifiedCache = result.command.args.some(argument =>
    argument.startsWith('-I/opt/dependency-cache/'))
  if (!readsCertifiedCache) return false
  const diagnostic = result.diagnostic ?? ''
  return diagnostic.includes(`${forcedHeader}: No such file or directory`)
}

function isVerifiedFirecrawlHybrid(event: ActionableChangeEvent): boolean {
  return event.verificationStatus === 'verified'
    && event.provider.toLowerCase() === 'firecrawl'
    && event.recipeIds.includes(FIRECRAWL_V1_V2_RECIPE_ID)
}

/** Refuse model execution when repository evidence exceeds the verified bundle. */
function missingVerifiedHarnessOperations(
  event: ActionableChangeEvent,
  impact: RepositoryImpact,
): string[] {
  if (!isVerifiedFirecrawlHybrid(event)) return []
  const authorized = new Set(event.operations.flatMap(operation =>
    operation.oldSymbol === undefined ? [] : [operation.oldSymbol]))
  return [...new Set(impact.evidence.flatMap(evidence => {
    if (evidence.deterministicRecipeSupported) return []
    const symbol = evidence.location?.symbol
    if (symbol === undefined) return []
    return authorized.has(symbol) ? [] : [symbol]
  }))].sort()
}

/**
 * Creates source-only seed edits from exact analyzer locations. The package
 * manifest is deliberately excluded and remains owned by dependencies.ts.
 */
function verifiedFirecrawlHarnessSeedEdits(
  files: Array<{ path: string; content: string }>,
  impact: RepositoryImpact,
  event: ActionableChangeEvent,
): Array<{ path: string; expectedHash: string; content: string }> {
  if (!isVerifiedFirecrawlHybrid(event)) return []
  const operations = new Map(event.operations.flatMap(operation =>
    operation.oldSymbol === undefined || operation.newSymbol === undefined
      ? []
      : [[operation.oldSymbol, operation.newSymbol] as const]))
  const evidenceByPath = new Map<string, ImpactEvidence[]>()
  for (const evidence of impact.evidence) {
    if (!evidence.deterministicRecipeSupported || evidence.location === undefined) continue
    const values = evidenceByPath.get(evidence.location.path) ?? []
    values.push(evidence)
    evidenceByPath.set(evidence.location.path, values)
  }
  const edits: Array<{ path: string; expectedHash: string; content: string }> = []
  for (const file of files) {
    const evidence = evidenceByPath.get(file.path) ?? []
    let content = file.content
    // The verified v2 artifact keeps the scoped npm identity. Hybrid seeds may
    // rename reviewed symbols, but never substitute an unevidenced package.
    const located = evidence.flatMap(item => {
      const oldSymbol = item.location?.symbol
      const newSymbol = oldSymbol === undefined ? undefined : operations.get(oldSymbol)
      return oldSymbol === undefined || newSymbol === undefined || item.location === undefined
        ? []
        : [{ oldSymbol, newSymbol, line: item.location.line, column: item.location.column }]
    }).sort((left, right) => right.line - left.line || right.column - left.column)
    for (const migration of located) {
      content = replaceLocatedSymbol(content, migration)
    }
    if (content !== file.content) {
      edits.push({ path: file.path, expectedHash: sha256(file.content), content })
    }
  }
  return edits
}

/**
 * Applies only exact method renames stated in verified evidence and located by
 * the repository analyzer. Request/response reshaping remains Harness-owned.
 */
function verifiedInstructionHarnessSeedEdits(
  files: Array<{ path: string; content: string }>,
  impact: RepositoryImpact,
  event: ActionableChangeEvent,
): Array<{ path: string; expectedHash: string; content: string }> {
  const mappings = verifiedInstructionMethodMappings(event)
  if (mappings.size === 0) return []
  const evidenceByPath = new Map<string, ImpactEvidence[]>()
  for (const evidence of impact.evidence) {
    if (evidence.kind !== 'sdk_call' || evidence.location === undefined) continue
    const separator = evidence.operation.lastIndexOf('.')
    const method = separator < 0 ? evidence.operation : evidence.operation.slice(separator + 1)
    if (!mappings.has(method)) continue
    const values = evidenceByPath.get(evidence.location.path) ?? []
    values.push(evidence)
    evidenceByPath.set(evidence.location.path, values)
  }
  const edits: Array<{ path: string; expectedHash: string; content: string }> = []
  for (const file of files) {
    let content = file.content
    const evidence = (evidenceByPath.get(file.path) ?? []).sort((left, right) =>
      right.location!.line - left.location!.line || right.location!.column - left.location!.column)
    for (const item of evidence) {
      const separator = item.operation.lastIndexOf('.')
      const oldSymbol = separator < 0 ? item.operation : item.operation.slice(separator + 1)
      const newSymbol = mappings.get(oldSymbol)
      if (newSymbol === undefined) continue
      content = replaceLocatedSymbol(content, {
        oldSymbol, newSymbol, line: item.location!.line, column: item.location!.column,
      })
    }
    if (content !== file.content) edits.push({
      path: file.path, expectedHash: sha256(file.content), content,
    })
  }
  return edits
}

export function reviewedSymfonyPredisImportSeedEdits(
  jobInput: MigrationJob,
  files: Array<{ path: string; content: string }>,
): Array<{ path: string; expectedHash: string; content: string }> {
  const contract = reviewedSymfonyPredisImportSeed(jobInput)
  if (contract === undefined) return []
  const sourcePaths = new Set(contract.sourcePaths)
  return files.flatMap(file => {
    if (!sourcePaths.has(file.path)) return []
    let content = file.content
    for (const replacement of contract.replacements) {
      const oldLine = `use ${replacement.old};`
      const replacementLine = `use ${replacement.replacement};`
      content = content.replaceAll(oldLine, replacementLine)
      const lines = content.split('\n')
      let seen = false
      content = lines.filter(line => {
        if (line !== replacementLine) return true
        if (seen) return false
        seen = true
        return true
      }).join('\n')
    }
    return content === file.content ? [] : [{
      path: file.path,
      expectedHash: sha256(file.content),
      content,
    }]
  })
}

export function reviewedSymfonyPredisMigrationViolations(
  jobInput: MigrationJob,
  files: Array<{ path: string; content: string }>,
): string[] {
  const contract = reviewedSymfonyPredisImportSeed(jobInput)
  if (contract === undefined) return []
  const byPath = new Map(files.map(file => [file.path, file.content]))
  const violations: string[] = []
  for (const path of contract.sourcePaths) {
    const content = byPath.get(path)
    if (content === undefined) {
      violations.push(`${path}: exact reviewed migration source is missing`)
      continue
    }
    for (const snippet of contract.requiredSnippetsByPath[path] ?? []) {
      const count = content.split(snippet).length - 1
      if (count !== 1) {
        violations.push(`${path}: required reviewed snippet must occur exactly once: ${snippet}`)
      }
    }
    for (const snippet of contract.forbiddenSnippets) {
      if (content.includes(snippet)) {
        violations.push(`${path}: forbidden legacy reviewed snippet remains: ${snippet}`)
      }
    }
  }
  return violations
}

function verifiedInstructionMethodMappings(event: ActionableChangeEvent): Map<string, string> {
  const mappings = new Map<string, string>()
  if (event.verificationStatus !== 'verified') return mappings
  const instructions = event.operations.flatMap(operation =>
    typeof operation.details?.instructions === 'string' ? [operation.details.instructions] : [])
  for (const instruction of instructions) {
    for (const match of instruction.matchAll(
      /\b([A-Za-z_$][\w$]*)\s*\([^)]*\)\s+is replaced by\s+([A-Za-z_$][\w$]*)\s*\(/giu,
    )) {
      const oldSymbol = match[1]
      const newSymbol = match[2]
      if (oldSymbol === undefined || newSymbol === undefined) continue
      const existing = mappings.get(oldSymbol)
      if (existing !== undefined && existing !== newSymbol) return new Map()
      mappings.set(oldSymbol, newSymbol)
    }
  }
  return mappings
}

function replaceLocatedSymbol(
  content: string,
  migration: { oldSymbol: string; newSymbol: string; line: number; column: number },
): string {
  const lines = content.split('\n')
  const line = lines[migration.line - 1]
  if (line === undefined) return content
  const preferred = migration.column - 1
  const index = line.slice(preferred).indexOf(migration.oldSymbol)
  const absolute = index === -1 ? line.indexOf(migration.oldSymbol) : preferred + index
  if (absolute === -1) return content
  lines[migration.line - 1] = line.slice(0, absolute)
    + migration.newSymbol
    + line.slice(absolute + migration.oldSymbol.length)
  return lines.join('\n')
}

function overlaySeedEdits(
  files: Array<{ path: string; content: string }>,
  edits: Array<{ path: string; expectedHash: string; content: string }>,
): Array<{ path: string; content: string }> {
  const byPath = new Map(edits.map(edit => [edit.path, edit]))
  return files.map(file => {
    const edit = byPath.get(file.path)
    if (edit === undefined) return file
    if (edit.expectedHash !== sha256(file.content)) {
      throw new Error(`verified Harness seed hash is stale for ${file.path}`)
    }
    return { path: file.path, content: edit.content }
  })
}

function acceptsReadOnlyCompatibility(
  policy: RepositoryPolicy,
  reviewedFiles: ReadonlyArray<{ path: string; expectedHash: string }>,
  compatibility: HarnessResult['readOnlyCompatibility'],
): boolean {
  const readonly = reviewedFiles.filter(file => !matchesPolicyPath(file.path, policy.allowedPaths))
  if (readonly.length === 0) return true
  const conclusions = compatibility ?? []
  const byPath = new Map(conclusions.map(conclusion => [conclusion.path, conclusion]))
  return conclusions.length === readonly.length && byPath.size === conclusions.length
    && readonly.every(file => byPath.get(file.path)?.expectedHash === file.expectedHash
      && byPath.get(file.path)?.verdict === 'compatible')
}

export function permitsManifestOnlyHarnessResult(
  authority: ActionableChangeEvent['verificationStatus'],
  evidence: readonly ImpactEvidence[],
  migrationRequirementCount: number,
  hasCodeOwnedDependencyMigration: boolean,
  review?: { policy: RepositoryPolicy; reviewedFiles: ReadonlyArray<{ path: string; expectedHash: string }>;
    compatibility?: HarnessResult['readOnlyCompatibility'] },
): boolean {
  if (authority !== 'verified' || !hasCodeOwnedDependencyMigration || migrationRequirementCount !== 0) return false
  if (!evidence.some(item => item.kind === 'dependency')) return false
  const readonlyReview = review !== undefined && (
    review.reviewedFiles.some(file => !matchesPolicyPath(file.path, review.policy.allowedPaths))
    || review.policy.modelReadablePaths?.some(path => !matchesPolicyPath(path, review.policy.allowedPaths)) === true)
  if (!readonlyReview) return evidence.every(item => item.kind === 'dependency' || item.kind === 'sdk_import')
  if (review === undefined || review.policy.modelReadablePaths === undefined
    || review.policy.validationCommands.length === 0 || review.policy.requiredChecks.length === 0) return false
  // Explicit dependency-only policy is an opt-in to review existing consumers
  // without manufacturing an unnecessary source patch. It grants no source
  // write authority: both executor and runner still enforce allowedPaths.
  const manifests = new Set(review.policy.allowedManifestPaths)
  if (review.policy.allowedPaths.length === 0 || !review.policy.allowedPaths.every(path =>
    path === normalizeRepositoryPath(path) && !/[*?\[\]{}]/u.test(path)
    && manifests.has(path) && (isDependencyManifest(path)
      || /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/u.test(path)))) return false
  if (!acceptsReadOnlyCompatibility(review.policy, review.reviewedFiles, review.compatibility)) return false
  const files = new Set(review.reviewedFiles.map(file => file.path))
  const consumerPaths = [...new Set(evidence.flatMap(item =>
    (item.kind === 'sdk_import' || item.kind === 'sdk_call') && item.location !== undefined
      && !isDependencyManifest(item.location.path)
      && matchesPolicyPath(item.location.path, review.policy.modelReadablePaths!)
      && !matchesPolicyPath(item.location.path, review.policy.deniedPaths)
      ? [item.location.path] : []))]
  // A consumer withheld by secret filtering cannot silently disappear from
  // the compatibility review. Unapproved paths still grant no read authority.
  return consumerPaths.length > 0 && consumerPaths.every(path => files.has(path))
}

export interface HarnessMigrationRequirement {
  path: string
  oldSymbol: string
  newSymbol: string
  operationKind: ActionableChangeEvent['operations'][number]['kind']
  binaryEvidence?: { oldSymbol: string; newSymbol: string; operation: string }
  declarationEvidence?: { oldSymbol: string; newSymbol: string; operation: string }
  swiftResponseAccesses?: Array<Omit<SwiftResponseContentAccess, 'offset'>>
  occurrences: HarnessMigrationOccurrence[]
}

export interface HarnessMigrationOccurrence {
  line: number
  column: number
  selectorPrefix: string
  anchorBefore?: string
  anchorAfter?: string
  quotedPythonAnnotation?: boolean
  mongodbFind?: MongoDbCFindSemantics
}

export interface MongoDbCFindSemantics {
  collection: string
  filter: string
  skip: string
  limit: string
  batchSize: string
  projection: string
  readPreference: string
}

export async function captureHarnessMigrationRequirements(
  rootDir: string,
  impact: RepositoryImpact,
  changeEvent: ActionableChangeEvent,
): Promise<HarnessMigrationRequirement[]> {
  const requirements: HarnessMigrationRequirement[] = []
  for (const operation of changeEvent.operations) {
    if (operation.oldSymbol === undefined || operation.newSymbol === undefined) continue
    const language = changeEvent.affectedLanguages?.length === 1 ? changeEvent.affectedLanguages[0] : undefined
    const oldSourceMethod = jvmDescriptorMethodName(operation.oldSymbol, language)
    const newSourceMethod = jvmDescriptorMethodName(operation.newSymbol, language)
    // A return/argument type change with the same name needs semantic validation,
    // not a fabricated identifier rename. Preserve its raw event unchanged.
    if (oldSourceMethod !== undefined && oldSourceMethod === newSourceMethod) continue
    const mapped = oldSourceMethod !== undefined && newSourceMethod !== undefined
    const swiftResponse = reviewedSwiftResponseChange(changeEvent)
    const oldSymbol = swiftResponse ? 'content?.string' : mapped ? oldSourceMethod : operation.oldSymbol
    const newSymbol = swiftResponse ? 'content' : mapped ? newSourceMethod : operation.newSymbol
    const locationsByPath = new Map<string, Map<string, { line: number; column: number }>>()
    for (const evidence of impact.evidence) {
      if (evidence.operation !== operation.oldSymbol || evidence.location === undefined) continue
      const path = normalizeRepositoryPath(evidence.location.path)
      const locations = locationsByPath.get(path) ?? new Map()
      locations.set(`${evidence.location.line}:${evidence.location.column}`, {
        line: evidence.location.line,
        column: evidence.location.column,
      })
      locationsByPath.set(path, locations)
    }
    for (const [path, locations] of locationsByPath) {
      const content = await readFile(await resolveExistingPathInsideRepository(rootDir, path), 'utf8')
      const accesses = swiftResponse ? swiftResponseContentAccesses(content).filter(access => {
        const prefix = content.slice(0, access.offset).split('\n')
        return locations.has(`${prefix.length}:${prefix.at(-1)!.length + 1}`)
      }) : []
      if (swiftResponse && (accesses.length === 0 || accesses.length !== locations.size)) {
        throw new Error('Swift response evidence no longer resolves to the exact owned source accesses')
      }
      requirements.push({
        path,
        oldSymbol,
        newSymbol,
        operationKind: operation.kind,
        ...(mapped ? { binaryEvidence: { oldSymbol: operation.oldSymbol, newSymbol: operation.newSymbol,
          operation: operation.operation } } : {}),
        ...(swiftResponse ? { declarationEvidence: { oldSymbol: operation.oldSymbol, newSymbol: operation.newSymbol,
          operation: operation.operation }, swiftResponseAccesses: accesses.map(({ offset: _offset, ...access }) => access) } : {}),
        occurrences: [...locations.values()].map(location => captureMigrationOccurrence(
          content,
          oldSymbol,
          location.line,
          location.column,
          path,
        )),
      })
    }
  }
  return requirements
}

export async function findIncompleteHarnessMigrations(
  rootDir: string,
  requirements: HarnessMigrationRequirement[],
): Promise<string[]> {
  const diagnostics: string[] = []
  for (const requirement of requirements) {
    const content = await readFile(
      await resolveExistingPathInsideRepository(rootDir, requirement.path),
      'utf8',
    )
    if (requirement.swiftResponseAccesses !== undefined) {
      const remaining = swiftResponseContentAccesses(content)
      const replacements = swiftResponseContentAccesses(content, true)
      const key = ({ functionName, clientName, resultName, assignmentName, fallbackName }: Omit<SwiftResponseContentAccess, 'offset'>) =>
        JSON.stringify([functionName, clientName, resultName, assignmentName, fallbackName])
      for (const access of requirement.swiftResponseAccesses) {
        const match = replacements.findIndex(candidate => key(candidate) === key(access))
        if (match < 0 || remaining.some(candidate => key(candidate) === key(access))) {
          diagnostics.push(`${requirement.path}: required Swift response-content migration did not preserve the owned ${access.functionName}/${access.assignmentName} usage and fallback`)
        } else replacements.splice(match, 1)
      }
      continue
    }
    const lines = normalizedLines(content, requirement.path)
    const rawLines = content.replace(/\r\n/gu, '\n').split('\n')
    const oldMatches = matchedOccurrences(
      lines,
      requirement.occurrences,
      requirement.oldSymbol,
      undefined,
      requirement.newSymbol,
      rawLines,
    )
    const newMatches = matchedOccurrences(
      lines,
      requirement.occurrences,
      requirement.newSymbol,
      { oldSymbol: requirement.oldSymbol, newSymbol: requirement.newSymbol },
      undefined,
      rawLines,
    )
    const hasQuotedPythonAnnotation = requirement.occurrences.some(item => item.quotedPythonAnnotation === true)
    const oldRemainsInExecutableCode = lines.some(line =>
      hasUnreplacedSymbol(line, requirement.oldSymbol, requirement.newSymbol))
    const newExistsInExecutableCode = lines.some(line =>
      literalTokenStarts(line, requirement.newSymbol).length > 0)
    const selectorPrefixes = new Set(requirement.occurrences.map(item => item.selectorPrefix))
    const structuralReplacement = requirement.operationKind === 'option_changed'
      || selectorPrefixes.size > 1
      || requirement.occurrences.some(item => !/(?:\.|\?\.|::|->)\s*$/u.test(item.selectorPrefix))
    const mongodbDiagnostics = findIncompleteMongoDbCFindMigrations(content, requirement)
    if (!hasQuotedPythonAnnotation
      && !oldRemainsInExecutableCode && newExistsInExecutableCode && structuralReplacement) {
      diagnostics.push(...mongodbDiagnostics)
      continue
    }
    if (requirement.operationKind === 'option_changed'
      && hasOptionAtEveryEvidenceOccurrence(lines, requirement)) {
      diagnostics.push(...mongodbDiagnostics)
      continue
    }
    if (!oldRemainsInExecutableCode
      && hasReceiverQualifiedReplacementCardinality(lines, requirement)) {
      diagnostics.push(...mongodbDiagnostics)
      continue
    }
    for (const [index, occurrence] of requirement.occurrences.entries()) {
      const oldRemains = oldMatches.has(index)
      const newPresent = newMatches.has(index)
      if (oldRemains || !newPresent) {
        diagnostics.push(
          `${requirement.path}: required migration ${requirement.oldSymbol} -> ${requirement.newSymbol} `
          + `did not update the evidence-backed usage at ${occurrence.line}:${occurrence.column}`,
        )
      }
    }
    diagnostics.push(...mongodbDiagnostics)
  }
  return diagnostics
}

function findIncompleteMongoDbCFindMigrations(
  content: string,
  requirement: HarnessMigrationRequirement,
): string[] {
  if (requirement.oldSymbol !== 'mongoc_collection_find'
    || requirement.newSymbol !== 'mongoc_collection_find_with_opts') return []
  const originals = requirement.occurrences.flatMap(occurrence =>
    occurrence.mongodbFind === undefined ? [] : [{ occurrence, semantics: occurrence.mongodbFind }])
  if (originals.length !== requirement.occurrences.length) {
    return [`${requirement.path}: MongoDB C find migration lacks captured legacy call semantics`]
  }
  const migratedCalls = cFunctionCalls(content, requirement.newSymbol)
  const available = new Set(migratedCalls.keys())
  const diagnostics: string[] = []
  for (const original of originals) {
    const match = migratedCalls.findIndex((call, index) => available.has(index)
      && sameCExpression(call.args[0], original.semantics.collection)
      && sameCExpression(call.args[1], original.semantics.filter)
      && sameCExpression(call.args[3], original.semantics.readPreference))
    if (match === -1) {
      diagnostics.push(
        `${requirement.path}: MongoDB C find migration at ${original.occurrence.line}:${original.occurrence.column} `
        + 'did not preserve collection, filter, and read preference',
      )
      continue
    }
    available.delete(match)
    const call = migratedCalls[match]!
    const opts = cIdentifier(call.args[2])
    const requiredOptions = [
      ...(!isNullCExpression(original.semantics.projection)
        ? [{ key: 'projection', value: original.semantics.projection }] : []),
      ...(!isZeroCExpression(original.semantics.skip)
        ? [{ key: 'skip', value: original.semantics.skip }] : []),
      ...(!isZeroCExpression(original.semantics.limit)
        ? [{ key: 'limit', value: original.semantics.limit }] : []),
      ...(!isZeroCExpression(original.semantics.batchSize)
        ? [{ key: 'batchSize', value: original.semantics.batchSize }] : []),
    ]
    if (requiredOptions.length === 0) continue
    if (opts === undefined || isNullCExpression(call.args[2])) {
      diagnostics.push(
        `${requirement.path}: MongoDB C find migration at ${original.occurrence.line}:${original.occurrence.column} `
        + `must pass a BSON opts document preserving ${requiredOptions.map(option => option.key).join(', ')}`,
      )
      continue
    }
    const previousCallEnd = migratedCalls.slice(0, match).at(-1)?.end ?? 0
    const context = content.slice(Math.max(previousCallEnd, call.start - 4_000), call.start)
    if (!new RegExp(`\\bbson_t\\s+\\*?\\s*${escapeRegExp(opts)}\\b`, 'u').test(context)
      || !new RegExp(`\\bbson_init\\s*\\(\\s*&\\s*${escapeRegExp(opts)}\\s*\\)`, 'u').test(context)) {
      diagnostics.push(
        `${requirement.path}: MongoDB C find migration at ${original.occurrence.line}:${original.occurrence.column} `
        + `does not initialize ${opts} as a BSON opts document`,
      )
      continue
    }
    for (const option of requiredOptions) {
      if (!hasBsonOption(context, opts, option.key, option.value)) {
        diagnostics.push(
          `${requirement.path}: MongoDB C find migration at ${original.occurrence.line}:${original.occurrence.column} `
          + `does not preserve legacy ${option.key}=${option.value.trim()} in ${opts}`,
        )
      }
    }
  }
  return diagnostics
}

function hasOptionAtEveryEvidenceOccurrence(
  lines: string[],
  requirement: HarnessMigrationRequirement,
): boolean {
  // This branch is only for additive option migrations where the old call is
  // intentionally retained (for example Redis.new -> protocol: 2). A shorter
  // replacement token can otherwise be found inside the unchanged old symbol
  // and falsely mark a contraction such as content?.string -> content done.
  if (requirement.oldSymbol.includes(requirement.newSymbol)
    || requirement.newSymbol.includes(requirement.oldSymbol)) return false
  const candidates = requirement.occurrences.map(occurrence => {
    const keys: string[] = []
    const oldNeedle = occurrence.selectorPrefix + requirement.oldSymbol
    for (const [lineIndex, line] of lines.entries()) {
      if (!anchorsMatch(lines, lineIndex, occurrence)) continue
      if (literalTokenStarts(line, requirement.newSymbol).length === 0) continue
      for (const column of literalTokenStarts(line, oldNeedle)) keys.push(`${lineIndex}:${column}`)
    }
    return keys
  })
  const owner = new Map<string, number>()
  const assign = (occurrenceIndex: number, visited: Set<string>): boolean => {
    for (const key of candidates[occurrenceIndex] ?? []) {
      if (visited.has(key)) continue
      visited.add(key)
      const existing = owner.get(key)
      if (existing === undefined || assign(existing, visited)) {
        owner.set(key, occurrenceIndex)
        return true
      }
    }
    return false
  }
  return requirement.occurrences.every((_occurrence, index) => assign(index, new Set()))
}

function hasReceiverQualifiedReplacementCardinality(
  lines: string[],
  requirement: HarnessMigrationRequirement,
): boolean {
  const required = new Map<string, number>()
  for (const occurrence of requirement.occurrences) {
    if (!/(?:\.|\?\.|::|->)\s*$/u.test(occurrence.selectorPrefix)) return false
    const needle = occurrence.selectorPrefix + requirement.newSymbol
    required.set(needle, (required.get(needle) ?? 0) + 1)
  }
  return [...required].every(([needle, count]) => lines.reduce(
    (total, line) => total + literalTokenStarts(line, needle).length,
    0,
  ) >= count)
}

function captureMigrationOccurrence(
  content: string,
  symbol: string,
  line: number,
  column: number,
  path: string,
): HarnessMigrationOccurrence {
  const lines = normalizedLines(content, path)
  const sourceLine = lines[line - 1]
  const rawSourceLine = content.replace(/\r\n/gu, '\n').split('\n')[line - 1] ?? ''
  if (sourceLine === undefined) {
    throw new Error(`migration evidence line ${line} is outside the source file`)
  }
  let starts = literalTokenStarts(sourceLine, symbol)
  let quotedPythonAnnotation = false
  if (starts.length === 0 && /\.pyi?$/iu.test(path)) {
    starts = quotedPythonAnnotationStarts(rawSourceLine, symbol)
    quotedPythonAnnotation = starts.length > 0
  }
  const expected = Math.max(0, column - 1)
  const start = starts.sort((left, right) => Math.abs(left - expected) - Math.abs(right - expected))[0]
  if (start === undefined) {
    throw new Error(`migration evidence at ${line}:${column} does not contain ${symbol}`)
  }
  const anchorBefore = nearestAnchor(lines, line - 2, -1)
  const anchorAfter = nearestAnchor(lines, line, 1)
  return {
    line,
    column,
    selectorPrefix: selectorPrefix(
      quotedPythonAnnotation ? rawSourceLine : sourceLine,
      start,
    ),
    ...(anchorBefore === undefined ? {} : { anchorBefore }),
    ...(anchorAfter === undefined ? {} : { anchorAfter }),
    ...(quotedPythonAnnotation ? { quotedPythonAnnotation: true } : {}),
    ...(symbol === 'mongoc_collection_find' && /\.c$/iu.test(path)
      ? { mongodbFind: captureMongoDbCFindSemantics(content, line, column) }
      : {}),
  }
}

function captureMongoDbCFindSemantics(
  content: string,
  line: number,
  column: number,
): MongoDbCFindSemantics {
  const calls = cFunctionCalls(content, 'mongoc_collection_find')
  const call = calls
    .filter(candidate => candidate.line === line)
    .sort((left, right) => Math.abs(left.column - column) - Math.abs(right.column - column))[0]
  if (call === undefined || call.args.length !== 8) {
    throw new Error(`MongoDB C migration evidence at ${line}:${column} is not an eight-argument legacy find call`)
  }
  return {
    collection: call.args[0]!,
    filter: call.args[5]!,
    skip: call.args[2]!,
    limit: call.args[3]!,
    batchSize: call.args[4]!,
    projection: call.args[6]!,
    readPreference: call.args[7]!,
  }
}

interface CFunctionCall {
  line: number
  column: number
  start: number
  end: number
  args: string[]
}

function cFunctionCalls(content: string, symbol: string): CFunctionCall[] {
  const sanitized = stripCCommentsAndLiterals(content)
  const pattern = new RegExp(`\\b${escapeRegExp(symbol)}\\s*\\(`, 'gu')
  return [...sanitized.matchAll(pattern)].map(match => {
    const start = match.index
    const open = start + match[0].lastIndexOf('(')
    let depth = 1
    let cursor = open + 1
    const separators: number[] = []
    for (; cursor < sanitized.length && depth > 0; cursor += 1) {
      const character = sanitized[cursor]
      if (character === '(' || character === '[' || character === '{') depth += 1
      else if (character === ')' || character === ']' || character === '}') depth -= 1
      else if (character === ',' && depth === 1) separators.push(cursor)
    }
    if (depth !== 0) throw new Error(`${symbol} call at line ${lineOf(content, start)} is unterminated`)
    const boundaries = [open, ...separators, cursor - 1]
    const args = boundaries.slice(0, -1).map((boundary, index) =>
      content.slice(boundary + 1, boundaries[index + 1]).trim())
    return {
      line: lineOf(content, start),
      column: start - content.lastIndexOf('\n', start - 1),
      start,
      end: cursor,
      args: args.length === 1 && args[0] === '' ? [] : args,
    }
  })
}

function stripCCommentsAndLiterals(content: string): string {
  return content.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/gu,
    match => match.replace(/[^\n]/gu, ' '),
  )
}

function hasBsonOption(context: string, opts: string, key: string, value: string): boolean {
  const normalizedValue = cIdentifier(value) ?? value.trim().replace(/^&\s*/u, '')
  const pattern = new RegExp(
    `\\bBSON_APPEND_(?:DOCUMENT|DOCUMENT_BEGIN|INT32|INT64|DOUBLE)\\s*\\(`
    + `\\s*&?\\s*${escapeRegExp(opts)}\\s*,\\s*"${escapeRegExp(key)}"`
    + `[\\s\\S]{0,160}?\\b${escapeRegExp(normalizedValue)}\\b`,
    'u',
  )
  return pattern.test(context)
}

function sameCExpression(left: string | undefined, right: string): boolean {
  return left !== undefined && normalizeCExpression(left) === normalizeCExpression(right)
}

function normalizeCExpression(value: string): string {
  return value.replace(/\s+/gu, '').replace(/^\((.*)\)$/u, '$1')
}

function isNullCExpression(value: string | undefined): boolean {
  return value === undefined || /^(?:NULL|nullptr|0)$/u.test(normalizeCExpression(value))
}

function isZeroCExpression(value: string): boolean {
  return /^(?:0(?:[uUlL]+)?|NULL)$/u.test(normalizeCExpression(value))
}

function cIdentifier(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  return /^&?([A-Za-z_]\w*)$/u.exec(normalizeCExpression(value))?.[1]
}

function lineOf(value: string, index: number): number {
  return value.slice(0, index).split('\n').length
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}

function matchedOccurrences(
  lines: string[],
  occurrences: HarnessMigrationOccurrence[],
  symbol: string,
  anchorMigration?: { oldSymbol: string; newSymbol: string },
  replacementSymbol?: string,
  rawLines?: string[],
): Set<number> {
  const adjacency = occurrences.map(occurrence => {
    const keys: string[] = []
    const needle = occurrence.selectorPrefix + symbol
    for (const [lineIndex, normalizedLine] of lines.entries()) {
      if (!anchorsMatch(lines, lineIndex, occurrence, anchorMigration)) continue
      const line = occurrence.quotedPythonAnnotation === true
        ? rawLines?.[lineIndex] ?? ''
        : normalizedLine
      const tokenStarts = occurrence.quotedPythonAnnotation === true
        ? quotedPythonAnnotationStarts(line, symbol)
          .filter(start => line.slice(Math.max(0, start - occurrence.selectorPrefix.length), start)
            .endsWith(occurrence.selectorPrefix))
          .map(start => start - occurrence.selectorPrefix.length)
        : literalTokenStarts(line, needle)
      for (const column of tokenStarts) {
        if (
          anchorMigration !== undefined
          && anchorMigration.oldSymbol.includes(symbol)
          && literalTokenStarts(
            line,
            occurrence.selectorPrefix + anchorMigration.oldSymbol,
          ).includes(column)
        ) continue
        if (
          replacementSymbol !== undefined
          && replacementSymbol.includes(symbol)
          && literalTokenStarts(line, occurrence.selectorPrefix + replacementSymbol).includes(column)
        ) continue
        const key = `${lineIndex}:${column}`
        keys.push(key)
      }
    }
    return keys
  })
  const candidateOwner = new Map<string, number>()
  const assign = (occurrenceIndex: number, visited: Set<string>): boolean => {
    for (const key of adjacency[occurrenceIndex] ?? []) {
      if (visited.has(key)) continue
      visited.add(key)
      const owner = candidateOwner.get(key)
      if (owner === undefined || assign(owner, visited)) {
        candidateOwner.set(key, occurrenceIndex)
        return true
      }
    }
    return false
  }
  for (const index of occurrences.keys()) assign(index, new Set())
  return new Set(candidateOwner.values())
}

function quotedPythonAnnotationStarts(value: string, symbol: string): number[] {
  const pattern = new RegExp(`(?::|->)\\s*(["'])${escapeRegExp(symbol)}\\1`, 'gu')
  return [...value.matchAll(pattern)].map(match => match.index + match[0].lastIndexOf(symbol))
}

function anchorsMatch(
  lines: string[],
  index: number,
  occurrence: HarnessMigrationOccurrence,
  anchorMigration?: { oldSymbol: string; newSymbol: string },
): boolean {
  const before = lines.slice(Math.max(0, index - 6), index).map(value => value.trim())
  const after = lines.slice(index + 1, index + 7).map(value => value.trim())
  return anchorMatches(before, occurrence.anchorBefore, anchorMigration)
    && anchorMatches(after, occurrence.anchorAfter, anchorMigration)
}

function anchorMatches(
  nearbyLines: string[],
  anchor: string | undefined,
  migration: { oldSymbol: string; newSymbol: string } | undefined,
): boolean {
  if (anchor === undefined || nearbyLines.includes(anchor)) return true
  if (migration === undefined) return false
  const starts = literalTokenStarts(anchor, migration.oldSymbol)
  if (starts.length === 0) return false
  let migrated = anchor
  for (const start of starts.reverse()) {
    migrated = migrated.slice(0, start) + migration.newSymbol
      + migrated.slice(start + migration.oldSymbol.length)
  }
  return nearbyLines.includes(migrated)
}

function selectorPrefix(line: string, symbolStart: number): string {
  const prefix = line.slice(0, symbolStart)
  const receiver = prefix.match(
    /([\p{ID_Start}_$][\p{ID_Continue}$]*(?:\s*(?:\.|\?\.|::|->)\s*[\p{ID_Start}_$][\p{ID_Continue}$]*)*\s*(?:\.|\?\.|::|->)\s*)$/u,
  )?.[1]
  // A receiver-qualified prefix distinguishes same-named methods. For unusual
  // computed syntax, retain a bounded exact line prefix and fail closed if the
  // model rewrites that context too broadly.
  return receiver ?? prefix.slice(-160)
}

function literalTokenStarts(value: string, needle: string): number[] {
  if (needle === '') return []
  const starts: number[] = []
  let offset = 0
  while (offset <= value.length - needle.length) {
    const found = value.indexOf(needle, offset)
    if (found === -1) break
    const before = found === 0 ? '' : value[found - 1]!
    const afterIndex = found + needle.length
    const after = afterIndex >= value.length ? '' : value[afterIndex]!
    const first = needle[0]!
    const last = needle.at(-1)!
    if ((!isIdentifierCharacter(first) || !isIdentifierCharacter(before))
      && (!isIdentifierCharacter(last) || !isIdentifierCharacter(after))) {
      starts.push(found)
    }
    offset = found + Math.max(1, needle.length)
  }
  return starts
}

function isIdentifierCharacter(value: string): boolean {
  return value !== '' && /[\p{ID_Continue}$]/u.test(value)
}

function nearestAnchor(lines: string[], start: number, direction: -1 | 1): string | undefined {
  for (let index = start, inspected = 0;
    index >= 0 && index < lines.length && inspected < 4;
    index += direction, inspected += 1) {
    const value = lines[index]!.trim()
    if (value !== '') return value.slice(0, 240)
  }
  return undefined
}

function normalizedLines(content: string, path: string): string[] {
  const lines = content.replace(/\r\n/gu, '\n').split('\n')
  let blockComment = false
  let quote: '"' | "'" | '`' | '"""' | "'''" | undefined
  const hashComments = /\.(?:py|pyi|ya?ml|toml|sh)$/iu.test(path)
  const clojure = /\.(?:clj|cljc|cljs|edn)$/iu.test(path)
  return lines.map(line => {
    const computedProperties = [...line.matchAll(
      /\[\s*(['"])([\p{ID_Start}_$][\p{ID_Continue}$]*)\1\s*\]/gu,
    )].map(match => ({
      bracketStart: match.index,
      end: match.index + match[0].length,
      start: match.index + match[0].indexOf(match[2]!),
      value: match[2]!,
    }))
    let escaped = false
    let output = ''
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index]!
      const next = line[index + 1]
      if (blockComment) {
        if (character === '*' && next === '/') {
          blockComment = false
          output += '  '
          index += 1
        } else output += ' '
        continue
      }
      if (quote !== undefined) {
        output += ' '
        if (escaped) escaped = false
        else if (character === '\\') escaped = true
        else if ((quote === '"""' || quote === "'''") && line.slice(index, index + 3) === quote) {
          output += '  '
          index += 2
          quote = undefined
        } else if (quote.length === 1 && character === quote) quote = undefined
        continue
      }
      const triple = line.slice(index, index + 3)
      if (triple === '"""' || triple === "'''") {
        quote = triple
        output += '   '
        index += 2
      } else if (character === '"' || (!clojure && (character === '`'
        || (character === "'" && line.indexOf("'", index + 1) !== -1)))) {
        quote = character
        output += ' '
      } else if (!clojure && character === '/' && next === '*') {
        blockComment = true
        output += '  '
        index += 1
      } else if ((!clojure && character === '/' && next === '/')
        || (clojure && character === ';') || (hashComments && character === '#')) {
        output += ' '.repeat(line.length - index)
        break
      } else output += character
    }
    if (quote === '"' || quote === "'") quote = undefined
    for (const property of computedProperties) {
      if (output[property.bracketStart] !== '[' || output[property.end - 1] !== ']') continue
      output = output.slice(0, property.start) + property.value + output.slice(property.start + property.value.length)
    }
    return output
  })
}

function restrictProbableJob(job: MigrationJob): MigrationJob {
  if (job.changeEvent.verificationStatus !== 'probable') return job
  const probable = job.policy.probableChanges
  return {
    ...job,
    policy: {
      ...job.policy,
      maxChangedFiles: Math.min(job.policy.maxChangedFiles, probable.maxChangedFiles),
      maxPatchBytes: Math.min(job.policy.maxPatchBytes, probable.maxPatchBytes),
    },
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

async function loadValidationContext(
  rootDir: string,
  diagnostics: string[],
  policy: RepositoryPolicy,
): Promise<Array<{ path: string; content: string }>> {
  const maxFileBytes = Math.min(policy.maxModelInputBytes, 32_000)
  const candidates = [...new Set(diagnostics.flatMap(diagnostic =>
    [
      ...diagnostic.matchAll(/(?:file:\/\/)?\/workspace\/([^:\s)]+):\d+:\d+/gu),
      ...diagnostic.matchAll(/^\s*(?:error|warning|info)\s+-\s+(.+?\.dart):\d+:\d+\s+-/gimu),
    ].flatMap(match => match[1] === undefined ? [] : [match[1]]),
  ))].slice(0, 3)
  const context: Array<{ path: string; content: string }> = []
  let contextBytes = 0
  for (const candidate of candidates) {
    let path: string
    try {
      path = normalizeRepositoryPath(candidate)
    } catch {
      continue
    }
    const readablePaths = policy.modelReadablePaths ?? policy.allowedPaths
    if (matchesPolicyPath(path, policy.deniedPaths) || !matchesPolicyPath(path, readablePaths)) continue
    if (!/\.(?:[cm]?[jt]s|json|pyi?|rs|go|c|cc|cpp|cxx|h|hh|hpp|hxx|ipp|tpp|inl|inc|ixx|cppm|java|kt|kts|scala|sbt|cs|csproj|xml|php|rb|swift|dart|exs?|clj|cljc|cljs|edn|ya?ml|gradle|properties|toml|mod|sum|lock|txt)$/u.test(path)) continue
    let content: string
    try {
      content = await readFile(await resolveExistingPathInsideRepository(rootDir, path), 'utf8')
    } catch {
      continue
    }
    const bytes = Buffer.byteLength(content)
    if (bytes > maxFileBytes || contextBytes + bytes > policy.maxModelInputBytes) continue
    if (scanTextForSecrets(content).length > 0) continue
    contextBytes += bytes
    context.push({ path, content: content.slice(0, MAX_VALIDATION_CONTEXT_CHARACTERS) })
  }
  return context
}

export function isDependencyManifest(path: string): boolean {
  const name = path.split('/').at(-1) ?? path
  return name === 'package.json'
    || name === 'pyproject.toml'
    || name === 'uv.lock'
    || name === 'Pipfile'
    || name === 'Pipfile.lock'
    || name === 'Cargo.toml'
    || name === 'Cargo.lock'
    || name === 'go.mod'
    || name === 'go.sum'
    || name === 'pom.xml'
    || /^build\.gradle(?:\.kts)?$/u.test(name)
    || name === 'gradle.lockfile'
    || name === 'build.sbt'
    || path.replaceAll('\\', '/').endsWith('/project/build.properties')
    || name.endsWith('.csproj')
    || name === 'Directory.Packages.props'
    || name === 'packages.lock.json'
    || name === 'composer.json'
    || name === 'composer.lock'
    || name === 'Gemfile'
    || name === 'Gemfile.lock'
    || name.endsWith('.gemspec')
    || name === 'Package.swift'
    || name === 'Package.resolved'
    || name === 'pubspec.yaml'
    || name === 'pubspec.lock'
    || name === 'mix.exs'
    || name === 'mix.lock'
    || name === 'deps.edn'
    || name === 'project.clj'
    || name === 'vcpkg.json'
    || /^requirements(?:[-_.].*)?\.txt$/u.test(name)
}

function hasUnreplacedSymbol(value: string, oldSymbol: string, newSymbol: string): boolean {
  const oldStarts = literalTokenStarts(value, oldSymbol)
  if (!newSymbol.includes(oldSymbol)) return oldStarts.length > 0
  const replacementStarts = new Set(literalTokenStarts(value, newSymbol))
  return oldStarts.some(start => !replacementStarts.has(start))
}

function matchesPolicyPath(path: string, prefixes: string[]): boolean {
  return prefixes.some(prefix => {
    const normalizedPrefix = normalizeRepositoryPath(prefix).replace(/\/$/u, '')
    if (normalizedPrefix === '.') return true
    return path === normalizedPrefix || path.startsWith(`${normalizedPrefix}/`)
  })
}

function validateHarnessResult(
  input: HarnessResult,
  job: MigrationJob,
  modelPolicy: RepositoryPolicy,
  impact: RepositoryImpact,
  unresolvedFiles: Array<{ path: string; content: string }>,
) {
  const result = HarnessResultSchema.parse(input)
  if (result.jobId !== job.id || result.baseSha !== job.baseSha) {
    throw new Error('Harness result does not match the fixed migration job')
  }
  if (result.repairAttempt !== job.repairAttempt) {
    throw new Error('Harness result repair attempt does not match the migration job')
  }
  const supplied = new Map(unresolvedFiles.map(file => [file.path, sha256(file.content)]))
  const seen = new Set<string>()
  for (const edit of result.edits) {
    const path = normalizeRepositoryPath(edit.path)
    if (seen.has(path)) throw new Error(`Harness result contains duplicate edit path: ${path}`)
    seen.add(path)
    if (supplied.get(path) !== edit.expectedHash) {
      throw new Error(`Harness result contains an unread or stale edit path: ${path}`)
    }
  }
  validateProposedEdits(
    result.edits,
    unresolvedFiles.map(file => ({ ...file, expectedHash: sha256(file.content) })),
    impact,
    modelPolicy,
    job.repairContext?.diagnostics,
  )
  return result
}

async function loadUnresolvedFiles(
  rootDir: string,
  impact: RepositoryImpact,
  policy: RepositoryPolicy,
  previousEdits: Array<{ path: string; expectedHash: string; content: string }>,
  validationContext: Array<{ path: string; content: string }>,
  excludeDependencyManifests = false,
  includeDeterministicEvidence = false,
  validatedBoundaries?: ValidatedHarnessEditScope['files'],
  preservedAffectedUsageWindows: Array<{ path: string; start: number; end: number }> = [],
) {
  const includeDeterministic = previousEdits.length > 0 || includeDeterministicEvidence
  const readablePrefixes = policy.modelReadablePaths ?? policy.allowedPaths
  const paths = [...new Set(impact.evidence
    .filter(item => includeDeterministic || !item.deterministicRecipeSupported)
    .flatMap(item => item.location?.path === undefined ? [] : [item.location.path])
    .concat(previousEdits.map(edit => edit.path), validationContext.map(file => file.path)))]
    .map(normalizeRepositoryPath)
    .filter(path => matchesPolicyPath(path, readablePrefixes))
    .filter(path => !matchesPolicyPath(path, policy.deniedPaths))
    .filter(path => !excludeDependencyManifests || !isDependencyManifest(path))
    .sort()
  // These bodies are about to be sent to a hosted model, so this read goes
  // through the same containment and symlink resolution as every other file
  // access in the package rather than concatenating rootDir with the path.
  const files: Array<{ path: string; content: string }> = []
  const writableCount = paths.filter(path => matchesPolicyPath(path, policy.allowedPaths)).length
  if (paths.length > 100) throw new Error('affected Harness file count exceeds the hard model context limit of 100')
  if (writableCount > policy.maxChangedFiles) {
    throw new Error(`affected writable Harness file count ${writableCount} exceeds maxChangedFiles ${policy.maxChangedFiles}`)
  }
  const maximumLoaderBytes = Math.min(
    32 * 1024 * 1024,
    policy.maxModelInputBytes * policy.maxChangedFiles,
  )
  let loadedBytes = 0
  for (const path of paths) {
    const content = await readFile(await resolveExistingPathInsideRepository(rootDir, path), 'utf8')
    const bytes = Buffer.byteLength(content)
    if (bytes > policy.maxModelInputBytes) {
      throw new Error(`affected Harness file ${path} exceeds the per-file model input limit`)
    }
    loadedBytes += bytes
    if (loadedBytes > maximumLoaderBytes) {
      throw new Error('affected Harness files exceed the bounded loader safety limit')
    }
    files.push({ path, content })
  }
  if (previousEdits.length === 0) {
    if (validatedBoundaries !== undefined) throw new Error('validated repair scope has no cumulative source edits')
    return { files, repairEditBoundaries: [] }
  }
  if (previousEdits.length > policy.maxChangedFiles) {
    throw new Error('previous repair edit count exceeds repository policy')
  }
  const filesByPath = new Map(files.map(file => [file.path, file]))
  let repairEditBoundaries = createHarnessRepairEditBoundaries(impact, files, previousEdits, validatedBoundaries)
  if (validatedBoundaries !== undefined && preservedAffectedUsageWindows.length > 0) {
    repairEditBoundaries = preserveHarnessAffectedUsageWindows(
      files,
      previousEdits,
      repairEditBoundaries,
      preservedAffectedUsageWindows,
    )
  }
  const seen = new Set<string>()
  let outputBytes = 0
  for (const edit of previousEdits) {
    const path = assertPathAllowed(edit.path, policy)
    if (seen.has(path)) throw new Error(`previous repair contains duplicate edit for ${path}`)
    seen.add(path)
    const file = filesByPath.get(path)
    if (file === undefined || sha256(file.content) !== edit.expectedHash) {
      throw new Error(`previous repair edit base hash is stale for ${path}`)
    }
    outputBytes += Buffer.byteLength(edit.content)
    if (outputBytes > policy.maxPatchBytes) {
      throw new Error('previous repair edits exceed repository patch policy')
    }
    file.content = edit.content
  }
  return { files, repairEditBoundaries }
}

function modelEvidence(result: MigrationExecutorResult): NonNullable<ProposalArtifact['model']> {
  return {
    provider: result.provider ?? 'deepseek',
    model: result.model,
    confidence: result.confidence,
    finishReason: result.finishReason,
  }
}

function prefixImpactPaths(
  impact: RepositoryImpact,
  workingDirectory: string,
): RepositoryImpact {
  const prefix = normalizeRepositoryPath(workingDirectory)
  if (prefix === '.') return impact
  return {
    ...impact,
    evidence: impact.evidence.map(item => item.location === undefined
      ? item
      : {
          ...item,
          location: {
            ...item.location,
            path: normalizeRepositoryPath(`${prefix}/${item.location.path}`),
          },
        }),
  }
}

function repairImpact(job: MigrationJob, current: RepositoryImpact): RepositoryImpact {
  const validated = job.repairContext?.validatedImpact
  if (validated === undefined) return current
  if (validated.changeEventId !== job.changeEvent.id || validated.baseSha !== job.baseSha) {
    throw new Error('validated repair impact does not match the migration job identity')
  }
  const evidence = [...validated.evidence, ...current.evidence]
    .filter((item, index, all) => all.findIndex(candidate =>
      JSON.stringify(candidate) === JSON.stringify(item)) === index)
  return {
    ...current,
    outcome: current.outcome === 'blocked' || validated.outcome === 'blocked'
      ? 'blocked'
      : current.outcome === 'affected_draftable' && validated.outcome === 'affected_draftable'
        ? 'affected_draftable'
        : 'affected_manual',
    evidence,
    reasons: [...new Set([...validated.reasons, ...current.reasons])],
  }
}

function prefixRepositoryPaths(paths: string[], workingDirectory: string): string[] {
  const prefix = normalizeRepositoryPath(workingDirectory)
  if (prefix === '.') return paths
  return paths.map(path => normalizeRepositoryPath(`${prefix}/${path}`))
}
