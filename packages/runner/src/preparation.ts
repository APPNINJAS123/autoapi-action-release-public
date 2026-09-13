import type { MigrationJob, RepositoryImpact } from '@automated-api/contracts'
import { MigrationJobSchema } from '@automated-api/contracts'
import {
  analyzeRepository,
  normalizeRepositoryPath,
  resolveExistingPathInsideRepository,
} from '@automated-api/remediation'
import { verifyFixedHead } from './git.js'
import { assertMaterializedRepositoryInputs } from './repositoryMaterialization.js'
import { hasReviewedEmbabelKotlinRecipeAuthority } from './reviewedKotlinConsumer.js'

export type PreparationAnalysisResult =
  | { status: 'prepare_dependencies'; impact: RepositoryImpact; deferPreliminaryProposal: boolean }
  | { status: 'not_affected' | 'blocked'; impact: RepositoryImpact }

export function shouldDeferPreliminaryProposal(jobInput: MigrationJob): boolean {
  const job = MigrationJobSchema.parse(jobInput)
  // The exact reviewed recipe belongs only to the initial deterministic
  // proposal. A repair already carries the failed validation context and must
  // reach Harness instead of re-entering the attempt-0 authority assertion.
  if (job.repairAttempt > 0 && job.repairContext !== undefined) return false
  return hasReviewedEmbabelKotlinRecipeAuthority(job)
}

/**
 * Performs the read-only repository analysis before customer dependency setup.
 * This deliberately parses manifests and source but never imports or executes
 * customer code. A terminal no-op can therefore avoid an unnecessary package
 * install, while any potentially affected repository continues through the
 * pinned-manager and offline proposal path.
 */
export async function analyzePreparation(
  jobInput: MigrationJob,
  rootDir: string,
): Promise<PreparationAnalysisResult> {
  const job = MigrationJobSchema.parse(jobInput)
  await verifyFixedHead(rootDir, job.baseSha)
  await assertMaterializedRepositoryInputs(job, rootDir)
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
  const impact = prefixImpactPaths(workspaceImpact, job.repository.workingDirectory)
  if (impact.outcome === 'not_affected') return { status: 'not_affected', impact }
  if (impact.outcome === 'blocked') return { status: 'blocked', impact }
  return {
    status: 'prepare_dependencies',
    impact,
    // The analysis-stage checkout is intentionally read-only. Exact reviewed
    // recipes are applied only by the final offline runner on its writable
    // workspace after dependency/toolchain certification.
    deferPreliminaryProposal: shouldDeferPreliminaryProposal(job),
  }
}

function prefixImpactPaths(impact: RepositoryImpact, workingDirectory: string): RepositoryImpact {
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
