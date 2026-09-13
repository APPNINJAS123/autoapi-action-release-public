import { createHash } from 'node:crypto'
import { lstat, readFile, realpath } from 'node:fs/promises'
import { resolve } from 'node:path'
import { MigrationJobSchema, type MigrationJob, type ToolchainCertification } from '@automated-api/contracts'
import { resolveExistingPathInsideRepository } from '@automated-api/remediation'

export interface ReviewedJvmContext { job: MigrationJob; repositoryRoot: string }
export type ReviewedJvmToolchainReceipt = NonNullable<ToolchainCertification['reviewedJvmToolchain']>

const bindings = Object.freeze([
  {
    name: 'autoapi-real-embabel-spring-ai-kotlin', baseSha: '6730800c9010bc288a90a43c64567838fce8e96a',
    owners: ['supportcontact584-png', 'sajsnddkn'],
    managerDirectory: 'autoapi-kotlin-proof', managerSpec: 'maven@3.9.11', javaVersion: '21.0.8',
    workflowPath: '.github/workflows/autoapi-kotlin.yml',
    workflowSha256: '325aa8da14abc32fb42bf7438cd3bac7e12efeb826f35f615b387a3505d60171',
    wrapper: {
      path: 'mvnw', sha256: '07dcf9a57f107e391b624961473157ca753af0bc5cfcc4c8693a9e29ff93c36d',
      archiveUrl: 'https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz',
      archiveSha512: 'bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978',
    },
  },
  {
    name: 'autoapi-real-embabel-spring-ai-kotlin', baseSha: '3b53abdc8ee91037f4ed5b045d172a0c906af64d',
    repositories: ['sajsnddkn/autoapi-real-embabel-spring-ai-kotlin',
      'APPNINJAS123/autoapi-real-embabel-spring-ai-kotlin-public'],
    managerDirectory: 'autoapi-kotlin-proof', managerSpec: 'maven@3.9.11', javaVersion: '21.0.8',
    workflowPath: '.github/workflows/autoapi-kotlin.yml',
    workflowSha256: 'c21371376973cc03f37f434d28737305467d73b89dc62b8d4f61662136f4ad31',
    wrapper: {
      path: 'mvnw', sha256: '07dcf9a57f107e391b624961473157ca753af0bc5cfcc4c8693a9e29ff93c36d',
      archiveUrl: 'https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz',
      archiveSha512: 'bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978',
    },
  },
  {
    name: 'autoapi-real-metarank-sentry-scala', baseSha: 'e44a8c60b7093575438ba45c1f4a5497ec365d20',
    owners: ['supportcontact584-png'],
    managerDirectory: '.', managerSpec: 'sbt@1.10.1', javaVersion: '11.0.28',
    workflowPath: '.github/workflows/autoapi-test.yml',
    workflowSha256: '2fc818f07b04083568858ac1923232244526ad0d13455d6c4a562a943d6bba3e',
  },
  {
    name: 'autoapi-real-metarank-sentry-scala', baseSha: '8565f1a86412524e489faeb9525d10710af54841',
    repositories: ['sajsnddkn/autoapi-real-metarank-sentry-scala',
      'APPNINJAS123/autoapi-real-metarank-sentry-scala-public'],
    managerDirectory: '.', managerSpec: 'sbt@1.10.1', javaVersion: '11.0.28',
    workflowPath: '.github/workflows/autoapi-test.yml',
    workflowSha256: '91ec86567af7659967a05f1df1394c7a8e3b6881ba9429b16169c2fd327c2617',
  },
] as const)

/** Read metadata without following customer links. Only an absent path may
 * trigger a reviewed fallback; malformed/nonregular present paths fail closed. */
export async function readJvmMetadata(root: string, file: string): Promise<string | undefined> {
  const parts = file.split('/')
  for (let index = 0; index < parts.length; index++) {
    const candidate = resolve(root, ...parts.slice(0, index + 1))
    let stat
    try { stat = await lstat(candidate) } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw error
    }
    if (stat.isSymbolicLink() || (index < parts.length - 1 ? !stat.isDirectory() : !stat.isFile())) {
      throw new Error(`JVM metadata must be regular and non-symlink: ${file}`)
    }
    if (index === parts.length - 1 && stat.size > 64 * 1024) throw new Error(`JVM metadata is oversized: ${file}`)
  }
  return readFile(resolve(root, file), 'utf8')
}

/** Not a generic workflow parser: exact job binding and independently reviewed
 * bytes select an explicit immutable runtime/archive, without executing them. */
export async function reviewedJvmToolchain(
  managerRoot: string, context: ReviewedJvmContext | undefined,
): Promise<ReviewedJvmToolchainReceipt> {
  if (context === undefined) throw new Error('Missing JVM metadata requires an exact reviewed migration job binding')
  const job = MigrationJobSchema.parse(context.job)
  const repository = `${job.repository.owner}/${job.repository.name}`
  const binding = bindings.find(item => item.baseSha === job.baseSha
    && item.managerSpec === job.repository.packageManager
    && item.managerDirectory === (job.repository.packageManagerDirectory ?? job.repository.workingDirectory)
    && ('repositories' in item
      ? (item.repositories as readonly string[]).includes(repository)
      : (item.owners as readonly string[]).map(owner => `${owner}/${item.name}`).includes(repository)))
  if (binding === undefined) throw new Error('Missing JVM metadata has no reviewed repository binding')
  const root = resolve(context.repositoryRoot)
  const expectedManager = await resolveExistingPathInsideRepository(root, binding.managerDirectory)
  if (await realpath(resolve(managerRoot)) !== expectedManager) throw new Error('Reviewed JVM manager root does not match its job')
  const workflow = await readJvmMetadata(root, binding.workflowPath)
  if (workflow === undefined || sha256(workflow) !== binding.workflowSha256) throw new Error('Reviewed JVM workflow bytes changed')
  if ('wrapper' in binding) {
    const wrapper = await readJvmMetadata(root, binding.wrapper.path)
    if (wrapper === undefined || sha256(wrapper) !== binding.wrapper.sha256) throw new Error('Reviewed JVM wrapper bytes changed')
  }
  return {
    policyVersion: 'reviewed-jvm-toolchain-v1', repositoryBinding: `${job.repository.owner}/${job.repository.name}@${job.baseSha}`,
    managerSpec: binding.managerSpec, javaVersion: binding.javaVersion,
    workflowPath: binding.workflowPath, workflowSha256: binding.workflowSha256,
    ...('wrapper' in binding ? { wrapper: { ...binding.wrapper } } : {}),
  }
}

/** Current execution cannot re-key a legacy-shaped certificate to omit the
 * reviewed metadata required by either exact historical JVM base. */
export function assertReviewedJvmCertification(certificate: ToolchainCertification): void {
  const binding = bindings.find(item => item.baseSha === certificate.baseSha && item.managerSpec === certificate.manager.spec)
  const receipt = certificate.reviewedJvmToolchain
  if (binding === undefined && receipt === undefined) return
  if (binding === undefined || receipt === undefined) throw new Error('Current JVM execution requires its exact reviewed metadata receipt')
  const repository = receipt.repositoryBinding.split('@')[0]!
  const approvedRepositories: readonly string[] = 'repositories' in binding
    ? binding.repositories
    : binding.owners.map(owner => `${owner}/${binding.name}`)
  if (!approvedRepositories.includes(repository)
    || receipt.workflowPath !== binding.workflowPath || receipt.workflowSha256 !== binding.workflowSha256
    || receipt.javaVersion !== binding.javaVersion
    || JSON.stringify(receipt.wrapper) !== JSON.stringify('wrapper' in binding ? binding.wrapper : undefined)) {
    throw new Error('JVM certification metadata does not match the reviewed repository receipt')
  }
}

function sha256(value: string): string { return createHash('sha256').update(value).digest('hex') }
