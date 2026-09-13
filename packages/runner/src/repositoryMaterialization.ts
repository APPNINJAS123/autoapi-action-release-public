import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { posix, resolve } from 'node:path'
import { promisify } from 'node:util'
import type { MigrationJob, RepositoryPolicy } from '@automated-api/contracts'
import { normalizeRepositoryPath, resolveExistingPathInsideRepository } from '@automated-api/remediation'

const exec = promisify(execFile)
const MAX_LFS_POINTER_BYTES = 1_024
const MAX_REVIEWED_WORKFLOW_BYTES = 128 * 1_024
const MAX_REPOSITORY_TREE_BYTES = 32 * 1024 * 1024
const MAX_REPOSITORY_SCAN_ENTRIES = 200_000
const MAX_POINTER_CANDIDATES = 10_000
const LFS_MAGIC = 'version https://git-lfs.github.com/spec/v1'
const LFS_MAGIC_LINE_PATTERN = '^version https://git-lfs\\.github\\.com/spec/v1$'

interface LfsPointerIdentity { path: string; oid: string; size: number }
interface TreeEntry { mode: string; type: string; oid: string; size?: number; path: string }

const METARANK_REPOSITORY = Object.freeze({
  owner: 'sajsnddkn',
  name: 'autoapi-real-metarank-sentry-scala',
  defaultBranch: 'main',
  workingDirectory: '.',
  packageManagerDirectory: '.',
  packageManager: 'sbt@1.10.1',
})
const METARANK_PUBLIC_REPOSITORY = Object.freeze({
  ...METARANK_REPOSITORY,
  owner: 'APPNINJAS123',
  name: 'autoapi-real-metarank-sentry-scala-public',
})
const METARANK_BASE_SHA = '8565f1a86412524e489faeb9525d10710af54841'
const METARANK_WORKFLOW = Object.freeze({
  path: '.github/workflows/autoapi-test.yml',
  blobOid: '978e05c34c0388d14c70ab8dc58f00221d1e675a',
  sha256: '91ec86567af7659967a05f1df1394c7a8e3b6881ba9429b16169c2fd327c2617',
  // The exact reviewed workflow uses actions/checkout with `lfs: false` and
  // runs the same Test/compile contract represented by the policy below.
  checkoutSemantics: 'actions-checkout-lfs-false-v1',
})
const definePolicy = (policy: RepositoryPolicy): RepositoryPolicy => Object.freeze(policy)
const METARANK_POLICY = definePolicy({
  allowedPaths: ['build.sbt'],
  modelReadablePaths: [
    'build.sbt',
    'src/main/scala/ai/metarank/util/analytics/ErrorReporter.scala',
  ],
  deniedPaths: ['.github/workflows', '.env', 'project/plugins.sbt'],
  validationCommands: [
    { executable: 'cs', args: ['launch', '--mode', 'offline', 'sbt:1.10.1', '--', 'Test/compile'], timeoutMs: 900_000 },
    { executable: 'python', args: ['scripts/verify-autoapi-sentry-scala-8.py', '--self-test'], timeoutMs: 60_000 },
  ],
  allowedNetworkHosts: [],
  maxChangedFiles: 1,
  maxPatchBytes: 100_000,
  maxModelInputBytes: 50_000,
  maxModelOutputTokens: 4_000,
  maxRunTimeMs: 3_600_000,
  maxRepairAttempts: 1,
  requiredChecks: ['scala-sbt-compile'],
  allowedLanguages: ['scala'],
  allowedManifestPaths: ['build.sbt'],
  probableChanges: {
    enabled: true,
    allowHarness: true,
    allowDraftPr: true,
    maxChangedFiles: 10,
    maxPatchBytes: 500_000,
  },
})

export const REVIEWED_METARANK_UNMATERIALIZED_POINTERS: readonly LfsPointerIdentity[] = Object.freeze([
  { path: 'deploy/kubernetes/templates/NOTES.txt', oid: '9f8c67e8069c98116f2d17e2bf1c31ec93f137b12c88b4c6ad017d25d65496ed', size: 1_751 },
  { path: 'doc/configuration/sample-error.json', oid: 'be567ea8b191ab097bab865e16a0db9a998a43d8204a7e838362b159d136695e', size: 6_228 },
  { path: 'doc/quickstart/request.json', oid: '760250734f1b294d9b7f5b7ac91b3b7b3e573a084a17afac84f9cf498c57cc85', size: 1_794 },
  { path: 'src/main/resources/crawlers.dat', oid: 'c1d1e5488970b5aec1836ecd5915644ec2fa62cbcba6c9c064e8bf03fabc0b15', size: 16_268 },
  { path: 'src/main/resources/referers.json', oid: 'e7620dd52a7d15e51e02210c3e07b747dbc45c4a490fd1203600b6fadf1efa57', size: 132_667 },
  { path: 'src/test/resources/codec/ctv-v1.bin', oid: '1f53dddebb11b830db2f3388b4bdb2d6617066d8b2b038c07c05579ebf66b8af', size: 207 },
  { path: 'src/test/resources/codec/ctv-v2.bin', oid: '5a8e2efb805b724eb1f7e5e19a55d44f4df0abef54c570dd2673d99cf4a5bd50', size: 208 },
  { path: 'src/test/resources/codec/ctv-v3.bin', oid: '1cd75fda1f292507c2f805e1d8d90782d808c68e89729244bb7f2f6d983020aa', size: 210 },
  { path: 'src/test/resources/embedding/cohere.csv', oid: '94ebdc6d0a4f45cb06682d4189eba84ae51ea2147f8764bc37154f2ed7baa58a', size: 221_274 },
  { path: 'src/test/resources/japanese.json', oid: 'ab879bf154b5826455e57f6ecbdad99fc51bd8e619a2a6b5775aea2867d05746', size: 244 },
  { path: 'src/test/resources/models/lightgbm.model', oid: 'a797bfc8f8060da6fceb69cc18ccf96d4b17c18e60be62e8c3426b76e94e3f0b', size: 703_876 },
  { path: 'src/test/resources/models/xgboost-b64.model', oid: '5008344b160e9ee18537f0e583d68092a32de3806922d5b6697d5f96fd50ac2c', size: 982_549 },
  { path: 'src/test/resources/models/xgboost.model', oid: '25c8b61a55db61a19bc034c514aac69533aa718a759af6686f6e4aa39c3f18e3', size: 727_341 },
  { path: 'src/test/resources/movielens/ratings.dat.gz', oid: '273193f099784fdba4f958863460b193e7e94492db9100c42e16b03c4c84f2e9', size: 5_903_722 },
  { path: 'src/test/resources/ranklens/events/events.jsonl.gz', oid: 'd4009c698bcc23f0648107dc167f2a3c797ebcb1737e68ec727c7057558a99aa', size: 4_023_025 },
  { path: 'src/test/resources/ranklens/ranklens.model', oid: '6bb5a1adbeae8d7db1c194310982a41ca3a94aa88c4c51a759c74615143828a0', size: 694_441 },
  { path: 'src/test/resources/sbert/sentence-transformer/all-MiniLM-L6-v2.onnx', oid: 'da179c2dacb24694cbabd1fcd91aae30fa8d37faa2d4d510d18455ee2d0b79b1', size: 90_979_431 },
  { path: 'src/test/resources/sbert/sentence-transformer/vocab.txt', oid: '07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3', size: 231_508 },
  { path: 'src/test/resources/snowplow/empty.tsv', oid: 'aed54264f3adb44644757edd073532f0ff8aebc07031ac2f853a9032328e4d01', size: 194 },
  { path: 'src/test/resources/snowplow/interaction.json', oid: '73efba1a1cf65a1611ec851e0723bc807c0558543138c3a2008112611a988da8', size: 3_096 },
  { path: 'src/test/resources/snowplow/interaction.tsv', oid: '291a57ce508ff27ef5d1404566969b62f0efae522b61efec75d4d892cccef3fc', size: 637 },
  { path: 'src/test/resources/snowplow/item.tsv', oid: 'f6c6563b708273dddd9590169483c5934db2374246110669c771fbc2810b01ac', size: 579 },
  { path: 'src/test/resources/snowplow/other.tsv', oid: '5ed0dfd15818d59f32ac0694753551aebb3722c32fcf866e2ab3cead400211ff', size: 350 },
  { path: 'src/test/resources/snowplow/ranking.tsv', oid: '4592250f0bcbedeebcc6dbefa1801abb28b017b3319dceb0dbf13ee8e56871a2', size: 655 },
  { path: 'src/test/resources/snowplow/user.tsv', oid: '913609f5d6fffd4ee0b274494bb2c7fabe695616ee905f58705f0cdaec94a430', size: 515 },
  { path: 'src/test/resources/tf-test.json.gz', oid: '3fe194cd509a8da1e93a2805523a6d0b553213062656a03a9d228bfd29d43ca8', size: 210 },
].sort(comparePointerIdentity))

/**
 * Git stores an LFS pointer as a complete ordinary blob. A clean worktree and
 * `git fsck` therefore do not prove that build/model inputs are materialized.
 * Every unresolved pointer fails closed. The sole exception is a complete,
 * immutable inventory from the reviewed Metarank base whose required CI also
 * checks out with LFS disabled; even there, policy or command inputs may never
 * intersect the exception.
 */
export async function assertMaterializedRepositoryInputs(
  job: MigrationJob,
  rootDir: string,
): Promise<void> {
  const repositoryRoot = await realpath(resolve(rootDir))
  const workingDirectory = normalizeRepositoryPath(job.repository.workingDirectory)
  const managerDirectory = normalizeRepositoryPath(
    job.repository.packageManagerDirectory ?? job.repository.workingDirectory,
  )
  await Promise.all([
    resolveExistingPathInsideRepository(repositoryRoot, workingDirectory),
    resolveExistingPathInsideRepository(repositoryRoot, managerDirectory),
  ])

  const tree = await readHeadTree(repositoryRoot)
  const treeByPath = new Map(tree.map(entry => [entry.path, entry]))
  const relevantScopes = [...new Set([
    ...job.policy.allowedPaths,
    ...(job.policy.modelReadablePaths ?? []),
    ...(job.policy.allowedManifestPaths ?? []),
    ...resolveRepositoryCommandScopes(job),
  ].map(normalizeRepositoryPath))]

  for (const entry of tree) {
    if (entry.mode === '120000' && scopeIntersectsPath(entry.path, relevantScopes)) {
      throw new Error(`repository input must not be a symbolic link: ${entry.path}`)
    }
  }

  const treeCandidates = await grepMagicCandidates(repositoryRoot, true)
  const treePointers: LfsPointerIdentity[] = []
  for (const path of treeCandidates) {
    const entry = treeByPath.get(path)
    if (entry === undefined || entry.type !== 'blob' || entry.mode === '120000') {
      throw new Error('repository materialization candidate is not an ordinary tracked blob')
    }
    if ((entry.size ?? MAX_LFS_POINTER_BYTES + 1) > MAX_LFS_POINTER_BYTES) continue
    const content = await readGitBlob(repositoryRoot, entry.oid)
    const parsed = parseLfsPointerStub(content)
    if (parsed === undefined) {
      throw new Error(`repository input contains malformed Git LFS pointer: ${path}`)
    }
    treePointers.push({ path, ...parsed })
  }
  treePointers.sort(comparePointerIdentity)

  const waiver = await reviewedPointerWaiver(job, repositoryRoot, treeByPath, treePointers)
  if (waiver !== undefined) {
    for (const pointer of treePointers) {
      if (scopeIntersectsPath(pointer.path, relevantScopes)) {
        throw new Error(`reviewed Git LFS waiver intersects repository input scope: ${pointer.path}`)
      }
    }
  }
  const worktreeCandidates = await grepMagicCandidates(repositoryRoot, false)
  for (const path of worktreeCandidates) {
    const entry = treeByPath.get(path)
    if (entry === undefined || entry.type !== 'blob' || entry.mode === '120000') {
      throw new Error('repository materialization candidate is not an ordinary tracked file')
    }
    const content = await readSmallRegularFile(repositoryRoot, path)
    if (content === undefined) continue
    const pointer = parseLfsPointerStub(content)
    if (pointer === undefined) {
      throw new Error(`repository input contains malformed Git LFS pointer: ${path}`)
    }
    if (scopeIntersectsPath(path, relevantScopes)) {
      throw new Error(`repository input contains unresolved Git LFS pointer: ${path}`)
    }
    if (waiver === undefined || !waiver.has(pointerKey({ path, ...pointer }))) {
      throw new Error(`repository input contains unresolved Git LFS pointer: ${path}`)
    }
  }
}

async function reviewedPointerWaiver(
  job: MigrationJob,
  repositoryRoot: string,
  treeByPath: ReadonlyMap<string, TreeEntry>,
  actualPointers: readonly LfsPointerIdentity[],
): Promise<ReadonlySet<string> | undefined> {
  if (!matchesReviewedMetarankRepository(job.repository)
    || job.baseSha !== METARANK_BASE_SHA) return undefined
  const workflow = treeByPath.get(METARANK_WORKFLOW.path)
  if (workflow === undefined) throw new Error('reviewed Git LFS waiver workflow identity changed')
  const workflowBytes = await readGitBlob(repositoryRoot, workflow.oid, MAX_REVIEWED_WORKFLOW_BYTES)
  assertReviewedMetarankPointerWaiverBinding(job, actualPointers, {
    path: workflow.path,
    mode: workflow.mode,
    type: workflow.type,
    oid: workflow.oid,
    sha256: sha256(workflowBytes),
    checkoutSemantics: METARANK_WORKFLOW.checkoutSemantics,
  })
  return new Set(REVIEWED_METARANK_UNMATERIALIZED_POINTERS.map(pointerKey))
}

export function assertReviewedMetarankPointerWaiverBinding(
  job: MigrationJob,
  actualPointers: readonly LfsPointerIdentity[],
  workflow: {
    path: string
    mode: string
    type: string
    oid: string
    sha256: string
    checkoutSemantics: string
  },
): void {
  const expectedRepository = job.repository.owner === METARANK_PUBLIC_REPOSITORY.owner
    ? METARANK_PUBLIC_REPOSITORY : METARANK_REPOSITORY
  if (!matchesReviewedMetarankRepository(job.repository)
    || job.baseSha !== METARANK_BASE_SHA
    || JSON.stringify(job.repository) !== JSON.stringify(expectedRepository)
    || JSON.stringify(job.policy) !== JSON.stringify(METARANK_POLICY)) {
    throw new Error('reviewed Git LFS waiver repository policy changed')
  }
  assertExactReviewedPointerInventory(actualPointers, REVIEWED_METARANK_UNMATERIALIZED_POINTERS)
  if (workflow.path !== METARANK_WORKFLOW.path || workflow.mode !== '100644'
    || workflow.type !== 'blob' || workflow.oid !== METARANK_WORKFLOW.blobOid) {
    throw new Error('reviewed Git LFS waiver workflow identity changed')
  }
  if (workflow.sha256 !== METARANK_WORKFLOW.sha256
    || workflow.checkoutSemantics !== 'actions-checkout-lfs-false-v1') {
    throw new Error('reviewed Git LFS waiver workflow semantics changed')
  }
}

function matchesReviewedMetarankRepository(repository: MigrationJob['repository']): boolean {
  return (repository.owner === METARANK_REPOSITORY.owner && repository.name === METARANK_REPOSITORY.name)
    || (repository.owner === METARANK_PUBLIC_REPOSITORY.owner
      && repository.name === METARANK_PUBLIC_REPOSITORY.name)
}

export function assertExactReviewedPointerInventory(
  actual: readonly LfsPointerIdentity[],
  expected: readonly LfsPointerIdentity[],
): void {
  const normalizedActual = [...actual].sort(comparePointerIdentity).map(pointerKey)
  const normalizedExpected = [...expected].sort(comparePointerIdentity).map(pointerKey)
  if (JSON.stringify(normalizedActual) !== JSON.stringify(normalizedExpected)) {
    throw new Error('reviewed Git LFS pointer inventory changed')
  }
}

export function resolveRepositoryCommandScopes(job: MigrationJob): string[] {
  const workingDirectory = normalizeRepositoryPath(job.repository.workingDirectory)
  return [...new Set(job.policy.validationCommands
    .flatMap(command => [command.executable, ...command.args])
    .flatMap(value => {
      if (!looksLikeRepositoryPath(value)) return []
      const portable = value.replaceAll('\\', '/')
      if (portable.startsWith('/') || /^[a-zA-Z]:\//u.test(portable)) return []
      try {
        return [normalizeRepositoryPath(posix.join(workingDirectory, portable))]
      } catch {
        return []
      }
    }))].sort()
}

function looksLikeRepositoryPath(value: string): boolean {
  if (value === '' || value.startsWith('-') || value.includes('\0')
    || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//u.test(value)) return false
  return value === '.' || value.startsWith('./') || value.startsWith('../')
    || value.includes('/') || value.includes('\\')
    || /(?:^|[^A-Za-z0-9])[A-Za-z0-9_.-]+\.[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)
}

function scopeIntersectsPath(path: string, scopes: readonly string[]): boolean {
  return scopes.some(scope => scope === '.' || path === scope
    || path.startsWith(`${scope}/`) || scope.startsWith(`${path}/`))
}

async function readHeadTree(repositoryRoot: string): Promise<TreeEntry[]> {
  const output = await git(repositoryRoot, ['ls-tree', '--long', '-r', '-z', '--full-tree', 'HEAD'])
  const records = output.toString('utf8').split('\0')
  if (records.at(-1) !== '') throw new Error('repository tree listing is not NUL terminated')
  records.pop()
  if (records.length > MAX_REPOSITORY_SCAN_ENTRIES) {
    throw new Error('repository materialization scan exceeds its bounded entry limit')
  }
  return records.map(record => {
    const separator = record.indexOf('\t')
    if (separator === -1) throw new Error('repository tree listing is malformed')
    const metadata = /^(100644|100755|120000|160000) (blob|commit) ([a-f0-9]{40}) +(-|[0-9]+)$/u
      .exec(record.slice(0, separator))
    const path = record.slice(separator + 1)
    if (metadata === null || path === '' || path.includes('\0')) {
      throw new Error('repository tree listing is malformed')
    }
    return {
      mode: metadata[1]!, type: metadata[2]!, oid: metadata[3]!,
      ...(metadata[4] === '-' ? {} : { size: Number(metadata[4]) }), path,
    }
  })
}

async function grepMagicCandidates(repositoryRoot: string, committed: boolean): Promise<string[]> {
  // `-a` is essential: malformed pointer stubs may contain NUL or other binary
  // bytes, and `-I` would silently omit them. The anchored, escaped expression
  // selects the complete magic line without emitting file content.
  const args = ['grep', '-a', '-E', '-l', '-z', '-e', LFS_MAGIC_LINE_PATTERN, ...(committed ? ['HEAD'] : []), '--']
  let output: Buffer
  try {
    output = await git(repositoryRoot, args)
  } catch (error) {
    if (isExitCode(error, 1)) return []
    throw error
  }
  const records = output.toString('utf8').split('\0')
  if (records.at(-1) !== '') throw new Error('repository pointer listing is not NUL terminated')
  records.pop()
  if (records.length > MAX_POINTER_CANDIDATES) {
    throw new Error('repository pointer listing exceeds its bounded candidate limit')
  }
  return records.map(record => {
    const path = committed && record.startsWith('HEAD:') ? record.slice(5) : record
    return normalizeRepositoryPath(path)
  }).sort()
}

async function readGitBlob(
  repositoryRoot: string,
  oid: string,
  maximumBytes = MAX_LFS_POINTER_BYTES,
): Promise<Buffer> {
  return git(repositoryRoot, ['cat-file', 'blob', oid], maximumBytes + 1)
}

async function readSmallRegularFile(repositoryRoot: string, path: string): Promise<Buffer | undefined> {
  const absolute = resolve(repositoryRoot, ...path.split('/'))
  const identity = await lstat(absolute)
  if (identity.isSymbolicLink()) throw new Error(`repository input must not be a symbolic link: ${path}`)
  if (!identity.isFile() || identity.size < 1 || identity.size > MAX_LFS_POINTER_BYTES) return undefined
  const descriptor = await open(
    absolute,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
  )
  try {
    const metadata = await descriptor.stat()
    if (!metadata.isFile() || metadata.size !== identity.size
      || metadata.dev !== identity.dev || metadata.ino !== identity.ino) {
      throw new Error('repository input changed during materialization verification')
    }
    const buffer = Buffer.alloc(metadata.size)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await descriptor.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    if (offset !== buffer.length) throw new Error('repository input changed during materialization verification')
    return buffer
  } finally {
    await descriptor.close()
  }
}

function parseLfsPointerStub(content: Buffer): { oid: string; size: number } | undefined {
  const normalized = content.toString('utf8').replaceAll('\r\n', '\n')
  if (normalized !== LFS_MAGIC && !normalized.startsWith(`${LFS_MAGIC}\n`)) return undefined
  const match = new RegExp(`^${LFS_MAGIC}\\noid sha256:([a-f0-9]{64})\\nsize (0|[1-9][0-9]*)\\n?$`, 'u')
    .exec(normalized)
  if (match === null) return undefined
  const size = Number(match[2])
  return Number.isSafeInteger(size) ? { oid: match[1]!, size } : undefined
}

function pointerKey(pointer: LfsPointerIdentity): string {
  return `${pointer.path}\0${pointer.oid}\0${pointer.size}`
}

function comparePointerIdentity(left: LfsPointerIdentity, right: LfsPointerIdentity): number {
  return pointerKey(left).localeCompare(pointerKey(right))
}

function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

async function git(repositoryRoot: string, args: string[], maxBuffer = MAX_REPOSITORY_TREE_BYTES): Promise<Buffer> {
  return (await exec('git', [
    '--no-replace-objects', '--literal-pathspecs', '-c', 'protocol.allow=never', '-C', repositoryRoot, ...args,
  ], {
    encoding: 'buffer', timeout: 60_000, maxBuffer,
    env: {
      PATH: process.env.PATH,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
      GIT_CONFIG_COUNT: '0',
      GIT_NO_LAZY_FETCH: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
    },
  })).stdout
}

function isExitCode(error: unknown, code: number): boolean {
  return typeof error === 'object' && error !== null && Number((error as { code?: unknown }).code) === code
}
