import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, opendir, readFile, realpath } from 'node:fs/promises'
import { basename, relative, resolve } from 'node:path'
import { promisify } from 'node:util'
import { MigrationJobSchema, type MigrationJob } from '@automated-api/contracts'
import { resolveExistingPathInsideRepository } from '@automated-api/remediation'

const excluded = new Set(['.git', '.hg', '.venv', 'venv', 'node_modules', 'dist', 'build', '.build', 'coverage',
  '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'vendor'])
const MAX_LOCKS = 256
const MAX_LOCK_BYTES = 16 * 1024 * 1024
const MAX_GRAPH_BYTES = 32 * 1024 * 1024
const MAX_TRAVERSED_ENTRIES = 50_000
const MAX_DIRECTORY_DEPTH = 32

/** Bind every original NuGet lock to the immutable job base, not just one
 * root-level file. No project/MSBuild evaluation or repository code executes. */
export async function certifyNugetLockGraph(repositoryPath: string, jobInput: MigrationJob): Promise<string> {
  const exec = promisify(execFile)
  const job = MigrationJobSchema.parse(jobInput)
  const root = await realpath(resolve(repositoryPath))
  const directory = job.repository.packageManagerDirectory ?? job.repository.workingDirectory
  const managerRoot = await resolveExistingPathInsideRepository(root, directory)
  const environment = {
    PATH: process.env['PATH'],
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_CONFIG_COUNT: '0', GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', GIT_PROTOCOL_FROM_USER: '0',
  }
  const git = async (args: string[]) => (await exec('git', [
    '--no-replace-objects', '--literal-pathspecs', '-c', 'protocol.allow=never', '-C', root, ...args,
  ], { env: environment, timeout: 30_000, maxBuffer: 16 * 1024 * 1024, encoding: 'buffer' })).stdout
  const prefix = directory === '.' ? '' : `${directory}/`
  const tree = (await git(['ls-tree', '-r', '-z', '--name-only', job.baseSha, '--', directory])).toString('utf8').split('\0')
  if (tree.length > MAX_TRAVERSED_ENTRIES) throw new Error('NuGet baseline tree exceeds the entry bound')
  const baseline = tree.filter(name => name.startsWith(prefix) && basename(name) === 'packages.lock.json'
      && !name.slice(prefix.length).split('/').some(part => excluded.has(part))).sort()
  if (baseline.length === 0) throw new Error('NuGet certification requires committed packages.lock.json files at the exact job base')
  if (baseline.length > MAX_LOCKS) throw new Error('NuGet lock inventory exceeds the lock count bound')
  const current: string[] = []
  let traversedEntries = 0
  async function collect(directoryPath: string, depth = 0): Promise<void> {
    if (depth > MAX_DIRECTORY_DEPTH) throw new Error('NuGet lock traversal exceeds the directory depth bound')
    for await (const entry of await opendir(directoryPath)) {
      if (++traversedEntries > MAX_TRAVERSED_ENTRIES) throw new Error('NuGet lock traversal exceeds the entry bound')
      if (entry.name === 'packages.lock.json') {
        if (!entry.isFile() || entry.isSymbolicLink()) throw new Error('NuGet lock must be a regular non-symlink file')
        current.push(relative(root, resolve(directoryPath, entry.name)).replaceAll('\\', '/'))
        if (current.length > MAX_LOCKS) throw new Error('NuGet lock inventory exceeds the lock count bound')
      } else if (entry.isDirectory() && !excluded.has(entry.name)) {
        await collect(resolve(directoryPath, entry.name), depth + 1)
      }
    }
  }
  await collect(managerRoot)
  if (JSON.stringify(current.sort()) !== JSON.stringify(baseline)) {
    throw new Error('NuGet lock inventory differs from the immutable job base')
  }
  const locks = []
  let graphBytes = 0
  for (const file of baseline) {
    const absolute = await resolveExistingPathInsideRepository(root, file)
    const metadata = await lstat(absolute)
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_LOCK_BYTES) {
      throw new Error('NuGet lock must be a bounded regular file')
    }
    graphBytes += metadata.size
    if (graphBytes > MAX_GRAPH_BYTES) throw new Error('NuGet lock graph exceeds the aggregate byte bound')
    const original = await git(['cat-file', 'blob', `${job.baseSha}:${file}`])
    const installed = await readFile(absolute)
    if (!original.equals(installed)) throw new Error(`NuGet certification lockfile changed: ${file}`)
    locks.push({ path: file, sha256: createHash('sha256').update(original).digest('hex') })
  }
  return createHash('sha256').update(JSON.stringify(locks)).digest('hex')
}
