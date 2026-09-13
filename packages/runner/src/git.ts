import { spawn } from 'node:child_process'
import { scrubEnvironment } from './environment.js'

export class GitCommandError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'GitCommandError'
  }
}

export async function git(rootDir: string, args: string[]): Promise<Buffer> {
  const child = spawn('git', args, {
    cwd: rootDir,
    // git runs inside a customer-controlled checkout and honours repository
    // configuration that can execute commands, so it gets the same credential
    // scrub as repository validation commands.
    env: scrubEnvironment(process.env),
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const stdout: Buffer[] = []
  const stderr: Buffer[] = []
  child.stdout.on('data', chunk => stdout.push(Buffer.from(chunk)))
  child.stderr.on('data', chunk => stderr.push(Buffer.from(chunk)))
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', resolve)
  })
  if (code !== 0) {
    throw new GitCommandError(`git ${args[0] ?? ''} failed: ${Buffer.concat(stderr).toString('utf8').trim()}`)
  }
  return Buffer.concat(stdout)
}

export async function verifyFixedHead(rootDir: string, expectedSha: string): Promise<void> {
  const actual = (await git(rootDir, ['rev-parse', 'HEAD'])).toString('utf8').trim()
  if (actual !== expectedSha) throw new GitCommandError(`repository HEAD ${actual} does not match job base ${expectedSha}`)
  // A clean-head gate only needs to know whether an untracked directory
  // exists; recursively enumerating every file can take minutes in large
  // customer monorepos mounted into the Linux validation container.
  const status = await git(rootDir, ['status', '--porcelain=v1', '--untracked-files=normal'])
  if (status.length !== 0) {
    throw new GitCommandError('repository worktree is not clean at the fixed job base')
  }
}

