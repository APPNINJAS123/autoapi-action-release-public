import { realpath } from 'node:fs/promises'
import { dirname, isAbsolute, posix, relative, resolve, sep } from 'node:path'
import type { RepositoryPolicy } from '@automated-api/contracts'

export class PolicyViolationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PolicyViolationError'
  }
}

export function normalizeRepositoryPath(path: string): string {
  const normalized = path.replaceAll('\\', '/').replace(/^\.\//u, '')
  if (normalized.length === 0 || isAbsolute(path) || /^[a-zA-Z]:\//u.test(normalized)) {
    throw new PolicyViolationError(`path must be repository-relative: ${path}`)
  }
  const collapsed = posix.normalize(normalized)
  if (collapsed === '..' || collapsed.startsWith('../')) {
    throw new PolicyViolationError(`path escapes repository: ${path}`)
  }
  return collapsed
}

export function assertPathAllowed(path: string, policy: RepositoryPolicy): string {
  const normalized = normalizeRepositoryPath(path)
  if (matchesAny(normalized, policy.deniedPaths)) {
    throw new PolicyViolationError(`path is denied by repository policy: ${normalized}`)
  }
  if (!matchesAny(normalized, policy.allowedPaths)) {
    throw new PolicyViolationError(`path is outside allowed repository paths: ${normalized}`)
  }
  return normalized
}

export function resolveInsideRepository(rootDir: string, path: string): string {
  const normalized = normalizeRepositoryPath(path)
  const root = resolve(rootDir)
  const absolute = resolve(root, ...normalized.split('/'))
  const fromRoot = relative(root, absolute)
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new PolicyViolationError(`resolved path escapes repository: ${path}`)
  }
  return absolute
}

export async function resolveExistingPathInsideRepository(rootDir: string, path: string): Promise<string> {
  const lexical = resolveInsideRepository(rootDir, path)
  const [realRoot, realTarget] = await Promise.all([realpath(rootDir), realpath(lexical)])
  assertContained(realRoot, realTarget, path)
  return realTarget
}

export async function resolveWritablePathInsideRepository(rootDir: string, path: string): Promise<string> {
  const lexical = resolveInsideRepository(rootDir, path)
  const [realRoot, realParent] = await Promise.all([realpath(rootDir), realpath(dirname(lexical))])
  assertContained(realRoot, realParent, path)
  return lexical
}

function assertContained(root: string, target: string, originalPath: string): void {
  const fromRoot = relative(root, target)
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new PolicyViolationError(`symlink resolves outside repository: ${originalPath}`)
  }
}

function matchesAny(path: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => {
    const normalizedPrefix = normalizeRepositoryPath(prefix).replace(/\/$/u, '')
    // `.` is the canonical repository-root scope. Treating it as a literal
    // prefix (`./`) rejected every normal nested path, so a policy that meant
    // "the whole repository" could not be used by the hosted Harness.
    if (normalizedPrefix === '.') return true
    return path === normalizedPrefix || path.startsWith(`${normalizedPrefix}/`)
  })
}
