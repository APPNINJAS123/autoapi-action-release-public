import { link, lstat, mkdir, open, unlink } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { ProposalRunnerResult } from './runner.js'

const RESERVED_OUTPUTS = Object.freeze([
  'result.json',
  'result.json.part',
  'manifest.json',
  'manifest.json.part',
  'proposal.patch',
  'proposal.patch.part',
])

interface PublicationEntry {
  name: 'result.json' | 'manifest.json' | 'proposal.patch'
  bytes: Buffer
}

interface OwnedPart {
  entry: PublicationEntry
  path: string
  device: number | bigint
  inode: number | bigint
}

export async function prepareRunnerOutputDirectory(outputPath: string): Promise<string> {
  const directory = resolve(outputPath)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const metadata = await lstat(directory)
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error('runner output path must be a real directory')
  }
  return directory
}

export async function publishProposalRunnerResult(
  outputPath: string,
  result: ProposalRunnerResult,
): Promise<void> {
  const directory = await prepareRunnerOutputDirectory(outputPath)
  const entries = publicationEntries(result)
  for (const name of RESERVED_OUTPUTS) await requireAbsent(resolve(directory, name), name)

  const ownedParts: OwnedPart[] = []
  const published: OwnedPart[] = []
  try {
    for (const entry of entries) {
      const partPath = resolve(directory, `${entry.name}.part`)
      const handle = await open(partPath, 'wx', 0o600).catch(error => {
        throw collisionError(entry.name, error)
      })
      try {
        const metadata = await handle.stat()
        const owned = {
          entry,
          path: partPath,
          device: metadata.dev,
          inode: metadata.ino,
        }
        ownedParts.push(owned)
        if (!metadata.isFile() || metadata.nlink !== 1) {
          throw new Error(`runner ${entry.name} staging file is not an owned regular file`)
        }
        await handle.chmod(0o600)
        await handle.writeFile(entry.bytes)
        await handle.sync()
      } finally {
        await handle.close()
      }
    }

    // Publish the result last. Its presence is the commit marker that any
    // proposed patch and manifest were already durably published.
    for (const part of ownedParts) {
      const destination = resolve(directory, part.entry.name)
      await link(part.path, destination).catch(error => {
        throw collisionError(part.entry.name, error)
      })
      await requireSameRegularFile(destination, part)
      published.push(part)
    }
    for (const part of ownedParts) await unlink(part.path)
    for (const part of published) await requirePublishedRegularFile(resolve(directory, part.entry.name))
  } catch (error) {
    for (const part of published.reverse()) {
      await unlinkIfSameRegularFile(resolve(directory, part.entry.name), part)
    }
    for (const part of ownedParts) await unlinkIfSameRegularFile(part.path, part)
    throw error
  }
}

function publicationEntries(result: ProposalRunnerResult): PublicationEntry[] {
  const resultBytes = Buffer.from(`${JSON.stringify({ ...result, patch: undefined }, null, 2)}\n`)
  if (result.status !== 'proposed') return [{ name: 'result.json', bytes: resultBytes }]
  return [
    { name: 'proposal.patch', bytes: result.patch },
    { name: 'manifest.json', bytes: Buffer.from(`${JSON.stringify(result.artifact, null, 2)}\n`) },
    { name: 'result.json', bytes: resultBytes },
  ]
}

async function requireAbsent(path: string, name: string): Promise<void> {
  try {
    await lstat(path)
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') return
    throw error
  }
  throw new Error(`reserved runner output already exists: ${name}`)
}

async function requireSameRegularFile(path: string, owned: OwnedPart): Promise<void> {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || metadata.dev !== owned.device || metadata.ino !== owned.inode) {
    throw new Error(`runner ${owned.entry.name} publication identity changed`)
  }
}

async function requirePublishedRegularFile(path: string): Promise<void> {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o777) !== 0o600) {
    throw new Error('runner output publication is not a private regular file')
  }
}

async function unlinkIfSameRegularFile(path: string, owned: OwnedPart): Promise<void> {
  try {
    const metadata = await lstat(path)
    if (metadata.isFile() && !metadata.isSymbolicLink()
      && metadata.dev === owned.device && metadata.ino === owned.inode) {
      await unlink(path)
    }
  } catch (error) {
    if (!(isNodeError(error) && error.code === 'ENOENT')) throw error
  }
}

function collisionError(name: string, cause: unknown): Error {
  const error = new Error(`reserved runner output collision: ${name}`)
  error.cause = cause
  return error
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error
}
