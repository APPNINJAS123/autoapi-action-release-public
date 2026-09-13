import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { lstat, readFile, readdir, rm } from 'node:fs/promises'
import path from 'node:path'

const MAX_FILES = 256
const MAX_BYTES = 16 * 1024 * 1024
const MANIFEST_NAME = '.autoapi-action-export-manifest.json'
const [rootInput, manifestInput] = process.argv.slice(2)
if (rootInput === undefined || manifestInput === undefined) {
  throw new Error('usage: import-action-export <root> <manifest>')
}

const root = path.resolve(rootInput)
const manifestPath = path.resolve(manifestInput)
if (manifestPath !== path.join(root, MANIFEST_NAME)) {
  throw new Error('Action export manifest must be the bound archive manifest')
}
const rootMetadata = await lstat(root)
if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
  throw new Error('Action export root must be a non-symlink directory')
}
const manifestMetadata = await lstat(manifestPath)
if (!manifestMetadata.isFile() || manifestMetadata.isSymbolicLink() || manifestMetadata.nlink !== 1) {
  throw new Error('Action export archive manifest must be one regular file')
}
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
assertManifest(manifest)
await assertTree(root, manifest, true)
await rm(manifestPath)
await assertTree(root, manifest, false)

function assertManifest(value) {
  if (value?.schemaVersion !== '1.0' || !Array.isArray(value.files)) {
    throw new Error('Invalid Action export manifest')
  }
  if (value.files.length === 0 || value.files.length > MAX_FILES || value.totalFiles !== value.files.length) {
    throw new Error('Action export manifest file count exceeds its bound')
  }
  const paths = new Set()
  let totalBytes = 0
  let previousPath
  for (const file of value.files) {
    if (typeof file?.path !== 'string'
      || file.path.length === 0
      || file.path.includes('\\')
      || path.posix.isAbsolute(file.path)
      || path.posix.normalize(file.path) !== file.path
      || file.path.split('/').some(component => component === '' || component === '.' || component === '..')
      || !Number.isSafeInteger(file.bytes)
      || file.bytes < 0
      || !/^[a-f0-9]{64}$/u.test(file.sha256)
      || paths.has(file.path)
      || (previousPath !== undefined && previousPath.localeCompare(file.path) >= 0)) {
      throw new Error('Invalid Action export manifest entry')
    }
    paths.add(file.path)
    totalBytes += file.bytes
    previousPath = file.path
  }
  if (!Number.isSafeInteger(value.totalBytes)
    || value.totalBytes !== totalBytes
    || value.totalBytes > MAX_BYTES) {
    throw new Error('Action export manifest bytes exceed its bound')
  }
}

async function assertTree(directory, expected, allowManifest) {
  const actual = []
  const pending = [directory]
  while (pending.length > 0) {
    const current = pending.pop()
    for (const name of (await readdir(current)).sort().reverse()) {
      const item = path.join(current, name)
      const relative = path.relative(directory, item).split(path.sep).join('/')
      if (allowManifest && relative === MANIFEST_NAME) continue
      const metadata = await lstat(item)
      if (metadata.isSymbolicLink()) throw new Error('Action export must not contain symbolic links')
      if (metadata.isDirectory()) {
        pending.push(item)
      } else if (metadata.isFile() && metadata.nlink === 1) {
        actual.push({
          path: relative,
          bytes: metadata.size,
          sha256: await sha256File(item),
        })
        if (actual.length > MAX_FILES) throw new Error('Action export file count exceeds its bound')
      } else {
        throw new Error('Action export must contain only independent regular files and directories')
      }
    }
  }
  actual.sort((left, right) => left.path.localeCompare(right.path))
  if (JSON.stringify(actual) !== JSON.stringify(expected.files)) {
    throw new Error('Action export tree does not match its content manifest')
  }
}

async function sha256File(filePath) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(filePath)) hash.update(chunk)
  return hash.digest('hex')
}
