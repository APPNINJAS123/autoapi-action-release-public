#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, readFile, readlink, readdir, symlink, writeFile } from 'node:fs/promises'
import { resolve, sep } from 'node:path'

const [, , operation, rootArgument, tree, manifestPath] = process.argv
if (!['capture', 'materialize', 'verify'].includes(operation)
  || !rootArgument || !/^[a-f0-9]{40}$/u.test(tree ?? '') || !manifestPath) {
  throw new Error('usage: verify-exact-worktree.mjs capture|materialize|verify ROOT TREE MANIFEST')
}

const root = resolve(rootArgument)

if (operation === 'capture') {
  const manifest = await expectedManifest('complete-workspace')
  const observed = await scanCompleteWorkspace()
  if (JSON.stringify(observed) !== JSON.stringify(manifest.entries)) {
    throw new Error('workspace does not exactly materialize the expected raw Git tree')
  }
  await writeManifest(manifest)
} else if (operation === 'materialize') {
  const { entries, directories } = readTree()
  const rootEntries = await readdir(root)
  if (rootEntries.length !== 1 || rootEntries[0] !== '.git') {
    throw new Error('exact worktree materialization requires an empty no-checkout clone')
  }
  const expectedStates = new Map()
  for (const entry of entries) expectedStates.set(entry.path, await materialize(entry))
  git(['read-tree', tree])
  const manifestEntries = []
  for (const entry of entries) {
    const expectedState = expectedStates.get(entry.path)
    const state = await rawState(root, entry.path)
    if (JSON.stringify(state) !== JSON.stringify(expectedState)) {
      throw new Error(`materialized bytes do not match git object: ${entry.path}`)
    }
    manifestEntries.push({
      path: entry.path,
      gitMode: entry.gitMode,
      gitType: entry.gitType,
      objectId: entry.objectId,
      state: expectedState,
    })
  }
  const manifestDirectories = []
  for (const path of directories) {
    const expectedState = { kind: 'directory' }
    if (JSON.stringify(await rawState(root, path)) !== JSON.stringify(expectedState)) {
      throw new Error(`materialized directory does not match git tree: ${path}`)
    }
    manifestDirectories.push({ path, state: expectedState })
  }
  const manifest = {
    schemaVersion: 'autoapi-exact-worktree-v2',
    scope: 'tracked-tree',
    tree,
    directories: manifestDirectories,
    entries: manifestEntries,
  }
  await writeManifest(manifest)
} else {
  const parsed = JSON.parse(await readFile(manifestPath, 'utf8'))
  if (parsed?.schemaVersion !== 'autoapi-exact-worktree-v2' || parsed.tree !== tree
    || !['complete-workspace', 'tracked-tree'].includes(parsed.scope)
    || !Array.isArray(parsed.entries)
    || (parsed.scope === 'tracked-tree' && !Array.isArray(parsed.directories))) {
    throw new Error('invalid exact-worktree manifest')
  }
  // A manifest is a durable receipt, not authority to redefine the fixed Git
  // tree. Rebuild its complete canonical inventory and raw blob states from
  // that tree before trusting any saved path or digest. This keeps a replaced
  // manifest from hiding a path that was removed or rewritten with it.
  const expected = await expectedManifest(parsed.scope)
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) {
    throw new Error('exact-worktree manifest does not match the expected raw Git tree')
  }
  if (parsed.scope === 'complete-workspace') {
    const observed = await scanCompleteWorkspace()
    if (JSON.stringify(observed) !== JSON.stringify(expected.entries)) {
      throw new Error('workspace bytes or path inventory changed before proposal execution')
    }
  } else for (const item of [...expected.directories, ...expected.entries]) {
    const observed = await rawState(root, item.path)
    if (JSON.stringify(observed) !== JSON.stringify(item.state)) {
      throw new Error(`tracked worktree bytes changed during offline certification: ${item.path}`)
    }
  }
}

async function expectedManifest(scope) {
  const { entries, directories } = readTree()
  const states = expectedTreeStates(entries)
  if (scope === 'complete-workspace') {
    const expected = []
    for (const path of directories) expected.push({ path, state: { kind: 'directory' } })
    for (const entry of entries) {
      expected.push({ path: entry.path, state: states.get(entry.path) })
    }
    expected.sort(comparePathState)
    return {
      schemaVersion: 'autoapi-exact-worktree-v2',
      scope,
      tree,
      entries: expected,
    }
  }
  return {
    schemaVersion: 'autoapi-exact-worktree-v2',
    scope,
    tree,
    directories: directories.map(path => ({ path, state: { kind: 'directory' } })),
    entries: entries.map(entry => ({
      path: entry.path,
      gitMode: entry.gitMode,
      gitType: entry.gitType,
      objectId: entry.objectId,
      state: states.get(entry.path),
    })),
  }
}

async function writeManifest(manifest) {
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`, { flag: 'wx', mode: 0o400 })
}

function readTree() {
  const output = git(['ls-tree', '-lrz', '--full-tree', tree])
  const entries = []
  const directories = new Set()
  for (const record of splitNul(output)) {
    const tab = record.indexOf(0x09)
    if (tab <= 0) throw new Error('invalid git tree record')
    const header = record.subarray(0, tab).toString('ascii')
    const match = /^(100644|100755|120000|160000) (blob|commit) ([a-f0-9]{40}) +([0-9]+|-)$/u.exec(header)
    if (match === null) throw new Error(`unsupported git tree entry: ${header}`)
    const objectBytes = match[4] === '-' ? undefined : Number(match[4])
    if (match[2] === 'blob' && (!Number.isSafeInteger(objectBytes) || objectBytes < 0)) {
      throw new Error('invalid git blob size')
    }
    if (match[2] === 'commit' && objectBytes !== undefined) throw new Error('invalid gitlink size')
    const path = decodePath(record.subarray(tab + 1))
    for (const parent of parentPaths(path)) directories.add(parent)
    entries.push({
      path, gitMode: match[1], gitType: match[2], objectId: match[3], objectBytes,
    })
  }
  return { entries, directories: [...directories].sort() }
}

function expectedTreeStates(entries) {
  const states = new Map()
  const blobs = entries.filter(entry => entry.gitType === 'blob')
  for (const entry of entries) {
    if (entry.gitType === 'commit') states.set(entry.path, { kind: 'directory' })
  }
  // Bound each invocation so a repository with many ordinary blobs is fast
  // without turning its full contents into one unbounded child-process buffer.
  const batches = []
  let batch = []
  let bytes = 0
  for (const entry of blobs) {
    if (batch.length > 0 && (batch.length === 4096 || bytes + entry.objectBytes > 64 * 1024 * 1024)) {
      batches.push(batch)
      batch = []
      bytes = 0
    }
    batch.push(entry)
    bytes += entry.objectBytes
  }
  if (batch.length > 0) batches.push(batch)

  for (const entriesInBatch of batches) {
    const input = Buffer.from(`${entriesInBatch.map(entry => entry.objectId).join('\n')}\n`, 'ascii')
    const output = git(['cat-file', '--batch'], input)
    let offset = 0
    for (const entry of entriesInBatch) {
      const headerEnd = output.indexOf(0x0a, offset)
      if (headerEnd < offset) throw new Error('invalid git cat-file batch header')
      const header = output.subarray(offset, headerEnd).toString('ascii')
      const match = /^([a-f0-9]{40}) blob ([0-9]+)$/u.exec(header)
      if (match === null || match[1] !== entry.objectId || Number(match[2]) !== entry.objectBytes) {
        throw new Error(`raw blob batch metadata does not match expected object: ${entry.path}`)
      }
      const contentStart = headerEnd + 1
      const contentEnd = contentStart + entry.objectBytes
      if (contentEnd >= output.length || output[contentEnd] !== 0x0a) {
        throw new Error(`invalid raw blob batch boundary: ${entry.path}`)
      }
      const content = output.subarray(contentStart, contentEnd)
      if (gitBlobObjectId(content) !== entry.objectId) {
        throw new Error(`raw blob bytes do not match expected object: ${entry.path}`)
      }
      states.set(entry.path, treeState(entry, content))
      offset = contentEnd + 1
    }
    if (offset !== output.length) throw new Error('unexpected trailing git cat-file batch output')
  }
  return states
}

async function expectedTreeState(entry) {
  if (entry.gitType === 'commit') return { kind: 'directory' }
  const content = git(['cat-file', 'blob', entry.objectId])
  if (gitBlobObjectId(content) !== entry.objectId) {
    throw new Error(`raw blob bytes do not match expected object: ${entry.path}`)
  }
  return treeState(entry, content)
}

function treeState(entry, content) {
  if (entry.gitMode === '120000') {
    return { kind: 'symlink', bytes: content.length, sha256: sha256(content) }
  }
  return {
    kind: 'file', bytes: content.length, executable: entry.gitMode === '100755',
    sha256: sha256(content),
  }
}

function comparePathState(left, right) {
  return left.path < right.path ? -1 : left.path > right.path ? 1 : 0
}

async function scanCompleteWorkspace() {
  const entries = []
  async function visit(directory = '') {
    const names = await readdir(resolve(root, directory))
    names.sort()
    for (const name of names) {
      // Repository internals are deliberately outside this check. They are
      // mutable Git implementation state and, crucially, this verifier never
      // consults them when deciding whether customer bytes stayed unchanged.
      if (directory === '' && name === '.git') continue
      const path = safePath(directory === '' ? name : `${directory}/${name}`)
      const state = await rawState(root, path)
      entries.push({ path, state })
      if (state.kind === 'directory') await visit(path)
    }
  }
  await visit()
  return entries.sort(comparePathState)
}

async function materialize(entry) {
  const absolute = resolve(root, safePath(entry.path))
  await mkdir(resolve(absolute, '..'), { recursive: true })
  if (entry.gitType === 'commit') {
    await mkdir(absolute)
    return { kind: 'directory' }
  }
  const content = git(['cat-file', 'blob', entry.objectId])
  if (gitBlobObjectId(content) !== entry.objectId) {
    throw new Error(`raw blob bytes do not match expected object: ${entry.path}`)
  }
  if (entry.gitMode === '120000') {
    await symlink(content, absolute)
    return { kind: 'symlink', bytes: content.length, sha256: sha256(content) }
  }
  await writeFile(absolute, content, { flag: 'wx', mode: entry.gitMode === '100755' ? 0o755 : 0o644 })
  await chmod(absolute, entry.gitMode === '100755' ? 0o755 : 0o644)
  return {
    kind: 'file', bytes: content.length, executable: entry.gitMode === '100755',
    sha256: sha256(content),
  }
}

function git(arguments_, input = undefined) {
  return execFileSync('/usr/bin/git', [
    `--git-dir=${resolve(root, '.git')}`,
    `--work-tree=${root}`,
    ...arguments_,
  ], {
    encoding: 'buffer',
    input,
    env: {
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_NO_REPLACE_OBJECTS: '1',
      PATH: '/usr/bin:/bin',
    },
    maxBuffer: 256 * 1024 * 1024,
  })
}

function splitNul(buffer) {
  const records = []
  let start = 0
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] !== 0) continue
    if (index > start) records.push(buffer.subarray(start, index))
    start = index + 1
  }
  if (start !== buffer.length) throw new Error('unterminated git tree output')
  return records
}

function decodePath(buffer) {
  const path = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
  if (!Buffer.from(path, 'utf8').equals(buffer)) throw new Error('non-canonical UTF-8 repository path')
  return safePath(path)
}

function safePath(path) {
  if (path === '' || path.startsWith('/') || path.includes('\\')
    || path.split('/').some(component => component === '' || component === '.' || component === '..')) {
    throw new Error('unsafe repository path')
  }
  const absolute = resolve(root, path)
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) throw new Error('repository path escaped root')
  return path
}

function parentPaths(path) {
  const components = path.split('/')
  const parents = []
  for (let index = 1; index < components.length; index += 1) {
    parents.push(components.slice(0, index).join('/'))
  }
  return parents
}

async function rawState(base, path) {
  const absolute = resolve(base, safePath(path))
  let stats
  try {
    stats = await lstat(absolute)
  } catch (error) {
    if (error?.code === 'ENOENT') return { kind: 'missing' }
    throw error
  }
  if (stats.isDirectory()) return { kind: 'directory' }
  if (stats.isSymbolicLink()) {
    const target = await readlink(absolute, { encoding: 'buffer' })
    return { kind: 'symlink', bytes: target.length, sha256: sha256(target) }
  }
  if (stats.isFile()) {
    let descriptor
    try {
      descriptor = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
      const opened = await descriptor.stat()
      if (!opened.isFile() || opened.dev !== stats.dev || opened.ino !== stats.ino) {
        throw new Error(`tracked worktree node changed while being inspected: ${path}`)
      }
      const content = await descriptor.readFile()
      return {
        kind: 'file',
        bytes: content.length,
        executable: (opened.mode & 0o111) !== 0,
        sha256: sha256(content),
      }
    } finally {
      await descriptor?.close()
    }
  }
  throw new Error(`unsupported tracked worktree node: ${path}`)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function gitBlobObjectId(value) {
  const header = Buffer.from(`blob ${value.length}\0`, 'ascii')
  return createHash('sha1').update(header).update(value).digest('hex')
}
