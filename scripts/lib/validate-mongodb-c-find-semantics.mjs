#!/usr/bin/env node
import { readFile } from 'node:fs/promises'

const [sourcePath, ...rawCounts] = process.argv.slice(2)
if (sourcePath === undefined || rawCounts.length !== 6) {
  console.error('usage: validate-mongodb-c-find-semantics <source> <calls> <projections> <skips> <limits> <batch-sizes> <non-null-read-prefs>')
  process.exit(2)
}
const counts = rawCounts.map(value => {
  if (!/^\d+$/u.test(value)) throw new Error(`invalid expected count: ${value}`)
  return Number(value)
})
const [expectedCalls, expectedProjections, expectedSkips, expectedLimits,
  expectedBatchSizes, expectedReadPreferences] = counts
const source = await readFile(sourcePath, 'utf8')
const calls = cFunctionCalls(source, 'mongoc_collection_find_with_opts')
if (calls.length !== expectedCalls) {
  throw new Error(`expected ${expectedCalls} mongoc_collection_find_with_opts calls; found ${calls.length}`)
}

const actual = { projection: 0, skip: 0, limit: 0, batchSize: 0, readPreferences: 0 }
for (const [index, call] of calls.entries()) {
  if (call.args.length !== 4) {
    throw new Error(`mongoc_collection_find_with_opts call at line ${call.line} must have four arguments`)
  }
  const opts = identifier(call.args[2])
  if (opts === undefined || isNull(call.args[2])) {
    throw new Error(`mongoc_collection_find_with_opts call at line ${call.line} must pass a BSON opts document`)
  }
  const previousEnd = calls[index - 1]?.end ?? 0
  const context = source.slice(Math.max(previousEnd, call.start - 4_000), call.start)
  if (!new RegExp(`\\bbson_t\\s+\\*?\\s*${escapeRegExp(opts)}\\b`, 'u').test(context)
    || !new RegExp(`\\bbson_init\\s*\\(\\s*&\\s*${escapeRegExp(opts)}\\s*\\)`, 'u').test(context)) {
    throw new Error(`mongoc_collection_find_with_opts call at line ${call.line} uses an uninitialized BSON opts document`)
  }
  for (const key of ['projection', 'skip', 'limit', 'batchSize']) {
    if (hasBsonOption(context, opts, key)) actual[key] += 1
  }
  if (!isNull(call.args[3])) actual.readPreferences += 1
}

for (const [name, expected, observed] of [
  ['projections', expectedProjections, actual.projection],
  ['skips', expectedSkips, actual.skip],
  ['limits', expectedLimits, actual.limit],
  ['batch sizes', expectedBatchSizes, actual.batchSize],
  ['non-null read preferences', expectedReadPreferences, actual.readPreferences],
]) {
  if (observed !== expected) throw new Error(`expected ${expected} preserved ${name}; found ${observed}`)
}

function cFunctionCalls(content, symbol) {
  const sanitized = stripCommentsAndLiterals(content)
  const pattern = new RegExp(`\\b${escapeRegExp(symbol)}\\s*\\(`, 'gu')
  return [...sanitized.matchAll(pattern)].map(match => {
    const start = match.index
    const open = start + match[0].lastIndexOf('(')
    let depth = 1
    let cursor = open + 1
    const separators = []
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
    return { start, end: cursor, line: lineOf(content, start), args }
  })
}

function stripCommentsAndLiterals(value) {
  return value.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/gu,
    match => match.replace(/[^\n]/gu, ' '),
  )
}

function hasBsonOption(context, opts, key) {
  return new RegExp(
    `\\bBSON_APPEND_(?:DOCUMENT|DOCUMENT_BEGIN|INT32|INT64|DOUBLE)\\s*\\(`
    + `\\s*&?\\s*${escapeRegExp(opts)}\\s*,\\s*"${escapeRegExp(key)}"`,
    'u',
  ).test(context)
}

function identifier(value) {
  return /^&?([A-Za-z_]\w*)$/u.exec(value.replace(/\s+/gu, ''))?.[1]
}

function isNull(value) {
  return /^(?:NULL|nullptr|0)$/u.test(value.replace(/\s+/gu, ''))
}

function lineOf(value, index) {
  return value.slice(0, index).split('\n').length
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}
