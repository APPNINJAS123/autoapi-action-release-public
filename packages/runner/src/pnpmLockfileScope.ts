import { isDeepStrictEqual } from 'node:util'
import { parse } from 'yaml'

const IMPORTER_DEPENDENCY_FIELDS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
] as const

export function collateralPnpmLockfileChanges(
  beforeSource: string,
  afterSource: string,
  importer: string,
  allowedPackages: readonly string[],
): string[] {
  const before = asRecord(parse(beforeSource), 'pnpm lockfile')
  const after = asRecord(parse(afterSource), 'pnpm lockfile')
  const findings: string[] = []

  for (const key of changedKeys(recordAt(before, 'importers'), recordAt(after, 'importers'))) {
    if (key !== importer) {
      findings.push(`importer:${key}`)
      continue
    }
    const beforeImporter = withoutAllowedImporterDependencies(
      recordAt(recordAt(before, 'importers'), key),
      allowedPackages,
    )
    const afterImporter = withoutAllowedImporterDependencies(
      recordAt(recordAt(after, 'importers'), key),
      allowedPackages,
    )
    if (!isDeepStrictEqual(beforeImporter, afterImporter)) findings.push(`importer:${key}`)
  }

  for (const section of ['packages', 'snapshots'] as const) {
    for (const key of changedKeys(recordAt(before, section), recordAt(after, section))) {
      if (!allowedPackages.some(name => key === name || key.startsWith(`${name}@`))) {
        findings.push(`${section}:${key}`)
      }
    }
  }

  const structuralBefore = { ...before }
  const structuralAfter = { ...after }
  for (const key of ['importers', 'packages', 'snapshots']) {
    delete structuralBefore[key]
    delete structuralAfter[key]
  }
  if (!isDeepStrictEqual(structuralBefore, structuralAfter)) findings.push('lockfile:metadata')
  return findings.slice(0, 20)
}

export function minimizePnpmLockfileChange(
  beforeSource: string,
  afterSource: string,
  importer: string,
  allowedPackages: readonly string[],
): string {
  let minimized = afterSource
  for (const section of ['packages', 'snapshots'] as const) {
    minimized = restoreUnrelatedSectionEntries(
      beforeSource,
      minimized,
      section,
      allowedPackages,
    )
  }
  const remaining = collateralPnpmLockfileChanges(
    beforeSource,
    minimized,
    importer,
    allowedPackages,
  )
  if (remaining.length > 0) {
    throw new Error(`pnpm changed unrelated lockfile entries: ${remaining.join(', ')}`)
  }
  return minimized
}

interface TextSection {
  start: number
  end: number
  prefix: string
  entries: Map<string, string>
}

function restoreUnrelatedSectionEntries(
  beforeSource: string,
  afterSource: string,
  sectionName: 'packages' | 'snapshots',
  allowedPackages: readonly string[],
): string {
  const before = textSection(beforeSource, sectionName)
  const after = textSection(afterSource, sectionName)
  const desired = new Map(after.entries)
  for (const key of changedKeys(
    recordAt(asRecord(parse(beforeSource), 'pnpm lockfile'), sectionName),
    recordAt(asRecord(parse(afterSource), 'pnpm lockfile'), sectionName),
  )) {
    if (allowedPackages.some(name => key === name || key.startsWith(`${name}@`))) continue
    const original = before.entries.get(key)
    if (original === undefined) desired.delete(key)
    else desired.set(key, original)
  }
  const body = [
    after.prefix,
    ...[...desired.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([, block]) => block),
  ].join('')
  return `${afterSource.slice(0, after.start)}${body}${afterSource.slice(after.end)}`
}

function textSection(source: string, name: string): TextSection {
  const sectionPattern = new RegExp(`^${name}:\\r?\\n`, 'mu')
  const match = sectionPattern.exec(source)
  if (match === null) throw new Error(`pnpm lockfile is missing ${name}`)
  const start = match.index + match[0].length
  const nextSection = /^[^\s#][^\r\n]*:\r?$/gmu
  nextSection.lastIndex = start
  const next = nextSection.exec(source)
  const end = next?.index ?? source.length
  const body = source.slice(start, end)
  const entryPattern = /^  \S[^\r\n]*\r?$/gmu
  const matches = [...body.matchAll(entryPattern)]
  const entries = new Map<string, string>()
  for (const [index, entry] of matches.entries()) {
    const line = entry[0]
    const parsed = asRecord(parse(`${line.trim()}\n`), `${name} entry`)
    const key = Object.keys(parsed)[0]
    if (key === undefined) throw new Error(`pnpm ${name} entry has no key`)
    const blockStart = entry.index
    const blockEnd = matches[index + 1]?.index ?? body.length
    entries.set(key, body.slice(blockStart, blockEnd))
  }
  const firstEntry = matches[0]?.index ?? body.length
  return { start, end, prefix: body.slice(0, firstEntry), entries }
}

function withoutAllowedImporterDependencies(
  input: Record<string, unknown>,
  allowedPackages: readonly string[],
): Record<string, unknown> {
  const result = structuredClone(input)
  for (const field of IMPORTER_DEPENDENCY_FIELDS) {
    const dependencies = result[field]
    if (!isRecord(dependencies)) continue
    for (const name of allowedPackages) delete dependencies[name]
  }
  return result
}

function changedKeys(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter(key => !isDeepStrictEqual(before[key], after[key]))
    .sort()
}

function recordAt(record: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = record[key]
  return value === undefined ? {} : asRecord(value, key)
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must contain a mapping`)
  return value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
