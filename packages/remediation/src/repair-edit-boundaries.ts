import { createHash } from 'node:crypto'
import type { HarnessRepairEditBoundary, RepositoryImpact } from '@automated-api/contracts'

type LineRange = { start: number; end: number }
type SourceFile = { path: string; content: string }
export type PreservedAffectedUsageWindow = { path: string; start: number; end: number }
const repairBoundaries = Symbol('runner-derived exact repair boundaries')
type BoundImpact = RepositoryImpact & {
  [repairBoundaries]?: ReadonlyMap<string, { content: string; ranges: LineRange[] }>
}

/** Carry exact, hash-bound repair authority through internal impact projections.
 * The symbol survives object spreads but is never serialized as impact evidence.
 * The explicit request field is bound again after every transport boundary.
 */
export function bindHarnessRepairEditBoundaries(
  impact: RepositoryImpact,
  files: readonly SourceFile[],
  boundaries: readonly HarnessRepairEditBoundary[] | undefined,
): RepositoryImpact {
  if (boundaries === undefined || boundaries.length === 0) return impact
  const byPath = new Map(files.map(file => [file.path, file]))
  const bound = new Map<string, { content: string; ranges: LineRange[] }>()
  for (const boundary of boundaries) {
    const file = byPath.get(boundary.path)
    if (file === undefined || createHash('sha256').update(file.content).digest('hex') !== boundary.expectedHash) {
      throw new Error(`repair edit boundary has an unknown or stale source: ${boundary.path}`)
    }
    if (bound.has(boundary.path)) throw new Error(`duplicate repair edit boundary: ${boundary.path}`)
    assertOrderedRanges(boundary.ranges, file.content.split('\n').length)
    bound.set(boundary.path, { content: file.content, ranges: boundary.ranges.map(range => ({ ...range })) })
  }
  return { ...impact, [repairBoundaries]: bound } as BoundImpact
}

export function harnessRepairEditRanges(
  impact: RepositoryImpact,
  path: string,
  content: string,
): LineRange[] | undefined {
  const boundary = (impact as BoundImpact)[repairBoundaries]?.get(path)
  if (boundary === undefined) return undefined
  // Internal operation groups may already have applied another validated edit.
  // Re-pin protected runs instead of reusing its now-stale line numbers.
  return mapProtectedEditRanges(boundary.content, content, boundary.ranges)
}

/** Add only already-certified source windows to a hash-bound repair scope.
 *
 * The persisted boundary describes authority in the migrated file while the
 * certified usage windows describe the original checkout. Mapping the
 * persisted authority backwards first proves that every historical change was
 * inside that authority. Mapping their union forwards then preserves both
 * grants without adding a file, a diagnostic, or context padding.
 */
export function preserveHarnessAffectedUsageWindows(
  originalFiles: readonly SourceFile[],
  previousEdits: ReadonlyArray<SourceFile & { expectedHash: string }>,
  validatedBoundaries: readonly HarnessRepairEditBoundary[],
  certifiedWindows: readonly PreservedAffectedUsageWindow[],
): HarnessRepairEditBoundary[] {
  const originals = new Map(originalFiles.map(file => [file.path, file]))
  const edits = new Map(previousEdits.map(edit => [edit.path, edit]))
  if (originals.size !== originalFiles.length || edits.size !== previousEdits.length
    || certifiedWindows.length > 10_000) {
    throw new Error('certified repair scope input exceeds its bounded source inventory')
  }
  const windows = new Map<string, LineRange[]>()
  const scopedPaths = new Set(validatedBoundaries.map(boundary => boundary.path))
  if (scopedPaths.size !== validatedBoundaries.length) {
    throw new Error('certified repair scope contains duplicate source paths')
  }
  for (const window of certifiedWindows) {
    // Certified evidence for an affected but unchanged file cannot make that
    // file part of a cumulative repair. The production caller pre-filters to
    // persisted reviewed paths, so any other path at this boundary is stale
    // or internally inconsistent and must fail closed rather than disappear.
    if (!scopedPaths.has(window.path) || !originals.has(window.path) || !edits.has(window.path)) {
      throw new Error(`certified affected usage window has an unknown source: ${window.path}`)
    }
    if (!Number.isSafeInteger(window.start) || !Number.isSafeInteger(window.end)
      || window.start < 1 || window.end < window.start) {
      throw new Error('certified affected usage window is invalid')
    }
    if (window.end > originals.get(window.path)!.content.split('\n').length) {
      throw new Error(`certified affected usage window exceeds its source: ${window.path}`)
    }
    windows.set(window.path, [...(windows.get(window.path) ?? []), {
      start: window.start,
      end: window.end,
    }])
  }
  return validatedBoundaries.map(boundary => {
    const original = originals.get(boundary.path)
    const edit = edits.get(boundary.path)
    if (original === undefined || edit === undefined
      || edit.expectedHash !== createHash('sha256').update(original.content).digest('hex')
      || boundary.expectedHash !== createHash('sha256').update(edit.content).digest('hex')) {
      throw new Error(`certified repair scope has an unknown or stale source: ${boundary.path}`)
    }
    const selected = windows.get(boundary.path) ?? []
    if (selected.length === 0) return { ...boundary, ranges: boundary.ranges.map(range => ({ ...range })) }

    // The reverse projection recovers the original coordinates of diagnostic
    // or prior-attempt authority without trusting stale original line numbers.
    const historicalOriginal = mapProtectedEditRanges(
      edit.content,
      original.content,
      boundary.ranges,
    )
    const originalAuthority = mergeRanges([...historicalOriginal, ...selected])
    const certifiedCurrent = mapProtectedEditRanges(
      original.content,
      edit.content,
      originalAuthority,
    )
    return {
      path: boundary.path,
      expectedHash: boundary.expectedHash,
      ranges: mergeRanges([...boundary.ranges, ...certifiedCurrent]),
    }
  })
}

/** Map entire authorized windows, never individual anchors followed by padding.
 * Every protected run must retain its exact lines in an ordered layout. When
 * repeated protected lines permit several layouts, only their intersection is
 * editable; ambiguous gaps gain no authority. Changed protected lines and
 * unauthorized edge insertions fail closed.
 */
export function mapProtectedEditRanges(before: string, after: string, ranges: readonly LineRange[]): LineRange[] {
  const original = before.split('\n')
  const current = after.split('\n')
  assertOrderedRanges(ranges, original.length)
  if (before === after) return ranges.map(range => ({ ...range }))
  const protectedRuns: Array<{ start: number; end: number; lines: string[] }> = []
  let cursor = 1
  for (const range of ranges) {
    if (cursor < range.start) protectedRuns.push({ start: cursor, end: range.start - 1,
      lines: original.slice(cursor - 1, range.start - 1) })
    cursor = range.end + 1
  }
  if (cursor <= original.length) protectedRuns.push({ start: cursor, end: original.length,
    lines: original.slice(cursor - 1) })
  if (protectedRuns.length === 0) return [{ start: 1, end: current.length }]
  let comparisons = 0
  const occurrences = protectedRuns.map(run => {
    const matches: number[] = []
    for (let start = 0; start + run.lines.length <= current.length; start += 1) {
      if (run.start === 1 && start !== 0) continue
      if (run.end === original.length && start + run.lines.length !== current.length) continue
      let same = true
      for (let offset = 0; offset < run.lines.length; offset += 1) {
        if (++comparisons > 2_000_000) throw new Error('repair boundary alignment exceeds its bounded comparison budget')
        if (current[start + offset] !== run.lines[offset]) { same = false; break }
      }
      if (same) matches.push(start)
    }
    if (matches.length === 0) throw new Error('previous repair changed a protected source interval')
    return matches
  })
  const earliest: number[] = []
  let minimum = 0
  for (const [index, matches] of occurrences.entries()) {
    const match = matches.find(start => start >= minimum)
    if (match === undefined) throw new Error('previous repair reordered protected source intervals')
    earliest.push(match)
    minimum = match + protectedRuns[index]!.lines.length
  }
  let maximum = current.length
  const latest: number[] = []
  for (let index = occurrences.length - 1; index >= 0; index -= 1) {
    const length = protectedRuns[index]!.lines.length
    const match = [...occurrences[index]!].reverse().find(start => start + length <= maximum)
    if (match === undefined) throw new Error('previous repair reordered protected source intervals')
    latest[index] = match
    maximum = match
  }
  return ranges.flatMap(range => {
    const preceding = protectedRuns.findIndex(run => run.end === range.start - 1)
    const following = protectedRuns.findIndex(run => run.start === range.end + 1)
    // Greedy earliest/latest are the extrema over all feasible ordered layouts.
    // An editable gap must start after every possible preceding run and end
    // before every possible following run. Never choose one ambiguous layout.
    const start = preceding < 0 ? 1 : latest[preceding]! + protectedRuns[preceding]!.lines.length + 1
    const end = following < 0 ? current.length : earliest[following]!
    return start <= end ? [{ start, end }] : []
  })
}

function assertOrderedRanges(ranges: readonly LineRange[], lineCount: number): void {
  let previousEnd = 0
  for (const range of ranges) {
    if (!Number.isSafeInteger(range.start) || !Number.isSafeInteger(range.end)
      || range.start <= previousEnd || (previousEnd > 0 && range.start === previousEnd + 1)
      || range.end < range.start || range.end > lineCount) {
      throw new Error('repair edit boundaries must be ordered, non-overlapping source line ranges')
    }
    previousEnd = range.end
  }
}

function mergeRanges(ranges: readonly LineRange[]): LineRange[] {
  return [...ranges].sort((left, right) => left.start - right.start || left.end - right.end)
    .reduce<LineRange[]>((merged, range) => {
      const previous = merged.at(-1)
      if (previous === undefined || range.start > previous.end + 1) merged.push({ ...range })
      else previous.end = Math.max(previous.end, range.end)
      return merged
    }, [])
}
