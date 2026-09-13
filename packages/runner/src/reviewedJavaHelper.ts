import { readFile } from 'node:fs/promises'
import type { ImpactEvidence, MigrationJob } from '@automated-api/contracts'
import { resolveExistingPathInsideRepository, sha256 } from '@automated-api/remediation'
import { reviewedDdTraceJavaHelper } from './repositoryEventBindings.js'

interface ReviewedJavaHelper {
  sourcePath: string
  insertionAnchor: string
  requiredDeclaration: string
  preservedPrefix: string
  preservedSuffix: string
}

const REVIEWED_CALL_ID_HELPER = [
  '  public static String getCallIdAsString(ResponseInputItem.FunctionCallOutput functionCallOutput) {',
  '    try {',
  '      Object callId = METHOD_HANDLES.invoke(',
  '          METHOD_HANDLES.method(FUNCTION_CALL_OUTPUT_CLASS, "callId"), functionCallOutput);',
  '      if (callId instanceof java.util.Optional) {',
  '        callId = ((java.util.Optional<?>) callId).orElse(null);',
  '      }',
  '      return callId instanceof String ? (String) callId : null;',
  '    } catch (Throwable t) {',
  '      log.debug("Error extracting call ID from FunctionCallOutput", t);',
  '      return null;',
  '    }',
  '  }',
  '',
].join('\n') + '\n'

export async function prepareReviewedDdTraceJavaHelper(
  job: MigrationJob,
  rootDir: string,
): Promise<ReviewedJavaHelper | undefined> {
  const plan = reviewedDdTraceJavaHelper(job)
  if (plan === undefined) return undefined
  const baseline = await readFile(
    await resolveExistingPathInsideRepository(rootDir, plan.sourcePath), 'utf8',
  )
  if (sha256(baseline) !== plan.baselineSha256) {
    throw new Error('reviewed Java helper baseline does not match its whole-file hash')
  }
  const anchor = uniqueDeclarationOffset(baseline, plan.insertionAnchor)
  return {
    ...plan,
    preservedPrefix: baseline.slice(0, anchor),
    preservedSuffix: baseline.slice(anchor),
  }
}

export function reviewedJavaHelperEvidence(
  contract: ReviewedJavaHelper | undefined,
  files: readonly { path: string; content: string }[],
): ImpactEvidence[] {
  if (contract === undefined) return []
  const source = files.find(file => file.path === contract.sourcePath)?.content
  if (source === undefined) throw new Error('reviewed Java helper source was not supplied to the Harness')
  assertPreservedSource(contract, source)
  const offset = uniqueDeclarationOffset(source, contract.insertionAnchor)
  const startLine = contract.preservedPrefix.split('\n').length
  const endLine = source.slice(0, offset).split('\n').length
  return [{
    kind: 'sdk_call',
    operation: 'reviewed_call_id_helper_insertion',
    location: {
      path: contract.sourcePath,
      line: startLine,
      ...(endLine === startLine ? {} : { endLine }),
      column: 1,
    },
    detail: [
      'The trusted runner already materialized the repository-reviewed helper immediately',
      'before getOutputAsString. This complete helper is read-only model context: do not add,',
      'modify, or duplicate it, its fields, or getOutputAsString. Use the helper from the',
      'evidence-backed caller migration.',
      'This companion location is not a provider-observed SDK call.',
    ].join(' '),
    deterministicRecipeSupported: false,
    language: 'java',
    ecosystem: 'maven',
  }]
}

/**
 * Materialize the one repository-reviewed compatibility helper before the
 * Harness runs. The model still owns the evidence-backed caller migration,
 * but it does not need to synthesize a class member whose complete behavior is
 * already fixed by the exact repository/event contract. On a repair attempt,
 * replace only the prior insertion slot; any change to original class bytes
 * continues to fail closed.
 */
export function reviewedJavaHelperSeedEdits(
  contract: ReviewedJavaHelper | undefined,
  files: readonly { path: string; content: string }[],
): Array<{ path: string; expectedHash: string; content: string }> {
  if (contract === undefined) return []
  const file = files.find(candidate => candidate.path === contract.sourcePath)
  if (file === undefined) return []
  assertPreservedSource(contract, file.content)
  uniqueDeclarationOffset(file.content, contract.insertionAnchor)
  const content = reviewedJavaHelperContent(contract)
  return content === file.content ? [] : [{
    path: file.path,
    expectedHash: sha256(file.content),
    content,
  }]
}

/**
 * A repair context combines code-owned seeds and model edits for replay. Split
 * the exact canonical helper seed back out before applying model policy. A
 * merely similar helper edit remains model-owned and is therefore rejected by
 * the read-only policy instead of being promoted to trusted code.
 */
export function partitionReviewedJavaHelperPreviousEdits(
  contract: ReviewedJavaHelper | undefined,
  edits: readonly { path: string; expectedHash: string; content: string }[],
): {
  trustedSeedEdits: Array<{ path: string; expectedHash: string; content: string }>
  modelEdits: Array<{ path: string; expectedHash: string; content: string }>
} {
  if (contract === undefined) return { trustedSeedEdits: [], modelEdits: [...edits] }
  const baseline = contract.preservedPrefix + contract.preservedSuffix
  const canonical = reviewedJavaHelperContent(contract)
  const trustedSeedEdits = edits.filter(edit => edit.path === contract.sourcePath
    && edit.expectedHash === sha256(baseline) && edit.content === canonical)
  if (trustedSeedEdits.length > 1) {
    throw new Error('previous repair contains duplicate reviewed Java helper seed')
  }
  const trusted = trustedSeedEdits[0]
  return {
    trustedSeedEdits,
    modelEdits: trusted === undefined ? [...edits] : edits.filter(edit => edit !== trusted),
  }
}

export function reviewedJavaHelperViolations(
  contract: ReviewedJavaHelper | undefined,
  files: readonly { path: string; content: string }[],
): string[] {
  if (contract === undefined) return []
  const source = files.find(file => file.path === contract.sourcePath)?.content
  if (source === undefined) return ['reviewed Java helper source is missing']
  try {
    assertPreservedSource(contract, source)
    uniqueDeclarationOffset(source, contract.insertionAnchor)
    if (source.split(contract.requiredDeclaration).length !== 2) {
      throw new Error('reviewed Java helper requires exactly one public static getCallIdAsString method')
    }
    const inserted = source.slice(contract.preservedPrefix.length, source.length - contract.preservedSuffix.length)
    assertSingleHelperInsertion(inserted)
    if (inserted !== REVIEWED_CALL_ID_HELPER) {
      throw new Error('reviewed Java helper must match the exact code-owned helper bytes')
    }
  } catch (error) {
    return [error instanceof Error ? error.message : 'reviewed Java helper contract failed']
  }
  return []
}

function assertSingleHelperInsertion(inserted: string): void {
  // Java translates Unicode escapes before lexical analysis. This deliberately
  // small Java-8 helper needs neither escapes nor text blocks; reject both so
  // they cannot disguise additional class members from the boundary scanner.
  if (/\\u+[0-9a-fA-F]{4}|"""/u.test(inserted)) {
    throw new Error('reviewed Java helper does not permit Unicode escapes or text blocks')
  }
  const code = inserted.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/\*[\s\S]*?\*\/|\/\/[^\n]*/gu,
    match => ' '.repeat(match.length)).trim()
  const declaration = /^public\s+static\s+String\s+getCallIdAsString\(\s*ResponseInputItem\.FunctionCallOutput\s+[A-Za-z_$][\w$]*\s*\)\s*\{/u.exec(code)
  if (declaration === null) throw new Error('reviewed Java insertion must be the public static call ID helper')
  let depth = 1
  for (let index = declaration[0].length; index < code.length; index += 1) {
    if (code[index] === '{') depth += 1
    if (code[index] === '}') depth -= 1
    if (depth === 0) {
      if (code.slice(index + 1).trim() === '') return
      break
    }
  }
  throw new Error('reviewed Java insertion must contain exactly one complete helper method')
}

function reviewedJavaHelperContent(contract: ReviewedJavaHelper): string {
  return contract.preservedPrefix + REVIEWED_CALL_ID_HELPER + contract.preservedSuffix
}

function assertPreservedSource(contract: ReviewedJavaHelper, source: string): void {
  // The new helper is the only insertion. The complete old extractor behavior,
  // imports, fields and closing class delimiter must remain byte-for-byte intact.
  if (!source.startsWith(contract.preservedPrefix) || !source.endsWith(contract.preservedSuffix)
    || source.length < contract.preservedPrefix.length + contract.preservedSuffix.length) {
    throw new Error('reviewed Java helper must preserve the original extractor fields and getOutputAsString body')
  }
}

function uniqueDeclarationOffset(source: string, anchor: string): number {
  const lines = source.split('\n')
  const indexes = lines.flatMap((line, index) => line === anchor ? [index] : [])
  if (indexes.length !== 1) {
    throw new Error('reviewed Java helper requires its unique standalone declaration anchor')
  }
  return lines.slice(0, indexes[0]!).reduce((offset, line) => offset + line.length + 1, 0)
}
