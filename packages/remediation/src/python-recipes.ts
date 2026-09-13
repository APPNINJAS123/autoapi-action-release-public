import { spawnSync } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import type { ActionableChangeEvent, RepositoryImpact } from '@automated-api/contracts'
import type { RecipeResult } from './recipe.js'
import { resolveExistingPathInsideRepository, resolveWritablePathInsideRepository } from './policy.js'

export const FIRECRAWL_PYTHON_V1_V2_RECIPE_ID = 'firecrawl-python-v1-v2'
export const FIRECRAWL_PYTHON_OLD_VERSION = '1.14.0'
export const FIRECRAWL_PYTHON_TARGET_VERSION = '4.31.0'
export const FIRECRAWL_PYTHON_TARGET_SHA256 = '40142f9dc8b291ab0573ed9ff62732e07ba5264074fcc633bb752d9510e8321e'

const REWRITER = fileURLToPath(new URL('./python/firecrawl_rewrite.py', import.meta.url))

export async function applyFirecrawlPythonV1ToV2Recipe(
  rootDir: string,
  impact: RepositoryImpact,
  event: ActionableChangeEvent,
): Promise<RecipeResult> {
  assertEligible(impact, event)
  const changedFiles: string[] = []
  const pythonPaths = [...new Set(impact.evidence.flatMap(item =>
    item.language === 'python' && item.location?.path?.match(/\.pyi?$/u)
      ? [item.location.path]
      : []))]
  for (const path of pythonPaths) {
    const absolute = await resolveExistingPathInsideRepository(rootDir, path)
    const content = await readFile(absolute, 'utf8')
    const result = rewritePython(path, content)
    if (result.content === content) continue
    await writeFile(await resolveWritablePathInsideRepository(rootDir, path), result.content, 'utf8')
    changedFiles.push(path)
  }

  const manifestPaths = [...new Set(impact.evidence.flatMap(item =>
    item.kind === 'python_dependency' && item.location?.path
      ? [item.location.path]
      : []))]
  for (const path of manifestPaths) {
    const name = path.split('/').at(-1) ?? path
    if (name !== 'pyproject.toml' && !/^requirements(?:[-_.].*)?\.txt$/u.test(name)) {
      throw new Error(`reviewed Firecrawl Python recipe does not support manifest ${path}`)
    }
    const absolute = await resolveExistingPathInsideRepository(rootDir, path)
    const content = await readFile(absolute, 'utf8')
    const updated = name === 'pyproject.toml'
      ? updatePyproject(content)
      : updateRequirement(content)
    if (updated === content) continue
    await writeFile(await resolveWritablePathInsideRepository(rootDir, path), updated, 'utf8')
    changedFiles.push(path)
  }
  if (pythonPaths.length === 0 || manifestPaths.length === 0 || changedFiles.length === 0) {
    throw new Error('reviewed Firecrawl Python recipe found no complete source-and-dependency migration')
  }
  return {
    recipeId: FIRECRAWL_PYTHON_V1_V2_RECIPE_ID,
    changedFiles: [...new Set(changedFiles)].sort(),
    notes: ['migrated the exact reviewed Firecrawl Python 1.14.0 to 4.31.0 transition'],
  }
}

function updatePyproject(content: string): string {
  const matches = [...content.matchAll(/(["'])firecrawl-py==1\.14\.0\1/giu)]
  if (matches.length !== 1) {
    throw new Error('Firecrawl Python recipe requires exactly one firecrawl-py==1.14.0 pyproject dependency')
  }
  return content.replace(/(["'])firecrawl-py==1\.14\.0\1/iu, `$1firecrawl-py==${FIRECRAWL_PYTHON_TARGET_VERSION}$1`)
}

function rewritePython(path: string, content: string): { content: string; edits: number } {
  const executable = process.env['AUTOMATED_API_PYTHON'] ?? 'python3'
  const result = spawnSync(executable, [REWRITER], {
    input: JSON.stringify({ path, content }), encoding: 'utf8', timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
    env: { PATH: process.env['PATH'], PYTHONIOENCODING: 'utf-8', PYTHONNOUSERSITE: '1' },
  })
  if (result.error) throw new Error(`Firecrawl Python rewriter could not start: ${result.error.message}`)
  if (result.status !== 0) throw new Error(`Firecrawl Python rewriter rejected the source: ${result.stderr.slice(0, 2_000)}`)
  const parsed = JSON.parse(result.stdout) as { content?: unknown; edits?: unknown }
  if (typeof parsed.content !== 'string' || typeof parsed.edits !== 'number') {
    throw new Error('Firecrawl Python rewriter returned an invalid result')
  }
  return { content: parsed.content, edits: parsed.edits }
}

function updateRequirement(content: string): string {
  let replacements = 0
  const updated = content.split(/(?<=\n)/u).map((line) => {
    const newline = line.endsWith('\n') ? '\n' : ''
    const value = newline ? line.slice(0, -1) : line
    const match = value.match(/^(\s*)firecrawl-py==1\.14\.0(?:\s+--hash=sha256:[a-f0-9]{64})+(\s*(?:#.*)?)$/iu)
    if (!match) return line
    replacements += 1
    return `${match[1]}firecrawl-py==${FIRECRAWL_PYTHON_TARGET_VERSION} --hash=sha256:${FIRECRAWL_PYTHON_TARGET_SHA256}${match[2]}${newline}`
  }).join('')
  if (replacements !== 1) throw new Error('Firecrawl Python recipe requires exactly one hash-locked firecrawl-py==1.14.0 line')
  return updated
}

function assertEligible(impact: RepositoryImpact, event: ActionableChangeEvent): void {
  if (impact.outcome !== 'affected_draftable'
    || !event.recipeIds.includes(FIRECRAWL_PYTHON_V1_V2_RECIPE_ID)
    || event.provider !== 'firecrawl'
    || event.oldVersion !== FIRECRAWL_PYTHON_OLD_VERSION
    || event.newVersion !== FIRECRAWL_PYTHON_TARGET_VERSION
    || impact.evidence.length === 0
    || !impact.evidence.some(item => item.kind === 'python_dependency' && item.deterministicRecipeSupported)
    || !impact.evidence.some(item => item.kind === 'python_call' && item.operation === 'scrape_url')
    || impact.evidence.some(item => item.language !== 'python' || !item.deterministicRecipeSupported)) {
    throw new Error('repository impact is not eligible for the reviewed Firecrawl Python recipe')
  }
}
