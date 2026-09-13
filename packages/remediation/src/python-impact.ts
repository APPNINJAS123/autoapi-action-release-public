import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import type {
  AffectedDependency,
  ActionableChangeEvent,
  ImpactEvidence,
  RepositoryImpact,
} from '@automated-api/contracts'

const ANALYZER = fileURLToPath(new URL('./python/analyze.py', import.meta.url))
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024
const ANALYSIS_TIMEOUT_MS = 30_000

export interface AnalyzePythonRepositoryInput {
  rootDir: string
  runtimeRootDir?: string
  baseSha: string
  changeEvent: ActionableChangeEvent
  pythonExecutable?: string
}

interface PythonAnalyzerOutput {
  manifests: string[]
  evidence: Array<{
    kind: 'python_import' | 'python_call' | 'python_dependency' | 'python_raw_endpoint' | 'dynamic_usage'
    operation: string
    path: string
    line: number
    column: number
    detail: string
    workspace: string
    deterministic?: boolean
  }>
  parseErrors: Array<{ path: string; line: number; detail: string }>
}

export async function analyzePythonRepository(
  input: AnalyzePythonRepositoryInput,
): Promise<RepositoryImpact> {
  const rootDir = resolve(input.rootDir)
  const dependencies = input.changeEvent.impactScope === 'api'
    ? []
    : effectivePythonDependencies(input.changeEvent)
  const apiHosts = input.changeEvent.impactScope === 'sdk'
    ? []
    : [...new Set(input.changeEvent.affectedApiHosts.map(host => host.toLowerCase()))]
  if (dependencies.length === 0 && apiHosts.length === 0) {
    return impact(input, 'blocked', [], [
      'change event has no PyPI dependency or API host metadata for Python analysis',
    ])
  }
  const selectedRuntimeWorkspace = runtimeWorkspace(rootDir, input.runtimeRootDir)
  const output = await runAnalyzer({
    rootDir,
    ...(selectedRuntimeWorkspace === undefined ? {} : {
      runtimeWorkspace: selectedRuntimeWorkspace,
    }),
    dependencies,
    apiHosts,
    recipeIds: input.changeEvent.recipeIds,
    affectedSymbols: [...new Set(input.changeEvent.operations.flatMap(operation =>
      operation.oldSymbol === undefined ? [] : [operation.oldSymbol]))],
  }, input.pythonExecutable ?? process.env['AUTOMATED_API_PYTHON'] ?? 'python3')
  const evidence: ImpactEvidence[] = output.evidence.map(item => ({
    kind: item.kind,
    operation: item.operation,
    location: {
      path: item.path,
      line: item.line,
      column: item.column,
    },
    detail: item.detail,
    deterministicRecipeSupported: item.deterministic === true,
    language: 'python',
    ...(item.kind === 'python_dependency' ? { ecosystem: 'pypi' as const } : {}),
    ...(item.workspace === '.' ? {} : { workspace: item.workspace }),
  }))
  if (evidence.length === 0) {
    const parseReason = output.parseErrors.length === 0
      ? []
      : [`${output.parseErrors.length} Python file(s) could not be parsed; no affected usage was proven`]
    return impact(input, 'not_affected', [], [
      `no Python dependency, import, bound SDK call, or API URL matched ${[
        ...dependencies.map(item => item.name),
        ...apiHosts,
      ].join(', ')}`,
      ...parseReason,
    ])
  }
  // A manifest-only match proves impact, but it cannot authorize a complete
  // deterministic source migration. The reviewed Python recipe requires both
  // its exact dependency transition and at least one safe source call; otherwise
  // the repository must go to the bounded Harness/manual path.
  const deterministic = evidence.every(item => item.deterministicRecipeSupported)
    && evidence.some(item => item.kind === 'python_dependency')
    && evidence.some(item => item.kind === 'python_call')
  return impact(input, deterministic ? 'affected_draftable' : 'affected_manual', evidence, [
    deterministic
      ? 'all affected Python usage is covered by an exact reviewed Python recipe'
      : 'affected Python usage was found and is routed to the bounded Harness until an exact reviewed Python recipe matches',
  ])
}

export function effectivePythonDependencies(event: ActionableChangeEvent): AffectedDependency[] {
  return event.affectedDependencies.filter(({ ecosystem }) => ecosystem === 'pypi')
}

async function runAnalyzer(
  request: {
    rootDir: string
    runtimeWorkspace?: string
    dependencies: AffectedDependency[]
    apiHosts: string[]
    recipeIds: string[]
    affectedSymbols: string[]
  },
  executable: string,
): Promise<PythonAnalyzerOutput> {
  const child = spawn(executable, [ANALYZER], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: process.env['PATH'], PYTHONIOENCODING: 'utf-8', PYTHONNOUSERSITE: '1' },
  })
  const stdout: Buffer[] = []
  const stderr: Buffer[] = []
  let outputBytes = 0
  child.stdout.on('data', (chunk: Buffer) => {
    outputBytes += chunk.length
    if (outputBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk)
  })
  child.stderr.on('data', (chunk: Buffer) => {
    if (Buffer.concat(stderr).length < 16_384) stderr.push(chunk.subarray(0, 16_384))
  })
  child.stdin.end(JSON.stringify(request))
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    child.kill('SIGKILL')
  }, ANALYSIS_TIMEOUT_MS)
  const result = await new Promise<{ code: number | null; error?: Error }>((resolvePromise) => {
    child.once('error', error => resolvePromise({ code: null, error }))
    child.once('exit', code => resolvePromise({ code }))
  }).finally(() => clearTimeout(timer))
  if (timedOut) throw new Error('Python impact analysis timed out')
  if (outputBytes > MAX_OUTPUT_BYTES) throw new Error('Python impact analysis exceeded its output budget')
  if (result.error !== undefined) {
    throw new Error(`Python impact analyzer could not start: ${result.error.message}`)
  }
  if (result.code !== 0) {
    throw new Error(`Python impact analyzer failed: ${Buffer.concat(stderr).toString('utf8').slice(0, 2_000)}`)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(Buffer.concat(stdout).toString('utf8'))
  } catch {
    throw new Error('Python impact analyzer returned malformed JSON')
  }
  return validateOutput(parsed)
}

function runtimeWorkspace(rootDir: string, runtimeRootDir: string | undefined): string | undefined {
  if (runtimeRootDir === undefined) return undefined
  const normalizedRoot = resolve(rootDir)
  const normalizedRuntime = resolve(runtimeRootDir)
  const prefix = `${normalizedRoot}${process.platform === 'win32' ? '\\' : '/'}`
  if (normalizedRuntime !== normalizedRoot && !normalizedRuntime.startsWith(prefix)) return undefined
  const relative = normalizedRuntime.slice(normalizedRoot.length).replaceAll('\\', '/').replace(/^\//u, '')
  return relative || '.'
}

function validateOutput(value: unknown): PythonAnalyzerOutput {
  if (typeof value !== 'object' || value === null || !('evidence' in value)
    || !Array.isArray(value.evidence) || !('manifests' in value)
    || !Array.isArray(value.manifests) || !('parseErrors' in value)
    || !Array.isArray(value.parseErrors)) {
    throw new Error('Python impact analyzer returned an invalid result')
  }
  return value as PythonAnalyzerOutput
}

function impact(
  input: Pick<AnalyzePythonRepositoryInput, 'baseSha' | 'changeEvent'>,
  outcome: RepositoryImpact['outcome'],
  evidence: ImpactEvidence[],
  reasons: string[],
): RepositoryImpact {
  return {
    schemaVersion: '1.0',
    changeEventId: input.changeEvent.id,
    baseSha: input.baseSha,
    outcome,
    evidence,
    reasons,
  }
}
