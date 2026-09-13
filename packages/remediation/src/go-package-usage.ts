import { spawnSync } from 'node:child_process'
import { dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

const helper = fileURLToPath(new URL('./go/package_usage.go', import.meta.url))
// Package clauses verified in the official SDK artifacts. Do not guess an
// implicit identifier from a module path: Go names need not match that path.
const defaultPackages = {
  'github.com/openai/openai-go': 'openai',
  'github.com/openai/openai-go/option': 'option',
} as const

export interface GoPackageDeclarationUsage {
  module: string
  start: number
  end: number
  declaration: string
}

export function goPackageDeclarationUsages(content: string, modules: string[]): GoPackageDeclarationUsage[] {
  if (modules.length === 0 || Buffer.byteLength(content) > 2 * 1024 * 1024
    || !modules.some(module => content.includes(module))) return []
  const options = {
    cwd: dirname(helper), input: JSON.stringify({ content, modules, defaultPackages }), encoding: 'utf8',
    maxBuffer: 1024 * 1024, timeout: 30_000,
    env: { PATH: process.env['PATH'], SystemRoot: process.env['SystemRoot'],
      USERPROFILE: process.env['USERPROFILE'], HOME: process.env['HOME'], LOCALAPPDATA: process.env['LOCALAPPDATA'],
      TMP: process.env['TMP'], TEMP: process.env['TEMP'], GOCACHE: process.env['GOCACHE'],
      GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local', GO111MODULE: 'off', GOWORK: 'off', GOMAXPROCS: '2' },
  } as const
  const configuredBinary = process.env['AUTOMATED_API_GO_PACKAGE_USAGE']
  if (configuredBinary !== undefined && !isAbsolute(configuredBinary)) return []
  const binary = configuredBinary ?? '/usr/local/bin/autoapi-go-package-usage'
  let result = spawnSync(binary, [], { ...options, timeout: 5_000 })
  // Development-only fallback. Deployed analysis/worker images must ship the
  // precompiled trusted helper; requests must not compile a tool per file.
  if ((result.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT'
    && process.env['AUTOMATED_API_ALLOW_GO_PARSER_SOURCE'] === '1') {
    result = spawnSync('go', ['run', helper], options)
  }
  // Missing runtime, malformed source or ambiguous bindings confer no broader
  // edit authority; the existing narrow evidence/validation gates still apply.
  if (result.error || result.status !== 0) return []
  let parsed: unknown
  try { parsed = JSON.parse(result.stdout) } catch { return [] }
  const lines = content.split('\n').length
  if (!Array.isArray(parsed) || parsed.length > 2000) return []
  if (!parsed.every(value => typeof value === 'object' && value !== null
    && modules.includes(value.module) && typeof value.declaration === 'string'
    && Number.isSafeInteger(value.start) && value.start > 0 && Number.isSafeInteger(value.end)
    && value.end >= value.start && value.end <= lines && value.end - value.start <= 1000)) return []
  return parsed as GoPackageDeclarationUsage[]
}
