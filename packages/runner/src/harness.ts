import {
  DeepSeekHarnessMigrationExecutor,
  DshSdkHarnessRuntimeFactory,
  type MigrationExecutor,
  type NetworkPolicyGuard,
} from '@automated-api/remediation'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const exec = promisify(execFile)

const PASSTHROUGH_ENVIRONMENT = [
  'PATH',
  'Path',
  'PATHEXT',
  'SystemRoot',
  'ComSpec',
  'TEMP',
  'TMP',
  'HOME',
  'USERPROFILE',
  'DSH_SESSION_ROOT',
] as const

type HarnessProvider = 'deepseek' | 'openrouter'

const OPENROUTER_WORKER_MODELS = new Set([
  'deepseek/deepseek-v4-flash',
  'deepseek/deepseek-v4-flash-0731',
])
const OPENROUTER_MASTER_MODEL = 'deepseek/deepseek-v4.1-flash'

interface HarnessRuntimeConfiguration {
  provider: HarnessProvider
  endpoint: URL
  credential: string
  initialModel: string
  repairModel: string
  reasoningEffort: 'off' | 'low' | 'high' | 'max'
}

export function createMigrationExecutorFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): MigrationExecutor | undefined {
  const command = environment['AUTOMATED_API_HARNESS_COMMAND']?.trim()
  if (command === undefined || command.length === 0) return undefined
  const runtime = harnessRuntimeConfigurationFromEnvironment(environment)
  const args = parseArgs(environment['AUTOMATED_API_HARNESS_ARGS_JSON'])
  const guardCommand = environment['AUTOMATED_API_NETWORK_GUARD_COMMAND']?.trim()
  if (guardCommand === undefined || guardCommand.length === 0) {
    throw new Error('Harness execution requires AUTOMATED_API_NETWORK_GUARD_COMMAND')
  }
  const childEnvironment: NodeJS.ProcessEnv = {}
  for (const name of PASSTHROUGH_ENVIRONMENT) {
    const value = environment[name]
    if (value !== undefined) childEnvironment[name] = value
  }
  // The pinned Harness adapter is OpenAI-compatible but names its credential
  // and endpoint after DeepSeek. Map only the selected provider credential into
  // that isolated child; never forward the caller's complete environment.
  childEnvironment['DEEPSEEK_API_KEY'] = runtime.credential
  childEnvironment['DEEPSEEK_BASE_URL'] = runtime.endpoint.toString().replace(/\/$/u, '')
  childEnvironment['DSH_THINKING'] = runtime.reasoningEffort === 'off' ? 'disabled' : 'enabled'
  childEnvironment['DSH_REASONING_EFFORT'] = runtime.reasoningEffort
  return new DeepSeekHarnessMigrationExecutor(
    new DshSdkHarnessRuntimeFactory({
      command,
      args,
      environment: childEnvironment,
      ...(environment['AUTOMATED_API_HARNESS_RUNTIME_CWD']?.trim() === undefined
        ? {}
        : { runtimeCwd: environment['AUTOMATED_API_HARNESS_RUNTIME_CWD']!.trim() }),
    }),
    new CommandNetworkPolicyGuard(guardCommand),
    runtime.endpoint.hostname,
    {
      provider: runtime.provider,
      initialModel: runtime.initialModel,
      repairModel: runtime.repairModel,
    },
  )
}

export function harnessNetworkHostFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): string {
  return harnessRuntimeConfigurationFromEnvironment(environment, false).endpoint.hostname
}

function harnessRuntimeConfigurationFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
  requireCredential = true,
): HarnessRuntimeConfiguration {
  const providerRaw = environment['AUTOMATED_API_HARNESS_PROVIDER']?.trim().toLowerCase() ?? 'deepseek'
  if (providerRaw !== 'deepseek' && providerRaw !== 'openrouter') {
    throw new Error('AUTOMATED_API_HARNESS_PROVIDER must be deepseek or openrouter')
  }
  const provider: HarnessProvider = providerRaw
  const credentialName = provider === 'openrouter' ? 'OPENROUTER_API_KEY' : 'DEEPSEEK_API_KEY'
  const credential = environment[credentialName]?.trim() ?? ''
  if (requireCredential && credential === '') {
    throw new Error(`AUTOMATED_API_HARNESS_COMMAND requires ${credentialName}`)
  }
  const endpointName = provider === 'openrouter' ? 'OPENROUTER_BASE_URL' : 'DEEPSEEK_BASE_URL'
  const defaultEndpoint = provider === 'openrouter'
    ? 'https://openrouter.ai/api/v1'
    : 'https://api.deepseek.com'
  const endpoint = parseEndpoint(environment[endpointName]?.trim() || defaultEndpoint, endpointName)
  if (provider === 'openrouter' && endpoint.hostname !== 'openrouter.ai') {
    throw new Error('OPENROUTER_BASE_URL must use the openrouter.ai hostname')
  }
  const initialModel = environment['AUTOMATED_API_HARNESS_MODEL']?.trim() || (
    provider === 'deepseek' ? 'deepseek-v4-flash' : ''
  )
  if (initialModel === '') {
    throw new Error('OpenRouter Harness requires AUTOMATED_API_HARNESS_MODEL')
  }
  if (provider === 'openrouter' && !OPENROUTER_WORKER_MODELS.has(initialModel)) {
    throw new Error('OpenRouter Harness worker must use an approved DeepSeek V4 Flash model ID')
  }
  const repairModel = environment['AUTOMATED_API_HARNESS_REPAIR_MODEL']?.trim() || (
    provider === 'deepseek' ? 'deepseek-v4-pro' : OPENROUTER_MASTER_MODEL
  )
  if (provider === 'openrouter' && repairModel !== OPENROUTER_MASTER_MODEL) {
    throw new Error(`OpenRouter Harness master must use ${OPENROUTER_MASTER_MODEL}`)
  }
  const reasoningEffortRaw = environment['AUTOMATED_API_HARNESS_REASONING_EFFORT']?.trim().toLowerCase()
    || (provider === 'openrouter' ? 'low' : 'max')
  if (!['off', 'low', 'high', 'max'].includes(reasoningEffortRaw)) {
    throw new Error('AUTOMATED_API_HARNESS_REASONING_EFFORT must be off, low, high, or max')
  }
  const reasoningEffort = reasoningEffortRaw as HarnessRuntimeConfiguration['reasoningEffort']
  return { provider, endpoint, credential, initialModel, repairModel, reasoningEffort }
}

export function harnessModelSelectionFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): Omit<HarnessRuntimeConfiguration, 'credential'> {
  const { credential: _credential, ...selection } = harnessRuntimeConfigurationFromEnvironment(environment, false)
  return selection
}

function parseEndpoint(raw: string, name: string): URL {
  let endpoint: URL
  try {
    endpoint = new URL(raw)
  } catch {
    throw new Error(`${name} must be a valid HTTPS URL`)
  }
  if (endpoint.protocol !== 'https:' || endpoint.username !== '' || endpoint.password !== '') {
    throw new Error(`${name} must be a credential-free HTTPS URL`)
  }
  return endpoint
}

class CommandNetworkPolicyGuard implements NetworkPolicyGuard {
  constructor(private readonly command: string) {}

  async assertEnforced(allowedHosts: readonly string[]): Promise<void> {
    await exec(this.command, ['verify', ...allowedHosts], {
      env: {
        PATH: process.env['PATH'],
        Path: process.env['Path'],
        SystemRoot: process.env['SystemRoot'],
      },
      timeout: 5_000,
      windowsHide: true,
    })
  }
}

function parseArgs(raw: string | undefined): string[] {
  if (raw === undefined || raw.trim() === '') return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('AUTOMATED_API_HARNESS_ARGS_JSON must be valid JSON')
  }
  if (!Array.isArray(parsed) || parsed.some(value => typeof value !== 'string')) {
    throw new Error('AUTOMATED_API_HARNESS_ARGS_JSON must be a JSON array of strings')
  }
  return parsed
}
