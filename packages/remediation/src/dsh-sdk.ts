import type { HarnessRuntime, HarnessRuntimeFactory } from './executor.js'

interface DshSdkModule {
  DeepSeekHarness: new (options: {
    launch: {
      command: string
      args: string[]
      cwd: string
      env: NodeJS.ProcessEnv
      requestTimeoutMs: number
    }
    cwd: string
    provider: string
    model: string
    maxTokens: number
  }) => {
    run(input: string, options: {
      sessionId: string
      onNotification?: (notification: unknown) => void
    }): Promise<{
      finalResponse: string
      events: readonly unknown[]
    }>
    close(): Promise<void>
  }
}

export interface DshSdkFactoryOptions {
  command: string
  args: string[]
  environment: NodeJS.ProcessEnv
  provider?: string
  runtimeCwd?: string
}

export class DshSdkHarnessRuntimeFactory implements HarnessRuntimeFactory {
  constructor(private readonly options: DshSdkFactoryOptions) {}

  async create(input: {
    cwd: string
    model: string
    maxTokens: number
    requestTimeoutMs: number
  }): Promise<HarnessRuntime> {
    const packageName = '@deepseek-ai/dsh-sdk-client'
    const module = await import(packageName) as unknown as DshSdkModule
    if (typeof module.DeepSeekHarness !== 'function') {
      throw new Error('installed DeepSeek Harness SDK does not export DeepSeekHarness')
    }
    const harness = new module.DeepSeekHarness({
      launch: {
        command: this.options.command,
        args: this.options.args,
        cwd: this.options.runtimeCwd ?? input.cwd,
        env: {
          ...this.options.environment,
          ...openRouterPreloadEnvironment(this.options.environment),
          DSH_CWD: input.cwd,
          DSH_MAX_TOKENS_AS_SUCCESS: 'false',
          DSH_SYSTEM_PROMPT: 'Return only the requested structured migration result. Do not invoke tools or inspect the filesystem.',
        },
        requestTimeoutMs: input.requestTimeoutMs,
      },
      cwd: input.cwd,
      provider: this.options.provider ?? 'deepseek-official',
      model: input.model,
      maxTokens: input.maxTokens,
    })
    return {
      async run(prompt, options) {
        const result = await runWithTerminalTurnFallback(harness, prompt, options.sessionId)
        const finishReason = finishReasonFromEvents(result.events)
        const diagnostic = harnessDiagnosticFromEvents(result.events)
        return {
          finalResponse: result.finalResponse,
          ...(finishReason === undefined ? {} : { finishReason }),
          ...(diagnostic === undefined ? {} : { diagnostic }),
        }
      },
      close: () => harness.close(),
    }
  }
}

function openRouterPreloadEnvironment(environment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  if (environment['DEEPSEEK_BASE_URL']?.replace(/\/$/u, '') !== 'https://openrouter.ai/api/v1') return {}
  // rc.7 serializes off as DeepSeek's `thinking`, not OpenRouter's `reasoning`.
  // NODE_OPTIONS reaches the Node Harness even when launched through a wrapper;
  // it does not modify fetch in the worker that owns this factory.
  const preload = new URL('./openrouter-preload.mjs', import.meta.url).href
  return {
    NODE_OPTIONS: [environment['NODE_OPTIONS'], `--import=${preload}`].filter(Boolean).join(' '),
  }
}

interface DshSdkRunner {
  run(input: string, options: {
    sessionId: string
    onNotification?: (notification: unknown) => void
  }): Promise<{
    finalResponse: string
    events: readonly unknown[]
  }>
}

interface TerminalRunResult {
  finalResponse: string
  events: readonly unknown[]
}

/**
 * The upstream SDK normally settles on `session.status=idle`. Some completed
 * turns do not emit that status, so also accept a durable terminal turn from
 * the exact activity interval that the SDK has already correlated to its
 * prompt receipt. The observer is deliberately fail-closed for malformed,
 * out-of-order, cross-session, or still-active tool/step state.
 */
export async function runWithTerminalTurnFallback(
  runner: DshSdkRunner,
  prompt: string,
  sessionId: string,
): Promise<TerminalRunResult> {
  const observer = createTerminalTurnObserver(sessionId)
  const sdkOutcome = runner.run(prompt, {
    sessionId,
    onNotification: observer.onNotification,
  }).then(
    (result) => ({ kind: 'result' as const, result }),
    (error: unknown) => ({ kind: 'error' as const, error }),
  )
  const terminalOutcome = observer.result.then((result) => ({ kind: 'result' as const, result }))
  const outcome = await Promise.race([sdkOutcome, terminalOutcome])
  if (outcome.kind === 'error') throw outcome.error
  return outcome.result
}

export function createTerminalTurnObserver(sessionId: string): {
  onNotification: (notification: unknown) => void
  result: Promise<TerminalRunResult>
} {
  const events: unknown[] = []
  const pendingToolCalls = new Set<string>()
  const pendingActions = new Set<string>()
  let receiptMessageId: string | undefined
  let activeTurn: number | undefined
  let openStep: number | undefined
  let requestStarted = false
  let lastSequence = -1
  let invalid = false
  let settled = false
  let resolveResult: (result: TerminalRunResult) => void = () => undefined
  const result = new Promise<TerminalRunResult>((resolve) => {
    resolveResult = resolve
  })

  const onNotification = (notification: unknown): void => {
    if (settled || invalid || !isRecord(notification) || notification.method !== 'session.event') return
    if (!isRecord(notification.params) || notification.params.sessionId !== sessionId) return
    const event = notification.params.event
    if (!isRecord(event) || typeof event.type !== 'string' || typeof event.seq !== 'number') {
      invalid = true
      return
    }

    if (receiptMessageId === undefined) {
      receiptMessageId = promptReceiptMessageId(event)
      if (receiptMessageId === undefined) return
      lastSequence = event.seq
      events.push(event)
      return
    }

    if (event.seq <= lastSequence) {
      invalid = true
      return
    }
    lastSequence = event.seq
    events.push(event)
    const data = isRecord(event.data) ? event.data : undefined

    if (event.type === 'turn/start') {
      if (activeTurn !== undefined || typeof data?.turn !== 'number') {
        invalid = true
        return
      }
      activeTurn = data.turn
      return
    }

    if (event.type === 'step/start') {
      if (!matchesTurn(data, activeTurn) || openStep !== undefined || typeof data?.step !== 'number') {
        invalid = true
        return
      }
      openStep = data.step
      return
    }

    if (event.type === 'request/header') {
      if (activeTurn === undefined || openStep === undefined) invalid = true
      else requestStarted = true
      return
    }

    if (event.type === 'tool/call') {
      if (!matchesStep(data, activeTurn, openStep) || typeof data?.callId !== 'string') invalid = true
      else pendingToolCalls.add(data.callId)
      return
    }

    if (event.type === 'tool/result') {
      const callId = toolResultCallId(data)
      if (!matchesStep(data, activeTurn, openStep) || callId === undefined || !pendingToolCalls.delete(callId)) {
        invalid = true
      }
      return
    }

    if (event.type === 'action/start') {
      const actionId = activityId(data)
      if (actionId === undefined) invalid = true
      else pendingActions.add(actionId)
      return
    }

    if (event.type === 'action/end') {
      const actionId = activityId(data)
      if (actionId === undefined || !pendingActions.delete(actionId)) invalid = true
      return
    }

    if (event.type === 'step/end') {
      if (!matchesStep(data, activeTurn, openStep)) invalid = true
      else openStep = undefined
      return
    }

    if (event.type !== 'turn/end') return
    if (
      !requestStarted
      || !matchesTurn(data, activeTurn)
      || openStep !== undefined
      || pendingToolCalls.size > 0
      || pendingActions.size > 0
      || terminalReason(data) === undefined
    ) return

    const finishReason = terminalReason(data)
    const finalResponse = finalResponseFromEvents(events)
    if (finishReason === 'completed' && finalResponse.length === 0) return
    settled = true
    resolveResult({ finalResponse, events: [...events] })
  }

  return { onNotification, result }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function promptReceiptMessageId(event: Record<string, unknown>): string | undefined {
  if (event.type !== 'agent/inbox/spliced' || !isRecord(event.data) || !Array.isArray(event.data.inserted)) {
    return undefined
  }
  for (const inserted of event.data.inserted) {
    if (!isRecord(inserted) || typeof inserted.id !== 'string' || !isRecord(inserted.source)) continue
    if (inserted.source.kind === 'user') return inserted.id
  }
  return undefined
}

function matchesTurn(data: Record<string, unknown> | undefined, turn: number | undefined): boolean {
  return turn !== undefined && data?.turn === turn
}

function matchesStep(
  data: Record<string, unknown> | undefined,
  turn: number | undefined,
  step: number | undefined,
): boolean {
  return matchesTurn(data, turn) && step !== undefined && data?.step === step
}

function toolResultCallId(data: Record<string, unknown> | undefined): string | undefined {
  if (!isRecord(data?.message) || !isRecord(data.message.source)) return undefined
  return typeof data.message.source.callId === 'string' ? data.message.source.callId : undefined
}

function activityId(data: Record<string, unknown> | undefined): string | undefined {
  for (const key of ['actionId', 'callId', 'id']) {
    if (typeof data?.[key] === 'string') return data[key]
  }
  return undefined
}

function terminalReason(data: Record<string, unknown> | undefined): string | undefined {
  if (!isRecord(data?.reason) || typeof data.reason.kind !== 'string') return undefined
  return data.reason.kind
}

function finalResponseFromEvents(events: readonly unknown[]): string {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index]
    if (!isRecord(event) || event.type !== 'assistant/message' || !isRecord(event.data)) continue
    const message = event.data.message
    if (!isRecord(message) || !Array.isArray(message.content)) continue
    return message.content
      .filter((block): block is Record<string, unknown> => isRecord(block) && block.type === 'text')
      .map((block) => typeof block.text === 'string' ? block.text : '')
      .join('')
  }
  return ''
}

export function harnessDiagnosticFromEvents(events: readonly unknown[]): string | undefined {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index]
    if (typeof event !== 'object' || event === null || !('type' in event) || event.type !== 'turn/end') continue
    if (!('data' in event) || typeof event.data !== 'object' || event.data === null || !('reason' in event.data)) {
      return undefined
    }
    const reason = event.data.reason
    if (typeof reason !== 'object' || reason === null || !('kind' in reason) || reason.kind !== 'error') {
      return undefined
    }
    const serialized = JSON.stringify(reason)
      .replace(/(?:sk|key)-[A-Za-z0-9_-]{10,}/gu, '[redacted]')
      .replace(/Bearer\s+[A-Za-z0-9._-]+/giu, 'Bearer [redacted]')
    return serialized.slice(0, 2_000)
  }
  return undefined
}

export function finishReasonFromEvents(events: readonly unknown[]): string | undefined {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index]
    if (typeof event !== 'object' || event === null || !('type' in event) || event.type !== 'turn/end') continue
    if (!('data' in event) || typeof event.data !== 'object' || event.data === null || !('reason' in event.data)) {
      return undefined
    }
    const reason = event.data.reason
    return typeof reason === 'object' && reason !== null && 'kind' in reason && typeof reason.kind === 'string'
      ? reason.kind
      : undefined
  }
  return undefined
}
