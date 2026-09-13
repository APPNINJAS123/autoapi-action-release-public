const CHAT_COMPLETIONS_URL = 'https://openrouter.ai/api/v1/chat/completions'

/** Adapt only the pinned Harness adapter's explicit thinking-off wire request. */
export function withOpenRouterReasoning(fetchImplementation) {
  return function fetchWithOpenRouterReasoning(input, init) {
    // rc.7 uses a string URL and JSON string body. Do not consume Request bodies,
    // streams, or other transports whose ownership/replay semantics differ.
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : undefined
    if (url !== CHAT_COMPLETIONS_URL || init?.method?.toUpperCase() !== 'POST'
      || typeof init.body !== 'string') return fetchImplementation(input, init)

    let body
    try {
      body = JSON.parse(init.body)
    } catch {
      return fetchImplementation(input, init)
    }
    if (body?.thinking?.type !== 'disabled') return fetchImplementation(input, init)

    const { thinking: _thinking, reasoning_effort: _effort, ...request } = body
    return fetchImplementation(input, {
      ...init,
      body: JSON.stringify({ ...request, reasoning: { enabled: false } }),
    })
  }
}
