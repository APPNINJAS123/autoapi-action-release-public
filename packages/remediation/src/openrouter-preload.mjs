import { withOpenRouterReasoning } from './openrouter-fetch.mjs'

// Loaded only inside the isolated Harness child. The transport also checks the
// exact destination, so this cannot rewrite direct DeepSeek or unrelated fetches.
globalThis.fetch = withOpenRouterReasoning(globalThis.fetch)
