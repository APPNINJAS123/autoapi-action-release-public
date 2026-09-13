const SECRET_ENVIRONMENT_NAME = /(token|secret|password|credential|api[_-]?key|private[_-]?key)/iu

/**
 * Strips credential-shaped variables before handing an environment to any
 * subprocess that touches customer-controlled repository content.
 *
 * This applies to `git` just as much as to repository validation commands:
 * git honours repository-influenced configuration that can execute commands
 * (textconv/diff drivers, core.fsmonitor, core.pager), so running git inside
 * an untrusted checkout is an execution surface, not a safe read.
 */
export function scrubEnvironment(environment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(environment).filter(
      ([name, value]) => value !== undefined
        && (name === 'TIKTOKEN_CACHE_DIR' || !SECRET_ENVIRONMENT_NAME.test(name)),
    ),
  )
}
