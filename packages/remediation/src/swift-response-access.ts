import type { ActionableChangeEvent } from '@automated-api/contracts'

const OLD_DECLARATION = 'public let message: Self.ChatCompletionMessage'
const NEW_DECLARATION = 'public let message: Self.Message'
const OLD_HASH = '54dcbf9469b938226a2cc151b22b05835d126ea875e2577fafff00dc43884732'
const NEW_HASH = 'dd6623b38863c290d3ef0566251f2a4b06825d8964efdcfb26902382eb1a50cd'
const SOURCES = [
  ['https://codeload.github.com/MacPaw/OpenAI/tar.gz/refs/tags/0.3.6', OLD_HASH],
  ['https://codeload.github.com/MacPaw/OpenAI/tar.gz/refs/tags/0.3.7', NEW_HASH],
  ['https://github.com/MacPaw/OpenAI/commit/c8d6a928cb970cd03d9eba98780aa909206ea97b.patch',
    'af9ead890a1414b7b93b067cb1043abfb54578bcbe02411c2cc1e0adcc267101'],
] as const

/** No fixture symbol or model-supplied mapping establishes this source contract. */
export function reviewedSwiftResponseChange(event: ActionableChangeEvent): boolean {
  const dependency = event.affectedDependencies?.[0]
  const operation = event.operations?.[0]
  return event.verificationStatus === 'verified' && event.provider === 'openai'
    && event.apiOrSdk === 'MacPaw OpenAI Swift SDK' && event.impactScope === 'sdk'
    && event.oldVersion === '0.3.6' && event.newVersion === '0.3.7'
    && event.affectedLanguages.length === 1 && event.affectedLanguages[0] === 'swift'
    && event.affectedDependencies.length === 1 && dependency?.ecosystem === 'swiftpm'
    && dependency.name === 'OpenAI' && dependency.oldVersionRange === '>=0.3.6 <0.3.7'
    && dependency.newVersion === '0.3.7' && dependency.newArtifactSha256 === NEW_HASH
    && dependency.importNames.length === 1 && dependency.importNames[0] === 'OpenAI'
    && event.operations.length === 1 && operation?.operation === 'ChatResult.Choice.message'
    && operation.kind === 'option_changed' && operation.oldSymbol === OLD_DECLARATION
    && operation.newSymbol === NEW_DECLARATION
    && SOURCES.every(([url, hash]) => event.evidence.filter(item => item.url === url).length === 1
      && event.evidence.some(item => item.url === url && item.contentHash === hash))
}

export interface SwiftResponseContentAccess {
  offset: number
  functionName: string
  clientName: string
  resultName: string
  assignmentName: string
  fallbackName: string
}

/**
 * Code-owned type edges read from OLD_HASH's OpenAI+OpenAIAsync.swift,
 * ChatResult.swift and ChatQuery.swift:
 * OpenAI.chats(query: ChatQuery) async throws -> ChatResult;
 * ChatResult.choices: [Choice]; Choice.message: Self.ChatCompletionMessage;
 * Choice.ChatCompletionMessage = ChatQuery.ChatCompletionMessageParam;
 * ChatCompletionMessageParam.content: Self.UserMessageParam.Content?;
 * UserMessageParam.Content.string: String?.
 * NEW_HASH changes Choice.message to Self.Message and Message.content to String?.
 * The exact publisher patch removes `.string` in its own response-reading demo.
 *
 * This deliberately small recognizer is not a Swift type checker. It accepts
 * only an unshadowed concrete function parameter, an immutable direct awaited
 * response and a same-block immutable assignment with an identifier fallback.
 * It cannot authorize arbitrary response aliases, interpolations or closures.
 */
export function swiftResponseContentAccesses(content: string, target = false): SwiftResponseContentAccess[] {
  const code = swiftCode(content)
  if (code === undefined || hasSwiftResponseTypeOverride(content)) return []
  const imports = [...code.matchAll(/(?:^|\n)[ \t]*import[ \t]+([^\n;]+)[ \t]*;?(?=\n|$)/gu)]
    .map(match => match[1]!.trim())
  if (!imports.includes('OpenAI') || imports.some(name => !['OpenAI', 'Foundation', 'ArgumentParser'].includes(name))
    || [...code.matchAll(/\bimport\b/gu)].length !== imports.length) return []
  const tokens = [...code.matchAll(/[A-Za-z_][A-Za-z_0-9]*|\?\.|->|\?\?|[^\s]/gu)]
    .map(match => ({ text: match[0], offset: match.index }))
  if (tokens.length > 200_000) return []
  const pairs = new Map<number, number>()
  const parents = new Map<number, number>()
  const stack: number[] = []
  const closing: Record<string, string> = { ')': '(', ']': '[', '}': '{' }
  for (const [index, token] of tokens.entries()) {
    parents.set(index, [...stack].reverse().find(item => tokens[item]!.text === '{') ?? -1)
    if (['(', '[', '{'].includes(token.text)) {
      stack.push(index)
      if (stack.length > 256) return []
    }
    else if (closing[token.text]) {
      const opening = stack.pop()
      if (opening === undefined || tokens[opening]!.text !== closing[token.text]) return []
      pairs.set(opening, index)
    }
  }
  if (stack.length !== 0) return []
  const functionCounts = new Map<string, number>()
  for (const [index, token] of tokens.entries()) if (token.text === 'func' && identifier(tokens[index + 1]?.text)) {
    const name = tokens[index + 1]!.text
    functionCounts.set(name, (functionCounts.get(name) ?? 0) + 1)
  }
  const output: SwiftResponseContentAccess[] = []
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index]!.text !== 'func' || !identifier(tokens[index + 1]?.text) || tokens[index + 2]?.text !== '(') continue
    if (functionCounts.get(tokens[index + 1]!.text) !== 1) continue
    const parameterEnd = pairs.get(index + 2)
    if (parameterEnd === undefined) continue
    let body = parameterEnd + 1
    while (body < tokens.length && body < parameterEnd + 12 && tokens[body]!.text !== '{') body++
    if (tokens[body]?.text !== '{') continue
    const end = pairs.get(body)
    if (end === undefined) continue
    const signatureTail = tokens.slice(parameterEnd + 1, body).map(token => token.text).join(' ')
    if (!/^(?:async )?(?:throws )?(?:-> [A-Za-z_][A-Za-z_0-9]*\s*\??)?\s*$/u.test(signatureTail)) continue
    // Nested functions, closures and parameter aliases are not inferred.
    const clients: string[] = []
    let parameterStart = index + 3
    for (let cursor = parameterStart; cursor <= parameterEnd; cursor++) {
      if (cursor !== parameterEnd && pairs.has(cursor)) { cursor = pairs.get(cursor)!; continue }
      if (cursor !== parameterEnd && tokens[cursor]!.text !== ',') continue
      const parameter = tokens.slice(parameterStart, cursor).map(token => token.text)
      if ((parameter.length === 3 || parameter.length === 4) && parameter.at(-2) === ':'
        && parameter.at(-1) === 'OpenAI' && parameter.slice(0, -2).every(identifier)) clients.push(parameter.at(-3)!)
      parameterStart = cursor + 1
    }
    for (const clientName of clients) {
      if (clientName === 'OpenAI') continue
      const uses = tokens.slice(body + 1, end).flatMap((token, offset) => token.text === clientName ? [offset + body + 1] : [])
      const responseBindings: Array<{ root: number; result: number }> = []
      for (const root of uses) {
        const prefix = tokens.slice(root - 5, root).map(token => token.text)
        const suffix = tokens.slice(root + 1, root + 8).map(token => token.text)
        if (prefix[0] !== 'let' || !identifier(prefix[1]) || prefix.slice(2).join(' ') !== '= try await'
          || suffix[0] !== '.' || suffix[1] !== 'chats' || suffix[2] !== '(' || suffix[3] !== 'query'
          || suffix[4] !== ':' || !identifier(suffix[5]) || suffix[6] !== ')') continue
        // The awaited response must not continue through an unproved call or cast.
        const after = tokens[root + 8]
        const callEnd = tokens[root + 7]!
        if (after !== undefined && ![';', '}'].includes(after.text)
          && !code.slice(callEnd.offset + 1, after.offset).includes('\n')) continue
        if (after?.text === '.' || after?.text === '?.' || after?.text === 'as') continue
        responseBindings.push({ root, result: root - 4 })
      }
      // Any unrecognized use can be a shadow, reassignment or closure capture.
      if (responseBindings.length !== uses.length || uses.length === 0) continue
      for (const binding of responseBindings) {
        const resultName = tokens[binding.result]!.text
        const resultUses: number[] = tokens.slice(body + 1, end).flatMap((token, offset) =>
          token.text === resultName && offset + body + 1 !== binding.result ? [offset + body + 1] : [])
        if (resultUses.length === 0) continue
        const accesses: SwiftResponseContentAccess[] = []
        for (const use of resultUses) {
          if (use <= binding.root || parents.get(use) !== parents.get(binding.root)) continue
          const chain = target ? ['.', 'choices', '.', 'first', '?.', 'message', '.', 'content']
            : ['.', 'choices', '.', 'first', '?.', 'message', '.', 'content', '?.', 'string']
          if (chain.some((text, offset) => tokens[use + offset + 1]?.text !== text)) continue
          const assignment = tokens.slice(use - 3, use).map(token => token.text)
          const tail = use + chain.length + 1
          if (assignment[0] !== 'let' || !identifier(assignment[1]) || assignment[2] !== '='
            || tokens[tail]?.text !== '??' || !identifier(tokens[tail + 1]?.text)) continue
          const last = tokens[tail + 1]!, after = tokens[tail + 2]
          if (after !== undefined && ![';', '}'].includes(after.text)
            && !code.slice(last.offset + last.text.length, after.offset).includes('\n')) continue
          if (after !== undefined && ![';', '}'].includes(after.text)
            && (!identifier(after.text) || ['as', 'is'].includes(after.text))) continue
          const contentToken = tokens[use + 8]!
          // Existing occurrence guards operate on this exact leaf, not arbitrary whitespace rewrites.
          if (!target && content.slice(contentToken.offset, contentToken.offset + 15) !== 'content?.string') continue
          accesses.push({ offset: contentToken.offset, functionName: tokens[index + 1]!.text,
            clientName, resultName, assignmentName: assignment[1]!, fallbackName: last.text })
        }
        if (accesses.length === resultUses.length) output.push(...accesses)
      }
    }
  }
  return output
}

/** Scan every repository Swift source before using the concrete imported type. */
export function hasSwiftResponseTypeOverride(content: string): boolean {
  const code = swiftCode(content)
  if (code === undefined) return true
  return /\b(?:typealias|struct|class|enum|protocol|actor|extension)\s+(?:[A-Za-z_]\w*\.)*(?:OpenAI|ChatResult|ChatQuery|Array|Optional|Sequence|Collection|BidirectionalCollection|RandomAccessCollection)\b/u.test(code)
    || /\b(?:let|var|func)\s+OpenAI\b/u.test(code)
    || /[<(,]\s*OpenAI\s*(?=[:,>)])/u.test(code)
}

function identifier(value: string | undefined): boolean {
  return value !== undefined && /^[A-Za-z_][A-Za-z_0-9]*$/u.test(value)
}

/** Preserve UTF-16 offsets; strings (including interpolation) grant no authority. */
function swiftCode(content: string): string | undefined {
  if (content.length > 2 * 1024 * 1024 || /[\u2028\u2029]/u.test(content)
    || content.replaceAll('\r\n', '\n').includes('\r')) return undefined
  const output = content.split('')
  const blank = (start: number, end: number) => {
    for (let index = start; index < end; index++) if (!/[\r\n]/u.test(output[index]!)) output[index] = ' '
  }
  const skipComment = (start: number): number | undefined => {
    let index = start + 2, depth = 1
    while (index < content.length && depth > 0) {
      if (content.startsWith('/*', index)) { depth++; index += 2 }
      else if (content.startsWith('*/', index)) { depth--; index += 2 }
      else index++
    }
    return depth === 0 ? index : undefined
  }
  const skipString = (start: number, nesting: number): number | undefined => {
    if (nesting > 64) return undefined
    const quote = /^(#*)("""|")/u.exec(content.slice(start, start + 64))!
    const delimiter = quote[2]! + quote[1]!, escape = '\\' + quote[1]!
    let index = start + quote[0].length
    while (index < content.length) {
      if (quote[2] === '"' && /[\r\n]/u.test(content[index]!)) return undefined
      if (content.startsWith(escape + '(', index)) {
        index += escape.length + 1; let depth = 1
        while (index < content.length && depth > 0) {
          if (/^(#*)("""|")/u.test(content.slice(index, index + 64))) {
            const end = skipString(index, nesting + 1)
            if (end === undefined) return undefined
            index = end
          } else if (content.startsWith('/*', index)) {
            const end = skipComment(index)
            if (end === undefined) return undefined
            index = end
          } else if (content.startsWith('//', index)) {
            const end = content.indexOf('\n', index)
            if (end < 0) return undefined
            index = end
          } else {
            if (content[index] === '(') depth++
            if (content[index] === ')') depth--
            index++
          }
        }
        if (depth !== 0) return undefined
      } else if (content.startsWith(escape, index)) {
        if (quote[2] === '"' && /[\r\n]/u.test(content[index + escape.length] ?? '')) return undefined
        index += escape.length + 1
      }
      else if (content.startsWith(delimiter, index)) return index + delimiter.length
      else index++
    }
    return undefined
  }
  for (let index = 0; index < content.length;) {
    if (content.startsWith('//', index)) {
      const end = content.indexOf('\n', index)
      blank(index, end < 0 ? content.length : end); index = end < 0 ? content.length : end; continue
    }
    if (content.startsWith('/*', index)) {
      const end = skipComment(index)
      if (end === undefined) return undefined
      blank(index, end); index = end; continue
    }
    const quote = /^(#*)("""|")/u.exec(content.slice(index, index + 64))
    if (quote) {
      const end = skipString(index, 0)
      if (end === undefined) return undefined
      blank(index, end); index = end; continue
    }
    index++
  }
  const code = output.join('')
  // Bare slash regexes need the Swift lexer. The reviewed consumer contains
  // only this unambiguous numeric progress division; all other slash forms
  // remain unsupported instead of exposing a regex literal as executable code.
  for (const slash of code.matchAll(/\//gu)) {
    if (!/\bDouble\(\s*[A-Za-z_]\w*\s*\)\s*$/u.test(code.slice(Math.max(0, slash.index - 512), slash.index))
      || !/^\s*Double\(\s*[A-Za-z_]\w*\s*\)/u.test(code.slice(slash.index + 1, slash.index + 513))) return undefined
  }
  // Conditional compilation, macros, escaped identifiers and non-ASCII code
  // require a compiler; no lexical fallback may grant ownership in those cases.
  return /[`#\u0080-\uffff]/u.test(code) ? undefined : code
}
