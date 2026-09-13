import type { ActionableChangeEvent, ImpactEvidence } from '@automated-api/contracts'

const OLD_ARCHIVE = 'b5e675b57ad22b15c9bcc765d5ac26f60b675408af916d31527af9bd5a81faae'
const NEW_ARCHIVE = 'de71c10edd106986b759ec7ecdd08b63b9c0ee7414a0d0c1da73d31ba2bccda6'
const MARKER = 'Ruby Redis 5.4.1 to 6.0.0 resolved constructor options: '
type Token = { value: string; offset: number; line: number; column: number; string?: boolean }
type Block = { kind: string; name: string; owner: string[]; singleton: boolean; header: Token[]; body: Token[]; indent: number }

export function isRubyRedisOwnershipEvidence(item: ImpactEvidence): boolean {
  return item.kind === 'sdk_call' && item.language === 'ruby' && item.ecosystem === 'gem'
    && item.operation === 'package migration' && item.location?.endLine !== undefined
    && item.location.endLine >= item.location.line && item.location.endLine - item.location.line <= 100
    && (item.detail === `${MARKER}Redis.new argument expression`
      || item.detail === `${MARKER}same-file options accessor hash`)
}

/** Bounded static resolution, not Ruby execution. Unsupported lexical forms,
 * dynamic binding, inheritance, reopened definitions and ambiguous accessors
 * yield no new authority. Only the call expression and proven returned hash
 * become editable; surrounding methods and application state stay protected.
 */
export function isReviewedRubyRedisMigration(event: ActionableChangeEvent): boolean {
  return !(event.provider !== 'redis' || event.verificationStatus !== 'verified' || event.impactScope !== 'sdk'
    || event.oldVersion !== '5.4.1' || event.newVersion !== '6.0.0'
    || event.affectedLanguages.length !== 1 || event.affectedLanguages[0] !== 'ruby'
    || event.affectedDependencies.length !== 1
    || !event.affectedDependencies.some(item => item.ecosystem === 'gem' && item.name === 'redis'
      && item.newVersion === '6.0.0' && item.newArtifactSha256 === NEW_ARCHIVE)
    || !event.operations.some(item => item.operation === 'package migration' && item.kind === 'option_changed'
      && item.oldSymbol === 'redis@5.4.1' && item.newSymbol === 'redis@6.0.0')
    || ![OLD_ARCHIVE, NEW_ARCHIVE].every(hash => event.evidence.some(item => item.contentHash === hash)))
}

export function rubyRedisOwnershipEvidence(content: string, path: string, event: ActionableChangeEvent): ImpactEvidence[] {
  if (!isReviewedRubyRedisMigration(event)) return []
  const tokens = tokenize(content)
  if (tokens === undefined) return []
  const syntax = blocks(tokens)
  if (syntax === undefined) return []
  const { definitions, owners, imported } = syntax
  if (!imported || tokens.some(token => !token.string && [
    'eval', 'class_eval', 'module_eval', 'instance_eval', 'const_set', 'remove_const', 'autoload',
    'define_method', 'define_singleton_method', 'alias', 'alias_method', 'undef', 'remove_method',
    'prepend', 'include', 'extend', 'load', 'require_relative', 'set_trace_func', 'binding',
    'instance_variable_set', 'class_variable_set', 'send', 'public_send', '__send__',
  ].includes(token.value))) return []
  if (definitions.some(item => item.name === 'Redis' || item.kind === 'def' && ['require', 'const_missing', 'method_missing'].includes(item.name))) return []
  const assignedConstants = new Set([...assignmentNames(tokens)].filter(name => /^[A-Z]/u.test(name)))
  if (assignedConstants.has('Redis')) return []
  const evidence: ImpactEvidence[] = []
  const emit = (start: Token, end: Token, description: string) => {
    if (end.line - start.line > 100) return
    evidence.push({ kind: 'sdk_call', operation: 'package migration', language: 'ruby', ecosystem: 'gem',
      location: { path, line: start.line, column: start.column, endLine: end.line },
      detail: `${MARKER}${description}`, deterministicRecipeSupported: false })
  }
  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (evidence.length > 200) return []
    const first = tokens[index]!
    if (first.value !== 'Redis' || first.string || tokens[index + 1]?.value !== '.'
      || tokens[index + 2]?.value !== 'new' || tokens[index + 3]?.value !== '(') continue
    const prefix = tokens[index - 1]?.value
    if (prefix === '.' || prefix === '&.' || prefix === ':' || prefix === '::'
      && tokens[index - 2]?.line === tokens[index - 1]?.line
      && /^[\w@]/u.test(tokens[index - 2]?.value ?? '')) continue
    const end = balancedEnd(tokens, index + 3, '(', ')')
    if (end === undefined) continue
    emit(prefix === '::' ? tokens[index - 1]! : first, tokens[end]!, 'Redis.new argument expression')
    const args = tokens.slice(index + 4, end)
    // Resolve only one explicit **accessor.hash_method forwarding edge.
    if (args.length !== 4 || args.some(token => token.string) || args[0]?.value !== '**' || args[2]?.value !== '.') continue
    const receiver = args[1]!.value
    const member = args[3]!.value
    if (!/^[a-z_][\w]*$/u.test(receiver) || !/^[a-z_][\w]*$/u.test(member)) continue
    const caller = owners.get(index)
    if (caller === undefined || caller.kind !== 'def' || !caller.singleton) continue
    if (caller.header.slice(2).some(token => token.value === receiver)
      || assignmentNames(caller.body).has(receiver)
      || caller.body.some((token, position, all) => ['|', 'for', 'in'].includes(token.value)
        || token.value === receiver && all[position - 1]?.value === '=>')) continue
    const accessors = definitions.filter(item => item.kind === 'def' && item.name === receiver
      && item.singleton === caller.singleton && sameOwner(item.owner, caller.owner))
    if (accessors.length !== 1 || accessors[0]!.header.length !== 2) continue
    const accessor = accessors[0]!
    let value = accessor.body
    if (value[0]?.value.startsWith('@') && value[1]?.value === '||=') {
      const variable = value[0].value
      if (assignmentOccurrences(tokens).filter(name => name === variable).length !== 1) continue
      value = value.slice(2)
    }
    if (value.length !== 3 || value.some(token => token.string) || !/^[A-Z][\w]*$/u.test(value[0]!.value)
      || value[1]?.value !== '.' || value[2]?.value !== 'new' || assignedConstants.has(value[0]!.value)) continue
    const className = value[0]!.value
    let candidate: Block | undefined
    for (let depth = accessor.owner.length; depth >= 0; depth -= 1) {
      const found = definitions.filter(item => item.name === className && item.kind !== 'def'
        && sameOwner(item.owner, accessor.owner.slice(0, depth)))
      if (found.length > 0) {
        if (found.length === 1 && found[0]!.kind === 'class') candidate = found[0]
        break
      }
    }
    if (candidate === undefined) continue
    const owner = [...candidate.owner, candidate.name]
    if (definitions.some(item => item.kind === 'def' && item.singleton && item.name === 'new' && sameOwner(item.owner, owner))) continue
    const methods = definitions.filter(item => item.kind === 'def' && !item.singleton
      && item.name === member && sameOwner(item.owner, owner))
    if (methods.length !== 1 || methods[0]!.header.length !== 2) continue
    if (tokens.some((token, position) => token.value.startsWith('attr_')
      && tokens.slice(position + 1).some(next => next.line === token.line && [receiver, member].includes(next.value)))) continue
    const body = methods[0]!.body
    if (body[0]?.value !== '{' || balancedEnd(body, 0, '{', '}') !== body.length - 1) continue
    emit(body[0], body.at(-1)!, 'same-file options accessor hash')
  }
  return evidence.filter((item, index) => evidence.findIndex(other => JSON.stringify(other) === JSON.stringify(item)) === index)
}

function sameOwner(left: string[], right: string[]): boolean { return left.join('::') === right.join('::') }

function assignmentNames(tokens: Token[]): Set<string> {
  return new Set(assignmentOccurrences(tokens))
}

function assignmentOccurrences(tokens: Token[]): string[] {
  const names: string[] = []
  let start = 0
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.line !== tokens[index - 1]?.line) start = index
    if (['=', '||=', '&&='].includes(tokens[index]!.value)) {
      for (const token of tokens.slice(start, index)) if (!token.string && /^[@A-Za-z_]\w*$/u.test(token.value)) names.push(token.value)
      start = index + 1
    }
  }
  return names
}

function balancedEnd(tokens: Token[], start: number, open: string, close: string): number | undefined {
  let depth = 0
  for (let index = start; index < tokens.length; index += 1) {
    const token = tokens[index]!
    if (token.string) continue
    if (token.value === open) depth += 1
    if (token.value === close && --depth === 0) return index
    if (token.line - tokens[start]!.line > 100) return undefined
  }
  return undefined
}

function blocks(tokens: Token[]): { definitions: Block[]; owners: Map<number, Block>; imported: boolean } | undefined {
  const lines = new Map<number, Token[]>()
  for (const token of tokens) {
    const line = lines.get(token.line) ?? []
    line.push(token)
    if (line.length > 512) return undefined
    lines.set(token.line, line)
  }
  const stack: Block[] = []
  const definitions: Block[] = []
  const owners = new Map<number, Block>()
  let imported = false
  const indexes = new Map(tokens.map((token, index) => [token, index]))
  for (const line of lines.values()) {
    const head = line[0]!
    const current = stack.filter(item => item.kind === 'def').at(-1)
    for (const token of line) {
      if (current !== undefined) owners.set(indexes.get(token)!, current)
      for (const item of stack) if (item.kind === 'def') item.body.push(token)
    }
    if (!head.string && head.value === 'end') {
      if (line.length !== 1 || stack.at(-1)?.indent !== head.column) return undefined
      const ended = stack.pop()!
      if (ended.kind === 'def') ended.body.pop()
      continue
    }
    if (!head.string && head.value === 'require' && line.length === 2 && line[1]?.string
      && line[1].value === 'redis' && stack.length === 0) imported = true
    const blockKind = !head.string && ['class', 'module', 'def', 'if', 'unless', 'case', 'begin', 'while', 'until', 'for'].includes(head.value)
      ? head.value : line.some(token => !token.string && token.value === 'do') ? 'do' : undefined
    if (blockKind === undefined) {
      if (line.some(token => !token.string && ['class', 'module', 'def', 'end', 'do'].includes(token.value))) return undefined
      continue
    }
    const namespaces = stack.filter(item => item.kind === 'module' || item.kind === 'class')
    if (['class', 'module', 'def'].includes(blockKind)
      && stack.some(item => !['class', 'module', 'singleton'].includes(item.kind))) return undefined
    const singleton = blockKind === 'class' && line.map(token => token.value).join(' ') === 'class << self'
    if (['class', 'module'].includes(blockKind) && !singleton
      && (line.length !== 2 || line[1]?.string || !/^[A-Z][\w]*$/u.test(line[1]?.value ?? ''))) return undefined
    if (blockKind === 'def' && (!/^[a-z_][\w]*[!?]?$/u.test(line[1]?.value ?? '')
      || line.length > 2 && line[2]?.value !== '('
      || line.some(token => token.value === '=') || current !== undefined)) return undefined
    const block: Block = { kind: singleton ? 'singleton' : blockKind, name: line[1]?.value ?? '',
      owner: namespaces.map(item => item.name), singleton: stack.some(item => item.kind === 'singleton'),
      header: line, body: [], indent: head.column }
    stack.push(block)
    if (['class', 'module', 'def'].includes(block.kind)) definitions.push(block)
    if (stack.length > 64 || definitions.length > 512) return undefined
  }
  return stack.length === 0 ? { definitions, owners, imported } : undefined
}

function tokenize(content: string): Token[] | undefined {
  if (content.length > 2 * 1024 * 1024 || /\r(?!\n)|[\u2028\u2029]/u.test(content)) return undefined
  const tokens: Token[] = []
  let line = 1
  let column = 1
  let offset = 0
  const advance = (text: string) => {
    for (const character of text) { if (character === '\n') { line += 1; column = 1 } else column += 1 }
    offset += text.length
  }
  while (offset < content.length) {
    const tail = content.slice(offset)
    if (/^\s/u.test(tail)) { advance(tail[0]!); continue }
    if (tail[0] === '#') { advance(tail.match(/^[^\n]*/u)![0]); continue }
    // Reject ambiguous Ruby literal/metaprogramming forms; never scan their
    // contents as executable SDK calls or declarations.
    if (/^(?:[%`/;]|=begin\b|__END__\b)/u.test(tail)) return undefined
    if (tail[0] === '"' || tail[0] === "'") {
      const quote = tail[0]
      let length = 1
      while (length < tail.length && tail[length] !== quote) {
        if (tail[length] === '\\') length += 2
        else length += 1
      }
      if (length >= tail.length) return undefined
      const value = tail.slice(1, length)
      if (quote === '"' && value.includes('#{')) return undefined
      tokens.push({ value, offset, line, column, string: true })
      advance(tail.slice(0, length + 1)); continue
    }
    const match = tail.match(/^(?:@@?[a-zA-Z_]\w*|[a-zA-Z_]\w*[!?]?|\d+|\|\|=|&&=|\*\*|::|<<|&\.|=>|\|\||&&|[.{}()[\]:,=<>+*|&!~?-])/u)
    if (match === null) return undefined
    const value = match[0]
    if (value === '<<' && tokens.at(-1)?.value !== 'class') return undefined
    tokens.push({ value, offset, line, column })
    if (tokens.length > 40_000) return undefined
    advance(value)
  }
  return tokens
}
