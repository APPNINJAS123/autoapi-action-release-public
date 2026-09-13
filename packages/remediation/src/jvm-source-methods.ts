import type { ActionableChangeEvent, RepositoryLanguage } from '@automated-api/contracts'

const IDENTIFIER = '[A-Za-z_$][A-Za-z0-9_$]*'
const FIELD = `\\[{0,255}(?:[BCDFIJSZ]|L${IDENTIFIER}(?:/${IDENTIFIER})*;)`
const DESCRIPTOR = new RegExp(`^(${IDENTIFIER})\\(((?:${FIELD})*)\\)(?:V|${FIELD})?$`, 'u')

/** The detector retains JVM argument descriptors, optionally including a return descriptor. */
export function jvmDescriptorMethodName(symbol: string, language: RepositoryLanguage | undefined): string | undefined {
  if (!['java', 'kotlin', 'scala'].includes(language ?? '') || symbol.length > 4096) return undefined
  return DESCRIPTOR.exec(symbol)?.[1]
}

/**
 * Narrow source bridge: an exact imported/unshadowed or fully qualified nested
 * Builder owner, followed by an inline builder chain. No variable/alias flow is
 * inferred, and build() terminates Builder ownership. Binary symbols stay intact.
 */
export function jvmDescriptorSourceCalls(input: {
  content: string; symbol: string; operation: string; language: RepositoryLanguage;
  importRoots: readonly string[];
  changeEvent: ActionableChangeEvent;
}): number[] {
  const method = jvmDescriptorMethodName(input.symbol, input.language)
  if (method === undefined || input.content.length > 2 * 1024 * 1024) return []
  const witness = reviewedBuilderWitness(input.changeEvent, input.language)
  if (witness === undefined) return []
  const operationOwner = input.operation.match(/^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.Builder(?=\s|$)/u)?.[1]
  const owner = witness.owner.replace(/\.Builder$/u, '')
  if (operationOwner !== owner && operationOwner !== owner.split('.').at(-1)) return []
  if (!witness.selfReturns.some(signature => signature === input.symbol
    || signature.slice(0, signature.indexOf(')') + 1) === input.symbol)) return []
  const code = maskJvmNonCode(input.content)
  // These lexical forms can hide receiver declarations from this deliberately
  // bounded scanner. Java translates Unicode escapes before tokenization.
  if (code.includes('`') || (input.language === 'java' && /\\u+[0-9a-f]{4}/iu.test(input.content))) return []
  const factoryMethod = jvmDescriptorMethodName(witness.factorySignature, input.language)!
  const roots = input.importRoots.filter(root => new RegExp(`^${IDENTIFIER}(?:\\.${IDENTIFIER})*$`, 'u').test(root))
  const imported = [...code.matchAll(new RegExp(`(?:^|\\n)[ \\t]*import[ \\t]+(${IDENTIFIER}(?:\\.${IDENTIFIER})*)(?:[ \\t]+as[ \\t]+(${IDENTIFIER}))?[ \\t]*;?(?=\\r?\\n|$)`, 'gu'))]
  const factories = new Set<string>()
  for (const match of imported) {
    const qualified = match[1]!
    if (!roots.some(root => qualified.startsWith(`${root}.`))) continue
    const nested = qualified === witness.owner
    const outer = qualified === owner
    if (!nested && !outer) continue
    const local = match[2] ?? qualified.split('.').at(-1)!
    if (imported.filter(item => (item[2] ?? item[1]!.split('.').at(-1)) === local).length !== 1) continue
    if (hasShadowedOwner(code, local)) continue
    const escaped = escapeRegex(local)
    if (nested) factories.add(`${escaped}\\s*\\(\\s*\\)`)
    else {
      factories.add(`${escaped}\\s*\\.\\s*${factoryMethod}\\s*\\(\\s*\\)`)
      factories.add(`${escaped}\\s*\\.\\s*Builder\\s*\\(\\s*\\)`)
    }
  }
  const qualifiedOwners = roots.some(root => owner.startsWith(`${root}.`)) ? [owner] : []
  for (const qualified of qualifiedOwners) {
    if (hasShadowedOwner(code, qualified.split('.')[0]!)) continue
    factories.add(`${escapeRegex(qualified)}\\s*\\.\\s*${factoryMethod}\\s*\\(\\s*\\)`)
    factories.add(`${escapeRegex(qualified)}\\s*\\.\\s*Builder\\s*\\(\\s*\\)`)
  }
  const expectedArguments = [...DESCRIPTOR.exec(input.symbol)![2]!.matchAll(new RegExp(FIELD, 'gu'))].length
  const pairs = parenthesisPairs(code)
  const offsets = new Set<number>()
  for (const factory of factories) {
    for (const root of code.matchAll(new RegExp(`(?<![\\w$.])${factory}`, 'gu'))) {
      let cursor = root.index + root[0].length
      for (let depth = 0; depth < 32; depth++) {
        const call = /^\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/u.exec(code.slice(cursor, cursor + 4096))
        if (call === null) break
        const opening = cursor + call[0].length - 1
        const closing = pairs.get(opening)
        if (closing === undefined || closing - root.index > 65536) break
        const name = call[1]!
        const arity = argumentCount(code, opening, closing, pairs)
        // Every link must independently return this exact Builder in the old
        // archive. An unknown method may return an unrelated client or builder.
        const selfReturns = witness.selfReturns.filter(signature => jvmDescriptorMethodName(signature, input.language) === name
          && [...DESCRIPTOR.exec(signature)![2]!.matchAll(new RegExp(FIELD, 'gu'))].length === arity)
        if (selfReturns.length !== 1) break
        if (name === method && arity === expectedArguments) {
          offsets.add(cursor + call[0].indexOf(name))
        }
        cursor = closing + 1
      }
    }
  }
  return [...offsets].sort((left, right) => left - right)
}

/** Public return descriptors structurally read from the exact rights-cleared old JAR. */
function reviewedBuilderWitness(event: ActionableChangeEvent, language: RepositoryLanguage) {
  const oldUrl = 'https://repo1.maven.org/maven2/org/springframework/ai/spring-ai-openai/1.1.7/spring-ai-openai-1.1.7.jar'
  const oldHash = '38df0789a4a889c580a8868347b38c18580669ea17f89d12d6c530154b59e277'
  const newUrl = 'https://repo1.maven.org/maven2/org/springframework/ai/spring-ai-openai/2.0.0-M8/spring-ai-openai-2.0.0-M8.jar'
  const newHash = 'dd956118d84a12b7742979adc2fc67fd398fd72dde759e1980f8ae84036f3a62'
  const dependency = event.affectedDependencies[0]
  if (event.verificationStatus !== 'verified' || event.provider !== 'spring-ai' || event.impactScope !== 'sdk'
    || event.oldVersion !== '1.1.7' || event.newVersion !== '2.0.0-M8'
    || event.affectedLanguages.length !== 1 || event.affectedLanguages[0] !== language
    || event.affectedDependencies.length !== 1 || dependency?.ecosystem !== 'maven'
    || dependency.name !== 'org.springframework.ai:spring-ai-openai'
    || dependency.oldVersionRange !== '1.1.7' || dependency.newVersion !== '2.0.0-M8'
    || dependency.newArtifactSha256 !== newHash
    || event.evidence.filter(item => item.url === oldUrl).length !== 1
    || !event.evidence.some(item => item.url === oldUrl && item.contentHash === oldHash)
    || event.evidence.filter(item => item.url === newUrl).length !== 1
    || !event.evidence.some(item => item.url === newUrl && item.contentHash === newHash)) return undefined
  const returnType = 'Lorg/springframework/ai/openai/OpenAiChatModel$Builder;'
  // The same old JAR also declares OpenAiChatModel.builder() with this return
  // descriptor; constructor expressions name the exact nested type directly.
  return { owner: 'org.springframework.ai.openai.OpenAiChatModel.Builder', factorySignature: `builder()${returnType}`, selfReturns: [
    'defaultOptions(Lorg/springframework/ai/openai/OpenAiChatOptions;)',
    'observationRegistry(Lio/micrometer/observation/ObservationRegistry;)',
    'openAiApi(Lorg/springframework/ai/openai/api/OpenAiApi;)',
    'retryTemplate(Lorg/springframework/retry/support/RetryTemplate;)',
    'toolCallingManager(Lorg/springframework/ai/model/tool/ToolCallingManager;)',
    'toolExecutionEligibilityPredicate(Lorg/springframework/ai/model/tool/ToolExecutionEligibilityPredicate;)',
  ].map(parameters => parameters + returnType) }
}

function hasShadowedOwner(code: string, name: string): boolean {
  const escaped = escapeRegex(name)
  return [
    `\\b(?:class|interface|enum|object|typealias|type|val|var|def|fun)\\s+${escaped}\\b`,
    `(?:[(,]\\s*(?:vararg\\s+)?)${escaped}\\s*:`,
    `\\b${IDENTIFIER}(?:<[^<>\\n]+>)?(?:\\[\\])?\\s+${escaped}\\s*(?=[,;)=])`,
    `\\b${escaped}\\s*=(?!=)`,
    `(?:<|,)\\s*${escaped}\\s*[:>,]`,
    `\\bimport\\s+static\\s+[\\w$.]+\\.(?:${escaped}|\\*)\\s*;`,
    `\\b${escaped}\\s*(?:=>|->)`,
    `(?:\\{|\\(|,)\\s*${escaped}(?:\\s*,\\s*${IDENTIFIER})*\\s*\\)?\\s*(?:=>|->)`,
  ].some(pattern => new RegExp(pattern, 'u').test(code))
}

function parenthesisPairs(code: string): Map<number, number> {
  const stack: number[] = [], pairs = new Map<number, number>()
  for (let index = 0; index < code.length; index++) {
    if (code[index] === '(') stack.push(index)
    else if (code[index] === ')' && stack.length) pairs.set(stack.pop()!, index)
  }
  return pairs
}

function argumentCount(code: string, opening: number, closing: number, pairs: Map<number, number>): number {
  if (!code.slice(opening + 1, closing).trim()) return 0
  let count = 1, brackets = 0, braces = 0
  for (let index = opening + 1; index < closing; index++) {
    if (code[index] === '(') {
      const end = pairs.get(index)
      if (end === undefined || end >= closing) return -1
      index = end
    } else if (code[index] === '[') brackets++
    else if (code[index] === ']') brackets--
    else if (code[index] === '{') braces++
    else if (code[index] === '}') braces--
    else if (code[index] === ',' && brackets === 0 && braces === 0) count++
  }
  // Kotlin and Scala permit a trailing argument comma.
  return code.slice(opening + 1, closing).trimEnd().endsWith(',') ? count - 1 : count
}

function maskJvmNonCode(content: string): string {
  const output = content.split('')
  let index = 0
  while (index < content.length) {
    const start = index
    let literal = false
    if (content.startsWith('//', index)) {
      const end = content.indexOf('\n', index)
      index = end < 0 ? content.length : end
    } else if (content.startsWith('/*', index)) {
      let depth = 1; index += 2
      while (index < content.length && depth) {
        if (content.startsWith('/*', index)) { depth++; index += 2 }
        else if (content.startsWith('*/', index)) { depth--; index += 2 }
        else index++
      }
    } else if (content[index] === '"' || content[index] === "'") {
      literal = true
      const quote = content.startsWith('"""', index) ? '"""' : content[index]!
      index += quote.length
      while (index < content.length) {
        if (content.startsWith(quote, index)) { index += quote.length; break }
        if (quote.length === 1 && content[index] === '\\') index += 2
        else index++
      }
    } else { index++; continue }
    for (let masked = start; masked < Math.min(index, content.length); masked++) {
      if (output[masked] !== '\n' && output[masked] !== '\r') output[masked] = ' '
    }
    if (literal) output[start] = '0'
  }
  return output.join('')
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
}
