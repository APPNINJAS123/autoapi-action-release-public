import type { ActionableChangeEvent, RepositoryImpact } from '@automated-api/contracts'
import {
  Node,
  Project,
  ScriptKind,
  SyntaxKind,
  type CallExpression,
  type CatchClause,
  type IfStatement,
  type SourceFile,
} from 'ts-morph'

export interface HarnessBehaviorFile {
  path: string
  content: string
}

interface ResponseFingerprint {
  receiver: string
  status: number
  keys: string[]
  strings: string[]
}

export type HarnessBehaviorObligation =
  | {
      kind: 'repository_text_migration'
      path: string
      requiredSnippets: string[]
      forbiddenSnippets: string[]
    }
  | {
      kind: 'missing_configuration_guard'
      path: string
      targetConstructor: string
      guardLine: number
      conditionShape: MissingConfigurationConditionShape
      response: ResponseFingerprint
    }
  | {
      kind: 'transport_fallback'
      path: string
      catchLine: number
      response: ResponseFingerprint
    }
  | {
      kind: 'optional_provider_status'
      path: string
      targetErrorType: string
      statusField: string
    }
  | {
      kind: 'provider_error_payload'
      path: string
      targetErrorType: string
      targetPayloadFields: string[]
      sourcePayloadAccess: string
    }
  | {
      kind: 'compatibility_method_preservation'
      path: string
      method: string
      compatibilityProperty: string
    }

/**
 * Derive behavior that the application already guarantees from its source and
 * the hash-bound target SDK declarations. This is deliberately provider-neutral:
 * no package, class, variable, message, or status is hard-coded.
 */
export function deriveHarnessBehaviorObligations(
  changeEvent: ActionableChangeEvent,
  impact: RepositoryImpact,
  files: readonly HarnessBehaviorFile[],
): HarnessBehaviorObligation[] {
  const excerpts = changeEvent.evidence.flatMap(item => item.excerpt?.text ?? []).join('\n')
  const targetConstructors = throwingConfigurationConstructors(changeEvent, excerpts)
  const targetErrorTypes = targetErrorTypeNames(changeEvent)
  const payloadFields = objectPayloadFields(excerpts)
  const optionalStatus = /\bstatus\s*:\s*(?:number\s*\|\s*undefined|undefined\s*\|\s*number|undefined)\b/u.test(excerpts)
  const compatibility = compatibilityContract(changeEvent, impact)
  const affectedPaths = new Set(impact.evidence.flatMap(item => item.location === undefined ? [] : [item.location.path]))
  const obligations: HarnessBehaviorObligation[] = []

  for (const file of files) {
    if (!affectedPaths.has(file.path) || !isJavaScriptFamily(file.path)) continue
    const source = parseSource(file)
    if (source === undefined) continue

    if (compatibility !== undefined) {
      for (const method of compatibility.unmappedMethods) {
        const hasOriginalCall = source.getDescendantsOfKind(SyntaxKind.CallExpression).some(call => {
          const expression = call.getExpression()
          return Node.isPropertyAccessExpression(expression) && expression.getName() === method
        })
        if (hasOriginalCall) obligations.push({
          kind: 'compatibility_method_preservation', path: file.path, method,
          compatibilityProperty: compatibility.property,
        })
      }
    }

    for (const targetConstructor of targetConstructors) {
      for (const guard of missingConfigurationGuards(source)) {
        const response = responseCalls(guard).find(item => item.fingerprint !== undefined)?.fingerprint
        if (response !== undefined) obligations.push({
          kind: 'missing_configuration_guard',
          path: file.path,
          targetConstructor,
          guardLine: guard.getStartLineNumber(),
          conditionShape: missingConfigurationConditionShape(guard.getExpression())!,
          response,
        })
      }
    }

    for (const clause of source.getDescendantsOfKind(SyntaxKind.CatchClause)) {
      const catchVariable = clause.getVariableDeclaration()?.getName()
      if (catchVariable === undefined) continue
      const calls = responseCalls(clause)
      for (const { fingerprint } of calls) {
        if (fingerprint !== undefined) obligations.push({
          kind: 'transport_fallback',
          path: file.path,
          catchLine: clause.getStartLineNumber(),
          response: fingerprint,
        })
      }
      const dynamicPayload = calls.map(item => item.payload)
        .find(payload => payload !== undefined && rootedMemberAccess(payload, catchVariable)
          && /\b(?:response|data|body|payload)\b/iu.test(payload))
      if (dynamicPayload !== undefined && payloadFields.length > 0) {
        for (const targetErrorType of targetErrorTypes) obligations.push({
          kind: 'provider_error_payload',
          path: file.path,
          targetErrorType,
          targetPayloadFields: payloadFields,
          sourcePayloadAccess: dynamicPayload,
        })
      }
    }
    if (optionalStatus) {
      for (const targetErrorType of targetErrorTypes) obligations.push({
        kind: 'optional_provider_status', path: file.path, targetErrorType, statusField: 'status',
      })
    }
  }
  return deduplicateObligations(obligations)
}

export function harnessBehaviorPromptContract(obligations: readonly HarnessBehaviorObligation[]) {
  return obligations.map(obligation => {
    switch (obligation.kind) {
      case 'repository_text_migration':
        return {
          ...obligation,
          requiredBehavior: 'Preserve each required exact repository migration snippet exactly once and remove every forbidden legacy snippet.',
        }
      case 'missing_configuration_guard':
        return {
          ...obligation,
          requiredBehavior: `Every new ${obligation.targetConstructor}(...) must execute after the existing missing-configuration guard response and return.`,
        }
      case 'transport_fallback':
        return {
          ...obligation,
          requiredBehavior: 'Preserve this existing catch fallback for transport, timeout, cancellation, and other errors without an HTTP status.',
        }
      case 'optional_provider_status':
        return {
          ...obligation,
          requiredBehavior: `Never pass a possibly undefined error.${obligation.statusField} to an HTTP response. Narrow it or retain the application fallback.`,
        }
      case 'provider_error_payload':
        return {
          ...obligation,
          requiredBehavior: `Preserve the provider payload using one of the evidence-backed target fields: ${obligation.targetPayloadFields.join(', ')}.`,
        }
      case 'compatibility_method_preservation':
        return {
          ...obligation,
          requiredBehavior: `The official migration evidence provides no replacement for ${obligation.method} but preserves it through the compatibility namespace. Keep the behavior by calling <client>.${obligation.compatibilityProperty}.${obligation.method}(...); do not delete it, replace it with a throw, or silently no-op.`,
        }
    }
  })
}

/** Validate model output against the derived source/SDK behavior contract. */
export function findHarnessBehaviorViolations(
  obligations: readonly HarnessBehaviorObligation[],
  resultingFiles: readonly HarnessBehaviorFile[],
): string[] {
  const files = new Map(resultingFiles.map(file => [file.path, file]))
  const violations: string[] = []
  const byPath = new Map<string, HarnessBehaviorObligation[]>()
  for (const obligation of obligations) {
    byPath.set(obligation.path, [...(byPath.get(obligation.path) ?? []), obligation])
  }
  for (const [path, pathObligations] of byPath) {
    const file = files.get(path)
    if (file === undefined) {
      violations.push(`${path}: behavior-contract source is missing`)
      continue
    }
    const repositoryTextObligations = pathObligations.filter(obligation =>
      obligation.kind === 'repository_text_migration')
    for (const obligation of repositoryTextObligations) {
      for (const snippet of obligation.requiredSnippets) {
        if (file.content.split(snippet).length - 1 !== 1) {
          violations.push(`${path}: required repository migration snippet must occur exactly once: ${snippet}`)
        }
      }
      for (const snippet of obligation.forbiddenSnippets) {
        if (file.content.includes(snippet)) {
          violations.push(`${path}: forbidden legacy repository snippet remains: ${snippet}`)
        }
      }
    }
    const sourceObligations = pathObligations.filter(obligation =>
      obligation.kind !== 'repository_text_migration')
    if (sourceObligations.length === 0) continue
    const source = parseSource(file)
    if (source === undefined) {
      violations.push(`${path}: migrated source could not be parsed for behavior validation`)
      continue
    }
    const catches = source.getDescendantsOfKind(SyntaxKind.CatchClause)
    for (const obligation of sourceObligations) {
      switch (obligation.kind) {
        case 'missing_configuration_guard': {
          const matchingGuard = missingConfigurationGuards(source).find(guard =>
            responseCalls(guard).some(call => call.fingerprint !== undefined
              && sameFingerprint(call.fingerprint, obligation.response))
            && missingConfigurationConditionShape(guard.getExpression())
              === obligation.conditionShape)
          if (matchingGuard === undefined) {
            violations.push(`${path}: existing missing-configuration guard response/return was not preserved`)
            break
          }
          const guardEnd = matchingGuard.getEnd()
          const constructors = source.getDescendantsOfKind(SyntaxKind.NewExpression)
            .filter(expression => expression.getExpression().getText() === obligation.targetConstructor)
          if (constructors.length === 0) {
            violations.push(`${path}: target constructor ${obligation.targetConstructor}(...) is missing`)
          } else if (constructors.some(expression => expression.getStart() < guardEnd)) {
            violations.push(`${path}: ${obligation.targetConstructor}(...) executes before the existing missing-configuration guard returns`)
          }
          break
        }
        case 'transport_fallback': {
          const retained = catches.some(clause => responseCalls(clause).some(call =>
            call.fingerprint !== undefined && sameFingerprint(call.fingerprint, obligation.response)))
          if (!retained) violations.push(
            `${path}: existing HTTP ${obligation.response.status} transport-error fallback payload was not preserved`,
          )
          break
        }
        case 'optional_provider_status': {
          for (const clause of catches) {
            const catchVariable = clause.getVariableDeclaration()?.getName()
            if (catchVariable === undefined || !catchHandlesType(clause, obligation.targetErrorType)) continue
            for (const statusCall of statusCalls(clause)) {
              const argument = statusCall.getArguments()[0]
              if (argument === undefined
                || argument.getText() !== `${catchVariable}.${obligation.statusField}`) continue
              if (!statusIsNarrowed(statusCall, catchVariable, obligation.statusField)) {
                violations.push(
                  `${path}: possibly undefined ${catchVariable}.${obligation.statusField} is passed to an HTTP status without a guard or fallback`,
                )
              }
            }
            const providerPayloadFields = pathObligations.flatMap(item =>
              item.kind === 'provider_error_payload' && item.targetErrorType === obligation.targetErrorType
                ? item.targetPayloadFields : [])
            for (const response of responseCalls(clause)) {
              if (!providerPayloadFields.some(field => response.payload === `${catchVariable}.${field}`)) continue
              if (!statusIsNarrowed(response.call, catchVariable, obligation.statusField)) {
                violations.push(
                  `${path}: provider error payload can bypass the existing transport fallback when ${catchVariable}.${obligation.statusField} is undefined; narrow the provider-error branch before selecting its payload`,
                )
              }
            }
          }
          break
        }
        case 'provider_error_payload': {
          const retained = catches.some(clause => {
            const catchVariable = clause.getVariableDeclaration()?.getName()
            if (catchVariable === undefined || !catchHandlesType(clause, obligation.targetErrorType)) return false
            return responseCalls(clause).some(call => call.payload !== undefined
              && obligation.targetPayloadFields.some(field => call.payload === `${catchVariable}.${field}`))
          })
          if (!retained) violations.push(
            `${path}: provider error payload was replaced instead of using ${obligation.targetPayloadFields.join(' or ')}`,
          )
          break
        }
        case 'compatibility_method_preservation': {
          const retained = source.getDescendantsOfKind(SyntaxKind.CallExpression).some(call => {
            const expression = call.getExpression()
            if (!Node.isPropertyAccessExpression(expression) || expression.getName() !== obligation.method) return false
            const receiver = expression.getExpression()
            return Node.isPropertyAccessExpression(receiver)
              && receiver.getName() === obligation.compatibilityProperty
          })
          if (!retained) violations.push(
            `${path}: ${obligation.method} behavior was not preserved through .${obligation.compatibilityProperty}.${obligation.method}(...)`,
          )
          break
        }
      }
    }
  }
  return [...new Set(violations)]
}

function compatibilityContract(changeEvent: ActionableChangeEvent, impact: RepositoryImpact): {
  property: string
  unmappedMethods: string[]
} | undefined {
  const instructions = changeEvent.operations.flatMap(operation => {
    const value = operation.details?.instructions
    return typeof value === 'string' ? [value] : []
  }).join('\n')
  const compatibility = instructions.match(
    /compatibility layer is available under\s+[A-Za-z_$][\w$]*\.([A-Za-z_$][\w$]*)\s+with the original method names/iu,
  )
  if (compatibility?.[1] === undefined) return undefined
  const renamed = new Set([...instructions.matchAll(
    /\b([A-Za-z_$][\w$]*)\s*\([^)]*\)\s+is replaced by\s+[A-Za-z_$][\w$]*\s*\(/giu,
  )].flatMap(match => match[1] === undefined ? [] : [match[1]]))
  const sdkReceivers = new Set(impact.evidence.flatMap(evidence => {
    if (evidence.kind !== 'sdk_call' || evidence.operation.endsWith('.result_usage')) return []
    const separator = evidence.operation.lastIndexOf('.')
    if (separator < 1 || !renamed.has(evidence.operation.slice(separator + 1))) return []
    return [evidence.operation.slice(0, separator)]
  }))
  const methods = impact.evidence.flatMap(evidence => {
    if (evidence.kind !== 'sdk_call' || evidence.operation.endsWith('.result_usage')) return []
    const separator = evidence.operation.lastIndexOf('.')
    const receiver = separator < 1 ? undefined : evidence.operation.slice(0, separator)
    const method = separator < 1 ? undefined : evidence.operation.slice(separator + 1)
    return receiver === undefined || method === undefined || !sdkReceivers.has(receiver) || renamed.has(method)
      ? [] : [method]
  })
  return { property: compatibility[1], unmappedMethods: [...new Set(methods)] }
}

function parseSource(file: HarnessBehaviorFile): SourceFile | undefined {
  try {
    const project = new Project({ useInMemoryFileSystem: true, skipAddingFilesFromTsConfig: true })
    const scriptKind = /\.(?:jsx|js|mjs|cjs)$/u.test(file.path) ? ScriptKind.JS : ScriptKind.TS
    return project.createSourceFile(file.path, file.content, { scriptKind, overwrite: true })
  } catch {
    return undefined
  }
}

function isJavaScriptFamily(path: string): boolean {
  return /\.(?:[cm]?[jt]sx?)$/iu.test(path)
}

function throwingConfigurationConstructors(changeEvent: ActionableChangeEvent, excerpts: string): string[] {
  if (!/\bconstructor\s*\([^)]*\)[\s\S]{0,8000}\bthrow\s+new\b/u.test(excerpts)
    || !/\b(?:missing|required|api.?key|token|credential|configuration)\b/iu.test(excerpts)) return []
  return [...new Set(changeEvent.operations.flatMap(operation => {
    const symbol = operation.newSymbol
    return symbol !== undefined
      && /^[A-Z_$][\w$]*$/u.test(symbol)
      && /(?:client|constructor|initiali[sz]|configuration)/iu.test(`${operation.operation} ${JSON.stringify(operation.details)}`)
      ? [symbol]
      : []
  }))]
}

function targetErrorTypeNames(changeEvent: ActionableChangeEvent): string[] {
  return [...new Set(changeEvent.operations.flatMap(operation => {
    const symbol = operation.newSymbol
    return symbol !== undefined && /(?:^|\.)[A-Z_$][\w$]*(?:Error|Exception)$/u.test(symbol) ? [symbol] : []
  }))]
}

function objectPayloadFields(excerpts: string): string[] {
  const fields = [...excerpts.matchAll(/\b(?:readonly\s+)?([A-Za-z_$][\w$]*)\??\s*:\s*([^;\n}]+)/gu)]
    .flatMap(match => match[1] !== undefined && /\b(?:Object|unknown|Record|Json|JSON|Map)\b/u.test(match[2] ?? '')
      && /(?:error|data|body|payload|response)/iu.test(match[1]) ? [match[1]] : [])
  return [...new Set(fields)]
}

type MissingConfigurationConditionShape = `${'falsy' | 'nullish' | 'empty'}:${string}`

function missingConfigurationGuards(source: SourceFile): IfStatement[] {
  return source.getDescendantsOfKind(SyntaxKind.IfStatement).filter(statement => {
    const condition = statement.getExpression().getText()
    return /(?:api.?key|token|credential|config)/iu.test(condition)
      && missingConfigurationConditionShape(statement.getExpression()) !== undefined
      && statement.getThenStatement().getDescendantsOfKind(SyntaxKind.ReturnStatement).length > 0
      && responseCalls(statement.getThenStatement()).some(call => call.fingerprint !== undefined)
  })
}

function missingConfigurationConditionShape(
  condition: Node,
): MissingConfigurationConditionShape | undefined {
  const expression = unwrapParentheses(condition)
  if (Node.isPrefixUnaryExpression(expression)
    && expression.getOperatorToken() === SyntaxKind.ExclamationToken) {
    const credential = credentialKind(expression.getOperand())
    return credential === undefined ? undefined : `falsy:${credential}`
  }
  if (!Node.isBinaryExpression(expression)) return undefined
  const operator = expression.getOperatorToken().getKind()
  if (![SyntaxKind.EqualsEqualsToken, SyntaxKind.EqualsEqualsEqualsToken].includes(operator)) {
    return undefined
  }
  const left = unwrapParentheses(expression.getLeft())
  const right = unwrapParentheses(expression.getRight())
  const leftCredential = credentialKind(left)
  const rightCredential = credentialKind(right)
  if (leftCredential !== undefined && isNullishLiteral(right)) return `nullish:${leftCredential}`
  if (rightCredential !== undefined && isNullishLiteral(left)) return `nullish:${rightCredential}`
  if (leftCredential !== undefined && isEmptyStringLiteral(right)) return `empty:${leftCredential}`
  if (rightCredential !== undefined && isEmptyStringLiteral(left)) return `empty:${rightCredential}`
  return undefined
}

function unwrapParentheses(node: Node): Node {
  let current = node
  while (Node.isParenthesizedExpression(current)) current = current.getExpression()
  return current
}

function credentialKind(node: Node): string | undefined {
  const expression = unwrapParentheses(node)
  const name = Node.isPropertyAccessExpression(expression)
    ? expression.getName()
    : Node.isElementAccessExpression(expression)
      ? expression.getArgumentExpression()?.getText().replace(/^['"]|['"]$/gu, '')
      : Node.isIdentifier(expression) ? expression.getText() : undefined
  if (name === undefined) return undefined
  const normalized = name.toLowerCase().replaceAll(/[^a-z0-9]/gu, '')
  if (normalized.endsWith('apikey')) return 'api_key'
  if (normalized.endsWith('accesstoken')) return 'access_token'
  if (normalized.endsWith('token')) return 'token'
  if (normalized.endsWith('credential')) return 'credential'
  return undefined
}

function isNullishLiteral(node: Node): boolean {
  return node.getKind() === SyntaxKind.NullKeyword
    || (Node.isIdentifier(node) && node.getText() === 'undefined')
}

function isEmptyStringLiteral(node: Node): boolean {
  return (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node))
    && node.getLiteralText() === ''
}

function responseCalls(node: Node): Array<{ call: CallExpression, fingerprint?: ResponseFingerprint, payload?: string }> {
  return node.getDescendantsOfKind(SyntaxKind.CallExpression).flatMap(call => {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression) || expression.getName() !== 'json') return []
    const statusCall = expression.getExpression()
    if (!Node.isCallExpression(statusCall)) return []
    const statusExpression = statusCall.getExpression()
    if (!Node.isPropertyAccessExpression(statusExpression) || statusExpression.getName() !== 'status') return []
    const receiver = statusExpression.getExpression().getText()
    const statusArgument = statusCall.getArguments()[0]
    const payload = call.getArguments()[0]?.getText()
    const numericStatus = statusArgument !== undefined && Node.isNumericLiteral(statusArgument)
      ? Number(statusArgument.getLiteralText()) : undefined
    const fingerprint = numericStatus === undefined || payload === undefined ? undefined : {
      receiver,
      status: numericStatus,
      keys: objectKeys(call.getArguments()[0]!),
      strings: call.getArguments()[0]!.getDescendantsOfKind(SyntaxKind.StringLiteral)
        .map(literal => literal.getLiteralText()).sort(),
    }
    return [{ call, ...(fingerprint === undefined ? {} : { fingerprint }), ...(payload === undefined ? {} : { payload }) }]
  })
}

function statusCalls(node: Node): CallExpression[] {
  return node.getDescendantsOfKind(SyntaxKind.CallExpression).filter(call => {
    const expression = call.getExpression()
    return Node.isPropertyAccessExpression(expression) && expression.getName() === 'status'
  })
}

function objectKeys(node: Node): string[] {
  if (!Node.isObjectLiteralExpression(node)) return []
  return node.getDescendantsOfKind(SyntaxKind.PropertyAssignment)
    .map(property => property.getName()).sort()
}

function rootedMemberAccess(value: string, root: string): boolean {
  return value === root || value.startsWith(`${root}.`) || value.startsWith(`${root}[`)
}

function sameFingerprint(left: ResponseFingerprint, right: ResponseFingerprint): boolean {
  return left.receiver === right.receiver && left.status === right.status
    && JSON.stringify(left.keys) === JSON.stringify(right.keys)
    && JSON.stringify(left.strings) === JSON.stringify(right.strings)
}

function catchHandlesType(clause: CatchClause, targetErrorType: string): boolean {
  return clause.getBlock().getText().includes(`instanceof ${targetErrorType}`)
}

function statusIsNarrowed(call: CallExpression, variable: string, field: string): boolean {
  const access = `${variable}.${field}`
  for (let current: Node | undefined = call; current !== undefined; current = current.getParent()) {
    if (Node.isIfStatement(current)) {
      const thenBranch = current.getThenStatement()
      const elseBranch = current.getElseStatement()
      const isInside = (branch: Node) => call.getStart() >= branch.getStart() && call.getEnd() <= branch.getEnd()
      const conditionIsTrue = isInside(thenBranch) ? true
        : elseBranch !== undefined && isInside(elseBranch) ? false : undefined
      if (conditionIsTrue !== undefined
        && conditionProvesDefinedStatus(current.getExpression(), access, conditionIsTrue)) return true
    }
    if (Node.isCatchClause(current)) break
  }
  return false
}

function conditionProvesDefinedStatus(node: Node, access: string, truthy: boolean): boolean {
  const condition = unwrapParentheses(node)
  if (Node.isPrefixUnaryExpression(condition) && condition.getOperatorToken() === SyntaxKind.ExclamationToken) {
    return conditionProvesDefinedStatus(condition.getOperand(), access, !truthy)
  }
  if (condition.getText() === access) return truthy
  if (!Node.isBinaryExpression(condition)) return false
  const operator = condition.getOperatorToken().getKind()
  const left = unwrapParentheses(condition.getLeft())
  const right = unwrapParentheses(condition.getRight())
  if (operator === SyntaxKind.AmpersandAmpersandToken || operator === SyntaxKind.BarBarToken) {
    const leftProves = conditionProvesDefinedStatus(left, access, truthy)
    const rightProves = conditionProvesDefinedStatus(right, access, truthy)
    // Both conjuncts hold on the true branch; both disjuncts fail on the
    // false branch. The opposite paths need a proof from each alternative.
    return (operator === SyntaxKind.AmpersandAmpersandToken) === truthy
      ? leftProves || rightProves : leftProves && rightProves
  }
  const equality = operator === SyntaxKind.EqualsEqualsEqualsToken || operator === SyntaxKind.EqualsEqualsToken
  const inequality = operator === SyntaxKind.ExclamationEqualsEqualsToken || operator === SyntaxKind.ExclamationEqualsToken
  if (!equality && !inequality) return false
  const equalOnPath = equality === truthy
  for (const [expression, value] of [[left, right], [right, left]]) {
    if (expression === undefined || value === undefined) continue
    if (Node.isTypeOfExpression(expression) && expression.getExpression().getText() === access
      && Node.isStringLiteral(value)) {
      if (value.getLiteralText() === 'number') return equalOnPath
      if (value.getLiteralText() === 'undefined') return !equalOnPath
    }
    if (expression.getText() === access && !equalOnPath) {
      if (Node.isIdentifier(value) && value.getText() === 'undefined') return true
      if (value.getKind() === SyntaxKind.NullKeyword
        && (operator === SyntaxKind.EqualsEqualsToken || operator === SyntaxKind.ExclamationEqualsToken)) return true
    }
  }
  return false
}

function deduplicateObligations(obligations: HarnessBehaviorObligation[]): HarnessBehaviorObligation[] {
  const seen = new Set<string>()
  return obligations.filter(obligation => {
    const key = JSON.stringify(obligation)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
