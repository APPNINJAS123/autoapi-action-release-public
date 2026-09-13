import { readFile, writeFile } from 'node:fs/promises'
import { relative, resolve, sep } from 'node:path'
import type { ActionableChangeEvent, RepositoryImpact } from '@automated-api/contracts'
import {
  Node,
  Project,
  SyntaxKind,
  VariableDeclarationKind,
  type CallExpression,
  type Identifier,
  type ImportDeclaration,
  type NewExpression,
  type PropertyAccessExpression,
  type SourceFile,
  type VariableDeclaration,
} from 'ts-morph'
import { UnsafeMigrationError, type RecipeResult } from './recipe.js'

export interface PackageMigration {
  from: string
  to: string
  targetVersion: string
  legacyMaxMajor: number
  legacyVersions?: readonly string[]
}

export interface ReviewedProviderRecipe {
  id: string
  provider: string
  documentationUrl: string
  packages: readonly PackageMigration[]
  addedPackages?: Readonly<Record<string, string>>
  addedPackageAnchors?: readonly string[]
  kind:
    | 'package_only'
    | 'slack_upload'
    | 'openai_v3_v4'
    | 'openrouter_agent'
    | 'supabase_auth_admin'
    | 'neon_query'
    | 'clerk_metadata'
  minimumNodeMajor?: number
}

export interface RecipeUsage {
  position: number
  operation: string
  detail: string
  supported: boolean
}

export const REVIEWED_PROVIDER_RECIPES: readonly ReviewedProviderRecipe[] = Object.freeze([
  {
    id: 'github-octokit-v21-v22',
    provider: 'github',
    documentationUrl: 'https://github.com/octokit/rest.js/releases/tag/v22.0.0',
    packages: [{ from: '@octokit/rest', to: '@octokit/rest', targetVersion: '22.0.1', legacyMaxMajor: 21 }],
    kind: 'package_only',
    minimumNodeMajor: 22,
  },
  {
    id: 'slack-files-upload-v2',
    provider: 'slack',
    documentationUrl: 'https://docs.slack.dev/tools/node-slack-sdk/web-api/#upload-a-file',
    packages: [{ from: '@slack/web-api', to: '@slack/web-api', targetVersion: '8.0.0', legacyMaxMajor: 7 }],
    kind: 'slack_upload',
    minimumNodeMajor: 20,
  },
  {
    id: 'twilio-node-v5-v6',
    provider: 'twilio',
    documentationUrl: 'https://github.com/twilio/twilio-node/releases/tag/6.0.0',
    packages: [{ from: 'twilio', to: 'twilio', targetVersion: '6.1.0', legacyMaxMajor: 5 }],
    kind: 'package_only',
    minimumNodeMajor: 20,
  },
  {
    id: 'openai-node-v3-v4',
    provider: 'openai',
    documentationUrl: 'https://github.com/openai/openai-node/discussions/217',
    packages: [{ from: 'openai', to: 'openai', targetVersion: '4.0.0', legacyMaxMajor: 3 }],
    kind: 'openai_v3_v4',
    minimumNodeMajor: 22,
  },
  {
    id: 'openai-node-v6-v7',
    provider: 'openai',
    documentationUrl: 'https://github.com/openai/openai-node/releases/tag/v7.0.0',
    packages: [{
      from: 'openai',
      to: 'openai',
      targetVersion: '7.6.0',
      legacyMaxMajor: 6,
    }],
    kind: 'package_only',
    minimumNodeMajor: 22,
  },
  {
    id: 'google-maps-node-v2-v3',
    provider: 'google-maps',
    documentationUrl: 'https://github.com/googlemaps/google-maps-services-js/releases/tag/v3.0.0',
    packages: [{
      from: '@googlemaps/google-maps-services-js',
      to: '@googlemaps/google-maps-services-js',
      targetVersion: '3.4.2',
      legacyMaxMajor: 2,
    }],
    kind: 'package_only',
    minimumNodeMajor: 22,
  },
  {
    id: 'openrouter-agent-package-split',
    provider: 'openrouter',
    documentationUrl: 'https://openrouter.ai/docs/agent-sdk/agent-migration',
    packages: [],
    addedPackages: { '@openrouter/agent': '0.9.0' },
    addedPackageAnchors: ['@openrouter/sdk'],
    kind: 'openrouter_agent',
    minimumNodeMajor: 22,
  },
  {
    id: 'supabase-js-v1-v2',
    provider: 'supabase',
    documentationUrl: 'https://supabase.com/blog/supabase-js-v2',
    packages: [{
      from: '@supabase/supabase-js',
      to: '@supabase/supabase-js',
      targetVersion: '2.112.3',
      legacyMaxMajor: 1,
    }],
    kind: 'supabase_auth_admin',
    minimumNodeMajor: 20,
  },
  {
    id: 'neon-serverless-v0-v1',
    provider: 'neon',
    documentationUrl: 'https://neon.com/blog/serverless-driver-ga',
    packages: [{
      from: '@neondatabase/serverless',
      to: '@neondatabase/serverless',
      targetVersion: '1.1.0',
      legacyMaxMajor: 0,
    }],
    kind: 'neon_query',
    minimumNodeMajor: 20,
  },
  {
    id: 'clerk-backend-v2-v3',
    provider: 'clerk',
    documentationUrl: 'https://clerk.com/docs/guides/development/upgrading/upgrade-guides/core-3',
    packages: [{ from: '@clerk/backend', to: '@clerk/backend', targetVersion: '3.16.10', legacyMaxMajor: 2 }],
    kind: 'clerk_metadata',
    minimumNodeMajor: 20,
  },
  {
    id: 'vercel-sdk-v1-refresh',
    provider: 'vercel',
    documentationUrl: 'https://vercel.com/docs/rest-api/sdk',
    packages: [{
      from: '@vercel/sdk',
      to: '@vercel/sdk',
      targetVersion: '1.28.21',
      legacyMaxMajor: 1,
      legacyVersions: ['1.1.0', '1.28.20'],
    }],
    kind: 'package_only',
    minimumNodeMajor: 22,
  },
])

const recipeById = new Map(REVIEWED_PROVIDER_RECIPES.map(recipe => [recipe.id, recipe]))

export function reviewedRecipeForEvent(event: ActionableChangeEvent): ReviewedProviderRecipe | undefined {
  const matches = event.recipeIds
    .map(id => recipeById.get(id))
    .filter((recipe): recipe is ReviewedProviderRecipe => recipe !== undefined)
    .filter(recipe => recipe.provider === event.provider.toLowerCase())
  return matches.length === 1 ? matches[0] : undefined
}

export function reviewedRecipeDependencies(event: ActionableChangeEvent): Array<{ name: string; version: string }> {
  const recipe = reviewedRecipeForEvent(event)
  if (recipe === undefined) return []
  const entries = [
    ...recipe.packages.map(rule => ({ name: rule.to, version: rule.targetVersion })),
    ...Object.entries(recipe.addedPackages ?? {}).map(([name, version]) => ({ name, version })),
  ]
  return [...new Map(entries.map(item => [item.name, item])).values()]
}

export function declaredMajor(range: string): number | undefined {
  const match = range.match(/(?:^|[^0-9])(\d+)(?:\.\d+|\.x|$)/u)
  return match?.[1] === undefined ? undefined : Number(match[1])
}

export function matchesLegacyPackageVersion(
  declared: string,
  rule: PackageMigration,
): boolean {
  const version = declared.match(/(?:^|[^0-9])(\d+\.\d+\.\d+)(?:[^0-9]|$)/u)?.[1]
  if (rule.legacyVersions !== undefined) return version !== undefined && rule.legacyVersions.includes(version)
  const major = declaredMajor(declared)
  return major !== undefined && major <= rule.legacyMaxMajor
}

export function inspectReviewedRecipeSource(
  sourceFile: SourceFile,
  recipe: ReviewedProviderRecipe,
): RecipeUsage[] {
  switch (recipe.kind) {
    case 'package_only':
      return []
    case 'slack_upload':
      return inspectSlack(sourceFile)
    case 'openai_v3_v4':
      return inspectOpenAi(sourceFile)
    case 'openrouter_agent':
      return inspectOpenRouter(sourceFile)
    case 'supabase_auth_admin':
      return inspectSupabase(sourceFile)
    case 'neon_query':
      return inspectNeon(sourceFile)
    case 'clerk_metadata':
      return inspectClerk(sourceFile)
  }
}

export async function applyReviewedProviderRecipe(
  rootDirInput: string,
  impact: RepositoryImpact,
  event: ActionableChangeEvent,
): Promise<RecipeResult> {
  const recipe = reviewedRecipeForEvent(event)
  if (recipe === undefined) throw new UnsafeMigrationError('no reviewed provider recipe matches this ActionableChangeEvent')
  if (impact.outcome === 'affected_manual' || impact.outcome === 'blocked') {
    throw new UnsafeMigrationError(`deterministic recipe refused impact outcome ${impact.outcome}`)
  }
  if (impact.outcome === 'not_affected') {
    return { recipeId: recipe.id, changedFiles: [], notes: ['repository is not affected'] }
  }
  if (impact.evidence.some(item => !item.deterministicRecipeSupported)) {
    throw new UnsafeMigrationError('deterministic recipe refused unsupported impact evidence')
  }

  const rootDir = resolve(rootDirInput)
  const project = sourceProject(rootDir)
  const originals = new Map(project.getSourceFiles().map(file => [file, file.getFullText()]))
  for (const sourceFile of project.getSourceFiles()) transformSource(sourceFile, recipe)

  const changedFiles: string[] = []
  for (const sourceFile of project.getSourceFiles()) {
    if (sourceFile.getFullText() === originals.get(sourceFile)) continue
    await sourceFile.save()
    changedFiles.push(relativePath(rootDir, sourceFile.getFilePath()))
  }
  if (await migrateManifest(rootDir, recipe)) changedFiles.push('package.json')
  changedFiles.sort()
  return {
    recipeId: recipe.id,
    changedFiles,
    notes: changedFiles.length === 0
      ? ['recipe was already applied']
      : [`applied reviewed migration ${recipe.id} from ${recipe.documentationUrl}`],
  }
}

function inspectSlack(sourceFile: SourceFile): RecipeUsage[] {
  const clients = variablesInitializedByNew(
    sourceFile,
    namedImportBindings(sourceFile, '@slack/web-api', 'WebClient'),
  )
  const usages: RecipeUsage[] = []
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression) || !matchesClientPath(expression, clients, ['files', 'upload'])) continue
    const options = call.getArguments()[0]
    const channels = Node.isObjectLiteralExpression(options) ? options.getProperty('channels') : undefined
    const initializer = Node.isPropertyAssignment(channels) ? channels.getInitializer() : undefined
    const supported = Node.isPropertyAssignment(channels)
      && Node.isStringLiteral(initializer)
      && !initializer.getLiteralText().includes(',')
    usages.push(usage(call, 'files.upload', 'Slack files.upload → filesUploadV2', supported))
  }
  return usages
}

function inspectOpenAi(sourceFile: SourceFile): RecipeUsage[] {
  const bindings = openAiBindings(sourceFile)
  const usages: RecipeUsage[] = []
  for (const declaration of bindings.unsupportedImports) {
    usages.push(usage(declaration, 'openai_import', 'mixed or incomplete OpenAI v3 imports', false))
  }
  for (const expression of bindings.unsupportedClients) {
    usages.push(usage(expression, 'openai_client', 'OpenAI v3 client construction is outside the reviewed shape', false))
  }
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (Node.isPropertyAccessExpression(expression)
      && matchesClientPath(expression, bindings.clients, ['createChatCompletion'])) {
      usages.push(usage(
        call,
        'createChatCompletion',
        'OpenAI createChatCompletion → chat.completions.create',
        reviewedOpenAiResponse(call) !== undefined,
      ))
    }
    const dynamicReceiver = Node.isElementAccessExpression(expression)
      ? expression.getExpression()
      : undefined
    if (Node.isIdentifier(dynamicReceiver)
      && identifierMatchesBindings(dynamicReceiver, bindings.clients)) {
      usages.push(usage(call, 'dynamic_sdk_method', 'dynamic OpenAI method selection', false))
    }
  }
  return usages
}

const OPENROUTER_IMPORTS = new Map([
  ['@openrouter/sdk/funcs/call-model', '@openrouter/agent/call-model'],
  ['@openrouter/sdk/lib/model-result', '@openrouter/agent/model-result'],
  ['@openrouter/sdk/lib/tool', '@openrouter/agent/tool'],
  ['@openrouter/sdk/lib/tool-types', '@openrouter/agent/tool-types'],
  ['@openrouter/sdk/lib/stop-conditions', '@openrouter/agent/stop-conditions'],
  ['@openrouter/sdk/lib/async-params', '@openrouter/agent/async-params'],
])

function inspectOpenRouter(sourceFile: SourceFile): RecipeUsage[] {
  const usages: RecipeUsage[] = []
  for (const declaration of sourceFile.getImportDeclarations()) {
    const module = declaration.getModuleSpecifierValue()
    if (OPENROUTER_IMPORTS.has(module)) {
      usages.push(usage(declaration, 'agent_import', `${module} moved to ${OPENROUTER_IMPORTS.get(module)}`, true))
      continue
    }
    if (module === '@openrouter/sdk' && declaration.getNamedImports().some(item =>
      ['callModel', 'tool', 'stepCountIs', 'hasToolCall'].includes(item.getName()),
    )) {
      usages.push(usage(declaration, 'agent_barrel_import', 'OpenRouter agent barrel imports require manual splitting', false))
    }
  }
  return usages
}

function inspectSupabase(sourceFile: SourceFile): RecipeUsage[] {
  const clients = variablesInitializedByCall(
    sourceFile,
    namedImportBindings(sourceFile, '@supabase/supabase-js', 'createClient'),
  )
  const usages = sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)
    .filter(expression => matchesClientPath(expression, clients, ['auth', 'api']))
    .map(expression => usage(expression, 'auth.api', 'auth.api → auth.admin', true))
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.ElementAccessExpression)) {
    const argument = expression.getArgumentExpression()
    if (!Node.isStringLiteral(argument) || argument.getLiteralText() !== 'api') continue
    const receiver = expression.getExpression()
    if (!Node.isPropertyAccessExpression(receiver)
      || !matchesClientPath(receiver, clients, ['auth'])) continue
    usages.push(usage(
      expression,
      'auth.api',
      'computed Supabase auth["api"] access requires Harness review',
      false,
    ))
  }
  return usages
}

function inspectNeon(sourceFile: SourceFile): RecipeUsage[] {
  const sqlNames = neonQueryNames(sourceFile)
  const usages: RecipeUsage[] = []
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isIdentifier(expression) || !identifierMatchesBindings(expression, sqlNames)) continue
    usages.push(usage(
      call,
      'conventional_query',
      'Neon conventional query function → sql.query',
      call.getArguments().length === 2,
    ))
  }
  return usages
}

function inspectClerk(sourceFile: SourceFile): RecipeUsage[] {
  const clients = variablesInitializedByCall(
    sourceFile,
    namedImportBindings(sourceFile, '@clerk/backend', 'createClerkClient'),
  )
  const usages: RecipeUsage[] = []
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression)) continue
    if (matchesClientPath(expression, clients, ['apiKeys', 'verifySecret'])) {
      usages.push(usage(
        call,
        'apiKeys.verifySecret',
        'Clerk apiKeys.verifySecret → apiKeys.verify',
        call.getArguments().length === 1,
      ))
      continue
    }
    if (!matchesClientPath(expression, clients, ['users', 'updateUser'])) continue
    const options = call.getArguments()[1]
    const supported = Node.isObjectLiteralExpression(options)
      && options.getProperties().every(property => Node.isPropertyAssignment(property)
        && ['publicMetadata', 'privateMetadata', 'unsafeMetadata'].includes(property.getName()))
    usages.push(usage(call, 'updateUser', 'Clerk updateUser metadata → updateUserMetadata', supported))
  }
  return usages
}

function transformSource(sourceFile: SourceFile, recipe: ReviewedProviderRecipe): void {
  switch (recipe.kind) {
    case 'package_only':
      return
    case 'slack_upload':
      transformSlack(sourceFile)
      return
    case 'openai_v3_v4':
      transformOpenAi(sourceFile)
      return
    case 'openrouter_agent':
      transformOpenRouter(sourceFile)
      return
    case 'supabase_auth_admin':
      transformSupabase(sourceFile)
      return
    case 'neon_query':
      transformNeon(sourceFile)
      return
    case 'clerk_metadata':
      transformClerk(sourceFile)
      return
  }
}

function transformSlack(sourceFile: SourceFile): void {
  const clients = variablesInitializedByNew(
    sourceFile,
    namedImportBindings(sourceFile, '@slack/web-api', 'WebClient'),
  )
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression) || !matchesClientPath(expression, clients, ['files', 'upload'])) continue
    const options = call.getArguments()[0]
    if (!Node.isObjectLiteralExpression(options)) throw new UnsafeMigrationError('Slack upload options must be literal')
    const channels = options.getProperty('channels')
    const initializer = Node.isPropertyAssignment(channels) ? channels.getInitializer() : undefined
    if (!Node.isPropertyAssignment(channels) || !Node.isStringLiteral(initializer)) {
      throw new UnsafeMigrationError('Slack channels must be one literal channel')
    }
    const channel = initializer.getLiteralText()
    if (channel.includes(',')) throw new UnsafeMigrationError('Slack filesUploadV2 supports one channel per upload')
    channels.getNameNode().replaceWithText('channel_id')
    expression.replaceWithText(expression.getText().replace(/\.files\.upload$/u, '.filesUploadV2'))
  }
}

function transformOpenAi(sourceFile: SourceFile): void {
  const bindings = openAiBindings(sourceFile)
  if (!bindings.hasLegacyImport) return
  if (bindings.unsupportedImports.length > 0 || bindings.unsupportedClients.length > 0
    || bindings.importDeclaration === undefined || bindings.defaultClientName === undefined) {
    throw new UnsafeMigrationError('OpenAI v3 imports and client construction must match the reviewed shape')
  }
  const responses = emptyBindings()
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression)
      || !matchesClientPath(expression, bindings.clients, ['createChatCompletion'])) continue
    const response = reviewedOpenAiResponse(call)
    if (response === undefined) {
      throw new UnsafeMigrationError(
        'OpenAI createChatCompletion responses require a direct const declaration',
      )
    }
    expression.replaceWithText(`${expression.getExpression().getText()}.chat.completions.create`)
    responses.names.add(response.name.getText())
    responses.declarations.add(response.declaration.getStart())
  }
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    if (expression.getName() !== 'data') continue
    const receiver = expression.getExpression()
    if (Node.isIdentifier(receiver) && identifierMatchesBindings(receiver, responses)) {
      expression.replaceWithText(receiver.getText())
    }
  }
  for (const expression of bindings.clientExpressions) {
    const configuration = expression.getArguments()[0]
    if (!Node.isNewExpression(configuration)) {
      throw new UnsafeMigrationError('OpenAIApi configuration must be inline for deterministic migration')
    }
    const options = configuration.getArguments()[0]?.getText() ?? '{}'
    expression.replaceWithText(`new ${bindings.defaultClientName}(${options})`)
  }
  bindings.importDeclaration.removeNamedImports()
  bindings.importDeclaration.setDefaultImport(bindings.defaultClientName)
}

function transformOpenRouter(sourceFile: SourceFile): void {
  for (const declaration of sourceFile.getImportDeclarations()) {
    const replacement = OPENROUTER_IMPORTS.get(declaration.getModuleSpecifierValue())
    if (replacement !== undefined) declaration.setModuleSpecifier(replacement)
  }
}

function transformSupabase(sourceFile: SourceFile): void {
  const clients = variablesInitializedByCall(
    sourceFile,
    namedImportBindings(sourceFile, '@supabase/supabase-js', 'createClient'),
  )
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    if (matchesClientPath(expression, clients, ['auth', 'api'])) {
      expression.getNameNode().replaceWithText('admin')
    }
  }
}

function transformNeon(sourceFile: SourceFile): void {
  const sqlNames = neonQueryNames(sourceFile)
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isIdentifier(expression) || !identifierMatchesBindings(expression, sqlNames)) continue
    if (call.getArguments().length !== 2) {
      throw new UnsafeMigrationError('Neon conventional query must provide SQL and values')
    }
    expression.replaceWithText(`${expression.getText()}.query`)
  }
}

function transformClerk(sourceFile: SourceFile): void {
  const clients = variablesInitializedByCall(
    sourceFile,
    namedImportBindings(sourceFile, '@clerk/backend', 'createClerkClient'),
  )
  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (!Node.isPropertyAccessExpression(expression)) continue
    if (matchesClientPath(expression, clients, ['apiKeys', 'verifySecret'])) {
      if (call.getArguments().length !== 1) {
        throw new UnsafeMigrationError('Clerk apiKeys.verifySecret requires one secret argument')
      }
      expression.getNameNode().replaceWithText('verify')
      continue
    }
    if (!matchesClientPath(expression, clients, ['users', 'updateUser'])) continue
    const options = call.getArguments()[1]
    if (!Node.isObjectLiteralExpression(options) || options.getProperties().some(property =>
      !Node.isPropertyAssignment(property)
      || !['publicMetadata', 'privateMetadata', 'unsafeMetadata'].includes(property.getName()),
    )) {
      throw new UnsafeMigrationError('Clerk updateUser mixes metadata with other user fields')
    }
    expression.getNameNode().replaceWithText('updateUserMetadata')
  }
}

function neonQueryNames(sourceFile: SourceFile): IdentifierBindings {
  return variablesInitializedByCall(
    sourceFile,
    namedImportBindings(sourceFile, '@neondatabase/serverless', 'neon'),
  )
}

interface OpenAiBindings {
  hasLegacyImport: boolean
  importDeclaration: ImportDeclaration | undefined
  defaultClientName: string | undefined
  clients: IdentifierBindings
  clientExpressions: NewExpression[]
  unsupportedImports: Node[]
  unsupportedClients: Node[]
}

function openAiBindings(sourceFile: SourceFile): OpenAiBindings {
  const imports = sourceFile.getImportDeclarations().filter(item => item.getModuleSpecifierValue() === 'openai')
  const relevant = imports.filter(item => item.getNamedImports().some(named =>
    named.getName() === 'Configuration' || named.getName() === 'OpenAIApi',
  ))
  const unsupportedImports: Node[] = []
  const declaration = relevant.length === 1 ? relevant[0] : undefined
  if (relevant.length !== 1) unsupportedImports.push(...relevant)
  if (declaration !== undefined) {
    const names = declaration.getNamedImports().map(item => item.getName())
    if (declaration.getDefaultImport() !== undefined
      || declaration.getNamespaceImport() !== undefined
      || names.length !== 2
      || !names.includes('Configuration')
      || !names.includes('OpenAIApi')) {
      unsupportedImports.push(declaration)
    }
  }
  const configurationNames = namedImportBindings(sourceFile, 'openai', 'Configuration')
  const apiNames = namedImportBindings(sourceFile, 'openai', 'OpenAIApi')
  const apiLocalName = [...apiNames.names][0]
  const defaultClientName = apiLocalName === undefined
    ? undefined
    : apiLocalName === 'OpenAIApi' ? 'OpenAI' : apiLocalName
  if (defaultClientName === 'OpenAI' && sourceFile.getDescendantsOfKind(SyntaxKind.Identifier).some(identifier =>
    identifier.getText() === 'OpenAI' && identifier.getFirstAncestorByKind(SyntaxKind.ImportDeclaration) === undefined,
  )) {
    if (declaration !== undefined) unsupportedImports.push(declaration)
  }

  const clients = emptyBindings()
  const clientExpressions: NewExpression[] = []
  const unsupportedClients: Node[] = []
  const allowedLegacyReferences = new Set<number>()
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    const constructor = expression.getExpression()
    if (!Node.isIdentifier(constructor) || !identifierMatchesBindings(constructor, apiNames)) continue
    const configuration = expression.getArguments()[0]
    const configurationConstructor = Node.isNewExpression(configuration)
      ? configuration.getExpression()
      : undefined
    const declarationNode = expression.getFirstAncestorByKind(SyntaxKind.VariableDeclaration)
    const name = declarationNode?.getNameNode()
    if (!Node.isNewExpression(configuration)
      || !Node.isIdentifier(configurationConstructor)
      || !identifierMatchesBindings(configurationConstructor, configurationNames)
      || expression.getArguments().length !== 1
      || configuration.getArguments().length > 1
      || declarationNode?.getInitializer() !== expression
      || !Node.isIdentifier(name)) {
      unsupportedClients.push(expression)
      continue
    }
    clients.names.add(name.getText())
    clients.declarations.add(declarationNode.getStart())
    clientExpressions.push(expression)
    allowedLegacyReferences.add(constructor.getStart())
    allowedLegacyReferences.add(configurationConstructor.getStart())
  }
  const legacyNames = new Set([...configurationNames.names, ...apiNames.names])
  for (const identifier of sourceFile.getDescendantsOfKind(SyntaxKind.Identifier)) {
    if (!legacyNames.has(identifier.getText())
      || identifier.getFirstAncestorByKind(SyntaxKind.ImportDeclaration) !== undefined
      || allowedLegacyReferences.has(identifier.getStart())) continue
    unsupportedClients.push(identifier)
  }
  return {
    hasLegacyImport: relevant.length > 0,
    importDeclaration: declaration,
    defaultClientName,
    clients,
    clientExpressions,
    unsupportedImports,
    unsupportedClients,
  }
}

interface IdentifierBindings {
  names: Set<string>
  declarations: Set<number>
}

function emptyBindings(): IdentifierBindings {
  return { names: new Set(), declarations: new Set() }
}

function namedImportBindings(sourceFile: SourceFile, module: string, imported: string): IdentifierBindings {
  const bindings = emptyBindings()
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== module) continue
    for (const specifier of declaration.getNamedImports()) {
      if (specifier.getName() !== imported) continue
      bindings.names.add(specifier.getAliasNode()?.getText() ?? specifier.getName())
      bindings.declarations.add(specifier.getStart())
    }
  }
  return bindings
}

function variablesInitializedByCall(sourceFile: SourceFile, factories: IdentifierBindings): IdentifierBindings {
  return variablesInitializedBy(sourceFile, factories, Node.isCallExpression)
}

function variablesInitializedByNew(sourceFile: SourceFile, constructors: IdentifierBindings): IdentifierBindings {
  return variablesInitializedBy(sourceFile, constructors, Node.isNewExpression)
}

function variablesInitializedBy(
  sourceFile: SourceFile,
  bindings: IdentifierBindings,
  predicate: (node: Node | undefined) => node is CallExpression | NewExpression,
): IdentifierBindings {
  const variables = emptyBindings()
  for (const declaration of sourceFile.getVariableDeclarations()) {
    const initializer = declaration.getInitializer()
    if (!predicate(initializer)) continue
    const expression = initializer.getExpression()
    const name = declaration.getNameNode()
    if (Node.isIdentifier(expression) && identifierMatchesBindings(expression, bindings) && Node.isIdentifier(name)) {
      variables.names.add(name.getText())
      variables.declarations.add(declaration.getStart())
    }
  }
  return variables
}

function matchesClientPath(
  expression: PropertyAccessExpression,
  clients: IdentifierBindings,
  path: readonly string[],
): boolean {
  const segments: string[] = []
  let current: Node = expression
  while (Node.isPropertyAccessExpression(current)) {
    segments.unshift(current.getName())
    current = current.getExpression()
  }
  return Node.isIdentifier(current)
    && identifierMatchesBindings(current, clients)
    && segments.length === path.length
    && segments.every((segment, index) => segment === path[index])
}

function identifierMatchesBindings(identifier: Identifier, bindings: IdentifierBindings): boolean {
  if (!bindings.names.has(identifier.getText())) return false
  const sourceFile = identifier.getSourceFile()
  const matchesLocalDeclaration = (declaration: Node): boolean =>
    declaration.getSourceFile().getFilePath() === sourceFile.getFilePath()
      && bindings.declarations.has(declaration.getStart())
  if ((identifier.getSymbol()?.getDeclarations() ?? []).some(matchesLocalDeclaration)) return true
  return identifier.getDefinitions().some(definition => {
    const declaration = definition.getDeclarationNode()
    return declaration !== undefined && matchesLocalDeclaration(declaration)
  })
}

export async function applyReviewedProviderDependencyUpdate(
  rootDirInput: string,
  event: ActionableChangeEvent,
): Promise<boolean> {
  const recipe = reviewedRecipeForEvent(event)
  return recipe === undefined ? false : migrateManifest(resolve(rootDirInput), recipe)
}

function reviewedOpenAiResponse(
  call: CallExpression,
): { declaration: VariableDeclaration; name: Identifier } | undefined {
  const declaration = call.getFirstAncestorByKind(SyntaxKind.VariableDeclaration)
  if (declaration === undefined) return undefined
  const name = declaration.getNameNode()
  if (!Node.isIdentifier(name)) return undefined
  const declarationList = declaration.getFirstAncestorByKind(SyntaxKind.VariableDeclarationList)
  if (declarationList?.getDeclarationKind() !== VariableDeclarationKind.Const) return undefined
  const initializer = declaration.getInitializer()
  const responseCall = Node.isAwaitExpression(initializer) ? initializer.getExpression() : initializer
  if (!Node.isCallExpression(responseCall) || responseCall.getStart() !== call.getStart()) return undefined
  const binding: IdentifierBindings = {
    names: new Set([name.getText()]),
    declarations: new Set([declaration.getStart()]),
  }
  for (const identifier of call.getSourceFile().getDescendantsOfKind(SyntaxKind.Identifier)) {
    if (identifier.getStart() === name.getStart() || !identifierMatchesBindings(identifier, binding)) continue
    const access = identifier.getParent()
    if (!Node.isPropertyAccessExpression(access)
      || access.getExpression().getStart() !== identifier.getStart()
      || access.getName() !== 'data'
      || isWriteAccess(access)) return undefined
  }
  return { declaration, name }
}

function isWriteAccess(access: PropertyAccessExpression): boolean {
  const parent = access.getParent()
  if (Node.isBinaryExpression(parent)
    && parent.getLeft().getStart() === access.getStart()
    && assignmentOperators.has(parent.getOperatorToken().getText())) return true
  if (Node.isPrefixUnaryExpression(parent)) {
    const operator = parent.getOperatorToken()
    return operator === SyntaxKind.PlusPlusToken || operator === SyntaxKind.MinusMinusToken
  }
  if (Node.isPostfixUnaryExpression(parent)) return true
  return parent?.getKind() === SyntaxKind.DeleteExpression
}

const assignmentOperators = new Set([
  '=', '+=', '-=', '*=', '/=', '%=', '**=', '&&=', '||=', '??=',
  '<<=', '>>=', '>>>=', '&=', '|=', '^=',
])

async function migrateManifest(rootDir: string, recipe: ReviewedProviderRecipe): Promise<boolean> {
  const path = resolve(rootDir, 'package.json')
  const manifest = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
  let changed = false
  let addedPackagesPlaced = false
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[field]
    if (!isStringRecord(dependencies)) continue
    for (const rule of recipe.packages) {
      const declared = dependencies[rule.from]
      if (declared === undefined || !matchesLegacyPackageVersion(declared, rule)) continue
      if (rule.from !== rule.to) delete dependencies[rule.from]
      dependencies[rule.to] = rule.targetVersion
      changed = true
    }
    const isAnchoredSection = (recipe.addedPackageAnchors ?? [])
      .some(name => dependencies[name] !== undefined)
    if (isAnchoredSection) {
      for (const [name, version] of Object.entries(recipe.addedPackages ?? {})) {
        if (dependencies[name] === version) continue
        dependencies[name] = version
        changed = true
      }
      addedPackagesPlaced = recipe.addedPackages !== undefined
    }
    if (changed) manifest[field] = sortRecord(dependencies)
  }
  if (!addedPackagesPlaced && recipe.addedPackages !== undefined) {
    const dependencies = isStringRecord(manifest.dependencies) ? manifest.dependencies : {}
    for (const [name, version] of Object.entries(recipe.addedPackages)) {
      if (dependencies[name] === version) continue
      dependencies[name] = version
      changed = true
    }
    manifest.dependencies = sortRecord(dependencies)
  }
  if (!changed) return false
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return true
}

function sourceProject(rootDir: string): Project {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    manipulationSettings: { useTrailingCommas: false },
    compilerOptions: { allowJs: true, checkJs: false, skipLibCheck: true },
  })
  project.addSourceFilesAtPaths([
    `${globRoot(rootDir)}/**/*.ts`,
    `${globRoot(rootDir)}/**/*.tsx`,
    `${globRoot(rootDir)}/**/*.js`,
    `${globRoot(rootDir)}/**/*.jsx`,
    `!${globRoot(rootDir)}/node_modules/**`,
    `!${globRoot(rootDir)}/dist/**`,
    `!${globRoot(rootDir)}/build/**`,
  ])
  return project
}

function usage(node: Node, operation: string, detail: string, supported: boolean): RecipeUsage {
  return { position: node.getStart(), operation, detail, supported }
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.values(value).every(item => typeof item === 'string')
}

function sortRecord(value: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)))
}

function globRoot(path: string): string {
  return path.split(sep).join('/')
}

function relativePath(rootDir: string, path: string): string {
  return relative(rootDir, path).split(sep).join('/')
}
