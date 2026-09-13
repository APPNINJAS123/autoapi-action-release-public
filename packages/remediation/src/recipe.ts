import { readFile, writeFile } from 'node:fs/promises'
import { relative, resolve, sep } from 'node:path'
import type { RepositoryImpact } from '@automated-api/contracts'
import {
  Node,
  Project,
  SyntaxKind,
  type CallExpression,
  type ObjectLiteralExpression,
  type SourceFile,
} from 'ts-morph'

export const FIRECRAWL_V1_V2_RECIPE_ID = 'firecrawl-typescript-v1-v2' as const
// Migration recipes pin the exact package version they were tested against.
// A range here would make the same verified ChangeEvent produce different
// lockfiles over time and makes an offline dependency cache impossible to
// prepare reliably.
export const FIRECRAWL_TARGET_PACKAGE_VERSION = '4.34.0' as const
const LEGACY_PACKAGE = '@mendable/firecrawl-js'
const LEGACY_CLASS = 'FirecrawlApp'
const CURRENT_CLASS = 'Firecrawl'

export const FIRECRAWL_DETERMINISTIC_METHOD_MIGRATIONS: ReadonlyMap<string, string> = new Map([
  ['scrapeUrl', 'scrape'],
  ['crawlUrl', 'crawl'],
  ['asyncCrawlUrl', 'startCrawl'],
  ['checkCrawlStatus', 'getCrawlStatus'],
  ['checkCrawlErrors', 'getCrawlErrors'],
])

export interface RecipeResult {
  recipeId: string
  changedFiles: string[]
  notes: string[]
}

export class UnsafeMigrationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UnsafeMigrationError'
  }
}

export async function applyFirecrawlV1ToV2Recipe(
  rootDirInput: string,
  impact: RepositoryImpact,
): Promise<RecipeResult> {
  if (impact.outcome === 'affected_manual' || impact.outcome === 'blocked') {
    throw new UnsafeMigrationError(`deterministic recipe refused impact outcome ${impact.outcome}`)
  }
  if (impact.outcome === 'not_affected') {
    return { recipeId: FIRECRAWL_V1_V2_RECIPE_ID, changedFiles: [], notes: ['repository is not affected'] }
  }
  if (impact.evidence.some(item => !item.deterministicRecipeSupported)) {
    throw new UnsafeMigrationError('deterministic recipe refused unsupported impact evidence')
  }

  const rootDir = resolve(rootDirInput)
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

  const originals = new Map<SourceFile, string>()
  for (const sourceFile of project.getSourceFiles()) originals.set(sourceFile, sourceFile.getFullText())

  // Project-wide context, matching the analyzer: the file that calls
  // client.scrapeUrl() often is not the file that imports the SDK.
  const context = projectClientContext(project.getSourceFiles())
  for (const sourceFile of project.getSourceFiles()) migrateSourceFile(sourceFile, context)

  const changedFiles: string[] = []
  for (const sourceFile of project.getSourceFiles()) {
    if (sourceFile.getFullText() === originals.get(sourceFile)) continue
    await sourceFile.save()
    changedFiles.push(toRelative(rootDir, sourceFile.getFilePath()))
  }

  if (await migratePackageManifest(rootDir)) changedFiles.push('package.json')

  changedFiles.sort()
  return {
    recipeId: FIRECRAWL_V1_V2_RECIPE_ID,
    changedFiles,
    notes: changedFiles.length === 0
      ? ['recipe was already applied']
      : ['migrated official Firecrawl v1 SDK methods and literal REST endpoints to v2'],
  }
}

export async function applyFirecrawlV1ToV2DependencyUpdate(rootDirInput: string): Promise<boolean> {
  return migratePackageManifest(resolve(rootDirInput))
}

function migrateSourceFile(sourceFile: SourceFile, context: ClientContext): void {
  migrateImports(sourceFile)

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression()
    if (Node.isPropertyAccessExpression(expression) && isClientReceiver(expression.getExpression(), context)) {
      const oldMethod = expression.getName()
      const newMethod = FIRECRAWL_DETERMINISTIC_METHOD_MIGRATIONS.get(oldMethod)
      if (newMethod === undefined) continue
      migrateOptions(call)
      expression.getNameNode().replaceWithText(newMethod)
      continue
    }
    if (Node.isElementAccessExpression(expression) && isClientReceiver(expression.getExpression(), context)) {
      throw new UnsafeMigrationError('dynamic Firecrawl method reached deterministic recipe')
    }
  }

  const rawEndpoint = /https:\/\/api\.firecrawl\.dev\/v1\/(scrape|crawl)(?:[/?#]|$)/u
  for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
    const value = literal.getLiteralText()
    if (rawEndpoint.test(value)) literal.setLiteralValue(value.replace('/v1/', '/v2/'))
  }
  // Template literals carry the same endpoints and must migrate too, otherwise
  // the analyzer reports the repository affected and the recipe leaves the v1
  // URL in place. replaceWithText keeps the surrounding backticks intact.
  for (const literal of sourceFile.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
    const value = literal.getLiteralText()
    if (rawEndpoint.test(value)) {
      literal.replaceWithText(`\`${value.replace('/v1/', '/v2/')}\``)
    }
  }
  for (const template of sourceFile.getDescendantsOfKind(SyntaxKind.TemplateExpression)) {
    const head = template.getHead()
    if (rawEndpoint.test(head.getLiteralText())) {
      head.replaceWithText(head.getText().replace('/v1/', '/v2/'))
    }
    for (const span of template.getTemplateSpans()) {
      const middleOrTail = span.getLiteral()
      if (rawEndpoint.test(middleOrTail.getLiteralText())) {
        middleOrTail.replaceWithText(middleOrTail.getText().replace('/v1/', '/v2/'))
      }
    }
  }
}

function migrateImports(sourceFile: SourceFile): void {
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== LEGACY_PACKAGE) continue
    const defaultImport = declaration.getDefaultImport()

    // Named `FirecrawlApp` imports must be rewritten too. v2 exports
    // `Firecrawl`; leaving the named import alone emits a symbol that does not
    // compile. The reviewed v2 artifact retains the exact scoped npm identity.
    for (const namedImport of declaration.getNamedImports()) {
      if (namedImport.getName() !== LEGACY_CLASS) continue
      const alias = namedImport.getAliasNode()?.getText()
      if (alias !== undefined) {
        // `{ FirecrawlApp as X }` -> `{ Firecrawl as X }`; call sites use X.
        namedImport.getNameNode().replaceWithText(CURRENT_CLASS)
        continue
      }
      // `{ FirecrawlApp }` -> `{ Firecrawl as FirecrawlApp }` so every existing
      // reference in the file keeps resolving without a project-wide rename.
      namedImport.getNameNode().replaceWithText(CURRENT_CLASS)
      namedImport.setAlias(LEGACY_CLASS)
    }

    if (defaultImport === undefined) continue
    const localName = defaultImport.getText()
    declaration.removeDefaultImport()
    if (localName === CURRENT_CLASS) declaration.addNamedImport(CURRENT_CLASS)
    else declaration.addNamedImport({ name: CURRENT_CLASS, alias: localName })
  }

}

function migrateOptions(call: CallExpression): void {
  const options = call.getArguments()[1]
  if (options === undefined) return
  if (!Node.isObjectLiteralExpression(options)) {
    throw new UnsafeMigrationError('non-literal Firecrawl options reached deterministic recipe')
  }
  migrateOptionObject(options)
}

function migrateOptionObject(options: ObjectLiteralExpression): void {
  for (const property of [...options.getProperties()]) {
    if (!Node.isPropertyAssignment(property)) {
      if (Node.isSpreadAssignment(property) || Node.isShorthandPropertyAssignment(property)) {
        throw new UnsafeMigrationError('spread or shorthand Firecrawl options are not deterministic')
      }
      continue
    }
    const name = property.getName()
    const initializer = property.getInitializer()
    if (initializer === undefined) throw new UnsafeMigrationError(`Firecrawl option ${name} has no initializer`)

    // Rename the name node in place rather than calling property.rename(),
    // which is a language-service symbol rename. With no tsconfig and no
    // node_modules loaded these option literals have no resolved symbol, so a
    // symbol rename can reach unrelated identically-named properties elsewhere
    // in the project and inflate the diff. Method renames below already use
    // the local form; this makes the option renames consistent with them.
    if (name === 'maxDepth') property.getNameNode().replaceWithText('maxDiscoveryDepth')
    if (name === 'allowBackwardCrawling') property.getNameNode().replaceWithText('crawlEntireDomain')
    if (name === 'ignoreSitemap') {
      if (!Node.isTrueLiteral(initializer) && !Node.isFalseLiteral(initializer)) {
        throw new UnsafeMigrationError('dynamic ignoreSitemap option is not deterministic')
      }
      const skip = Node.isTrueLiteral(initializer)
      property.getNameNode().replaceWithText('sitemap')
      property.setInitializer(skip ? '"skip"' : '"include"')
    }
    if (name === 'parsePDF') {
      if (!Node.isTrueLiteral(initializer) && !Node.isFalseLiteral(initializer)) {
        throw new UnsafeMigrationError('dynamic parsePDF option is not deterministic')
      }
      const parsers = Node.isTrueLiteral(initializer) ? '["pdf"]' : '[]'
      property.replaceWithText(`parsers: ${parsers}`)
    }
    if (name === 'formats') {
      if (!Node.isArrayLiteralExpression(initializer)) {
        throw new UnsafeMigrationError('dynamic formats option is not deterministic')
      }
      for (const element of initializer.getElements()) {
        if (!Node.isStringLiteral(element)) continue
        if (element.getLiteralText() === 'extract') {
          throw new UnsafeMigrationError('extract format needs an explicit JSON prompt/schema migration')
        }
        if (element.getLiteralText() === 'screenshot@fullPage') {
          element.replaceWithText('{ type: "screenshot", fullPage: true }')
        }
      }
    }
  }
}

interface ClientContext {
  classNames: Set<string>
  receiverNames: Set<string>
}

function projectClientContext(sourceFiles: SourceFile[]): ClientContext {
  const classNames = new Set<string>()
  const receiverNames = new Set<string>()
  for (const sourceFile of sourceFiles) {
    const local = clientContext(sourceFile)
    for (const name of local.classNames) classNames.add(name)
    for (const name of local.receiverNames) receiverNames.add(name)
  }
  return { classNames, receiverNames }
}

function clientContext(sourceFile: SourceFile): ClientContext {
  const classNames = new Set<string>()
  for (const declaration of sourceFile.getImportDeclarations()) {
    if (declaration.getModuleSpecifierValue() !== LEGACY_PACKAGE) continue
    const defaultImport = declaration.getDefaultImport()
    if (defaultImport !== undefined) classNames.add(defaultImport.getText())
    for (const namedImport of declaration.getNamedImports()) {
      classNames.add(namedImport.getAliasNode()?.getText() ?? namedImport.getName())
    }
  }
  for (const declaration of sourceFile.getVariableDeclarations()) {
    const initializer = declaration.getInitializer()
    if (!Node.isCallExpression(initializer) || initializer.getExpression().getText() !== 'require') continue
    const argument = initializer.getArguments()[0]
    if (Node.isStringLiteral(argument) && argument.getLiteralText() === LEGACY_PACKAGE) {
      classNames.add(declaration.getName())
    }
  }

  const receiverNames = new Set<string>()
  for (const expression of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    if (!classNames.has(expression.getExpression().getText())) continue
    const parent = expression.getParent()
    if (Node.isVariableDeclaration(parent) || Node.isPropertyDeclaration(parent)) {
      receiverNames.add(parent.getName())
    }
  }
  return { classNames, receiverNames }
}

function isClientReceiver(receiver: Node, context: ClientContext): boolean {
  if (Node.isNewExpression(receiver)) return context.classNames.has(receiver.getExpression().getText())
  if (Node.isIdentifier(receiver)) return context.receiverNames.has(receiver.getText())
  if (Node.isPropertyAccessExpression(receiver)) return context.receiverNames.has(receiver.getName())
  return false
}

async function migratePackageManifest(rootDir: string): Promise<boolean> {
  const path = resolve(rootDir, 'package.json')
  let raw: string
  try {
    raw = await readFile(path, 'utf8')
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return false
    throw error
  }
  const manifest = JSON.parse(raw) as Record<string, unknown>
  let changed = false
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[field]
    if (!isStringRecord(dependencies) || dependencies[LEGACY_PACKAGE] === undefined) continue
    dependencies[LEGACY_PACKAGE] = FIRECRAWL_TARGET_PACKAGE_VERSION
    manifest[field] = sortRecord(dependencies)
    changed = true
  }
  if (!changed) return false
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return true
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

function toRelative(rootDir: string, path: string): string {
  return relative(rootDir, path).split(sep).join('/')
}
