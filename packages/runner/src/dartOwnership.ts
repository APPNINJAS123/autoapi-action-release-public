import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { StringDecoder } from 'node:string_decoder'
import { parseDocument } from 'yaml'
import type { ImpactEvidence, MigrationJob, RepositoryPolicy } from '@automated-api/contracts'
import type { PreservedAffectedUsageWindow } from '@automated-api/remediation'
import { assertPathAllowed, sha256 } from '@automated-api/remediation'
import { readToolchainCertification } from './toolchainCertification.js'
import { scanTextForSecrets } from './secrets.js'
import { OPENAI_DART_062_FILES } from './dartSdk062Manifest.js'

const OLD_ARCHIVE = '037605a210cb3b1d8ac72b11a4ace26f25ee9267aaf981d2af1d7f0524adcbf5'
const NEW_ARCHIVE = 'f9fd52b5306bf70f3269f81ba09b02df7f98c97294da9b98c0daaccb4bc5630a'
const DART_RUNTIME = 'dart@sha256:78ec6a5fd1834ad0f5816e314ef8ca2abbf49c1fb8b9019ee5ba69890435110f'
const DECLARATIONS = new Set(['FUNCTION', 'METHOD', 'CONSTRUCTOR', 'GETTER', 'SETTER', 'FIELD', 'TOP_LEVEL_VARIABLE', 'TYPE_ALIAS'])
const SKIP_DIRECTORIES = new Set(['.git', '.dart_tool', 'node_modules', 'build', '.pub-cache'])
const LIMIT_BYTES = 256 * 1024 * 1024
const LIMIT_FILES = 12_000
const LIMIT_RESPONSE_BYTES = 32 * 1024 * 1024

interface DartPackage { name: string; rootUri: string; packageUri: string; languageVersion: string }
interface ShadowFile { path: string; source: string; shadowPath: string }
export interface DartOwnershipShadow {
  root: string
  repository: string
  sdkRoot: string
  packageConfig: string
  files: ShadowFile[]
  packageConfigHash: string
}
interface Outline {
  element: { kind: string; name: string }
  codeOffset: number
  codeLength: number
  children?: Outline[]
}
interface Navigation {
  files: string[]
  targets: Array<{ fileIndex: number; offset: number; length: number }>
  regions: Array<{ offset: number; length: number; targets: number[] }>
}

export function isReviewedDartPackageMigration(job: MigrationJob): boolean {
  const event = job.changeEvent
  return event.verificationStatus === 'verified'
    && event.oldVersion === '0.6.2' && event.newVersion === '1.0.1'
    && event.affectedLanguages.length === 1 && event.affectedLanguages[0] === 'dart'
    && event.affectedDependencies.some(dependency => dependency.ecosystem === 'pub'
      && dependency.name === 'openai_dart' && dependency.newVersion === '1.0.1'
      && dependency.newArtifactSha256 === NEW_ARCHIVE)
    && event.operations.some(operation => operation.operation === 'package migration'
      && operation.oldSymbol === 'openai_dart@0.6.2' && operation.newSymbol === 'openai_dart@1.0.1')
}

export function isResolvedDartOwnershipEvidence(item: ImpactEvidence): boolean {
  return item.kind === 'sdk_call' && item.language === 'dart' && item.ecosystem === 'pub'
    && item.operation === 'package migration' && item.location !== undefined
    && Number.isSafeInteger(item.location.line) && item.location.line >= 1
    && Number.isSafeInteger(item.location.endLine) && item.location.endLine! >= item.location.line
    && item.location.endLine! - item.location.line <= 1000
    && /^Dart 3\.10\.0 resolved openai_dart@0\.6\.2 ownership in declaration "(?:[^"\\\r\n]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"; package graph [a-f0-9]{64}; SDK archive 037605a210cb3b1d8ac72b11a4ace26f25ee9267aaf981d2af1d7f0524adcbf5$/u.test(item.detail)
}

export function certifiedDartRepairUsageWindows(job: MigrationJob): PreservedAffectedUsageWindow[] {
  if (!isReviewedDartPackageMigration(job)) return []
  const impact = job.repairContext?.validatedImpact
  const scope = job.repairContext?.validatedEditScope
  if (impact === undefined || scope === undefined) return []
  const reviewedPaths = new Set(scope.files.map(file => file.path))
  return impact.evidence.filter(item => isResolvedDartOwnershipEvidence(item)
    && item.location !== undefined && reviewedPaths.has(item.location.path)).map(item => ({
    path: item.location!.path,
    start: item.location!.line,
    end: item.location!.endLine!,
  }))
}

// Only the post-install, network-disabled proposal container receives this
// certificate. Initial impact analysis must not turn unresolved names into
// ownership claims or run a customer analyzer/plugin configuration.
export async function resolvedDartOwnership(job: MigrationJob, rootDir: string): Promise<ImpactEvidence[]> {
  if (!isReviewedDartPackageMigration(job)) return []
  const certificatePath = process.env['AUTOMATED_API_TOOLCHAIN_CERTIFICATE']
  if (certificatePath === undefined) return []
  const certificate = await readToolchainCertification(certificatePath)
  if (certificate.jobId !== job.id || certificate.baseSha !== job.baseSha
    || certificate.manager.name !== 'dart' || certificate.manager.version !== '3.10.0'
    || certificate.manager.spec !== 'dart@3.10.0' || certificate.manager.variant !== 'dart-pub'
    || certificate.runtime.dart !== '3.10.0' || !certificate.runtimeImages.includes(DART_RUNTIME)
    || certificate.lockfile?.path !== 'pubspec.lock'
    || certificate.lockfile.beforeHash !== certificate.lockfile.afterHash) {
    throw new Error('resolved Dart analysis requires the exact certified job, base, runtime, and original lockfile')
  }
  const root = await realpath(rootDir)
  const managerRoot = await containedPath(root, job.repository.packageManagerDirectory ?? job.repository.workingDirectory)
  const lock = await boundedFile(resolve(managerRoot, 'pubspec.lock'), 4 * 1024 * 1024)
  if (sha256(lock) !== certificate.lockfile.beforeHash) {
    throw new Error('resolved Dart analysis lockfile differs from its offline certificate')
  }
  const cache = process.env['PUB_CACHE']
  if (cache !== '/opt/dependency-cache/pub') throw new Error('resolved Dart analysis requires the isolated pub cache')
  const shadow = await prepareDartOwnershipShadow({ root, managerRoot, cache, policy: job.policy, lock })
  try {
    const windows = await analyzeDartOwnershipShadow(shadow)
    return windows.map(window => ({
      kind: window.kind, operation: 'package migration', language: 'dart', ecosystem: 'pub',
      deterministicRecipeSupported: false,
      location: { path: window.path, line: window.startLine, endLine: window.endLine, column: 1 },
      detail: `Dart 3.10.0 resolved openai_dart@0.6.2 ownership in declaration ${JSON.stringify(window.declaration)}; package graph ${shadow.packageConfigHash}; SDK archive ${OLD_ARCHIVE}`,
    }))
  } finally {
    await rm(shadow.root, { recursive: true, force: true })
  }
}

export async function prepareDartOwnershipShadow(input: {
  root: string; managerRoot: string; cache: string; policy: RepositoryPolicy; lock: string;
}): Promise<DartOwnershipShadow> {
  const root = await realpath(input.root)
  const cache = await realpath(input.cache)
  const configPath = await containedPath(root, relative(root, resolve(input.managerRoot, '.dart_tool/package_config.json')))
  const configText = await boundedFile(configPath, 1024 * 1024)
  const config = JSON.parse(configText) as { configVersion?: number; packages?: DartPackage[] }
  if (config.configVersion !== 2 || !Array.isArray(config.packages)
    || config.packages.length === 0 || config.packages.length > 300
    || new Set(config.packages.map(item => item.name)).size !== config.packages.length) {
    throw new Error('Dart package configuration has an invalid bounded inventory')
  }
  const document = parseDocument(input.lock, { uniqueKeys: true })
  if (document.errors.length !== 0) throw new Error('Dart package lock is invalid')
  const lock = document.toJS({ maxAliasCount: 0 }) as { packages?: Record<string, {
    source?: string; version?: string; description?: { name?: string; url?: string; sha256?: string }
  }> }
  const sdkLock = lock.packages?.['openai_dart']
  if (sdkLock?.source !== 'hosted' || sdkLock.version !== '0.6.2'
    || sdkLock.description?.name !== 'openai_dart' || sdkLock.description.url !== 'https://pub.dev'
    || sdkLock.description.sha256 !== OLD_ARCHIVE) {
    throw new Error('Dart ownership requires the exact official old SDK archive')
  }
  const shadowRoot = await mkdtemp(resolve(tmpdir(), 'autoapi-dart-ownership-'))
  const shadowRepository = resolve(shadowRoot, 'repository')
  const mappedPackages: DartPackage[] = []
  const copied = new Map<string, string>()
  const originals = new Map<string, { source: string; repositorySource: boolean }>()
  let bytes = 0
  let visitedEntries = 0
  let sdkRoot: string | undefined
  try {
    async function copyFile(source: string, destination: string, repositorySource: boolean): Promise<void> {
      if (copied.has(destination)) return
      if (repositorySource) {
        const path = relative(root, source).split(sep).join('/')
        try { assertPathAllowed(path, { ...input.policy, allowedPaths: ['.'] }) } catch { return }
        await containedPath(root, path)
      }
      const content = await boundedFile(source, 32 * 1024 * 1024)
      if (repositorySource && scanTextForSecrets(content).length !== 0) return
      bytes += Buffer.byteLength(content)
      if (bytes > LIMIT_BYTES || copied.size >= LIMIT_FILES) throw new Error('Dart shadow source inventory exceeds its bounds')
      await mkdir(dirname(destination), { recursive: true })
      await writeFile(destination, content, { flag: 'wx', mode: 0o600 })
      copied.set(destination, content)
      originals.set(destination, { source, repositorySource })
    }
    async function copyTree(source: string, destination: string, repositorySource: boolean): Promise<void> {
      let entries
      try {
        if (await realpath(source) !== resolve(source) || !(await lstat(source)).isDirectory()) throw new Error('Dart resolution directory may not follow a symlink')
        entries = await readdir(source, { withFileTypes: true })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
        throw error
      }
      for (const entry of entries) {
        if (++visitedEntries > 50_000) throw new Error('Dart shadow directory inventory exceeds its bounds')
        if (entry.isSymbolicLink()) throw new Error('Dart resolution inputs may not contain symlinks')
        if (entry.isDirectory() && !SKIP_DIRECTORIES.has(entry.name)) {
          await copyTree(resolve(source, entry.name), resolve(destination, entry.name), repositorySource)
        } else if (entry.isFile() && entry.name.endsWith('.dart')) {
          await copyFile(resolve(source, entry.name), resolve(destination, entry.name), repositorySource)
        }
      }
    }
    for (const item of config.packages) {
      if (!/^[a-z_][a-z0-9_]*$/u.test(item.name) || item.packageUri !== 'lib/'
        || !/^\d+\.\d+$/u.test(item.languageVersion) || typeof item.rootUri !== 'string') {
        throw new Error('Dart package configuration contains an unsupported package entry')
      }
      const sourceUrl = new URL(item.rootUri, pathToFileURL(configPath))
      if (sourceUrl.protocol !== 'file:' || sourceUrl.host !== '' || sourceUrl.search !== '' || sourceUrl.hash !== '') {
        throw new Error('Dart resolution package roots must be local canonical paths')
      }
      const sourceRoot = resolve(fileURLToPath(sourceUrl))
      if (await realpath(sourceRoot) !== resolve(sourceRoot)) throw new Error('Dart package root contains a symlink')
      const local = isWithin(root, sourceRoot)
      let destination: string
      if (local) {
        destination = resolve(shadowRepository, relative(root, sourceRoot))
      } else {
        const record = lock.packages?.[item.name]
        if (record?.source !== 'hosted' || record.description?.name !== item.name
          || record.description.url !== 'https://pub.dev' || !/^[a-f0-9]{64}$/u.test(record.description.sha256 ?? '')
          || typeof record.version !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/u.test(record.version)
          || sourceRoot !== resolve(cache, 'hosted/pub.dev', `${item.name}-${record.version}`)) {
          throw new Error('Dart package root does not match its frozen hosted dependency')
        }
        const archiveHash = (await boundedFile(resolve(cache, 'hosted-hashes/pub.dev', `${item.name}-${record.version}.sha256`), 128)).trim()
        if (archiveHash !== record.description.sha256) throw new Error('Dart cached archive hash differs from its frozen lock')
        destination = resolve(shadowRoot, 'hosted', `${item.name}-${record.version}`)
      }
      if (item.name === 'openai_dart') {
        if (local) throw new Error('Dart SDK ownership cannot come from a repository override')
        for (const [file, hash] of Object.entries(OPENAI_DART_062_FILES)) {
          const content = await boundedFile(await containedPath(sourceRoot, file), 32 * 1024 * 1024)
          if (sha256(content) !== hash) throw new Error('Dart SDK source differs from its verified archive')
          await copyFile(resolve(sourceRoot, file), resolve(destination, file), false)
        }
        sdkRoot = destination
      } else {
        await copyTree(resolve(sourceRoot, 'lib'), resolve(destination, 'lib'), local)
      }
      mappedPackages.push({ name: item.name, rootUri: pathToFileURL(`${destination}/`).href,
        packageUri: 'lib/', languageVersion: item.languageVersion })
    }
    if (sdkRoot === undefined) throw new Error('Dart graph does not contain its reviewed SDK')
    const candidates: ShadowFile[] = []
    // Candidate authority remains the explicit policy; other copied library
    // sources exist only to resolve imports and never become model inputs.
    for (const path of input.policy.allowedPaths.filter(path => path.endsWith('.dart'))) {
      const source = await containedPath(root, path)
      const destination = resolve(shadowRepository, path)
      await copyFile(source, destination, true)
      const content = copied.get(destination)
      if (content === undefined) continue
      candidates.push({ path, source: content, shadowPath: destination })
    }
    if (candidates.length === 0 || candidates.length > 100) throw new Error('Dart analysis has no bounded policy source candidates')
    // Every source directive is checked before the server starts. Besides
    // blocking absolute/file imports, this builds the read-only relative-import
    // closure without exposing customer configuration or execution hooks.
    for (const [destination, content] of copied) {
      const original = originals.get(destination)!
      for (const uri of dartSourceDirectiveUris(content)) {
        if (/^dart:[a-z_]+$/u.test(uri)) continue
        if (uri.includes('\\') || uri.includes('%') || uri.includes('?') || uri.includes('#') || isAbsolute(uri)) {
          throw new Error('Dart source directive is not a bounded shadow URI')
        }
        let target: string
        let source: string
        let repositorySource: boolean
        if (uri.startsWith('package:')) {
          const match = /^package:([a-z_][a-z0-9_]*)\/(.+\.dart)$/u.exec(uri)
          const item = mappedPackages.find(item => item.name === match?.[1])
          if (match === null || item === undefined) throw new Error('Dart source imports an unknown shadow package')
          const packageRoot = resolve(fileURLToPath(item.rootUri), 'lib')
          target = resolve(packageRoot, match[2]!)
          if (!isWithin(packageRoot, target)) throw new Error('Dart package directive escapes its library')
          // All hosted library files and local library resolution inputs have
          // already been copied. Denied/secret-bearing files remain absent.
          if (!copied.has(target)) throw new Error('Dart source imports an unavailable shadow library')
          continue
        }
        if (uri.includes(':') || !uri.endsWith('.dart')) throw new Error('Dart source directive uses an unsupported URI')
        target = resolve(dirname(destination), uri)
        const boundary = original.repositorySource ? shadowRepository
          : mappedPackages.map(item => resolve(fileURLToPath(item.rootUri)))
            .find(directory => isWithin(directory, destination))
        if (boundary === undefined || !isWithin(boundary, target)) throw new Error('Dart relative directive escapes its shadow package')
        source = resolve(dirname(original.source), uri)
        repositorySource = original.repositorySource
        await copyFile(source, target, repositorySource)
        if (!copied.has(target)) throw new Error('Dart source imports a denied or secret-bearing resolution input')
      }
    }
    const generatedConfig = JSON.stringify({ configVersion: 2, packages: mappedPackages })
    const packageConfig = resolve(shadowRepository, '.dart_tool/package_config.json')
    for (const directory of new Set([shadowRoot, shadowRepository, ...mappedPackages.map(item => resolve(fileURLToPath(item.rootUri)))])) {
      await mkdir(resolve(directory, '.dart_tool'), { recursive: true })
      await writeFile(resolve(directory, 'analysis_options.yaml'), '', { flag: 'wx', mode: 0o600 })
      await writeFile(resolve(directory, '.dart_tool/package_config.json'), generatedConfig, { flag: 'wx', mode: 0o600 })
    }
    return { root: shadowRoot, repository: shadowRepository, sdkRoot, packageConfig, files: candidates, packageConfigHash: sha256(configText) }
  } catch (error) {
    await rm(shadowRoot, { recursive: true, force: true })
    throw error
  }
}

export async function analyzeDartOwnershipShadow(
  shadow: DartOwnershipShadow,
  launch: typeof spawn = spawn,
): Promise<Array<{ kind: 'sdk_import' | 'sdk_call'; path: string; startLine: number; endLine: number; declaration: string }>> {
  const home = resolve(shadow.root, 'home')
  await mkdir(home)
  const process = launch('/usr/lib/dart/bin/dart', [
    '/usr/lib/dart/bin/snapshots/analysis_server.dart.snapshot', '--protocol=analyzer',
    '--suppress-analytics', '--disable-file-byte-store', `--cache=${resolve(shadow.root, 'cache')}`,
    `--packages=${shadow.packageConfig}`,
  ], {
    cwd: shadow.root, stdio: ['pipe', 'pipe', 'pipe'],
    env: { HOME: home, PATH: '/usr/lib/dart/bin:/usr/bin:/bin', DART_SUPPRESS_ANALYTICS: 'true' },
  }) as ChildProcessWithoutNullStreams
  const session = new DartAnalysisSession(process)
  try {
    await session.request('analysis.setAnalysisRoots', { included: [shadow.repository], excluded: [] })
    await session.request('analysis.setSubscriptions', { subscriptions: { OUTLINE: shadow.files.map(file => file.shadowPath) } })
    const output = []
    for (const file of shadow.files) {
      const navigation = await session.request('analysis.getNavigation', { file: file.shadowPath, offset: 0, length: file.source.length }) as Navigation
      const diagnostics = await session.request('analysis.getErrors', { file: file.shadowPath }) as { errors?: Array<{ severity?: string }> }
      if (!Array.isArray(diagnostics.errors) || diagnostics.errors.some(error => error.severity === 'ERROR')) {
        throw new Error('Dart source does not have an unambiguous resolved baseline')
      }
      const outline = await session.outline(file.shadowPath)
      for (const range of dartOwnedDeclarationRanges(file.source, navigation, outline, shadow.sdkRoot)) {
        output.push({ kind: 'sdk_call' as const, path: file.path, ...range })
      }
      for (const directive of dartSourceDirectives(file.source)) {
        if (!directive.uri.startsWith('package:openai_dart/')) continue
        const resolved = navigation.regions.some(region => region.offset >= directive.start
          && region.offset + region.length <= directive.end && region.targets.length === 1
          && sdkNavigationTarget(navigation, region.targets[0]!, shadow.sdkRoot))
        if (!resolved) continue
        const range = exactLineRange(file.source, directive.start, directive.end - directive.start)
        if (range !== undefined) output.push({ kind: 'sdk_import' as const, path: file.path, ...range, declaration: '<SDK directive>' })
      }
    }
    return output
  } finally {
    await session.close()
  }
}

export function dartOwnedDeclarationRanges(source: string, navigation: Navigation, outline: Outline, sdkRoot: string) {
  if (/\r(?!\n)|[\u2028\u2029]/u.test(source)) throw new Error('Dart ownership requires canonical LF or CRLF source lines')
  const declarations: Outline[] = []
  let count = 0
  const visit = (node: Outline, depth = 0): void => {
    if (++count > 10_000 || depth > 100 || node.element === undefined
      || typeof node.element.kind !== 'string' || typeof node.element.name !== 'string') throw new Error('Dart outline exceeds its bounds')
    if (!Number.isSafeInteger(node.codeOffset) || !Number.isSafeInteger(node.codeLength)
      || node.codeOffset < 0 || node.codeLength < 0 || node.codeOffset + node.codeLength > source.length) {
      throw new Error('Dart outline exceeds its exact source')
    }
    if (DECLARATIONS.has(node.element.kind)) declarations.push(node)
    for (const child of node.children ?? []) visit(child, depth + 1)
  }
  visit(outline)
  if (!Array.isArray(navigation.files) || !Array.isArray(navigation.targets) || !Array.isArray(navigation.regions)
    || navigation.regions.length > 100_000 || declarations.length > 2000) throw new Error('Dart navigation exceeds its bounds')
  const selected = new Set<Outline>()
  for (const region of navigation.regions) {
    if (!Number.isSafeInteger(region.offset) || !Number.isSafeInteger(region.length)
      || region.offset < 0 || region.length < 1 || region.offset + region.length > source.length
      || !Array.isArray(region.targets) || region.targets.length !== 1) continue
    if (!Number.isSafeInteger(region.targets[0])) continue
    if (!sdkNavigationTarget(navigation, region.targets[0]!, sdkRoot)) continue
    const enclosing = declarations.filter(node => region.offset >= node.codeOffset
      && region.offset + region.length <= node.codeOffset + node.codeLength)
      .sort((left, right) => left.codeLength - right.codeLength)[0]
    if (enclosing !== undefined) selected.add(enclosing)
  }
  return [...selected].sort((a, b) => a.codeOffset - b.codeOffset).flatMap(node => {
    const range = exactLineRange(source, node.codeOffset, node.codeLength)
    return range === undefined ? [] : [{ ...range, declaration: node.element.name }]
  })
}

function sdkNavigationTarget(navigation: Navigation, index: number, sdkRoot: string): boolean {
  if (!Number.isSafeInteger(index)) return false
  const target = navigation.targets[index]
  const file = target === undefined ? undefined : navigation.files[target.fileIndex]
  return target !== undefined && Number.isSafeInteger(target.fileIndex)
    && typeof file === 'string' && isAbsolute(file) && resolve(file) === file
    && isWithin(sdkRoot, file)
    && Object.hasOwn(OPENAI_DART_062_FILES, relative(sdkRoot, file).split(sep).join('/'))
}

function exactLineRange(source: string, offset: number, length: number) {
  const end = offset + length
  const lineStart = source.lastIndexOf('\n', offset - 1) + 1
  const nextLine = source.indexOf('\n', end)
  const suffix = source.slice(end, nextLine === -1 ? source.length : nextLine)
  // Edit authority is line-based. Do not include unrelated neighbors that
  // share the first/last line, even when the compiler has exact byte offsets.
  if (length === 0 || /\S/u.test(source.slice(lineStart, offset))
    || (!source.slice(0, end).endsWith('\n') && /\S/u.test(suffix))) return undefined
  const range = { startLine: source.slice(0, offset).split('\n').length, endLine: source.slice(0, end - 1).split('\n').length }
  return range.endLine - range.startLine <= 1000 ? range : undefined
}

class DartAnalysisSession {
  private sequence = 0
  private pending = new Map<string, { resolve(value: unknown): void; reject(error: Error): void }>()
  private outlines = new Map<string, Outline>()
  private outlineWaiters = new Map<string, { resolve(value: Outline): void; reject(error: Error): void }>()
  private timer: ReturnType<typeof setTimeout>
  private failure: Error | undefined
  private exited: Promise<void>
  constructor(private readonly process: ChildProcessWithoutNullStreams) {
    let buffer = ''
    let bytes = 0
    const decoder = new StringDecoder('utf8')
    this.exited = new Promise(resolve => process.once('close', resolve))
    this.timer = setTimeout(() => this.fail(), 60_000)
    process.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length
      if (bytes > LIMIT_RESPONSE_BYTES) { this.fail(); return }
      buffer += decoder.write(chunk)
      let newline
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline)
        buffer = buffer.slice(newline + 1)
        let message: { id?: string; error?: unknown; result?: unknown; event?: string; params?: { file?: string; outline?: Outline } }
        try { message = JSON.parse(line) } catch { this.fail(); return }
        if (message.event === 'server.pluginError' || message.event === 'server.error') { this.fail(); return }
        if (message.id !== undefined) {
          const pending = this.pending.get(message.id)
          this.pending.delete(message.id)
          if (message.error !== undefined) pending?.reject(new Error('trusted Dart analysis request failed'))
          else pending?.resolve(message.result)
        }
        if (message.event === 'analysis.outline' && message.params?.file !== undefined && message.params.outline !== undefined) {
          this.outlines.set(message.params.file, message.params.outline)
          this.outlineWaiters.get(message.params.file)?.resolve(message.params.outline)
          this.outlineWaiters.delete(message.params.file)
        }
      }
    })
    process.stderr.on('data', () => {})
    process.stdin.on('error', () => this.fail())
    process.stdout.on('error', () => this.fail())
    process.stderr.on('error', () => this.fail())
    process.on('error', () => this.fail())
    process.on('exit', () => this.fail())
  }
  request(method: string, params: unknown): Promise<unknown> {
    if (this.failure !== undefined) return Promise.reject(this.failure)
    const id = String(++this.sequence)
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.process.stdin.write(`${JSON.stringify({ id, method, params })}\n`, error => { if (error !== null && error !== undefined) this.fail() })
    })
  }
  outline(file: string): Promise<Outline> {
    if (this.failure !== undefined) return Promise.reject(this.failure)
    const outline = this.outlines.get(file)
    if (outline !== undefined) return Promise.resolve(outline)
    return new Promise((resolve, reject) => this.outlineWaiters.set(file, { resolve, reject }))
  }
  async close(): Promise<void> {
    clearTimeout(this.timer)
    if (this.failure === undefined) {
      this.process.stdin.write(`${JSON.stringify({ id: String(++this.sequence), method: 'server.shutdown' })}\n`)
    } else this.process.kill('SIGKILL')
    const deadline = setTimeout(() => this.process.kill('SIGKILL'), 5000)
    try { await this.exited } finally { clearTimeout(deadline) }
  }
  private fail(): void {
    if (this.failure !== undefined) return
    const error = new Error('trusted Dart analysis stopped or exceeded its bounded response/deadline')
    this.failure = error
    for (const pending of this.pending.values()) pending.reject(error)
    for (const pending of this.outlineWaiters.values()) pending.reject(error)
    this.pending.clear(); this.outlineWaiters.clear(); clearTimeout(this.timer); this.process.kill('SIGKILL')
  }
}

// This lexer does not establish symbol ownership. It only prevents the trusted
// resolver from reading files outside the copied graph, before it is started.
export function dartSourceDirectiveUris(source: string): string[] {
  return dartSourceDirectives(source).map(item => item.uri)
}

function dartSourceDirectives(source: string): Array<{ uri: string; start: number; end: number }> {
  const tokens: Array<{ value: string; string: boolean; offset: number }> = []
  let index = 0
  const skipComment = (): boolean => {
    if (source.startsWith('//', index)) {
      index += 2
      while (index < source.length && !/[\r\n\u2028\u2029]/u.test(source[index]!)) index++
      return true
    }
    if (!source.startsWith('/*', index)) return false
    let depth = 1
    index += 2
    while (index < source.length && depth > 0) {
      if (source.startsWith('/*', index)) { depth++; index += 2 }
      else if (source.startsWith('*/', index)) { depth--; index += 2 }
      else index++
    }
    if (depth !== 0) throw new Error('Dart source has an unterminated comment')
    return true
  }
  const stringAtIndex = (): boolean => source[index] === "'" || source[index] === '"'
    || (source[index] === 'r' && (source[index + 1] === "'" || source[index + 1] === '"'))
  const consumeString = (depth = 0): string => {
    if (depth > 100) throw new Error('Dart interpolation nesting exceeds its bounds')
    const raw = source[index] === 'r'
    if (raw) index++
    const quote = source[index]!
    const delimiter = source.startsWith(quote.repeat(3), index) ? quote.repeat(3) : quote
    index += delimiter.length
    let value = ''
    let special = false
    while (index < source.length && !source.startsWith(delimiter, index)) {
      if (delimiter.length === 1 && /[\r\n\u2028\u2029]/u.test(source[index]!)) throw new Error('Dart single-line string crosses a physical line')
      if (!raw && source[index] === '\\') {
        if (delimiter.length === 1 && /[\r\n\u2028\u2029]/u.test(source[index + 1] ?? '')) throw new Error('Dart single-line escape crosses a physical line')
        special = true; index += 2
      } else if (!raw && source.startsWith('${', index)) {
        special = true; index += 2
        let braces = 1
        while (index < source.length && braces > 0) {
          if (skipComment()) continue
          if (stringAtIndex()) { consumeString(depth + 1); continue }
          if (/[A-Za-z_$]/u.test(source[index]!)) {
            const start = index++
            while (index < source.length && /[A-Za-z0-9_$]/u.test(source[index]!)) index++
            const word = source.slice(start, index)
            if (word === 'import' || word === 'export' || word === 'part') {
              const saved = index
              while (index < source.length) {
                if (/\s/u.test(source[index]!)) { index++; continue }
                if (skipComment()) continue
                break
              }
              if (stringAtIndex() || (word === 'part' && /^of\b/u.test(source.slice(index)))) throw new Error('Dart interpolation contains a malformed directive')
              index = saved
            }
            continue
          }
          if (source[index] === '{') braces++
          if (source[index] === '}') braces--
          index++
        }
        if (braces !== 0) throw new Error('Dart source has an unterminated interpolation')
      } else {
        if (!raw && source[index] === '$') special = true
        value += source[index++]!
      }
    }
    if (index >= source.length) throw new Error('Dart source has an unterminated string')
    index += delimiter.length
    return special ? '\u0000' : value
  }
  while (index < source.length) {
    const offset = index
    const char = source[index]!
    if (/\s/u.test(char)) { index++; continue }
    if (skipComment()) continue
    if (stringAtIndex()) {
      // Escapes/interpolation in URI literals are rejected, never interpreted
      // differently from the compiler. Ordinary runtime strings are ignored.
      tokens.push({ value: consumeString(), string: true, offset })
    } else if (/[a-zA-Z_$]/u.test(char)) {
      const begin = index++
      while (index < source.length && /[a-zA-Z0-9_$]/u.test(source[index]!)) index++
      tokens.push({ value: source.slice(begin, index), string: false, offset })
    } else {
      tokens.push({ value: char, string: false, offset }); index++
    }
    if (tokens.length > 1_000_000) throw new Error('Dart source token inventory exceeds its bounds')
  }
  const output: Array<{ uri: string; start: number; end: number }> = []
  for (let cursor = 0; cursor < tokens.length; cursor++) {
    const token = tokens[cursor]!
    // Inspect even syntactically misplaced directives: compiler recovery must
    // not read a forbidden URI before the later diagnostic rejection.
    if (token.string || !['import', 'export', 'part'].includes(token.value)) continue
    // `part` is also a legal ordinary identifier. A directive must start with
    // a URI (or `part of`); conditions may contain non-URI string values.
    if (tokens[cursor + 1]?.string !== true && !(token.value === 'part' && tokens[cursor + 1]?.value === 'of')) continue
    let parentheses = 0
    let condition: typeof tokens = []
    const uris: string[] = []
    for (cursor++; cursor < tokens.length && (tokens[cursor]!.string || tokens[cursor]!.value !== ';'); cursor++) {
      const value = tokens[cursor]!
      if (!value.string && ['import', 'export', 'part'].includes(value.value)) throw new Error('Dart source has a nested malformed directive')
      if (!value.string && value.value === '(') {
        if (parentheses !== 0 || tokens[cursor - 1]?.value !== 'if') throw new Error('Dart directive has a malformed condition')
        parentheses = 1; condition = []; continue
      }
      if (!value.string && value.value === ')') {
        if (parentheses !== 1) throw new Error('Dart directive has an unbalanced condition')
        const identifier = (item: typeof tokens[number] | undefined) => item !== undefined && !item.string && /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(item.value)
        let position = 0
        if (!identifier(condition[position++])) throw new Error('Dart directive has an unsupported condition')
        while (condition[position]?.value === '.' && identifier(condition[position + 1])) position += 2
        if (position !== condition.length) {
          if (condition[position]?.value !== '=' || condition[position + 1]?.value !== '='
            || condition[position + 2]?.string !== true || condition[position + 2]?.value.includes('\u0000')
            || position + 3 !== condition.length) throw new Error('Dart directive has an unsupported condition')
        }
        parentheses = 0; continue
      }
      if (parentheses !== 0) { condition.push(value); continue }
      if (!value.string || parentheses !== 0) continue
      if (value.value.includes('\u0000')) throw new Error('Dart directive URI may not contain escapes or interpolation')
      uris.push(value.value)
    }
    if (parentheses !== 0 || cursor >= tokens.length) throw new Error('Dart source has an unterminated directive or condition')
    for (const uri of uris) output.push({ uri, start: token.offset, end: (tokens[cursor]?.offset ?? source.length - 1) + 1 })
  }
  return output
}

async function boundedFile(path: string, limit: number): Promise<string> {
  const metadata = await lstat(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > limit
    || await realpath(path) !== resolve(path)) throw new Error('Dart resolution requires bounded canonical regular source files')
  const bytes = await readFile(path)
  const content = bytes.toString('utf8')
  if (!Buffer.from(content, 'utf8').equals(bytes)) throw new Error('Dart resolution inputs must be valid unchanged UTF-8')
  return content
}
async function containedPath(root: string, path: string): Promise<string> {
  const absolute = resolve(root, path)
  if (!isWithin(root, absolute) || await realpath(absolute) !== absolute) throw new Error('Dart resolution path escapes or follows a symlink')
  return absolute
}
function isWithin(root: string, path: string): boolean {
  const value = relative(root, path)
  return !isAbsolute(value) && value !== '..' && !value.startsWith(`..${sep}`)
}
