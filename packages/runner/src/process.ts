import { spawn } from 'node:child_process'
import { access, lstat, readFile, realpath } from 'node:fs/promises'
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import type {
  CommandSpec,
  ValidationCommandResult,
} from '@automated-api/contracts'
import { resolveExistingPathInsideRepository, sha256 } from '@automated-api/remediation'
import { scrubEnvironment } from './environment.js'
import {
  dependencyLockfileVerificationCommand,
  dependencySynchronizationCommand,
  type MigrationDependency,
} from './dependencies.js'
import { scanTextForSecrets } from './secrets.js'
import type { ReviewedJvmContext } from './reviewedJvmToolchain.js'

const MAX_CAPTURE_BYTES = 256 * 1024
const MAX_DIAGNOSTIC_BYTES = 4_000
// Grace period between the timeout's SIGTERM and an unconditional SIGKILL.
const KILL_ESCALATION_MS = 5_000
const TERMINAL_RESULT_RESERVE_MS = 10_000

export interface CommandExecutionBudget {
  deadlineAtMs: number
  terminalResultReserveMs?: number
}

export interface ValidationManagerContext {
  repositoryRoot: string
  packageManagerDirectory: string
}

export async function runValidationCommands(
  rootDir: string,
  commands: CommandSpec[],
  budget?: CommandExecutionBudget,
  managerContext?: ValidationManagerContext,
): Promise<ExecutedValidationResult[]> {
  const results: ExecutedValidationResult[] = []
  for (const command of commands) {
    const result = await runCommand(rootDir, command, {}, budget, managerContext)
    results.push(result)
    if (result.timedOut && remainingExecutionTimeMs(budget) <= 0) break
  }
  return results
}

export async function synchronizeDependencies(
  rootDir: string,
  configuredPackageManagerOrLanguage?: string,
  exactDependencies: readonly MigrationDependency[] = [],
  budget?: CommandExecutionBudget,
  reviewedJvmContext?: ReviewedJvmContext,
): Promise<ExecutedValidationResult[]> {
  const vendorCommand = await goVendorSynchronizationCommand(rootDir, configuredPackageManagerOrLanguage)
  const cargo = configuredPackageManagerOrLanguage === 'rust'
    || /^cargo@/iu.test(configuredPackageManagerOrLanguage ?? '')
  const cpp = configuredPackageManagerOrLanguage === 'c' || configuredPackageManagerOrLanguage === 'cpp'
    || /^vcpkg@/iu.test(configuredPackageManagerOrLanguage ?? '')
  const managed = /^(?:java|kotlin|scala|csharp|php|ruby|swift|dart|elixir|clojure)$/u.test(configuredPackageManagerOrLanguage ?? '')
    || /^(?:maven|gradle|sbt|dotnet|composer|bundler|swift|dart|mix|clojure|leiningen)@/iu.test(configuredPackageManagerOrLanguage ?? '')
  const updates: Array<MigrationDependency | undefined> = cpp
    ? [undefined]
    : (cargo || managed) && exactDependencies.length > 0
    ? [...exactDependencies]
    : [undefined]
  const results: ExecutedValidationResult[] = []
  for (const update of updates) {
    const command = await dependencySynchronizationCommand(
      rootDir,
      configuredPackageManagerOrLanguage,
      update,
      reviewedJvmContext,
    )
    if (command !== undefined) {
      results.push(await runCommand(rootDir, command, {
        NODE_ENV: 'development',
        NPM_CONFIG_PRODUCTION: 'false',
      }, budget))
      if (results.at(-1)?.timedOut && remainingExecutionTimeMs(budget) <= 0) break
    }
  }
  if (vendorCommand !== undefined && results.length > 0
    && results.every(result => result.exitCode === 0 && !result.timedOut)) {
    results.push(await runCommand(rootDir, vendorCommand, { GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local' }, budget))
  }
  return results
}

/** Preserve a repository's existing vendored-module contract after go mod tidy.
 * Never introduce vendoring or follow a customer-controlled vendor link. */
export async function goVendorSynchronizationCommand(
  rootDir: string,
  configuredPackageManagerOrLanguage?: string,
): Promise<CommandSpec | undefined> {
  if (configuredPackageManagerOrLanguage !== 'go' && !/^go@/iu.test(configuredPackageManagerOrLanguage ?? '')) return undefined
  let vendor
  try { vendor = await lstat(resolve(rootDir, 'vendor')) } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (!vendor.isDirectory() || vendor.isSymbolicLink()) throw new Error('Go vendor must be a regular directory inside the manager root')
  await resolveExistingPathInsideRepository(rootDir, 'vendor')
  let modules
  try { modules = await lstat(resolve(rootDir, 'vendor/modules.txt')) } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (!modules.isFile() || modules.isSymbolicLink()) throw new Error('Go vendor/modules.txt must be a regular file')
  return { executable: 'go', args: ['mod', 'vendor'], timeoutMs: 5 * 60 * 1000 }
}

export async function synchronizeGradleDependencyWithPolicyValidation(
  rootDir: string,
  configuredPackageManager: string,
  exactDependency: MigrationDependency,
  validationCommand: CommandSpec,
  budget?: CommandExecutionBudget,
): Promise<ExecutedValidationResult[]> {
  if (!hasPolicyBackedOfflineGradleVerification(configuredPackageManager, [validationCommand])) {
    throw new Error('combined Gradle synchronization requires a real offline policy validation')
  }
  const synchronizationCommand = await dependencySynchronizationCommand(
    rootDir,
    configuredPackageManager,
    exactDependency,
  )
  if (synchronizationCommand === undefined
    || !/^(?:\.\/)?gradlew(?:\.bat)?$/iu.test(synchronizationCommand.executable)) {
    throw new Error('combined Gradle synchronization requires the tested Gradle wrapper')
  }
  const command = combineGradleDependencyAndPolicyValidation(
    synchronizationCommand,
    validationCommand,
  )
  return [await runCommand(rootDir, command, {
    NODE_ENV: 'development',
    NPM_CONFIG_PRODUCTION: 'false',
  }, budget)]
}

export function combineGradleDependencyAndPolicyValidation(
  synchronizationCommand: CommandSpec,
  validationCommand: CommandSpec,
): CommandSpec {
  const duplicateFlags = new Set([
    '--offline', '--no-daemon', '--no-parallel',
    '-Pkotlin.compiler.execution.strategy=in-process',
  ])
  return {
    executable: synchronizationCommand.executable,
    args: [
      ...synchronizationCommand.args,
      ...validationCommand.args.filter(argument => !(duplicateFlags.has(argument)
        && synchronizationCommand.args.includes(argument))),
    ],
    timeoutMs: Math.max(synchronizationCommand.timeoutMs, validationCommand.timeoutMs),
  }
}

export async function verifySynchronizedDependencyLockfile(
  rootDir: string,
  configuredPackageManager?: string,
  budget?: CommandExecutionBudget,
  reviewedJvmContext?: ReviewedJvmContext,
): Promise<ExecutedValidationResult[]> {
  const command = await dependencyLockfileVerificationCommand(rootDir, configuredPackageManager, reviewedJvmContext)
  return command === undefined ? [] : [await runCommand(rootDir, command, {
    NODE_ENV: 'development',
    NPM_CONFIG_PRODUCTION: 'false',
  }, budget)]
}

export function hasPolicyBackedOfflineGradleVerification(
  configuredPackageManager: string | undefined,
  commands: readonly CommandSpec[],
): boolean {
  if (!/^gradle@/iu.test(configuredPackageManager ?? '')) return false
  return commands.some(command => {
    if (!/^(?:\.\/)?gradlew(?:\.bat)?$/iu.test(command.executable)) return false
    if (!command.args.includes('--offline')) return false
    if (command.args.some(argument => argument === '-m' || argument === '--dry-run'
      || argument === '-x' || argument === '--exclude-task' || argument.startsWith('--exclude-task='))) return false
    return command.args.some(argument => !argument.startsWith('-')
      && /(?:^|:)(?:test|check|build)$/iu.test(argument))
  })
}

export function policyBackedOfflineGradleVerificationIndex(
  configuredPackageManager: string | undefined,
  commands: readonly CommandSpec[],
): number {
  if (!/^gradle@/iu.test(configuredPackageManager ?? '')) return -1
  return commands.findIndex(command => hasPolicyBackedOfflineGradleVerification(
    configuredPackageManager,
    [command],
  ))
}

export async function validatePythonSyntax(
  rootDir: string,
  paths: string[],
  budget?: CommandExecutionBudget,
): Promise<ExecutedValidationResult[]> {
  const python = process.env['AUTOMATED_API_PYTHON'] ?? 'python3'
  const sourcePaths = [...new Set(paths.filter(path => /\.pyi?$/u.test(path)))]
  if (sourcePaths.length === 0) return []
  return runValidationCommands(rootDir, sourcePaths.map(path => ({
    executable: python,
    args: [
      '-c',
      'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1], type_comments=True)',
      path,
    ],
    timeoutMs: 30_000,
  })), budget)
}

export async function validateChangedSourceSyntax(
  rootDir: string,
  paths: string[],
  configuredPackageManagerOrLanguage?: string,
  budget?: CommandExecutionBudget,
): Promise<ExecutedValidationResult[]> {
  const python = await validatePythonSyntax(rootDir, paths, budget)
  return [
    ...python,
    ...await runValidationCommands(rootDir, await nativeSyntaxCommands(rootDir, paths, configuredPackageManagerOrLanguage), budget),
  ]
}

export async function nativeSyntaxCommands(
  rootDir: string,
  paths: string[],
  configuredPackageManagerOrLanguage?: string,
): Promise<CommandSpec[]> {
  const rust = await Promise.all(
    [...new Set(paths.filter(path => /\.rs$/u.test(path)))].map(async path => ({
      executable: 'rustfmt',
      args: ['--check', '--edition', await rustEditionForSource(rootDir, path), path],
      timeoutMs: 30_000,
    })),
  )
  const go = [...new Set(paths.filter(path => /\.go$/u.test(path)))].map(path => ({
    executable: 'gofmt',
    args: ['-d', path],
    timeoutMs: 30_000,
  }))
  const clojureManager = paths.some(path => /\.clj[cs]?$/u.test(path))
    ? await clojureSyntaxManager(rootDir, configuredPackageManagerOrLanguage)
    : configuredPackageManagerOrLanguage
  const managed: CommandSpec[] = [
    ...[...new Set(paths.filter(path => /\.php$/u.test(path)))].map(path => ({ executable: 'php', args: ['-l', path], timeoutMs: 30_000 })),
    ...[...new Set(paths.filter(path => /\.rb$/u.test(path)))].map(path => ({ executable: 'ruby', args: ['-c', path], timeoutMs: 30_000 })),
    ...[...new Set(paths.filter(path => /\.swift$/u.test(path)))].map(path => ({ executable: 'swiftc', args: ['-parse', path], timeoutMs: 30_000 })),
    // `dart analyze` resolves imports against the current package graph. At
    // this point the proposed dependency upgrade has not been synchronized,
    // so analyzing a migrated file can report false missing types from the old
    // lockfile. The formatter still parses the complete Dart grammar without
    // modifying the file; the configured post-sync analyzer remains the
    // authoritative semantic gate.
    ...[...new Set(paths.filter(path => /\.dart$/u.test(path)))].map(path => ({ executable: 'dart', args: ['format', '--output=none', path], timeoutMs: 30_000 })),
    ...clojureSyntaxCommands(paths, clojureManager),
  ]
  return [...rust, ...go, ...managed]
}

export function clojureSyntaxCommands(
  paths: string[],
  configuredPackageManagerOrLanguage?: string,
): CommandSpec[] {
  const leiningen = /^(?:leiningen)(?:@|$)/iu.test(configuredPackageManagerOrLanguage ?? '')
  return [...new Set(paths.filter(path => /\.clj[cs]?$/u.test(path)))].map(path => ({
      executable: leiningen ? 'lein' : 'clojure',
      args: leiningen
        ? ['-o', 'trampoline', 'run', '-m', 'clojure.main', '-e', clojureReaderExpression(path)]
        : ['-Srepro', '-M', '-e', clojureReaderExpression(path)],
      timeoutMs: 30_000,
    }))
}

function clojureReaderExpression(path: string): string {
  const literal = JSON.stringify(path)
  return `(let [p ${literal} eof (Object.)] (with-open [r (clojure.lang.LineNumberingPushbackReader. (clojure.java.io/reader p))] (binding [*read-eval* false] (loop [] (when-not (identical? eof (read {:eof eof :read-cond :allow :features #{:clj}} r)) (recur))))))`
}

async function clojureSyntaxManager(
  rootDir: string,
  configuredPackageManagerOrLanguage?: string,
): Promise<string | undefined> {
  if (/^(?:leiningen|clojure)(?:@|$)/iu.test(configuredPackageManagerOrLanguage ?? '')) {
    return configuredPackageManagerOrLanguage
  }
  const [toolsDeps, leiningen] = await Promise.all([
    fileExists(resolve(rootDir, 'deps.edn')),
    fileExists(resolve(rootDir, 'project.clj')),
  ])
  return leiningen && !toolsDeps ? 'leiningen' : configuredPackageManagerOrLanguage
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

export async function normalizeChangedNativeSources(
  rootDir: string,
  paths: string[],
  budget?: CommandExecutionBudget,
): Promise<ExecutedValidationResult[]> {
  return runValidationCommands(rootDir, await nativeFormattingCommands(rootDir, paths), budget)
}

export async function nativeFormattingCommands(
  rootDir: string,
  paths: string[],
): Promise<CommandSpec[]> {
  const rust = await Promise.all(
    [...new Set(paths.filter(path => /\.rs$/u.test(path)))].map(async path => ({
      executable: 'rustfmt',
      args: ['--edition', await rustEditionForSource(rootDir, path), path],
      timeoutMs: 30_000,
    })),
  )
  const goFormatter = process.env['AUTOMATED_API_GOIMPORTS']?.trim() || 'gofmt'
  const go = [...new Set(paths.filter(path => /\.go$/u.test(path)))].map(path => ({
    executable: goFormatter,
    args: ['-w', path],
    timeoutMs: 30_000,
  }))
  const dart = [...new Set(paths.filter(path => /\.dart$/u.test(path)))].map(path => ({
    executable: 'dart',
    args: ['format', path],
    timeoutMs: 30_000,
  }))
  return [...rust, ...go, ...dart]
}

export function hasBlockingSyntaxFailure(results: readonly ExecutedValidationResult[]): boolean {
  return results.some(result => {
    if (!result.timedOut && result.exitCode === 0) return false
    const executable = result.command.executable.replaceAll('\\', '/').split('/').at(-1)
      ?.replace(/\.exe$/iu, '')
    return executable !== 'rustfmt' && executable !== 'gofmt' && executable !== 'goimports'
  })
}

export async function rustEditionForSource(rootDir: string, sourcePath: string): Promise<string> {
  const root = resolve(rootDir)
  const source = isAbsolute(sourcePath) ? resolve(sourcePath) : resolve(root, sourcePath)
  const sourceRelative = relative(root, source)
  if (sourceRelative === '..' || sourceRelative.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    return '2021'
  }

  let directory = dirname(source)
  while (true) {
    const manifest = await readCargoManifest(join(directory, 'Cargo.toml'))
    if (manifest !== undefined) {
      const packageSection = tomlSection(manifest, 'package')
      const explicit = packageSection.match(/^\s*edition\s*=\s*["'](2015|2018|2021|2024)["']/mu)?.[1]
      if (explicit !== undefined) return explicit
      if (/^\s*edition(?:\.workspace\s*=\s*true|\s*=\s*\{\s*workspace\s*=\s*true\s*\})/mu.test(packageSection)) {
        const workspaceEdition = await findWorkspaceEdition(root, directory)
        if (workspaceEdition !== undefined) return workspaceEdition
      }
    }
    if (directory === root) break
    const parent = dirname(directory)
    if (parent === directory || relative(root, parent).startsWith('..')) break
    directory = parent
  }
  return '2021'
}

async function findWorkspaceEdition(root: string, start: string): Promise<string | undefined> {
  let directory = start
  while (true) {
    const manifest = await readCargoManifest(join(directory, 'Cargo.toml'))
    if (manifest !== undefined) {
      const edition = tomlSection(manifest, 'workspace.package')
        .match(/^\s*edition\s*=\s*["'](2015|2018|2021|2024)["']/mu)?.[1]
      if (edition !== undefined) return edition
    }
    if (directory === root) return undefined
    const parent = dirname(directory)
    if (parent === directory || relative(root, parent).startsWith('..')) return undefined
    directory = parent
  }
}

async function readCargoManifest(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return undefined
  }
}

function tomlSection(manifest: string, section: string): string {
  const marker = `[${section}]`
  const start = manifest.indexOf(marker)
  if (start === -1) return ''
  const bodyStart = start + marker.length
  const nextSection = manifest.indexOf('\n[', bodyStart)
  return manifest.slice(bodyStart, nextSection === -1 ? undefined : nextSection)
}

export interface ExecutedValidationResult extends ValidationCommandResult {
  diagnostic?: string
}

async function runCommand(
  rootDir: string,
  command: CommandSpec,
  environmentOverrides: NodeJS.ProcessEnv = {},
  budget?: CommandExecutionBudget,
  managerContext?: ValidationManagerContext,
): Promise<ExecutedValidationResult> {
  const startedAt = Date.now()
  const timeoutMs = Math.min(command.timeoutMs, remainingExecutionTimeMs(budget, startedAt))
  if (timeoutMs <= 0) {
    const empty = Buffer.alloc(0)
    return {
      command,
      exitCode: null,
      timedOut: true,
      durationMs: 0,
      stdoutHash: sha256(empty),
      stderrHash: sha256(empty),
      diagnostic: 'validation command was not started because the job deadline leaves no execution time after reserving terminal-result persistence',
    }
  }
  const environment = {
    ...scrubEnvironment(process.env),
    ...validationEnvironmentOverrides(command.executable),
    ...environmentOverrides,
  }
  // macOS exposes its temporary directory through both /var and /private/var.
  // Canonicalize both absolute inputs before deriving a repository-relative
  // path so the alias cannot look like a lexical escape. The existing-path
  // resolver below still enforces the real containment boundary.
  const canonicalRepositoryRoot = managerContext === undefined
    ? undefined
    : await realpath(managerContext.repositoryRoot)
  const canonicalManagerDirectory = managerContext === undefined
    ? undefined
    : await realpath(managerContext.packageManagerDirectory)
  const virtualEnvironmentRoot = managerContext === undefined ? rootDir
    : await resolveExistingPathInsideRepository(canonicalRepositoryRoot!,
        relative(canonicalRepositoryRoot!, canonicalManagerDirectory!) || '.')
  if (managerContext !== undefined) {
    // A repository-root policy may intentionally keep its package manager in
    // a nested fixture directory, while a monorepo member has the inverse
    // relationship. Accept either form only after both canonical paths were
    // independently confined to the repository. Unrelated sibling workspaces
    // must never borrow each other's environments.
    const canonicalWorkingDirectory = await realpath(rootDir)
    await resolveExistingPathInsideRepository(canonicalRepositoryRoot!,
      relative(canonicalRepositoryRoot!, canonicalWorkingDirectory) || '.')
    const workingFromManager = relative(virtualEnvironmentRoot, canonicalWorkingDirectory)
    const managerFromWorking = relative(canonicalWorkingDirectory, virtualEnvironmentRoot)
    if (isContainedRelativePath(workingFromManager)) {
      await resolveExistingPathInsideRepository(virtualEnvironmentRoot, workingFromManager || '.')
    } else if (isContainedRelativePath(managerFromWorking)) {
      await resolveExistingPathInsideRepository(canonicalWorkingDirectory, managerFromWorking || '.')
    } else {
      throw new Error('validation working directory and package manager directory must be nested')
    }
  }
  const virtualEnvironmentDirectory = resolve(virtualEnvironmentRoot, '.venv')
  const virtualEnvironmentBin = resolve(
    virtualEnvironmentDirectory,
    process.platform === 'win32' ? 'Scripts' : 'bin',
  )
  try {
    const metadata = await lstat(virtualEnvironmentDirectory)
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error('validation virtual environment must use owned directories, not symlinks')
    }
    const binMetadata = await lstat(virtualEnvironmentBin)
    if (!binMetadata.isDirectory() || binMetadata.isSymbolicLink()) {
      throw new Error('validation virtual environment must use owned directories, not symlinks')
    }
    await resolveExistingPathInsideRepository(virtualEnvironmentRoot,
      relative(virtualEnvironmentRoot, virtualEnvironmentBin))
    const pathName = Object.keys(environment).find(name => name.toLowerCase() === 'path') ?? 'PATH'
    environment[pathName] = [virtualEnvironmentBin, environment[pathName]]
      .filter((value): value is string => value !== undefined && value.length > 0)
      .join(delimiter)
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error
    // A virtual environment is optional. Commands continue with the scrubbed
    // process PATH when this workspace does not own one.
  }
  const child = spawn(command.executable, command.args, {
    cwd: rootDir,
    env: environment,
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    // Own the process group so a timeout can reap the whole tree. Commands like
    // `npm test` spawn children that survive a bare child.kill(), which would
    // leave the exit promise pending forever and hang the proposal job.
    detached: process.platform !== 'win32',
  })
  const stdout: Buffer[] = []
  const stderr: Buffer[] = []
  let stdoutBytes = 0
  let stderrBytes = 0
  child.stdout.on('data', (chunk: Buffer) => {
    if (stdoutBytes >= MAX_CAPTURE_BYTES) return
    const kept = chunk.subarray(0, MAX_CAPTURE_BYTES - stdoutBytes)
    stdout.push(kept)
    stdoutBytes += kept.length
  })
  child.stderr.on('data', (chunk: Buffer) => {
    if (stderrBytes >= MAX_CAPTURE_BYTES) return
    const kept = chunk.subarray(0, MAX_CAPTURE_BYTES - stderrBytes)
    stderr.push(kept)
    stderrBytes += kept.length
  })

  let timedOut = false
  let launchError: string | undefined
  let escalation: NodeJS.Timeout | undefined
  const timer = setTimeout(() => {
    timedOut = true
    signal(child, 'SIGTERM')
    // A process that traps or ignores SIGTERM must still die, or the exit
    // promise below never settles and the job hangs past every declared budget.
    escalation = setTimeout(() => signal(child, 'SIGKILL'), KILL_ESCALATION_MS)
  }, timeoutMs)

  // A spawn failure (missing executable) is a validation result, not a crash:
  // a misconfigured policy command should fail its check, not abort the job.
  const exitCode = await new Promise<number | null>((resolve) => {
    child.once('error', error => {
      launchError = `could not start ${command.executable}: ${error.message}`
      resolve(null)
    })
    child.once('exit', code => resolve(code))
  }).finally(() => {
    clearTimeout(timer)
    if (escalation !== undefined) clearTimeout(escalation)
  })

  const stdoutBuffer = Buffer.concat(stdout)
  const stderrBuffer = Buffer.concat(stderr)
  const diagnostic = launchError ?? boundedDiagnostic(
    stdoutBuffer,
    stderrBuffer,
    timedOut
      ? timeoutMs < command.timeoutMs
        ? `validation command timed out after ${timeoutMs}ms to preserve terminal-result persistence before the job deadline`
        : `validation command timed out after ${command.timeoutMs}ms`
      : undefined,
  )
  return {
    command,
    exitCode,
    timedOut,
    durationMs: Date.now() - startedAt,
    stdoutHash: sha256(stdoutBuffer),
    stderrHash: sha256(stderrBuffer),
    ...(diagnostic === '' ? {} : { diagnostic }),
  }
}

function isContainedRelativePath(candidate: string): boolean {
  return candidate === '' || (!isAbsolute(candidate)
    && candidate !== '..'
    && !candidate.startsWith(`..${sep}`))
}

function remainingExecutionTimeMs(
  budget: CommandExecutionBudget | undefined,
  nowMs = Date.now(),
): number {
  if (budget === undefined) return Number.POSITIVE_INFINITY
  const reserveMs = Math.max(0, budget.terminalResultReserveMs ?? TERMINAL_RESULT_RESERVE_MS)
  return Math.max(0, Math.floor(budget.deadlineAtMs - nowMs - reserveMs))
}

export function validationEnvironmentOverrides(executable: string): NodeJS.ProcessEnv {
  const name = executable.replaceAll('\\', '/').split('/').at(-1)?.replace(/\.exe$/iu, '')
  if (name?.toLowerCase() !== 'dotnet') return {}
  return {
    // Persistent MSBuild and Roslyn compiler servers can inherit the captured
    // stdout/stderr pipes after `dotnet` exits, keeping the validation job open
    // until the server idle timeout. Sandbox validations must terminate with
    // the command that produced their result.
    DOTNET_CLI_USE_MSBUILD_SERVER: '0',
    MSBUILDDISABLENODEREUSE: '1',
    UseSharedCompilation: 'false',
  }
}

function boundedDiagnostic(stdout: Buffer, stderr: Buffer, marker?: string): string {
  const combined = redactPrivateKeyBlocks([
    stdout.length === 0 ? '' : `stdout:\n${stdout.toString('utf8')}`,
    stderr.length === 0 ? '' : `stderr:\n${stderr.toString('utf8')}`,
  ].filter(Boolean).join('\n')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, '')
    .replace(/[^\t\n\r\x20-\x7e]/gu, ''))
  if (combined === '') return marker ?? ''
  const lines = combined.split(/\r?\n/u)
  const secretLines = new Set(scanTextForSecrets(combined).map(finding => finding.line - 1))
  const redacted = lines.map((line, index) =>
    secretLines.has(index) ? '[redacted secret-like validation output]' : line)
    .join('\n')
  const marked = marker === undefined ? redacted : `${marker}\n${redacted}`
  const bytes = Buffer.from(marked)
  if (bytes.length <= MAX_DIAGNOSTIC_BYTES) return marked
  const prefix = Buffer.from([
    ...(marker === undefined ? [] : [marker]),
    '[truncated validation output]',
    '',
  ].join('\n'))
  return Buffer.concat([
    prefix,
    bytes.subarray(bytes.length - (MAX_DIAGNOSTIC_BYTES - prefix.length)),
  ]).toString('utf8')
}

function redactPrivateKeyBlocks(value: string): string {
  return value.replace(
    /-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/gu,
    '[redacted secret-like validation output]',
  )
}

function signal(child: ReturnType<typeof spawn>, name: 'SIGTERM' | 'SIGKILL'): void {
  try {
    // Negative pid targets the whole process group created by `detached`.
    if (process.platform !== 'win32' && child.pid !== undefined) {
      process.kill(-child.pid, name)
      return
    }
    child.kill(name)
  } catch {
    // Already gone, or the group was reaped between the check and the signal.
  }
}
