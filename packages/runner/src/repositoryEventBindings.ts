import {
  MigrationJobSchema,
  RepositoryPolicySchema,
  type MigrationJob,
  type RepositoryPolicy,
} from '@automated-api/contracts'

const DD_TRACE_OPENAI_JAVA_REPOSITORY = Object.freeze({
  name: 'autoapi-real-dd-trace-openai-java',
  publicName: 'autoapi-real-dd-trace-openai-java-public',
  baseSha: '2c431c47474a136e53bf8ffbc937a05ad3091d27',
  packageManagerDirectory: 'autoapi-validation/openai-java-callid',
  packageManager: 'gradle@9.7.1',
})

const DD_TRACE_OPENAI_JAVA_LOCK_MIGRATION = Object.freeze({
  lockPath: 'dd-java-agent/instrumentation/openai-java/openai-java-3.0/gradle.lockfile',
  baselineLockSha256: '84cd17e392e7130f4bd7a010b931d0f6e3ce2a012a71e50fcc796561242675c3',
  resolvedLockSha256: '50bade87d05dd08e606ed137ef7a77cfd0fabc169d5659c90282f0442259fe4a',
  lockReplacements: Object.freeze([
    Object.freeze({
      old: 'com.openai:openai-java-client-okhttp:4.52.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
      replacement: 'com.openai:openai-java-client-okhttp:4.54.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
    }),
    Object.freeze({
      old: 'com.openai:openai-java-core:4.52.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
      replacement: 'com.openai:openai-java-core:4.54.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
    }),
    Object.freeze({
      old: 'com.openai:openai-java:4.52.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
      replacement: 'com.openai:openai-java:4.54.0=latestDepTestCompileClasspath,latestDepTestRuntimeClasspath',
    }),
    Object.freeze({
      old: 'org.jetbrains.kotlin:kotlin-reflect:1.8.10=latestDepTestRuntimeClasspath,testRuntimeClasspath',
      replacement: [
        'org.jetbrains.kotlin:kotlin-reflect:1.8.10=testRuntimeClasspath',
        'org.jetbrains.kotlin:kotlin-reflect:1.8.20=latestDepTestRuntimeClasspath',
      ].join('\n'),
    }),
  ]),
})

const DD_TRACE_OPENAI_JAVA_PATHS = Object.freeze([
  'dd-java-agent/instrumentation/openai-java/openai-java-3.0/gradle.lockfile',
  'dd-java-agent/instrumentation/openai-java/openai-java-3.0/src/main/java/datadog/trace/instrumentation/openai_java/FunctionCallOutputExtractor.java',
  'dd-java-agent/instrumentation/openai-java/openai-java-3.0/src/main/java/datadog/trace/instrumentation/openai_java/ResponseDecorator.java',
])

const OPENAI_JAVA_EVIDENCE_HASHES = Object.freeze([
  '43a391794c89d4c0aeaffe3208835e37b7c2ba15a48d00a79122a9bc855b3e0a',
  'de024b4e52ca74b62a3ca00f356baa13ed8f7f8e24482e4d24327e51cb85a720',
  '7edbad6c81d549bbe86273a404ec2fe0d102c4c3a6df12ef2038de166b747ff3',
  'bb24da4ae2aba43267fcc2fc7d6cbab5b3967ef3e96c102a794951bdf3ffd4e0',
  'dd7a5b5c3c012f1b812268203026aa721335d6a89620453fda56c3ab011f51d6',
  '6f1347374b37cdf36f46c54d95c495af04c2cb8881b80c82806c0fe04af4f9fc',
])

const OPENAI_JAVA_EVIDENCE = Object.freeze([
  ['https://repo1.maven.org/maven2/com/openai/openai-java/4.52.0/openai-java-4.52.0.jar', OPENAI_JAVA_EVIDENCE_HASHES[0]],
  ['https://repo1.maven.org/maven2/com/openai/openai-java/4.54.0/openai-java-4.54.0.jar', OPENAI_JAVA_EVIDENCE_HASHES[1]],
  ['https://repo1.maven.org/maven2/com/openai/openai-java-core/4.52.0/openai-java-core-4.52.0.jar', OPENAI_JAVA_EVIDENCE_HASHES[2]],
  ['https://repo1.maven.org/maven2/com/openai/openai-java-core/4.54.0/openai-java-core-4.54.0.jar', OPENAI_JAVA_EVIDENCE_HASHES[3]],
  ['https://raw.githubusercontent.com/openai/openai-java/v4.52.0/CHANGELOG.md', OPENAI_JAVA_EVIDENCE_HASHES[4]],
  ['https://raw.githubusercontent.com/openai/openai-java/v4.54.0/CHANGELOG.md', OPENAI_JAVA_EVIDENCE_HASHES[5]],
] as const)

const LANGROID_FIRECRAWL_REPOSITORY = Object.freeze({
  name: 'autoapi-real-langroid-firecrawl-python',
  publicName: 'autoapi-real-langroid-firecrawl-python-public',
  defaultBranch: 'codex/proof-firecrawl-1.14.0',
  baseSha: 'fcd37dea6fa4054ab5218fe98bb9a533a9a6328f',
  packageManager: 'uv@0.8.14',
})

const LANGROID_FIRECRAWL_PATHS = Object.freeze([
  'autoapi-fixture/pyproject.toml',
  'autoapi-fixture/uv.lock',
  'langroid/parsing/url_loader.py',
])

const FIRECRAWL_PYTHON_EVIDENCE_HASHES = Object.freeze([
  'e17c699015e7d634e2dd275c8895c5743f3ab3c47f8a9e99b1437ece883c5ec9',
  'be06bd136e4fab3e2ddc36485e284d4e89affc2a3dd4315909b856551ce2d772',
  '40142f9dc8b291ab0573ed9ff62732e07ba5264074fcc633bb752d9510e8321e',
  'd824fa21e0db37110105e60fff3025cd37b801063d66211a65f7ba593a85eb35',
])

const SYMFONY_PREDIS_REPOSITORY = Object.freeze({
  name: 'autoapi-real-symfony-cache-predis-php',
  publicName: 'autoapi-real-symfony-cache-predis-php-public',
  defaultBranch: 'main',
  baseSha: 'cc52a5087a44899e60f3f633c974f92aae14743b',
  packageManager: 'composer@2.8.10',
})

const SYMFONY_PREDIS_PATHS = Object.freeze([
  'composer.json',
  'composer.lock',
  'Traits/RedisTrait.php',
  'Adapter/RedisTagAwareAdapter.php',
])

const SYMFONY_PREDIS_EVIDENCE = Object.freeze([
  Object.freeze({
    url: 'https://codeload.github.com/predis/predis/zip/a2fb02d738bedadcffdbb07efa3a5e7bd57f8d6e',
    contentHash: '0c8597d810c50986901cfa9d5fceeeb021cb801d241774da85b8eafb2aec627a',
  }),
  Object.freeze({
    url: 'https://codeload.github.com/predis/predis/zip/99c253733dee9447d26257dc669d33d5ac84713d',
    contentHash: '6f3499fd9f74ce9268dd67e5ea04ad874536c3c9447ac0fa6da31fef294a29e1',
  }),
  Object.freeze({
    url: 'https://raw.githubusercontent.com/predis/predis/99c253733dee9447d26257dc669d33d5ac84713d/CHANGELOG.md',
    contentHash: 'ed12a3ea01ab601461b6c6c813f3cd8a1e6a379cccb41c0d602fe76f15755ad7',
  }),
])

const SYMFONY_PREDIS_MIGRATION_INSTRUCTION = [
  'For this exact Symfony Cache source, replace each',
  '`$hosts = [$host->getClientFor(\'master\')];` with',
  '`$hosts = [$host->getClientBy(\'role\', \'master\')];`.',
  'Predis 2 no longer treats `master` as a connection ID; the reviewed role selector',
  'preserves the existing replication-master selection and returned-client behavior.',
  'Move ClusterInterface, RedisCluster, and PredisCluster imports from',
  '`Predis\\Connection\\Aggregate` to `Predis\\Connection\\Cluster`, and move',
  'ReplicationInterface to `Predis\\Connection\\Replication`.',
  '`switchToMaster()` is not replacement authority for `getClientFor()` and must not be introduced.',
].join(' ')

const SYMFONY_PREDIS_IMPORT_REPLACEMENTS = Object.freeze([
  Object.freeze({
    old: 'Predis\\Connection\\Aggregate\\ClusterInterface',
    replacement: 'Predis\\Connection\\Cluster\\ClusterInterface',
  }),
  Object.freeze({
    old: 'Predis\\Connection\\Aggregate\\RedisCluster',
    replacement: 'Predis\\Connection\\Cluster\\RedisCluster',
  }),
  Object.freeze({
    old: 'Predis\\Connection\\Aggregate\\PredisCluster',
    replacement: 'Predis\\Connection\\Cluster\\PredisCluster',
  }),
  Object.freeze({
    old: 'Predis\\Connection\\Aggregate\\ReplicationInterface',
    replacement: 'Predis\\Connection\\Replication\\ReplicationInterface',
  }),
])

const SYMFONY_PREDIS_REQUIRED_SNIPPETS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'Traits/RedisTrait.php': Object.freeze([
    'use Predis\\Connection\\Cluster\\ClusterInterface;',
    'use Predis\\Connection\\Cluster\\RedisCluster;',
    'use Predis\\Connection\\Replication\\ReplicationInterface;',
    "$hosts = [$host->getClientBy('role', 'master')];",
  ]),
  'Adapter/RedisTagAwareAdapter.php': Object.freeze([
    'use Predis\\Connection\\Cluster\\ClusterInterface;',
    'use Predis\\Connection\\Cluster\\PredisCluster;',
    'use Predis\\Connection\\Replication\\ReplicationInterface;',
    "$hosts = [$host->getClientBy('role', 'master')];",
  ]),
})

const SYMFONY_PREDIS_FORBIDDEN_SNIPPETS = Object.freeze([
  'Predis\\Connection\\Aggregate\\',
  "getClientFor('master')",
  'switchToMaster',
])

const LANGROID_FIRECRAWL_CALL_CONSTRAINT = [
  'For this exact Langroid source, keep Firecrawl construction as',
  '`Firecrawl(api_key=self.config.api_key)`; do not move the crawler configuration timeout',
  'onto the client constructor. Preserve the existing `params` mapping and its',
  '`params["timeout"] = self.config.timeout` assignment, then pass that same mapping with',
  '`**params` to both `app.scrape(...)` and `app.start_crawl(...)`.',
].join(' ')

const JVM_OLD_SYMBOL = 'callId()Ljava/lang/String;'
const JVM_NEW_SYMBOL = 'callId()Ljava/util/Optional;'
const CUSTOMER_OLD_SYMBOL = 'output.callId()'
const CUSTOMER_NEW_SYMBOL = 'FunctionCallOutputExtractor.getCallIdAsString(output)'
const CUSTOMER_MIGRATION_INSTRUCTION = [
  'For this exact dd-trace compatibility module, replace output.callId() with',
  'FunctionCallOutputExtractor.getCallIdAsString(output). The trusted runner has already',
  'materialized the exact cross-version getCallIdAsString helper in FunctionCallOutputExtractor.',
  'That helper source is read-only model context: do not add, modify, or duplicate the helper,',
  'its fields, or getOutputAsString. Limit the model-owned source migration to callers of',
  'output.callId(); the code-owned helper handles both the pre-4.54 String result and the',
  '4.54 Optional<String> result while preserving the existing error fallback.',
].join(' ')

/**
 * Translate one genuine provider-level JVM signature into the already-reviewed
 * dd-trace compatibility migration. This is deliberately bound to one exact
 * repository, base, policy, dependency, operation, and evidence set. It cannot
 * grant the customer-specific helper migration to another repository or event.
 */
export function bindReviewedRepositoryChangeEvent(jobInput: MigrationJob): MigrationJob {
  const job = MigrationJobSchema.parse(jobInput)
  if (job.baseSha === SYMFONY_PREDIS_REPOSITORY.baseSha
    && ([SYMFONY_PREDIS_REPOSITORY.name, SYMFONY_PREDIS_REPOSITORY.publicName] as readonly string[])
      .includes(job.repository.name)
    && !matchesSymfonyPredisRepositoryIdentity(job)) {
    throw new Error('Symfony Predis repository binding requires a reviewed mirror owner/name pair')
  }
  if (matchesSymfonyPredisRepositoryIdentity(job)) {
    if (!matchesSymfonyPredisTargetShape(job)) {
      throw new Error('Symfony Predis repository binding requires the complete reviewed repository policy')
    }
    if (!matchesGenuinePredisPhpEvent(job)) {
      throw new Error('Symfony Predis repository binding requires the genuine official getClientFor to getClientBy event')
    }
    return bindSymfonyPredisContract(job)
  }
  if (matchesLangroidTarget(job) && matchesGenuineFirecrawlPythonEvent(job)) {
    return bindLangroidResponseContracts(job)
  }
  if (!matchesDdTraceTarget(job) || !matchesGenuineOpenAiJavaEvent(job)) return job

  const operation = job.changeEvent.operations[0]!
  return MigrationJobSchema.parse({
    ...job,
    changeEvent: {
      ...job.changeEvent,
      evidence: job.changeEvent.evidence.map(({ url, contentHash }) => ({ url, contentHash })),
      operations: [{
        kind: operation.kind,
        operation: operation.operation,
        oldSymbol: CUSTOMER_OLD_SYMBOL,
        newSymbol: CUSTOMER_NEW_SYMBOL,
        details: {
          migrationHintType: 'method_rename',
          oldSignature: 'String ResponseInputItem.FunctionCallOutput.callId()',
          newSignature: 'Optional<String> ResponseInputItem.FunctionCallOutput.callId()',
          instructions: CUSTOMER_MIGRATION_INSTRUCTION,
          migration: CUSTOMER_MIGRATION_INSTRUCTION,
          compatibilityConstraint: [
            'Preserve the OpenAI Java 3.0.1 compile/test floor and the build.gradle dynamic',
            'latestDepTest selector; a direct Optional method call would break the floor.',
          ].join(' '),
          requiredBehavior: [
            'Preserve a present call ID, return null for an empty Optional, continue accepting',
            'the pre-4.54 String result, and retain the existing extractor error fallback.',
          ].join(' '),
          repositoryBinding: `${job.repository.owner}/${job.repository.name}@${DD_TRACE_OPENAI_JAVA_REPOSITORY.baseSha}`,
        },
      }],
    },
  })
}

/**
 * Return the exact import-only seed for the reviewed Symfony/Predis fixture.
 * The semantic getClientFor -> getClientBy call remains Harness-owned. This
 * helper deliberately repeats the complete repository/event predicate so
 * provider-controlled details cannot grant a deterministic edit elsewhere.
 */
export function reviewedSymfonyPredisImportSeed(jobInput: MigrationJob): {
  sourcePaths: readonly string[]
  replacements: readonly { old: string; replacement: string }[]
  requiredSnippetsByPath: Readonly<Record<string, readonly string[]>>
  forbiddenSnippets: readonly string[]
} | undefined {
  const job = MigrationJobSchema.parse(jobInput)
  if (!matchesSymfonyPredisTargetShape(job)
    || !matchesGenuinePredisPhpEvent(job)) return undefined
  return {
    sourcePaths: SYMFONY_PREDIS_PATHS.slice(2),
    replacements: SYMFONY_PREDIS_IMPORT_REPLACEMENTS,
    requiredSnippetsByPath: SYMFONY_PREDIS_REQUIRED_SNIPPETS,
    forbiddenSnippets: SYMFONY_PREDIS_FORBIDDEN_SNIPPETS,
  }
}

/**
 * Return the complete resolver-derived lock migration for the one reviewed
 * dd-trace acceptance job. The hidden manager remains validation-only; this
 * deterministic seed is bound to the exact repository, event and policy.
 */
export function reviewedDdTraceGradleLockMigration(jobInput: MigrationJob): {
  lockPath: string
  baselineLockSha256: string
  resolvedLockSha256: string
  lockReplacements: readonly { old: string; replacement: string }[]
} | undefined {
  const job = MigrationJobSchema.parse(jobInput)
  if (!matchesDdTraceTarget(job) || !matchesGenuineOpenAiJavaEvent(job)) return undefined
  return { ...DD_TRACE_OPENAI_JAVA_LOCK_MIGRATION }
}

/** A source-bound insertion point, not general authority over a managed file. */
export function reviewedDdTraceJavaHelper(jobInput: MigrationJob): {
  sourcePath: string
  baselineSha256: string
  insertionAnchor: string
  requiredDeclaration: string
} | undefined {
  const job = MigrationJobSchema.parse(jobInput)
  if (!matchesDdTraceTarget(job) || !matchesGenuineOpenAiJavaEvent(job)) return undefined
  return {
    sourcePath: DD_TRACE_OPENAI_JAVA_PATHS[1]!,
    baselineSha256: '11fb2206934351e2b1824339c631978b31dc0df651cd7953a96a04649460ae9b',
    insertionAnchor: '  public static String getOutputAsString(ResponseInputItem.FunctionCallOutput functionCallOutput) {',
    requiredDeclaration: 'public static String getCallIdAsString(',
  }
}

/**
 * Derive the policy exposed to hosted model execution for the one exact
 * reviewed dd-trace migration. The helper remains readable so the model can
 * assess its caller, but only trusted runner code may materialize or replace
 * that helper. Every other repository/event retains its original policy.
 */
export function reviewedDdTraceModelPolicy(jobInput: MigrationJob): RepositoryPolicy {
  const job = MigrationJobSchema.parse(jobInput)
  const helper = reviewedDdTraceJavaHelper(job)
  if (helper === undefined) return job.policy
  const allowedPaths = job.policy.allowedPaths.filter(path => path !== helper.sourcePath)
  if (allowedPaths.length !== job.policy.allowedPaths.length - 1
    || !job.policy.modelReadablePaths?.includes(helper.sourcePath)) {
    throw new Error('reviewed Java helper model policy does not contain its exact readable source path')
  }
  return RepositoryPolicySchema.parse({ ...job.policy, allowedPaths })
}

function bindSymfonyPredisContract(job: MigrationJob): MigrationJob {
  const operation = job.changeEvent.operations[0]!
  return MigrationJobSchema.parse({
    ...job,
    changeEvent: {
      ...job.changeEvent,
      evidence: job.changeEvent.evidence.map(({ url, contentHash }) => ({ url, contentHash })),
      operations: [{
        kind: operation.kind,
        operation: operation.operation,
        oldSymbol: operation.oldSymbol,
        newSymbol: operation.newSymbol,
        details: {
          migrationHintType: 'method_rename',
          oldSignature: 'Predis\\Client::getClientFor($connectionID)',
          newSignature: 'Predis\\Client::getClientBy($selector, $value)',
          instructions: SYMFONY_PREDIS_MIGRATION_INSTRUCTION,
          migration: SYMFONY_PREDIS_MIGRATION_INSTRUCTION,
          requiredPattern: "$hosts = [$host->getClientBy('role', 'master')];",
          repositoryCallContract: {
            kind: 'symfony-predis-master-selection-v1',
            sourcePaths: ['Traits/RedisTrait.php', 'Adapter/RedisTagAwareAdapter.php'],
            oldCall: "getClientFor('master')",
            requiredCall: "getClientBy('role', 'master')",
            namespaceReplacements: [
              ...SYMFONY_PREDIS_IMPORT_REPLACEMENTS.map(item => `${item.old} -> ${item.replacement}`),
            ],
            forbiddenSymbols: ['Predis\\Connection\\Aggregate', 'getClientFor', 'switchToMaster'],
            repositoryBinding: `${job.repository.owner}/${job.repository.name}@${SYMFONY_PREDIS_REPOSITORY.baseSha}`,
          },
        },
      }],
    },
  })
}

function bindLangroidResponseContracts(job: MigrationJob): MigrationJob {
  return MigrationJobSchema.parse({
    ...job,
    changeEvent: {
      ...job.changeEvent,
      operations: job.changeEvent.operations.map(operation => {
        const responseContract = operation.details?.['responseContract']
        const constrainCall = ['client', 'scrape', 'start_crawl'].includes(operation.operation)
        const details = {
          ...operation.details,
          ...(constrainCall ? {
            instructions: `${String(operation.details?.['instructions'] ?? '').trim()} ${LANGROID_FIRECRAWL_CALL_CONSTRAINT}`.trim(),
          } : {}),
          ...(operation.operation === 'start_crawl' ? {
            repositoryCallContract: {
              kind: 'langroid-firecrawl-options-v1',
              sourcePath: 'langroid/parsing/url_loader.py',
              repositoryBinding: `${job.repository.owner}/${job.repository.name}@${LANGROID_FIRECRAWL_REPOSITORY.baseSha}`,
              className: 'FirecrawlCrawler',
              functionName: 'crawl',
              clientType: 'Firecrawl',
              clientVariable: 'app',
              mappingName: 'params',
              requiredMappingEntry: { key: 'timeout', value: 'self.config.timeout' },
              requiredExpansionMethods: ['scrape', 'start_crawl'],
              forbiddenClientKeywords: ['timeout'],
            },
          } : {}),
        }
        if (typeof responseContract !== 'object' || responseContract === null) {
          return { ...operation, details }
        }
        const contract = responseContract as Record<string, unknown>
        return {
          ...operation,
          details: {
            ...details,
            responseContract: {
              ...contract,
              enforcement: {
                requiredAttributes: true,
                sourcePath: 'langroid/parsing/url_loader.py',
                repositoryBinding: `${job.repository.owner}/${job.repository.name}@${LANGROID_FIRECRAWL_REPOSITORY.baseSha}`,
              },
              ...(contract['serialization'] === undefined ? {} : {
                serialization: {
                  ...(contract['serialization'] as Record<string, unknown>),
                  required: true,
                },
              }),
            },
          },
        }
      }),
    },
  })
}

function matchesLangroidTarget(job: MigrationJob): boolean {
  return matchesReviewedRepository(job, LANGROID_FIRECRAWL_REPOSITORY.name,
    LANGROID_FIRECRAWL_REPOSITORY.publicName, ['supportcontact584-png', 'sajsnddkn'])
    && job.repository.defaultBranch === LANGROID_FIRECRAWL_REPOSITORY.defaultBranch
    && (job.repository.workingDirectory ?? '.') === '.'
    && job.repository.packageManagerDirectory === 'autoapi-fixture'
    && job.repository.packageManager === LANGROID_FIRECRAWL_REPOSITORY.packageManager
    && job.baseSha === LANGROID_FIRECRAWL_REPOSITORY.baseSha
    && sameStrings(job.policy.allowedPaths, LANGROID_FIRECRAWL_PATHS)
    && sameStrings(job.policy.modelReadablePaths, ['langroid/parsing/url_loader.py'])
    && sameStrings(job.policy.allowedManifestPaths, LANGROID_FIRECRAWL_PATHS.slice(0, 2))
    && sameStrings(job.policy.allowedLanguages, ['python'])
}

function matchesSymfonyPredisTargetShape(job: MigrationJob): boolean {
  return matchesSymfonyPredisRepositoryIdentity(job)
    && job.repository.defaultBranch === SYMFONY_PREDIS_REPOSITORY.defaultBranch
    && (job.repository.workingDirectory ?? '.') === '.'
    && (job.repository.packageManagerDirectory ?? '.') === '.'
    && job.repository.packageManager === SYMFONY_PREDIS_REPOSITORY.packageManager
    && job.baseSha === SYMFONY_PREDIS_REPOSITORY.baseSha
    && sameStrings(job.policy.allowedPaths, SYMFONY_PREDIS_PATHS)
    && sameStrings(job.policy.modelReadablePaths, SYMFONY_PREDIS_PATHS.slice(2))
    && sameStrings(job.policy.allowedManifestPaths, SYMFONY_PREDIS_PATHS.slice(0, 2))
    && sameStrings(job.policy.deniedPaths, ['.github/workflows', '.env', 'scripts'])
    && sameStrings(job.policy.allowedLanguages, ['php'])
    && sameStrings(job.policy.requiredChecks, ['php-tests-and-predis2-contract'])
    && job.policy.allowedNetworkHosts.length === 0
    && job.policy.maxChangedFiles === 4
    && job.policy.maxPatchBytes === 250_000
    && job.policy.maxModelInputBytes === 100_000
    && job.policy.maxModelOutputTokens === 10_000
    && job.policy.maxRunTimeMs === 900_000
    && job.policy.maxRepairAttempts === 2
    && job.policy.probableChanges.enabled === true
    && job.policy.probableChanges.allowHarness === true
    && job.policy.probableChanges.allowDraftPr === true
    && job.policy.probableChanges.maxChangedFiles === 10
    && job.policy.probableChanges.maxPatchBytes === 500_000
    && sameCommands(job.policy.validationCommands, [
      {
        executable: 'env',
        args: ['SYMFONY_DEPRECATIONS_HELPER=max[indirect]=1', 'php', 'vendor/bin/simple-phpunit', '--colors=never'],
        timeoutMs: 600_000,
      },
      { executable: 'php', args: ['scripts/verify-autoapi-predis2.php'], timeoutMs: 60_000 },
    ])
}

function matchesSymfonyPredisRepositoryIdentity(job: MigrationJob): boolean {
  return matchesReviewedRepository(job, SYMFONY_PREDIS_REPOSITORY.name,
    SYMFONY_PREDIS_REPOSITORY.publicName)
    && job.baseSha === SYMFONY_PREDIS_REPOSITORY.baseSha
}

function matchesGenuinePredisPhpEvent(job: MigrationJob): boolean {
  const event = job.changeEvent
  const dependency = event.affectedDependencies[0]
  const operation = event.operations[0]
  return event.verificationStatus === 'verified'
    && /^chg_[a-f0-9]{24}$/u.test(event.id)
    && event.provider === 'redis'
    && event.apiOrSdk === 'Predis PHP client'
    && event.oldVersion === '1.1.10'
    && event.newVersion === '2.0.0'
    && event.recipeIds.length === 0
    && event.affectedPackages.length === 0
    && event.affectedApiHosts.length === 0
    && sameStrings(event.affectedLanguages, ['php'])
    && event.affectedDependencies.length === 1
    && dependency?.ecosystem === 'composer'
    && dependency.name === 'predis/predis'
    && sameStrings(dependency.importNames, ['Predis'])
    && dependency.oldVersionRange === '>=1.1.10 <2.0.0'
    && dependency.newVersion === '2.0.0'
    && dependency.newArtifactSha256 === SYMFONY_PREDIS_EVIDENCE[1]!.contentHash
    && event.operations.length === 1
    && operation?.kind === 'method_renamed'
    && operation.operation === 'Predis client connection selection'
    && operation.oldSymbol === 'getClientFor'
    && operation.newSymbol === 'getClientBy'
    && operation.details?.['migrationHintType'] === 'method_rename'
    && event.evidence.length === SYMFONY_PREDIS_EVIDENCE.length
    && SYMFONY_PREDIS_EVIDENCE.every(expected => event.evidence.some(item =>
      item.url === expected.url && item.contentHash === expected.contentHash))
}

function matchesGenuineFirecrawlPythonEvent(job: MigrationJob): boolean {
  const event = job.changeEvent
  const dependency = event.affectedDependencies[0]
  const observedEvidence = new Set(event.evidence.map(item => item.contentHash))
  const expectedOperations = new Map<string, {
    oldSymbol: string; newSymbol: string; resultType: string; requiredAttributes: string[];
    evidenceBasis: string[]; itemType?: string;
  }>([
    ['scrape', { oldSymbol: 'scrape_url', newSymbol: 'scrape', resultType: 'Document',
      requiredAttributes: ['markdown', 'metadata', 'metadata.status_code', 'metadata.url', 'metadata.title'],
      evidenceBasis: ['Document(BaseModel)', 'DocumentMetadata(BaseModel)', 'Requires-Dist: pydantic>=2.0'] }],
    ['start_crawl', { oldSymbol: 'async_crawl_url', newSymbol: 'start_crawl', resultType: 'CrawlResponse',
      requiredAttributes: ['id'], evidenceBasis: ['CrawlResponse(BaseModel)', 'Requires-Dist: pydantic>=2.0'] }],
    ['crawl_status', { oldSymbol: 'check_crawl_status', newSymbol: 'get_crawl_status', resultType: 'CrawlJob',
      itemType: 'Document', requiredAttributes: ['status', 'data', 'data[].markdown', 'data[].metadata',
        'data[].metadata.url', 'data[].metadata.title'],
      evidenceBasis: ['CrawlJob(BaseModel)', 'Document(BaseModel)', 'DocumentMetadata(BaseModel)',
        'Requires-Dist: pydantic>=2.0'] }],
  ])
  const contracted = event.operations.filter(operation => expectedOperations.has(operation.operation))
  const client = event.operations.find(operation => operation.operation === 'client')
  return event.verificationStatus === 'verified'
    && event.provider === 'firecrawl'
    && event.apiOrSdk === 'Firecrawl Python SDK'
    && event.oldVersion === '1.14.0'
    && event.newVersion === '4.31.0'
    && sameStrings(event.recipeIds, ['firecrawl-python-v1-v2'])
    && sameStrings(event.affectedLanguages, ['python'])
    && event.affectedDependencies.length === 1
    && dependency?.ecosystem === 'pypi'
    && dependency.name === 'firecrawl-py'
    && sameStrings(dependency.importNames, ['firecrawl'])
    && dependency.oldVersionRange === '==1.14.0'
    && dependency.newVersion === '4.31.0'
    && dependency.newArtifactSha256 === FIRECRAWL_PYTHON_EVIDENCE_HASHES[2]
    && event.operations.length === 4
    && client?.kind === 'method_renamed'
    && client.oldSymbol === 'FirecrawlApp'
    && client.newSymbol === 'Firecrawl'
    && contracted.length === expectedOperations.size
    && contracted.every(operation => {
      const expected = expectedOperations.get(operation.operation)!
      const contract = operation.details?.['responseContract'] as Record<string, unknown> | undefined
      const serialization = contract?.['serialization'] as Record<string, unknown> | undefined
      return operation.kind === 'method_renamed'
        && operation.oldSymbol === expected.oldSymbol
        && operation.newSymbol === expected.newSymbol
        && contract !== undefined && contract !== null
        && contract['language'] === 'python'
        && contract['resultType'] === expected.resultType
        && contract['forbidMappingAccess'] === true
        && (expected.itemType === undefined ? contract['itemType'] === undefined
          : contract['itemType'] === expected.itemType)
        && Array.isArray(contract['requiredAttributes'])
        && sameStrings(contract['requiredAttributes'] as string[], expected.requiredAttributes)
        && Array.isArray(contract['evidenceBasis'])
        && sameStrings(contract['evidenceBasis'] as string[], expected.evidenceBasis)
        && (operation.operation !== 'crawl_status'
          || (serialization?.['method'] === 'model_dump' && serialization['mode'] === 'json'
            && serialization['consumer'] === 'json.dump' && serialization['required'] === undefined))
    })
    && observedEvidence.size === FIRECRAWL_PYTHON_EVIDENCE_HASHES.length
    && FIRECRAWL_PYTHON_EVIDENCE_HASHES.every(hash => observedEvidence.has(hash))
}

function matchesDdTraceTarget(job: MigrationJob): boolean {
  return matchesReviewedRepository(job, DD_TRACE_OPENAI_JAVA_REPOSITORY.name,
    DD_TRACE_OPENAI_JAVA_REPOSITORY.publicName)
    && job.repository.defaultBranch === 'main'
    && (job.repository.workingDirectory ?? '.') === '.'
    && job.repository.packageManagerDirectory === DD_TRACE_OPENAI_JAVA_REPOSITORY.packageManagerDirectory
    && job.repository.packageManager === DD_TRACE_OPENAI_JAVA_REPOSITORY.packageManager
    && job.baseSha === DD_TRACE_OPENAI_JAVA_REPOSITORY.baseSha
    && sameStrings(job.policy.allowedPaths, DD_TRACE_OPENAI_JAVA_PATHS)
    && sameStrings(job.policy.modelReadablePaths, [
      'dd-java-agent/instrumentation/openai-java/openai-java-3.0/build.gradle',
      ...DD_TRACE_OPENAI_JAVA_PATHS,
      'dd-java-agent/instrumentation/openai-java/openai-java-3.0/src/test/groovy/ResponseServiceTest.groovy',
    ])
    && sameStrings(job.policy.allowedManifestPaths, [DD_TRACE_OPENAI_JAVA_PATHS[0]!])
    && sameStrings(job.policy.deniedPaths, ['.github/workflows', '.env', 'scripts', 'autoapi-validation'])
    && sameStrings(job.policy.allowedLanguages, ['java'])
    && sameStrings(job.policy.requiredChecks, ['java-openai-454-contract'])
    && job.policy.allowedNetworkHosts.length === 0
    && job.policy.maxChangedFiles === 3
    && job.policy.maxPatchBytes === 250_000
    && job.policy.maxModelInputBytes === 120_000
    && job.policy.maxModelOutputTokens === 10_000
    && job.policy.maxRunTimeMs === 3_600_000
    && job.policy.maxRepairAttempts === 1
    && job.policy.probableChanges.enabled === true
    && job.policy.probableChanges.allowHarness === true
    && job.policy.probableChanges.allowDraftPr === true
    && job.policy.probableChanges.maxChangedFiles === 10
    && job.policy.probableChanges.maxPatchBytes === 500_000
    && sameCommands(job.policy.validationCommands, [
      { executable: 'autoapi-validation/openai-java-callid/run-contract', args: [], timeoutMs: 90_000 },
      { executable: 'python', args: ['scripts/verify-autoapi-openai-java-454.py'], timeoutMs: 30_000 },
    ])
}

function matchesReviewedRepository(
  job: MigrationJob,
  canonicalName: string,
  publicName: string,
  canonicalOwners: readonly string[] = ['sajsnddkn'],
): boolean {
  return (canonicalOwners.includes(job.repository.owner) && job.repository.name === canonicalName)
    || (job.repository.owner === 'APPNINJAS123' && job.repository.name === publicName)
}

function matchesGenuineOpenAiJavaEvent(job: MigrationJob): boolean {
  const event = job.changeEvent
  const dependency = event.affectedDependencies[0]
  const operation = event.operations[0]
  const observedEvidence = new Set(event.evidence.map(item => `${item.url}\u0000${item.contentHash}`))
  return event.verificationStatus === 'verified'
    && event.provider === 'openai'
    && event.apiOrSdk === 'OpenAI Java SDK'
    && event.oldVersion === '4.52.0'
    && event.newVersion === '4.54.0'
    && event.recipeIds.length === 0
    && event.affectedPackages.length === 0
    && event.affectedApiHosts.length === 0
    && event.impactScope === 'sdk'
    && sameStrings(event.affectedLanguages, ['java'])
    && event.affectedDependencies.length === 1
    && dependency?.ecosystem === 'maven'
    && dependency.name === 'com.openai:openai-java'
    && sameStrings(dependency.importNames, ['com.openai'])
    && dependency.oldVersionRange === '>=4.52.0 <4.54.0'
    && dependency.newVersion === '4.54.0'
    && dependency.newArtifactSha256 === OPENAI_JAVA_EVIDENCE_HASHES[1]
    && event.operations.length === 1
    && operation?.kind === 'method_renamed'
    && operation?.operation === 'com.openai.models.responses.ResponseInputItem.FunctionCallOutput.callId()'
    && operation.oldSymbol === JVM_OLD_SYMBOL
    && operation.newSymbol === JVM_NEW_SYMBOL
    && operation.details?.['migrationHintType'] === 'method_rename'
    && event.evidence.length === OPENAI_JAVA_EVIDENCE.length
    && observedEvidence.size === OPENAI_JAVA_EVIDENCE.length
    && OPENAI_JAVA_EVIDENCE.every(([url, hash]) => observedEvidence.has(`${url}\u0000${hash}`))
}

function sameStrings(left: readonly string[] | undefined, right: readonly string[]): boolean {
  return left !== undefined
    && left.length === right.length
    && left.every((value, index) => value === right[index])
}

function sameCommands(
  left: readonly { executable: string; args: readonly string[]; timeoutMs: number }[],
  right: readonly { executable: string; args: readonly string[]; timeoutMs: number }[],
): boolean {
  return left.length === right.length && left.every((command, index) => {
    const expected = right[index]
    return expected !== undefined
      && command.executable === expected.executable
      && command.timeoutMs === expected.timeoutMs
      && sameStrings(command.args, expected.args)
  })
}
