import { createHash, randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import type { MigrationJob } from '@automated-api/contracts'
import { resolveExistingPathInsideRepository } from '@automated-api/remediation'
import { readJvmMetadata, type ReviewedJvmContext } from './reviewedJvmToolchain.js'

const BASE = '3b53abdc8ee91037f4ed5b045d172a0c906af64d'
const POM_PATH = 'autoapi-kotlin-proof/pom.xml'
const CANONICAL_POM_SHA256 = '88c8b06f3280ecc30207f17684cdf5fb3560162b5fb0361623ec89ec1dac7d79'
const OLD_VERSION = '1.1.7'
const TARGET_VERSION = '2.0.0-M8'
const OLD_JAR = '38df0789a4a889c580a8868347b38c18580669ea17f89d12d6c530154b59e277'
const TARGET_JAR = 'dd956118d84a12b7742979adc2fc67fd398fd72dde759e1980f8ae84036f3a62'
const TARGET_ARGUMENT = '-Dspring-ai.version=2.0.0-M8'

export const REVIEWED_EMBABEL_KOTLIN_RECIPE_ID = 'embabel-spring-ai-openai-1.1.7-2.0.0-M8-exact-v1'
export const REVIEWED_EMBABEL_KOTLIN_RECIPE_PROVENANCE = Object.freeze({
  upstreamBaseSha: 'dd432fa12e4ded6ed88712c1bd3fa461d47a6488',
  officialFixSha: 'f681b4c940bf416b9287859e89e45324b4d2c03e',
  officialFixUrl: 'https://github.com/embabel/embabel-agent/commit/f681b4c940bf416b9287859e89e45324b4d2c03e.patch',
  officialFixSha256: '9cb7557bd4beacd88c9c82eaf4a238ee9c4f668ad80e7ca35d625ea679f3df15',
  upstreamAsyncCorrectionSha: '4021424c127dc0f11efa92489c2d16a49429128b',
})

const FACTORY_PATH = 'embabel-agent-openai/src/main/kotlin/com/embabel/agent/openai/OpenAiCompatibleModelFactory.kt'
const DOCKER_PATH = 'embabel-agent-autoconfigure/models/embabel-agent-dockermodels-autoconfigure/src/main/kotlin/com/embabel/agent/config/models/docker/DockerLocalModelsConfig.kt'
const BASE_SOURCE_HASHES = Object.freeze({
  [FACTORY_PATH]: '6147bf70715066c63cb06a09399d3e29cf391827481dad9fc617c032c79de055',
  [DOCKER_PATH]: '6668a8d84d5c24e4abe12ee03081008b82bc4ee11f127df6aecee046291a8eaa',
})
const TARGET_SOURCE_HASHES = Object.freeze({
  [FACTORY_PATH]: '8c62438e361c1c972bb102529179f448066eb49762a8fc486ebae16a686c33b4',
  [DOCKER_PATH]: '05dce31a2c56c9cda1ae5f15c6011c079e881fcc3d14b63805d75f8fd1e0b167',
})

interface ExactReplacement { old: string; replacement: string }

const FACTORY_HISTORICAL_HUNKS: readonly ExactReplacement[] = [
  { old: "import com.embabel.common.byok.ByokFactory\nimport com.embabel.common.byok.InvalidApiKeyException\nimport com.embabel.common.util.ObjectProviders\nimport com.embabel.common.util.loggerFor\nimport io.micrometer.observation.ObservationRegistry\nimport org.slf4j.Logger\nimport org.slf4j.LoggerFactory\nimport org.springframework.ai.chat.model.ChatModel\nimport org.springframework.ai.document.MetadataMode\nimport org.springframework.ai.model.NoopApiKey\nimport org.springframework.ai.model.SimpleApiKey\nimport org.springframework.ai.model.tool.ToolCallingManager\nimport org.springframework.ai.openai.OpenAiChatModel\nimport org.springframework.ai.openai.OpenAiChatOptions\nimport org.springframework.ai.openai.OpenAiEmbeddingModel\nimport org.springframework.ai.openai.OpenAiEmbeddingOptions\nimport org.springframework.ai.openai.api.OpenAiApi\nimport org.springframework.ai.retry.RetryUtils\nimport org.springframework.beans.factory.ObjectProvider\nimport org.springframework.http.client.SimpleClientHttpRequestFactory\nimport org.springframework.retry.support.RetryTemplate\nimport org.springframework.web.client.RestClient\nimport org.springframework.web.reactive.function.client.WebClient\nimport java.time.LocalDate\n\n/**\n * Generic support for OpenAI compatible models.\n * Use to register LLM beans.\n * @param baseUrl The base URL of the OpenAI API. Null for OpenAI default.\n * @param apiKey The API key for the OpenAI compatible provider, or null for no authentication.\n */\nopen class OpenAiCompatibleModelFactory(\n    val baseUrl: String?,\n    private val apiKey: String?,\n    private val completionsPath: String?,\n    private val embeddingsPath: String?,\n    private val httpHeaders: Map<String,String> = emptyMap(),\n    private val observationRegistry: ObservationRegistry = ObservationRegistry.NOOP,\n    private val restClientBuilder: ObjectProvider<RestClient.Builder> = ObjectProviders.empty(),\n    private val webClientBuilder: ObjectProvider<WebClient.Builder> = ObjectProviders.empty(),\n) {\n\n    companion object {\n        private const val CONNECT_TIMEOUT_MS = 5000\n        private const val READ_TIMEOUT_MS = 600000\n        private val PASS_THROUGH_RETRY_TEMPLATE: RetryTemplate = RetryTemplate.builder().maxAttempts(1).build()\n\n        /**\n         * Returns a [ByokSpec] for OpenAI.\n", replacement: "import com.embabel.common.byok.ByokFactory\nimport com.embabel.common.byok.InvalidApiKeyException\nimport com.embabel.common.util.ObjectProviders\nimport com.openai.client.OpenAIClient\nimport com.openai.client.OpenAIClientAsync\nimport com.openai.client.okhttp.OpenAIOkHttpClient\nimport com.openai.client.okhttp.OpenAIOkHttpClientAsync\nimport io.micrometer.observation.ObservationRegistry\nimport org.slf4j.Logger\nimport org.slf4j.LoggerFactory\nimport org.springframework.ai.chat.model.ChatModel\nimport org.springframework.ai.document.MetadataMode\nimport org.springframework.ai.model.tool.ToolCallingManager\nimport org.springframework.ai.openai.OpenAiChatModel\nimport org.springframework.ai.openai.OpenAiChatOptions\nimport org.springframework.ai.openai.OpenAiEmbeddingModel\nimport org.springframework.ai.openai.OpenAiEmbeddingOptions\nimport org.springframework.beans.factory.ObjectProvider\nimport org.springframework.web.client.RestClient\nimport org.springframework.web.reactive.function.client.WebClient\nimport java.time.Duration\nimport java.time.LocalDate\n\n/**\n * Generic support for OpenAI compatible models.\n * Use to register LLM beans.\n *\n * Spring AI 2.0 swapped its hand-rolled `OpenAiApi` for the official openai-java SDK\n * (`OpenAIClient`). The migration removes Spring's `RestClient`/`WebClient` from the\n * HTTP path entirely \u2014 the SDK uses OkHttp internally. The [restClientBuilder] and\n * [webClientBuilder] parameters are kept for source compatibility with the previous\n * constructor signature but are no longer wired into HTTP calls. Likewise, retries\n * are now wrapped at the ChatClientLlmOperations layer via spring-retry, so any\n * `retryTemplate` argument here is a no-op.\n *\n * @param baseUrl The base URL of the OpenAI API. Null for OpenAI default.\n * @param apiKey The API key for the OpenAI compatible provider, or null for no authentication.\n * @param completionsPath Custom completions endpoint path (no longer settable on the\n *   openai-java SDK; logged as a warning and ignored \u2014 bake the full path into [baseUrl]).\n * @param embeddingsPath Custom embeddings endpoint path (same caveat as [completionsPath]).\n * @param httpHeaders Extra headers sent on every request, applied via OpenAIClient builder.\n * @param observationRegistry Micrometer registry for Spring AI's chat model instrumentation.\n * @param restClientBuilder Unused since Spring AI 2.0; retained for source compatibility.\n * @param webClientBuilder Unused since Spring AI 2.0; retained for source compatibility.\n */\nopen class OpenAiCompatibleModelFactory(\n    val baseUrl: String?,\n    private val apiKey: String?,\n    private val completionsPath: String? = null,\n    private val embeddingsPath: String? = null,\n    private val httpHeaders: Map<String, String> = emptyMap(),\n    private val observationRegistry: ObservationRegistry = ObservationRegistry.NOOP,\n    @Suppress(\"UNUSED_PARAMETER\")\n    restClientBuilder: ObjectProvider<RestClient.Builder> = ObjectProviders.empty(),\n    @Suppress(\"UNUSED_PARAMETER\")\n    webClientBuilder: ObjectProvider<WebClient.Builder> = ObjectProviders.empty(),\n) {\n\n    companion object {\n        private const val CONNECT_TIMEOUT_MS = 5_000L\n        private const val READ_TIMEOUT_MS = 600_000L\n\n        /**\n         * Returns a [ByokSpec] for OpenAI.\n" },
  { old: "            baseUrl ?: \"default OpenAI location\",\n            if (apiKey == null) \"not set\" else \"set\",\n        )\n    }\n\n    protected val openAiApi = createOpenAiApi()\n\n    private fun createOpenAiApi(): OpenAiApi {\n        val builder = OpenAiApi.builder()\n            .apiKey(if (apiKey != null) SimpleApiKey(apiKey) else NoopApiKey())\n        if (baseUrl != null) {\n            loggerFor<OpenAiModels>().info(\"Using custom OpenAI base URL: {}\", baseUrl)\n            builder.baseUrl(baseUrl)\n        }\n        if (completionsPath != null) {\n            loggerFor<OpenAiModels>().info(\"Using custom OpenAI completions path: {}\", completionsPath)\n            builder.completionsPath(completionsPath)\n        }\n        if (embeddingsPath != null) {\n            loggerFor<OpenAiModels>().info(\"Using custom OpenAI embeddings path: {}\", embeddingsPath)\n            builder.embeddingsPath(embeddingsPath)\n        }\n\n        //add observation registry to rest and web client builders\n        builder\n            .restClientBuilder(\n                restClientBuilder.getIfAvailable {\n                    RestClient.builder().requestFactory(\n                        SimpleClientHttpRequestFactory().apply {\n                            setConnectTimeout(CONNECT_TIMEOUT_MS)\n                            setReadTimeout(READ_TIMEOUT_MS)\n                        }\n                    )\n                }\n                    .observationRegistry(observationRegistry)\n            )\n        builder\n            .webClientBuilder(\n                webClientBuilder.getIfAvailable {\n                    WebClient.builder()\n                }\n                    .observationRegistry(observationRegistry)\n            )\n\n        return builder.build()\n    }\n\n", replacement: "            baseUrl ?: \"default OpenAI location\",\n            if (apiKey == null) \"not set\" else \"set\",\n        )\n        if (completionsPath != null) {\n            logger.warn(\n                \"completionsPath '{}' is no longer honoured by Spring AI 2.0 (openai-java SDK uses fixed endpoint paths). \" +\n                        \"Bake the path into baseUrl instead.\",\n                completionsPath,\n            )\n        }\n        if (embeddingsPath != null) {\n            logger.warn(\n                \"embeddingsPath '{}' is no longer honoured by Spring AI 2.0 (openai-java SDK uses fixed endpoint paths).\",\n                embeddingsPath,\n            )\n        }\n    }\n\n    /**\n     * Shared OpenAI client used by chat + embedding paths.\n     * Built lazily so subclasses can finish initialising before first use.\n     */\n    protected val openAiClient: OpenAIClient = createOpenAiClient()\n    protected val openAiClientAsync: OpenAIClientAsync = createOpenAiClientAsync()\n\n    private fun resolvedBaseUrl(): String? = baseUrl?.trimEnd('/')?.let { \"$it/v1\" }\n\n    private fun createOpenAiClient(): OpenAIClient {\n        val builder = OpenAIOkHttpClient.builder()\n            .timeout(Duration.ofMillis(READ_TIMEOUT_MS))\n        if (apiKey != null) {\n            builder.apiKey(apiKey)\n        } else {\n            builder.apiKey(\"no-auth\")\n        }\n        val baseUrl = resolvedBaseUrl()\n        if (baseUrl != null) {\n            logger.info(\"Using custom OpenAI base URL: {}\", baseUrl)\n            builder.baseUrl(baseUrl)\n        }\n        httpHeaders.forEach { (name, value) -> builder.putHeader(name, value) }\n        return builder.build()\n    }\n\n    private fun createOpenAiClientAsync(): OpenAIClientAsync {\n        val builder = OpenAIOkHttpClientAsync.builder()\n            .timeout(Duration.ofMillis(READ_TIMEOUT_MS))\n        if (apiKey != null) {\n            builder.apiKey(apiKey)\n        } else {\n            builder.apiKey(\"no-auth\")\n        }\n        val baseUrl = resolvedBaseUrl()\n        if (baseUrl != null) builder.baseUrl(baseUrl)\n        httpHeaders.forEach { (name, value) -> builder.putHeader(name, value) }\n        return builder.build()\n    }\n\n" },
  { old: "        provider: String,\n        knowledgeCutoffDate: LocalDate?,\n        optionsConverter: OptionsConverter<*> = OpenAiChatOptionsConverter,\n        retryTemplate: RetryTemplate = RetryUtils.DEFAULT_RETRY_TEMPLATE,\n    ): LlmService<*> {\n        return SpringAiLlmService(\n            name = model,\n            chatModel = chatModelOf(model, retryTemplate),\n            provider = provider,\n            optionsConverter = optionsConverter,\n            pricingModel = pricingModel,\n", replacement: "        provider: String,\n        knowledgeCutoffDate: LocalDate?,\n        optionsConverter: OptionsConverter<*> = OpenAiChatOptionsConverter,\n        @Suppress(\"UNUSED_PARAMETER\")\n        retryTemplate: Any? = null,\n    ): LlmService<*> {\n        return SpringAiLlmService(\n            name = model,\n            chatModel = chatModelOf(model),\n            provider = provider,\n            optionsConverter = optionsConverter,\n            pricingModel = pricingModel,\n" },
  { old: "     * Validates the configured API key by making a probe call, then returns a production\n     * [LlmService] if successful.\n     *\n     * The probe uses a single-attempt retry template (no retries) so a 401 fails fast.\n     * On any exception the provider-specific error is translated to [InvalidApiKeyException],\n     * keeping Spring AI types out of the caller.\n     */\n", replacement: "     * Validates the configured API key by making a probe call, then returns a production\n     * [LlmService] if successful.\n     *\n     * Spring AI 2.0 no longer accepts a spring-retry [RetryTemplate] on the model builder,\n     * so the probe relies on the openai-java SDK's own no-retry default (any 401 fails fast).\n     * On any exception the provider-specific error is translated to [InvalidApiKeyException],\n     * keeping Spring AI types out of the caller.\n     */\n" },
  { old: "            pricingModel = pricingModel,\n            provider = provider,\n            knowledgeCutoffDate = knowledgeCutoffDate,\n            retryTemplate = PASS_THROUGH_RETRY_TEMPLATE,\n        )\n        try {\n            probe.createMessageSender(LlmOptions()).call(listOf(UserMessage(\"Hi\")), emptyList())\n", replacement: "            pricingModel = pricingModel,\n            provider = provider,\n            knowledgeCutoffDate = knowledgeCutoffDate,\n        )\n        try {\n            probe.createMessageSender(LlmOptions()).call(listOf(UserMessage(\"Hi\")), emptyList())\n" },
  { old: "        pricingModel: PricingModel? = null,\n    ): EmbeddingService {\n        val embeddingModel = OpenAiEmbeddingModel(\n            openAiApi,\n            MetadataMode.EMBED,\n            OpenAiEmbeddingOptions.builder()\n                .model(model)\n                .build(),\n        )\n        return SpringAiEmbeddingService(\n            name = model,\n", replacement: "        pricingModel: PricingModel? = null,\n    ): EmbeddingService {\n        val embeddingModel = OpenAiEmbeddingModel(\n            openAiClient,\n            MetadataMode.EMBED,\n            OpenAiEmbeddingOptions.builder()\n                .model(model)\n                .build(),\n            observationRegistry,\n        )\n        return SpringAiEmbeddingService(\n            name = model,\n" },
  { old: "        )\n    }\n\n    protected fun chatModelOf(\n        model: String,\n        retryTemplate: RetryTemplate,\n    ): ChatModel {\n        return OpenAiChatModel.builder()\n            .defaultOptions(\n                OpenAiChatOptions.builder()\n                    .model(model)\n                    .httpHeaders(httpHeaders)\n                    .build()\n            )\n            .toolCallingManager(\n", replacement: "        )\n    }\n\n    /**\n     * Build the underlying [ChatModel] for [model].\n     *\n     * Spring AI 2.0 removed the spring-retry hook on this builder; retries are handled at the\n     * ChatClientLlmOperations layer instead. The [retryTemplate] parameter is kept for source\n     * compatibility with downstream subclasses (the previous Spring AI 1.x signature) but is\n     * ignored.\n     */\n    @JvmOverloads\n    protected fun chatModelOf(\n        model: String,\n        @Suppress(\"UNUSED_PARAMETER\")\n        retryTemplate: Any? = null,\n    ): ChatModel {\n        return OpenAiChatModel.builder()\n            .options(\n                OpenAiChatOptions.builder()\n                    .model(model)\n                    .apply { if (httpHeaders.isNotEmpty()) customHeaders(httpHeaders) }\n                    .build()\n            )\n            .toolCallingManager(\n" },
  { old: "                    .observationRegistry(observationRegistry)\n                    .build()\n            )\n            .openAiApi(openAiApi)\n            .retryTemplate(retryTemplate)\n            .observationRegistry(\n                observationRegistry\n            ).build()\n    }\n}\n\n", replacement: "                    .observationRegistry(observationRegistry)\n                    .build()\n            )\n            .openAiClient(openAiClient)\n            .openAiClientAsync(openAiClientAsync)\n            .observationRegistry(observationRegistry)\n            .build()\n    }\n}\n\n" },
]

const FACTORY_HUNKS: readonly ExactReplacement[] = [
  ...FACTORY_HISTORICAL_HUNKS,
  {
    old: '    private fun resolvedBaseUrl(): String? = baseUrl?.trimEnd(\'/\')?.let { "$it/v1" }',
    replacement: '    private fun resolvedBaseUrl(): String? = baseUrl?.trimEnd(\'/\')?.let {\n'
      + '        if (it.endsWith("/v1")) it else "$it/v1"\n'
      + '    }',
  },
]

const DOCKER_HUNKS: readonly ExactReplacement[] = [
  { old: "import com.embabel.common.ai.autoconfig.RegisteredModel\nimport com.embabel.common.ai.model.*\nimport com.embabel.common.util.ExcludeFromJacocoGeneratedReport\nimport io.micrometer.observation.ObservationRegistry\nimport org.slf4j.LoggerFactory\nimport org.springframework.ai.document.MetadataMode\nimport org.springframework.ai.model.NoopApiKey\nimport org.springframework.ai.model.tool.ToolCallingManager\nimport org.springframework.ai.openai.OpenAiChatModel\nimport org.springframework.ai.openai.OpenAiChatOptions\nimport org.springframework.ai.openai.OpenAiEmbeddingModel\nimport org.springframework.ai.openai.OpenAiEmbeddingOptions\nimport org.springframework.ai.openai.api.OpenAiApi\nimport org.springframework.beans.factory.ObjectProvider\nimport org.springframework.beans.factory.config.ConfigurableBeanFactory\nimport org.springframework.boot.context.properties.ConfigurationProperties\n", replacement: "import com.embabel.common.ai.autoconfig.RegisteredModel\nimport com.embabel.common.ai.model.*\nimport com.embabel.common.util.ExcludeFromJacocoGeneratedReport\nimport com.openai.client.OpenAIClient\nimport com.openai.client.OpenAIClientAsync\nimport com.openai.client.okhttp.OpenAIOkHttpClient\nimport com.openai.client.okhttp.OpenAIOkHttpClientAsync\nimport io.micrometer.observation.ObservationRegistry\nimport org.slf4j.LoggerFactory\nimport org.springframework.ai.document.MetadataMode\nimport org.springframework.ai.model.tool.ToolCallingManager\nimport org.springframework.ai.openai.OpenAiChatModel\nimport org.springframework.ai.openai.OpenAiChatOptions\nimport org.springframework.ai.openai.OpenAiEmbeddingModel\nimport org.springframework.ai.openai.OpenAiEmbeddingOptions\nimport org.springframework.beans.factory.ObjectProvider\nimport org.springframework.beans.factory.config.ConfigurableBeanFactory\nimport org.springframework.boot.context.properties.ConfigurationProperties\n" },
  { old: "import org.springframework.http.MediaType\nimport org.springframework.web.client.RestClient\nimport org.springframework.web.client.body\nimport org.springframework.web.reactive.function.client.WebClient\n\n\n@ConfigurationProperties(prefix = \"embabel.agent.platform.models.docker\")\n", replacement: "import org.springframework.http.MediaType\nimport org.springframework.web.client.RestClient\nimport org.springframework.web.client.body\n\n\n@ConfigurationProperties(prefix = \"embabel.agent.platform.models.docker\")\n" },
  { old: " * discovery fails silently and no models are registered.\n * Model names will be precisely as reported from\n * http://localhost:12434/engines/v1/models (assuming default port).\n */\n@ExcludeFromJacocoGeneratedReport(reason = \"Docker model configuration can't be unit tested\")\n@Configuration(proxyBeanMethods = false)\n", replacement: " * discovery fails silently and no models are registered.\n * Model names will be precisely as reported from\n * http://localhost:12434/engines/v1/models (assuming default port).\n *\n * Spring AI 2.0 swapped its hand-rolled `OpenAiApi` for the openai-java SDK\n * ([OpenAIClient]). The migration removes Spring's `RestClient`/`WebClient` from\n * the OpenAI HTTP path entirely \u2014 the SDK uses OkHttp internally. Spring AI 2.0\n * also dropped the spring-retry `RetryTemplate` parameter on `OpenAiChatModel.Builder`;\n * retries are now wrapped at the ChatClientLlmOperations layer instead.\n */\n@ExcludeFromJacocoGeneratedReport(reason = \"Docker model configuration can't be unit tested\")\n@Configuration(proxyBeanMethods = false)\n" },
  { old: "    ConfigurableModelProviderProperties::class\n)\nclass DockerLocalModelsConfig(\n    private val dockerRetryProperties: DockerRetryProperties,\n    private val dockerConnectionProperties: DockerConnectionProperties,\n    private val configurableBeanFactory: ConfigurableBeanFactory,\n    private val properties: ConfigurableModelProviderProperties,\n", replacement: "    ConfigurableModelProviderProperties::class\n)\nclass DockerLocalModelsConfig(\n    @Suppress(\"UNUSED_PARAMETER\")\n    dockerRetryProperties: DockerRetryProperties,\n    private val dockerConnectionProperties: DockerConnectionProperties,\n    private val configurableBeanFactory: ConfigurableBeanFactory,\n    private val properties: ConfigurableModelProviderProperties,\n" },
  { old: "    private data class Model(\n        val id: String,\n    )\n\n    private fun loadModels(): List<Model> =\n        try {\n", replacement: "    private data class Model(\n        val id: String,\n    )\n\n    /**\n     * Shared OpenAI-compatible client pointing at the local Docker endpoint.\n     * Built lazily on first model creation so a missing endpoint doesn't crash\n     * Spring startup (loadModels already swallows the failure).\n     */\n    private val openAiClient: OpenAIClient by lazy {\n        OpenAIOkHttpClient.builder()\n            .baseUrl(\"${dockerConnectionProperties.baseUrl.trimEnd('/')}/v1\")\n            // The openai-java SDK rejects null/blank API keys even when the\n            // backing server doesn't require auth. Placeholder is fine.\n            .apiKey(\"no-auth\")\n            .build()\n    }\n\n    private val openAiClientAsync: OpenAIClientAsync by lazy {\n        OpenAIOkHttpClientAsync.builder()\n            .baseUrl(\"${dockerConnectionProperties.baseUrl.trimEnd('/')}/v1\")\n            .apiKey(\"no-auth\")\n            .build()\n    }\n\n    private fun loadModels(): List<Model> =\n        try {\n" },
  { old: "\n    private fun dockerEmbeddingServiceOf(model: Model): SpringAiEmbeddingService {\n        val springEmbeddingModel = OpenAiEmbeddingModel(\n            OpenAiApi.Builder()\n                .baseUrl(dockerConnectionProperties.baseUrl)\n                .apiKey(NoopApiKey())\n                .build(),\n            MetadataMode.EMBED,\n            OpenAiEmbeddingOptions.builder()\n                .model(model.id)\n                .build(),\n        )\n\n        return SpringAiEmbeddingService(\n", replacement: "\n    private fun dockerEmbeddingServiceOf(model: Model): SpringAiEmbeddingService {\n        val springEmbeddingModel = OpenAiEmbeddingModel(\n            openAiClient,\n            MetadataMode.EMBED,\n            OpenAiEmbeddingOptions.builder()\n                .model(model.id)\n                .build(),\n            observationRegistry.getIfUnique { ObservationRegistry.NOOP },\n        )\n\n        return SpringAiEmbeddingService(\n" },
  { old: "\n    private fun dockerLlmOf(model: Model): SpringAiLlmService {\n        val chatModel = OpenAiChatModel.builder()\n            .openAiApi(\n                OpenAiApi.Builder()\n                    .baseUrl(dockerConnectionProperties.baseUrl)\n                    .apiKey(NoopApiKey())\n                    .restClientBuilder(\n                        RestClient.builder()\n                            .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n                    )\n                    .webClientBuilder(\n                        WebClient.builder()\n                            .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n                    )\n                    .build()\n            )\n            .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n            .toolCallingManager(\n                ToolCallingManager.builder()\n                    .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n                    .build()\n            )\n            .defaultOptions(\n                OpenAiChatOptions.builder()\n                    .model(model.id)\n                    .build()\n            )\n            .retryTemplate(dockerRetryProperties.retryTemplate(\"docker-${model.id}\"))\n            .build()\n        return SpringAiLlmService(\n            name = model.id,\n", replacement: "\n    private fun dockerLlmOf(model: Model): SpringAiLlmService {\n        val chatModel = OpenAiChatModel.builder()\n            .openAiClient(openAiClient)\n            .openAiClientAsync(openAiClientAsync)\n            .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n            .toolCallingManager(\n                ToolCallingManager.builder()\n                    .observationRegistry(observationRegistry.getIfUnique { ObservationRegistry.NOOP })\n                    .build()\n            )\n            .options(\n                OpenAiChatOptions.builder()\n                    .model(model.id)\n                    .build()\n            )\n            .build()\n        return SpringAiLlmService(\n            name = model.id,\n" },
]

const BASE_POM_SHA256 = 'd90331743692f37b918cd276836bde76fbe165717c462b19514b071bd950cf92'
const TARGET_POM_SHA256 = '9378748355c8780b883e9e5a6b9216245c0f192411f668f456fff423ed76374b'

const EXPECTED_POLICY = Object.freeze({
  allowedPaths: [POM_PATH, FACTORY_PATH, DOCKER_PATH],
  modelReadablePaths: [FACTORY_PATH, DOCKER_PATH],
  deniedPaths: ['.github/workflows', '.env', 'scripts'],
  validationCommands: [
    { executable: 'python', args: ['scripts/verify-autoapi-spring-ai-m8.py', 'target', '--manifest-only'], timeoutMs: 60_000 },
    { executable: './mvnw', args: ['-o', '-B', TARGET_ARGUMENT, '-f', POM_PATH, 'clean', 'verify'], timeoutMs: 900_000 },
    { executable: 'python', args: ['scripts/verify-autoapi-spring-ai-m8.py', 'target', '--compiled'], timeoutMs: 60_000 },
  ],
  allowedNetworkHosts: [],
  maxChangedFiles: 3,
  maxPatchBytes: 300_000,
  maxModelInputBytes: 180_000,
  maxModelOutputTokens: 16_000,
  maxRunTimeMs: 3_600_000,
  maxRepairAttempts: 1,
  requiredChecks: ['kotlin-spring-ai-m8-contract'],
  allowedLanguages: ['kotlin'],
  allowedManifestPaths: [POM_PATH],
  probableChanges: { enabled: true, allowHarness: true, allowDraftPr: true, maxChangedFiles: 10, maxPatchBytes: 500_000 },
})

const EXPECTED_EVIDENCE = Object.freeze([
  ['https://raw.githubusercontent.com/spring-projects/spring-ai/63f321c2a6c8369487d33f71bccf476c27faf5c3/spring-ai-docs/src/main/antora/modules/ROOT/pages/upgrade-notes.adoc', 'e3368aafb27679c85bfbf22ff73db7202e8558ffbe43294dac3917a1cbf0a3d5', 'spring-ai migration_guide'],
  ['https://raw.githubusercontent.com/spring-projects/spring-ai/d8503868d3e84547db51d8f10379e1a075fe2d99/models/spring-ai-openai/src/main/java/org/springframework/ai/openai/OpenAiChatModel.java', '20f2718766f1e41e7995d555ea63542332b4a128cc913a35f820f9d447555840', 'spring-ai sdk'],
  ['https://raw.githubusercontent.com/spring-projects/spring-ai/d8503868d3e84547db51d8f10379e1a075fe2d99/models/spring-ai-openai/src/main/java/org/springframework/ai/openai/OpenAiEmbeddingModel.java', '79145f70d33984390502c6e297b053369397ad53ee744818779e2e5d6e7f5f22', 'spring-ai sdk'],
  ['https://raw.githubusercontent.com/spring-projects/spring-ai/ee80d234382117eadceb7b76bb6819738d98e8d8/models/spring-ai-openai/src/main/java/org/springframework/ai/openai/OpenAiChatModel.java', '97d87d7e534e82a824ac8e5aa38bb48d91f055a31acbac5ec5ce4cb015452429', 'spring-ai sdk'],
  ['https://raw.githubusercontent.com/spring-projects/spring-ai/ee80d234382117eadceb7b76bb6819738d98e8d8/models/spring-ai-openai/src/main/java/org/springframework/ai/openai/OpenAiEmbeddingModel.java', 'c2a638befeb8a4ed023496c5742e58b268133295f9f7a91c0b7803c8416c3a58', 'spring-ai sdk'],
  ['https://repo1.maven.org/maven2/org/springframework/ai/spring-ai-openai/1.1.7/spring-ai-openai-1.1.7.jar', OLD_JAR, 'spring-ai sdk'],
  ['https://repo1.maven.org/maven2/org/springframework/ai/spring-ai-openai/2.0.0-M8/spring-ai-openai-2.0.0-M8.jar', TARGET_JAR, 'spring-ai sdk'],
] as const)

const EXPECTED_OPERATIONS = Object.freeze([
  ['OpenAiChatModel.Builder OpenAI transport', 'openAiApi(Lorg/springframework/ai/openai/api/OpenAiApi;)', 'openAiClient(Lcom/openai/client/OpenAIClient;)', 'dc2b565a01c9e155912d52d9f1c2bf79960cd7553e233ccd5e5b11e3f17355ca'],
  ['OpenAiChatModel.Builder options', 'defaultOptions(Lorg/springframework/ai/openai/OpenAiChatOptions;)', 'options(Lorg/springframework/ai/openai/OpenAiChatOptions;)', '1b9c8f5070a98a8c95a4edf95692c8ecb3423587887ab87da6239815ad5b6f57'],
] as const)


/** This is authority for one reviewed test overlay, not general Maven property editing. */
export function isReviewedKotlinConsumerJob(job: MigrationJob): boolean {
  return job.baseSha === BASE
    && ((job.repository.owner === 'sajsnddkn'
      && job.repository.name === 'autoapi-real-embabel-spring-ai-kotlin')
      || (job.repository.owner === 'APPNINJAS123'
        && job.repository.name === 'autoapi-real-embabel-spring-ai-kotlin-public'))
    && job.repository.defaultBranch === 'autoapi-kotlin-1.1.7-historical-base'
    && job.repository.workingDirectory === '.'
    && job.repository.packageManagerDirectory === 'autoapi-kotlin-proof'
    && job.repository.packageManager === 'maven@3.9.11'
}

function assertMigrationAuthority(job: MigrationJob): void {
  const event = job.changeEvent
  const dependency = event.affectedDependencies[0]
  if (event.verificationStatus !== 'verified'
    || event.affectedLanguages.length !== 1 || event.affectedLanguages[0] !== 'kotlin'
    || event.oldVersion !== OLD_VERSION || event.newVersion !== TARGET_VERSION
    || event.affectedDependencies.length !== 1 || dependency?.ecosystem !== 'maven'
    || dependency.name !== 'org.springframework.ai:spring-ai-openai'
    || dependency.oldVersionRange !== OLD_VERSION || dependency.newVersion !== TARGET_VERSION
    || dependency.newArtifactSha256 !== TARGET_JAR
    || ![OLD_JAR, TARGET_JAR].every(hash => event.evidence.some(item => item.contentHash === hash))
    || job.policy.allowedManifestPaths?.length !== 1 || job.policy.allowedManifestPaths[0] !== POM_PATH) {
    throw new Error('Reviewed Kotlin consumer requires its exact verified SDK artifact and manifest authority')
  }
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function exactStrings(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index])
}

function assertExactRecipeAuthority(job: MigrationJob): void {
  assertMigrationAuthority(job)
  const event = job.changeEvent
  const dependency = event.affectedDependencies[0]!
  const exactDependency = dependency.ecosystem === 'maven'
    && dependency.name === 'org.springframework.ai:spring-ai-openai'
    && exactStrings(dependency.importNames, ['org.springframework.ai.openai'])
    && dependency.oldVersionRange === OLD_VERSION
    && dependency.newVersion === TARGET_VERSION
    && dependency.newArtifactSha256 === TARGET_JAR
  const exactEvidence = event.evidence.length === EXPECTED_EVIDENCE.length
    && event.evidence.every((item, index) => {
      const expected = EXPECTED_EVIDENCE[index]!
      return item.url === expected[0] && item.contentHash === expected[1] && item.title === expected[2]
    })
  const exactOperations = event.operations.length === EXPECTED_OPERATIONS.length
    && event.operations.every((operation, index) => {
      const expected = EXPECTED_OPERATIONS[index]!
      const details = operation.details
      return operation.kind === 'method_renamed'
        && operation.operation === expected[0]
        && operation.oldSymbol === expected[1]
        && operation.newSymbol === expected[2]
        && details.migrationHintType === 'method_rename'
        && details.sourceProvenanceHash === expected[3]
        && typeof details.instructions === 'string' && details.instructions.length > 0
        && typeof details.sourceEventId === 'string' && /^chg_[0-9a-f]{24}$/u.test(details.sourceEventId)
        && Object.keys(details).sort().join(',') === 'instructions,migrationHintType,sourceEventId,sourceProvenanceHash'
    })
  // Part A regenerates source event IDs and explanatory prose on each real
  // collection. Bind their stable semantic/provenance tuples, then require the
  // fresh IDs to reproduce the signed package-major lineage fingerprint.
  const sourceEvents = event.operations.map(operation => ({
    id: operation.details.sourceEventId,
    provenanceHash: operation.details.sourceProvenanceHash,
  })).sort((left, right) => String(left.id).localeCompare(String(right.id)))
  const bundleFingerprint = createHash('sha256').update(Buffer.from(JSON.stringify({
    schemaVersion: '1.0',
    sourceEvents,
  }))).digest('hex')
  if (job.repairAttempt !== 0 || job.repairContext !== undefined
    || stableJson(job.policy) !== stableJson(EXPECTED_POLICY)
    || event.schemaVersion !== '1.0' || event.provider !== 'spring-ai'
    || event.apiOrSdk !== 'Spring AI OpenAI' || event.impactScope !== 'sdk'
    || event.oldVersion !== OLD_VERSION || event.newVersion !== TARGET_VERSION
    || event.verificationStatus !== 'verified' || event.confidence !== 0.95
    || !exactStrings(event.affectedPackages, []) || !exactStrings(event.affectedLanguages, ['kotlin'])
    || !exactStrings(event.affectedApiHosts, []) || event.affectedDependencies.length !== 1
    || !exactDependency || !exactStrings(event.recipeIds, []) || !exactOperations || !exactEvidence
    || !/^chg_[0-9a-f]{24}$/u.test(event.id) || !/^[0-9a-f]{64}$/u.test(event.provenanceHash)
    || event.provenanceHash !== bundleFingerprint || event.id !== `chg_${bundleFingerprint.slice(0, 24)}`
    || !Number.isFinite(Date.parse(event.verifiedAt))) {
    throw new Error('Reviewed Embabel recipe requires its exact repository policy and live Part A event tuple')
  }
}

/** Select the exact reviewed deterministic route without reading or mutating
 * customer files. A matching repository with changed authority fails closed. */
export function hasReviewedEmbabelKotlinRecipeAuthority(job: MigrationJob): boolean {
  if (!isReviewedKotlinConsumerJob(job)) return false
  assertExactRecipeAuthority(job)
  return true
}

function applyExactHunks(content: string, hunks: readonly ExactReplacement[], path: string): string {
  let migrated = content
  for (const [index, hunk] of hunks.entries()) {
    const first = migrated.indexOf(hunk.old)
    if (first === -1 || migrated.indexOf(hunk.old, first + hunk.old.length) !== -1) {
      throw new Error(`Reviewed Embabel source hunk ${index + 1} is not unique in ${path}`)
    }
    migrated = `${migrated.slice(0, first)}${hunk.replacement}${migrated.slice(first + hunk.old.length)}`
  }
  return migrated
}

interface AtomicRecipeEntry {
  logicalPath: string
  path: string
  original: Buffer
  target: Buffer
  mode: number
  stagedPath: string
  backupPath: string
  backupReady: boolean
  committed: boolean
}

/** Test-only fault hook used to prove cross-file rollback. Production callers omit it. */
export interface ReviewedKotlinRecipeOptions {
  beforeCommit?: (index: number, path: string) => void | Promise<void>
}

async function applyAtomically(entries: AtomicRecipeEntry[], options: ReviewedKotlinRecipeOptions): Promise<void> {
  try {
    for (const entry of entries) {
      const handle = await open(entry.stagedPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, entry.mode)
      try {
        await handle.writeFile(entry.target)
        await handle.sync()
      } finally {
        await handle.close()
      }
    }
    for (const entry of entries) {
      const current = await readFile(entry.path)
      const stat = await lstat(entry.path)
      if (!stat.isFile() || stat.isSymbolicLink() || !current.equals(entry.original)) {
        throw new Error(`Reviewed Embabel source changed during transaction: ${entry.logicalPath}`)
      }
    }
    for (const [index, entry] of entries.entries()) {
      await options.beforeCommit?.(index, entry.logicalPath)
      await rename(entry.path, entry.backupPath)
      entry.backupReady = true
      await rename(entry.stagedPath, entry.path)
      entry.committed = true
    }
  } catch (error) {
    const rollbackErrors: unknown[] = []
    for (const entry of [...entries].reverse()) {
      try {
        if (entry.committed) await rm(entry.path, { force: true })
        if (entry.backupReady) await rename(entry.backupPath, entry.path)
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError)
      }
    }
    await Promise.all(entries.map(entry => rm(entry.stagedPath, { force: true }).catch(() => undefined)))
    if (rollbackErrors.length > 0) throw new AggregateError([error, ...rollbackErrors], 'Reviewed Embabel transaction rollback failed')
    throw error
  }
  // The target bytes are committed at this point. Backup cleanup is best effort;
  // cleanup failure must not misreport a completed migration as an unknown state.
  await Promise.all(entries.map(entry => rm(entry.backupPath, { force: true }).catch(() => undefined)))
}

/** Exact three-file migration for the reviewed Embabel Spring AI M8 acceptance repository. */
export async function applyReviewedEmbabelKotlinRecipe(
  repositoryRoot: string,
  job: MigrationJob,
  options: ReviewedKotlinRecipeOptions = {},
): Promise<{ recipeId: typeof REVIEWED_EMBABEL_KOTLIN_RECIPE_ID; changedFiles: string[]; notes: string[] } | undefined> {
  if (!hasReviewedEmbabelKotlinRecipeAuthority(job)) return undefined
  const pom = await readReviewedKotlinPom(repositoryRoot, job, 'either')
  if (pom === undefined) throw new Error('Reviewed Embabel proof POM is unavailable')
  const sourceSpecs = [
    { path: FACTORY_PATH, hunks: FACTORY_HUNKS },
    { path: DOCKER_PATH, hunks: DOCKER_HUNKS },
  ] as const
  const resolvedSources = await Promise.all(sourceSpecs.map(async spec => {
    const logicalPath = spec.path
    const source = await readJvmMetadata(repositoryRoot, logicalPath)
    if (source === undefined) throw new Error(`Reviewed Embabel source is missing: ${logicalPath}`)
    const path = resolve(repositoryRoot, logicalPath)
    const content = Buffer.from(source, 'utf8')
    const stat = await lstat(path)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Reviewed Embabel source must be a regular non-symlink: ${logicalPath}`)
    return { logicalPath, path, hunks: spec.hunks, content, stat }
  }))
  const sourceStates = resolvedSources.map(source => {
    const digest = createHash('sha256').update(source.content).digest('hex')
    if (digest === BASE_SOURCE_HASHES[source.logicalPath]) return 'baseline'
    if (digest === TARGET_SOURCE_HASHES[source.logicalPath]) return 'target'
    throw new Error(`Reviewed Embabel source bytes changed: ${source.logicalPath}`)
  })
  const pomDigest = createHash('sha256').update(pom.content).digest('hex')
  const allTarget = sourceStates.every(state => state === 'target') && pom.version === TARGET_VERSION
  if (allTarget) {
    if (pomDigest !== TARGET_POM_SHA256) throw new Error('Reviewed Embabel target POM bytes changed')
    return { recipeId: REVIEWED_EMBABEL_KOTLIN_RECIPE_ID, changedFiles: [], notes: ['exact target already applied'] }
  }
  if (!sourceStates.every(state => state === 'baseline') || pom.version !== OLD_VERSION || pomDigest !== BASE_POM_SHA256) {
    throw new Error('Reviewed Embabel checkout is a mixed or unreviewed migration state')
  }
  const sourceTargets = resolvedSources.map(source => {
    const content = Buffer.from(applyExactHunks(source.content.toString('utf8'), source.hunks, source.logicalPath), 'utf8')
    const digest = createHash('sha256').update(content).digest('hex')
    if (digest !== TARGET_SOURCE_HASHES[source.logicalPath]) {
      throw new Error(`Reviewed Embabel target hash mismatch: ${source.logicalPath}`)
    }
    return { content, source }
  })
  const targetPom = Buffer.from(pom.content.replace(
    `<spring-ai.version>${OLD_VERSION}</spring-ai.version>`,
    `<spring-ai.version>${TARGET_VERSION}</spring-ai.version>`,
  ), 'utf8')
  if (createHash('sha256').update(targetPom).digest('hex') !== TARGET_POM_SHA256) {
    throw new Error('Reviewed Embabel target POM hash mismatch')
  }
  const pomPath = await resolveExistingPathInsideRepository(repositoryRoot, POM_PATH)
  const pomStat = await lstat(pomPath)
  if (!pomStat.isFile() || pomStat.isSymbolicLink()) throw new Error('Reviewed Embabel POM must be a regular non-symlink')
  const token = randomUUID()
  const entries: AtomicRecipeEntry[] = [
    { logicalPath: POM_PATH, path: pomPath, original: Buffer.from(pom.content), target: targetPom, mode: pomStat.mode & 0o777,
      stagedPath: resolve(dirname(pomPath), `.autoapi-${token}.tmp`), backupPath: resolve(dirname(pomPath), `.autoapi-${token}.bak`), backupReady: false, committed: false },
    ...sourceTargets.map(({ content, source }, index) => ({ logicalPath: source.logicalPath, path: source.path,
      original: source.content, target: content, mode: source.stat.mode & 0o777,
      stagedPath: resolve(dirname(source.path), `.autoapi-${token}-${index}.tmp`),
      backupPath: resolve(dirname(source.path), `.autoapi-${token}-${index}.bak`), backupReady: false, committed: false })),
  ]
  await applyAtomically(entries, options)
  return {
    recipeId: REVIEWED_EMBABEL_KOTLIN_RECIPE_ID,
    changedFiles: [POM_PATH, FACTORY_PATH, DOCKER_PATH],
    notes: ['applied exact reviewed Spring AI M8 migration to two consumers and one proof POM'],
  }
}

export async function readReviewedKotlinPom(
  repositoryRoot: string, job: MigrationJob, expected: 'baseline' | 'target' | 'either',
): Promise<{ content: string; version: string } | undefined> {
  if (!isReviewedKotlinConsumerJob(job)) return undefined
  assertMigrationAuthority(job)
  const content = await readJvmMetadata(repositoryRoot, POM_PATH)
  if (content === undefined) throw new Error('Reviewed Kotlin consumer proof POM is missing')
  const properties = [...content.matchAll(/<spring-ai\.version>(1\.1\.7|2\.0\.0-M8)<\/spring-ai\.version>/gu)]
  if (properties.length !== 1) throw new Error('Reviewed Kotlin proof POM needs one exact SDK version property')
  const version = properties[0]![1]!
  const canonical = content.replace(properties[0]![0], '<spring-ai.version>AUTOAPI_REVIEWED_SDK_VERSION</spring-ai.version>')
  if (createHash('sha256').update(canonical).digest('hex') !== CANONICAL_POM_SHA256) {
    throw new Error('Reviewed Kotlin proof POM changed outside the one SDK version property')
  }
  if (expected !== 'either' && version !== (expected === 'baseline' ? OLD_VERSION : TARGET_VERSION)) {
    throw new Error(`Reviewed Kotlin ${expected} requires its exact ${expected === 'baseline' ? OLD_VERSION : TARGET_VERSION} POM`)
  }
  return { content, version }
}

/** Preserve every manifest byte except the approved old-to-target property value. */
export async function migrateReviewedKotlinPom(repositoryRoot: string, job: MigrationJob): Promise<boolean | undefined> {
  const pom = await readReviewedKotlinPom(repositoryRoot, job, 'either')
  if (pom === undefined) return undefined
  if (pom.version === TARGET_VERSION) return false
  const path = await resolveExistingPathInsideRepository(repositoryRoot, POM_PATH)
  await writeFile(path, pom.content.replace(
    `<spring-ai.version>${OLD_VERSION}</spring-ai.version>`,
    `<spring-ai.version>${TARGET_VERSION}</spring-ai.version>`,
  ), 'utf8')
  return true
}

/** Host preparation passes this only to the disposable TARGET graph invocation. */
export async function reviewedKotlinTargetPreparationArgument(repositoryRoot: string, job: MigrationJob): Promise<string> {
  return await readReviewedKotlinPom(repositoryRoot, job, 'target') === undefined ? '' : TARGET_ARGUMENT
}

/** Original certification must not select the target framework profile. Offline
 * proposal sync selects it only after validating the actual migrated POM bytes. */
export async function reviewedKotlinMavenArguments(
  managerRoot: string, context: ReviewedJvmContext | undefined,
): Promise<string[]> {
  if (context === undefined || !isReviewedKotlinConsumerJob(context.job)) return []
  const expected = await resolveExistingPathInsideRepository(context.repositoryRoot, 'autoapi-kotlin-proof')
  if (await realpath(resolve(managerRoot)) !== expected) throw new Error('Reviewed Kotlin Maven manager root differs from its job')
  const pom = await readReviewedKotlinPom(context.repositoryRoot, context.job, 'either')
  return pom?.version === TARGET_VERSION ? [TARGET_ARGUMENT] : []
}
