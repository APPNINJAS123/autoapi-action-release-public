export {
  analyzeRepository,
  analyzeFirecrawlRepository,
  npmRangesMayIntersect,
  type AnalyzeRepositoryInput,
} from './impact.js'
export {
  analyzePythonRepository,
  effectivePythonDependencies,
  type AnalyzePythonRepositoryInput,
} from './python-impact.js'
export {
  analyzeGoRepository,
  analyzeRustRepository,
  type AnalyzeNativeRepositoryInput,
} from './native-impact.js'
export {
  analyzeManagedRepository,
  type AnalyzeManagedRepositoryInput,
} from './managed-impact.js'
export { jvmDescriptorMethodName, jvmDescriptorSourceCalls } from './jvm-source-methods.js'
export { reviewedSwiftResponseChange, swiftResponseContentAccesses, type SwiftResponseContentAccess } from './swift-response-access.js'
export {
  analyzeCRepository,
  analyzeCppRepository,
  parseVcpkgManifest,
  type AnalyzeCppRepositoryInput,
} from './cpp-impact.js'
export {
  applyFirecrawlPythonV1ToV2Recipe,
  FIRECRAWL_PYTHON_OLD_VERSION,
  FIRECRAWL_PYTHON_TARGET_SHA256,
  FIRECRAWL_PYTHON_TARGET_VERSION,
  FIRECRAWL_PYTHON_V1_V2_RECIPE_ID,
} from './python-recipes.js'
export {
  applyFirecrawlV1ToV2DependencyUpdate,
  applyFirecrawlV1ToV2Recipe,
  FIRECRAWL_TARGET_PACKAGE_VERSION,
  FIRECRAWL_V1_V2_RECIPE_ID,
  UnsafeMigrationError,
  type RecipeResult,
} from './recipe.js'
export {
  applyReviewedProviderDependencyUpdate,
  applyReviewedProviderRecipe,
  declaredMajor,
  inspectReviewedRecipeSource,
  REVIEWED_PROVIDER_RECIPES,
  reviewedRecipeDependencies,
  reviewedRecipeForEvent,
  type PackageMigration,
  type RecipeUsage,
  type ReviewedProviderRecipe,
} from './provider-recipes.js'
export {
  applyProposedEdits,
  DeepSeekHarnessMigrationExecutor,
  extractHarnessJson,
  HarnessExecutionError,
  MAX_HARNESS_MODEL_ATTEMPTS_PER_CONTEXT,
  readHarnessFailureProvenance,
  sha256,
  validateProposedEdits,
  createHarnessRepairEditBoundaries,
  captureHarnessValidatedEditBoundaries,
  type HarnessRuntime,
  type HarnessRuntimeFactory,
  type HarnessFailureCategory,
  type HarnessFailureProvenance,
  type HarnessModelConfiguration,
  type MigrationExecutor,
  type MigrationExecutorInput,
  type MigrationExecutorResult,
  type NetworkPolicyGuard,
  type ProposedEdit,
  type UnresolvedFile,
} from './executor.js'
export {
  bindHarnessRepairEditBoundaries,
  preserveHarnessAffectedUsageWindows,
  type PreservedAffectedUsageWindow,
} from './repair-edit-boundaries.js'
export {
  DshSdkHarnessRuntimeFactory,
  finishReasonFromEvents,
  harnessDiagnosticFromEvents,
  type DshSdkFactoryOptions,
} from './dsh-sdk.js'
export {
  assertPathAllowed,
  normalizeRepositoryPath,
  PolicyViolationError,
  resolveExistingPathInsideRepository,
  resolveInsideRepository,
  resolveWritablePathInsideRepository,
} from './policy.js'
export {
  assertNonSyntheticChangeEvent,
  type ChangeEventEvidenceBoundary,
} from './evidence-boundary.js'
