#!/usr/bin/env node
import { createToolchainCertification } from './toolchainCertification.js'

const [jobPath, repositoryPath, outputPath] = process.argv.slice(2)
if (jobPath === undefined || repositoryPath === undefined || outputPath === undefined) {
  console.error('usage: automated-api-toolchain-certification <job.json> <repository> <output.json>')
  process.exitCode = 2
} else {
  const required = (name: string): string => {
    const value = process.env[name]?.trim()
    if (value === undefined || value === '') throw new Error(`${name} is required`)
    return value
  }
  await createToolchainCertification({
    jobPath,
    repositoryPath,
    outputPath,
    expectedManager: {
      name: required('MANAGER_NAME') as never,
      version: required('MANAGER_VERSION'),
      spec: required('MANAGER_SPEC'),
      variant: required('MANAGER_VARIANT') as never,
      lockfile: required('MANAGER_LOCKFILE') as never,
      ...(process.env['RUNTIME_VERSION']?.trim() ? { runtimeVersion: process.env['RUNTIME_VERSION']!.trim() } : {}),
      ...(process.env['ERLANG_VERSION']?.trim() ? { erlangVersion: process.env['ERLANG_VERSION']!.trim() } : {}),
      ...(process.env['SCALA_VERSION']?.trim() ? { scalaVersion: process.env['SCALA_VERSION']!.trim() } : {}),
      ...(process.env['COURSIER_VERSION']?.trim() ? { coursierVersion: process.env['COURSIER_VERSION']!.trim() } : {}),
      ...(process.env['HEX_VERSION']?.trim() ? {
        hexVersion: process.env['HEX_VERSION']!.trim(),
        hexArchiveUrl: required('HEX_ARCHIVE_URL'),
        hexArchiveSha512: required('HEX_ARCHIVE_SHA512'),
        rebar3Version: required('REBAR3_VERSION'),
        rebar3ArchiveUrl: required('REBAR3_ARCHIVE_URL'),
        rebar3ArchiveSha512: required('REBAR3_ARCHIVE_SHA512'),
      } : {}),
      ...(process.env['PYTHON_VERSION']?.trim() ? {
        language: 'python' as const,
        pythonVersion: process.env['PYTHON_VERSION']!.trim(),
      } : required('MANAGER_VARIANT') === 'rust-cargo' ? { language: 'rust' as const }
        : required('MANAGER_VARIANT') === 'go-modules' ? { language: 'go' as const }
          : required('MANAGER_VARIANT') === 'jvm-maven' || required('MANAGER_VARIANT') === 'jvm-gradle' ? { language: (process.env['REPOSITORY_LANGUAGE'] === 'kotlin' ? 'kotlin' : 'java') as 'java' | 'kotlin' }
            : required('MANAGER_VARIANT') === 'scala-sbt' ? { language: 'scala' as const }
            : required('MANAGER_VARIANT') === 'dotnet-nuget' ? { language: 'csharp' as const }
              : required('MANAGER_VARIANT') === 'php-composer' ? { language: 'php' as const }
                : required('MANAGER_VARIANT') === 'ruby-bundler' ? { language: 'ruby' as const }
                  : required('MANAGER_VARIANT') === 'swift-package' ? { language: 'swift' as const }
                    : required('MANAGER_VARIANT') === 'dart-pub' ? { language: 'dart' as const }
                      : required('MANAGER_VARIANT') === 'elixir-mix' ? { language: 'elixir' as const }
                      : required('MANAGER_VARIANT') === 'clojure-tools-deps' || required('MANAGER_VARIANT') === 'clojure-leiningen' ? { language: 'clojure' as const }
                        : required('MANAGER_VARIANT') === 'c-vcpkg' ? { language: 'c' as const }
                          : required('MANAGER_VARIANT') === 'cpp-vcpkg' ? { language: 'cpp' as const } : {}),
    },
    runnerImageId: required('RUNNER_IMAGE_ID'),
    runtimeImages: JSON.parse(required('RUNTIME_IMAGES_JSON')) as string[],
    managerExecutionVerified: process.env['AUTOMATED_API_MANAGER_EXECUTION_VERIFIED'] === '1',
    ...(process.env['AUTOMATED_API_PYTHON_CERTIFIED_RECEIPT']?.trim() ? {
      pythonEnvironmentReceiptPath: process.env['AUTOMATED_API_PYTHON_CERTIFIED_RECEIPT']!.trim(),
    } : {}),
    ...(process.env['LOCKFILE_BEFORE_SHA256']?.trim() ? {
      lockfileBeforeHash: process.env['LOCKFILE_BEFORE_SHA256']!.trim(),
    } : {}),
    ...(process.env['AUTOMATED_API_VCPKG_RESOLVED_MANIFEST']?.trim() ? {
      vcpkgResolvedManifestPath: process.env['AUTOMATED_API_VCPKG_RESOLVED_MANIFEST']!.trim(),
      vcpkgProjectionManifestPath: required('AUTOMATED_API_VCPKG_PROJECTION_MANIFEST'),
    } : {}),
  })
}
