#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { MigrationJobSchema } from '@automated-api/contracts'
import { selectPreparationPackageManager, writeDependencyManifestDirectory } from './dependencies.js'
import { selectGradlePrefetchProjects, selectGradlePrefetchTasks } from './gradlePrefetchProjects.js'

const [jobPath, repositoryPath, manifestPath] = process.argv.slice(2)
if (jobPath === undefined || repositoryPath === undefined || manifestPath === undefined) {
  console.error('usage: automated-api-dependencies <job.json> <repository> <manifest-directory>')
  process.exitCode = 2
} else {
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(jobPath), 'utf8')))
  const manager = await selectPreparationPackageManager(repositoryPath, job)
  const packageManagerDirectory = job.repository.packageManagerDirectory
    ?? job.repository.workingDirectory
  const managerRoot = resolve(repositoryPath, packageManagerDirectory)
  const manifestName = await writeDependencyManifestDirectory(jobPath, manifestPath, manager, managerRoot)
  process.stdout.write([
    manager.name,
    manager.version,
    manager.variant,
    manager.lockfile,
    manager.spec,
    packageManagerDirectory,
    manifestName,
    manager.pythonVersion ?? '',
    manager.runtimeVersion ?? '',
    manager.scalaVersion ?? '',
    manager.coursierVersion ?? '',
    manager.erlangVersion ?? '',
    manager.hexVersion ?? '',
    manager.hexArchiveUrl ?? '',
    manager.hexArchiveSha512 ?? '',
    manager.rebar3Version ?? '',
    manager.rebar3ArchiveUrl ?? '',
    manager.rebar3ArchiveSha512 ?? '',
    manager.variant === 'jvm-gradle' ? selectGradlePrefetchProjects(job) : '',
    manager.variant === 'jvm-gradle' ? selectGradlePrefetchTasks(job) : '',
  ].join('\u001f') + '\n')
}
