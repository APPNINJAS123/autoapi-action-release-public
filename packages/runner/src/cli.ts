#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { HarnessResultSchema, MigrationJobSchema } from '@automated-api/contracts'
import {
  createMigrationExecutorFromEnvironment,
  harnessNetworkHostFromEnvironment,
} from './harness.js'
import { ProposalRunner } from './runner.js'
import { prepareRunnerOutputDirectory, publishProposalRunnerResult } from './outputPublication.js'

const [jobPath, repositoryPath, outputPath, harnessResultPath] = process.argv.slice(2)
if (jobPath === undefined || repositoryPath === undefined || outputPath === undefined) {
  console.error('usage: automated-api-proposal <job.json> <repository> <output-directory>')
  process.exitCode = 2
} else {
  const outputDirectory = await prepareRunnerOutputDirectory(outputPath)
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(jobPath), 'utf8')))
  const harnessResult = harnessResultPath === undefined
    ? undefined
    : HarnessResultSchema.parse(JSON.parse(await readFile(resolve(harnessResultPath), 'utf8')))
  const result = await new ProposalRunner(
    createMigrationExecutorFromEnvironment(),
    harnessNetworkHostFromEnvironment(),
  ).run(
    job,
    resolve(repositoryPath),
    harnessResult,
  )
  await publishProposalRunnerResult(outputDirectory, result)
}
