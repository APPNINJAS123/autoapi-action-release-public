#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { MigrationJobSchema } from '@automated-api/contracts'
import {
  composerDependencyResolutionTargets,
  prepareDependencyResolution,
  rubyDependencyResolutionTargets,
} from './dependencies.js'
import { reviewedKotlinTargetPreparationArgument } from './reviewedKotlinConsumer.js'

const [jobPath, repositoryPath, mode] = process.argv.slice(2)
if (jobPath === undefined || repositoryPath === undefined) {
  console.error('usage: automated-api-dependency-resolution <job.json> <disposable-repository>')
  process.exitCode = 2
} else {
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(jobPath), 'utf8')))
  if (mode === '--maven-target-property') {
    process.stdout.write(await reviewedKotlinTargetPreparationArgument(resolve(repositoryPath), job))
  } else if (mode === '--ruby-targets') {
    const targets = await rubyDependencyResolutionTargets(resolve(repositoryPath), job)
    if (targets.length === 0) throw new Error('Ruby resolution requires reviewed changed dependency names')
    process.stdout.write(`${targets.join('\n')}\n`)
  } else if (mode === '--composer-targets') {
    const targets = await composerDependencyResolutionTargets(resolve(repositoryPath), job)
    if (targets.length === 0) throw new Error('Composer resolution requires reviewed changed dependency names')
    process.stdout.write(`${targets.join('\n')}\n`)
  } else {
    if (mode !== undefined) throw new Error('unsupported dependency resolution mode')
    const changed = await prepareDependencyResolution(resolve(repositoryPath), job)
    process.stdout.write(changed ? 'changed\n' : 'unchanged\n')
  }
}
