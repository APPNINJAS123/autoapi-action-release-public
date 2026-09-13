#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { MigrationJobSchema } from '@automated-api/contracts'
import { analyzePreparation } from './preparation.js'

const [jobPath, repositoryPath, outputPath] = process.argv.slice(2)
if (jobPath === undefined || repositoryPath === undefined || outputPath === undefined) {
  console.error('usage: automated-api-preparation <job.json> <repository> <output-directory>')
  process.exitCode = 2
} else {
  const job = MigrationJobSchema.parse(JSON.parse(await readFile(resolve(jobPath), 'utf8')))
  const result = await analyzePreparation(job, resolve(repositoryPath))
  await mkdir(resolve(outputPath), { recursive: true })
  await writeFile(
    resolve(outputPath, 'preparation.json'),
    `${JSON.stringify(result, null, 2)}\n`,
  )
  if (result.status !== 'prepare_dependencies') {
    await writeFile(
      resolve(outputPath, 'result.json'),
      `${JSON.stringify(result, null, 2)}\n`,
    )
  }
  process.stdout.write(`${result.status}\n`)
}
