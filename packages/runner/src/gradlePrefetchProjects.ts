import type { MigrationJob } from '@automated-api/contracts'

const qualifiedTask = /^:(?:[A-Za-z0-9_.-]+:)*[A-Za-z0-9_.-]+$/u

export function selectGradlePrefetchProjects(job: MigrationJob): string {
  const tasks = qualifiedGradleTasks(job)
  if (tasks === undefined) return '*'
  const projects = new Set<string>()
  for (const task of tasks) {
    const segments = task.slice(1).split(':')
    projects.add(segments.length === 1 ? ':' : `:${segments.slice(0, -1).join(':')}`)
  }
  return [...projects].sort().join(',')
}

export function selectGradlePrefetchTasks(job: MigrationJob): string {
  return qualifiedGradleTasks(job)?.join(',') ?? '*'
}

function qualifiedGradleTasks(job: MigrationJob): string[] | undefined {
  const tasks = new Set<string>()
  let foundGradleCommand = false
  for (const command of job.policy.validationCommands) {
    const executable = command.executable.replaceAll('\\', '/').split('/').at(-1)?.toLowerCase()
    if (executable !== 'gradle' && executable !== 'gradlew' && executable !== 'gradlew.bat') continue
    foundGradleCommand = true
    const commandTasks = command.args.filter(argument => argument.startsWith(':'))
    if (commandTasks.length === 0 || commandTasks.some(task => !qualifiedTask.test(task))) return undefined
    commandTasks.forEach(task => tasks.add(task))
  }
  return foundGradleCommand && tasks.size > 0 ? [...tasks].sort() : undefined
}
