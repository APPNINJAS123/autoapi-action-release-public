import { spawnSync } from 'node:child_process'
import { lstat, readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

/** Project only release-age policy, never indexes, sources, or build settings. */
export async function pythonUvReleaseAgePolicy(managerRoot: string): Promise<string[]> {
  for (const filename of ['uv.toml', 'pyproject.toml']) {
    const path = resolve(managerRoot, filename)
    const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined
      throw error
    })
    if (metadata === undefined) continue
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1024 * 1024) {
      throw new Error('uv release-age policy requires a bounded regular configuration file')
    }
    const result = spawnSync(process.env['AUTOMATED_API_PYTHON'] ?? 'python3', ['-I', '-c', parsePolicy], {
      input: JSON.stringify({ content: await readFile(path, 'utf8'), standalone: filename === 'uv.toml' }),
      encoding: 'utf8', timeout: 15_000, maxBuffer: 2 * 1024 * 1024,
    })
    if (result.error || result.status !== 0) {
      throw new Error(`uv release-age policy rejected: ${result.stderr?.trim() || result.error?.message || 'parser failed'}`)
    }
    const policy = JSON.parse(result.stdout) as { global?: string; packages: Record<string, string> }
    return [
      ...(policy.global === undefined ? [] : [`exclude-newer = ${JSON.stringify(policy.global)}`]),
      ...(Object.keys(policy.packages).length === 0 ? [] : [
        '', '[tool.uv.exclude-newer-package]',
        ...Object.entries(policy.packages).sort(([left], [right]) => left.localeCompare(right))
          .map(([name, age]) => `${JSON.stringify(name)} = ${JSON.stringify(age)}`),
      ]),
    ]
  }
  return []
}

// uv.toml takes precedence over [tool.uv] in a colocated pyproject.toml.
// Parse data only: no imports from, or execution of, the customer project.
const parsePolicy = String.raw`
import json, sys, tomllib
data = json.load(sys.stdin)
document = tomllib.loads(data['content'])
policy = document if data['standalone'] else document.get('tool', {}).get('uv', {})
if not isinstance(policy, dict):
    raise ValueError('uv configuration must be a table')
result = {'packages': {}}
if 'exclude-newer' in policy:
    if not isinstance(policy['exclude-newer'], str):
        raise ValueError('exclude-newer must be a string')
    result['global'] = policy['exclude-newer']
packages = policy.get('exclude-newer-package', {})
if not isinstance(packages, dict) or not all(isinstance(value, str) for value in packages.values()):
    raise ValueError('exclude-newer-package must be a table of strings')
result['packages'] = packages
print(json.dumps(result))
`
