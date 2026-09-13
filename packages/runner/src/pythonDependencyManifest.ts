import { spawnSync } from 'node:child_process'
import { lstat, readFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'

/** Parse TOML without importing the project or executing any package code. */
export async function updatePythonProjectDependency(
  content: string,
  dependency: { name: string; oldVersion: string; newVersion: string },
  manifestPath: string,
  repositoryRoot: string,
  allowedUvLockPaths?: ReadonlySet<string>,
): Promise<string> {
  let directory = dirname(resolve(manifestPath))
  const root = resolve(repositoryRoot)
  const manifestRelative = relative(root, resolve(manifestPath))
  if (isAbsolute(manifestRelative) || manifestRelative === '..' || manifestRelative.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    throw new Error('Python dependency manifest must remain inside its repository')
  }
  let lock: { content: string; projectPath: string } | undefined
  while (directory === root || !relative(root, directory).startsWith('..')) {
    const lockPath = resolve(directory, 'uv.lock')
    if (allowedUvLockPaths !== undefined && !allowedUvLockPaths.has(lockPath)) {
      if (directory === root) break
      directory = dirname(directory)
      continue
    }
    const metadata = await lstat(lockPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined
      throw error
    })
    if (metadata !== undefined) {
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 16 * 1024 * 1024) {
        throw new Error('Python dependency migration requires a bounded regular workspace uv.lock')
      }
      lock = { content: await readFile(lockPath, 'utf8'), projectPath: relative(directory, dirname(manifestPath)).replaceAll('\\', '/') || '.' }
      break
    }
    if (directory === root) break
    directory = dirname(directory)
  }
  const result = spawnSync(process.env['AUTOMATED_API_PYTHON'] ?? 'python3', ['-I', '-c', rewrite], {
    input: JSON.stringify({ content, dependency, lock }), encoding: 'utf8', timeout: 15_000, maxBuffer: 20 * 1024 * 1024,
  })
  if (result.error || result.status !== 0) {
    throw new Error(`Python dependency manifest rejected: ${result.stderr?.trim() || result.error?.message || 'parser failed'}`)
  }
  const updated: unknown = JSON.parse(result.stdout)
  if (typeof updated !== 'string') throw new Error('Python dependency parser returned an invalid manifest')
  return updated
}

// tomllib establishes the authoritative field path. A candidate literal edit
// is accepted only when reparsing proves exactly that one structural delta.
// This preserves comments/formatting without treating TOML as a regex language.
const rewrite = String.raw`
import copy, json, re, sys, tomllib

def normalized(value):
    return re.sub(r'[-_.]+', '-', value).lower()

def update(data):
    content, dependency = data['content'], data['dependency']
    document = tomllib.loads(content)
    project = document.get('project', {})
    if not isinstance(project, dict):
        raise ValueError('project must be a table')
    target = normalized(dependency['name'])
    arrays = [(('project', 'dependencies'), project.get('dependencies', []))]
    optional = project.get('optional-dependencies', {})
    if not isinstance(optional, dict):
        raise ValueError('optional dependencies must be a table')
    arrays += [(('project', 'optional-dependencies', key), values) for key, values in optional.items()]
    matches = []
    for path, requirements in arrays:
        if not isinstance(requirements, list) or not all(isinstance(item, str) for item in requirements):
            raise ValueError('project dependency fields must be string arrays')
        for index, requirement in enumerate(requirements):
            name = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)', requirement)
            if name and normalized(name[1]) == target:
                matches.append((path + (index,), requirement))
    if not matches:
        return content
    if len(matches) != 1:
        raise ValueError('requires one unambiguous project dependency declaration')
    path, requirement = matches[0]
    simple = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9_,.-]+\])?(\s*)(==|>=)(\s*)([0-9]+\.[0-9]+\.[0-9]+)', requirement)
    if not simple or (simple[4] == '>=' and simple[2]):
        raise ValueError('requires a simple exact pin or lower bound without markers or compound constraints')
    if simple[6] != dependency['oldVersion']:
        return content
    if simple[4] == '>=':
        overrides = document.get('tool', {}).get('uv', {}).get('sources', {})
        if any(normalized(name) == target for name in overrides):
            raise ValueError('lower bound cannot override a tool.uv.sources binding')
        locked = data.get('lock')
        if not locked:
            raise ValueError('lower bound requires the owning project/workspace uv.lock')
        packages = tomllib.loads(locked['content']).get('package', [])
        if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
            raise ValueError('invalid uv.lock packages')
        resolved = [item for item in packages if normalized(item.get('name', '')) == target]
        if len(resolved) != 1 or resolved[0].get('version') != dependency['oldVersion']:
            raise ValueError('uv.lock must resolve one unique distribution at the exact old version')
        distribution = resolved[0]
        source = distribution.get('source', {})
        if set(source) != {'registry'} or distribution.get('resolution-markers'):
            raise ValueError('uv.lock dependency must be an unambiguous registry distribution')
        project_name = project.get('name')
        owners = [item for item in packages if isinstance(project_name, str)
                  and normalized(item.get('name', '')) == normalized(project_name)
                  and item.get('source') in ({'editable': locked['projectPath']}, {'virtual': locked['projectPath']})]
        if len(owners) != 1:
            raise ValueError('uv.lock does not identify this owning project/workspace member')
        owner = owners[0]
        links = owner.get('dependencies', []) if path[1] == 'dependencies' else owner.get('optional-dependencies', {}).get(path[2], [])
        links = [item for item in links if normalized(item.get('name', '')) == target]
        if len(links) != 1 or links[0].get('version', dependency['oldVersion']) != dependency['oldVersion'] or 'marker' in links[0]:
            raise ValueError('uv.lock does not bind this dependency group to the exact distribution')
    replacement = requirement[:simple.start(6)] + dependency['newVersion']
    expected = copy.deepcopy(document)
    field = expected
    for key in path[:-1]:
        field = field[key]
    field[path[-1]] = replacement
    edits = []
    for quote in ('"', "'"):
        literal = quote + requirement + quote
        start = 0
        while True:
            start = content.find(literal, start)
            if start < 0:
                break
            changed = content[:start] + quote + replacement + quote + content[start + len(literal):]
            try:
                if tomllib.loads(changed) == expected:
                    edits.append(changed)
            except tomllib.TOMLDecodeError:
                pass
            start += len(literal)
    if len(edits) != 1:
        raise ValueError('cannot locate one lossless dependency string edit')
    return edits[0]

try:
    print(json.dumps(update(json.load(sys.stdin))))
except (ValueError, TypeError, KeyError, AttributeError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(2)
`
