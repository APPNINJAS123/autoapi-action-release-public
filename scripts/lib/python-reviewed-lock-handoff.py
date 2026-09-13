"""One reviewed, graph-preserving Langroid lock transition; not a resolver fallback.

The historical PyPI index no longer lists lancedb 0.8.2 even though its immutable
wheel URLs remain available. Preserve the original universal graph, and accept
only the independently verified Firecrawl wheel whose unconditional requirements
are already satisfied on every existing branch. No customer/SDK code is executed.
"""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from email.parser import BytesParser

BASE_SHA = 'e67e78253371cea719f4ca49b82afbc6f4e819b7'
OLD_LOCK = '0f9c111078e2832aba63772de4a9ac01eb589b348fe323fad8dc11754538ed22'
OLD_MANIFEST = '9b5ddd623ec302eca0a60e87430aba5381b5a7a25b976b74c01c908c8738706b'
NEW_MANIFEST = '289a45954d8180b99868146a9f35e58d7574e021cb6ab7b003dc507e2195171e'
POLICY_HASH = '057741de55d2fb59eb891bc97b43b1dfa9ab25eedabfc6a04a894ccaa675e78b'
OLD_WHEEL = 'dfb69644da1542d24d90e34a36e3b5733764121f2c992245c869513e2e184547'
OLD_URL = 'https://files.pythonhosted.org/packages/57/b9/08d730e7a844ee723acbfb14430f8dfa4386b18c086b7d23fcbe7a451568/firecrawl_py-1.13.5-py3-none-any.whl'
WHEEL = {'name': 'firecrawl-py', 'version': '4.31.0', 'kind': 'wheel',
         'filename': 'firecrawl_py-4.31.0-py3-none-any.whl', 'size': 248266,
         'url': 'https://files.pythonhosted.org/packages/68/4e/fd679c8307bc650ed0ae84c3716c7611f1bc437fecd460c12dcb26ba363c/firecrawl_py-4.31.0-py3-none-any.whl',
         'sha256': '40142f9dc8b291ab0573ed9ff62732e07ba5264074fcc633bb752d9510e8321e'}
DEPENDENCIES = ('aiohttp', 'httpx', 'nest-asyncio', 'pydantic', 'python-dotenv', 'requests', 'websockets')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def read(path, maximum=16 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('reviewed lock requires a bounded regular file')
    return path.read_bytes()


def directory(cache):
    target = cache / 'python-reviewed-lock'
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError('invalid reviewed lock cache directory')
    target.mkdir(exist_ok=True)
    return target


def write_bound(path, data):
    """Create an immutable cache receipt without following even broken links."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if read(path) != data:
            raise ValueError('reviewed lock cached receipt changed')
        return
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def binding(job):
    repository = job.get('repository', {})
    # The standalone baseline-installation diagnostic has no migration event.
    # It receives no handoff; consume still rejects a missing full-case handoff.
    if 'changeEvent' not in job:
        return None
    identities = {('supportcontact584-png', 'autoapi-real-langroid-full-firecrawl-python'),
                  ('sajsnddkn', 'autoapi-real-langroid-full-firecrawl-python'),
                  ('APPNINJAS123', 'autoapi-real-langroid-full-firecrawl-python-public')}
    names = {name for _, name in identities}
    if repository.get('name') not in names:
        return None
    if (repository.get('owner'), repository.get('name')) not in identities:
        raise ValueError('reviewed lock repository owner/name tuple mismatch')
    event = job.get('changeEvent', {})
    dependency = {'ecosystem': 'pypi', 'name': 'firecrawl-py', 'importNames': ['firecrawl'],
                  'oldVersionRange': '==1.13.5', 'newVersion': '4.31.0', 'newArtifactSha256': WHEEL['sha256']}
    expected_repository = {'owner': repository.get('owner'), 'name': repository.get('name'),
                           'defaultBranch': 'codex/full-upstream-firecrawl-proof', 'workingDirectory': '.',
                           'packageManagerDirectory': '.', 'packageManager': 'uv@0.12.5',
                           'pythonEnvironment': {'extras': ['firecrawl'], 'noDev': True}}
    evidence = {(item.get('url'), item.get('contentHash')) for item in event.get('evidence', [])}
    if repository != expected_repository or job.get('baseSha') != BASE_SHA or sha(canonical(job.get('policy'))) != POLICY_HASH:
        raise ValueError('reviewed lock repository/base/policy tuple mismatch')
    if event.get('provider') != 'firecrawl' or event.get('apiOrSdk') != 'Firecrawl Python SDK' or event.get('verificationStatus') != 'verified' or event.get('oldVersion') != '1.13.5' or event.get('newVersion') != '4.31.0' or event.get('affectedDependencies') != [dependency] or event.get('affectedLanguages') != ['python'] or event.get('recipeIds') != [] or not {(OLD_URL, OLD_WHEEL), (WHEEL['url'], WHEEL['sha256'])}.issubset(evidence) or not re.fullmatch(r'[a-f0-9]{64}', event.get('provenanceHash', '')):
        raise ValueError('reviewed lock genuine event tuple mismatch')
    return {'jobId': job['id'], 'baseSha': BASE_SHA, 'eventId': event['id'],
            'eventProvenanceHash': event['provenanceHash'], 'eventSha256': sha(canonical(event)),
            'jobSha256': sha(canonical(job)), 'repository': repository,
            'oldManifestSha256': OLD_MANIFEST, 'newManifestSha256': NEW_MANIFEST,
            'oldLockSha256': OLD_LOCK, 'wheelSha256': WHEEL['sha256']}


def prefetch_inputs(project, cache, job):
    identity = binding(job)
    if identity is None:
        return None
    lock, manifest = read(project / 'uv.lock'), read(project / 'pyproject.toml')
    if sha(lock) != OLD_LOCK or sha(manifest) != OLD_MANIFEST:
        raise ValueError('reviewed lock original checkout hashes differ')
    target = directory(cache)
    for name, data in [('baseline.lock', lock), ('baseline.toml', manifest)]:
        write_bound(target / name, data)
    return copy.deepcopy(WHEEL)


def seed_uv_cache(cache, job, uv, deadline):
    """Seed uv's registry cache without importing or running the target SDK."""
    if binding(job) is None:
        return
    target = directory(cache)
    wheel = target / WHEEL['filename']
    graph_preserving_lock(read(target / 'baseline.lock'), read(target / 'baseline.toml'), wheel)
    seed = target / 'target-seed'
    if seed.is_symlink() or seed.exists():
        raise ValueError('reviewed lock seed environment already exists')
    environment = {**os.environ, 'UV_CACHE_DIR': str(cache / 'uv')}
    try:
        subprocess.run([uv, 'venv', '--offline', str(seed), '--python', sys.executable],
                       check=True, timeout=min(60, deadline.remaining()), env=environment)
        subprocess.run([uv, 'pip', 'install', '--python', str(seed / 'bin/python'), '--no-deps',
                        '--no-build', 'firecrawl-py==4.31.0'],
                       check=True, timeout=deadline.remaining(), env=environment)
        _, _, _, _, installed = graph_preserving_lock(
            read(target / 'baseline.lock'), read(target / 'baseline.toml'), wheel, True)
        site = seed / 'lib' / ('python' + '.'.join(map(str, sys.version_info[:2]))) / 'site-packages'
        for name, expected in installed.items():
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('reviewed target wheel has an unsafe installed path')
            path = site.joinpath(*relative.parts)
            if not path.resolve().is_relative_to(site.resolve()) or sha(read(path, 2 * 1024 * 1024)) != expected:
                raise ValueError('uv registry cache seed differs from the reviewed target wheel')
    finally:
        if seed.is_symlink():
            raise ValueError('reviewed lock seed environment became a symlink')
        if seed.exists():
            shutil.rmtree(seed)


def graph_preserving_lock(lock_bytes, manifest_bytes, wheel_path, include_receipt=False):
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name
    if sha(lock_bytes) != OLD_LOCK or sha(manifest_bytes) != OLD_MANIFEST or sha(read(wheel_path, 2 * 1024 * 1024)) != WHEEL['sha256']:
        raise ValueError('reviewed lock baseline or genuine wheel hash mismatch')
    with zipfile.ZipFile(wheel_path) as archive:
        metadata_path = 'firecrawl_py-4.31.0.dist-info/METADATA'
        wheel_metadata_path = 'firecrawl_py-4.31.0.dist-info/WHEEL'
        if archive.namelist().count(metadata_path) != 1 or archive.namelist().count(wheel_metadata_path) != 1 or archive.getinfo(metadata_path).file_size > 256 * 1024:
            raise ValueError('ambiguous or excessive genuine wheel metadata')
        metadata_bytes = archive.read(metadata_path)
        wheel_metadata_bytes = archive.read(wheel_metadata_path)
        metadata = BytesParser().parsebytes(metadata_bytes)
        wheel_metadata = BytesParser().parsebytes(wheel_metadata_bytes)
        installed = {name: sha(archive.read(name)) for name in archive.namelist()
                     if not name.endswith('/') and not name.endswith('.dist-info/RECORD')}
    if metadata.get_all('Name') != ['firecrawl-py'] or metadata.get_all('Version') != ['4.31.0'] or metadata.get_all('Requires-Python') != ['>=3.8'] or wheel_metadata.get_all('Tag') != ['py3-none-any'] or wheel_metadata.get('Root-Is-Purelib') != 'true':
        raise ValueError('reviewed SDK identity or universal Python wheel coverage differs')
    original = tomllib.loads(lock_bytes.decode())
    manifest = tomllib.loads(manifest_bytes.decode())
    if original['requires-python'] != '>=3.10, <3.13' or manifest['project']['requires-python'] != '<3.13,>=3.10':
        raise ValueError('reviewed universal Python range differs')
    packages = original['package']
    roots = [package for package in packages if package['name'] == 'langroid']
    old_sdks = [package for package in packages if package['name'] == 'firecrawl-py']
    if len(roots) != 1 or len(old_sdks) != 1 or old_sdks[0]['version'] != '1.13.5':
        raise ValueError('reviewed root/SDK graph is ambiguous')
    root, old_sdk = roots[0], old_sdks[0]
    incoming = []
    for package in packages:
        for dependency in package.get('dependencies', []):
            if dependency['name'] == 'firecrawl-py':
                incoming.append((package['name'], 'dependencies', dependency))
        for extra, dependencies in package.get('optional-dependencies', {}).items():
            for dependency in dependencies:
                if dependency['name'] == 'firecrawl-py':
                    incoming.append((package['name'], extra, dependency))
    if incoming != [('langroid', 'firecrawl', {'name': 'firecrawl-py'})]:
        raise ValueError('reviewed SDK has an unqualified incoming dependency edge')
    requirements = []
    dependency_nodes = []
    for raw in metadata.get_all('Requires-Dist', []):
        requirement = Requirement(raw)
        name = canonicalize_name(requirement.name)
        candidates = [package for package in packages if canonicalize_name(package['name']) == name]
        if (requirement.marker is not None or requirement.extras or requirement.url
                or len(candidates) != 1 or candidates[0].get('resolution-markers')
                or candidates[0].get('source') != {'registry': 'https://pypi.org/simple'}
                or candidates[0]['version'] not in requirement.specifier):
            raise ValueError('target SDK dependency is not satisfied on every original branch')
        requirements.append(name)
        dependency_nodes.append({'name': name, 'version': candidates[0]['version'],
                                 'source': candidates[0]['source']})
    if tuple(sorted(requirements)) != DEPENDENCIES:
        raise ValueError('genuine SDK requirements differ from the reviewed set')
    new_sdk = {'name': 'firecrawl-py', 'version': '4.31.0', 'source': {'registry': 'https://pypi.org/simple'},
               'dependencies': [{'name': name} for name in DEPENDENCIES],
               'wheels': [{'url': WHEEL['url'], 'hash': 'sha256:' + WHEEL['sha256'], 'size': WHEEL['size']}]}
    text = lock_bytes.decode()
    matches = list(re.finditer(r'(?m)^\[\[package\]\]\nname = "firecrawl-py"\n[\s\S]*?(?=^\[\[package\]\]|\Z)', text))
    old_requirement = '    { name = "firecrawl-py", marker = "extra == \'firecrawl\'", specifier = ">=1.13.5" },'
    new_requirement = old_requirement.replace('>=1.13.5', '>=4.31.0')
    if len(matches) != 1 or text.count(old_requirement) != 1:
        raise ValueError('reviewed SDK record/root requirement anchor is ambiguous')
    replacement = '\n'.join(['[[package]]', 'name = "firecrawl-py"', 'version = "4.31.0"',
                              'source = { registry = "https://pypi.org/simple" }', 'dependencies = [',
                              *['    { name = ' + json.dumps(name) + ' },' for name in DEPENDENCIES], ']',
                              'wheels = [', '    { url = ' + json.dumps(WHEEL['url']) + ', hash = "sha256:' + WHEEL['sha256'] + '", size = ' + str(WHEEL['size']) + ' },', ']', '', ''])
    match = matches[0]
    changed = text[:match.start()] + replacement + text[match.end():]
    changed = changed.replace(old_requirement, new_requirement)
    parsed = tomllib.loads(changed)
    expected = copy.deepcopy(original)
    expected['package'][packages.index(old_sdk)] = new_sdk
    root_requirement = [item for item in expected['package'][packages.index(root)]['metadata']['requires-dist'] if item['name'] == 'firecrawl-py']
    if root_requirement != [{'name': 'firecrawl-py', 'marker': "extra == 'firecrawl'", 'specifier': '>=1.13.5'}]:
        raise ValueError('reviewed root SDK requirement differs')
    root_requirement[0]['specifier'] = '>=4.31.0'
    if parsed != expected:
        raise ValueError('reviewed update changed an unrelated graph field or platform branch')
    # Byte equality is stronger than parsed equality for all unrelated records.
    restored = changed.replace(new_requirement, old_requirement)
    restored = restored.replace(replacement, match.group(), 1)
    if restored != text:
        raise ValueError('reviewed update did not preserve unrelated original bytes')
    result = changed.encode()
    if include_receipt:
        return result, dependency_nodes, sha(metadata_bytes), sha(wheel_metadata_bytes), installed
    return result


def certify(project, cache, job):
    identity = binding(job)
    if identity is None:
        return None
    target = directory(cache)
    lock, manifest = read(target / 'baseline.lock'), read(target / 'baseline.toml')
    if read(project / 'uv.lock') != lock or read(project / 'pyproject.toml') != manifest:
        raise ValueError('reviewed original checkout changed before offline certification')
    generated, dependency_nodes, metadata_sha, wheel_metadata_sha, installed = graph_preserving_lock(
        lock, manifest, target / WHEEL['filename'], True)
    write_bound(target / 'target.lock', generated)
    return {'schemaVersion': 1, **identity, 'targetLockSha256': sha(generated),
            'preservedUniversalGraph': True, 'targetRequirements': list(DEPENDENCIES),
            'targetDependencyNodes': dependency_nodes, 'wheelMetadataSha256': metadata_sha,
            'wheelRecordSha256': wheel_metadata_sha, 'targetInstalled': installed}


def consume(project, cache, receipt):
    handoff = receipt.get('reviewedLockHandoff')
    if handoff is None:
        if receipt['baseSha'] == BASE_SHA:
            raise ValueError('reviewed full Langroid lock handoff is missing')
        return False
    target = directory(cache)
    generated, dependency_nodes, metadata_sha, wheel_metadata_sha, installed = graph_preserving_lock(
        read(target / 'baseline.lock'), read(target / 'baseline.toml'), target / WHEEL['filename'], True)
    if (handoff.get('schemaVersion') != 1 or handoff.get('jobId') != receipt.get('jobId')
            or handoff.get('baseSha') != receipt.get('baseSha') or handoff.get('baseSha') != BASE_SHA
            or not re.fullmatch(r'(?:chg_[a-f0-9]{24}|firecrawl-python-1\.13\.5-v2)', handoff.get('eventId', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', handoff.get('eventProvenanceHash', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', handoff.get('eventSha256', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', handoff.get('jobSha256', ''))
            or handoff.get('oldManifestSha256') != OLD_MANIFEST
            or handoff.get('newManifestSha256') != NEW_MANIFEST
            or handoff.get('oldLockSha256') != OLD_LOCK or handoff.get('wheelSha256') != WHEEL['sha256']
            or handoff.get('targetLockSha256') != sha(generated)
            or handoff.get('preservedUniversalGraph') is not True
            or handoff.get('targetRequirements') != list(DEPENDENCIES)
            or handoff.get('targetDependencyNodes') != dependency_nodes
            or handoff.get('wheelMetadataSha256') != metadata_sha
            or handoff.get('wheelRecordSha256') != wheel_metadata_sha
            or handoff.get('targetInstalled') != installed
            or read(target / 'target.lock') != generated
            or sha(read(project / 'pyproject.toml')) != NEW_MANIFEST):
        raise ValueError('reviewed target lock receipt or current manifest differs')
    current = read(project / 'uv.lock')
    if current != generated and sha(current) != OLD_LOCK:
        raise ValueError('reviewed target lock cannot replace an unrecognized lock')
    (project / 'uv.lock').write_bytes(generated)
    return handoff
