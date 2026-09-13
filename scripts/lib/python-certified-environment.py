"""Opaque uv prefetch, isolated reviewed source builds, and offline consumption.

The Action runs `build` in a separate network-none container with only inputs and
wheel output mounted. Neither customer source nor the dependency cache is exposed
to a source build. `certify` independently checks reviewed output hashes.
"""
import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from email.parser import Parser


RECIPES = json.loads(Path(__file__).with_name('python-source-recipes.json').read_text())
MAX_ARTIFACT = 300 * 1024 * 1024
MAX_CERTIFIED_ARTIFACTS = 2000
MAX_CERTIFIED_BYTES = 2 * 1024 ** 3
CERTIFIED_UV = '/opt/dependency-cache/uv-tool/bin/uv'
TRUSTED_SYNC_PATH = '/opt/dependency-cache/uv-tool/bin:/usr/local/bin:/usr/bin:/bin'


class CertifiedEnvironmentUnavailable(RuntimeError):
    """The runner's sealed certification input is absent or corrupt."""


def reviewed_lock_handoff():
    path = Path(__file__).with_name('python-reviewed-lock-handoff.py')
    spec = importlib.util.spec_from_file_location('autoapi_reviewed_python_lock', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, maximum=MAX_ARTIFACT):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('expected bounded regular artifact: ' + path.name)
    return path


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def selection_args(job):
    selection = job.get('repository', {}).get('pythonEnvironment', {})
    if set(selection) - {'extras', 'noDev'}:
        raise ValueError('unsupported Python environment selection')
    extras = selection.get('extras', [])
    if not isinstance(extras, list) or len(extras) > 20 or any(
        not isinstance(extra, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}', extra)
        for extra in extras
    ) or not isinstance(selection.get('noDev', False), bool):
        raise ValueError('invalid Python environment selection')
    return (['--no-dev'] if selection.get('noDev', False) else []) + [
        arg for extra in sorted(set(extras)) for arg in ['--extra', extra]
    ]


def recipe_for(item):
    matches = [recipe for recipe in RECIPES['recipes'] if
               recipe['name'] == item['name'] and recipe['version'] == item['version']
               and recipe['sourceSha256'] == item['sha256']]
    if len(matches) != 1:
        raise ValueError('source distribution has no exact reviewed build recipe: ' + item['name'])
    return matches[0]


def filename(url):
    parsed = urllib.parse.urlsplit(url)
    name = PurePosixPath(parsed.path).name
    if parsed.scheme != 'https' or parsed.netloc != 'files.pythonhosted.org' or parsed.query or parsed.fragment:
        raise ValueError('only hash-locked public PyPI artifacts are supported')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,239}', name):
        raise ValueError('unsafe artifact filename')
    return name


def select_artifacts(document):
    # pip is part of the pinned Python runtime; importing its vendored packaging
    # only parses marker/tag data, never imports customer code or build backends.
    from pip._vendor.packaging.markers import Marker
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.utils import parse_wheel_filename
    tags = {tag: rank for rank, tag in enumerate(sys_tags())}
    result = []
    for package in document['packages']:
        if package.get('marker') and not Marker(package['marker']).evaluate():
            continue
        candidates = []
        for artifact in package.get('wheels', []):
            matching = tags.keys() & parse_wheel_filename(filename(artifact['url']))[3]
            if matching:
                candidates.append((min(tags[tag] for tag in matching), artifact))
        kind, artifact = ('wheel', min(candidates, key=lambda item: item[0])[1]) if candidates else ('sdist', package.get('sdist'))
        if artifact is None:
            raise ValueError('selected package is not an immutable PyPI artifact')
        item = {'name': normalized(package['name']), 'version': package['version'], 'kind': kind,
                'filename': filename(artifact['url']), 'url': artifact['url'],
                'sha256': artifact['hashes']['sha256'], 'size': artifact['size']}
        if not re.fullmatch(r'[a-f0-9]{64}', item['sha256']) or not 0 < item['size'] <= MAX_ARTIFACT:
            raise ValueError('artifact hash or size is invalid')
        if kind == 'sdist':
            recipe_for(item)
        result.append(item)
    if len(result) > 2000 or len({item['name'] for item in result}) != len(result):
        raise ValueError('ambiguous or excessive selected packages')
    if sum(item['size'] for item in result) > 2 * 1024 ** 3:
        raise ValueError('selected artifact budget exceeded')
    return sorted(result, key=lambda item: item['name'])


def exported_selection(project, uv, args):
    lock = regular(project / 'uv.lock', 16 * 1024 * 1024)
    before = digest(lock)
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / 'pylock.toml'
        subprocess.run([uv, 'export', '--directory', str(project), '--offline', '--frozen',
                        '--format', 'pylock.toml', '--no-emit-workspace', '--output-file', str(target), *args],
                       check=True, stdout=subprocess.DEVNULL, timeout=60)
        selected = select_artifacts(tomllib.loads(target.read_text()))
    if digest(lock) != before:
        raise ValueError('uv export changed the original lock')
    return selected


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('artifact redirects are not authorized')


class DownloadDeadlineExceeded(TimeoutError):
    pass


class DownloadDeadline:
    def __init__(self, value):
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('artifact downloads require an absolute job deadline')
        self.wall = parsed.timestamp()
        self.monotonic = time.monotonic() + self.wall - time.time()

    def remaining(self):
        remaining = min(self.wall - time.time(), self.monotonic - time.monotonic())
        if remaining <= 0:
            raise DownloadDeadlineExceeded('artifact download job deadline exhausted')
        return remaining


def transient_download_failure(error):
    if isinstance(error, DownloadDeadlineExceeded):
        return False
    if isinstance(error, urllib.error.HTTPError):
        return error.code == 429 or 500 <= error.code <= 599
    if isinstance(error, urllib.error.URLError):
        return transient_download_failure(error.reason)
    return isinstance(error, (TimeoutError, ConnectionResetError)) or (
        isinstance(error, OSError) and error.errno in {errno.ETIMEDOUT, errno.ECONNRESET, errno.ECONNABORTED})


def retry_download(operation, deadline):
    for attempt in range(3):
        deadline.remaining()
        try:
            return operation()
        except (OSError, urllib.error.URLError) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            if not transient_download_failure(error) or attempt == 2:
                raise
            delay = 0.25 * (attempt + 1)
            if deadline.remaining() <= delay + 1:
                raise DownloadDeadlineExceeded('insufficient job deadline for artifact retry') from error
            time.sleep(delay)


def public_archive_root(value):
    root = Path(value).absolute()
    if root != root.resolve(strict=True) or not root.is_dir() or root == Path(root.anchor):
        raise ValueError('public archive cache must be an explicit non-symlink directory')
    return root


def public_archive_key(item):
    if filename(item['url']) != item['filename'] or not re.fullmatch(r'[a-f0-9]{64}', item['sha256']):
        raise ValueError('invalid public archive identity')
    if not isinstance(item['size'], int) or not 0 < item['size'] <= MAX_ARTIFACT:
        raise ValueError('invalid public archive size')
    return item['sha256'] + '-' + item['filename']


def verify_public_archive(item, path):
    public_archive_key(item)
    if regular(path).stat().st_nlink != 1 or path.stat().st_size != item['size'] or digest(path) != item['sha256']:
        raise ValueError('public archive cache hash/size/link mismatch')
    if item['filename'].endswith('.whl'):
        from pip._vendor.packaging.utils import parse_wheel_filename
        name, version, _, _ = parse_wheel_filename(item['filename'])
        if 'name' in item and (normalized(item['name']) != normalized(name) or item['version'] != str(version)):
            raise ValueError('public archive wheel filename identity mismatch')
        verify_wheel(path, name, str(version), item['sha256'])
    elif item['filename'].endswith(('.tar.gz', '.zip')) and item.get('kind') == 'sdist':
        # Only these exact reviewed public source hashes may enter this cache.
        recipe_for(item)
    else:
        raise ValueError('unsupported public archive cache entry')


def copy_public_archive(item, source, target, deadline):
    deadline.remaining()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.public-', suffix='.part', delete=False) as output:
            temporary = Path(output.name)
            with regular(source).open('rb') as stream:
                size = 0
                while chunk := stream.read(64 * 1024):
                    deadline.remaining()
                    size += len(chunk)
                    if size > item['size']:
                        raise ValueError('public archive copy exceeded expected size')
                    output.write(chunk)
        verify_public_archive(item, temporary)
        deadline.remaining()
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def public_archive_hit(item, root, directory, deadline):
    entry = root / public_archive_key(item)
    if not entry.exists() and not entry.is_symlink():
        return False
    # A corrupt cache hint is never consumed. Symlinks and hard links fail
    # closed, rather than reading files outside this dedicated cache.
    if entry.is_symlink() or not entry.is_file() or entry.stat().st_nlink != 1:
        raise ValueError('unsafe public archive cache entry')
    try:
        copy_public_archive(item, entry, directory / item['filename'], deadline)
    except ValueError:
        return False
    return True


def publish_public_archive(item, source, root, deadline):
    # Serialize publishers across jobs without stale lock ownership after a
    # killed process. Copy before locking; only quota accounting and promotion
    # are serialized, with the same original deadline while acquiring the lock.
    lock = root / '.publisher.lock'
    if lock.is_symlink() or (lock.exists() and (not lock.is_file() or lock.stat().st_nlink != 1)):
        raise ValueError('unsafe public archive cache lock')
    with tempfile.NamedTemporaryFile(dir=root, prefix='.publish-', suffix='.part', delete=False) as pending:
        staged = Path(pending.name)
    try:
        copy_public_archive(item, source, staged, deadline)
        with lock.open('a+b') as stream:
            if os.name == 'nt':
                import msvcrt
                if stream.tell() == 0:
                    stream.write(b'0'); stream.flush()
                stream.seek(0)
                acquire = lambda: msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                acquire = lambda: fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            while True:
                deadline.remaining()
                try:
                    acquire()
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    time.sleep(min(0.05, deadline.remaining()))
            entries = list(root.iterdir())
            total = 0
            for entry in entries:
                try:
                    total += entry.lstat().st_size
                except FileNotFoundError:
                    pass  # Another downloader atomically promoted its staging file.
            if len(entries) >= 2000 or total > 2 * 1024 ** 3:
                return
            deadline.remaining()
            os.replace(staged, root / public_archive_key(item))
    finally:
        staged.unlink(missing_ok=True)


def download(item, directory, deadline, public_cache=None):
    if public_cache is not None and public_archive_hit(item, public_cache, directory, deadline):
        return
    retry_download(lambda: download_once(item, directory, deadline), deadline)
    if public_cache is not None:
        verify_public_archive(item, directory / item['filename'])
        publish_public_archive(item, directory / item['filename'], public_cache, deadline)


def download_once(item, directory, deadline):
    if filename(item['url']) != item['filename']:
        raise ValueError('artifact filename does not match its immutable URL')
    target = directory / item['filename']
    if target.exists() and regular(target).stat().st_size == item['size'] and digest(target) == item['sha256']:
        deadline.remaining()
        return
    request = urllib.request.Request(item['url'], headers={'User-Agent': 'AutoAPI/1.0'})
    # Stream each bounded transfer so parallel downloads do not retain entire
    # wheels in memory. Only publish a cache entry after exact size/hash checks.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix='download-', suffix='.part', delete=False) as output:
            temporary = Path(output.name)
            checksum = hashlib.sha256()
            received = 0
            with urllib.request.build_opener(NoRedirect).open(request, timeout=min(45, deadline.remaining())) as response:
                while True:
                    if response.fp is None:
                        break
                    # urllib's socket timeout must shrink before each read;
                    # otherwise a later stalled read can outlive the job.
                    response.fp.raw._sock.settimeout(min(45, deadline.remaining()))
                    chunk = response.read(min(64 * 1024, item['size'] - received + 1))
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > item['size']:
                        raise ValueError('download did not match immutable artifact hash/size')
                    checksum.update(chunk)
                    output.write(chunk)
            if received != item['size'] or checksum.hexdigest() != item['sha256']:
                raise ValueError('download did not match immutable artifact hash/size')
        deadline.remaining()
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify_wheel(path, name, version, expected):
    if digest(regular(path)) != expected:
        raise ValueError('wheel hash differs from certified artifact')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(entries) > 20000 or sum(entry.file_size for entry in entries) > MAX_ARTIFACT:
            raise ValueError('unbounded or duplicate wheel entries')
        for entry in entries:
            parts = PurePosixPath(entry.filename).parts
            if not parts or '..' in parts or entry.filename.startswith('/') or chr(92) in entry.orig_filename or ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('unsafe wheel member')
        metadata = [value for value in names if len(PurePosixPath(value).parts) == 2 and value.endswith('.dist-info/METADATA')]
        if len(metadata) != 1:
            raise ValueError('wheel has ambiguous distribution metadata')
        parsed = Parser().parsestr(archive.read(metadata[0]).decode())
        if normalized(parsed['Name']) != name or parsed['Version'] != version:
            raise ValueError('wheel package identity mismatch')


def certified_wheel_entry(item, size=None):
    if item['kind'] == 'sdist':
        recipe = recipe_for(item)
        entry = {'name': item['name'], 'version': item['version'], 'filename': recipe['wheel'],
                 'sha256': recipe['wheelSha256']}
        if size is not None:
            entry['size'] = size
        return entry
    return {'name': item['name'], 'version': item['version'], 'filename': item['filename'],
            'sha256': item['sha256'], 'size': item['size']}


def copy_certified_artifact(source, target, expected_hash, expected_size=None):
    source = regular(source)
    source_size = source.stat().st_size
    if source.stat().st_nlink != 1 or source_size <= 0 \
            or expected_size is not None and source_size != expected_size \
            or digest(source) != expected_hash:
        raise ValueError('certified artifact source hash/size/link mismatch')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o400)
    try:
        with os.fdopen(descriptor, 'wb') as output_stream, source.open('rb') as input_stream:
            copied = 0
            while chunk := input_stream.read(64 * 1024):
                copied += len(chunk)
                if copied > source_size:
                    raise ValueError('certified artifact copy exceeded expected size')
                output_stream.write(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    if target.is_symlink() or target.stat().st_nlink != 1 or target.stat().st_size != source_size \
            or digest(target) != expected_hash:
        target.unlink(missing_ok=True)
        raise ValueError('certified artifact destination hash/size/link mismatch')
    return source_size


def expected_certified_artifacts(selected):
    expected = []
    for item in selected:
        expected.append({'role': 'locked-' + item['kind'], 'name': item['name'],
                         'version': item['version'], 'filename': item['filename'],
                         'sha256': item['sha256'], 'size': item['size']})
        if item['kind'] == 'sdist':
            recipe = recipe_for(item)
            expected.append({'role': 'reviewed-build-wheel', 'name': item['name'],
                             'version': item['version'], 'filename': recipe['wheel'],
                             'sha256': recipe['wheelSha256']})
    return sorted(expected, key=lambda item: (item['filename'], item['role']))


def verify_certified_artifacts(cache, selected, receipt):
    expected = expected_certified_artifacts(selected)
    if not isinstance(receipt, list) or len(receipt) != len(expected) \
            or len(expected) > MAX_CERTIFIED_ARTIFACTS \
            or len({item['filename'] for item in expected}) != len(expected):
        raise ValueError('certified artifact receipt differs from selected artifacts')
    for expected_item, received in zip(expected, receipt):
        if not isinstance(received, dict) \
                or {key: received.get(key) for key in expected_item} != expected_item \
                or set(received) != set(expected_item) | {'size'} \
                or not isinstance(received.get('size'), int) \
                or not 0 < received['size'] <= MAX_ARTIFACT:
            raise ValueError('certified artifact receipt differs from selected artifacts')
    directory = cache / 'python-certified-artifacts'
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != cache.resolve():
        raise ValueError('invalid certified artifact directory')
    actual = list(directory.iterdir())
    if len(actual) != len(receipt) or {path.name for path in actual} != {item['filename'] for item in receipt}:
        raise ValueError('certified artifact directory contains unexpected entries')
    total = 0
    for item in receipt:
        path = regular(directory / item['filename'])
        if path.stat().st_nlink != 1 or path.stat().st_size != item['size'] or digest(path) != item['sha256']:
            raise ValueError('certified artifact hash/size/link mismatch')
        total += item['size']
        if total > MAX_CERTIFIED_BYTES:
            raise ValueError('certified artifact directory exceeded artifact budget')
        if item['role'] in {'locked-wheel', 'reviewed-build-wheel'}:
            verify_wheel(path, item['name'], item['version'], item['sha256'])
        else:
            recipe_for(next(selected_item for selected_item in selected
                            if selected_item['name'] == item['name'] and selected_item['kind'] == 'sdist'))
    return directory


def verify_certified_root(cache, receipt):
    if receipt.get('sealedOutput') is not True:
        raise ValueError('Python certification is not a sealed separate output')
    expected = {'python-certified.json', 'python-certified-artifacts', 'python-certified-wheels'}
    if receipt.get('tokenizerData') is not None:
        expected.add('tiktoken')
    if receipt.get('reviewedLockHandoff') is not None:
        expected.add('python-reviewed-lock')
    if cache.is_symlink() or not cache.is_dir() or {path.name for path in cache.iterdir()} != expected:
        raise ValueError('sealed Python certification contains unexpected entries')


def verify_certified_wheelhouse(cache, selected, receipt):
    expected = sorted((certified_wheel_entry(item) for item in selected), key=lambda item: item['filename'])
    if not isinstance(receipt, list) or len(receipt) != len(expected) or len(expected) > 2000 \
            or len({item['name'] for item in expected}) != len(expected) \
            or len({item['filename'] for item in expected}) != len(expected):
        raise ValueError('certified wheelhouse receipt differs from selected artifacts')
    selected_by_name = {item['name']: item for item in selected}
    for expected_item, received in zip(expected, receipt):
        selected_item = selected_by_name[expected_item['name']]
        if not isinstance(received, dict) or {key: received.get(key) for key in expected_item} != expected_item \
                or set(received) != set(expected_item) | {'size'} or not isinstance(received.get('size'), int) \
                or not 0 < received['size'] <= MAX_ARTIFACT \
                or (selected_item['kind'] == 'wheel' and received['size'] != selected_item['size']):
            raise ValueError('certified wheelhouse receipt differs from selected artifacts')
    directory = cache / 'python-certified-wheels'
    if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent != cache.resolve():
        raise ValueError('invalid certified wheelhouse directory')
    actual = list(directory.iterdir())
    if len(actual) != len(expected) or {path.name for path in actual} != {item['filename'] for item in expected}:
        raise ValueError('certified wheelhouse contains unexpected artifacts')
    total = 0
    for item in receipt:
        path = regular(directory / item['filename'])
        if path.stat().st_nlink != 1 or path.stat().st_size != item['size']:
            raise ValueError('certified wheel artifact has multiple links')
        total += path.stat().st_size
        if total > MAX_CERTIFIED_BYTES:
            raise ValueError('certified wheelhouse exceeded artifact budget')
        verify_wheel(path, item['name'], item['version'], item['sha256'])
    return directory


def bootstrap_uv(cache, job, public_cache=None, resolved_manager=None):
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.utils import parse_wheel_filename
    deadline = DownloadDeadline(job['deadlineAt'])
    deadline.remaining()
    item = RECIPES['uvBootstrap']
    declared_manager = job.get('repository', {}).get('packageManager')
    # dependencyCli resolves absent repository settings from the manifest. Its
    # exact result is passed by the trusted Action, not guessed by this helper.
    manager = resolved_manager if resolved_manager is not None else declared_manager
    if manager != 'uv@' + item['version'] or (declared_manager is not None and declared_manager != manager):
        raise ValueError('unsupported certified uv bootstrap version')
    if not set(sys_tags()).intersection(parse_wheel_filename(item['filename'])[3]):
        raise ValueError('unsupported certified uv bootstrap platform')
    cache = public_archive_root(cache)
    public_cache = public_archive_root(public_cache) if public_cache else None
    if public_cache and (cache == public_cache or cache.is_relative_to(public_cache) or public_cache.is_relative_to(cache)):
        raise ValueError('uv installation and public archive cache must be separate')
    target = cache / 'uv-tool'
    if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
        raise ValueError('uv bootstrap requires a fresh installation directory')
    # The only reusable state is an untrusted public wheel. Never inherit an
    # installed executable, pip cache, environment, or certification receipt.
    with tempfile.TemporaryDirectory(prefix='uv-bootstrap-', dir=cache) as temporary:
        inputs = Path(temporary)
        download(item, inputs, deadline, public_cache)
        verify_public_archive(item, inputs / item['filename'])
        requirement = inputs / 'requirements.txt'
        requirement.write_text('uv==' + item['version'] + ' --hash=sha256:' + item['sha256'] + '\n')
        try:
            subprocess.run([sys.executable, '-I', '-m', 'pip', '--isolated', 'install',
                            '--no-index', '--no-cache-dir', '--no-deps', '--only-binary=:all:',
                            '--require-hashes', '--find-links', str(inputs), '--target', str(target),
                            '--requirement', str(requirement)], check=True, timeout=deadline.remaining())
        except subprocess.TimeoutExpired as error:
            raise DownloadDeadlineExceeded('uv bootstrap job deadline exhausted') from error
    deadline.remaining()


def prefetch(project, cache, job, uv, public_cache=None):
    deadline = DownloadDeadline(job['deadlineAt'])
    deadline.remaining()
    public_cache = public_archive_root(public_cache) if public_cache else None
    handoff = reviewed_lock_handoff()
    reviewed_wheel = handoff.prefetch_inputs(project, cache, job)
    if reviewed_wheel is not None:
        download(reviewed_wheel, handoff.directory(cache), deadline, public_cache)
        handoff.seed_uv_cache(cache, job, uv, deadline)
    inputs = cache / 'python-build-inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    selected = exported_selection(project, uv, selection_args(job))
    # Cap network fan-out; every worker independently enforces immutable bytes.
    workers = ThreadPoolExecutor(max_workers=4)
    try:
        pending = [workers.submit(download, item, inputs, deadline, public_cache) for item in selected]
        for future in as_completed(pending):
            future.result()
    finally:
        workers.shutdown(wait=True, cancel_futures=True)
    prefetch_tokenizer_data(selected, inputs, cache, deadline)
    if any(item['kind'] == 'sdist' for item in selected):
        for tool in RECIPES['buildTools']:
            download(tool, inputs, deadline, public_cache)
    deadline.remaining()
    (inputs / 'selection.json').write_text(json.dumps(selected))


def prefetch_tokenizer_data(selected, inputs, cache, deadline):
    deadline.remaining()
    wheels = [item for item in selected if item['name'] == 'tiktoken' and item['kind'] == 'wheel']
    if not wheels:
        return
    artifact = wheels[0]
    wheel = regular(inputs / artifact['filename'])
    if digest(wheel) != artifact['sha256']:
        raise ValueError('tokenizer SDK artifact hash mismatch')
    data = RECIPES['tokenizerData']
    with zipfile.ZipFile(wheel) as archive:
        member = archive.getinfo('tiktoken_ext/openai_public.py')
        if member.file_size > 256 * 1024:
            raise ValueError('tokenizer static metadata exceeded budget')
        tree = ast.parse(archive.read(member).decode())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'cl100k_base']
    calls = [node for function in functions for node in ast.walk(function) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == 'load_tiktoken_bpe']
    if len(calls) != 1 or not calls[0].args or not isinstance(calls[0].args[0], ast.Constant) or calls[0].args[0].value != data['url']:
        raise ValueError('tokenizer SDK does not declare the reviewed runtime data URL')
    hashes = [keyword.value.value for keyword in calls[0].keywords if keyword.arg == 'expected_hash' and isinstance(keyword.value, ast.Constant)]
    if hashes != [data['sha256']]:
        raise ValueError('tokenizer SDK runtime data hash differs from reviewed metadata')
    target = cache / 'tiktoken' / hashlib.sha1(data['url'].encode()).hexdigest()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and digest(regular(target, data['maximumBytes'])) == data['sha256']:
        return
    def fetch():
        with urllib.request.build_opener(NoRedirect).open(data['url'], timeout=min(45, deadline.remaining())) as response:
            return response.read(data['maximumBytes'] + 1)
    payload = retry_download(fetch, deadline)
    if len(payload) > data['maximumBytes'] or hashlib.sha256(payload).hexdigest() != data['sha256']:
        raise ValueError('tokenizer runtime data hash/size mismatch')
    deadline.remaining()
    target.write_bytes(payload)


def verify_tokenizer_data(selected, cache):
    if not any(item['name'] == 'tiktoken' for item in selected):
        return None
    data = RECIPES['tokenizerData']
    target = cache / 'tiktoken' / hashlib.sha1(data['url'].encode()).hexdigest()
    if digest(regular(target, data['maximumBytes'])) != data['sha256']:
        raise ValueError('certified tokenizer runtime data changed')
    return {'url': data['url'], 'sha256': data['sha256']}


def build(inputs, output):
    selected = json.loads(regular(inputs / 'selection.json', 4 * 1024 * 1024).read_text())
    sources = [item for item in selected if item['kind'] == 'sdist']
    if not sources:
        return
    tools = []
    for tool in RECIPES['buildTools']:
        path = regular(inputs / tool['filename'])
        if digest(path) != tool['sha256']:
            raise ValueError('build tool hash mismatch')
        tools.append(str(path))
    for item in sources:
        recipe_for(item)
        if filename(item['url']) != item['filename'] or digest(regular(inputs / item['filename'])) != item['sha256']:
            raise ValueError('source hash mismatch')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        toolpath = Path(temp) / 'tools'
        subprocess.run([sys.executable, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps', '--target', str(toolpath), *tools], check=True, timeout=60)
        env = {'PATH': os.environ['PATH'], 'HOME': temp, 'PYTHONPATH': str(toolpath), 'PYTHONNOUSERSITE': '1',
               'SOURCE_DATE_EPOCH': RECIPES['sourceDateEpoch'], 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
        subprocess.run([sys.executable, '-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation', '--wheel-dir', str(output),
                        *[str(inputs / item['filename']) for item in sources]], cwd=temp, env=env, check=True, timeout=180)


def certification_output(cache, output):
    if output is None:
        raise ValueError('certification requires a separate sealed output directory')
    target = Path(output)
    if target.is_symlink() or not target.is_dir() or target.resolve() == Path(target.anchor):
        raise ValueError('certified output must be an explicit non-symlink directory')
    if target.resolve() != cache.resolve() and (target.resolve().is_relative_to(cache.resolve())
                                                or cache.resolve().is_relative_to(target.resolve())):
        raise ValueError('certified output and build cache must be separate')
    if target.resolve() != cache.resolve() and any(target.iterdir()):
        raise ValueError('certification requires a fresh output directory')
    return target


def copy_auxiliary_certification(cache, certified_cache, tokenizer_data, handoff):
    if certified_cache.resolve() == cache.resolve():
        return
    if tokenizer_data is not None:
        relative = Path('tiktoken') / hashlib.sha1(tokenizer_data['url'].encode()).hexdigest()
        source = cache / relative
        target = certified_cache / relative
        target.parent.mkdir(mode=0o700)
        copy_certified_artifact(source, target, tokenizer_data['sha256'])
    if handoff is not None:
        source = reviewed_lock_handoff().directory(cache)
        target = certified_cache / 'python-reviewed-lock'
        target.mkdir(mode=0o700)
        expected_names = {'baseline.lock', 'baseline.toml', 'target.lock', reviewed_lock_handoff().WHEEL['filename']}
        actual_names = {path.name for path in source.iterdir()}
        if actual_names != expected_names:
            raise ValueError('reviewed lock cache contains unexpected entries')
        for name in sorted(expected_names):
            input_path = regular(source / name, 16 * 1024 * 1024)
            copy_certified_artifact(input_path, target / name, digest(input_path), input_path.stat().st_size)


def certify(project, cache, job, uv, output):
    selected = exported_selection(project, uv, selection_args(job))
    inputs = cache / 'python-build-inputs'
    original_lock = digest(project / 'uv.lock')
    installed = {}
    exceptions = []
    certified_cache = certification_output(cache, output)
    wheelhouse = certified_cache / 'python-certified-wheels'
    artifacts = certified_cache / 'python-certified-artifacts'
    if wheelhouse.is_symlink() or wheelhouse.exists():
        raise ValueError('certification requires a fresh wheelhouse directory')
    if artifacts.is_symlink() or artifacts.exists():
        raise ValueError('certification requires a fresh artifact directory')
    wheelhouse.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    wheelhouse_receipt = []
    artifact_receipt = []
    artifact_total = 0
    wheelhouse_total = 0
    try:
        with tempfile.TemporaryDirectory() as temp:
            requirements = []
            for item in selected:
                input_source = inputs / item['filename']
                input_size = copy_certified_artifact(
                    input_source, artifacts / item['filename'], item['sha256'], item['size'])
                artifact_total += input_size
                if artifact_total > MAX_CERTIFIED_BYTES:
                    raise ValueError('certified artifact directory exceeded artifact budget')
                artifact_receipt.append({'role': 'locked-' + item['kind'], 'name': item['name'],
                                         'version': item['version'], 'filename': item['filename'],
                                         'sha256': item['sha256'], 'size': input_size})
                if item['kind'] == 'sdist':
                    recipe = recipe_for(item)
                    source = cache / 'python-built-wheels' / recipe['wheel']
                    expected = recipe['wheelSha256']
                    exceptions.append(item['name'])
                    # Original source remains independently bound to the lock.
                    if digest(regular(input_source)) != item['sha256']:
                        raise ValueError('certification source hash mismatch')
                    build_size = copy_certified_artifact(
                        source, artifacts / source.name, expected)
                    artifact_total += build_size
                    if artifact_total > MAX_CERTIFIED_BYTES:
                        raise ValueError('certified artifact directory exceeded artifact budget')
                    artifact_receipt.append({'role': 'reviewed-build-wheel', 'name': item['name'],
                                             'version': item['version'], 'filename': source.name,
                                             'sha256': expected, 'size': build_size})
                else:
                    source = input_source
                    expected = item['sha256']
                verify_wheel(source, item['name'], item['version'], expected)
                if item['kind'] == 'sdist':
                    with zipfile.ZipFile(source) as archive:
                        installed[item['name']] = {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()
                                                  if not name.endswith('/') and not name.endswith('.dist-info/RECORD')}
                target = wheelhouse / source.name
                wheelhouse_total += copy_certified_artifact(source, target, expected)
                if wheelhouse_total > MAX_CERTIFIED_BYTES:
                    raise ValueError('certified wheelhouse exceeded artifact budget')
                verify_wheel(regular(target), item['name'], item['version'], expected)
                wheelhouse_receipt.append(certified_wheel_entry(item, target.stat().st_size))
                requirements.append(item['name'] + '==' + item['version'] + ' --hash=sha256:' + expected)
            artifact_receipt.sort(key=lambda item: (item['filename'], item['role']))
            wheelhouse_receipt.sort(key=lambda item: item['filename'])
            verify_certified_artifacts(certified_cache, selected, artifact_receipt)
            verify_certified_wheelhouse(certified_cache, selected, wheelhouse_receipt)
            requirement = Path(temp) / 'requirements.txt'
            requirement.write_text('\n'.join(requirements) + '\n')
            subprocess.run([uv, 'venv', '--offline', str(project / '.venv'), '--python', sys.executable], check=True, timeout=60)
            subprocess.run([uv, 'pip', 'install', '--python', str(project / '.venv/bin/python'), '--offline', '--no-build', '--no-index',
                            '--no-deps', '--require-hashes', '--find-links', str(wheelhouse), '-r', str(requirement)], check=True, timeout=180)
        # No raw archive/build-cache mount is needed to consume this prepared environment.
        command = [uv, 'sync', '--directory', str(project), '--offline', '--frozen', '--no-install-workspace', '--no-build',
                   '--python', sys.executable, *selection_args(job)]
        command += [arg for name in exceptions for arg in ['--no-binary-package', name]]
        subprocess.run(command, check=True, timeout=180)
        if digest(project / 'uv.lock') != original_lock:
            raise ValueError('certification changed original lock')
        verify_installed(project, installed)
        tokenizer_data = verify_tokenizer_data(selected, cache)
        handoff = reviewed_lock_handoff().certify(project, cache, job)
        copy_auxiliary_certification(cache, certified_cache, tokenizer_data, handoff)
        receipt_path = certified_cache / 'python-certified.json'
        receipt_payload = json.dumps({'schemaVersion': 2, 'lockSha256': original_lock,
            'jobId': job['id'], 'baseSha': job['baseSha'], 'manifestSha256': digest(regular(project / 'pyproject.toml')),
            'pythonVersion': '.'.join(map(str, sys.version_info[:3])), 'runnerImageId': os.environ['RUNNER_IMAGE_ID'],
            'recipeRegistrySha256': digest(Path(__file__).with_name('python-source-recipes.json')),
            'selected': selected, 'installed': installed, 'selectionArgs': selection_args(job), 'tokenizerData': tokenizer_data,
            'sealedOutput': certified_cache.resolve() != cache.resolve(),
            'certifiedArtifacts': artifact_receipt, 'certifiedWheelhouse': wheelhouse_receipt,
            'reviewedLockHandoff': handoff})
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | (os.O_NOFOLLOW if hasattr(os, 'O_NOFOLLOW') else 0), 0o400)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(receipt_payload)
            stream.flush()
            os.fsync(stream.fileno())
        verify_certified_root(certified_cache, json.loads(receipt_payload))
    except BaseException:
        if wheelhouse.is_symlink():
            raise ValueError('certified wheelhouse became a symlink')
        if wheelhouse.exists():
            shutil.rmtree(wheelhouse)
        if artifacts.is_symlink():
            raise ValueError('certified artifact directory became a symlink')
        if artifacts.exists():
            shutil.rmtree(artifacts)
        raise
    # These directories are created by this helper below the per-job cache;
    # they contain only opaque downloads and disposable builder outputs.
    for directory in [inputs, cache / 'python-built-wheels']:
        if directory.is_symlink() or directory.parent.resolve() != cache.resolve():
            raise ValueError('invalid disposable build directory')
        if directory.exists():
            shutil.rmtree(directory)


def verify_installed(project, installed):
    site = project / '.venv/lib' / ('python' + '.'.join(map(str, sys.version_info[:2]))) / 'site-packages'
    for files in installed.values():
        for name, expected in files.items():
            target = site / name
            if not target.resolve().is_relative_to(site.resolve()) or digest(regular(target)) != expected:
                raise ValueError('certified installed wheel was altered or removed')


def reset_virtual_environment(project):
    """Remove only the job-owned venv before an offline certified rebuild."""
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError('virtual environment cleanup requires fd-safe traversal')
    environment = project / '.venv'
    try:
        metadata = environment.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError('existing virtual environment is not a bounded directory')
    if environment.resolve().parent != project.resolve():
        raise ValueError('existing virtual environment escapes the project')
    shutil.rmtree(environment)


def sync(project, cache, uv):
    try:
        if uv != CERTIFIED_UV:
            raise ValueError('certified synchronization requires the exact trusted uv executable')
        receipt_path = regular(cache / 'python-certified.json', 8 * 1024 * 1024)
        receipt = json.loads(receipt_path.read_text())
        certificate = json.loads(regular(Path(os.environ['AUTOMATED_API_TOOLCHAIN_CERTIFICATE'])).read_text())
        if certificate.get('pythonEnvironmentReceiptHash') != digest(receipt_path) or receipt['jobId'] != certificate['jobId'] or receipt['baseSha'] != certificate['baseSha']:
            raise ValueError('Python environment receipt is not bound to the authoritative toolchain certificate')
        if receipt['pythonVersion'] != '.'.join(map(str, sys.version_info[:3])) or receipt['pythonVersion'] != certificate['runtime']['python'] or receipt['runnerImageId'] != certificate['runnerImageId']:
            raise ValueError('Python environment runtime identity mismatch')
        if receipt['recipeRegistrySha256'] != digest(Path(__file__).with_name('python-source-recipes.json')):
            raise ValueError('Python source recipe registry changed after certification')
        if receipt['schemaVersion'] != 2:
            raise ValueError('unsupported Python environment receipt')
        verify_certified_root(cache, receipt)
        if verify_tokenizer_data(receipt['selected'], cache) != receipt['tokenizerData']:
            raise ValueError('tokenizer runtime data receipt mismatch')
        args = receipt['selectionArgs']
        # Re-parse the trusted schema before using persisted command arguments.
        extras = [args[index + 1] for index, value in enumerate(args) if value == '--extra']
        if selection_args({'repository': {'pythonEnvironment': {'extras': extras, 'noDev': '--no-dev' in args}}}) != args:
            raise ValueError('invalid certified environment arguments')
        verify_certified_artifacts(cache, receipt['selected'], receipt['certifiedArtifacts'])
        wheelhouse = verify_certified_wheelhouse(cache, receipt['selected'], receipt['certifiedWheelhouse'])
    except CertifiedEnvironmentUnavailable:
        raise
    except Exception as error:
        raise CertifiedEnvironmentUnavailable('sealed Python certification input is unavailable') from error
    # This reads the model-authorized current lock. Keep it outside the runner
    # infrastructure boundary: a model edit which drops a retained dependency
    # must be repairable code, never a suppressed cache incident.
    verify_retained_source_dependencies(project, receipt['selected'])
    exceptions = []
    for item in receipt['selected']:
        if item['kind'] == 'sdist':
            recipe_for(item)
            exceptions += ['--no-binary-package', item['name']]
    # Certification runs in a raw, isolated tree. The final writable proposal
    # workspace intentionally does not inherit its untracked .venv and must not
    # trust an ignored environment supplied by the repository. Rebuild from
    # only the complete, receipt-bound wheelhouse under network isolation.
    reset_virtual_environment(project)
    subprocess_environment = os.environ.copy()
    subprocess_environment['PATH'] = TRUSTED_SYNC_PATH
    try:
        with tempfile.TemporaryDirectory() as temp:
            requirement = Path(temp) / 'requirements.txt'
            requirement.write_text('\n'.join(
                item['name'] + '==' + item['version'] + ' --hash=sha256:' + item['sha256']
                for item in receipt['certifiedWheelhouse']) + '\n')
            subprocess.run([uv, 'venv', '--offline', str(project / '.venv'), '--python', sys.executable],
                           check=True, timeout=60, env=subprocess_environment)
            subprocess.run([uv, 'pip', 'install', '--python', str(project / '.venv/bin/python'), '--offline', '--no-build',
                            '--no-index', '--no-deps', '--require-hashes',
                            '--find-links', str(wheelhouse), '-r', str(requirement)], check=True, timeout=180,
                           env=subprocess_environment)
    except subprocess.SubprocessError as error:
        raise CertifiedEnvironmentUnavailable('sealed Python environment reconstruction failed') from error
    handoff = reviewed_lock_handoff().consume(project, cache, receipt)
    frozen = bool(handoff)
    # uv may reconcile already-installed packages during sync. Keep the exact
    # certified wheelhouse visible so that reconciliation remains complete and
    # network-independent after the disposable download/build cache is gone.
    subprocess.run([uv, 'sync', '--directory', str(project), '--offline', '--no-build', '--no-install-workspace',
                    '--python', sys.executable, '--find-links', str(wheelhouse),
                    *(['--frozen', '--find-links', str(reviewed_lock_handoff().directory(cache))] if frozen else []),
                    *args, *exceptions], check=True, timeout=180, env=subprocess_environment)
    if frozen and digest(project / 'uv.lock') != receipt['reviewedLockHandoff']['targetLockSha256']:
        raise ValueError('frozen synchronization changed the reviewed target lock')
    verify_retained_source_dependencies(project, receipt['selected'])
    retained = receipt['installed'] if not frozen else {
        name: files for name, files in receipt['installed'].items() if name != 'firecrawl-py'}
    verify_installed(project, retained)
    if frozen:
        verify_installed(project, {'firecrawl-py': handoff['targetInstalled']})


def verify_retained_source_dependencies(project, selected):
    # Harness may produce an authorized target lock before synchronization.
    # Only the retained source packages need their original source identities;
    # unrelated wheel-backed dependency changes must not require the old hash.
    locked = tomllib.loads(regular(project / 'uv.lock', 16 * 1024 * 1024).read_text())
    for item in selected:
        if item['kind'] != 'sdist':
            continue
        recipe_for(item)
        matches = [package for package in locked.get('package', []) if normalized(package['name']) == item['name']]
        if len(matches) != 1 or matches[0].get('version') != item['version'] or matches[0].get('source') != {'registry': 'https://pypi.org/simple'} or matches[0].get('sdist', {}).get('hash') != 'sha256:' + item['sha256']:
            raise ValueError('upgrading or removing a certified source package requires a separately certified target recipe: ' + item['name'])


if __name__ == '__main__':
    try:
        mode = sys.argv[1]
        if mode == 'build':
            build(Path(sys.argv[2]), Path(sys.argv[3]))
        elif mode == 'sync':
            sync(Path.cwd(), Path(sys.argv[2]), sys.argv[3])
        elif mode == 'bootstrap-uv':
            cache, job_path, resolved_manager, *public_cache = sys.argv[2:]
            if len(public_cache) > 1:
                raise ValueError('bootstrap accepts at most one public archive cache')
            job = json.loads(Path(job_path).read_text())
            bootstrap_uv(Path(cache), job, public_cache[0] if public_cache else None, resolved_manager)
        elif mode == 'prefetch':
            project, cache, job_path, uv, *public_cache = sys.argv[2:]
            if len(public_cache) > 1:
                raise ValueError('prefetch accepts at most one public archive cache')
            job = json.loads(Path(job_path).read_text())
            prefetch(Path(project), Path(cache), job, uv, public_cache[0] if public_cache else None)
        else:
            project, cache, job_path, uv, *certified_output = sys.argv[2:]
            if (mode == 'certify' and len(certified_output) != 1) \
                    or (mode != 'certify' and certified_output):
                raise ValueError('invalid certified environment arguments')
            job = json.loads(Path(job_path).read_text())
            if mode == 'certify':
                certify(Path(project), Path(cache), job, uv, certified_output[0])
            else:
                prefetch(Path(project), Path(cache), job, uv)
    except DownloadDeadlineExceeded as error:
        # Preserve a machine-readable timeout through Docker, the shell EXIT
        # trap, and the local Action supervisor. Do not infer it from log text.
        print(str(error), file=sys.stderr)
        sys.exit(124)
    except CertifiedEnvironmentUnavailable as error:
        # Reserved machine-readable exit status. The runner only interprets it
        # for its own generated dependency synchronization command; policy
        # commands cannot acquire this infrastructure classification.
        print(str(error), file=sys.stderr)
        sys.exit(86)
