import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
import re


class SeedError(RuntimeError):
    pass


def safe_member_name(raw_name: str, allowed_roots: tuple[str, ...]) -> str:
    name = raw_name.removesuffix('/')
    if not name or name.startswith('/') or '\\' in name:
        raise SeedError(f'unsafe cache archive member name: {raw_name!r}')
    pieces = name.split('/')
    if any(piece in ('', '.', '..') for piece in pieces):
        raise SeedError(f'unsafe cache archive member name: {raw_name!r}')
    normalized = PurePosixPath(name).as_posix()
    if not any(normalized == root or normalized.startswith(f'{root}/') or root.startswith(f'{normalized}/') for root in allowed_roots):
        raise SeedError(f'cache archive member is outside the allowlist: {raw_name!r}')
    return normalized


def normalized_mode(name: str, entry_type: str) -> int:
    if entry_type == 'directory':
        return 0o755
    path = PurePosixPath(name)
    if name.startswith('gradle/wrapper/dists/') and path.name == 'gradle' and path.parent.name == 'bin':
        return 0o755
    return 0o644


def nested_mounts(source_root: Path, selected_roots: tuple[Path, ...], mountinfo: Path = Path('/proc/self/mountinfo'), required: bool = False) -> list[Path]:
    if not mountinfo.is_file():
        if required:
            raise SeedError('Linux mountinfo is unavailable; refusing external cache seed')
        return []
    source = source_root.resolve()
    selected = tuple(path.resolve() for path in selected_roots)
    result = []
    for line in mountinfo.read_text(encoding='utf-8').splitlines():
        fields = line.split(' ')
        if len(fields) < 5:
            continue
        encoded = fields[4]
        mountpoint = Path(encoded.replace('\\040', ' ').replace('\\011', '\t').replace('\\012', '\n').replace('\\134', '\\')).resolve()
        if mountpoint == source:
            continue
        if any(mountpoint == root or root in mountpoint.parents for root in selected):
            result.append(mountpoint)
    return result


def scan_tree(source_root: Path, relative_roots: tuple[str, ...], max_bytes: int, max_nodes: int, mountinfo: Path = Path('/proc/self/mountinfo'), require_mountinfo: bool = False) -> tuple[int, int]:
    root_stat = os.lstat(source_root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise SeedError('cache seed source root must be a non-symlink directory')
    selected = tuple(source_root.joinpath(*PurePosixPath(root).parts) for root in relative_roots)
    mounted = nested_mounts(source_root, selected, mountinfo, require_mountinfo)
    if mounted:
        raise SeedError(f'cache seed contains a nested mount: {mounted[0]}')

    logical_bytes = 0
    node_count = 0

    def account(path: Path) -> None:
        nonlocal logical_bytes, node_count
        metadata = os.lstat(path)
        if metadata.st_dev != root_stat.st_dev:
            raise SeedError(f'cache seed crosses a filesystem boundary: {path}')
        if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise SeedError(f'cache seed contains a non-file/non-directory entry: {path}')
        if metadata.st_mode & 0o7000:
            raise SeedError(f'cache seed contains special permission bits: {path}')
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise SeedError(f'cache seed contains a hard-linked regular file: {path}')
        node_count += 1
        if node_count > max_nodes:
            raise SeedError('cache seed exceeds the total node-count bound')
        if stat.S_ISREG(metadata.st_mode):
            logical_bytes += metadata.st_size
            if logical_bytes > max_bytes:
                raise SeedError('cache seed exceeds the logical regular-file byte bound')
            return
        with os.scandir(path) as entries:
            for entry in entries:
                account(Path(entry.path))

    for path in selected:
        ancestor = source_root
        for piece in path.relative_to(source_root).parts:
            ancestor /= piece
            metadata = os.lstat(ancestor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise SeedError(f'cache seed path traverses a non-directory or symlink: {ancestor}')
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SeedError(f'cache seed subtree must be a non-symlink directory: {path}')
        account(path)
    return logical_bytes, node_count


def load_manifest(path: Path, expected_sha256: str, expected_key: str, allowed_roots: tuple[str, ...], max_bytes: int, max_nodes: int) -> dict[str, dict]:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_size > 64 * 1024 * 1024:
        raise SeedError('cache seed manifest must be a bounded non-symlink regular file')
    raw = path.read_bytes()
    if not re.fullmatch(r'[a-f0-9]{64}', expected_sha256) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SeedError('cache seed manifest SHA-256 does not match the separately supplied digest')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('schemaVersion') != '1.0':
        raise SeedError('cache seed manifest has an unsupported schema')
    if value.get('certificationKey') != expected_key:
        raise SeedError('cache seed manifest certification key does not match this manager/toolchain')
    if value.get('roots') != list(allowed_roots) or not isinstance(value.get('entries'), list):
        raise SeedError('cache seed manifest roots do not match the code-owned allowlist')
    entries: dict[str, dict] = {}
    logical_bytes = 0
    for entry in value['entries']:
        if not isinstance(entry, dict) or set(entry) - {'path', 'type', 'mode', 'size', 'sha256'}:
            raise SeedError('cache seed manifest contains a malformed entry')
        name = safe_member_name(entry.get('path', ''), allowed_roots)
        if name in entries or entry.get('type') not in ('file', 'directory'):
            raise SeedError(f'cache seed manifest contains a duplicate or invalid entry: {name}')
        if any(root.startswith(f'{name}/') for root in allowed_roots) and entry['type'] != 'directory':
            raise SeedError(f'cache seed manifest makes an allowlist ancestor executable content: {name}')
        if entry.get('mode') != normalized_mode(name, entry['type']):
            raise SeedError(f'cache seed manifest contains a non-normalized permission mode: {name}')
        if entry['type'] == 'file':
            size = entry.get('size')
            digest = entry.get('sha256')
            if not isinstance(size, int) or size < 0 or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
                raise SeedError(f'cache seed manifest contains invalid file metadata: {name}')
            logical_bytes += size
        elif set(entry) != {'path', 'type', 'mode'}:
            raise SeedError(f'cache seed manifest contains invalid directory metadata: {name}')
        entries[name] = entry
    if len(entries) > max_nodes or logical_bytes > max_bytes:
        raise SeedError('cache seed manifest exceeds configured bounds')
    return entries


def stream_sha256(source) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def validate_archive(archive: Path, allowed_roots: tuple[str, ...], manifest: dict[str, dict], max_bytes: int, max_nodes: int) -> tuple[int, int, set[str]]:
    logical_bytes = 0
    explicit_names: set[str] = set()
    extracted_names: set[str] = set()
    with tarfile.open(archive, mode='r:') as source:
        for member in source:
            name = safe_member_name(member.name, allowed_roots)
            if name in explicit_names:
                raise SeedError(f'duplicate cache archive member: {name}')
            explicit_names.add(name)
            path = PurePosixPath(name)
            extracted_names.add(name)
            for parent in path.parents:
                if parent.as_posix() != '.':
                    extracted_names.add(parent.as_posix())
            if not (member.isdir() or member.isfile()):
                raise SeedError(f'cache archive contains a link or special entry: {name}')
            expected = manifest.get(name)
            expected_type = 'directory' if member.isdir() else 'file'
            if expected is None or expected.get('type') != expected_type:
                raise SeedError(f'cache archive member is absent from or differs from the trusted manifest: {name}')
            if member.mode & 0o7000:
                raise SeedError(f'cache archive member contains special permission bits: {name}')
            if normalized_mode(name, expected_type) != expected['mode']:
                raise SeedError(f'cache archive member normalized mode differs from the trusted manifest: {name}')
            if len(extracted_names) > max_nodes:
                raise SeedError('cache archive exceeds the total node-count bound')
            if member.isfile():
                logical_bytes += member.size
                if logical_bytes > max_bytes:
                    raise SeedError('cache archive exceeds the logical regular-file byte bound')
                extracted = source.extractfile(member)
                if extracted is None or member.size != expected['size'] or stream_sha256(extracted) != expected['sha256']:
                    raise SeedError(f'cache archive payload does not match the trusted manifest: {name}')
    if extracted_names != set(manifest):
        raise SeedError('cache archive membership does not match the trusted manifest')
    return logical_bytes, len(extracted_names), extracted_names


def ensure_empty_directory(destination: Path) -> None:
    metadata = os.lstat(destination)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SeedError('cache seed destination must be a non-symlink directory')
    with os.scandir(destination) as entries:
        if next(entries, None) is not None:
            raise SeedError('cache seed destination must be empty')


def own_and_verify(destination: Path, runtime_uid: int, runtime_gid: int, manifest: dict[str, dict], max_bytes: int, max_nodes: int) -> None:
    logical_bytes = 0
    node_count = 0
    actual_names: set[str] = set()
    destination_device = os.lstat(destination).st_dev
    for current, directories, files in os.walk(destination, topdown=False, followlinks=False):
        for name in (*directories, *files):
            path = Path(current, name)
            metadata = os.lstat(path)
            if metadata.st_dev != destination_device:
                raise SeedError(f'extracted cache crosses a filesystem boundary: {path}')
            if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise SeedError(f'extracted cache contains a link or special entry: {path}')
            relative = path.relative_to(destination).as_posix()
            actual_names.add(relative)
            node_count += 1
            if node_count > max_nodes:
                raise SeedError('extracted cache exceeds the total node-count bound')
            if stat.S_ISREG(metadata.st_mode):
                logical_bytes += metadata.st_size
                if logical_bytes > max_bytes:
                    raise SeedError('extracted cache exceeds the logical regular-file byte bound')
                expected = manifest.get(relative)
                if expected is None or expected.get('type') != 'file' or metadata.st_size != expected['size']:
                    raise SeedError(f'extracted cache differs from the trusted manifest: {relative}')
                with path.open('rb') as source:
                    if stream_sha256(source) != expected['sha256']:
                        raise SeedError(f'extracted cache payload differs from the trusted manifest: {relative}')
            elif manifest.get(relative, {}).get('type') != 'directory':
                raise SeedError(f'extracted cache directory differs from the trusted manifest: {relative}')
            os.chmod(path, manifest[relative]['mode'], follow_symlinks=False)
            os.chown(path, runtime_uid, runtime_gid, follow_symlinks=False)
    if actual_names != set(manifest):
        raise SeedError('extracted cache does not match the validated archive manifest')
    os.chown(destination, runtime_uid, runtime_gid, follow_symlinks=False)


def seed(args: argparse.Namespace) -> None:
    source = Path(args.source)
    destination = Path(args.destination)
    roots = tuple(args.paths)
    for root in roots:
        safe_member_name(root, roots)
    existing = []
    for root in roots:
        try:
            os.lstat(source.joinpath(*PurePosixPath(root).parts))
        except FileNotFoundError:
            continue
        existing.append(root)
    existing_roots = tuple(existing)
    ensure_empty_directory(destination)
    manifest = load_manifest(Path(args.manifest), args.expected_manifest_sha256, args.certification_key, roots, args.max_bytes, args.max_nodes)
    if not existing_roots:
        if manifest:
            raise SeedError('cache seed manifest describes missing allowlisted content')
        return
    scan_tree(source, existing_roots, args.max_bytes, args.max_nodes, Path(args.mountinfo), True)
    selected = tuple(source.joinpath(*PurePosixPath(root).parts) for root in existing_roots)
    mounted = nested_mounts(source, selected, Path(args.mountinfo), True)
    if mounted:
        raise SeedError(f'cache seed contains a nested mount: {mounted[0]}')
    with tempfile.TemporaryDirectory(prefix='autoapi-cache-seed-') as temporary:
        archive = Path(temporary, 'seed.tar')
        command = [args.tar, '--create', '--file', str(archive), '--one-file-system', '--directory', str(source), '--', *existing_roots]
        subprocess.run(command, check=True)
        logical_bytes, node_count, names = validate_archive(archive, roots, manifest, args.max_bytes, args.max_nodes)
        ensure_empty_directory(destination)
        subprocess.run([
            args.tar, '--extract', '--file', str(archive), '--directory', str(destination),
            '--no-same-owner', '--no-same-permissions',
        ], check=True)
        own_and_verify(destination, args.runtime_uid, args.runtime_gid, manifest, args.max_bytes, args.max_nodes)
        with archive.open('rb') as archive_source:
            digest = stream_sha256(archive_source)
        print(f'Validated cache seed: nodes={node_count} logical_bytes={logical_bytes} sha256={digest}', file=sys.stderr)


def create_manifest(args: argparse.Namespace) -> None:
    source = Path(args.source)
    roots = tuple(args.paths)
    for root in roots:
        safe_member_name(root, roots)
    existing = []
    for root in roots:
        try:
            os.lstat(source.joinpath(*PurePosixPath(root).parts))
        except FileNotFoundError:
            continue
        existing.append(root)
    scan_tree(source, tuple(existing), args.max_bytes, args.max_nodes, Path(args.mountinfo), False)
    entries: dict[str, dict] = {}
    for root in existing:
        selected = source.joinpath(*PurePosixPath(root).parts)
        for current, directories, files in os.walk(selected, followlinks=False):
            for path in (Path(current), *(Path(current, name) for name in directories), *(Path(current, name) for name in files)):
                relative = path.relative_to(source).as_posix()
                safe_member_name(relative, roots)
                for parent in PurePosixPath(relative).parents:
                    name = parent.as_posix()
                    if name != '.':
                        entries[name] = {'path': name, 'type': 'directory', 'mode': normalized_mode(name, 'directory')}
                metadata = os.lstat(path)
                if metadata.st_mode & 0o7000:
                    raise SeedError(f'cache seed contains special permission bits: {path}')
                if stat.S_ISDIR(metadata.st_mode):
                    entries[relative] = {'path': relative, 'type': 'directory', 'mode': normalized_mode(relative, 'directory')}
                elif stat.S_ISREG(metadata.st_mode):
                    with path.open('rb') as file_source:
                        digest = stream_sha256(file_source)
                    entries[relative] = {
                        'path': relative, 'type': 'file', 'mode': normalized_mode(relative, 'file'), 'size': metadata.st_size, 'sha256': digest,
                    }
                else:
                    raise SeedError(f'cache seed contains a link or special entry: {path}')
    value = {
        'schemaVersion': '1.0',
        'certificationKey': args.certification_key,
        'roots': list(roots),
        'entries': [entries[name] for name in sorted(entries)],
    }
    raw = (json.dumps(value, separators=(',', ':'), sort_keys=True) + '\n').encode()
    target = source / '.autoapi-cache-seed-manifest.json'
    descriptor, temporary_name = tempfile.mkstemp(prefix='.autoapi-cache-seed-manifest-', dir=source)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    print(hashlib.sha256(raw).hexdigest())


def create_manifest_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--certification-key', required=True)
    parser.add_argument('--max-bytes', type=int, default=2 * 1024 * 1024 * 1024)
    parser.add_argument('--max-nodes', type=int, default=200_000)
    parser.add_argument('--mountinfo', default='/proc/self/mountinfo')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args(arguments)
    try:
        create_manifest(args)
    except (OSError, SeedError) as error:
        print(f'Cache seed manifest creation rejected: {error}', file=sys.stderr)
        return 2
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == 'create-manifest':
        return create_manifest_main(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--runtime-uid', required=True, type=int)
    parser.add_argument('--runtime-gid', required=True, type=int)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--certification-key', required=True)
    parser.add_argument('--max-bytes', type=int, default=2 * 1024 * 1024 * 1024)
    parser.add_argument('--max-nodes', type=int, default=200_000)
    parser.add_argument('--tar', default='/bin/tar')
    parser.add_argument('--mountinfo', default='/proc/self/mountinfo')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    if args.runtime_uid < 0 or args.runtime_gid < 0 or args.max_bytes < 0 or args.max_nodes < 1:
        parser.error('ownership and bound values must be non-negative')
    try:
        seed(args)
    except (OSError, SeedError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f'Cache seed rejected: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
