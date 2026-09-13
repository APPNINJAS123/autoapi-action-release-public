#!/usr/bin/env python3
"""Stream bounded vcpkg failure diagnostics as a deterministic tar archive."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tarfile


MAX_FILES = 64
MAX_FILE_TAIL_BYTES = 128 * 1024
MAX_TOTAL_TAIL_BYTES = 4 * 1024 * 1024
ALLOWED_NAMES = {"issue_body.md"}


def candidate_files(root: str, issue_body: str | None) -> list[tuple[str, str, int]]:
    candidates: list[tuple[str, str, int]] = []
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if not os.path.islink(os.path.join(directory, name))
        )
        for name in sorted(files):
            if not (name.endswith(".log") or name in ALLOWED_NAMES):
                continue
            path = os.path.join(directory, name)
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                continue
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if relative == ".." or relative.startswith("../"):
                raise RuntimeError("vcpkg diagnostic path escaped its root")
            candidates.append((f"vcpkg-buildtrees/{relative}", path, metadata.st_mtime_ns))
    if issue_body is not None and os.path.exists(issue_body):
        metadata = os.lstat(issue_body)
        if os.path.basename(issue_body) != "issue_body.md" or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("vcpkg issue body must be a regular issue_body.md file")
        candidates.append(("vcpkg-install/issue_body.md", issue_body, metadata.st_mtime_ns))
    return candidates


def ordered_candidates(candidates: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    activity: dict[str, int] = {}
    for relative, _, modified_ns in candidates:
        package = relative.split("/", 2)[1] if relative.startswith("vcpkg-buildtrees/") else ""
        activity[package] = max(activity.get(package, 0), modified_ns)

    def priority(candidate: tuple[str, str, int]) -> tuple[int, int, int, str]:
        relative, _, modified_ns = candidate
        name = relative.rsplit("/", 1)[-1]
        if relative == "vcpkg-install/issue_body.md":
            return (0, 0, -modified_ns, relative)
        package = relative.split("/", 2)[1]
        if name.startswith("config-") and name.endswith("-out.log"):
            file_priority = 0
        elif "CMakeCache" in name or "CMakeConfigureLog" in name:
            file_priority = 1
        elif name.startswith("stdout-") or name.endswith("-err.log"):
            file_priority = 2
        else:
            file_priority = 3
        return (1, -activity[package], file_priority, relative)

    return sorted(candidates, key=priority)


def tail(path: str) -> tuple[bytes, int, str]:
    size = os.path.getsize(path)
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
        source.seek(max(0, size - MAX_FILE_TAIL_BYTES))
        content = source.read(MAX_FILE_TAIL_BYTES)
    return content, size, digest.hexdigest()


def add_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = 0o600
    info.mtime = 0
    archive.addfile(info, io.BytesIO(content))


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: collect-vcpkg-diagnostics.py <vcpkg-buildtrees-root> [issue-body]")
    requested_root = sys.argv[1]
    if os.path.lexists(requested_root) and os.path.islink(requested_root):
        raise RuntimeError("vcpkg diagnostic root must be a non-symlink directory")
    root = os.path.realpath(requested_root)
    if os.path.lexists(root) and not os.path.isdir(root):
        raise RuntimeError("vcpkg diagnostic root must be a directory")
    records: list[dict[str, object]] = []
    payloads: list[tuple[str, bytes]] = []
    total = 0
    candidates = [] if not os.path.isdir(root) else ordered_candidates(candidate_files(root, sys.argv[2] if len(sys.argv) == 3 else None))
    for relative, path, _ in candidates[:MAX_FILES]:
        content, original_bytes, sha256 = tail(path)
        remaining = MAX_TOTAL_TAIL_BYTES - total
        if remaining <= 0:
            break
        if len(content) > remaining:
            content = content[-remaining:]
        total += len(content)
        payloads.append((relative, content))
        records.append({
            "path": relative,
            "originalBytes": original_bytes,
            "capturedTailBytes": len(content),
            "sha256": sha256,
        })
    manifest = json.dumps({
        "schemaVersion": "1.0",
        "maxFiles": MAX_FILES,
        "maxFileTailBytes": MAX_FILE_TAIL_BYTES,
        "maxTotalTailBytes": MAX_TOTAL_TAIL_BYTES,
        "candidateFileCount": len(candidates),
        "capturedFileCount": len(records),
        "omittedFileCount": len(candidates) - len(records),
        "files": records,
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        add_bytes(archive, "autoapi-vcpkg-diagnostics.json", manifest)
        for name, content in payloads:
            add_bytes(archive, name, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
