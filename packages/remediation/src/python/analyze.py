#!/usr/bin/env python3
"""Read-only Python repository indexer for Automated API impact analysis.

The process accepts one JSON object on stdin and emits one JSON object on
stdout. It never imports or executes customer modules.
"""

from __future__ import annotations

import ast
import configparser
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXCLUDED_DIRECTORIES = {
    ".git", ".hg", ".mypy_cache", ".nox", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "__pycache__", "build", "coverage", "dist",
    "htmlcov", "node_modules", "site-packages", "venv", "vendor",
}
MANIFEST_NAMES = {
    "Pipfile", "Pipfile.lock", "poetry.lock", "pdm.lock", "pyproject.toml",
    "setup.cfg", "setup.py", "uv.lock",
}
REQUIREMENTS_PATTERN = re.compile(r"^(?:requirements(?:[-_.].*)?|constraints(?:[-_.].*)?)\.txt$", re.I)
NAME_PATTERN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def relative(root: Path, path: Path) -> str:
    value = path.relative_to(root).as_posix()
    return value or "."


def workspace_for(root: Path, path: Path, manifests: list[Path]) -> str:
    candidates = [item.parent for item in manifests if item.parent == path.parent or item.parent in path.parents]
    if not candidates:
        return "."
    selected = max(candidates, key=lambda item: len(item.parts))
    return relative(root, selected)


def iter_repository(root: Path):
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name not in EXCLUDED_DIRECTORIES and not Path(current, name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current, name)
            if path.is_symlink():
                continue
            yield path


def manifest_paths(root: Path, paths: list[Path]) -> list[Path]:
    return [
        path for path in paths
        if path.name in MANIFEST_NAMES or REQUIREMENTS_PATTERN.match(path.name)
    ]


def requirement_names(path: Path) -> list[tuple[str, int]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    names: list[tuple[str, int]] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-r", "--requirement", "-c", "--constraint")):
            continue
        if line.startswith(("-e", "--editable", "git+", "http://", "https://", ".", "/")):
            continue
        match = NAME_PATTERN.match(line)
        if match:
            names.append((match.group(1), line_number))
    return names


def pyproject_names(path: Path) -> list[tuple[str, int]]:
    try:
        import tomllib
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (ImportError, OSError, UnicodeError, ValueError):
        return []
    values: list[str] = []
    project = data.get("project", {}) if isinstance(data, dict) else {}
    if isinstance(project, dict):
        dependencies = project.get("dependencies", [])
        if isinstance(dependencies, list):
            values.extend(item for item in dependencies if isinstance(item, str))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    values.extend(item for item in group if isinstance(item, str))
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    if isinstance(poetry, dict):
        for field in ("dependencies", "dev-dependencies"):
            group = poetry.get(field, {})
            if isinstance(group, dict):
                values.extend(str(name) for name in group if str(name).lower() != "python")
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            for group in groups.values():
                dependencies = group.get("dependencies", {}) if isinstance(group, dict) else {}
                if isinstance(dependencies, dict):
                    values.extend(str(name) for name in dependencies)
    result: list[tuple[str, int]] = []
    lines = text.splitlines()
    for value in values:
        match = NAME_PATTERN.match(value)
        if match:
            normalized = normalize_distribution(match.group(1))
            line_number = next((
                index for index, line in enumerate(lines, start=1)
                if normalized in normalize_distribution(line)
            ), 1)
            result.append((match.group(1), line_number))
    return result


def setup_cfg_names(path: Path) -> list[tuple[str, int]]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return []
    values: list[str] = []
    for section, option in (("options", "install_requires"), ("options.extras_require", None)):
        if not parser.has_section(section):
            continue
        if option is not None and parser.has_option(section, option):
            values.extend(parser.get(section, option).splitlines())
        elif option is None:
            for _, content in parser.items(section):
                values.extend(content.splitlines())
    return [(match.group(1), 1) for value in values if (match := NAME_PATTERN.match(value))]


def setup_py_names(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return []
    result: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg not in {"install_requires", "extras_require"}:
                continue
            for child in ast.walk(keyword.value):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    match = NAME_PATTERN.match(child.value)
                    if match:
                        result.append((match.group(1), getattr(child, "lineno", 1)))
    return result


def manifest_dependencies(path: Path) -> list[tuple[str, int]]:
    if REQUIREMENTS_PATTERN.match(path.name):
        return requirement_names(path)
    if path.name in {"pyproject.toml", "Pipfile"}:
        return pyproject_names(path)
    if path.name == "setup.cfg":
        return setup_cfg_names(path)
    if path.name == "setup.py":
        return setup_py_names(path)
    return []


def root_name(value: str) -> str:
    return value.split(".", 1)[0]


def version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.match(r"^v?(\d+(?:\.\d+)*)", value.strip(), re.I)
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def requirement_can_match(raw_line: str, affected_range: Any) -> bool:
    """Conservatively decides whether a declared PEP-440-like range can include the old release."""
    if not isinstance(affected_range, str):
        return True
    affected_match = re.match(r"^==\s*([^\s,;]+)", affected_range)
    if not affected_match:
        return True
    old = version_tuple(affected_match.group(1))
    if old is None:
        return True
    comparisons = re.findall(r"(===|==|!=|~=|>=|<=|>|<|\^)\s*v?(\d+(?:\.\d+)*)", raw_line)
    if not comparisons:
        return True
    for operator, value in comparisons:
        bound = version_tuple(value)
        if bound is None:
            return True
        width = max(len(old), len(bound))
        candidate = old + (0,) * (width - len(old))
        limit = bound + (0,) * (width - len(bound))
        if operator in {"==", "==="} and candidate != limit:
            return False
        if operator == "!=" and candidate == limit:
            return False
        if operator == ">=" and candidate < limit:
            return False
        if operator == ">" and candidate <= limit:
            return False
        if operator == "<=" and candidate > limit:
            return False
        if operator == "<" and candidate >= limit:
            return False
        if operator == "^" and (candidate < limit or candidate[0] != limit[0]):
            return False
        if operator == "~=":
            upper_prefix = limit[:max(1, len(bound) - 1)]
            if candidate < limit or candidate[:len(upper_prefix)] != upper_prefix:
                return False
    return True


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def host_matches(host: str, pattern: str) -> bool:
    host_labels = host.lower().split(".")
    pattern_labels = pattern.lower().split(".")
    if "*" not in pattern:
        return host.lower() == pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern_labels[1:]
        return len(host_labels) > len(suffix) and host_labels[-len(suffix):] == suffix
    return len(host_labels) == len(pattern_labels) and all(
        expected == "*" or expected == actual
        for actual, expected in zip(host_labels, pattern_labels)
    )


def matching_host(value: str, patterns: list[str]) -> str | None:
    for candidate in re.findall(r"https?://[A-Za-z0-9.*_-]+(?:\.[A-Za-z0-9_-]+)+", value):
        host = urlparse(candidate).hostname
        if host and any(host_matches(host, pattern) for pattern in patterns):
            return host.lower()
    return None


class SourceAnalyzer(ast.NodeVisitor):
    def __init__(self, root: Path, path: Path, workspace: str, import_roots: set[str], hosts: list[str], firecrawl_recipe: bool, affected_symbols: set[str], local_classes: set[str]):
        self.root = root
        self.path = path
        self.workspace = workspace
        self.import_roots = import_roots
        self.hosts = hosts
        self.firecrawl_recipe = firecrawl_recipe
        self.affected_symbols = affected_symbols
        self.local_classes = local_classes
        self.alias_scopes: list[dict[str, str]] = [{}]
        self.receiver_scopes: list[dict[str, str]] = [{}]
        self.evidence: list[dict[str, Any]] = []

    def emit(self, kind: str, operation: str, node: ast.AST, detail: str, deterministic: bool = False) -> None:
        self.evidence.append({
            "kind": kind,
            "operation": operation,
            "path": relative(self.root, self.path),
            "line": max(1, getattr(node, "lineno", 1)),
            "column": max(1, getattr(node, "col_offset", 0) + 1),
            "detail": detail,
            "workspace": self.workspace,
            "deterministic": deterministic,
        })

    def lookup(self, name: str, scopes: list[dict[str, str]]) -> str | None:
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return None

    def imported_origin(self, node: ast.AST) -> str | None:
        value = dotted_name(node)
        if not value:
            return None
        first, *rest = value.split(".")
        origin = self.lookup(first, self.alias_scopes) or self.lookup(first, self.receiver_scopes)
        return ".".join([origin, *rest]) if origin else None

    def expression_origin(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Await):
            return self.expression_origin(node.value)
        if isinstance(node, ast.Call):
            return self.imported_origin(node.func)
        if isinstance(node, ast.Subscript):
            return self.expression_origin(node.value)
        return self.imported_origin(node)

    def annotation_origin(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                return self.annotation_origin(ast.parse(node.value, mode="eval").body)
            except SyntaxError:
                return None
        origin = self.imported_origin(node)
        if origin:
            return origin
        if isinstance(node, ast.Subscript):
            return self.annotation_origin(node.slice)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self.annotation_origin(node.left) or self.annotation_origin(node.right)
        return None

    def emit_annotation(self, node: ast.AST | None) -> None:
        origin = self.annotation_origin(node)
        if not origin:
            return
        operation = origin.rsplit(".", 1)[-1]
        if operation not in self.affected_symbols:
            return
        self.emit(
            "python_import",
            operation,
            node,
            f"type annotation is bound to affected Python SDK symbol {origin!r}",
            self.firecrawl_recipe and origin == "firecrawl.FirecrawlApp",
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if root_name(alias.name) not in self.import_roots:
                continue
            local = alias.asname or root_name(alias.name)
            self.alias_scopes[-1][local] = alias.name
            if self.firecrawl_recipe and root_name(alias.name) == "firecrawl":
                # Module-style legacy access is detected through the call below,
                # but is outside the reviewed import rewrite.
                self.emit("python_import", "package_usage", node, f"module import of Firecrawl requires Harness review")
                continue
            self.emit("python_import", "package_usage", node, f"import from affected Python package {alias.name!r}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if root_name(module) not in self.import_roots:
            return
        for alias in node.names:
            local = alias.asname or alias.name
            self.alias_scopes[-1][local] = f"{module}.{alias.name}" if module else alias.name
        if self.firecrawl_recipe and root_name(module) == "firecrawl" and not any(
            alias.name == "FirecrawlApp" for alias in node.names
        ):
            return
        firecrawl_safe = self.firecrawl_recipe and root_name(module) == "firecrawl" and any(
            alias.name == "FirecrawlApp" for alias in node.names
        )
        operation = next((alias.name for alias in node.names if alias.name in self.affected_symbols), "package_usage")
        self.emit("python_import", operation, node, f"import from affected Python package {module!r}", firecrawl_safe)

    def visit_Assign(self, node: ast.Assign) -> None:
        origin = self.expression_origin(node.value)
        if origin:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.receiver_scopes[-1][target.id] = origin
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.emit_annotation(node.annotation)
        if isinstance(node.target, ast.Name) and node.value is not None:
            origin = self.expression_origin(node.value)
            if origin:
                self.receiver_scopes[-1][node.target.id] = origin
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        origin = self.expression_origin(node.iter)
        if origin and isinstance(node.target, ast.Name):
            self.receiver_scopes[-1][node.target.id] = origin
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_Subscript(self, node: ast.Subscript) -> None:
        origin = self.expression_origin(node.value)
        if origin:
            self.emit(
                "dynamic_usage", "sdk_response_access", node,
                f"subscript access is bound to affected Python SDK response {origin!r}",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        origin = self.imported_origin(node.func)
        if origin:
            operation = origin.rsplit(".", 1)[-1]
            if self.firecrawl_recipe and origin.startswith("firecrawl.") and (
                "FirecrawlApp" not in origin and operation != "scrape_url"
            ):
                self.generic_visit(node)
                return
            firecrawl_safe = self.firecrawl_recipe and (
                operation == "FirecrawlApp"
                or (operation == "scrape_url" and len(node.args) == 1 and len(node.keywords) == 0)
            ) and origin.startswith("firecrawl.")
            self.emit("python_call", operation, node, f"call is bound to affected Python SDK symbol {origin!r}", firecrawl_safe)
        elif self.firecrawl_recipe and isinstance(node.func, ast.Attribute) and node.func.attr == "scrape_url":
            receiver_is_local = (
                isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id in self.local_classes
            )
            if not receiver_is_local:
                self.emit(
                    "dynamic_usage", "unresolved_firecrawl_receiver", node,
                    "scrape_url receiver is not bound to a local FirecrawlApp construction",
                )
        if isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args:
            receiver = self.imported_origin(node.args[0])
            if receiver:
                self.emit("dynamic_usage", "dynamic_python_attribute", node, "dynamic attribute access on an affected Python SDK receiver")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            host = matching_host(node.value, self.hosts)
            if host:
                self.emit("python_raw_endpoint", "api_host_usage", node, f"request URL uses affected API host {host!r}")

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        static = "".join(value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else "{}" for value in node.values)
        host = matching_host(static, self.hosts)
        if host:
            self.emit("python_raw_endpoint", "api_host_usage", node, f"f-string URL uses affected API host {host!r}")
        self.generic_visit(node)

    def scoped(self, node: ast.AST) -> None:
        self.alias_scopes.append({})
        self.receiver_scopes.append({})
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg:
                arguments.append(node.args.vararg)
            if node.args.kwarg:
                arguments.append(node.args.kwarg)
            for argument in arguments:
                origin = self.annotation_origin(argument.annotation)
                if origin:
                    self.receiver_scopes[-1][argument.arg] = origin
                    self.emit_annotation(argument.annotation)
            self.emit_annotation(node.returns)
        self.generic_visit(node)
        self.receiver_scopes.pop()
        self.alias_scopes.pop()

    visit_FunctionDef = scoped
    visit_AsyncFunctionDef = scoped
    visit_Lambda = scoped
    visit_ClassDef = scoped


def main() -> None:
    request = json.load(sys.stdin)
    root = Path(request["rootDir"]).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("rootDir must be a directory")
    dependencies = request.get("dependencies", [])
    distribution_targets = {
        normalize_distribution(item["name"]): item
        for item in dependencies if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    distributions = {name: item["name"] for name, item in distribution_targets.items()}
    import_root_distributions: dict[str, set[str]] = {}
    for item in dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        distribution = normalize_distribution(item["name"])
        for name in item.get("importNames", []):
            if isinstance(name, str):
                import_root_distributions.setdefault(root_name(name), set()).add(distribution)
    import_roots = set(import_root_distributions)
    hosts = [value.lower() for value in request.get("apiHosts", []) if isinstance(value, str)]
    firecrawl_recipe = "firecrawl-python-v1-v2" in request.get("recipeIds", [])
    affected_symbols = {
        value for value in request.get("affectedSymbols", []) if isinstance(value, str)
    }
    runtime_workspace = request.get("runtimeWorkspace")
    if not isinstance(runtime_workspace, str):
        runtime_workspace = None
    paths = list(iter_repository(root))
    manifests = manifest_paths(root, paths)
    evidence: list[dict[str, Any]] = []
    firecrawl_safe_workspaces: set[str] = set()
    firecrawl_current_workspaces: set[str] = set()
    workspace_package_status: dict[str, dict[str, bool]] = {}

    for manifest in manifests:
        for name, line in manifest_dependencies(manifest):
            normalized = normalize_distribution(name)
            if normalized not in distributions:
                continue
            raw_line = ""
            try:
                raw_line = manifest.read_text(encoding="utf-8").splitlines()[line - 1]
            except (OSError, UnicodeError, IndexError):
                pass
            manifest_workspace = relative(root, manifest.parent)
            affected = requirement_can_match(
                raw_line,
                distribution_targets[normalized].get("oldVersionRange"),
            )
            previous = workspace_package_status.setdefault(manifest_workspace, {}).get(normalized)
            workspace_package_status[manifest_workspace][normalized] = affected or previous is True
            if not affected:
                continue
            deterministic = firecrawl_recipe and normalized == "firecrawl-py" and bool(
                re.search(r"(?:^\s*|[\"'])firecrawl-py==1\.14\.0(?:\b|[\"'])", raw_line, re.I)
            )
            current = firecrawl_recipe and normalized == "firecrawl-py" and bool(
                re.search(r"(?:^\s*|[\"'])firecrawl-py==4\.31\.0(?:\b|[\"'])", raw_line, re.I)
            )
            if current:
                firecrawl_current_workspaces.add(manifest_workspace)
                continue
            if deterministic:
                firecrawl_safe_workspaces.add(manifest_workspace)
            evidence.append({
                "kind": "python_dependency",
                "operation": "package_usage",
                "path": relative(root, manifest),
                "line": line,
                "column": 1,
                "detail": f"PyPI dependency {name!r} is affected",
                "workspace": manifest_workspace,
                "deterministic": deterministic,
            })

    errors: list[dict[str, Any]] = []
    for path in (item for item in paths if item.suffix in {".py", ".pyi"}):
        try:
            content = path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(path), type_comments=True)
        except SyntaxError as error:
            errors.append({
                "path": relative(root, path),
                "line": max(1, error.lineno or 1),
                "detail": "Python syntax could not be parsed deterministically",
            })
            continue
        except (OSError, UnicodeError):
            continue
        local_classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        source_workspace = workspace_for(root, path, manifests)
        package_status = dict(workspace_package_status.get(source_workspace, {}))
        if runtime_workspace is not None:
            package_status.update(workspace_package_status.get(runtime_workspace, {}))
        source_import_roots = {
            name for name in import_roots
            # Import roots are not distribution identities. Several official
            # packages can expose the same root (for example `firecrawl-py`
            # and `firecrawl` both expose `firecrawl`). Require the exact
            # affected distribution in the nearest manifest before binding
            # imports or calls to a package-scoped ChangeEvent.
            if any(package_status.get(distribution, False)
                   for distribution in import_root_distributions.get(name, set()))
        }
        source_import_roots -= ({"firecrawl"} if source_workspace in firecrawl_current_workspaces else set())
        analyzer = SourceAnalyzer(
            root, path, source_workspace, source_import_roots, hosts,
            firecrawl_recipe and (
                source_workspace in firecrawl_safe_workspaces
                or runtime_workspace in firecrawl_safe_workspaces
            ),
            affected_symbols,
            local_classes,
        )
        analyzer.visit(tree)
        evidence.extend(analyzer.evidence)

    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in evidence:
        key = (item["kind"], item["operation"], item["path"], item["line"], item["column"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    json.dump({
        "manifests": [relative(root, item) for item in manifests],
        "evidence": unique,
        "parseErrors": errors,
    }, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
