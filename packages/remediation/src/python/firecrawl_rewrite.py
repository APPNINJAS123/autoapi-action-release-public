#!/usr/bin/env python3
"""AST-gated, formatting-preserving Firecrawl Python v1-to-v2 token rewrite."""

from __future__ import annotations

import ast
import json
import sys
from typing import Any


def offsets(content: str) -> list[int]:
    result = [0]
    for line in content.splitlines(keepends=True):
        result.append(result[-1] + len(line))
    return result


def position(lines: list[int], line: int, column: int) -> int:
    return lines[line - 1] + column


class Rewriter(ast.NodeVisitor):
    def __init__(self, content: str):
        self.content = content
        self.lines = offsets(content)
        self.alias_scopes: list[dict[str, str]] = [{}]
        self.receiver_scopes: list[set[str]] = [set()]
        self.edits: list[tuple[int, int, str]] = []
        self.unsafe: list[str] = []

    def lookup_alias(self, name: str) -> str | None:
        for scope in reversed(self.alias_scopes):
            if name in scope:
                return scope[name]
        return None

    def is_receiver(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self.receiver_scopes))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not (node.module or "").startswith("firecrawl"):
            return
        for alias in node.names:
            local = alias.asname or alias.name
            self.alias_scopes[-1][local] = alias.name
            if alias.name != "FirecrawlApp":
                continue
            start = position(self.lines, alias.lineno, alias.col_offset)
            self.edits.append((start, start + len("FirecrawlApp"), "Firecrawl"))

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if self.lookup_alias(node.value.func.id) == "FirecrawlApp":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.receiver_scopes[-1].add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if self.lookup_alias(node.value.func.id) == "FirecrawlApp":
                self.receiver_scopes[-1].add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and self.is_receiver(node.func.value.id):
            if node.func.attr == "scrape_url":
                if len(node.args) != 1 or node.keywords:
                    self.unsafe.append("scrape_url call is outside the reviewed one-argument shape")
                else:
                    end = position(self.lines, node.func.end_lineno or node.func.lineno, node.func.end_col_offset or node.func.col_offset)
                    self.edits.append((end - len("scrape_url"), end, "scrape"))
        self.generic_visit(node)

    def scoped(self, node: ast.AST) -> None:
        self.alias_scopes.append({})
        self.receiver_scopes.append(set())
        self.generic_visit(node)
        self.receiver_scopes.pop()
        self.alias_scopes.pop()

    visit_FunctionDef = scoped
    visit_AsyncFunctionDef = scoped
    visit_Lambda = scoped
    visit_ClassDef = scoped


def main() -> None:
    request = json.load(sys.stdin)
    content = request["content"]
    tree = ast.parse(content, filename=request.get("path", "<input>"), type_comments=True)
    rewriter = Rewriter(content)
    rewriter.visit(tree)
    if rewriter.unsafe:
        raise ValueError("; ".join(rewriter.unsafe))
    output = content
    for start, end, replacement in sorted(rewriter.edits, reverse=True):
        output = output[:start] + replacement + output[end:]
    json.dump({"content": output, "edits": len(rewriter.edits)}, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
