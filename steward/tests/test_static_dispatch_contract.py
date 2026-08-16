from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, order=True)
class _Violation:
    path: str
    line: int
    kind: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line} {self.kind}"


@dataclass(frozen=True)
class _HasattrGuard:
    receiver: ast.AST
    name: str | None
    negated: bool


def _is_named_call(node: ast.Call, name: str) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == name


def _is_getattr_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _is_named_call(node, "getattr")


def _expression_key(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _argument_shape(node: ast.Call) -> tuple[object, ...]:
    positional = tuple(
        "starred" if isinstance(argument, ast.Starred) else "positional"
        for argument in node.args
    )
    keywords = tuple("**" if keyword.arg is None else keyword.arg for keyword in node.keywords)
    return (positional, keywords)


def _catches_type_error(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "TypeError"
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_catches_type_error(item) for item in node.elts)
    return False


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _calls_in(nodes: ast.AST | list[ast.stmt]) -> list[ast.Call]:
    collector = _CallCollector()
    if isinstance(nodes, list):
        for node in nodes:
            collector.visit(node)
    else:
        collector.visit(nodes)
    return collector.calls


class _TopLevelCallCollector(_CallCollector):
    """Collect calls from simple try statements, not from nested branches."""

    def visit_If(self, _node: ast.If) -> None:
        return

    def visit_For(self, _node: ast.For) -> None:
        return

    def visit_AsyncFor(self, _node: ast.AsyncFor) -> None:
        return

    def visit_While(self, _node: ast.While) -> None:
        return

    def visit_With(self, _node: ast.With) -> None:
        return

    def visit_AsyncWith(self, _node: ast.AsyncWith) -> None:
        return

    def visit_Try(self, _node: ast.Try) -> None:
        return

    def visit_TryStar(self, _node: ast.TryStar) -> None:
        return

    def visit_Match(self, _node: ast.Match) -> None:
        return


def _top_level_calls_in(nodes: list[ast.stmt]) -> list[ast.Call]:
    collector = _TopLevelCallCollector()
    for node in nodes:
        collector.visit(node)
    return collector.calls


class _HasattrGuardCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.guards: list[_HasattrGuard] = []
        self._negated = False

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._negated = not self._negated
            self.visit(node.operand)
            self._negated = not self._negated
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_named_call(node, "hasattr") and len(node.args) >= 2:
            name = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
            if isinstance(name, str):
                self.guards.append(_HasattrGuard(node.args[0], name, self._negated))
            else:
                self.guards.append(_HasattrGuard(node.args[0], None, self._negated))
        self.generic_visit(node)


def _hasattr_guards(node: ast.AST) -> list[_HasattrGuard]:
    collector = _HasattrGuardCollector()
    collector.visit(node)
    return collector.guards


def _is_platform_name(node: ast.AST, platform_names: set[str]) -> bool:
    # An imported OS capability check is a platform boundary, not Steward
    # business-method discovery.
    return isinstance(node, ast.Name) and node.id in platform_names


def _platform_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    names.add(alias.asname or "os")
    return names


def _same_receiver(left: ast.AST, right: ast.AST) -> bool:
    return _expression_key(left) == _expression_key(right)


class _StaticDispatchVisitor(ast.NodeVisitor):
    def __init__(self, path: str, platform_names: set[str]) -> None:
        self.path = path
        self.platform_names = platform_names
        self.violations: set[_Violation] = set()
        self._getattr_bindings: list[set[str]] = [set()]

    def _add(self, node: ast.AST, kind: str) -> None:
        self.violations.add(_Violation(self.path, node.lineno, kind))  # type: ignore[attr-defined]

    def _is_getattr_bound(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._getattr_bindings))

    def _record_assignment(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        current = self._getattr_bindings[-1]
        current.discard(target.id)
        if _is_getattr_call(value):
            current.add(target.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._getattr_bindings.append(set())
        self.generic_visit(node)
        self._getattr_bindings.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._getattr_bindings.append(set())
        self.generic_visit(node)
        self._getattr_bindings.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._getattr_bindings.append(set())
        self.generic_visit(node)
        self._getattr_bindings.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            self._record_assignment(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._record_assignment(node.target, node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.generic_visit(node)
        self._record_assignment(node.target, node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        self.generic_visit(node)
        current = self._getattr_bindings[-1]
        for target in node.targets:
            if isinstance(target, ast.Name):
                current.discard(target.id)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Call) and _is_getattr_call(node.func):
            self._add(node, "direct-getattr-call")
        elif isinstance(node.func, ast.Name):
            if node.func.id == "callable":
                self._add(node, "callable-probe")
            elif self._is_getattr_bound(node.func.id):
                self._add(node, "getattr-alias-call")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guards = _hasattr_guards(node.test)
        for guard in guards:
            if _is_platform_name(guard.receiver, self.platform_names):
                continue
            region: ast.AST | list[ast.stmt]
            if guard.negated:
                region = node.orelse
            else:
                region = node.body
                for call in _calls_in(node.test):
                    self._check_hasattr_call(call, guard)
            for call in _calls_in(region):
                self._check_hasattr_call(call, guard)
        self.generic_visit(node)

    def _check_hasattr_call(self, node: ast.Call, guard: _HasattrGuard) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        if not _same_receiver(node.func.value, guard.receiver):
            return
        if guard.name is not None and node.func.attr != guard.name:
            return
        self._add(node, "hasattr-guarded-call")

    def visit_Try(self, node: ast.Try) -> None:
        attempted = _top_level_calls_in(node.body)
        for handler in node.handlers:
            if not _catches_type_error(handler.type):
                continue
            fallback = _calls_in(handler.body)
            for original in attempted:
                original_identity = _expression_key(original.func)
                original_shape = _argument_shape(original)
                for retry in fallback:
                    if (
                        _expression_key(retry.func) == original_identity
                        and _argument_shape(retry) != original_shape
                    ):
                        self._add(retry, "typeerror-signature-retry")
        self.generic_visit(node)


def _scan_tree(paths: list[Path]) -> tuple[str, ...]:
    violations: set[_Violation] = set()
    for path in sorted(paths):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        visitor = _StaticDispatchVisitor(relative, _platform_names(tree))
        visitor.visit(tree)
        violations.update(visitor.violations)
    return tuple(str(item) for item in sorted(violations))


def _scan_source(source: str, path: str = "snippet.py") -> tuple[str, ...]:
    tree = ast.parse(dedent(source), filename=path)
    visitor = _StaticDispatchVisitor(path, _platform_names(tree))
    visitor.visit(tree)
    return tuple(str(item) for item in sorted(visitor.violations))


def _tracked_source_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "steward/src/coquic_steward"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    )
    return [
        REPOSITORY_ROOT / value
        for value in result.stdout.decode().split("\0")
        if value.endswith(".py")
    ]


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        ("getattr(store, 'publish')()", "direct-getattr-call"),
        (
            "callback = getattr(store, 'on_change')\ncallback()",
            "getattr-alias-call",
        ),
        ("if callable(callback):\n    callback()", "callable-probe"),
        (
            "if hasattr(store, 'publish'):\n    store.publish()",
            "hasattr-guarded-call",
        ),
        (
            "try:\n    publisher.publish(generation)\nexcept TypeError:\n    publisher.publish()",
            "typeerror-signature-retry",
        ),
    ],
)
def test_rejects_prohibited_dispatch_forms(source: str, kind: str) -> None:
    violations = _scan_source(source)
    assert any(item.endswith(f" {kind}") for item in violations), violations
    assert all(item.startswith("snippet.py:") for item in violations)


def test_accepts_typed_calls_data_reflection_os_fallback_and_unrelated_exceptions() -> None:
    source = """
        import os

        store.publish(generation)
        if hasattr(value, name):
            selected = getattr(value, name)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            flags |= os.O_CLOEXEC
        try:
            value = first()
        except TypeError:
            value = second()
    """
    assert _scan_source(source) == ()


def test_scans_every_tracked_production_python_file_without_importing_it() -> None:
    assert _scan_tree(_tracked_source_paths()) == ()
