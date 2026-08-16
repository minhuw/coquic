from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass, field
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


@dataclass
class _ScopeFrame:
    kind: str
    parent: _ScopeFrame | None
    bindings: dict[str, frozenset[str]] = field(default_factory=dict)
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)


_GETATTR = "getattr"
_OS_MODULE = "os-module"
_BUILTINS_MODULE = "builtins-module"
_BUILTIN_CALLABLE = "builtin-callable"
_BUILTIN_GETATTR = "builtin-getattr"
_OTHER = "other"


def _is_named_call(node: ast.Call, name: str) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == name


def _expression_key(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _argument_shape(node: ast.Call) -> tuple[object, ...]:
    positional = tuple(
        "starred" if isinstance(argument, ast.Starred) else "positional"
        for argument in node.args
    )
    keywords = tuple(
        "**" if keyword.arg is None else keyword.arg for keyword in node.keywords
    )
    return (positional, keywords)


def _argument_fingerprint(
    node: ast.Call,
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    positional = tuple(
        (
            "starred",
            _expression_key(argument.value),
        )
        if isinstance(argument, ast.Starred)
        else ("positional", _expression_key(argument))
        for argument in node.args
    )
    keywords = tuple(
        (
            "**" if keyword.arg is None else keyword.arg,
            _expression_key(keyword.value),
        )
        for keyword in node.keywords
    )
    return positional, keywords


def _argument_descriptors(
    node: ast.Call,
) -> tuple[tuple[str, str | None, str], ...]:
    """Describe argument values while allowing positional/keyword conversion."""

    positional = tuple(
        (
            "starred",
            None,
            _expression_key(argument.value),
        )
        if isinstance(argument, ast.Starred)
        else ("positional", None, _expression_key(argument))
        for argument in node.args
    )
    keywords = tuple(
        (
            "double-starred",
            None,
            _expression_key(keyword.value),
        )
        if keyword.arg is None
        else ("keyword", keyword.arg, _expression_key(keyword.value))
        for keyword in node.keywords
    )
    return positional + keywords


def _arguments_have_same_values(left: ast.Call, right: ast.Call) -> bool:
    left_arguments = _argument_descriptors(left)
    right_arguments = _argument_descriptors(right)
    if len(left_arguments) != len(right_arguments):
        return False
    for (
        (left_kind, left_name, left_value),
        (right_kind, right_name, right_value),
    ) in zip(left_arguments, right_arguments):
        if left_value != right_value:
            return False
        if {left_kind, right_kind} & {"starred", "double-starred"}:
            if left_kind != right_kind:
                return False
        elif left_kind == right_kind == "keyword" and left_name != right_name:
            return False
    return True


def _is_strict_argument_subset(
    left: tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]],
    right: tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]],
) -> bool:
    """Match a fallback that removes arguments without changing retained ones."""

    left_positional, left_keywords = left
    right_positional, right_keywords = right
    if len(left_positional) > len(right_positional):
        return False
    if left_positional != right_positional[: len(left_positional)]:
        return False

    right_keyword_values = dict(right_keywords)
    for name, value in left_keywords:
        if right_keyword_values.get(name) != value:
            return False
    return (
        len(left_positional) < len(right_positional)
        or len(left_keywords) < len(right_keywords)
    )


def _arguments_are_compatible(
    left: ast.Call,
    right: ast.Call,
) -> bool:
    if _arguments_have_same_values(left, right):
        return True
    return _is_strict_argument_subset(
        _argument_fingerprint(left), _argument_fingerprint(right)
    ) or _is_strict_argument_subset(
        _argument_fingerprint(right), _argument_fingerprint(left)
    )


def _catches_type_error(node: ast.AST | None) -> bool:
    """Recognize handlers that include TypeError among their exceptions."""

    if isinstance(node, ast.Name):
        return node.id == "TypeError"
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_catches_type_error(item) for item in node.elts)
    return False


class _TypeErrorReraiseCollector(ast.NodeVisitor):
    def __init__(self, handler_name: str | None) -> None:
        self.handler_name = handler_name
        self.found = False

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc is None:
            self.found = True
        elif isinstance(node.exc, ast.Name) and node.exc.id == self.handler_name:
            self.found = True
        elif (
            isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "TypeError"
        ):
            self.found = True
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return


def _handler_rethrows_type_error(handler: ast.ExceptHandler) -> bool:
    collector = _TypeErrorReraiseCollector(handler.name)
    for statement in handler.body:
        collector.visit(statement)
    return collector.found


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_Try(self, _node: ast.Try) -> None:
        # A nested handler may consume TypeError before it can reach the
        # handler belonging to the try whose calls are being collected.
        return

    def visit_TryStar(self, _node: ast.TryStar) -> None:
        return

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return


class _TypeErrorEscapeCallCollector(_CallCollector):
    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        catches_type_error = any(
            _catches_type_error(handler.type) for handler in node.handlers
        )
        rethrows_type_error = any(
            _catches_type_error(handler.type)
            and _handler_rethrows_type_error(handler)
            for handler in node.handlers
        )
        if not catches_type_error or rethrows_type_error:
            for statement in node.body:
                self.visit(statement)
        for handler in node.handlers:
            if not _catches_type_error(handler.type):
                for statement in handler.body:
                    self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        for statement in node.finalbody:
            self.visit(statement)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)


def _calls_in(nodes: ast.AST | list[ast.stmt]) -> list[ast.Call]:
    collector = _CallCollector()
    if isinstance(nodes, list):
        for node in nodes:
            collector.visit(node)
    else:
        collector.visit(nodes)
    return collector.calls


def _calls_reaching_type_error_handler(
    nodes: ast.AST | list[ast.stmt],
) -> list[ast.Call]:
    collector = _TypeErrorEscapeCallCollector()
    if isinstance(nodes, list):
        for node in nodes:
            collector.visit(node)
    else:
        collector.visit(nodes)
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
            self.guards.append(_HasattrGuard(node.args[0], name, self._negated))
        self.generic_visit(node)


def _hasattr_guards(node: ast.AST) -> list[_HasattrGuard]:
    collector = _HasattrGuardCollector()
    collector.visit(node)
    return collector.guards


def _same_receiver(left: ast.AST, right: ast.AST) -> bool:
    return _expression_key(left) == _expression_key(right)


def _block_all_paths_exit(statements: list[ast.stmt]) -> bool:
    """Return whether every path through a statement block terminates."""

    for statement in statements:
        if _statement_all_paths_exit(statement):
            return True
    return False


def _statement_all_paths_exit(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(statement, ast.If):
        return bool(statement.orelse) and _block_all_paths_exit(
            statement.body
        ) and _block_all_paths_exit(statement.orelse)
    if isinstance(statement, (ast.Try, ast.TryStar)):
        if statement.finalbody and _block_all_paths_exit(statement.finalbody):
            return True
        if not _block_all_paths_exit(statement.body):
            return False
        return all(_block_all_paths_exit(handler.body) for handler in statement.handlers)
    return False


class _LocalBindingCollector(ast.NodeVisitor):
    """Collect names local to one function without descending into child scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.names.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)


class _StaticDispatchVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.violations: set[_Violation] = set()
        self._module = _ScopeFrame("module", None)
        self._scopes: list[_ScopeFrame] = [self._module]
        self._block_stack: list[tuple[list[ast.stmt], int]] = []

    @property
    def _scope(self) -> _ScopeFrame:
        return self._scopes[-1]

    def _add(self, node: ast.AST, kind: str) -> None:
        self.violations.add(_Violation(self.path, node.lineno, kind))  # type: ignore[attr-defined]

    def _lookup(self, name: str) -> frozenset[str] | None:
        frame: _ScopeFrame | None = self._scope
        while frame is not None:
            state = frame.bindings.get(name)
            if state is not None:
                return state
            frame = frame.parent
        return None

    def _assignment_scope(self, name: str) -> _ScopeFrame:
        frame = self._scope
        if name in frame.global_names:
            return self._module
        if name in frame.nonlocal_names:
            parent = frame.parent
            while parent is not None and parent.kind == "class":
                parent = parent.parent
            return parent if parent is not None else frame
        return frame

    def _bind(self, name: str, *kinds: str) -> None:
        self._assignment_scope(name).bindings[name] = frozenset(kinds)

    def _delete(self, name: str) -> None:
        frame = self._assignment_scope(name)
        if frame is self._module:
            frame.bindings.pop(name, None)
        else:
            # A deleted local still shadows an outer binding for the rest of
            # the function, even though using it would raise at runtime.
            frame.bindings[name] = frozenset({_OTHER})

    def _snapshot(self) -> list[tuple[_ScopeFrame, dict[str, frozenset[str]]]]:
        return [(frame, dict(frame.bindings)) for frame in self._scopes]

    @staticmethod
    def _merge_snapshots(
        *snapshots: list[tuple[_ScopeFrame, dict[str, frozenset[str]]]],
    ) -> list[tuple[_ScopeFrame, dict[str, frozenset[str]]]]:
        if not snapshots:
            return []
        merged: list[tuple[_ScopeFrame, dict[str, frozenset[str]]]] = []
        for index, (frame, _) in enumerate(snapshots[0]):
            keys: set[str] = set()
            for snapshot in snapshots:
                keys.update(snapshot[index][1])
            state: dict[str, frozenset[str]] = {}
            for key in keys:
                kinds: set[str] = set()
                for snapshot in snapshots:
                    kinds.update(snapshot[index][1].get(key, ()))
                state[key] = frozenset(kinds)
            merged.append((frame, state))
        return merged

    @staticmethod
    def _restore(snapshot: list[tuple[_ScopeFrame, dict[str, frozenset[str]]]]) -> None:
        for frame, bindings in snapshot:
            frame.bindings.clear()
            frame.bindings.update(bindings)

    def _visit_block(self, statements: list[ast.stmt]) -> None:
        for index, statement in enumerate(statements):
            self._block_stack.append((statements, index))
            self.visit(statement)
            self._block_stack.pop()

    def _is_builtin_function(self, node: ast.AST, name: str) -> bool:
        if isinstance(node, ast.Name):
            state = self._lookup(node.id)
            if node.id != name:
                return False
            if state is None:
                return True
            expected = {
                "callable": _BUILTIN_CALLABLE,
                "getattr": _BUILTIN_GETATTR,
                "hasattr": "builtin-hasattr",
            }[name]
            return expected in state
        if not isinstance(node, ast.Attribute) or node.attr != name:
            return False
        if not isinstance(node.value, ast.Name):
            return False
        state = self._lookup(node.value.id)
        return state is not None and _BUILTINS_MODULE in state

    def _is_getattr_expression(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Call) and self._is_builtin_function(node.func, "getattr")

    def _binding_for_value(self, value: ast.AST) -> frozenset[str]:
        if self._is_getattr_expression(value):
            return frozenset({_GETATTR})
        if isinstance(value, ast.Name):
            state = self._lookup(value.id)
            if state is not None and _GETATTR in state:
                return state
        if isinstance(value, ast.IfExp):
            return self._binding_for_value(value.body) | self._binding_for_value(value.orelse)
        if isinstance(value, ast.BoolOp):
            kinds: set[str] = set()
            for item in value.values:
                kinds.update(self._binding_for_value(item))
            return frozenset(kinds or {_OTHER})
        return frozenset({_OTHER})

    def _assign_target(self, target: ast.AST, state: frozenset[str]) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, *state)
            return
        if isinstance(target, ast.Starred):
            self._assign_target(target.value, frozenset({_OTHER}))
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_target(item, frozenset({_OTHER}))
            return
        self.visit(target)

    def _assign_value(self, target: ast.AST, value: ast.AST) -> None:
        self._assign_target(target, self._binding_for_value(value))

    def _is_platform_receiver(self, receiver: ast.AST) -> bool:
        if not isinstance(receiver, ast.Name):
            return False
        state = self._lookup(receiver.id)
        return state == frozenset({_OS_MODULE})

    def _check_hasattr_call(self, node: ast.Call, guard: _HasattrGuard) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        if not _same_receiver(node.func.value, guard.receiver):
            return
        if guard.name is not None and node.func.attr != guard.name:
            return
        self._add(node, "hasattr-guarded-call")

    def _check_hasattr_region(
        self,
        region: ast.AST | list[ast.stmt],
        guard: _HasattrGuard,
    ) -> None:
        for call in _calls_in(region):
            self._check_hasattr_call(call, guard)

    def _check_hasattr_guards(
        self,
        node: ast.If,
        guards: list[_HasattrGuard],
    ) -> None:
        following = (
            self._block_stack[-1][0][self._block_stack[-1][1] + 1 :]
            if self._block_stack
            else []
        )
        for guard in guards:
            if self._is_platform_receiver(guard.receiver):
                continue
            if guard.negated:
                # The negative branch is the one where the attribute is
                # absent.  Its else branch is successful, and a following
                # statement is also dominated when the negative branch exits.
                self._check_hasattr_region(node.orelse, guard)
                if _block_all_paths_exit(node.body):
                    self._check_hasattr_region(following, guard)
            else:
                self._check_hasattr_region(node.body, guard)
                self._check_hasattr_region(node.test, guard)

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_block(node.body)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self._check_hasattr_guards(node, _hasattr_guards(node.test))
        baseline = self._snapshot()

        self._visit_block(node.body)
        body_state = self._snapshot()
        self._restore(baseline)
        self._visit_block(node.orelse)
        else_state = self._snapshot()
        self._restore(self._merge_snapshots(body_state, else_state))

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        baseline = self._snapshot()
        self._assign_target(node.target, frozenset({_OTHER}))
        self._visit_block(node.body)
        body_state = self._snapshot()
        self._restore(baseline)
        self._visit_block(node.orelse)
        else_state = self._snapshot()
        self._restore(self._merge_snapshots(body_state, else_state))

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit(node.iter)
        baseline = self._snapshot()
        self._assign_target(node.target, frozenset({_OTHER}))
        self._visit_block(node.body)
        body_state = self._snapshot()
        self._restore(baseline)
        self._visit_block(node.orelse)
        else_state = self._snapshot()
        self._restore(self._merge_snapshots(body_state, else_state))

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        baseline = self._snapshot()
        self._visit_block(node.body)
        body_state = self._snapshot()
        self._restore(baseline)
        self._visit_block(node.orelse)
        else_state = self._snapshot()
        self._restore(self._merge_snapshots(body_state, else_state))

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(item.optional_vars, frozenset({_OTHER}))
        self._visit_block(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(item.optional_vars, frozenset({_OTHER}))
        self._visit_block(node.body)

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        attempted = _calls_reaching_type_error_handler(node.body)
        for handler in node.handlers:
            if not _catches_type_error(handler.type):
                continue
            for retry in _calls_in(handler.body):
                for original in attempted:
                    if (
                        _expression_key(retry.func) == _expression_key(original.func)
                        and _argument_shape(retry) != _argument_shape(original)
                        and _arguments_are_compatible(retry, original)
                    ):
                        self._add(retry, "typeerror-signature-retry")

        baseline = self._snapshot()
        self._visit_block(node.body)
        branch_states = [self._snapshot()]
        for handler in node.handlers:
            self._restore(baseline)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name is not None:
                self._bind(handler.name, _OTHER)
            self._visit_block(handler.body)
            branch_states.append(self._snapshot())

        self._restore(branch_states[0])
        self._visit_block(node.orelse)
        branch_states.append(self._snapshot())
        self._restore(self._merge_snapshots(*branch_states))
        self._visit_block(node.finalbody)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        baseline = self._snapshot()
        states: list[list[tuple[_ScopeFrame, dict[str, frozenset[str]]]]] = []
        for case in node.cases:
            self._restore(baseline)
            if case.guard is not None:
                self.visit(case.guard)
            self._visit_block(case.body)
            states.append(self._snapshot())
        states.append(baseline)
        self._restore(self._merge_snapshots(*states))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_definition(node)

    def _visit_function_definition(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_arguments(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        self._bind(node.name, _OTHER)
        collector = _LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)
        parameters = _argument_names(node.args)
        local_names = (collector.names | parameters) - collector.global_names - collector.nonlocal_names
        parent = self._scope.parent if self._scope.kind == "class" else self._scope
        frame = _ScopeFrame(
            "function",
            parent,
            {name: frozenset({_OTHER}) for name in local_names},
            set(collector.global_names),
            set(collector.nonlocal_names),
        )
        self._scopes.append(frame)
        self._visit_block(node.body)
        self._scopes.pop()

    def _visit_arguments(self, arguments: ast.arguments) -> None:
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ):
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self.visit(arguments.kwarg.annotation)
        for default in (*arguments.defaults, *(item for item in arguments.kw_defaults if item is not None)):
            self.visit(default)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_arguments(node.args)
        collector = _LocalBindingCollector()
        collector.visit(node.body)
        parameters = _argument_names(node.args)
        local_names = (collector.names | parameters) - collector.global_names - collector.nonlocal_names
        parent = self._scope.parent if self._scope.kind == "class" else self._scope
        frame = _ScopeFrame(
            "function",
            parent,
            {name: frozenset({_OTHER}) for name in local_names},
            set(collector.global_names),
            set(collector.nonlocal_names),
        )
        self._scopes.append(frame)
        self.visit(node.body)
        self._scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind(node.name, _OTHER)
        frame = _ScopeFrame("class", self._scope)
        self._scopes.append(frame)
        self._visit_block(node.body)
        self._scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        state = self._binding_for_value(node.value)
        for target in node.targets:
            self._assign_target(target, state)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._assign_value(node.target, node.value)
        else:
            self._assign_target(node.target, frozenset({_OTHER}))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._assign_target(node.target, frozenset({_OTHER}))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._assign_value(node.target, node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._delete(target.id)
            else:
                self.visit(target)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name == "os" or alias.name.startswith("os."):
                self._bind(name, _OS_MODULE)
            elif alias.name == "builtins" or alias.name.startswith("builtins."):
                self._bind(name, _BUILTINS_MODULE)
            else:
                self._bind(name, _OTHER)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            if node.module == "builtins" and alias.name == "callable":
                self._bind(name, _BUILTIN_CALLABLE)
            elif node.module == "builtins" and alias.name == "getattr":
                self._bind(name, _BUILTIN_GETATTR)
            else:
                self._bind(name, _OTHER)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Call) and self._is_getattr_expression(node.func):
            self._add(node, "direct-getattr-call")
        elif self._is_builtin_function(node.func, "callable"):
            self._add(node, "callable-probe")
        elif isinstance(node.func, ast.Name):
            state = self._lookup(node.func.id)
            if state is not None and _GETATTR in state:
                self._add(node, "getattr-alias-call")
        self.generic_visit(node)


def _argument_names(arguments: ast.arguments) -> set[str]:
    names = {
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        )
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return names


def _scan_tree(paths: list[Path]) -> tuple[str, ...]:
    violations: set[_Violation] = set()
    for path in sorted(paths):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        visitor = _StaticDispatchVisitor(relative)
        visitor.visit(tree)
        violations.update(visitor.violations)
    return tuple(str(item) for item in sorted(violations))


def _scan_source(source: str, path: str = "snippet.py") -> tuple[str, ...]:
    tree = ast.parse(dedent(source), filename=path)
    visitor = _StaticDispatchVisitor(path)
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


def test_merges_aliases_and_respects_lexical_parameter_shadowing() -> None:
    dynamic = """
        callback = getattr(store, "publish")
        if use_typed:
            callback = store.publish
        callback()
    """
    assert any(
        item.endswith(" getattr-alias-call") for item in _scan_source(dynamic)
    )

    shadowed = """
        callback = getattr(store, "publish")
        def invoke(callback):
            callback()
    """
    assert _scan_source(shadowed) == ()


def test_collects_typeerror_attempts_inside_control_flow() -> None:
    source = """
        try:
            if ready:
                publisher.publish(generation)
        except TypeError:
            publisher.publish()
    """
    assert any(
        item.endswith(" typeerror-signature-retry") for item in _scan_source(source)
    )


def test_detects_typeerror_in_mixed_exception_handler() -> None:
    source = """
        try:
            publisher.publish(generation)
        except (TypeError, ValueError):
            publisher.publish()
    """
    assert any(
        item.endswith(" typeerror-signature-retry") for item in _scan_source(source)
    )


def test_collects_typeerror_attempts_through_nested_nonmatching_handler() -> None:
    source = """
        try:
            try:
                publisher.publish(generation)
            except ValueError:
                other()
        except TypeError:
            publisher.publish()
    """
    assert any(
        item.endswith(" typeerror-signature-retry") for item in _scan_source(source)
    )


def test_detects_positional_to_keyword_signature_retry() -> None:
    source = """
        try:
            publisher.publish(generation)
        except TypeError:
            publisher.publish(generation=generation)
    """
    assert any(
        item.endswith(" typeerror-signature-retry") for item in _scan_source(source)
    )

    unrelated = """
        try:
            publisher.publish(generation)
        except TypeError:
            publisher.publish(generation=other)
    """
    assert _scan_source(unrelated) == ()


def test_does_not_cross_nested_exception_boundaries() -> None:
    source = """
        try:
            try:
                publisher.publish(generation)
            except TypeError:
                other()
        except TypeError:
            publisher.publish()
    """
    assert _scan_source(source) == ()


def test_follows_a_successful_negative_hasattr_guard_after_early_exit() -> None:
    source = """
        def invoke():
            if not hasattr(store, "publish"):
                return
            store.publish()
    """
    assert any(
        item.endswith(" hasattr-guarded-call") for item in _scan_source(source)
    )


def test_resolves_platform_and_builtin_bindings_lexically() -> None:
    platform_shadow = """
        import os
        def invoke(os):
            if hasattr(os, "publish"):
                os.publish()
    """
    assert any(
        item.endswith(" hasattr-guarded-call")
        for item in _scan_source(platform_shadow)
    )

    qualified_builtin = """
        import builtins
        if builtins.callable(callback):
            callback()
    """
    assert any(
        item.endswith(" callable-probe") for item in _scan_source(qualified_builtin)
    )


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
