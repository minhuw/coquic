"""Private, evidence-only capture for Codex tool lifecycle hooks.

The hook command is intentionally small and defensive.  It accepts a single
Codex hook envelope on stdin, records data under the context directory passed
by Steward, and always exits successfully.  A hook must never be able to
change the Codex decision or process outcome.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess  # nosec B404 - all invocations use an argv list
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 1
MAX_COMPLETED_RECORDS = 4096
MAX_TOOL_INPUT_BYTES = 1024 * 1024
MAX_TOOL_RESPONSE_BYTES = 1024 * 1024
MAX_HOOK_ENVELOPE_BYTES = MAX_TOOL_INPUT_BYTES + MAX_TOOL_RESPONSE_BYTES + 64 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
SUPPORTED_TOOLS = frozenset({"Bash", "apply_patch"})
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:_\-]{0,127}\Z")
TREE_RE = re.compile(r"[0-9a-f]{40,64}\Z")
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
LOCK_TIMEOUT_SECONDS = 0.05

_ERROR_CATEGORIES = frozenset(
    {
        "context_unavailable",
        "invalid_envelope",
        "unsafe_identity",
        "wrong_context",
        "unsupported_tool",
        "oversized_input",
        "oversized_response",
        "snapshot_failed",
        "lock_failed",
        "clock_failed",
        "write_failed",
        "duplicate_tool_use",
        "missing_pre",
        "missing_post",
        "replay_mismatch",
        "external_mutation",
        "gap_detected",
        "overlap_detected",
        "hook_not_observed",
        "record_limit",
        "final_patch_mismatch",
        "cleanup_failed",
        "tool_failed",
    }
)


def _require_private_file(path: Path) -> None:
    try:
        info = path.stat()
    except (OSError, ValueError):
        raise _CaptureFailure("context_unavailable")
    if path.is_symlink() or info.st_uid != os.getuid():
        raise _CaptureFailure("context_unavailable")
    if stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE:
        raise _CaptureFailure("context_unavailable")


def _require_private_directory(path: Path) -> None:
    try:
        info = path.stat()
    except (OSError, ValueError):
        raise _CaptureFailure("context_unavailable")
    if path.is_symlink() or info.st_uid != os.getuid():
        raise _CaptureFailure("context_unavailable")
    if stat.S_IMODE(info.st_mode) != PRIVATE_DIR_MODE:
        raise _CaptureFailure("context_unavailable")


def _contains_symlink(path: Path) -> bool:
    current = path
    try:
        while current != current.parent:
            if current.is_symlink():
                return True
            current = current.parent
    except OSError:
        return True
    return False


class _CaptureFailure(Exception):
    """Internal category-only failure; its text is never written to artifacts."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category if category in _ERROR_CATEGORIES else "write_failed"


@dataclass(frozen=True)
class HookSummary:
    schema_version: int
    state: str
    discovered: int
    captured: int
    empty: int
    failed: int
    incomplete: int
    gaps: int
    overlaps: int
    omitted: int
    reasons: tuple[str, ...]
    run_start_tree: str | None
    final_tree: str | None
    replayed_tree: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state": self.state,
            "completeness": self.state,
            "discovered": self.discovered,
            "captured": self.captured,
            "empty": self.empty,
            "failed": self.failed,
            "incomplete": self.incomplete,
            "gaps": self.gaps,
            "overlaps": self.overlaps,
            "omitted": self.omitted,
            "reasons": list(self.reasons),
            "reason_categories": list(self.reasons),
            "run_start_tree": self.run_start_tree,
            "final_tree": self.final_tree,
            "replayed_tree": self.replayed_tree,
            "run_start_tree_id": self.run_start_tree,
            "final_tree_id": self.final_tree,
            "replayed_tree_id": self.replayed_tree,
        }

    def diagnostics_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state": self.state,
            "completeness": self.state,
            "discovered": self.discovered,
            "captured": self.captured,
            "empty": self.empty,
            "failed": self.failed,
            "incomplete": self.incomplete,
            "gaps": self.gaps,
            "overlaps": self.overlaps,
            "omitted": self.omitted,
            "reasons": list(self.reasons),
            "reason_categories": list(self.reasons),
        }


@dataclass(frozen=True)
class _Envelope:
    event: str
    session_id: str
    turn_id: str
    cwd: Path
    tool_name: str
    tool_use_id: str
    tool_input: Any
    tool_response: Any | None
    raw_input_bytes: bytes
    raw_response_bytes: bytes | None


def _utc_now() -> str:
    try:
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")
    except (OSError, RuntimeError, OverflowError, TypeError, ValueError):
        raise _CaptureFailure("clock_failed")


def _monotonic_ns() -> int:
    try:
        return int(time.monotonic_ns())
    except (OSError, OverflowError, RuntimeError, TypeError, ValueError):
        raise _CaptureFailure("clock_failed")


def _safe_id(value: object) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise _CaptureFailure("unsafe_identity")
    return value


def _bounded_json_bytes(value: Any, limit: int, category: str) -> bytes:
    try:
        data = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise _CaptureFailure("invalid_envelope")
    if len(data) > limit:
        raise _CaptureFailure(category)
    return data


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _parse_envelope(raw: bytes, expected_event: str | None = None) -> _Envelope:
    if len(raw) > MAX_HOOK_ENVELOPE_BYTES:
        raise _CaptureFailure("invalid_envelope")
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _CaptureFailure("invalid_envelope")
    if not isinstance(value, dict):
        raise _CaptureFailure("invalid_envelope")
    event = value.get("hook_event_name")
    if not isinstance(event, str) or event not in {"PreToolUse", "PostToolUse"}:
        raise _CaptureFailure("invalid_envelope")
    if expected_event is not None and event != expected_event:
        raise _CaptureFailure("invalid_envelope")
    session_id = _safe_id(value.get("session_id"))
    turn_id = _safe_id(value.get("turn_id"))
    tool_use_id = _safe_id(value.get("tool_use_id"))
    cwd_value = value.get("cwd")
    if not isinstance(cwd_value, str) or not cwd_value or "\x00" in cwd_value:
        raise _CaptureFailure("wrong_context")
    cwd = Path(cwd_value)
    tool_name = value.get("tool_name")
    if not isinstance(tool_name, str) or tool_name not in SUPPORTED_TOOLS:
        raise _CaptureFailure("unsupported_tool")
    if "tool_input" not in value:
        raise _CaptureFailure("invalid_envelope")
    tool_input = value["tool_input"]
    input_bytes = _bounded_json_bytes(tool_input, MAX_TOOL_INPUT_BYTES, "oversized_input")
    response = None
    response_bytes = None
    if event == "PostToolUse":
        if "tool_response" not in value:
            raise _CaptureFailure("invalid_envelope")
        response = value["tool_response"]
        response_bytes = _bounded_json_bytes(
            response, MAX_TOOL_RESPONSE_BYTES, "oversized_response"
        )
    return _Envelope(
        event=event,
        session_id=session_id,
        turn_id=turn_id,
        cwd=cwd,
        tool_name=tool_name,
        tool_use_id=tool_use_id,
        tool_input=tool_input,
        tool_response=response,
        raw_input_bytes=input_bytes,
        raw_response_bytes=response_bytes,
    )


parse_hook_envelope = _parse_envelope


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    handle = None
    acquired = False
    try:
        path.parent.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        handle = path.open("a+b")
        os.chmod(path, PRIVATE_FILE_MODE)
        try:
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        except (OSError, RuntimeError, OverflowError, ValueError):
            raise _CaptureFailure("clock_failed")
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (BlockingIOError, OSError) as exc:
                if (
                    not isinstance(exc, BlockingIOError)
                    and getattr(exc, "errno", None) not in {11, 13}
                ):
                    raise _CaptureFailure("lock_failed")
                try:
                    expired = time.monotonic() >= deadline
                except (OSError, RuntimeError, OverflowError, ValueError):
                    raise _CaptureFailure("clock_failed")
                if expired:
                    raise _CaptureFailure("lock_failed")
                time.sleep(0.001)
        yield
    except _CaptureFailure:
        raise
    except (OSError, ValueError):
        raise _CaptureFailure("lock_failed")
    finally:
        if handle is not None:
            if acquired:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            handle.close()


def _atomic_write(path: Path, data: bytes, *, mode: int = PRIVATE_FILE_MODE) -> None:
    temporary: Path | None = None
    try:
        path.parent.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        os.chmod(path.parent, PRIVATE_DIR_MODE)
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".capture-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except (OSError, TypeError):
        raise _CaptureFailure("write_failed")
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        existing = path.read_bytes() if path.exists() else b""
        if len(existing) > MAX_MANIFEST_BYTES:
            raise _CaptureFailure("record_limit")
        line = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        data = existing + line.encode("utf-8")
        if len(data) > MAX_MANIFEST_BYTES:
            raise _CaptureFailure("record_limit")
        _atomic_write(path, data)
    except _CaptureFailure:
        raise
    except (OSError, UnicodeError, TypeError, ValueError):
        raise _CaptureFailure("write_failed")


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _GitSnapshot:
    """Snapshot a repository into an isolated index and object directory."""

    def __init__(self, cwd: Path, root: Path, *, object_directory: Path | None = None):
        self.cwd = cwd.resolve(strict=True)
        self.root = root
        self.object_directory = object_directory
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.env: dict[str, str] = {}
        self.repo_root: Path | None = None
        self._start()

    def _run(self, args: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(  # nosec B603
                ["git", *args],
                cwd=self.cwd,
                env={**os.environ, **self.env},
                shell=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except (OSError, ValueError):
            raise _CaptureFailure("snapshot_failed")
        if check and result.returncode != 0:
            raise _CaptureFailure("snapshot_failed")
        return result

    def _start(self) -> None:
        root = self._run(["rev-parse", "--show-toplevel"])
        objects = self._run(["rev-parse", "--git-path", "objects"])
        if root.returncode or objects.returncode:
            raise _CaptureFailure("snapshot_failed")
        try:
            self.repo_root = Path(root.stdout.strip()).resolve(strict=True)
            object_path = Path(objects.stdout.strip())
            if not object_path.is_absolute():
                object_path = (self.cwd / object_path).resolve(strict=True)
            self.temp = tempfile.TemporaryDirectory(prefix=".tool-changes-", dir=str(self.root))
            temp_root = Path(self.temp.name)
            if self.object_directory is None:
                temp_objects = temp_root / "objects"
                temp_objects.mkdir(mode=PRIVATE_DIR_MODE)
            else:
                temp_objects = self.object_directory
                temp_objects.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
                os.chmod(temp_objects, PRIVATE_DIR_MODE)
            self.env = {
                "GIT_INDEX_FILE": str(temp_root / "index"),
                "GIT_OBJECT_DIRECTORY": str(temp_objects),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(object_path),
            }
        except (OSError, RuntimeError, ValueError):
            raise _CaptureFailure("snapshot_failed")

    def close(self) -> None:
        if self.temp is not None:
            try:
                self.temp.cleanup()
            except OSError:
                pass
            self.temp = None
        if self.object_directory is not None:
            try:
                for directory in self.object_directory.rglob("*"):
                    if directory.is_dir():
                        os.chmod(directory, PRIVATE_DIR_MODE)
                    elif directory.is_file():
                        os.chmod(directory, PRIVATE_FILE_MODE)
                os.chmod(self.object_directory, PRIVATE_DIR_MODE)
            except OSError:
                # Object cleanup/permission hardening is evidence-only.
                pass

    def tree(self) -> str:
        self._run(["read-tree", "HEAD"], check=True)
        self._run(["add", "-A", "--", "."], check=True)
        result = self._run(["write-tree"], check=True)
        value = result.stdout.strip()
        if not TREE_RE.fullmatch(value):
            raise _CaptureFailure("snapshot_failed")
        return value

    def head_tree(self) -> str:
        result = self._run(["rev-parse", "HEAD^{tree}"], check=True)
        value = result.stdout.strip()
        if not TREE_RE.fullmatch(value):
            raise _CaptureFailure("snapshot_failed")
        return value

    def diff(self, base: str, result: str) -> tuple[bytes, list[str]]:
        if not TREE_RE.fullmatch(base) or not TREE_RE.fullmatch(result):
            raise _CaptureFailure("snapshot_failed")
        patch = self._run(
            ["diff-tree", "--binary", "--full-index", "--no-commit-id", "-r", base, result, "--"],
            check=True,
        ).stdout.encode("utf-8")
        status = self._run(
            ["diff-tree", "--name-status", "-z", "--no-commit-id", "-r", base, result, "--"],
            check=True,
        ).stdout
        parts = status.split("\0")
        paths: list[str] = []
        index = 0
        while index < len(parts):
            marker = parts[index]
            index += 1
            if not marker:
                continue
            count = 2 if marker[:1] in {"R", "C"} else 1
            if index + count > len(parts):
                raise _CaptureFailure("snapshot_failed")
            for raw in parts[index : index + count]:
                paths.append(self._relative(raw))
            index += count
        return patch, sorted(set(paths))

    def _relative(self, raw: str) -> str:
        if not raw or "\x00" in raw or self.repo_root is None:
            raise _CaptureFailure("unsafe_identity")
        path = Path(raw)
        if path.is_absolute():
            try:
                path = path.resolve(strict=False).relative_to(self.repo_root)
            except (OSError, RuntimeError, ValueError):
                raise _CaptureFailure("unsafe_identity")
        value = path.as_posix()
        if not value or value == "." or value.startswith("../") or "/../" in value:
            raise _CaptureFailure("unsafe_identity")
        return value


class ToolChangeCapture:
    """Cross-process context for paired Codex ``PreToolUse``/``PostToolUse``."""

    def __init__(self, cwd: Path, run_dir: Path, context_path: Path):
        self.cwd = Path(cwd).resolve(strict=True)
        self.run_dir = Path(run_dir).resolve(strict=False)
        self.context_path = Path(context_path).resolve(strict=False)
        self.manifest_path = self.run_dir / "manifest.jsonl"
        self.summary_path = self.run_dir / "summary.json"
        self.lock_path = self.run_dir / ".lock"
        self.pending_path = self.run_dir / "pending.json"
        self.state_path = self.run_dir / "state.json"
        self.degradation_path = self.run_dir / ".degraded"
        self.input_dir = self.run_dir / "inputs"
        self.response_dir = self.run_dir / "responses"
        self.patch_dir = self.run_dir / "patches"
        self.object_dir = self.run_dir / ".objects"
        self._closed = False

    @classmethod
    def start(cls, cwd: Path, run_dir: Path, *, session_id: str | None = None, turn_id: str | None = None) -> "ToolChangeCapture":
        run_dir = Path(run_dir)
        try:
            run_dir.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
            os.chmod(run_dir, PRIVATE_DIR_MODE)
        except (OSError, ValueError):
            return cls.unavailable(cwd, run_dir)
        context_path = run_dir / "context.json"
        instance = cls(cwd, run_dir, context_path)
        try:
            snapshot = _GitSnapshot(
                instance.cwd, instance.run_dir, object_directory=instance.object_dir
            )
            try:
                start_tree = snapshot.tree()
            finally:
                snapshot.close()
            now_mono = _monotonic_ns()
            state = {
                "schema_version": SCHEMA_VERSION,
                "cwd": str(instance.cwd),
                "session_id": session_id,
                "turn_id": turn_id,
                "run_start_tree": start_tree,
                "last_tree": start_tree,
                "next_start_sequence": 0,
                "next_completion_sequence": 0,
                "discovered": 0,
                "captured": 0,
                "empty": 0,
                "failed": 0,
                "incomplete": 0,
                "gaps": 0,
                "overlaps": 0,
                "omitted": 0,
                "reasons": [],
                "pending": {},
                "completed_tool_use_ids": [],
                "start_mono_ns": now_mono,
                "start_utc": _utc_now(),
                "finalized": False,
                "final_tree": None,
                "replayed_tree": None,
            }
            with _file_lock(instance.lock_path):
                _atomic_write(instance.state_path, _json_bytes(state))
                _atomic_write(
                    instance.context_path,
                    _json_bytes(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "context": str(instance.context_path),
                            "cwd": str(instance.cwd),
                            "session_id": session_id,
                            "turn_id": turn_id,
                        }
                    ),
                )
                _atomic_write(instance.pending_path, _json_bytes({}))
        except _CaptureFailure as exc:
            instance._record_reason(exc.category)
            instance._write_unavailable_summary(exc.category)
        except Exception:
            instance._record_reason("context_unavailable")
            instance._write_unavailable_summary("context_unavailable")
        return instance

    @classmethod
    def unavailable(cls, cwd: Path, run_dir: Path) -> "ToolChangeCapture":
        """Return a no-write context used when startup itself is unavailable."""
        run_dir = Path(run_dir)
        try:
            resolved_cwd = Path(cwd).resolve(strict=False)
            resolved_run_dir = run_dir.resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            resolved_cwd = Path(cwd)
            resolved_run_dir = run_dir
        instance = cls.__new__(cls)
        instance.cwd = resolved_cwd
        instance.run_dir = resolved_run_dir
        instance.context_path = resolved_run_dir / "context.json"
        instance.manifest_path = resolved_run_dir / "manifest.jsonl"
        instance.summary_path = resolved_run_dir / "summary.json"
        instance.lock_path = resolved_run_dir / ".lock"
        instance.pending_path = resolved_run_dir / "pending.json"
        instance.state_path = resolved_run_dir / "state.json"
        instance.degradation_path = resolved_run_dir / ".degraded"
        instance.input_dir = resolved_run_dir / "inputs"
        instance.response_dir = resolved_run_dir / "responses"
        instance.patch_dir = resolved_run_dir / "patches"
        instance.object_dir = resolved_run_dir / ".objects"
        instance._closed = False
        instance._write_unavailable_summary("context_unavailable")
        return instance

    @classmethod
    def from_context(cls, context_path: Path) -> "ToolChangeCapture":
        candidate = Path(context_path)
        try:
            if not candidate.is_absolute():
                raise _CaptureFailure("context_unavailable")
            if ".." in candidate.parts:
                raise _CaptureFailure("context_unavailable")
            if _contains_symlink(candidate):
                raise _CaptureFailure("context_unavailable")
        except OSError:
            raise _CaptureFailure("context_unavailable")
        path = candidate.resolve(strict=False)
        if not path.name == "context.json":
            raise _CaptureFailure("context_unavailable")
        try:
            _require_private_file(path)
            _require_private_directory(path.parent)
            context = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(context, dict) or context.get("schema_version") != SCHEMA_VERSION:
                raise _CaptureFailure("context_unavailable")
            if context.get("context") != str(path):
                raise _CaptureFailure("context_unavailable")
            cwd = context.get("cwd")
            if not isinstance(cwd, str):
                raise _CaptureFailure("context_unavailable")
        except _CaptureFailure:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise _CaptureFailure("context_unavailable")
        return cls(Path(cwd), path.parent, path)

    def _record_reason(self, reason: str) -> None:
        if reason not in _ERROR_CATEGORIES:
            reason = "write_failed"
        try:
            with _file_lock(self.lock_path):
                state = self._load_state()
                reasons = list(state.get("reasons", []))
                if reason not in reasons:
                    reasons.append(reason)
                state["reasons"] = reasons[:32]
                _atomic_write(self.state_path, _json_bytes(state))
        except _CaptureFailure as exc:
            self._write_degradation(exc.category)
        except Exception:
            self._write_degradation(reason)

    def _write_degradation(self, reason: str) -> None:
        if reason not in _ERROR_CATEGORIES:
            reason = "write_failed"
        try:
            _atomic_write(self.degradation_path, _json_bytes({"reason": reason}))
        except Exception:
            pass

    def _consume_degradation(self, state: dict[str, Any]) -> None:
        try:
            value = json.loads(self.degradation_path.read_text(encoding="utf-8"))
            reason = value.get("reason") if isinstance(value, dict) else None
            if isinstance(reason, str):
                state["reasons"] = _append_reason(state, reason)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return

    def _load_state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise _CaptureFailure("context_unavailable")
        if not isinstance(value, dict):
            raise _CaptureFailure("context_unavailable")
        return value

    def _write_unavailable_summary(self, reason: str) -> None:
        summary = HookSummary(
            SCHEMA_VERSION,
            "unavailable",
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (reason,),
            None,
            None,
            None,
        )
        try:
            self.run_dir.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
            _atomic_write(self.summary_path, _json_bytes(summary.as_dict()))
        except Exception:
            pass

    def _validate_context(self, envelope: _Envelope, state: dict[str, Any]) -> None:
        if envelope.cwd.resolve(strict=False) != self.cwd:
            raise _CaptureFailure("wrong_context")
        expected_session = state.get("session_id")
        expected_turn = state.get("turn_id")
        if expected_session is not None and envelope.session_id != expected_session:
            raise _CaptureFailure("wrong_context")
        if expected_turn is not None and envelope.turn_id != expected_turn:
            raise _CaptureFailure("wrong_context")

    def _persist_behavior(self, directory: Path, sequence: int, tool_id: str, data: bytes) -> dict[str, Any]:
        # The file name contains only validated identity values.  The payload is
        # private and is never copied to public diagnostics.
        name = f"{sequence}-{tool_id}.json"
        path = directory / name
        _atomic_write(path, data)
        return {
            "path": f"{directory.name}/{name}",
            "bytes": len(data),
            "sha256": _hash_bytes(data),
        }

    def _snapshot(self) -> str:
        snapshot = _GitSnapshot(
            self.cwd, self.run_dir, object_directory=self.object_dir
        )
        try:
            return snapshot.tree()
        finally:
            snapshot.close()

    def pre_tool_use(self, envelope: _Envelope) -> None:
        try:
            with _file_lock(self.lock_path):
                state = self._load_state()
                self._validate_context(envelope, state)
                if state.get("finalized"):
                    raise _CaptureFailure("context_unavailable")
                if state.get("session_id") is None:
                    state["session_id"] = envelope.session_id
                if state.get("turn_id") is None:
                    state["turn_id"] = envelope.turn_id
                state["discovered"] = int(state.get("discovered", 0)) + 1
                pending = dict(state.get("pending", {}))
                completed_value = state.get("completed_tool_use_ids", [])
                completed_ids = (
                    {item for item in completed_value if isinstance(item, str)}
                    if isinstance(completed_value, list)
                    else set()
                )
                if (
                    envelope.tool_use_id in pending
                    or envelope.tool_use_id in completed_ids
                ):
                    state["reasons"] = _append_reason(state, "duplicate_tool_use")
                    _atomic_write(self.state_path, _json_bytes(state))
                    return
                if len(pending) + int(state.get("next_completion_sequence", 0)) >= MAX_COMPLETED_RECORDS:
                    state["omitted"] = int(state.get("omitted", 0)) + 1
                    state["reasons"] = _append_reason(state, "record_limit")
                    _atomic_write(self.state_path, _json_bytes(state))
                    return
                sequence = int(state.get("next_start_sequence", 0)) + 1
                state["next_start_sequence"] = sequence
                start_mono_ns = _monotonic_ns()
                started_at = _utc_now()
                current_tree = self._snapshot()
                gap = current_tree != state.get("last_tree")
                if gap:
                    state["gaps"] = int(state.get("gaps", 0)) + 1
                    state["reasons"] = _append_reason(state, "gap_detected")
                if pending:
                    state["overlaps"] = int(state.get("overlaps", 0)) + 1
                    state["reasons"] = _append_reason(state, "overlap_detected")
                    for existing in pending.values():
                        existing["overlap"] = True
                input_meta = self._persist_behavior(self.input_dir, sequence, envelope.tool_use_id, envelope.raw_input_bytes)
                record = {
                    "tool_use_id": envelope.tool_use_id,
                    "tool_name": envelope.tool_name,
                    "session_id": envelope.session_id,
                    "turn_id": envelope.turn_id,
                    "start_sequence": sequence,
                    "start_monotonic_ns": start_mono_ns,
                    "started_at": started_at,
                    "base_tree": current_tree,
                    "gap_before": gap,
                    "overlap": bool(pending),
                    "input": input_meta,
                }
                pending[envelope.tool_use_id] = record
                state["pending"] = pending
                _atomic_write(self.state_path, _json_bytes(state))
                _atomic_write(self.pending_path, _json_bytes(pending))
        except _CaptureFailure as exc:
            self._record_reason(exc.category)
        except Exception:
            self._record_reason("snapshot_failed")

    def post_tool_use(self, envelope: _Envelope) -> None:
        try:
            with _file_lock(self.lock_path):
                state = self._load_state()
                self._validate_context(envelope, state)
                if state.get("finalized"):
                    raise _CaptureFailure("context_unavailable")
                pending = dict(state.get("pending", {}))
                record = pending.get(envelope.tool_use_id)
                if not isinstance(record, dict):
                    completed_value = state.get("completed_tool_use_ids", [])
                    duplicate = (
                        isinstance(completed_value, list)
                        and envelope.tool_use_id in completed_value
                    )
                    state["reasons"] = _append_reason(
                        state, "duplicate_tool_use" if duplicate else "missing_pre"
                    )
                    _atomic_write(self.state_path, _json_bytes(state))
                    return
                result_tree = self._snapshot()
                snapshot = _GitSnapshot(
                    self.cwd, self.run_dir, object_directory=self.object_dir
                )
                try:
                    patch, paths = snapshot.diff(str(record["base_tree"]), result_tree)
                finally:
                    snapshot.close()
                completion_sequence = int(state.get("next_completion_sequence", 0)) + 1
                state["next_completion_sequence"] = completion_sequence
                response_meta = None
                if envelope.raw_response_bytes is not None:
                    response_meta = self._persist_behavior(
                        self.response_dir,
                        int(record["start_sequence"]),
                        envelope.tool_use_id,
                        envelope.raw_response_bytes,
                    )
                success = _response_success(envelope.tool_response)
                changed = bool(patch)
                status = "captured" if success and changed else "empty" if success else "failed"
                patch_meta = None
                if changed:
                    patch_name = f"{record['start_sequence']}-{envelope.tool_use_id}.patch"
                    patch_path = self.patch_dir / patch_name
                    _atomic_write(patch_path, patch)
                    patch_meta = {
                        "path": f"{self.patch_dir.name}/{patch_name}",
                        "bytes": len(patch),
                        "sha256": _hash_bytes(patch),
                    }
                finish_mono_ns = _monotonic_ns()
                start_mono_ns = int(record["start_monotonic_ns"])
                if finish_mono_ns < start_mono_ns:
                    state["reasons"] = _append_reason(state, "clock_failed")
                duration = max(0, int((finish_mono_ns - start_mono_ns) / 1_000_000))
                complete_record = {
                    **record,
                    "completion_sequence": completion_sequence,
                    "start_order": int(record["start_sequence"]),
                    "completion_order": completion_sequence,
                    "completed_at": _utc_now(),
                    "duration_ms": duration,
                    "result_tree": result_tree,
                    "base_tree_id": record["base_tree"],
                    "result_tree_id": result_tree,
                    "status": status,
                    "paths": paths,
                    "patch": patch_meta,
                    "patch_path": patch_meta["path"] if patch_meta else None,
                    "patch_size_bytes": patch_meta["bytes"] if patch_meta else 0,
                    "patch_sha256": patch_meta["sha256"] if patch_meta else None,
                    "response": response_meta,
                    "response_artifact": response_meta,
                    "input_artifact": record["input"],
                    "gap_before": bool(record.get("gap_before")),
                    "error_category": None if success else "tool_failed",
                }
                if not success:
                    state["failed"] = int(state.get("failed", 0)) + 1
                    state["reasons"] = _append_reason(state, "tool_failed")
                elif changed:
                    state["captured"] = int(state.get("captured", 0)) + 1
                else:
                    state["empty"] = int(state.get("empty", 0)) + 1
                state["last_tree"] = result_tree
                pending.pop(envelope.tool_use_id, None)
                state["pending"] = pending
                completed_ids = list(state.get("completed_tool_use_ids", []))
                completed_ids.append(envelope.tool_use_id)
                state["completed_tool_use_ids"] = completed_ids[-MAX_COMPLETED_RECORDS:]
                _append_jsonl(self.manifest_path, complete_record)
                _atomic_write(self.state_path, _json_bytes(state))
                _atomic_write(self.pending_path, _json_bytes(pending))
        except _CaptureFailure as exc:
            self._record_reason(exc.category)
        except Exception:
            self._record_reason("snapshot_failed")

    def finalize(self, *, final_patch_path: Path | None = None) -> HookSummary:
        if self._closed and self.summary_path.exists() and final_patch_path is None:
            return _summary_from_file(self.summary_path)
        try:
            with _file_lock(self.lock_path):
                state = self._load_state()
                self._consume_degradation(state)
                pending = dict(state.get("pending", {}))
                if pending and not state.get("finalized"):
                    state["incomplete"] = int(state.get("incomplete", 0)) + len(pending)
                    state["reasons"] = _append_reason(state, "missing_post")
                    for pending_record in pending.values():
                        if isinstance(pending_record, dict):
                            _append_jsonl(
                                self.manifest_path,
                                {
                                    **pending_record,
                                    "status": "incomplete",
                                    "completion_sequence": None,
                                    "completed_at": None,
                                    "duration_ms": None,
                                    "result_tree": None,
                                    "paths": [],
                                    "patch": None,
                                    "patch_path": None,
                                    "patch_size_bytes": 0,
                                    "patch_sha256": None,
                                    "response": None,
                                    "response_artifact": None,
                                    "error_category": "missing_post",
                                },
                            )
                state["pending"] = {}
                try:
                    final_tree = self._snapshot()
                except _CaptureFailure:
                    final_tree = None
                    state["reasons"] = _append_reason(state, "snapshot_failed")
                replayed_tree = self._replay(state)
                state["final_tree"] = final_tree
                state["replayed_tree"] = replayed_tree
                if final_tree is not None and state.get("last_tree") != final_tree:
                    state["reasons"] = _append_reason(state, "external_mutation")
                if replayed_tree is None or final_tree is None or replayed_tree != final_tree:
                    state["reasons"] = _append_reason(state, "replay_mismatch")
                if final_patch_path is not None:
                    try:
                        final_bytes = final_patch_path.read_bytes()
                        if state.get("run_start_tree") and final_tree:
                            snap = _GitSnapshot(
                                self.cwd,
                                self.run_dir,
                                object_directory=self.object_dir,
                            )
                            try:
                                head_tree = snap.head_tree()
                                patched_tree = (
                                    head_tree
                                    if not final_bytes
                                    else self._apply_patch_tree(
                                        snap, head_tree, final_bytes
                                    )
                                )
                            finally:
                                snap.close()
                            if patched_tree != final_tree:
                                state["reasons"] = _append_reason(state, "final_patch_mismatch")
                    except (OSError, _CaptureFailure):
                        state["reasons"] = _append_reason(state, "final_patch_mismatch")
                state["finalized"] = True
                _atomic_write(self.state_path, _json_bytes(state))
                summary = _summary_for_state(state)
                _atomic_write(self.summary_path, _json_bytes(summary.as_dict()))
        except _CaptureFailure as exc:
            self._record_reason(exc.category)
            self._write_unavailable_summary(exc.category)
            summary = _summary_from_file(self.summary_path)
        except Exception:
            self._record_reason("write_failed")
            self._write_unavailable_summary("write_failed")
            summary = _summary_from_file(self.summary_path)
        self._closed = True
        return summary

    def reconcile(self, final_patch_path: Path | None = None) -> HookSummary:
        """Refresh the private summary against the current worktree and patch.

        Executor-owned patches are saved after Codex exits.  Reconciliation is
        deliberately idempotent so that the runner's initial finalization can
        be corrected without reopening a Codex hook context or appending
        duplicate incomplete records.
        """

        self._closed = False
        return self.finalize(final_patch_path=final_patch_path)

    close = finalize

    def _replay(self, state: dict[str, Any]) -> str | None:
        records: list[dict[str, Any]] = []
        try:
            if self.manifest_path.exists():
                for line in self.manifest_path.read_text(encoding="utf-8").splitlines():
                    item = json.loads(line)
                    if (
                        isinstance(item, dict)
                        and item.get("status") == "captured"
                        and item.get("patch")
                        and not item.get("gap_before")
                        and not item.get("overlap")
                    ):
                        records.append(item)
            records.sort(key=lambda item: int(item.get("completion_sequence", 0)))
            if not state.get("run_start_tree"):
                return None
            base = str(state["run_start_tree"])
            for item in records:
                patch = item.get("patch")
                if not isinstance(patch, dict) or not isinstance(patch.get("path"), str):
                    return None
                path = self.run_dir / patch["path"]
                data = path.read_bytes()
                if _hash_bytes(data) != patch.get("sha256"):
                    return None
                if item.get("base_tree") != base:
                    return None
                # Validate each canonical patch independently and ensure the
                # recorded result tree is exactly what the patch creates.
                snap = _GitSnapshot(
                    self.cwd, self.run_dir, object_directory=self.object_dir
                )
                try:
                    result = self._apply_patch_tree(snap, base, data)
                finally:
                    snap.close()
                if result != item.get("result_tree"):
                    return None
                base = result
            return base
        except (OSError, UnicodeError, ValueError, TypeError, _CaptureFailure):
            return None

    @staticmethod
    def _apply_patch_tree(snapshot: _GitSnapshot, base: str, patch: bytes) -> str:
        if not TREE_RE.fullmatch(base):
            raise _CaptureFailure("replay_mismatch")
        snapshot._run(["read-tree", base], check=True)
        try:
            proc = subprocess.run(  # nosec B603
                ["git", "apply", "--binary", "--cached", "--whitespace=nowarn", "-"],
                cwd=snapshot.cwd,
                env={**os.environ, **snapshot.env},
                shell=False,
                input=patch,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError:
            raise _CaptureFailure("replay_mismatch")
        if proc.returncode:
            raise _CaptureFailure("replay_mismatch")
        result = snapshot._run(["write-tree"], check=True).stdout.strip()
        if not TREE_RE.fullmatch(result):
            raise _CaptureFailure("replay_mismatch")
        return result

    @property
    def summary(self) -> HookSummary:
        if self.summary_path.exists():
            return _summary_from_file(self.summary_path)
        try:
            return _summary_for_state(self._load_state())
        except _CaptureFailure:
            return HookSummary(SCHEMA_VERSION, "unavailable", 0, 0, 0, 0, 0, 0, 0, 0, ("context_unavailable",), None, None, None)

    @property
    def diagnostics(self) -> dict[str, Any]:
        return self.summary.diagnostics_dict()

    @property
    def context(self) -> Path:
        return self.context_path


ToolChangeRecorder = ToolChangeCapture
HookCaptureContext = ToolChangeCapture


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _append_reason(state: dict[str, Any], reason: str) -> list[str]:
    reasons = list(state.get("reasons", []))
    if reason not in reasons and reason in _ERROR_CATEGORIES:
        reasons.append(reason)
    return reasons[:32]


def _response_success(value: Any) -> bool:
    if isinstance(value, dict):
        for key in ("success", "ok"):
            if key in value and isinstance(value[key], bool):
                return value[key]
        for key in ("exit_code", "returncode", "exitCode"):
            if key in value and isinstance(value[key], int):
                return value[key] == 0
        status = value.get("status")
        if isinstance(status, str) and status.lower() in {"error", "failed", "failure"}:
            return False
        response_type = value.get("type")
        if isinstance(response_type, str) and response_type.lower() in {"error", "failed", "failure"}:
            return False
        if isinstance(value.get("error"), (str, dict, list)) and value.get("error"):
            return False
    return True


def _summary_for_state(state: dict[str, Any]) -> HookSummary:
    reasons = tuple(str(item) for item in state.get("reasons", []) if item in _ERROR_CATEGORIES)
    discovered = int(state.get("discovered", 0))
    captured = int(state.get("captured", 0))
    empty = int(state.get("empty", 0))
    failed = int(state.get("failed", 0))
    incomplete = int(state.get("incomplete", 0))
    gaps = int(state.get("gaps", 0))
    overlaps = int(state.get("overlaps", 0))
    omitted = int(state.get("omitted", 0))
    final_tree = state.get("final_tree")
    replayed_tree = state.get("replayed_tree")
    if not discovered and not captured and not empty and not failed:
        state_name = "unavailable"
        reasons = reasons or ("hook_not_observed",)
    elif reasons or incomplete or gaps or overlaps or omitted or final_tree is None or replayed_tree != final_tree:
        state_name = "partial"
    else:
        state_name = "complete"
    return HookSummary(
        SCHEMA_VERSION,
        state_name,
        discovered,
        captured,
        empty,
        failed,
        incomplete,
        gaps,
        overlaps,
        omitted,
        reasons,
        state.get("run_start_tree"),
        final_tree,
        replayed_tree,
    )


def _summary_from_file(path: Path) -> HookSummary:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        state_value = data.get("state", "unavailable")
        state = (
            state_value
            if state_value in {"complete", "partial", "unavailable"}
            else "unavailable"
        )
        raw_reasons = data.get("reasons", [])
        reasons = (
            tuple(str(item) for item in raw_reasons if item in _ERROR_CATEGORIES)
            if isinstance(raw_reasons, list)
            else ()
        )
        return HookSummary(
            int(data.get("schema_version", SCHEMA_VERSION)),
            state,
            int(data.get("discovered", 0)),
            int(data.get("captured", 0)),
            int(data.get("empty", 0)),
            int(data.get("failed", 0)),
            int(data.get("incomplete", 0)),
            int(data.get("gaps", 0)),
            int(data.get("overlaps", 0)),
            int(data.get("omitted", 0)),
            reasons,
            data.get("run_start_tree"),
            data.get("final_tree"),
            data.get("replayed_tree"),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return HookSummary(SCHEMA_VERSION, "unavailable", 0, 0, 0, 0, 0, 0, 0, 0, ("context_unavailable",), None, None, None)


def handle_hook(raw: bytes | str, *, context_path: Path | None = None) -> None:
    """Process one envelope and swallow all failures for hook exit isolation."""
    if context_path is None:
        value = os.environ.get("COQUIC_STEWARD_HOOK_CONTEXT")
        if not value:
            return
        context_path = Path(value)
    try:
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        envelope = _parse_envelope(raw_bytes)
        capture = ToolChangeCapture.from_context(context_path)
        if envelope.event == "PreToolUse":
            capture.pre_tool_use(envelope)
        else:
            capture.post_tool_use(envelope)
    except _CaptureFailure as exc:
        # Keep the failure vocabulary bounded and avoid serializing exception
        # text from malformed or oversized hook envelopes.
        try:
            if context_path is not None:
                ToolChangeCapture.from_context(context_path)._record_reason(exc.category)
        except Exception:
            pass
    except Exception:
        # Hook failure is deliberately silent and successful from Codex's
        # perspective.  The next finalization records an unavailable reason.
        try:
            if context_path is not None:
                ToolChangeCapture.from_context(context_path)._record_reason("invalid_envelope")
        except Exception:
            pass


def _read_hook_envelope(fd: int = 0) -> bytes:
    data = bytearray()
    read_limit = MAX_HOOK_ENVELOPE_BYTES + 1
    while len(data) < read_limit:
        chunk = os.read(fd, min(64 * 1024, read_limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def main(argv: list[str] | None = None) -> int:
    if not os.environ.get("COQUIC_STEWARD_HOOK_CONTEXT"):
        return 0
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--finalize", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 0
    context_value = os.environ.get("COQUIC_STEWARD_HOOK_CONTEXT")
    if not context_value:
        return 0
    try:
        context_path = Path(context_value)
        if args.finalize:
            ToolChangeCapture.from_context(context_path).finalize()
        else:
            handle_hook(_read_hook_envelope(), context_path=context_path)
    except Exception:
        pass
    return 0


process_hook = handle_hook


def reconcile_tool_changes(
    context_path: Path, *, final_patch_path: Path | None = None
) -> HookSummary:
    """Reconcile a runner-owned hook context without exposing private data."""

    try:
        return ToolChangeCapture.from_context(context_path).reconcile(
            final_patch_path=final_patch_path
        )
    except _CaptureFailure as exc:
        capture = ToolChangeCapture.unavailable(Path.cwd(), Path(context_path).parent)
        capture._record_reason(exc.category)
        return capture.summary
    except Exception:
        capture = ToolChangeCapture.unavailable(Path.cwd(), Path(context_path).parent)
        capture._record_reason("write_failed")
        return capture.summary


if __name__ == "__main__":  # pragma: no cover - exercised by Codex
    raise SystemExit(main())


__all__ = [
    "HookCaptureContext",
    "HookSummary",
    "ToolChangeCapture",
    "ToolChangeRecorder",
    "handle_hook",
    "main",
    "parse_hook_envelope",
    "process_hook",
    "reconcile_tool_changes",
]
