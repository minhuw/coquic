"""Codex invocation primitives shared by the task-container supervisor.

The process boundary owns argv construction, byte-oriented JSONL handling, and
derived observability.  It intentionally has no SQLite or public-archive
knowledge beyond an append callback supplied by the trusted supervisor.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - explicit argv and shell=False
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from ..core.models import CodexStage
from .process_stream import (
    ExactTerminationStrategy,
    PostEofWait,
    drain_process,
    reap_process,
)


class _InvocationPipe(Protocol):
    def read(self, size: int) -> bytes: ...

    def close(self) -> None: ...

    def fileno(self) -> int: ...

    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...


class InvocationProcess(Protocol):
    stdout: _InvocationPipe | None
    stderr: _InvocationPipe | None
    stdin: _InvocationPipe | None
    returncode: int | None

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def send_signal(self, sig: int) -> None: ...

    def kill(self) -> None: ...


@dataclass(frozen=True)
class InvocationRequest:
    codex_bin: str
    cwd: Path
    prompt: str
    output_last_message: Path
    stage: CodexStage
    model: str | None = None
    reasoning_effort: str | None = None
    output_schema: Path | None = None
    sandbox: str = "workspace-write"
    provider_session_id: str | None = None
    role: str = "implementation"
    session_uid: int | None = None
    session_id: str | None = None
    run_id: str | None = None

    @property
    def resume(self) -> bool:
        return self.provider_session_id is not None

    def argv(
        self,
        *,
        codex_bin: str | None = None,
        path_mapper: Callable[[Path], str] | None = None,
    ) -> list[str]:
        render_path = path_mapper or (lambda value: str(value))
        args = [codex_bin or self.codex_bin, "exec"]
        if self.provider_session_id is not None:
            args.extend(["resume"])
        args.append("--json")
        args.extend(["--config", shell_environment_policy_config()])
        if self.model:
            args.extend(["--model", self.model])
        if self.reasoning_effort:
            args.extend(
                ["--config", f"model_reasoning_effort={json.dumps(self.reasoning_effort)}"]
            )
        if self.stage == CodexStage.code:
            args.extend(["--dangerously-bypass-hook-trust"])
        if not self.resume:
            args.extend(["--sandbox", self.sandbox, "--cd", render_path(self.cwd)])
        args.extend(
            ["--output-last-message", render_path(self.output_last_message)]
        )
        if self.output_schema is not None:
            args.extend(["--output-schema", render_path(self.output_schema)])
        if self.provider_session_id is not None:
            args.append(self.provider_session_id)
        args.append("-")
        return args


@dataclass
class JsonlStream:
    """Byte-preserving complete-line decoder.

    ``append`` receives the exact bytes, including the newline.  Invalid UTF-8
    is retained in the archive and only affects the derived event list.
    """

    append: Callable[[bytes], None]
    observe: Callable[[dict[str, Any]], None] | None = None
    suffix: bytes = b""
    provider_session_id: str | None = None
    malformed_lines: int = 0

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise TypeError("JSONL stream chunks must be bytes")
        data = self.suffix + chunk
        lines = data.splitlines(keepends=True)
        self.suffix = b""
        if lines and not lines[-1].endswith(b"\n"):
            self.suffix = lines.pop()
        for line in lines:
            if not line.endswith(b"\n"):
                self.suffix += line
                continue
            self.append(line)
            self._observe(line)

    def finish(self) -> bytes:
        """Return the incomplete suffix without publishing it as a record."""

        suffix = self.suffix
        self.suffix = b""
        return suffix

    def _observe(self, line: bytes) -> None:
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.malformed_lines += 1
            return
        if not isinstance(value, dict):
            self.malformed_lines += 1
            return
        if self.observe is not None:
            try:
                self.observe(value)
            except Exception:
                # Observability must not change process draining or decoding.
                pass
        for key in ("thread_id", "session_id", "sessionId"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                self.provider_session_id = candidate
                break
        payload = value.get("thread")
        if isinstance(payload, dict):
            candidate = payload.get("id") or payload.get("session_id")
            if isinstance(candidate, str) and candidate:
                self.provider_session_id = candidate


@dataclass(frozen=True)
class InvocationOutcome:
    exit_code: int
    stdout: bytes
    stderr: bytes
    incomplete_suffix: bytes
    events: tuple[dict[str, Any], ...]
    provider_session_id: str | None
    malformed_lines: int = 0
    forced: bool = False
    interrupted: bool = False

    @property
    def completed(self) -> bool:
        return self.exit_code == 0 and not self.interrupted and not self.forced


def launch_local(request: InvocationRequest, *, api_key: str | None = None) -> subprocess.Popen[bytes]:
    """Test harness launcher; production uses the task-container runtime."""

    environment = dict(os.environ)
    if api_key is not None:
        environment["CODEX_API_KEY"] = api_key
    environment["CODEX_HOME"] = str(request.output_last_message.parent / "codex-home")
    return subprocess.Popen(  # nosec B603 - argv is explicit and shell=False
        request.argv(),
        cwd=request.cwd,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )


_STDERR_TAIL_SIZE = 64 * 1024


def stream_process(
    process: InvocationProcess,
    request: InvocationRequest,
    *,
    append: Callable[[bytes], None],
    observe: Callable[[dict[str, Any]], None] | None = None,
    timeout_seconds: float,
    interrupt_grace_seconds: float = 2.0,
    interrupted: bool = False,
) -> InvocationOutcome:
    """Stream both process pipes while retaining bounded diagnostics."""

    decoder = JsonlStream(append, observe=observe)
    stderr_data = _BoundedBytes(_STDERR_TAIL_SIZE)
    try:
        input_bytes = request.prompt.encode("utf-8") + b"\n"
    except Exception:
        reap_process(
            process,
            ExactTerminationStrategy(grace_seconds=interrupt_grace_seconds),
        )
        raise
    outcome = drain_process(
        process,
        input_bytes,
        decoder.feed,
        stderr_data.extend,
        timeout_seconds,
        ExactTerminationStrategy(grace_seconds=interrupt_grace_seconds),
        PostEofWait.bounded(),
    )
    if outcome.reader_error is not None:
        raise outcome.reader_error
    return InvocationOutcome(
        exit_code=outcome.exit_code,
        stdout=b"",
        stderr=bytes(stderr_data),
        incomplete_suffix=decoder.finish(),
        events=(),
        provider_session_id=decoder.provider_session_id,
        malformed_lines=decoder.malformed_lines,
        forced=outcome.forced,
        interrupted=interrupted or outcome.timed_out,
    )


class _BoundedBytes:
    """Retain only the tail needed for private diagnostics."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()

    def extend(self, chunk: bytes) -> None:
        self.data.extend(chunk)
        if len(self.data) > self.limit:
            del self.data[: len(self.data) - self.limit]

    def __bytes__(self) -> bytes:
        return bytes(self.data)


def shell_environment_policy_config() -> str:
    """Return the minimal Codex config override for tool child isolation."""

    return 'shell_environment_policy.inherit="none"'


def approved_tool_environment() -> tuple[str, ...]:
    return (
        "PATH",
        "HOME",
        "CODEX_HOME",
        "LANG",
        "LC_ALL",
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "COQUIC_STEWARD_TASK_ID",
        "COQUIC_STEWARD_ROLE",
    )
