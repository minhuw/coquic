"""Codex invocation primitives shared by the task-container supervisor.

The process boundary owns argv construction, byte-oriented JSONL handling, and
derived observability.  It intentionally has no SQLite or public-archive
knowledge beyond an append callback supplied by the trusted supervisor.
"""

from __future__ import annotations

import json
import io
import os
import selectors
import signal
import subprocess  # nosec B404 - explicit argv and shell=False
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from ..core.models import CodexStage


class InvocationProcess(Protocol):
    stdout: Any
    stderr: Any
    stdin: Any
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
            self.observe(value)
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
    """Stream process stdout without text decoding or complete-record caps."""

    if process.stdin is not None:
        try:
            process.stdin.write(request.prompt.encode("utf-8"))
            process.stdin.write(b"\n")
            process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    decoder = JsonlStream(append, observe=observe)
    stderr_data = _BoundedBytes(64 * 1024)
    selector = selectors.DefaultSelector()
    streams = ((process.stdout, True), (process.stderr, False))
    selector_supported = True
    for stream, is_stdout in streams:
        if stream is not None:
            try:
                selector.register(stream, selectors.EVENT_READ, is_stdout)
            except (ValueError, OSError, PermissionError):
                selector_supported = False
                break
    started = time.monotonic()
    forced = False
    if not selector_supported:
        for stream, is_stdout in streams:
            if stream is None:
                continue
            while True:
                data = stream.read(65536)
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not data:
                    break
                if is_stdout:
                    decoder.feed(data)
                else:
                    stderr_data.extend(data)
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except (subprocess.TimeoutExpired, TimeoutError):
            forced = True
            process.kill()
            exit_code = process.wait()
        return InvocationOutcome(
            exit_code=exit_code,
            stdout=b"",
            stderr=bytes(stderr_data),
            incomplete_suffix=decoder.finish(),
            events=(),
            provider_session_id=decoder.provider_session_id,
            malformed_lines=decoder.malformed_lines,
            forced=forced,
            interrupted=interrupted,
        )
    while selector.get_map() or process.poll() is None:
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            interrupted = True
            try:
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=interrupt_grace_seconds)
            except (OSError, subprocess.TimeoutExpired, TimeoutError):
                forced = True
                try:
                    process.kill()
                except OSError:
                    pass
            break
        for key, _ in selector.select(min(0.25, remaining)):
            stream = key.fileobj
            is_stdout = key.data
            try:
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except (AttributeError, io.UnsupportedOperation):
                    chunk = stream.read(65536)
            except OSError:
                chunk = b""
            if not chunk:
                selector.unregister(stream)
                continue
            if is_stdout:
                decoder.feed(chunk)
            else:
                stderr_data.extend(chunk)
    try:
        exit_code = process.wait(timeout=interrupt_grace_seconds)
    except (subprocess.TimeoutExpired, TimeoutError):
        forced = True
        try:
            process.kill()
        except OSError:
            pass
        exit_code = process.wait()
    return InvocationOutcome(
        exit_code=exit_code,
        stdout=b"",
        stderr=bytes(stderr_data),
        incomplete_suffix=decoder.finish(),
        events=(),
        provider_session_id=decoder.provider_session_id,
        malformed_lines=decoder.malformed_lines,
        forced=forced,
        interrupted=interrupted,
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
