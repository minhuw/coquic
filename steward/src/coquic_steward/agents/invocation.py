"""Codex invocation primitives shared by the task-container supervisor.

The process boundary owns argv construction, byte-oriented JSONL handling, and
derived observability.  It intentionally has no SQLite or public-archive
knowledge beyond an append callback supplied by the trusted supervisor.
"""

from __future__ import annotations

import io
import json
import os
import queue
import select
import selectors
import signal
import subprocess  # nosec B404 - explicit argv and shell=False
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from ..core.models import CodexStage


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


_STREAM_CHUNK_SIZE = 64 * 1024
_STDERR_TAIL_SIZE = 64 * 1024
_HANDOFF_WAIT_SECONDS = 0.05
_READER_POLL_SECONDS = 0.01


@dataclass(frozen=True)
class _PipeReadResult:
    stream_index: int
    kind: str
    data: bytes = b""
    error: Exception | None = None


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

    if process.stdin is not None:
        try:
            process.stdin.write(request.prompt.encode("utf-8"))
            process.stdin.write(b"\n")
            process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    decoder = JsonlStream(append, observe=observe)
    stderr_data = _BoundedBytes(_STDERR_TAIL_SIZE)
    streams = _unique_streams(((process.stdout, True), (process.stderr, False)))
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    fallback_threads: list[threading.Thread] = []
    reader_error: Exception | None = None
    try:
        selector_supported = True
        try:
            for stream, is_stdout in streams:
                selector.register(stream, selectors.EVENT_READ, is_stdout)
        except (KeyError, OSError, TypeError, ValueError):
            selector_supported = False

        if selector_supported:
            exit_code, forced, interrupted = _drain_with_selector(
                process,
                selector,
                decoder,
                stderr_data,
                deadline=deadline,
                interrupt_grace_seconds=interrupt_grace_seconds,
                interrupted=interrupted,
            )
        else:
            selector.close()
            exit_code, forced, interrupted, reader_error = _drain_with_fallback(
                process,
                streams,
                decoder,
                stderr_data,
                deadline=deadline,
                interrupt_grace_seconds=interrupt_grace_seconds,
                interrupted=interrupted,
                reader_threads=fallback_threads,
            )
    finally:
        selector.close()
        _close_streams(streams)
        for thread in fallback_threads:
            thread.join()
    if reader_error is not None:
        raise reader_error
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


def _unique_streams(
    streams: Iterable[tuple[_InvocationPipe | None, bool]],
) -> tuple[tuple[_InvocationPipe, bool], ...]:
    unique: list[tuple[_InvocationPipe, bool]] = []
    seen: set[int] = set()
    for stream, is_stdout in streams:
        if stream is None or id(stream) in seen:
            continue
        seen.add(id(stream))
        unique.append((stream, is_stdout))
    return tuple(unique)


def _close_streams(
    streams: Iterable[tuple[_InvocationPipe, bool]],
) -> None:
    seen: set[int] = set()
    for stream, _ in streams:
        identity = id(stream)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            stream.close()
        except Exception:
            pass


def _terminate_after_deadline(
    process: InvocationProcess,
    *,
    interrupt_grace_seconds: float,
) -> tuple[int, bool]:
    """Terminate a live process, escalating only after the grace period."""

    if process.poll() is not None:
        return process.wait(), False
    try:
        process.send_signal(signal.SIGTERM)
    except OSError:
        pass
    try:
        exit_code = process.wait(timeout=interrupt_grace_seconds)
    except (subprocess.TimeoutExpired, TimeoutError):
        try:
            process.kill()
        except OSError:
            pass
        return process.wait(), True
    return exit_code, False


def _drain_with_selector(
    process: InvocationProcess,
    selector: selectors.BaseSelector,
    decoder: JsonlStream,
    stderr_data: _BoundedBytes,
    *,
    deadline: float,
    interrupt_grace_seconds: float,
    interrupted: bool,
) -> tuple[int, bool, bool]:
    forced = False
    while selector.get_map() or process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exit_code, forced = _terminate_after_deadline(
                process,
                interrupt_grace_seconds=interrupt_grace_seconds,
            )
            return exit_code, forced, True
        if not selector.get_map():
            try:
                exit_code = process.wait(timeout=remaining)
            except (subprocess.TimeoutExpired, TimeoutError):
                exit_code, forced = _terminate_after_deadline(
                    process,
                    interrupt_grace_seconds=interrupt_grace_seconds,
                )
                return exit_code, forced, True
            return exit_code, forced, interrupted
        try:
            ready = selector.select(min(0.25, remaining))
        except (OSError, ValueError):
            ready = ()
        for key, _ in ready:
            stream = key.fileobj
            is_stdout = bool(key.data)
            try:
                try:
                    chunk = os.read(stream.fileno(), _STREAM_CHUNK_SIZE)
                except (AttributeError, io.UnsupportedOperation):
                    chunk = stream.read(_STREAM_CHUNK_SIZE)
            except (OSError, ValueError):
                chunk = b""
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            if not chunk:
                try:
                    selector.unregister(stream)
                except (KeyError, OSError, ValueError):
                    pass
                continue
            if is_stdout:
                decoder.feed(chunk)
            else:
                stderr_data.extend(chunk)
    return process.wait(), forced, interrupted


def _publish_pipe_result(
    handoff: queue.Queue[_PipeReadResult],
    result: _PipeReadResult,
    stop: threading.Event,
) -> bool:
    while not stop.is_set():
        try:
            handoff.put(result, timeout=_HANDOFF_WAIT_SECONDS)
        except queue.Full:
            continue
        return True
    return False


def _read_pipe(
    stream: _InvocationPipe,
    stream_index: int,
    handoff: queue.Queue[_PipeReadResult],
    stop: threading.Event,
) -> None:
    try:
        try:
            fileno = stream.fileno()
        except (AttributeError, io.UnsupportedOperation):
            fileno = None
        if fileno is None:
            while not stop.is_set():
                data = stream.read(_STREAM_CHUNK_SIZE)
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not isinstance(data, bytes):
                    raise TypeError("invocation streams must return bytes")
                if not data:
                    _publish_pipe_result(
                        handoff,
                        _PipeReadResult(stream_index, "eof"),
                        stop,
                    )
                    return
                if not _publish_pipe_result(
                    handoff,
                    _PipeReadResult(stream_index, "data", data),
                    stop,
                ):
                    return
            return
        while not stop.is_set():
            ready, _, _ = select.select(
                (fileno,), (), (), _READER_POLL_SECONDS
            )
            if stop.is_set():
                return
            if not ready:
                continue
            data = os.read(fileno, _STREAM_CHUNK_SIZE)
            if not data:
                _publish_pipe_result(
                    handoff,
                    _PipeReadResult(stream_index, "eof"),
                    stop,
                )
                return
            if not _publish_pipe_result(
                handoff,
                _PipeReadResult(stream_index, "data", data),
                stop,
            ):
                return
    except Exception as error:
        _publish_pipe_result(
            handoff,
            _PipeReadResult(stream_index, "error", error=error),
            stop,
        )


def _drain_with_fallback(
    process: InvocationProcess,
    streams: tuple[tuple[_InvocationPipe, bool], ...],
    decoder: JsonlStream,
    stderr_data: _BoundedBytes,
    *,
    deadline: float,
    interrupt_grace_seconds: float,
    interrupted: bool,
    reader_threads: list[threading.Thread],
) -> tuple[int, bool, bool, Exception | None]:
    handoff: queue.Queue[_PipeReadResult] = queue.Queue(maxsize=max(1, len(streams)))
    stop = threading.Event()
    threads = tuple(
        threading.Thread(
            target=_read_pipe,
            args=(stream, index, handoff, stop),
            daemon=False,
            name=f"invocation-stream-{index}",
        )
        for index, (stream, _) in enumerate(streams)
    )
    for thread in threads:
        thread.start()
        reader_threads.append(thread)

    completed: set[int] = set()
    exit_code: int | None = None
    forced = False
    reader_error: Exception | None = None
    try:
        while len(completed) < len(streams) or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exit_code, forced = _terminate_after_deadline(
                    process,
                    interrupt_grace_seconds=interrupt_grace_seconds,
                )
                interrupted = True
                break
            if len(completed) == len(streams):
                try:
                    exit_code = process.wait(timeout=remaining)
                except (subprocess.TimeoutExpired, TimeoutError):
                    exit_code, forced = _terminate_after_deadline(
                        process,
                        interrupt_grace_seconds=interrupt_grace_seconds,
                    )
                    interrupted = True
                break
            try:
                result = handoff.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if result.kind == "data":
                if streams[result.stream_index][1]:
                    decoder.feed(result.data)
                else:
                    stderr_data.extend(result.data)
            elif result.kind == "eof":
                completed.add(result.stream_index)
            elif result.kind == "error":
                completed.add(result.stream_index)
                reader_error = result.error or RuntimeError(
                    "invocation stream reader failed"
                )
                stop.set()
                exit_code, forced = _terminate_after_deadline(
                    process,
                    interrupt_grace_seconds=interrupt_grace_seconds,
                )
                break
    finally:
        stop.set()
    if exit_code is None:
        exit_code = process.wait()
    return exit_code, forced, interrupted, reader_error


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
