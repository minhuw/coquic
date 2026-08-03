from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    cwd: Path
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ProcessGroupCancellationOwner:
    """Track daemon-owned process groups and cancel them as one lifecycle unit.

    ``run_command`` creates a new session for every trusted subprocess.  The
    owner therefore needs only the process leader PID to terminate the whole
    command tree.  A process remains registered until its output drains and
    wait has observed its exit, which lets shutdown wait for the worker future's
    acknowledgement instead of merely sending a signal and closing state.
    """

    def __init__(self, name: str = "steward") -> None:
        self.name = str(name)
        self._condition = threading.Condition()
        self._processes: dict[int, subprocess.Popen[str]] = {}
        self._cancel_requested = False
        self._force_requested = False

    def register(self, process: subprocess.Popen[str]) -> None:
        pid = int(getattr(process, "pid", 0) or 0)
        if pid <= 0:
            return
        with self._condition:
            self._processes[pid] = process
            cancel = self._force_requested
            cooperative = self._cancel_requested and not cancel
        if cancel:
            _terminate_process_group(process, signal.SIGKILL)
        elif cooperative:
            _terminate_process_group(process, signal.SIGTERM)

    def unregister(self, process: subprocess.Popen[str]) -> None:
        pid = int(getattr(process, "pid", 0) or 0)
        with self._condition:
            if pid > 0:
                self._processes.pop(pid, None)
            self._condition.notify_all()

    @property
    def active_count(self) -> int:
        with self._condition:
            return len(self._processes)

    def request_cancel(self, *, force: bool = False) -> int:
        """Signal all registered groups; return the number of groups signalled."""

        with self._condition:
            self._cancel_requested = True
            self._force_requested = self._force_requested or force
            processes = tuple(self._processes.values())
        selected = signal.SIGKILL if force else signal.SIGTERM
        count = 0
        for process in processes:
            _terminate_process_group(process, selected)
            count += 1
        return count

    cancel = request_cancel

    def force_cancel(self) -> int:
        return self.request_cancel(force=True)

    def wait(self, timeout: float | None = None) -> bool:
        """Wait until every registered command has acknowledged process exit."""

        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._processes:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    wait_for_quiescence = wait


_current_owner: ContextVar[ProcessGroupCancellationOwner | None] = ContextVar(
    "steward_subprocess_owner", default=None
)


_CAPTURE_CHUNK_BYTES = 64 * 1024


class _StreamCapture:
    """Drain one subprocess stream while retaining an optional prefix."""

    def __init__(self, stream: Any, max_output_bytes: int | None, *, text: bool):
        self.stream = stream
        self.max_output_bytes = max_output_bytes
        self.text = text
        self._chunks: list[str | bytes] = []
        self._retained_bytes = 0
        self.error: BaseException | None = None

    def drain(self) -> None:
        try:
            while True:
                chunk = self.stream.read(_CAPTURE_CHUNK_BYTES)
                if not chunk:
                    return
                self._retain(chunk)
        except BaseException as exc:
            self.error = exc

    def value(self) -> str | bytes:
        if self.text:
            return "".join(
                chunk for chunk in self._chunks if isinstance(chunk, str)
            )
        return b"".join(chunk for chunk in self._chunks if isinstance(chunk, bytes))

    def _retain(self, chunk: str | bytes) -> None:
        if self.max_output_bytes is None:
            self._chunks.append(chunk)
            return
        remaining = self.max_output_bytes - self._retained_bytes
        if remaining <= 0:
            return
        if isinstance(chunk, bytes):
            retained = chunk[:remaining]
            self._chunks.append(retained)
            self._retained_bytes += len(retained)
            return
        retained_characters: list[str] = []
        for character in chunk:
            encoded = character.encode("utf-8", errors="replace")
            if len(encoded) > remaining:
                break
            retained_characters.append(character)
            remaining -= len(encoded)
            self._retained_bytes += len(encoded)
            if remaining <= 0:
                break
        if retained_characters:
            self._chunks.append("".join(retained_characters))


class _ProcessCapture:
    """Run concurrent stream drains and close stdin after delivering input."""

    def __init__(
        self,
        process: subprocess.Popen[Any],
        *,
        max_output_bytes: int | None,
        text: bool,
        input_value: str | bytes | None,
    ):
        self.process = process
        self.text = text
        self.stdout = _StreamCapture(
            process.stdout, max_output_bytes, text=text
        )
        self.stderr = _StreamCapture(
            process.stderr, max_output_bytes, text=text
        )
        self.input_value = input_value
        self.input_error: BaseException | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for capture, name in (
            (self.stdout, "steward-subprocess-stdout-drainer"),
            (self.stderr, "steward-subprocess-stderr-drainer"),
        ):
            thread = threading.Thread(target=capture.drain, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        if self.input_value is not None and self.process.stdin is not None:
            thread = threading.Thread(
                target=self._write_input,
                name="steward-subprocess-stdin-writer",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def finish(self) -> tuple[str | bytes, str | bytes]:
        self.wait_for_drain()
        if self.input_error is not None:
            raise self.input_error
        if self.stdout.error is not None:
            raise self.stdout.error
        if self.stderr.error is not None:
            raise self.stderr.error
        return self.stdout.value(), self.stderr.value()

    def wait_for_drain(self, timeout: float | None = None) -> bool:
        """Wait for every capture worker, returning whether all streams ended."""

        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        for thread in self._threads:
            if deadline is None:
                thread.join()
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)
        return not any(thread.is_alive() for thread in self._threads)

    def _write_input(self) -> None:
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(self.input_value)
            self.process.stdin.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except BaseException as exc:
            self.input_error = exc
        finally:
            try:
                self.process.stdin.close()
            except OSError:
                pass


def _validate_capture_limit(max_output_bytes: int | None) -> None:
    if max_output_bytes is not None and (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes < 0
    ):
        raise ValueError("max_output_bytes must be a non-negative integer or None")


def _communicate_bounded(
    process: subprocess.Popen[Any],
    *,
    input_value: str | bytes | None,
    timeout: float | None,
    max_output_bytes: int | None,
    text: bool,
    terminate: Callable[[int], None],
    timeout_grace: float,
) -> tuple[str | bytes, str | bytes, bool]:
    """Drain both streams continuously and reap a process after timeout."""

    _validate_capture_limit(max_output_bytes)
    capture = _ProcessCapture(
        process,
        max_output_bytes=max_output_bytes,
        text=text,
        input_value=input_value,
    )
    capture.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate(signal.SIGTERM)
        grace_deadline = time.monotonic() + max(0.0, timeout_grace)
        process_exited = False
        try:
            process.wait(timeout=max(0.0, grace_deadline - time.monotonic()))
            process_exited = True
        except subprocess.TimeoutExpired:
            pass
        streams_drained = capture.wait_for_drain(
            timeout=max(0.0, grace_deadline - time.monotonic())
        )
        if not process_exited or not streams_drained:
            terminate(signal.SIGKILL)
            process.wait()
    stdout, stderr = capture.finish()
    return stdout, stderr, timed_out


class use_subprocess_owner:
    """Context manager binding an owner to trusted commands in this thread."""

    def __init__(self, owner: ProcessGroupCancellationOwner | None):
        self.owner = owner
        self._token: Any = None

    def __enter__(self) -> ProcessGroupCancellationOwner | None:
        self._token = _current_owner.set(self.owner)
        return self.owner

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        if self._token is not None:
            _current_owner.reset(self._token)


bind_subprocess_owner = use_subprocess_owner
SubprocessCancellationOwner = ProcessGroupCancellationOwner
ProcessGroupOwner = ProcessGroupCancellationOwner


def current_subprocess_owner() -> ProcessGroupCancellationOwner | None:
    return _current_owner.get()


def run_command(
    args: list[str],
    cwd: Path,
    *,
    check: bool = False,
    input_text: str | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    replace_env: bool = False,
    cancellation_owner: ProcessGroupCancellationOwner | None = None,
    max_output_bytes: int | None = None,
) -> CommandResult:
    _validate_argv(args)
    _validate_capture_limit(max_output_bytes)
    proc: subprocess.Popen[str] | None = None
    owner = cancellation_owner or _current_owner.get()
    try:
        process_env = None
        if env is not None:
            if replace_env:
                process_env = env.copy()
            else:
                process_env = os.environ.copy()
                process_env.update(env)
        proc = _TrustedProcess(
            args,
            cwd=cwd,
            env=process_env,
            text=True,
            errors="replace" if max_output_bytes is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else None,
            start_new_session=True,
        )
        if owner is not None:
            owner.register(proc)
        stdout_value, stderr_value, timed_out = _communicate_bounded(
            proc,
            input_value=input_text,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            text=True,
            terminate=lambda sig: _terminate_process_group(proc, sig),
            timeout_grace=5,
        )
        stdout = str(stdout_value)
        stderr = str(stderr_value)
        if timed_out:
            timeout_message = f"command timed out after {timeout} seconds"
            stderr = f"{stderr}\n{timeout_message}" if stderr else timeout_message
            result = CommandResult(
                args=args,
                cwd=cwd,
                returncode=124,
                stdout=stdout,
                stderr=stderr,
            )
            if check:
                raise RuntimeError(_failure_message(result))
            return result
    except FileNotFoundError as exc:
        result = CommandResult(
            args=args,
            cwd=cwd,
            returncode=127,
            stdout="",
            stderr=str(exc),
        )
        if check:
            raise RuntimeError(_failure_message(result)) from exc
        return result
    except OSError as exc:
        result = CommandResult(
            args=args,
            cwd=cwd,
            returncode=126,
            stdout="",
            stderr=str(exc),
        )
        if check:
            raise RuntimeError(_failure_message(result)) from exc
        return result
    finally:
        if owner is not None and proc is not None:
            owner.unregister(proc)
    result = CommandResult(
        args=args, cwd=cwd, returncode=proc.returncode, stdout=stdout, stderr=stderr
    )
    if check and not result.ok:
        raise RuntimeError(_failure_message(result))
    return result


def _validate_argv(args: list[str]) -> None:
    if not args:
        raise ValueError("command arguments must not be empty")
    if not all(isinstance(arg, str) and arg for arg in args):
        raise ValueError("command arguments must be non-empty strings")


class _TrustedProcess(subprocess.Popen[str]):
    def __init__(
        self,
        args: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None,
        text: bool,
        errors: str | None,
        stdout: int,
        stderr: int,
        stdin: int | None,
        start_new_session: bool,
    ) -> None:
        super().__init__(
            args,
            cwd=cwd,
            env=env,
            shell=False,
            text=text,
            errors=errors,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            start_new_session=start_new_session,
        )


def _timeout_text(value: str | bytes | None) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _failure_message(result: CommandResult) -> str:
    return (
        f"command failed with {result.returncode}: {' '.join(result.args)}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def _terminate_process_group(proc: subprocess.Popen[str], sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        return
