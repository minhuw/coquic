from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
    command tree.  A process remains registered until ``communicate`` has
    observed its exit, which lets shutdown wait for the worker future's
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
) -> CommandResult:
    _validate_argv(args)
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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else None,
            start_new_session=True,
        )
        if owner is not None:
            owner.register(proc)
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
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
    except subprocess.TimeoutExpired as exc:
        if proc is not None:
            _terminate_process_group(proc, signal.SIGTERM)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_process_group(proc, signal.SIGKILL)
                stdout, stderr = proc.communicate()
        else:
            stdout = _timeout_text(exc.stdout)
            stderr = _timeout_text(exc.stderr)
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
