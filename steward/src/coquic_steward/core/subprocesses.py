from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


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


def run_command(
    args: list[str],
    cwd: Path,
    *,
    check: bool = False,
    input_text: str | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    replace_env: bool = False,
) -> CommandResult:
    proc: subprocess.Popen[str] | None = None
    try:
        process_env = None
        if env is not None:
            if replace_env:
                process_env = env.copy()
            else:
                process_env = os.environ.copy()
                process_env.update(env)
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=process_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else None,
            start_new_session=True,
        )
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
    result = CommandResult(
        args=args, cwd=cwd, returncode=proc.returncode, stdout=stdout, stderr=stderr
    )
    if check and not result.ok:
        raise RuntimeError(_failure_message(result))
    return result


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
