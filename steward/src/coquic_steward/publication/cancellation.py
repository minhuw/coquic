"""Cooperative fences for one admitted publication operation."""

from collections.abc import Callable
from contextvars import ContextVar


class PublicationStopped(BaseException):
    """Unwind publication without converting cancellation into a retry/hide."""


publication_checkpoint: ContextVar[Callable[[], None] | None] = ContextVar(
    "publication_checkpoint", default=None
)


def check_publication_active() -> None:
    checkpoint = publication_checkpoint.get()
    if checkpoint is not None:
        checkpoint()


def run_publication_process(
    argv: list[str], *, capture_output: bool, text: bool, timeout: float,
    check: bool, pass_fds: tuple[int, ...], env: dict[str, str],
):
    """Keep scanner/OCR bytes and descriptor passing, but own the process group."""

    import os
    import signal
    import subprocess
    from ..core.subprocesses import current_subprocess_owner

    check_publication_active()
    owner = current_subprocess_owner()
    if publication_checkpoint.get() is None or owner is None:
        return subprocess.run(
            argv, capture_output=capture_output, text=text, timeout=timeout,
            check=check, pass_fds=pass_fds, env=env,
        )
    # Scanner/OCR have one fixed, byte-capturing subprocess contract.
    if not capture_output or text or check:
        raise ValueError("invalid publication process contract")
    with subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds,
        env=env, start_new_session=True,
    ) as process:
        owner.register(process)
        try:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
        finally:
            owner.unregister(process)
    check_publication_active()
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
