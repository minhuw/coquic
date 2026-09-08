from __future__ import annotations

import errno
import io
import os
import select
import subprocess
import sys
import time

import pytest

from coquic_steward.agents.process_stream import (
    ExactTerminationStrategy,
    PostEofWait,
    _write_input,
    drain_process,
)


def test_closed_child_stdin_still_drains_nonzero_exit_and_reaps() -> None:
    stderr = b"model rejected prompt\n" * 8192
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os; os.close(0); os.write(1, b'ready\\n'); "
            "os.write(2, b'model rejected prompt\\n' * 8192); "
            "os.write(1, b'rejected\\n'); raise SystemExit(7)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        try:
            # Synchronize on actual closure, not scheduler timing or prompt size.
            assert select.select((process.stdout,), (), (), 5)[0]
            assert os.read(process.stdout.fileno(), 6) == b"ready\n"
            outcome = drain_process(
                process,
                b"prompt\n",
                stdout_chunks.append,
                stderr_chunks.append,
                5,
                ExactTerminationStrategy(),
                PostEofWait.bounded(),
            )

            assert outcome.exit_code == process.returncode == 7
            assert not outcome.timed_out
            assert not outcome.forced
            assert outcome.reader_error is None
            assert b"".join(stdout_chunks) == b"rejected\n"
            assert b"".join(stderr_chunks) == stderr
            assert stdout_chunks[-1] == stderr_chunks[-1] == b""
            assert process.stdin.closed and process.stdout.closed and process.stderr.closed
            with pytest.raises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("suppress_errors", [False, True])
@pytest.mark.parametrize("operation", ["write", "flush"])
@pytest.mark.parametrize("error_type", [BrokenPipeError, ConnectionResetError])
def test_closed_stdin_errors_are_eof(
    suppress_errors: bool, operation: str, error_type: type[OSError]
) -> None:
    class ClosedStdin(io.BytesIO):
        def write(self, data: bytes) -> int:
            if operation == "write":
                raise error_type("child closed stdin")
            return super().write(data)

        def flush(self) -> None:
            raise error_type("child closed stdin")

    stream = ClosedStdin()
    _write_input(
        stream, b"prompt", deadline=time.monotonic() + 1, suppress_errors=suppress_errors
    )
    assert stream.closed


@pytest.mark.parametrize("operation", ["write", "flush"])
@pytest.mark.parametrize(
    "error", [OSError(errno.EIO, "write failed"), TimeoutError("write timed out")]
)
def test_other_stdin_errors_propagate(operation: str, error: OSError) -> None:
    class FailingStdin(io.BytesIO):
        def write(self, data: bytes) -> int:
            if operation == "write":
                raise error
            return super().write(data)

        def flush(self) -> None:
            raise error

    stream = FailingStdin()
    with pytest.raises(type(error)) as failure:
        _write_input(
            stream, b"prompt", deadline=time.monotonic() + 1, suppress_errors=False
        )
    assert failure.value is error
    assert stream.closed


@pytest.mark.parametrize("suppress_errors", [False, True])
@pytest.mark.parametrize("expired", [False, True])
def test_stdin_write_deadline_is_not_suppressed(
    suppress_errors: bool, expired: bool
) -> None:
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
        # A full pipe exercises select's timeout; an expired deadline never waits.
        os.set_blocking(writer.fileno(), False)
        with pytest.raises(BlockingIOError):
            while True:
                os.write(writer.fileno(), b"x" * 4096)
        os.set_blocking(writer.fileno(), True)
        with pytest.raises(TimeoutError, match="process input write exceeded its deadline"):
            _write_input(
                writer,
                b"prompt",
                deadline=time.monotonic() + (-1 if expired else 0.01),
                suppress_errors=suppress_errors,
            )
        assert writer.closed
        assert not reader.closed


@pytest.mark.parametrize("suppress_errors", [False, True])
def test_stdin_short_write_is_not_suppressed(suppress_errors: bool) -> None:
    class ShortStdin(io.BytesIO):
        def write(self, data: bytes) -> int:
            return super().write(data[:-1])

    stream = ShortStdin()
    with pytest.raises(RuntimeError, match="process stdin accepted a short write"):
        _write_input(
            stream, b"prompt", deadline=time.monotonic() + 1, suppress_errors=suppress_errors
        )
    assert stream.closed
