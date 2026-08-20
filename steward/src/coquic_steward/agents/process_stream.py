"""Shared byte-oriented Codex process lifecycle handling.

The adapters own policy-specific decoding and output handling.  This module
owns the process boundary: writing input, draining both output pipes, enforcing
deadlines, terminating the requested process boundary, and reaping readers.
"""

from __future__ import annotations

import io
import os
import queue
import select
import selectors
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol


_STREAM_CHUNK_SIZE = 64 * 1024
_HANDOFF_WAIT_SECONDS = 0.05
_READER_POLL_SECONDS = 0.01
_INPUT_WRITE_MINIMUM_SECONDS = 0.1
_TERMINATION_POLL_SECONDS = 0.01


class _Pipe(Protocol):
    def read(self, size: int) -> bytes | str: ...

    def close(self) -> None: ...

    def fileno(self) -> int: ...

    def write(self, data: bytes | str) -> int: ...

    def flush(self) -> None: ...


class _Process(Protocol):
    stdin: _Pipe | None
    stdout: _Pipe | None
    stderr: _Pipe | None
    returncode: int | None

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def send_signal(self, sig: int) -> None: ...

    def kill(self) -> None: ...


@dataclass(frozen=True)
class DrainOutcome:
    """The process result after all streams and reader threads are cleaned up."""

    exit_code: int
    timed_out: bool = False
    forced: bool = False
    reader_error: Exception | None = None


class PostEofWait:
    """Policy for waiting after both output pipes reach EOF."""

    @classmethod
    def bounded(cls) -> BoundedPostEofWait:
        return BoundedPostEofWait()

    @classmethod
    def unbounded(cls) -> UnboundedPostEofWait:
        return UnboundedPostEofWait()

    def wait(
        self,
        process: _Process,
        *,
        deadline: float,
        terminate: TerminationStrategy,
    ) -> tuple[int, bool, bool]:
        raise NotImplementedError


@dataclass(frozen=True)
class BoundedPostEofWait(PostEofWait):
    """Keep the original deadline active after pipe EOF."""

    def wait(
        self,
        process: _Process,
        *,
        deadline: float,
        terminate: TerminationStrategy,
    ) -> tuple[int, bool, bool]:
        if process.poll() is not None:
            return process.wait(), False, False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exit_code, forced = _terminate_after_deadline(process, terminate)
            return exit_code, True, forced
        try:
            return process.wait(timeout=remaining), False, False
        except (subprocess.TimeoutExpired, TimeoutError):
            exit_code, forced = _terminate_after_deadline(process, terminate)
            return exit_code, True, forced


@dataclass(frozen=True)
class UnboundedPostEofWait(PostEofWait):
    """Wait for natural process exit without applying the pipe deadline."""

    def wait(
        self,
        process: _Process,
        *,
        deadline: float,
        terminate: TerminationStrategy,
    ) -> tuple[int, bool, bool]:
        del deadline, terminate
        return process.wait(), False, False


class TerminationStrategy(Protocol):
    """Terminate one process boundary and return its reaped result."""

    def terminate(self, process: _Process) -> tuple[int, bool]: ...


@dataclass(frozen=True)
class ExactTerminationStrategy:
    """Signal and, after a bounded grace, kill only the exact process."""

    grace_seconds: float = 2.0

    def terminate(self, process: _Process) -> tuple[int, bool]:
        try:
            if process.poll() is not None:
                return process.wait(), False
        except Exception:
            pass

        signal_error: Exception | None = None
        try:
            process.send_signal(signal.SIGTERM)
        except OSError:
            # The process may have exited between poll and signal delivery.
            pass
        except Exception as error:
            signal_error = error

        try:
            exit_code = process.wait(timeout=self.grace_seconds)
        except (subprocess.TimeoutExpired, TimeoutError):
            try:
                process.kill()
            except ProcessLookupError:
                if process.poll() is not None:
                    return process.wait(), True
                raise
            except Exception as error:
                # Do not fall through to an untimed wait when escalation
                # itself failed.  Surface the boundary failure instead.
                if process.poll() is not None:
                    process.wait()
                raise error from signal_error
            exit_code = process.wait()
            if signal_error is not None:
                raise signal_error
            return exit_code, True

        if signal_error is not None:
            raise signal_error
        return exit_code, False


@dataclass(frozen=True)
class GroupTerminationStrategy:
    """Signal a process group, falling back to the process object."""

    grace_seconds: float = 5.0

    def terminate(self, process: _Process) -> tuple[int, bool]:
        pid = getattr(process, "pid", None)
        try:
            if pid is None:
                raise OSError("process has no process-group identity")
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                process.send_signal(signal.SIGTERM)
            except Exception:
                pass

        if pid is None:
            try:
                return process.wait(timeout=self.grace_seconds), False
            except (subprocess.TimeoutExpired, TimeoutError):
                try:
                    process.kill()
                except Exception as error:
                    if process.poll() is not None:
                        return process.wait(), True
                    raise error
                return process.wait(), True

        deadline = time.monotonic() + self.grace_seconds
        while True:
            if process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    process.wait(timeout=min(remaining, _TERMINATION_POLL_SECONDS))
                except (subprocess.TimeoutExpired, TimeoutError):
                    pass
            if not _process_group_exists(pid):
                return process.wait(), False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_TERMINATION_POLL_SECONDS, remaining))

        escalation_error: Exception | None = None
        try:
            if pid is None:
                raise OSError("process has no process-group identity")
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception as error:
                    escalation_error = error
        except Exception:
            try:
                process.kill()
            except Exception as error:
                escalation_error = error

        if escalation_error is not None:
            if process.poll() is not None:
                return process.wait(), True
            raise escalation_error
        return process.wait(), True


def _process_group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


# Explicit aliases make the two process-boundary policies easy to discover.
ExactTermination = ExactTerminationStrategy
GroupTermination = GroupTerminationStrategy
ExactProcessTermination = ExactTerminationStrategy
GroupProcessTermination = GroupTerminationStrategy


@dataclass(frozen=True)
class _PipeReadResult:
    stream_index: int
    kind: str
    data: bytes = b""
    error: Exception | None = None


def drain_process(
    process: _Process,
    input_bytes: bytes,
    stdout_chunk: Callable[[bytes], None],
    stderr_chunk: Callable[[bytes], None],
    timeout_seconds: float,
    terminate: TerminationStrategy,
    post_eof_wait: PostEofWait,
    *,
    suppress_input_errors: bool = False,
) -> DrainOutcome:
    """Drain a process and reap it before returning or exposing an error.

    ``stdout_chunk`` and ``stderr_chunk`` receive raw bytes.  An empty bytes
    callback marks EOF for the corresponding stream.  Callback failures are
    returned in ``reader_error`` only after the process, pipes, and fallback
    readers have been cleaned up.
    """

    streams = _unique_streams(((process.stdout, True), (process.stderr, False)))
    fallback_threads: list[threading.Thread] = []
    fallback_stop = threading.Event()
    selector = selectors.DefaultSelector()
    exit_code: int | None = None
    timed_out = False
    forced = False
    reader_error: Exception | None = None

    input_deadline = time.monotonic() + max(
        _INPUT_WRITE_MINIMUM_SECONDS,
        timeout_seconds,
    )
    try:
        try:
            _write_input(
                process.stdin,
                input_bytes,
                deadline=input_deadline,
                suppress_errors=suppress_input_errors,
            )
        except Exception:
            # Input setup failures are outside the returned reader-error
            # contract, but the child must still be reaped before propagating.
            _reap_after_error(process, terminate)
            raise

        deadline = time.monotonic() + timeout_seconds
        selector_supported = True
        try:
            for stream, is_stdout in streams:
                selector.register(stream, selectors.EVENT_READ, is_stdout)
        except (KeyError, OSError, TypeError, ValueError):
            selector_supported = False

        try:
            if selector_supported:
                (
                    exit_code,
                    timed_out,
                    forced,
                    reader_error,
                ) = _drain_with_selector(
                    process,
                    selector,
                    stdout_chunk,
                    stderr_chunk,
                    deadline=deadline,
                    terminate=terminate,
                    post_eof_wait=post_eof_wait,
                )
            else:
                selector.close()
                (
                    exit_code,
                    timed_out,
                    forced,
                    reader_error,
                ) = _drain_with_fallback(
                    process,
                    streams,
                    stdout_chunk,
                    stderr_chunk,
                    deadline=deadline,
                    terminate=terminate,
                    post_eof_wait=post_eof_wait,
                    reader_threads=fallback_threads,
                    stop=fallback_stop,
                )
        except Exception as error:
            reader_error = error
            exit_code, forced = _reap_after_error(process, terminate)
    finally:
        fallback_stop.set()
        selector.close()
        _close_streams(streams)
        for thread in fallback_threads:
            thread.join()

    if exit_code is None:
        exit_code = _wait_reaped(process)
    return DrainOutcome(
        exit_code=exit_code,
        timed_out=timed_out,
        forced=forced,
        reader_error=reader_error,
    )


def reap_process(
    process: _Process,
    terminate: TerminationStrategy,
) -> tuple[int, bool]:
    """Reap a launched process when adapter setup fails before draining."""

    try:
        return _reap_after_error(process, terminate)
    finally:
        _close_streams(
            (
                (process.stdin, False),
                (process.stdout, True),
                (process.stderr, False),
            )
        )


def _write_input(
    stream: _Pipe | None,
    data: bytes,
    *,
    deadline: float,
    suppress_errors: bool,
) -> None:
    if stream is None:
        return
    try:
        try:
            fileno = stream.fileno()
        except (AttributeError, io.UnsupportedOperation, OSError, ValueError):
            fileno = None
        if fileno is None:
            try:
                written = stream.write(data)
                expected = len(data)
            except TypeError:
                # Keep the direct helper usable with text-wrapped test doubles
                # while production adapters always launch binary pipes.
                encoding = getattr(stream, "encoding", None) or "utf-8"
                text = data.decode(encoding, errors="strict")
                written = stream.write(text)
                expected = len(text)
            if written is not None and written != expected:
                raise RuntimeError("process stdin accepted a short write")
        else:
            offset = 0
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("process input write exceeded its deadline")
                try:
                    _, writable, _ = select.select((), (fileno,), (), remaining)
                except (OSError, ValueError):
                    writable = (fileno,)
                if not writable:
                    raise TimeoutError("process input write exceeded its deadline")
                written = os.write(fileno, data[offset:])
                if written <= 0:
                    raise RuntimeError("process stdin accepted an empty write")
                offset += written
        stream.flush()
    except TimeoutError:
        raise
    except (BrokenPipeError, OSError):
        if not suppress_errors:
            raise
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _unique_streams(
    streams: Iterable[tuple[_Pipe | None, bool]],
) -> tuple[tuple[_Pipe, bool], ...]:
    unique: list[tuple[_Pipe, bool]] = []
    seen: set[int] = set()
    for stream, is_stdout in streams:
        if stream is None or id(stream) in seen:
            continue
        seen.add(id(stream))
        unique.append((stream, is_stdout))
    return tuple(unique)


def _close_streams(streams: Iterable[tuple[_Pipe, bool]]) -> None:
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


def _wait_reaped(process: _Process) -> int:
    return process.wait()


def _reap_after_error(
    process: _Process,
    terminate: TerminationStrategy,
) -> tuple[int, bool]:
    try:
        return terminate.terminate(process)
    except Exception as termination_error:
        # Preserve the original adapter error while making a bounded best
        # effort to close the process boundary.  If the fallback escalation
        # fails, do not wait indefinitely for a process that is still live.
        try:
            process.kill()
        except ProcessLookupError:
            if process.poll() is not None:
                return process.wait(), True
            raise termination_error
        except Exception as kill_error:
            if process.poll() is not None:
                process.wait()
            raise kill_error from termination_error
        return process.wait(), True


def _terminate_after_deadline(
    process: _Process,
    terminate: TerminationStrategy,
) -> tuple[int, bool]:
    return terminate.terminate(process)


def _wait_after_eof(
    process: _Process,
    *,
    deadline: float,
    terminate: TerminationStrategy,
    post_eof_wait: PostEofWait,
) -> tuple[int, bool, bool]:
    return post_eof_wait.wait(
        process,
        deadline=deadline,
        terminate=terminate,
    )


def _handle_chunk(
    stream_index: int,
    data: bytes,
    streams: tuple[tuple[_Pipe, bool], ...],
    stdout_chunk: Callable[[bytes], None],
    stderr_chunk: Callable[[bytes], None],
) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise TypeError("process streams must return bytes")
    if streams[stream_index][1]:
        stdout_chunk(data)
    else:
        stderr_chunk(data)


def _drain_with_selector(
    process: _Process,
    selector: selectors.BaseSelector,
    stdout_chunk: Callable[[bytes], None],
    stderr_chunk: Callable[[bytes], None],
    *,
    deadline: float,
    terminate: TerminationStrategy,
    post_eof_wait: PostEofWait,
) -> tuple[int, bool, bool, Exception | None]:
    stream_infos = tuple(
        (key.fileobj, bool(key.data)) for key in selector.get_map().values()
    )
    stream_by_identity = {id(stream): info for stream, info in stream_infos}
    timed_out = False
    forced = False
    reader_error: Exception | None = None

    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exit_code, forced = _terminate_after_deadline(process, terminate)
            return exit_code, True, forced, reader_error
        try:
            ready = selector.select(min(0.25, remaining))
        except (OSError, ValueError):
            ready = ()
        for key, _ in ready:
            stream = key.fileobj
            if id(stream) not in stream_by_identity:
                continue
            stream_index = next(
                index
                for index, (candidate, _) in enumerate(stream_infos)
                if candidate is stream
            )
            try:
                try:
                    chunk = os.read(stream.fileno(), _STREAM_CHUNK_SIZE)
                except (AttributeError, io.UnsupportedOperation):
                    chunk = stream.read(_STREAM_CHUNK_SIZE)
            except (OSError, ValueError) as error:
                reader_error = error
                exit_code, forced = _reap_after_error(process, terminate)
                return exit_code, timed_out, forced, reader_error
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            if not chunk:
                try:
                    selector.unregister(stream)
                except (KeyError, OSError, ValueError):
                    pass
                try:
                    _handle_chunk(
                        stream_index,
                        b"",
                        stream_infos,
                        stdout_chunk,
                        stderr_chunk,
                    )
                except Exception as error:
                    reader_error = error
                    exit_code, forced = _reap_after_error(process, terminate)
                    return exit_code, timed_out, forced, reader_error
                continue
            try:
                _handle_chunk(
                    stream_index,
                    chunk,
                    stream_infos,
                    stdout_chunk,
                    stderr_chunk,
                )
            except Exception as error:
                reader_error = error
                exit_code, forced = _reap_after_error(process, terminate)
                return exit_code, timed_out, forced, reader_error

    exit_code, timed_out, forced = _wait_after_eof(
        process,
        deadline=deadline,
        terminate=terminate,
        post_eof_wait=post_eof_wait,
    )
    return exit_code, timed_out, forced, reader_error


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
    stream: _Pipe,
    stream_index: int,
    handoff: queue.Queue[_PipeReadResult],
    stop: threading.Event,
) -> None:
    try:
        try:
            fileno = stream.fileno()
        except (AttributeError, io.UnsupportedOperation, OSError, ValueError):
            fileno = None
        if fileno is None:
            while not stop.is_set():
                data = stream.read(_STREAM_CHUNK_SIZE)
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not isinstance(data, bytes):
                    raise TypeError("process streams must return bytes")
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
            ready, _, _ = select.select((fileno,), (), (), _READER_POLL_SECONDS)
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
    process: _Process,
    streams: tuple[tuple[_Pipe, bool], ...],
    stdout_chunk: Callable[[bytes], None],
    stderr_chunk: Callable[[bytes], None],
    *,
    deadline: float,
    terminate: TerminationStrategy,
    post_eof_wait: PostEofWait,
    reader_threads: list[threading.Thread],
    stop: threading.Event,
) -> tuple[int, bool, bool, Exception | None]:
    handoff: queue.Queue[_PipeReadResult] = queue.Queue(maxsize=max(1, len(streams)))
    threads = tuple(
        threading.Thread(
            target=_read_pipe,
            args=(stream, index, handoff, stop),
            daemon=False,
            name=f"process-stream-{index}",
        )
        for index, (stream, _) in enumerate(streams)
    )
    for thread in threads:
        thread.start()
        reader_threads.append(thread)

    completed: set[int] = set()
    exit_code: int | None = None
    timed_out = False
    forced = False
    reader_error: Exception | None = None
    try:
        while len(completed) < len(streams):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exit_code, forced = _terminate_after_deadline(process, terminate)
                timed_out = True
                break
            try:
                result = handoff.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if result.kind == "data":
                try:
                    _handle_chunk(
                        result.stream_index,
                        result.data,
                        streams,
                        stdout_chunk,
                        stderr_chunk,
                    )
                except Exception as error:
                    reader_error = error
                    stop.set()
                    exit_code, forced = _reap_after_error(process, terminate)
                    break
            elif result.kind == "eof":
                completed.add(result.stream_index)
                try:
                    _handle_chunk(
                        result.stream_index,
                        b"",
                        streams,
                        stdout_chunk,
                        stderr_chunk,
                    )
                except Exception as error:
                    reader_error = error
                    stop.set()
                    exit_code, forced = _reap_after_error(process, terminate)
                    break
            elif result.kind == "error":
                completed.add(result.stream_index)
                reader_error = result.error or RuntimeError(
                    "process stream reader failed"
                )
                stop.set()
                exit_code, forced = _reap_after_error(process, terminate)
                break
    finally:
        stop.set()

    if reader_error is None and exit_code is None:
        exit_code, timed_out, forced = _wait_after_eof(
            process,
            deadline=deadline,
            terminate=terminate,
            post_eof_wait=post_eof_wait,
        )
    elif exit_code is None:
        exit_code = _wait_reaped(process)
    return exit_code, timed_out, forced, reader_error
