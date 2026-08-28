from __future__ import annotations

import io
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.agents import CodexRunner
from coquic_steward.agents.diagnostics import diagnostics_for_paths
from coquic_steward.agents.invocation import (
    InvocationOutcome,
    InvocationRequest,
    JsonlStream,
    stream_process,
)
from coquic_steward.agents.runner import _is_transient_codex_message
from coquic_steward.agents.tool_changes import ToolChangeCapture
from coquic_steward.core.config import StewardConfig, StewardLimits
from coquic_steward.core.models import (
    CodexStage,
    ProjectSignals,
    TaskKind,
    TaskSpec,
    WorkerKind,
)
from coquic_steward.execution import ResumeCategory, SessionSupervisor
from coquic_steward.execution.container import (
    ContainerInspection,
    ExecIdentity,
    SubprocessDockerClient,
    TaskContainerRuntime,
)
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import (
    FreshPlannerSession,
    LocalSessionInvoker,
    _ActiveInvocation,
    runtime_factory_for_config,
)
from coquic_steward.planning.planner import CodexPlanner, planner_schema_path
from coquic_steward.storage import TaskStore


class FakeInvoker(LocalSessionInvoker):
    def __init__(self) -> None:
        super().__init__()
        self.requests = []

    def invoke(
        self,
        request,
        *,
        api_key,
        append,
        observe,
        on_started,
        timeout_seconds,
        interrupt_grace_seconds,
        launch_gate=None,
    ):
        assert api_key == "fake-key"
        self.requests.append(request)
        on_started(ExecIdentity("fake", request.run_id, 4321, request.session_uid))
        line = b'{"thread_id":"provider-session"}\n'
        append(line)
        observe({"thread_id": "provider-session"})
        request.output_last_message.parent.mkdir(parents=True, exist_ok=True)
        request.output_last_message.write_text("done\n", encoding="utf-8")
        return InvocationOutcome(
            exit_code=0,
            stdout=line,
            stderr=b"",
            incomplete_suffix=b"",
            events=({"thread_id": "provider-session"},),
            provider_session_id="provider-session",
        )


class InterruptedInvoker(FakeInvoker):
    def invoke(
        self,
        request,
        *,
        api_key,
        append,
        observe,
        on_started,
        timeout_seconds,
        interrupt_grace_seconds,
        launch_gate=None,
    ):
        outcome = super().invoke(
            request,
            api_key=api_key,
            append=append,
            observe=observe,
            on_started=on_started,
            timeout_seconds=timeout_seconds,
            interrupt_grace_seconds=interrupt_grace_seconds,
            launch_gate=launch_gate,
        )
        return InvocationOutcome(
            exit_code=130,
            stdout=outcome.stdout,
            stderr=b"",
            incomplete_suffix=b"partial",
            events=outcome.events,
            provider_session_id=outcome.provider_session_id,
            interrupted=True,
        )


def _interrupted_session(config: StewardConfig, checkpoint_id: str | None):
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=InterruptedInvoker(),
        image_digest="sha256:" + "a" * 64,
    )
    first = supervisor.start(
        task.id,
        pipeline.id,
        role="implementation",
        prompt="do work",
        cwd=config.repo_root,
        api_key="fake-key",
        checkpoint_id=checkpoint_id,
    )
    predecessor = store.get_run(first.run_id)
    session = store.get_session(first.session_id)
    assert session.private_home_path is not None
    (session.private_home_path / "sessions" / "provider.json").write_text("{}")
    supervisor.invoker = FakeInvoker()
    return store, supervisor, predecessor, session


def test_fresh_session_has_private_home_uid_and_no_auth(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    invoker = FakeInvoker()
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=invoker,
        image_digest="sha256:" + "a" * 64,
    )
    result = supervisor.start(
        task.id,
        pipeline.id,
        role="implementation",
        prompt="do work",
        cwd=config.repo_root,
        api_key="fake-key",
    )
    session = store.get_session(result.session_id)
    run = store.get_run(result.run_id)
    assert result.status.value == "succeeded"
    assert session.home_uid is not None
    assert session.private_home_path is not None
    assert not (session.private_home_path / "auth.json").exists()
    assert result.transcript_path.read_bytes() == b'{"thread_id":"provider-session"}\n'
    assert run.wrapper_pid == 4321
    assert run.exec_identity == run.id
    assert invoker.requests[0].output_last_message.parent == session.private_home_path


def test_resume_requires_exact_provider_id_and_links_new_run(config: StewardConfig) -> None:
    store, supervisor, predecessor, _ = _interrupted_session(
        config, "checkpoint-one"
    )
    resumed = supervisor.resume(
        predecessor.id,
        prompt="continue",
        api_key="fake-key",
        checkpoint_id="checkpoint-one",
    )
    assert resumed.category is ResumeCategory.success
    assert resumed.result is not None
    assert resumed.result.run_id != predecessor.id
    assert store.get_run(resumed.result.run_id).resume_of_run_id == predecessor.id


@pytest.mark.parametrize(
    ("persisted_checkpoint", "current_checkpoint"),
    [
        ("checkpoint-one", None),
        ("checkpoint-one", ""),
        (None, "checkpoint-one"),
        ("checkpoint-one", "checkpoint-two"),
    ],
)
def test_resume_rejects_missing_ambiguous_or_mismatched_checkpoint(
    config: StewardConfig,
    persisted_checkpoint: str | None,
    current_checkpoint: str | None,
) -> None:
    store, supervisor, predecessor, _ = _interrupted_session(
        config, persisted_checkpoint
    )
    resumed = supervisor.resume(
        predecessor.id,
        prompt="continue",
        api_key="fake-key",
        checkpoint_id=current_checkpoint,
    )
    assert resumed.category is ResumeCategory.checkpoint_drift
    assert len(store.list_runs(predecessor.task_id)) == 1


def test_jsonl_stream_preserves_invalid_bytes_and_incomplete_suffix() -> None:
    records: list[bytes] = []
    stream = JsonlStream(records.append)
    stream.feed(b"\xff\xfe\n{" + b"x" * 10000 + b"}\npartial")
    assert records[0] == b"\xff\xfe\n"
    assert records[1].endswith(b"}\n")
    assert stream.finish() == b"partial"


def test_runtime_factory_is_scoped_per_task(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    first, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="one", prompt="p")
    )
    second, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="two", prompt="p")
    )
    created = []

    def factory(task):
        root = config.private_dir / "runtime-factory" / task.id
        roots = {
            name: root / name
            for name in ("archive", "sessions", "git", "common", "scratch")
        }
        for path in roots.values():
            path.mkdir(parents=True, exist_ok=True)
        runtime = TaskContainerRuntime(
            TaskContainerConfig(
                task_id=task.id,
                image="coquic-steward-task",
                image_digest="sha256:" + "a" * 64,
                worktree=config.repo_root,
                archive=roots["archive"],
                private_sessions=roots["sessions"],
                git_dir=roots["git"],
                git_common_dir=roots["common"],
                scratch=roots["scratch"],
            ),
            client=SubprocessDockerClient(),
        )
        created.append((task.id, runtime))
        return runtime

    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=factory,
        image_digest="sha256:" + "a" * 64,
    )
    first_runtime, _ = supervisor._boundary_for(first)
    second_runtime, _ = supervisor._boundary_for(second)
    repeated_runtime, _ = supervisor._boundary_for(first)
    assert first_runtime is repeated_runtime
    assert first_runtime is not second_runtime
    assert [task_id for task_id, _ in created] == [first.id, second.id]


def test_task_session_mount_root_is_traversable_by_allocated_uids(
    config: StewardConfig, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    task.worktree_path = config.repo_root
    store.save(task)
    configured = replace(
        config,
        task_image_digest="sha256:" + "a" * 64,
    )
    monkeypatch.setattr(
        "coquic_steward.execution.session._provision_group_tree",
        lambda _root, _gid: None,
    )
    runtime = runtime_factory_for_config(configured)(store.get(task.id))
    mode = stat.S_IMODE(runtime.config.private_sessions.stat().st_mode)
    assert mode == 0o711


def test_inspect_and_interrupt_recover_persisted_container_identity(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    session, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="persisted-session",
        private_home_path=config.private_sessions_dir / task.id / "persisted-session",
        private_home_relative_path=f"{task.id}/persisted-session",
        image_digest="sha256:" + "a" * 64,
        codex_identity="codex-0.144.6",
        cwd=config.repo_root,
        checkpoint_id="checkpoint-one",
        provider_store_identity="codex-sessions-v1",
        owner_role="implementation",
        session_idempotency_key=None,
        role="implementation",
        model=None,
        reasoning=None,
        image_version="sha256:" + "a" * 64,
        runtime_version="task-runtime-v1",
        run_checkpoint_id="checkpoint-one",
        run_provider_store_identity="codex-sessions-v1",
    )
    store.update_run(run.id, wrapper_pid=4321, exec_identity="docker-exec-one")

    class RecoverableRuntime(TaskContainerRuntime):
        def __init__(self) -> None:
            roots = {
                name: config.private_dir / "recoverable-runtime" / name
                for name in ("archive", "sessions", "git", "common", "scratch")
            }
            for path in roots.values():
                path.mkdir(parents=True, exist_ok=True)
            super().__init__(
                TaskContainerConfig(
                    task_id=task.id,
                    image="coquic-steward-task",
                    image_digest="sha256:" + "a" * 64,
                    worktree=config.repo_root,
                    archive=roots["archive"],
                    private_sessions=roots["sessions"],
                    git_dir=roots["git"],
                    git_common_dir=roots["common"],
                    scratch=roots["scratch"],
                ),
                client=SubprocessDockerClient(),
            )
            self.probed = None
            self.live = True
            self.signals = []
            self.stopped = False

        def inspect(self):
            return ContainerInspection(
                container_id="container-id",
                name=self.config.container_name,
                state="running",
                running=True,
                labels={},
            )

        def exec_is_live(self, identity):
            self.probed = identity
            if self.signals and self.signals[-1][1] == signal.SIGKILL:
                assert store.get_run(run.id).state == "running"
            return self.live

        def signal(self, identity, sig):
            self.signals.append((identity, sig))
            if sig == signal.SIGKILL:
                self.live = False

        def stop(self, container_id=None, *, timeout=None):
            self.stopped = True

    created = []

    def factory(_task):
        runtime = RecoverableRuntime()
        created.append(runtime)
        return runtime

    restarted = SessionSupervisor(
        config,
        store,
        runtime_factory=factory,
        image_digest="sha256:" + "a" * 64,
    )
    inspection = restarted.inspect(run.id)
    expected = ExecIdentity(
        f"coquic-steward-task-{task.id}",
        "docker-exec-one",
        4321,
        session.home_uid,
    )
    assert inspection.live
    assert inspection.identity == expected
    assert created[0].probed == expected

    interrupted = restarted.interrupt(run.id, grace_seconds=0)
    assert interrupted.forced
    assert interrupted.status.value == "forced"
    assert created[0].signals == [
        (expected, signal.SIGTERM),
        (expected, signal.SIGKILL),
    ]
    assert created[0].probed == expected
    assert not created[0].live
    assert not created[0].stopped
    assert created[0].inspect().running
    persisted = store.get_run(run.id)
    assert persisted.state == "interrupted"
    assert persisted.exit_reason == "forced termination"


def test_interrupt_uses_invoker_process_during_active_publication(
    config: StewardConfig,
) -> None:
    class Store:
        def mark_run_interrupted(self, run_id, *, reason):
            self.reason = reason
            return SimpleNamespace(exit_code=143)

    class LiveProcess:
        def __init__(self) -> None:
            self.signals: list[int] = []
            self.waits: list[float] = []
            self.kills = 0

        def send_signal(self, sig: int) -> None:
            self.signals.append(sig)

        def wait(self, timeout: float | None = None) -> None:
            assert timeout is not None
            self.waits.append(timeout)
            raise subprocess.TimeoutExpired(["codex"], timeout)

        def kill(self) -> None:
            self.kills += 1

    store = Store()
    invoker = LocalSessionInvoker()
    process = LiveProcess()
    invoker.process = process
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=invoker,
        image_digest="sha256:" + "a" * 64,
    )
    supervisor._active["run-one"] = _ActiveInvocation(invoker, None)

    result = supervisor.interrupt("run-one", grace_seconds=0.25)

    assert process.signals == [signal.SIGTERM]
    assert process.waits == [0.25]
    assert process.kills == 1
    assert result.forced
    assert result.status.value == "forced"
    assert store.reason == "forced termination"


def test_interrupt_does_not_treat_runtime_probe_failure_as_process_exit(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    private_sessions = config.private_sessions_dir / task.id
    archive = config.tasks_dir / task.id
    scratch = config.private_dir / "task-scratch" / task.id
    for path in (private_sessions, archive, scratch):
        path.mkdir(parents=True, exist_ok=True)
    runtime_config = TaskContainerConfig(
        task_id=task.id,
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        worktree=config.repo_root,
        archive=archive,
        private_sessions=private_sessions,
        git_dir=config.repo_root / ".git",
        git_common_dir=config.repo_root / ".git",
        scratch=scratch,
    )
    session, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="persisted-session",
        private_home_path=private_sessions / "persisted-session",
        private_home_relative_path=f"{task.id}/persisted-session",
        image_digest=runtime_config.image_digest,
        codex_identity="codex-0.144.6",
        cwd=config.repo_root,
        checkpoint_id="checkpoint-one",
        provider_store_identity="codex-sessions-v1",
        owner_role="implementation",
        session_idempotency_key=None,
        role="implementation",
        model=None,
        reasoning=None,
        image_version=runtime_config.image_digest,
        runtime_version="task-runtime-v1",
        run_checkpoint_id="checkpoint-one",
        run_provider_store_identity="codex-sessions-v1",
    )
    store.update_run(run.id, wrapper_pid=4321, exec_identity="docker-exec-one")

    class TransientDockerFailure(SubprocessDockerClient):
        def __init__(self) -> None:
            self.live = True
            self.signals: list[int] = []
            self.live_when_probe_failed = False

        def run(
            self,
            argv,
            *,
            input=None,
            timeout=None,
            max_output_bytes=None,
        ):
            signal_value = int(
                next(
                    argv[index + 1].split("=", 1)[1]
                    for index, value in enumerate(argv)
                    if value == "--env"
                    and argv[index + 1].startswith("COQUIC_STEWARD_SIGNAL=")
                )
            )
            self.signals.append(signal_value)
            if signal_value == signal.SIGTERM:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if signal_value == 0 and len(self.signals) == 2:
                self.live_when_probe_failed = self.live
                return subprocess.CompletedProcess(
                    argv,
                    1,
                    b"",
                    b"Cannot connect to the Docker daemon",
                )
            if signal_value == signal.SIGKILL:
                self.live = False
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if signal_value == 0 and not self.live:
                return subprocess.CompletedProcess(
                    argv, 1, b"", b"/bin/kill: (4321): No such process"
                )
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    client = TransientDockerFailure()
    runtime = TaskContainerRuntime(runtime_config, client=client)
    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=lambda _task: runtime,
        image_digest=runtime_config.image_digest,
    )
    interrupted = supervisor.interrupt(run.id, grace_seconds=0)
    assert client.live_when_probe_failed
    assert client.signals == [signal.SIGTERM, 0, signal.SIGKILL, 0]
    assert interrupted.forced
    persisted = store.get_run(run.id)
    assert persisted.state == "interrupted"
    assert persisted.exit_reason == "forced termination"
    assert session.home_uid is not None


class _CompletedProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"") -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.stdin = io.BytesIO()
        self.returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def send_signal(self, sig):
        self.returncode = 128 + sig

    def kill(self):
        self.returncode = 137


class _BarrierPipe:
    def __init__(self, barrier: threading.Barrier, payload: bytes) -> None:
        self._barrier = barrier
        self._payload = payload
        self._reads = 0
        self.reader_threads: list[threading.Thread] = []
        self.close_calls = 0

    def fileno(self) -> int:
        raise io.UnsupportedOperation("selector unsupported")

    def read(self, _size: int) -> bytes:
        self.reader_threads.append(threading.current_thread())
        if self._reads == 0:
            self._reads += 1
            self._barrier.wait(timeout=1)
            return self._payload
        return b""

    def close(self) -> None:
        self.close_calls += 1


class _HeldOpenPipe:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.closed = threading.Event()
        self.reader_threads: list[threading.Thread] = []
        self.close_calls = 0

    def fileno(self) -> int:
        raise io.UnsupportedOperation("selector unsupported")

    def read(self, _size: int) -> bytes:
        self.reader_threads.append(threading.current_thread())
        self.started.set()
        self.closed.wait()
        return b""

    def close(self) -> None:
        self.close_calls += 1
        self.closed.set()


class _ErrorPipe:
    def __init__(self) -> None:
        self._reads = 0
        self.reader_threads: list[threading.Thread] = []
        self.close_calls = 0

    def fileno(self) -> int:
        raise io.UnsupportedOperation("selector unsupported")

    def read(self, _size: int) -> bytes:
        self.reader_threads.append(threading.current_thread())
        self._reads += 1
        if self._reads == 1:
            return b'{"type":"prefix"}\n'
        raise OSError("reader failed")

    def close(self) -> None:
        self.close_calls += 1


class _FallbackProcess:
    def __init__(self, stdout, stderr, *, live: bool = False, graceful: bool = False):
        self.stdout = stdout
        self.stderr = stderr
        self.stdin = io.BytesIO()
        self.returncode = None if live else 0
        self.signals: list[int] = []
        self.kill_calls = 0
        self._graceful = graceful
        self._exited = threading.Event()
        if not live:
            self._exited.set()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self._exited.wait(timeout):
            raise subprocess.TimeoutExpired(["fake"], timeout)
        assert self.returncode is not None
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)
        if self._graceful:
            self.returncode = 143
            self._exited.set()

    def kill(self):
        self.kill_calls += 1
        self.returncode = 137
        self._exited.set()


def _request(tmp_path: Path) -> InvocationRequest:
    return InvocationRequest(
        codex_bin="codex",
        cwd=tmp_path,
        prompt="prompt",
        output_last_message=tmp_path / "last.md",
        stage=CodexStage.code,
    )


def test_fallback_drains_stdout_and_stderr_concurrently(tmp_path: Path) -> None:
    barrier = threading.Barrier(2)
    line = b'{"type":"item.completed"}\n'
    stdout = _BarrierPipe(barrier, line * 10000 + b"partial")
    stderr = _BarrierPipe(barrier, b"x" * 100000)
    records: list[bytes] = []
    events: list[dict] = []

    outcome = stream_process(
        _FallbackProcess(stdout, stderr),
        _request(tmp_path),
        append=records.append,
        observe=events.append,
        timeout_seconds=1,
    )

    assert len(records) == 10000
    assert len(events) == 10000
    assert outcome.incomplete_suffix == b"partial"
    assert len(outcome.stderr) == 64 * 1024
    assert stdout.close_calls == 1
    assert stderr.close_calls == 1
    threads = {*stdout.reader_threads, *stderr.reader_threads}
    assert len(threads) == 2
    assert all(not thread.daemon and not thread.is_alive() for thread in threads)


def test_fallback_deadline_escalates_and_joins_open_readers(tmp_path: Path) -> None:
    stdout = _HeldOpenPipe()
    stderr = _HeldOpenPipe()
    process = _FallbackProcess(stdout, stderr, live=True)
    started = time.monotonic()

    outcome = stream_process(
        process,
        _request(tmp_path),
        append=lambda _chunk: None,
        timeout_seconds=0.05,
        interrupt_grace_seconds=0.02,
    )

    assert time.monotonic() - started < 1
    assert process.signals == [signal.SIGTERM]
    assert process.kill_calls == 1
    assert outcome.exit_code == 137
    assert outcome.interrupted
    assert outcome.forced
    assert stdout.close_calls == 1
    assert stderr.close_calls == 1
    threads = {*stdout.reader_threads, *stderr.reader_threads}
    assert len(threads) == 2
    assert all(not thread.daemon and not thread.is_alive() for thread in threads)


def test_fallback_deadline_honors_graceful_termination(tmp_path: Path) -> None:
    stdout = _HeldOpenPipe()
    stderr = _HeldOpenPipe()
    process = _FallbackProcess(stdout, stderr, live=True, graceful=True)

    outcome = stream_process(
        process,
        _request(tmp_path),
        append=lambda _chunk: None,
        timeout_seconds=0.05,
        interrupt_grace_seconds=0.2,
    )

    assert process.signals == [signal.SIGTERM]
    assert process.kill_calls == 0
    assert outcome.exit_code == 143
    assert outcome.interrupted
    assert not outcome.forced


def test_fallback_shared_stream_is_read_and_closed_once(tmp_path: Path) -> None:
    stream = _HeldOpenPipe()
    process = _FallbackProcess(stream, stream, live=True)

    outcome = stream_process(
        process,
        _request(tmp_path),
        append=lambda _chunk: None,
        timeout_seconds=0.05,
        interrupt_grace_seconds=0.02,
    )

    assert outcome.interrupted
    assert stream.close_calls == 1
    assert len(stream.reader_threads) == 1
    assert not stream.reader_threads[0].daemon
    assert not stream.reader_threads[0].is_alive()


def test_fallback_reader_error_is_raised_after_cleanup(tmp_path: Path) -> None:
    stdout = _ErrorPipe()
    records: list[bytes] = []

    with pytest.raises(OSError, match="reader failed"):
        stream_process(
            _FallbackProcess(stdout, io.BytesIO()),
            _request(tmp_path),
            append=records.append,
            timeout_seconds=1,
        )

    assert records == [b'{"type":"prefix"}\n']
    assert stdout.close_calls == 1
    threads = {*stdout.reader_threads}
    assert len(threads) == 1
    assert all(not thread.daemon and not thread.is_alive() for thread in threads)


def test_fallback_real_pipe_readers_stop_when_descendant_keeps_writers(
    tmp_path: Path, monkeypatch
) -> None:
    class UnsupportedSelector(selectors.SelectSelector):
        def register(self, *_args, **_kwargs):
            raise TypeError("selector unsupported")

    monkeypatch.setattr(selectors, "DefaultSelector", UnsupportedSelector)
    descendant_pid_path = tmp_path / "descendant.pid"
    child_code = (
        "import pathlib, signal, subprocess, sys, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "descendant = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(1)']); "
        f"pathlib.Path({str(descendant_pid_path)!r}).write_text(str(descendant.pid)); "
        "time.sleep(10)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    started = time.monotonic()
    try:
        outcome = stream_process(
            process,
            _request(tmp_path),
            append=lambda _chunk: None,
            timeout_seconds=0.05,
            interrupt_grace_seconds=0.02,
        )
        elapsed = time.monotonic() - started
    finally:
        if descendant_pid_path.exists():
            try:
                os.kill(int(descendant_pid_path.read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass

    assert elapsed < 0.5
    assert outcome.interrupted
    assert outcome.forced
    assert process.poll() is not None


def test_streaming_result_does_not_retain_complete_stdout(tmp_path: Path) -> None:
    line = b'{"type":"item.completed"}\n'
    records = []
    events = []
    request = InvocationRequest(
        codex_bin="codex",
        cwd=tmp_path,
        prompt="prompt",
        output_last_message=tmp_path / "last.md",
        stage=CodexStage.code,
    )
    outcome = stream_process(
        _CompletedProcess(line * 10000 + b"partial", b"x" * 100000),
        request,
        append=records.append,
        observe=events.append,
        timeout_seconds=1,
    )
    assert len(records) == 10000
    assert len(events) == 10000
    assert outcome.stdout == b""
    assert outcome.events == ()
    assert outcome.incomplete_suffix == b"partial"
    assert len(outcome.stderr) == 64 * 1024


def test_signal_planner_uses_fresh_session_run_and_private_lineage(
    config: StewardConfig,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        StewardConfig,
        "read_codex_api_key_bytes",
        lambda _config: "fake-key",
    )

    class PlannerInvoker(LocalSessionInvoker):
        def __init__(self) -> None:
            super().__init__()
            self.requests = []

        def invoke(
            self,
            request,
            *,
            api_key,
            append,
            timeout_seconds,
            interrupt_grace_seconds,
            launch_gate=None,
        ):
            assert api_key == "fake-key"
            self.requests.append(request)
            line = b'{"thread_id":"provider-session"}\n'
            append(line)
            request.output_last_message.write_text(
                '{"consumed_item_ids":[],"tasks":[]}\n', encoding="utf-8"
            )
            return InvocationOutcome(
                exit_code=0,
                stdout=line,
                stderr=b"",
                incomplete_suffix=b"",
                events=({"thread_id": "provider-session"},),
                provider_session_id="provider-session",
            )

    invoker = PlannerInvoker()
    session = FreshPlannerSession(config, invoker=invoker)
    planner = CodexPlanner(config, invocation=session)
    first = planner.run(
        ProjectSignals(repository="minhuw/coquic"),
        [],
        run_id="planner-run-one",
    )
    second = planner.run(
        ProjectSignals(repository="minhuw/coquic"),
        [],
        run_id="planner-run-two",
    )

    assert first.completed
    assert second.completed
    assert first.planned == []
    assert second.planned == []
    assert first.thread_id is None
    assert second.thread_id is None
    assert [first.run_id, second.run_id] == [
        "planner-run-one",
        "planner-run-two",
    ]
    assert first.transcript_path != second.transcript_path
    assert first.transcript_path.parent != second.transcript_path.parent
    assert [request.run_id for request in invoker.requests] == [
        "planner-run-one",
        "planner-run-two",
    ]
    assert len({request.session_id for request in invoker.requests}) == 2
    assert len({request.session_uid for request in invoker.requests}) == 2
    assert all(request.provider_session_id is None for request in invoker.requests)
    assert all(request.output_schema is not None for request in invoker.requests)
    assert all(
        request.output_schema.read_bytes() == planner_schema_path(config).read_bytes()
        for request in invoker.requests
    )
    assert all(
        request.output_last_message.parent == planner_run.transcript_path.parent
        for request, planner_run in zip(invoker.requests, (first, second), strict=True)
    )
    assert all(
        planner_run.transcript_path.read_bytes()
        == b'{"thread_id":"provider-session"}\n'
        for planner_run in (first, second)
    )
    assert all(
        planner_run.transcript_path.parent == planner_run.prompt_path.parent
        for planner_run in (first, second)
    )


def test_production_construction_rejects_local_codex_fallback(
    config: StewardConfig,
) -> None:
    production = replace(
        config,
        local_codex_test_harness=False,
        task_image_digest=None,
    )
    store = TaskStore.create(production.db_path)
    with pytest.raises(ValueError, match="task-container"):
        StewardExecutor(production, store)
    with pytest.raises(ValueError, match="task-container"):
        CodexPlanner(production)

def test_codex_planner_selects_explicit_runner_boundaries(
    config: StewardConfig,
) -> None:
    default_planner = CodexPlanner(config)
    assert isinstance(default_planner.runner, CodexRunner)

    explicit_runner = CodexRunner(config)
    explicit_planner = CodexPlanner(config, runner=explicit_runner)
    assert explicit_planner.runner is explicit_runner

    class MethodLookalike:
        def run(self, *_args, **_kwargs):
            raise AssertionError("unsupported planner lookalike was invoked")

    class NestedRunner:
        def __init__(self) -> None:
            self.runner = explicit_runner

    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=MethodLookalike())
    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=NestedRunner())

    supervisor = SessionSupervisor(
        config,
        TaskStore.create(config.db_path),
        require_boundary=False,
    )
    with pytest.raises(TypeError, match="FreshPlannerSession"):
        CodexPlanner(config, invocation=supervisor)
    with pytest.raises(ValueError, match="either runner or invocation"):
        CodexPlanner(
            config,
            runner=explicit_runner,
            invocation=FreshPlannerSession(config),
        )

def test_codex_runner_places_resume_options_before_session(
    config: StewardConfig, tmp_path: Path
) -> None:
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_model": "gpt-5.6-terra",
            "codex_reasoning_effort": "medium",
        }
    )
    runner = CodexRunner(config)
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")
    last_message = tmp_path / "last.md"

    args = runner._args(
        config.repo_root,
        last_message,
        output_schema=schema,
        resume_session="planner-thread-1",
    )

    assert args[:3] == [config.codex_bin, "exec", "resume"]
    assert args[-2:] == ["planner-thread-1", "-"]
    assert args.index("--output-schema") < args.index("planner-thread-1")
    assert args[args.index("--model") + 1] == "gpt-5.6-terra"
    assert 'model_reasoning_effort="medium"' in args
    assert args.index("--config") < args.index("planner-thread-1")
    assert "--cd" not in args
    assert "--sandbox" not in args

def test_codex_runner_review_uses_structured_exec(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{tmp_path / "args.txt"}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'printf \'{"verdict":"approve","summary":"ok","findings":[],"validation_gaps":[],"remaining_risk":""}\\n\' > "$last"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    runner = CodexRunner(config)
    task, _ = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = runner.run_review(task, "review prompt", config.repo_root, output_schema=schema)
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").splitlines()

    assert result.completed
    assert args[:2] == ["exec", "--json"]
    assert "review" not in args
    assert args[-1] == "-"
    assert args.index("--cd") < args.index("--output-last-message")
    assert "--skip-git-repo-check" not in args
    assert "/reviewer/" in args[args.index("--output-last-message") + 1]
    assert args[args.index("--output-schema") + 1] == str(schema)

def test_codex_review_failure_uses_stderr_summary(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'printf "error: bad review invocation\\n" >&2\n'
        "exit 2\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task, _ = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = CodexRunner(config).run_review(task, "review prompt", config.repo_root, output_schema=schema)

    assert not result.completed
    assert result.exit_code == 2
    assert result.final_message == "error: bad review invocation"
    assert result.diagnostics["status"] == "failed"
    assert result.diagnostics["last_error"] == "error: bad review invocation"

def test_codex_diagnostics_detect_missing_last_message(tmp_path: Path) -> None:
    transcript = tmp_path / "codex.jsonl"
    last_message = tmp_path / "last-message.md"
    transcript.write_text(
        '{"type":"thread.started","thread_id":"thread-1"}\n'
        '{"type":"turn.started"}\n'
        '{"type":"item.started","item":{"id":"item_0","type":"command_execution","status":"in_progress","command":"date"}}\n',
        encoding="utf-8",
    )

    diagnostics = diagnostics_for_paths(
        transcript_path=transcript,
        last_message_path=last_message,
        completed=False,
    )

    assert diagnostics.status == "abandoned"
    assert diagnostics.last_message_present is False
    assert diagnostics.thread_id == "thread-1"
    assert diagnostics.last_item_type == "command_execution"
    assert diagnostics.last_item_status == "in_progress"

def test_codex_review_uses_review_timeout(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "sleep 5\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "limits": StewardLimits(
                worker_timeout_minutes=10,
                review_timeout_minutes=0,
            ),
        }
    )
    config.ensure_dirs()
    task, _ = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    schema = tmp_path / "review.schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")

    result = CodexRunner(config).run_review(
        task, "review prompt", config.repo_root, output_schema=schema
    )

    assert not result.completed
    assert result.exit_code == 124
    assert "timed out after 0 minute(s)" in result.final_message

def test_codex_runner_writes_prompt_and_transcript(
    config: StewardConfig, tmp_path: Path
) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'done\\n' > \"$last\"\n"
        'printf \'{"message":"done"}\\n\'\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert result.completed
    assert result.final_message == "done\n"
    assert result.transcript_path.exists()

def test_codex_runner_retries_transient_failure_and_resumes(
    config: StewardConfig, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    count = tmp_path / "count.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'count=$(cat "{count}" 2>/dev/null || printf 0)\n'
        "count=$((count + 1))\n"
        f'printf "%s" "$count" > "{count}"\n'
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$count" -eq 1 ]; then\n'
        "  printf 'stream disconnected before completion\\n' > \"$last\"\n"
        "  printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"thread-transient\"}'\n"
        "  exit 1\n"
        "fi\n"
        "printf 'done\\n' > \"$last\"\n"
        "printf '%s\\n' '{\"message\":\"done\"}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    store = TaskStore.create(config.db_path)
    task = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    delays: list[float] = []
    monkeypatch.setattr(
        "coquic_steward.agents.runner.time.sleep", lambda delay: delays.append(delay)
    )

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert result.completed
    assert result.thread_id == "thread-transient"
    assert result.diagnostics["retry_count"] == 1
    retry = result.diagnostics["retries"][0]
    assert retry["attempt"] == 1
    assert retry["next_attempt"] == 2
    assert Path(retry["transcript_path"]).exists()
    assert Path(retry["last_message_path"]).read_text(encoding="utf-8") == (
        "stream disconnected before completion\n"
    )
    archived_context = Path(retry["tool_changes_path"]) / "context.json"
    assert ToolChangeCapture.from_context(archived_context).summary.state == "unavailable"
    assert delays == [5.0]
    assert "exec resume" in calls.read_text(encoding="utf-8").splitlines()[1]
    assert "thread-transient" in calls.read_text(encoding="utf-8").splitlines()[1]

@pytest.mark.parametrize(
    "message",
    [
        "Selected model is at capacity. Please try a different model.",
        "unexpected status 503 Service Unavailable",
        "HTTP status 502",
        "Could not resolve host: cch.example.test",
    ],
)
def test_codex_transient_failure_classification(message: str) -> None:
    assert _is_transient_codex_message(message)

def test_codex_does_not_retry_deterministic_failure() -> None:
    assert not _is_transient_codex_message("invalid output schema")
    assert not _is_transient_codex_message("maximum output tokens exceeded")

def test_codex_runner_reports_missing_codex_executable(config: StewardConfig) -> None:
    config = config.__class__(
        **{**config.__dict__, "codex_bin": "/missing/codex-for-steward-test"}
    )
    config.ensure_dirs()
    task = TaskStore.create(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert not result.completed
    assert result.exit_code == 127
    assert "unable to start Codex executable" in result.final_message
    transcript = result.transcript_path.read_text(encoding="utf-8")
    event = json.loads(transcript)
    assert event["type"] == "stderr"
    assert "unable to start Codex executable" in event["text"]
