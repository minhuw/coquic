from __future__ import annotations

import io
import signal
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.agents.invocation import (
    InvocationOutcome,
    InvocationRequest,
    JsonlStream,
    stream_process,
)
from coquic_steward.core.config import StewardConfig
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
    TaskContainerRuntime,
)
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import runtime_factory_for_config
from coquic_steward.planning.planner import CodexPlanner
from coquic_steward.storage import TaskStore


class FakeInvoker:
    def __init__(self) -> None:
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
    ):
        outcome = super().invoke(
            request,
            api_key=api_key,
            append=append,
            observe=observe,
            on_started=on_started,
            timeout_seconds=timeout_seconds,
            interrupt_grace_seconds=interrupt_grace_seconds,
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
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)
    first, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="one", prompt="p")
    )
    second, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="two", prompt="p")
    )
    created = []

    def factory(task):
        runtime = object()
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
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)
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

    class RecoverableRuntime:
        def __init__(self) -> None:
            self.config = SimpleNamespace(
                container_name=f"coquic-steward-task-{task.id}"
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

        def stop(self, *args, **kwargs):
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


def test_interrupt_does_not_treat_runtime_probe_failure_as_process_exit(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)
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

    class TransientDockerFailure:
        def __init__(self) -> None:
            self.live = True
            self.signals: list[int] = []
            self.live_when_probe_failed = False

        def run(self, argv, **_kwargs):
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


def test_signal_planner_uses_canonical_session_run_and_archive_lineage(
    config: StewardConfig,
    monkeypatch,
) -> None:
    monkeypatch.setenv("CODEX_API_KEY", "fake-key")
    store = TaskStore(config.db_path)
    allocations = []
    create_session_with_run = store.create_session_with_run

    def record_allocation(*args, **kwargs):
        allocated = create_session_with_run(*args, **kwargs)
        allocations.append((kwargs, allocated))
        return allocated

    monkeypatch.setattr(store, "create_session_with_run", record_allocation)

    class PlannerInvoker(FakeInvoker):
        def invoke(self, request, **kwargs):
            outcome = super().invoke(request, **kwargs)
            request.output_last_message.write_text(
                '{"consumed_item_ids":[],"tasks":[]}\n', encoding="utf-8"
            )
            return outcome

    class CapturingSupervisor(SessionSupervisor):
        def run(self, *args, **kwargs):
            result = super().run(*args, **kwargs)
            self.worker_results = [
                *getattr(self, "worker_results", []),
                result,
            ]
            return result

    invoker = PlannerInvoker()
    supervisor = CapturingSupervisor(
        config,
        store,
        invoker=invoker,
        image_digest="sha256:" + "a" * 64,
        codex_identity="codex-0.144.6",
    )
    planner = CodexPlanner(config, invocation=supervisor)
    first = planner.run(ProjectSignals(repository="minhuw/coquic"), [])
    second = planner.run(ProjectSignals(repository="minhuw/coquic"), [])

    assert len(allocations) == 2
    assert first.thread_id is None
    assert second.thread_id is None
    assert first.run_id not in {None, "steward-planner", "provider-session"}
    assert second.run_id not in {None, first.run_id, "provider-session"}
    assert all(result.thread_id is None for result in supervisor.worker_results)
    assert [result.run_id for result in supervisor.worker_results] == [
        first.run_id,
        second.run_id,
    ]

    sessions = store.list_sessions("steward-planner")
    assert len(sessions) == 2
    assert [session.home_uid for session in sessions] == [10000, 10001]
    assert all(session.checkpoint_id for session in sessions)
    assert all(session.provider_session_id == "provider-session" for session in sessions)
    assert all(
        kwargs["checkpoint_id"] == session.checkpoint_id
        and allocated_session.id == session.id
        and allocated_run.id in {first.run_id, second.run_id}
        for (kwargs, (allocated_session, allocated_run)), session in zip(
            allocations, sessions, strict=True
        )
    )
    assert [request.session_uid for request in invoker.requests] == [10000, 10001]
    assert [request.session_id for request in invoker.requests] == [
        session.id for session in sessions
    ]
    for planner_run in (first, second):
        run = store.get_run(planner_run.run_id)
        run_json = (
            config.tasks_dir
            / "steward-planner"
            / "pipelines"
            / run.pipeline_id
            / "runs"
            / run.id
            / "run.json"
        )
        assert run_json.exists()
        assert "provider-session" not in run_json.read_text(encoding="utf-8")
        assert planner_run.transcript_path.parent == run_json.parent


def test_production_construction_rejects_local_codex_fallback(
    config: StewardConfig,
) -> None:
    production = replace(
        config,
        local_codex_test_harness=False,
        task_image_digest=None,
    )
    store = TaskStore(production.db_path)
    with pytest.raises(ValueError, match="task-container"):
        StewardExecutor(production, store)
    with pytest.raises(ValueError, match="task-container"):
        CodexPlanner(production)
