from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.agents.invocation import (
    InvocationOutcome,
    InvocationRequest,
    JsonlStream,
    stream_process,
)
from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import CodexStage, TaskKind, TaskSpec, WorkerKind
from coquic_steward.execution import ResumeCategory, SessionSupervisor
from coquic_steward.execution.container import ExecIdentity
from coquic_steward.execution.executor import StewardExecutor
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
    )
    predecessor = store.get_run(first.run_id)
    session = store.get_session(first.session_id)
    assert session.private_home_path is not None
    (session.private_home_path / "sessions" / "provider.json").write_text("{}")
    supervisor.invoker = FakeInvoker()
    resumed = supervisor.resume(predecessor.id, prompt="continue", api_key="fake-key")
    assert resumed.category is ResumeCategory.success
    assert resumed.result is not None
    assert resumed.result.run_id != predecessor.id
    assert store.get_run(resumed.result.run_id).resume_of_run_id == predecessor.id


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
