from __future__ import annotations

from pathlib import Path

from coquic_steward.agents.invocation import InvocationOutcome, JsonlStream
from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import TaskKind, TaskSpec, WorkerKind
from coquic_steward.execution import ResumeCategory, SessionSupervisor
from coquic_steward.storage import TaskStore


class FakeInvoker:
    def invoke(self, request, *, api_key, append, timeout_seconds, interrupt_grace_seconds):
        assert api_key == "fake-key"
        line = b'{"thread_id":"provider-session"}\n'
        append(line)
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
    def invoke(self, request, *, api_key, append, timeout_seconds, interrupt_grace_seconds):
        outcome = super().invoke(
            request,
            api_key=api_key,
            append=append,
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
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=FakeInvoker(),
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
    assert result.status.value == "succeeded"
    assert session.home_uid is not None
    assert session.private_home_path is not None
    assert not (session.private_home_path / "auth.json").exists()
    assert result.transcript_path.read_bytes() == b'{"thread_id":"provider-session"}\n'


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
