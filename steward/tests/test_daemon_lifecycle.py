from __future__ import annotations

import json
import signal
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.core.models import (
    CodexRunState,
    PipelineCursorPhase,
    TaskKind,
    TaskSpec,
    TaskStatus,
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    WorkerResult,
    WorkerKind,
)
from coquic_steward.planning import PlannerRun as SchedulerPlannerRun
from coquic_steward.core.config import (
    StewardConfig,
    StewardContainerConfig,
    StewardTaskSyncConfig,
)
from coquic_steward.execution.container import TaskContainerRuntime
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.executor import StewardExecutor
from coquic_steward.execution.session import (
    FreshPlannerSession,
    InvocationStatus,
    ResumeCategory,
    ResumeResult,
    SessionResult,
    SessionSupervisor,
    runtime_factory_for_config,
    worktree_checkpoint,
)
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.cli import _run_until_stopped
from coquic_steward.orchestration.daemon import StewardDaemon, TickResult
from coquic_steward.orchestration.preflight import (
    StewardPreflightError,
    run_preflight,
)
from coquic_steward.storage import TaskStore


IMAGE = "sha256:" + "a" * 64


def _task(store: TaskStore, title: str = "lifecycle"):
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title=title,
            prompt=f"complete {title}",
        )
    )
    return task, store.list_pipelines(task.id)[0]


def _planner_signal(store: TaskStore, suffix: str = "retry") -> SignalItem:
    item = SignalItem(
        id=f"signal-item-{suffix}",
        provider="synthetic-provider",
        kind="synthetic.alert",
        fingerprint=f"fingerprint-{suffix}",
        title=f"Synthetic {suffix}",
    )
    store.ingest_signal_collection(
        SignalFetchRun(
            id=f"fetch-{suffix}",
            provider=item.provider,
            status=SignalFetchStatus.ok,
        ),
        [item],
    )
    return item


def test_planner_retry_defers_unchanged_input_and_success_resets_state(
    config, monkeypatch
) -> None:
    store = TaskStore(config.db_path)
    item = _planner_signal(store)
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    store.control_loop.claim_planner_run("planner-run-failed-retry", [signal_id])
    store.control_loop.complete_planner_run(
        "planner-run-failed-retry", [], state="failed"
    )
    store.control_loop.schedule_retry("planner")
    daemon = StewardDaemon(config, store)
    calls = 0

    def successful_no_work(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=config.private_dir / "missing-planner.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", successful_no_work
    )
    daemon._plan_until_idle(TickResult())
    assert calls == 0
    assert store.control_loop.pending_retry("planner") is not None

    daemon._plan(TickResult(), [item])
    assert calls == 1
    assert store.control_loop.pending_retry("planner") is None


def test_startup_reconstructs_terminal_planner_publication(config) -> None:
    store = TaskStore(config.db_path)
    item = _planner_signal(store, "publication")
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    run_id = "planner-run-publication"
    source_root = config.private_dir / "planner-publication-source"
    source_root.mkdir(parents=True)
    artifacts = {
        "prompt.md": b"synthetic prompt\n",
        "codex.jsonl": b'{"type":"failed"}\n',
        "last-message.md": b"synthetic failure\n",
    }
    for name, value in artifacts.items():
        (source_root / name).write_bytes(value)
    store.control_loop.claim_planner_run(run_id, [signal_id])
    store.control_loop.complete_planner_run(
        run_id,
        [],
        state="failed",
        artifact_sources={
            name: (str(source_root / name), True) for name in artifacts
        },
    )

    daemon = StewardDaemon(config, store)
    daemon._startup_reconcile_control_loop()

    published = config.control_loop_dir / "planner-runs" / run_id
    assert daemon._control_loop_archive.verify_planner_run(run_id)
    assert (published / "prompt.md").read_bytes() == artifacts["prompt.md"]
    assert run_id not in daemon._planner_publication_queue


def test_locked_daemon_routes_scheduler_planning_through_fresh_boundary(
    config, monkeypatch
) -> None:
    configured = replace(
        config,
        local_codex_test_harness=False,
        task_image_digest=IMAGE,
    )
    store = TaskStore(configured.db_path)
    item = _planner_signal(store, "isolated-boundary")
    seen: list[object] = []

    def fake_run_planner(_config, _signals, _active, **kwargs):
        seen.append(kwargs.get("invocation"))
        return SchedulerPlannerRun(
            planned=[],
            accepted_count=0,
            proposed_count=0,
            completed=True,
            exit_code=0,
            prompt_path=None,
            transcript_path=configured.private_dir / "missing-planner.jsonl",
            thread_id=None,
            consumed_item_ids=[item.id],
        )

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.run_planner", fake_run_planner
    )
    daemon = StewardDaemon(configured, store)
    daemon._plan(TickResult(), [item])

    assert isinstance(daemon.planner_session, FreshPlannerSession)
    assert seen == [daemon.planner_session]
    assert store.list_tasks() == []


def _interrupted_run(config, store, *, role="implementation", checkpoint=None):
    task, pipeline = _task(store, role)
    action = f"{task.id}:{pipeline.id}:implementation-0"
    checkpoint_id = checkpoint or worktree_checkpoint(config, config.repo_root)
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "implementation",
        {
            "pipeline_id": pipeline.id,
            "phase": "implementation",
            "action_id": action,
        },
    )
    private_home = config.private_sessions_dir / task.id / "session-original"
    session, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="session-original",
        private_home_path=private_home,
        private_home_relative_path=f"{task.id}/session-original",
        image_digest=IMAGE,
        codex_identity="codex-test",
        cwd=config.repo_root,
        checkpoint_id=checkpoint_id,
        provider_store_identity="codex-sessions-v1",
        owner_role=role,
        session_idempotency_key=action,
        role=role,
        model=None,
        reasoning=None,
        image_version=IMAGE,
        runtime_version="task-runtime-v1",
        run_checkpoint_id=checkpoint_id,
        run_provider_store_identity="codex-sessions-v1",
    )
    private_home.mkdir(parents=True, exist_ok=True)
    (private_home / "sessions").mkdir()
    (private_home / "sessions" / "provider.json").write_text(
        "{}\n", encoding="utf-8"
    )
    store.update_session(session.id, provider_session_id="private-provider-id")
    store.mark_run_interrupted(run.id, reason="test interruption")
    return task, pipeline, store.get_run(run.id)


class FakeSupervisor:
    def __init__(self, config, store, *, live=False, resume=ResumeCategory.success):
        self.config = config
        self.store = store
        self.live = live
        self.resume_category = resume
        self.calls = []
        self.remove_failures = 0

    def reconcile_container(self, task_id, *, ensure_running=True):
        self.calls.append(("reconcile-container", task_id, ensure_running))
        return SimpleNamespace(container_id=f"container-{task_id}", running=True)

    def inspect(self, run_id):
        self.calls.append(("inspect", run_id))
        return SimpleNamespace(
            live=self.live,
            container=SimpleNamespace(container_id="container-test"),
        )

    def build_recovery_packet(self, run_id):
        return SimpleNamespace(prompt=lambda: '{"recovery":"bounded"}')

    def resume_with_retries(self, run_id, **kwargs):
        self.calls.append(("resume", run_id, kwargs["max_attempts"]))
        if self.resume_category is not ResumeCategory.success:
            return ResumeResult(self.resume_category)
        predecessor = self.store.get_run(run_id)
        resumed = self.store.create_run(
            predecessor.task_id,
            predecessor.pipeline_id,
            predecessor.session_id,
            role=predecessor.role,
            resume_of_run_id=predecessor.id,
            image_version=predecessor.image_version,
            runtime_version=predecessor.runtime_version,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity=predecessor.provider_store_identity,
        )
        return ResumeResult(
            ResumeCategory.success,
            result=self._complete(resumed),
        )

    def recover(self, run_id, **_kwargs):
        self.calls.append(("recover", run_id))
        predecessor = self.store.get_run(run_id)
        session = self.store.create_session(
            predecessor.task_id,
            predecessor.pipeline_id,
            private_home_path=(
                self.config.private_sessions_dir
                / predecessor.task_id
                / "session-recovery"
            ),
            private_home_relative_path=(
                f"{predecessor.task_id}/session-recovery"
            ),
            image_digest=predecessor.image_version,
            codex_identity="codex-test",
            cwd=self.config.repo_root,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity="codex-sessions-v1",
            owner_role=predecessor.role,
            idempotency_key=f"fresh-recovery:{predecessor.id}",
        )
        recovered = self.store.create_run(
            predecessor.task_id,
            predecessor.pipeline_id,
            session.id,
            role=predecessor.role,
            retry_of_run_id=predecessor.id,
            image_version=predecessor.image_version,
            runtime_version=predecessor.runtime_version,
            checkpoint_id=predecessor.checkpoint_id,
            provider_store_identity=predecessor.provider_store_identity,
        )
        return ResumeResult(
            ResumeCategory.success,
            result=self._complete(recovered),
            evidence={"recovery": True},
        )

    def _complete(self, run):
        self.store.transition_run(
            run.id,
            CodexRunState.succeeded.value,
            expected_state=CodexRunState.running.value,
            exit_code=0,
            result_summary="completed",
        )
        run_dir = (
            self.config.tasks_dir
            / run.task_id
            / "pipelines"
            / run.pipeline_id
            / "runs"
            / run.id
        )
        run_dir.mkdir(parents=True, exist_ok=True)
        transcript = run_dir / "codex.jsonl"
        last_message = run_dir / "last-message.md"
        transcript.write_text("{}\n", encoding="utf-8")
        last_message.write_text("done\n", encoding="utf-8")
        return SessionResult(
            run.task_id,
            run.pipeline_id,
            run.session_id,
            run.id,
            InvocationStatus.succeeded,
            0,
            None,
            transcript,
            last_message,
        )

    def interrupt(self, run_id, **kwargs):
        self.calls.append(("interrupt", run_id, kwargs["force"]))
        try:
            self.store.mark_run_interrupted(run_id, reason="daemon shutdown")
        except ValueError:
            pass

    def stop_container(self, task_id, **_kwargs):
        self.calls.append(("stop", task_id))

    def remove_container(self, task_id):
        self.calls.append(("remove", task_id))
        if self.remove_failures:
            self.remove_failures -= 1
            raise RuntimeError("injected remove failure")


def test_config_preflight_launch_has_epoch_and_bounded_no_init_status(config):
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)

    assert daemon.preflight_report is not None
    assert "epoch" in daemon.preflight_report.checks
    assert daemon.preflight_report.configured_sync is False
    assert "private" not in daemon.preflight_report.summary
    assert config.epoch_path.exists()


def _task_image_labels(*, runtime_protocol="task-container-v1"):
    return {
        "org.opencontainers.image.source-revision": "a" * 32,
        "coquic.steward.runtime-protocol": runtime_protocol,
        "coquic.steward.codex-version": "0.144.6",
        "coquic.steward.closure": "b" * 32,
    }


def test_preflight_rejects_unrelated_task_image_metadata(config, monkeypatch):
    key = config.coquic_home / "codex-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    docker = config.coquic_home / "bin" / "docker"
    docker.parent.mkdir()
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    container = StewardContainerConfig(
        enabled=True,
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=config.coquic_home,
        codex_api_key_path=key,
        docker_bin=str(docker),
    )
    nested = StewardConfig(
        repo_root=config.repo_root,
        container=container,
        local_codex_test_harness=True,
    )

    def command(args, **_kwargs):
        stdout = (
            json.dumps([{"Config": {"Labels": {"unrelated": "image"}}}])
            if args[1:3] == ["image", "inspect"]
            else ""
        )
        return SimpleNamespace(ok=True, stdout=stdout)

    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command", command
    )

    with pytest.raises(StewardPreflightError, match="task image identity"):
        run_preflight(nested, check_remote_push=False)


def test_preflight_rejects_unlocked_docker_and_sync_executables(config, monkeypatch):
    key = config.coquic_home / "codex-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    container = StewardContainerConfig(
        enabled=True,
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=config.coquic_home,
        codex_api_key_path=key,
        docker_bin="/bin/true",
    )
    nested = StewardConfig(
        repo_root=config.repo_root,
        container=container,
        local_codex_test_harness=True,
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.preflight.run_command",
        lambda *_args, **_kwargs: SimpleNamespace(
            ok=True,
            stdout=json.dumps(
                [{"Config": {"Labels": _task_image_labels()}}]
            ),
        ),
    )

    with pytest.raises(StewardPreflightError, match="Docker executable identity"):
        run_preflight(nested, check_remote_push=False)

    identity = config.coquic_home / "task-sync-key"
    identity.write_text("fake\n", encoding="utf-8")
    identity.chmod(0o600)
    known_hosts = config.coquic_home / "known-hosts"
    known_hosts.write_text("receiver.example.test ssh-ed25519 fake\n", encoding="utf-8")
    sync = StewardTaskSyncConfig(
        enabled=True,
        remote_user="archive",
        remote_host="receiver.example.test",
        identity_path=identity,
        known_hosts_path=known_hosts,
        ssh_bin="/bin/true",
        rsync_bin=shutil.which("rsync") or "rsync",
    )
    sync_config = StewardConfig(
        repo_root=config.repo_root,
        task_sync=sync,
        local_codex_test_harness=True,
    )

    with pytest.raises(StewardPreflightError, match="SSH executable identity"):
        run_preflight(sync_config, check_remote_push=False)


def test_startup_reconcile_orders_task_identity_before_dispatch(config):
    store = TaskStore(config.db_path)
    second, _ = _task(store, "z-second")
    first, _ = _task(store, "a-first")
    daemon = StewardDaemon(config, store)

    outcomes = daemon.startup_reconcile()

    assert [item.task_id for item in outcomes] == sorted([first.id, second.id])
    assert daemon.runtime.reconciliation_complete


def test_reconcile_adopts_matching_live_wrapper_without_duplicate(config):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    store.restart_run = lambda *_args, **_kwargs: None
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    supervisor = FakeSupervisor(config, store, live=True)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]
    daemon.run_cycle(plan=False, dispatch=False)

    assert outcome.disposition == "adopted"
    assert not any(call[0] == "resume" for call in supervisor.calls)
    assert store.get_run(run.id).state == "running"
    assert outcome.task_id == task.id
    assert sum(call[0] == "inspect" for call in supervisor.calls) == 2


def test_complete_atomic_result_is_ingested_once(config, monkeypatch):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    archive = TaskArchiveWriter(config)
    pipeline = store.get_pipeline(run.pipeline_id)
    archive.materialize_ledger(task, pipeline, [store.get_run(run.id)])
    archive.write_run_file(task.id, pipeline.id, run.id, "last-message.md", "done\n")
    archive.write_run_file(
        task.id,
        pipeline.id,
        run.id,
        "result.json",
        {"status": "available", "summary": "complete", "path": None},
    )
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    ingested = []
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda predecessor, result: (
            ingested.append((predecessor, result.run_id))
            or SimpleNamespace(status="ingested")
        ),
    )

    first = daemon.startup_reconcile()[0]
    second = daemon.startup_reconcile()[0]

    assert first.disposition == "ingested"
    assert second.disposition == "ingested"
    assert ingested == [(run.id, run.id)]
    assert store.get_run(run.id).state == "succeeded"


def test_exact_id_resume_is_wired_and_persisted_without_private_identity(
    config, monkeypatch
):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "resumed"
    assert ("resume", run.id, 2) in supervisor.calls
    decisions = [
        event
        for event in store.events(task.id)
        if event.kind == "session.recovery.decision"
    ]
    assert decisions[-1].data["decision"] == "resume"
    assert "private-provider-id" not in json.dumps(decisions[-1].data)


def test_shutdown_interrupts_blocking_startup_resume(config):
    store = TaskStore(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)

    class BlockingSupervisor(FakeSupervisor):
        def __init__(self, config, store):
            super().__init__(config, store)
            self.resume_started = threading.Event()
            self.release_resume = threading.Event()

        def resume_with_retries(self, run_id, **_kwargs):
            self.resume_started.set()
            self.release_resume.wait(timeout=2)
            return ResumeResult(ResumeCategory.unavailable_store)

        def interrupt(self, run_id, **kwargs):
            self.calls.append(("interrupt", run_id, kwargs["force"]))
            self.release_resume.set()

    supervisor = BlockingSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._resume_or_recover(task, predecessor, store.list_runs(task.id))
        )
    )
    recovery.start()
    assert supervisor.resume_started.wait(timeout=1)

    daemon.request_shutdown(force=True)
    recovery.join(timeout=1)
    still_blocking = recovery.is_alive()
    supervisor.release_resume.set()
    recovery.join(timeout=2)

    assert still_blocking is False
    assert ("interrupt", predecessor.id, True) in supervisor.calls
    assert outcomes and outcomes[0].disposition == "interrupted"


def test_corrupt_resume_falls_back_to_fresh_recovery_packet(config, monkeypatch):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = FakeSupervisor(
        config,
        store,
        resume=ResumeCategory.corrupt_store,
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "resumed"
    assert any(call[0] == "recover" for call in supervisor.calls)
    recovery = next(
        event
        for event in reversed(store.events(task.id))
        if event.kind == "session.recovery.decision"
        and event.data.get("decision") == "fresh-recovery"
    )
    assert recovery.data["resume_category"] == "corrupt-store"
    assert store.get_run(outcome.run_id).retry_of_run_id == run.id


def test_fresh_recovery_lineage_is_durable_before_process_returns(
    config, monkeypatch
):
    store = TaskStore(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=object(),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    allocated = []

    def prepare_home(session):
        assert session.private_home_path is not None
        session.private_home_path.mkdir(parents=True, exist_ok=True)

    def crash_before_process_returns(_task, _session, run, _request, **_kwargs):
        allocated.append(store.get_run(run.id))
        raise KeyboardInterrupt

    monkeypatch.setattr(supervisor, "_prepare_home", prepare_home)
    monkeypatch.setattr(supervisor, "_execute", crash_before_process_returns)

    with pytest.raises(KeyboardInterrupt):
        supervisor.recover(predecessor.id, cwd=config.repo_root)

    assert len(allocated) == 1
    recovery = allocated[0]
    assert recovery.retry_of_run_id == predecessor.id
    store.mark_run_interrupted(recovery.id, reason="daemon crashed during recovery")
    runs = store.list_runs(task.id)
    root = StewardDaemon._interrupted_recovery_root(runs)
    assert root is not None and root.id == predecessor.id

    daemon = StewardDaemon(
        config,
        store,
        session_supervisor=FakeSupervisor(config, store),
    )
    outcome = daemon._resume_or_recover(task, root, runs)

    assert outcome.disposition == "blocked"
    assert outcome.run_id == recovery.id
    assert outcome.detail == "fresh recovery was interrupted; evidence is preserved"


def test_checkpoint_identity_conflict_blocks_without_resume(config):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    store.update_session(run.session_id, checkpoint_id="different-checkpoint")
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "blocked"
    assert "checkpoint" in outcome.detail
    assert not any(call[0] in {"resume", "recover"} for call in supervisor.calls)
    assert store.get(task.id).status != TaskStatus.failed


def test_resume_rejects_worktree_mutation_after_interruption(config):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = SessionSupervisor(
        config,
        store,
        invoker=object(),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    checkpoint = run.checkpoint_id
    assert checkpoint is not None
    tracked = config.repo_root / "README.md"
    tracked.write_text("changed after interruption\n", encoding="utf-8")

    resumed = supervisor.resume(
        run.id,
        prompt="continue",
        cwd=config.repo_root,
        checkpoint_id=checkpoint,
    )

    assert resumed.category is ResumeCategory.checkpoint_drift
    assert len(store.list_runs(task.id)) == 1


def test_commit_and_remote_ancestry_identity_conflict_blocks(config):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "commit identity")
    task.worktree_path = config.repo_root
    store.save(task)
    store.add_event(
        task.id,
        "pipeline.commit",
        "missing commit",
        {"pipeline_id": pipeline.id, "commit": "f" * 40},
    )
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "blocked"
    assert "commit" in outcome.detail


def test_validation_crash_releases_exact_phase_claim_for_deterministic_rerun(
    config,
):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "validation crash")
    action = f"{task.id}:{pipeline.id}:validation"
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "validation",
        {
            "pipeline_id": pipeline.id,
            "phase": "validation",
            "action_id": action,
            "input": {"payload": {}},
        },
    )
    daemon = StewardDaemon(config, store)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "interrupted"
    assert "released" in outcome.detail
    assert daemon.executor._in_progress_action(
        task.id,
        pipeline.id,
        PipelineCursorPhase.validation,
    ) is None
    assert any(
        event.kind == "pipeline.phase.interrupted"
        and event.data.get("action_id") == action
        for event in store.events(task.id)
    )


def test_commit_crash_adopts_exact_tree_once_before_manifest(config):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "commit crash")
    task.worktree_path = config.repo_root
    store.save(task)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=config.repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_pipelines SET base_identity = ? WHERE id = ?",
            (head, pipeline.id),
        )
        connection.exec_driver_sql(
            "UPDATE task_executions SET base_commit = ?, worktree_path = ? WHERE task_id = ?",
            (head, str(config.repo_root), task.id),
        )
    action = f"{task.id}:{pipeline.id}:commit"
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "commit",
        {
            "pipeline_id": pipeline.id,
            "phase": "commit",
            "action_id": action,
            "input": {"payload": {"expected_tree": tree}},
        },
    )
    daemon = StewardDaemon(config, store)

    outcome = daemon.startup_reconcile()[0]

    assert outcome.disposition == "ingested"
    assert store.get(task.id).status == TaskStatus.no_changes
    finishes = [
        event
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("action_id") == action
    ]
    assert len(finishes) == 1


def test_ledger_backed_stale_task_uses_identity_reconciliation(config):
    store = TaskStore(config.db_path)
    task, _ = _task(store, "stale ledger")
    store.start_worker(task.id, "running")
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE tasks SET updated_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (task.id,),
        )

    recovered = store.recover_stale_active_tasks(stale_after_minutes=1)

    assert recovered == []
    assert store.get(task.id).status == TaskStatus.running


def test_worker_pool_capacity_max_dispatch_and_heartbeat_remain_responsive(config):
    store = TaskStore(config.db_path)
    _task(store, "pool one")
    _task(store, "pool two")
    daemon = StewardDaemon(config, store)
    release = threading.Event()
    started = threading.Event()

    def worker(_task_id):
        started.set()
        release.wait(2)
        return True

    daemon._run_task_worker = worker
    pool = ThreadPoolExecutor(max_workers=2)
    result = TickResult()
    before = time.monotonic()
    daemon._dispatch_queued_pool(result, pool, max_dispatch=1)
    elapsed = time.monotonic() - before

    assert started.wait(1)
    assert result.dispatched == 1
    assert elapsed < 0.5
    daemon._begin_cycle("heartbeat")
    assert daemon.runtime.heartbeat_at is not None
    daemon._complete_cycle(TickResult(), "heartbeat")
    release.set()
    pool.shutdown(wait=True)


def test_shutdown_grace_bounds_blocked_worker_pool(config):
    object.__setattr__(config, "shutdown_grace_seconds", 5.0)
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)
    release = threading.Event()
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(release.wait, 30)
    daemon._worker_pool = pool
    daemon._active_futures["blocked"] = future

    started = time.monotonic()
    result = daemon.shutdown()
    elapsed = time.monotonic() - started
    release.set()
    future.result(timeout=1)

    assert result.forced
    assert elapsed < config.shutdown_grace_seconds + 1


def test_shutdown_interrupted_implementation_preserves_restart_state(config):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "interrupted implementation")
    task.worktree_path = config.repo_root
    store.save(task)

    class InterruptedRunner:
        def paths(self, task, *, name="worker"):
            root = config.logs_dir / task.id / name
            return root / "codex.jsonl", root / "last-message.md"

        def run(self, task, _prompt, cwd, **_kwargs):
            transcript, message = self.paths(task)
            transcript.parent.mkdir(parents=True, exist_ok=True)
            transcript.write_text("{}\n", encoding="utf-8")
            message.write_text("interrupted\n", encoding="utf-8")
            return WorkerResult(
                completed=False,
                command=["fake-codex"],
                cwd=cwd,
                exit_code=143,
                transcript_path=transcript,
                last_message_path=message,
                diagnostics={"status": "interrupted"},
            )

    executor = StewardExecutor(config, store, runner=InterruptedRunner())
    outcome = executor._durable_implementation(
        store.get(task.id), store.get_pipeline(pipeline.id)
    )
    daemon = StewardDaemon(config, store)
    daemon.executor = SimpleNamespace(advance_once=lambda _task_id: outcome)
    finalized = []
    daemon.finalize_terminal_task = finalized.append

    assert outcome.status == "interrupted"
    assert store.get(task.id).status == TaskStatus.running
    assert daemon._run_task_worker(task.id) is False
    assert finalized == []


def test_session_runner_preserves_interrupted_run_identity(config):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "session interruption")
    task.worktree_path = config.repo_root
    store.save(task)
    transcript = config.logs_dir / task.id / "codex.jsonl"
    message = config.logs_dir / task.id / "last-message.md"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("{}\n", encoding="utf-8")
    message.write_text("interrupted\n", encoding="utf-8")

    class InterruptedSupervisor:
        def start(self, *_args, **_kwargs):
            return SessionResult(
                task.id,
                pipeline.id,
                "session-test",
                "run-test",
                InvocationStatus.interrupted,
                143,
                None,
                transcript,
                message,
            )

    executor = StewardExecutor(
        config,
        store,
        session_supervisor=InterruptedSupervisor(),
    )

    result = executor.runner.run(task, "implement", config.repo_root)

    assert result.session_id == "session-test"
    assert result.run_id == "run-test"
    assert result.pipeline_id == pipeline.id
    assert result.diagnostics["status"] == "interrupted"


def test_enabled_nested_container_config_drives_runtime_fields(config):
    state = config.repo_root.parent / "container-state"
    state.mkdir()
    key = config.repo_root.parent / "codex-api-key"
    key.write_text("fake\n", encoding="utf-8")
    key.chmod(0o600)
    container = StewardContainerConfig(
        enabled=True,
        image="nested-task-image",
        image_digest=IMAGE,
        repository_host_path=config.repo_root,
        state_host_path=state,
        codex_api_key_path=key,
        docker_bin="/bin/true",
    )
    nested = StewardConfig(repo_root=config.repo_root, container=container)
    nested.ensure_dirs()

    executor = StewardExecutor(nested, TaskStore(nested.db_path))

    assert nested.task_image == container.image
    assert nested.task_image_digest == container.image_digest
    assert executor.session_supervisor is not None

    with pytest.raises(ValueError, match="conflicts"):
        StewardConfig(
            repo_root=config.repo_root,
            task_image_digest="sha256:" + "b" * 64,
            container=container,
        )


def test_sigint_sigterm_second_signal_stops_not_removes_restart_state(config):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_runs SET state = 'running', completed_at = NULL WHERE id = ?",
            (run.id,),
        )
    supervisor = FakeSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    daemon.request_shutdown()
    daemon.request_shutdown(force=True)
    result = daemon.shutdown(force=True)

    assert result.forced
    assert daemon.lifecycle_state.value == "stopped"
    assert any(call[0] == "interrupt" for call in supervisor.calls)
    assert any(call[0] == "stop" for call in supervisor.calls)
    assert not any(call[0] == "remove" for call in supervisor.calls)
    assert config.private_sessions_dir.joinpath(task.id).exists()
    assert store.get(task.id).status != TaskStatus.failed


def test_cli_signal_handler_only_sets_shutdown_intent(monkeypatch):
    installed = {}
    requests = []

    class SignalSafeDaemon:
        lifecycle_state = SimpleNamespace(value="stopped")

        def request_shutdown_from_signal(self, *, force=False):
            requests.append(force)

        def request_shutdown(self, **_kwargs):
            raise AssertionError("signal handler performed full shutdown work")

        def run_forever(self):
            installed[signal.SIGTERM](signal.SIGTERM, None)
            installed[signal.SIGINT](signal.SIGINT, None)

    monkeypatch.setattr(signal, "getsignal", lambda _selected: signal.SIG_DFL)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda selected, handler: installed.__setitem__(selected, handler),
    )

    _run_until_stopped(SignalSafeDaemon())

    assert requests == [False, True]


def test_shutdown_request_is_lock_free(config):
    daemon = StewardDaemon(config, TaskStore(config.db_path))

    with daemon._runtime_lock:
        daemon.request_shutdown()

    assert daemon.stopping
    assert daemon.shutdown(force=True).state.value == "stopped"


def test_shutdown_does_not_claim_failed_container_stop(config):
    store = TaskStore(config.db_path)
    task, _ = _task(store, "container stop failure")

    class StopFailure(FakeSupervisor):
        def stop_container(self, task_id, **_kwargs):
            self.calls.append(("stop", task_id))
            raise RuntimeError("Docker unavailable")

    supervisor = StopFailure(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert result.state.value == "stopping"
    assert daemon.lifecycle_state.value == "stopping"
    assert result.stopped_containers == 0
    assert result.final_sync_attempted is False
    assert ("stop", task.id) in supervisor.calls


def test_shutdown_discovers_and_stops_uncached_owned_container(config):
    store = TaskStore(config.db_path)
    task, _ = _task(store, "uncached owned container")
    task.worktree_path = config.repo_root
    store.save(task)
    task_dir = TaskArchiveWriter(config).task_dir(task.id)
    task_dir.mkdir(parents=True)
    (task_dir / "task.json").write_text(
        json.dumps({"taskId": "different-task"}), encoding="utf-8"
    )

    class ExistingRuntime:
        def __init__(self):
            self.running = True
            self.stop_calls = 0

        def stop(self, *, timeout=None):
            self.stop_calls += 1
            self.running = False

        def inspect(self):
            return SimpleNamespace(running=self.running)

    runtime = ExistingRuntime()
    supervisor = SessionSupervisor(
        config,
        store,
        runtime_factory=lambda _task: runtime,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    reconciliation = daemon.startup_reconcile()[0]
    result = daemon.shutdown(force=True)

    assert reconciliation.disposition == "blocked"
    assert runtime.running is False
    assert runtime.stop_calls == 1
    assert result.stopped_containers == 1
    assert daemon.lifecycle_state.value == "stopped"


def test_shutdown_treats_queued_task_without_container_as_noop(config):
    configured = replace(config, task_image_digest=IMAGE)
    store = TaskStore(configured.db_path)
    task, _ = _task(store, "queued without container")
    supervisor = SessionSupervisor(
        configured,
        store,
        runtime_factory=runtime_factory_for_config(configured),
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(configured, store, session_supervisor=supervisor)

    result = daemon.shutdown(force=True)

    assert store.get(task.id).status == TaskStatus.queued
    assert result.stopped_containers == 0
    assert result.state.value == "stopped"
    assert daemon.lifecycle_state.value == "stopped"


def test_recovery_waits_for_live_wrapper_before_adoption(config, monkeypatch):
    store = TaskStore(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)

    class SlowLaunchSupervisor(FakeSupervisor):
        def __init__(self, config, store):
            super().__init__(config, store)
            self.successor_created = threading.Event()
            self.inspection_attempted = threading.Event()
            self.release_launch = threading.Event()
            self.launch_completed = threading.Event()
            self.successor_id = None

        def resume_with_retries(self, run_id, **_kwargs):
            predecessor = self.store.get_run(run_id)
            successor = self.store.create_run(
                predecessor.task_id,
                predecessor.pipeline_id,
                predecessor.session_id,
                role=predecessor.role,
                resume_of_run_id=predecessor.id,
                image_version=predecessor.image_version,
                runtime_version=predecessor.runtime_version,
                checkpoint_id=predecessor.checkpoint_id,
                provider_store_identity=predecessor.provider_store_identity,
            )
            self.successor_id = successor.id
            self.successor_created.set()
            self.release_launch.wait(timeout=2)
            result = ResumeResult(
                ResumeCategory.success,
                result=self._complete(successor),
            )
            self.launch_completed.set()
            return result

        def inspect(self, run_id):
            self.calls.append(("inspect", run_id))
            self.inspection_attempted.set()
            return SimpleNamespace(live=False, container=None)

    supervisor = SlowLaunchSupervisor(config, store)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "reconcile_session_result",
        lambda *_: SimpleNamespace(status="ingested"),
    )
    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._resume_or_recover(task, predecessor, store.list_runs(task.id))
        )
    )
    recovery.start()
    assert supervisor.successor_created.wait(timeout=1)

    inspection_attempted = supervisor.inspection_attempted.wait(timeout=1)
    finished_before_wrapper = not recovery.is_alive()
    adopted_before_wrapper = daemon._adopted_runs.get(task.id)
    supervisor.release_launch.set()
    recovery.join(timeout=2)
    assert supervisor.launch_completed.wait(timeout=1)

    assert inspection_attempted is True
    assert finished_before_wrapper is False
    assert adopted_before_wrapper is None
    assert outcomes and outcomes[0].disposition == "resumed"


def test_recovery_does_not_adopt_before_wrapper_is_published(config):
    store = TaskStore(config.db_path)
    task, pipeline, predecessor = _interrupted_run(config, store)

    class SlowRuntime:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()
            self.config = SimpleNamespace(
                container_name="steward-test",
                container_path=lambda path, _role: path,
            )

        def ensure_started(self):
            self.entered.set()
            self.release.wait(timeout=3)
            raise RuntimeError("launch stopped before wrapper creation")

        def inspect(self):
            return SimpleNamespace(running=True, container_id="container-test")

    runtime = SlowRuntime()
    supervisor = SessionSupervisor(
        config,
        store,
        runtime=runtime,
        image_digest=IMAGE,
        codex_identity="codex-test",
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    def launch():
        return supervisor.start(
            task.id,
            pipeline.id,
            role="implementation",
            prompt="recover",
            cwd=config.repo_root,
            checkpoint_id=predecessor.checkpoint_id,
            retry_of_run_id=predecessor.id,
        )

    outcomes = []
    recovery = threading.Thread(
        target=lambda: outcomes.append(
            daemon._await_recovery_operation(task, predecessor, launch)
        )
    )
    recovery.start()
    try:
        assert runtime.entered.wait(timeout=1)
        recovery.join(timeout=0.2)
        successors = [
            run
            for run in store.list_runs(task.id)
            if run.retry_of_run_id == predecessor.id
        ]
        assert successors
        successor = successors[-1]

        inspection = supervisor.inspect(successor.id)

        assert recovery.is_alive()
        assert inspection.live is False
        assert inspection.identity is None
        assert daemon._adopted_runs.get(task.id) is None
    finally:
        runtime.release.set()
        recovery.join(timeout=2)

    assert not recovery.is_alive()
    assert outcomes and outcomes[0].status == "unavailable"
    assert store.get_run(successor.id).state == "failed"


def test_recovered_result_without_durable_phase_advance_stays_blocked(config):
    store = TaskStore(config.db_path)
    task, _, predecessor = _interrupted_run(config, store)
    supervisor = FakeSupervisor(config, store)
    recovered = store.create_run(
        predecessor.task_id,
        predecessor.pipeline_id,
        predecessor.session_id,
        role=predecessor.role,
        resume_of_run_id=predecessor.id,
        image_version=predecessor.image_version,
        runtime_version=predecessor.runtime_version,
        checkpoint_id=predecessor.checkpoint_id,
        provider_store_identity=predecessor.provider_store_identity,
    )
    result = supervisor._complete(recovered)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    daemon.executor = SimpleNamespace(reconcile_session_result=lambda *_args: None)

    outcome = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )

    assert outcome.disposition == "blocked"
    assert not any(
        event.kind == "session.recovery.completed" for event in store.events(task.id)
    )


def test_recovered_result_advances_exact_interrupted_phase_once(config):
    store = TaskStore(config.db_path)
    task, pipeline, predecessor = _interrupted_run(config, store)
    task.worktree_path = config.repo_root
    store.save(task)
    action = store.get_session(predecessor.session_id).idempotency_key
    assert action is not None
    store.add_event(
        task.id,
        "pipeline.phase.finished",
        "provisioned",
        {
            "pipeline_id": pipeline.id,
            "phase": "provisioned",
            "output": {
                "action_id": f"{task.id}:{pipeline.id}:provisioned",
                "next_phase": "implementation",
            },
        },
    )
    store.add_event(
        task.id,
        "pipeline.phase.interrupted",
        "implementation interrupted",
        {
            "pipeline_id": pipeline.id,
            "phase": "implementation",
            "action_id": action,
            "run_id": predecessor.id,
        },
    )
    transcript = config.logs_dir / task.id / "implementation.jsonl"
    message = config.logs_dir / task.id / "implementation.md"
    store.begin_iteration(
        task.id,
        0,
        "Initial implementation",
        worker_name="implementation",
        worker_prompt_path=None,
        worker_transcript_path=transcript,
        worker_last_message_path=message,
    )
    (config.repo_root / "README.md").write_text(
        "recovered implementation\n", encoding="utf-8"
    )
    supervisor = FakeSupervisor(config, store)
    recovered = store.create_run(
        predecessor.task_id,
        predecessor.pipeline_id,
        predecessor.session_id,
        role=predecessor.role,
        resume_of_run_id=predecessor.id,
        image_version=predecessor.image_version,
        runtime_version=predecessor.runtime_version,
        checkpoint_id=predecessor.checkpoint_id,
        provider_store_identity=predecessor.provider_store_identity,
    )
    result = supervisor._complete(recovered)
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)

    first = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )
    second = daemon._ingest_recovered_result(
        task,
        predecessor,
        store.get_run(recovered.id),
        result=result,
    )

    events = store.events(task.id)
    matching_finishes = [
        event
        for event in events
        if event.kind == "pipeline.phase.finished"
        and event.data.get("output", {}).get("action_id") == action
    ]
    matching_completions = [
        event
        for event in events
        if event.kind == "session.recovery.completed"
        and event.data.get("predecessor_run_id") == predecessor.id
    ]
    assert first.disposition == "resumed"
    assert second.disposition == "resumed"
    assert len(matching_finishes) == 1
    assert len(matching_completions) == 1


def test_sync_immediate_cadence_coalesces_overlap_and_failure_is_nonblocking(
    config, monkeypatch
):
    store = TaskStore(config.db_path)
    task, _ = _task(store, "sync independent")
    daemon = StewardDaemon(config, store)
    object.__setattr__(
        daemon.config,
        "task_sync",
        SimpleNamespace(
            enabled=True,
            transfer_timeout_seconds=1,
            to_archive_sync_config=lambda _root: object(),
        ),
    )
    calls = []

    class FailingSync:
        def __init__(self, *_args, **_kwargs):
            calls.append("start")

        def run_once(self):
            raise RuntimeError("fake receiver unavailable")

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.TaskArchiveSynchronizer",
        FailingSync,
    )
    daemon._sync_running = True
    assert daemon._run_task_sync_cycle() is False
    assert calls == []
    daemon._sync_running = False
    assert daemon._run_task_sync_cycle() is False
    assert calls == ["start"]
    assert store.get(task.id).status == TaskStatus.queued


def test_final_sync_obeys_shutdown_deadline(config):
    daemon = StewardDaemon(config, TaskStore(config.db_path))
    object.__setattr__(
        daemon.config,
        "task_sync",
        SimpleNamespace(
            enabled=True,
            transfer_timeout_seconds=30,
            to_archive_sync_config=lambda _root: object(),
        ),
    )
    release = threading.Event()
    daemon._run_task_sync_cycle = lambda: release.wait(2)

    started = time.monotonic()
    daemon._stop_task_sync(final=True, deadline=started + 0.05)
    elapsed = time.monotonic() - started
    release.set()

    assert elapsed < 0.5
    assert daemon._sync_final_attempted
    assert daemon._sync_stop.is_set()


def test_terminal_seal_uses_canonical_utc_timestamp(config):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "canonical terminal timestamp")
    _, run = store.create_session_with_run(
        task.id,
        pipeline.id,
        session_id="session-terminal",
        private_home_path=config.private_sessions_dir / task.id / "session-terminal",
        private_home_relative_path=f"{task.id}/session-terminal",
        image_digest=IMAGE,
        codex_identity="codex-test",
        cwd=config.repo_root,
        checkpoint_id="terminal-checkpoint",
        provider_store_identity="codex-sessions-v1",
        owner_role="implementation",
        session_idempotency_key=f"{task.id}:{pipeline.id}:implementation",
        role="implementation",
        model=None,
        reasoning=None,
        image_version=IMAGE,
        runtime_version="task-runtime-v1",
        run_checkpoint_id="terminal-checkpoint",
        run_provider_store_identity="codex-sessions-v1",
    )
    store.transition_run(
        run.id,
        CodexRunState.failed.value,
        expected_state=CodexRunState.running.value,
        exit_code=1,
        result_summary="terminal",
    )
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "failed",
        {"pipeline_id": pipeline.id, "terminal_status": "failed"},
    )
    store.transition_pipeline(pipeline.id, "failed", phase="complete")
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    daemon = StewardDaemon(config, store)

    assert daemon.finalize_terminal_task(task.id) is True

    manifest = json.loads(
        (config.tasks_dir / task.id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["completedAt"].endswith("Z")
    assert "+00:00" not in manifest["completedAt"]


def test_terminal_seal_rejects_unresolved_external_action(config, monkeypatch):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "unresolved terminal action")
    store.add_event(
        task.id,
        "pipeline.phase.started",
        "push",
        {
            "pipeline_id": pipeline.id,
            "phase": "push",
            "action_id": f"{task.id}:{pipeline.id}:push",
        },
    )
    store.finish_task(task.id, TaskStatus.blocked, "push unresolved")
    archive_calls = []

    class RecordingArchive:
        def __init__(self, _config):
            archive_calls.append("created")

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.TaskArchiveWriter",
        RecordingArchive,
    )
    daemon = StewardDaemon(config, store)

    assert daemon.finalize_terminal_task(task.id) is False
    assert archive_calls == []
    kinds = [event.kind for event in store.events(task.id)]
    assert "cleanup_blocked" in kinds
    assert "cleanup_pending" not in kinds
    assert "cleanup_complete" not in kinds


def test_terminal_manifest_cleanup_container_worktree_home_crash_retry(
    config, monkeypatch
):
    store = TaskStore(config.db_path)
    task, pipeline = _task(store, "terminal cleanup")
    store.add_event(
        task.id,
        "pipeline.ready_to_seal",
        "failed",
        {"pipeline_id": pipeline.id, "terminal_status": "failed"},
    )
    store.finish_task(task.id, TaskStatus.failed, "terminal")
    task = store.get(task.id)
    worktree = config.worktrees_dir / task.id
    worktree.mkdir(parents=True)
    task.worktree_path = worktree
    store.save(task)
    private_home = config.private_sessions_dir / task.id
    private_home.mkdir(parents=True)
    (private_home / "history").write_text("private", encoding="utf-8")
    supervisor = FakeSupervisor(config, store)
    supervisor.remove_failures = 1
    calls = supervisor.calls

    class FakeArchive:
        def __init__(self, _config):
            self.root = config.tasks_dir

        def task_dir(self, task_id):
            return self.root / task_id

        def create_task_from_record(self, record, **_kwargs):
            path = self.task_dir(record.id)
            path.mkdir(parents=True, exist_ok=True)
            (path / "task.json").write_text("{}", encoding="utf-8")
            return path / "task.json"

        def materialize_run(self, *_args, **_kwargs):
            return None

        def materialize_pipeline(self, *_args, **_kwargs):
            return None

        def seal(self, task_id, *_args, **_kwargs):
            calls.append(("seal", task_id))
            manifest = self.task_dir(task_id) / "manifest.json"
            manifest.write_bytes(b"sealed-public-bytes")
            return manifest

        def verify_or_raise(self, task_id):
            assert (self.task_dir(task_id) / "manifest.json").read_bytes() == (
                b"sealed-public-bytes"
            )
            return True

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.TaskArchiveWriter",
        FakeArchive,
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(
        daemon.executor,
        "clean_finished_task_worktree",
        lambda record: shutil.rmtree(record.worktree_path),
    )

    assert daemon.finalize_terminal_task(task.id) is False
    assert any(event.kind == "cleanup_pending" for event in store.events(task.id))
    assert worktree.exists() and private_home.exists()
    assert daemon.finalize_terminal_task(task.id) is True

    kinds = [event.kind for event in store.events(task.id)]
    assert kinds.index("cleanup_pending") < kinds.index("cleanup.container_removed")
    assert kinds.index("cleanup.container_removed") < kinds.index(
        "cleanup.worktree_removed"
    )
    assert kinds[-1] == "cleanup_complete"
    assert not worktree.exists()
    assert not private_home.exists()
    assert (config.tasks_dir / task.id / "manifest.json").read_bytes() == (
        b"sealed-public-bytes"
    )


def test_terminal_container_remove_requires_stopped_identity(config):
    task, _ = _task(TaskStore(config.db_path), "container remove")
    root = config.repo_root
    runtime_config = TaskContainerConfig(
        task_id=task.id,
        image="task-image",
        image_digest=IMAGE,
        worktree=root,
        archive=config.tasks_dir / task.id,
        private_sessions=config.private_sessions_dir / task.id,
        git_dir=root / ".git",
        git_common_dir=root / ".git",
        repo_root=root,
    )
    runtime_config.archive.mkdir(parents=True, exist_ok=True)
    runtime_config.private_sessions.mkdir(parents=True, exist_ok=True)
    calls = []

    class Client:
        def run(self, argv, **_kwargs):
            calls.append(argv)
            if argv[0] == "inspect":
                value = {
                    "Id": "container-id",
                    "State": {"Status": "exited", "Running": False},
                    "Config": {
                        "Image": IMAGE,
                        "Labels": runtime_config.labels,
                    },
                }
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

    TaskContainerRuntime(runtime_config, client=Client()).remove()

    assert [call[0] for call in calls] == ["inspect", "rm"]
