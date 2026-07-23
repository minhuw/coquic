from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.core.models import (
    CodexRunState,
    PipelineCursorPhase,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
)
from coquic_steward.execution.container import TaskContainerRuntime
from coquic_steward.execution.container_config import TaskContainerConfig
from coquic_steward.execution.session import (
    InvocationStatus,
    ResumeCategory,
    ResumeResult,
    SessionResult,
)
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.orchestration.daemon import StewardDaemon, TickResult
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


def _interrupted_run(config, store, *, role="implementation", checkpoint=None):
    task, pipeline = _task(store, role)
    action = checkpoint or f"{task.id}:{pipeline.id}:implementation-0"
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
        checkpoint_id=action,
        provider_store_identity="codex-sessions-v1",
        owner_role=role,
        session_idempotency_key="original-action",
        role=role,
        model=None,
        reasoning=None,
        image_version=IMAGE,
        runtime_version="task-runtime-v1",
        run_checkpoint_id=action,
        run_provider_store_identity="codex-sessions-v1",
    )
    private_home.mkdir(parents=True, exist_ok=True)
    (private_home / "sessions").mkdir()
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

    assert outcome.disposition == "adopted"
    assert not any(call[0] == "resume" for call in supervisor.calls)
    assert store.get_run(run.id).state == "running"
    assert outcome.task_id == task.id


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
        lambda predecessor, result: ingested.append((predecessor, result.run_id)),
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
    monkeypatch.setattr(daemon.executor, "reconcile_session_result", lambda *_: None)

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


def test_corrupt_resume_falls_back_to_fresh_recovery_packet(config, monkeypatch):
    store = TaskStore(config.db_path)
    task, _, run = _interrupted_run(config, store)
    supervisor = FakeSupervisor(
        config,
        store,
        resume=ResumeCategory.corrupt_store,
    )
    daemon = StewardDaemon(config, store, session_supervisor=supervisor)
    monkeypatch.setattr(daemon.executor, "reconcile_session_result", lambda *_: None)

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


def test_terminal_manifest_cleanup_container_worktree_home_crash_retry(
    config, monkeypatch
):
    store = TaskStore(config.db_path)
    task, _ = _task(store, "terminal cleanup")
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
