from __future__ import annotations

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.models import (
    PipelineCursorPhase,
    PipelinePhase,
    TaskKind,
    TaskSpec,
    TaskStatus,
    WorkerKind,
    WorktreeCheckpoint,
)
from coquic_steward.execution.task_archive import TaskArchive
from coquic_steward.execution.worktree import Worktrees
from coquic_steward.storage import SQLiteStoreLifecycleError, TaskStore
from coquic_steward.storage.sqlite import TaskLedgerOwnershipError


def test_new_layout_and_epoch_are_explicit(repo: Path, coquic_home: Path) -> None:
    config = StewardConfig(repo_root=repo)
    config.ensure_dirs()
    assert config.db_path == coquic_home / "steward.sqlite"
    assert config.worktrees_dir == coquic_home / "worktrees"
    assert config.tasks_dir == coquic_home / "tasks"
    assert config.private_root == coquic_home / "private"
    epoch = config.ensure_epoch()
    assert epoch["policy"] == "post-steward-2.0"
    assert config.ensure_epoch() == epoch


def test_config_and_archive_share_the_immutable_epoch(config: StewardConfig) -> None:
    epoch = config.ensure_epoch()
    path = config.epoch_path
    original_bytes = path.read_bytes()

    assert TaskArchive(config).ensure_epoch() == epoch
    assert config.ensure_epoch() == epoch
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize("contents", [b"not json\n", b"{}\n"])
def test_config_rejects_invalid_epoch_without_replacement(
    config: StewardConfig, contents: bytes
) -> None:
    path = config.epoch_path
    path.write_bytes(contents)

    with pytest.raises(RuntimeError):
        config.ensure_epoch()

    assert path.read_bytes() == contents


def test_config_rejects_epoch_symlink_without_replacement(config: StewardConfig) -> None:
    target = config.tasks_dir / "epoch-target"
    target_bytes = b"untouched\n"
    target.write_bytes(target_bytes)
    config.epoch_path.symlink_to(target.name)

    with pytest.raises(RuntimeError):
        config.ensure_epoch()

    assert config.epoch_path.is_symlink()
    assert target.read_bytes() == target_bytes


def test_task_store_direct_construction_is_rejected(config: StewardConfig) -> None:
    Store = TaskStore
    with pytest.raises(TypeError) as error:
        Store(config.db_path)

    message = str(error.value)
    assert "TaskStore.create()" in message
    assert "TaskStore.open()" in message


@pytest.mark.parametrize(
    ("operation", "obsolete_key"),
    [
        ("pipeline", "base"),
        ("pipeline", "input"),
        ("pipeline", "output"),
        ("pipeline", "patch"),
        ("run", "provider_id"),
        ("run", "provider_run"),
        ("run", "reasoning_effort"),
        ("run", "summary"),
    ],
)
def test_store_rejects_obsolete_field_names(
    config: StewardConfig, operation: str, obsolete_key: str
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    value = {obsolete_key: "obsolete"}

    with pytest.raises(ValueError, match=rf"unsupported {operation} fields"):
        if operation == "pipeline":
            store.create_pipeline(task.id, **value)
        else:
            pipeline = store.list_pipelines(task.id)[0]
            session = store.create_session(task.id, pipeline.id)
            store.create_run(
                task.id,
                pipeline.id,
                session.id,
                role="implementation",
                **value,
            )


def test_open_rejects_a_database_without_its_durable_wal_namespace(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_database = source_root / "steward.sqlite"
    source_root.mkdir()
    source = TaskStore.create(source_database)
    try:
        source.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title="wal-only",
                prompt="prompt",
            )
        )
        assert source_database.with_name("steward.sqlite-wal").stat().st_size > 0
        target_root = tmp_path / "target"
        target_root.mkdir()
        shutil.copy2(source_database, target_root / source_database.name)
        shutil.copytree(source_root / "tasks", target_root / "tasks")
    finally:
        source.engine.dispose()

    with pytest.raises(SQLiteStoreLifecycleError, match="WAL sidecar is missing"):
        TaskStore.open(target_root / source_database.name)

    assert not (target_root / "steward.sqlite-wal").exists()
    assert not (target_root / "steward.sqlite-shm").exists()


def test_ledger_allocates_ordered_lineage_and_private_fields(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="ledger",
            prompt="prompt",
        )
    )
    executions = store.list_executions(task.id)
    pipelines = store.list_pipelines(task.id)
    assert len(executions) == len(pipelines) == 1
    execution = executions[0]
    pipeline = pipelines[0]
    assert pipeline.ordinal == 1
    assert pipeline.trigger == "initial"
    assert pipeline.parent_pipeline_id is None
    assert execution.task_id == pipeline.task_id == task.id
    assert pipeline.execution_id == execution.id
    assert execution.owning_pipeline_id == pipeline.id
    assert [(event.kind, event.data) for event in store.events(task.id)] == [
        ("task.created", {})
    ]
    session = store.create_session(
        task.id,
        pipeline.id,
        provider_session_id="provider-private",
        private_home_path=Path("/private/codex"),
    )
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")
    store.mark_run_interrupted(run.id, reason="process exited")
    recovery = store.link_recovery_run(run.id)
    assert recovery.resume_of_run_id == run.id
    assert recovery.session_id == session.id
    assert store.get_session(session.id).provider_session_id == "provider-private"
    assert [item.role_ordinal for item in store.list_runs(task.id)] == [1, 2]


def test_terminal_run_releases_active_session_before_child_transfer(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="child", prompt="p")
    )
    parent = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, parent.id)
    run = store.create_run(task.id, parent.id, session.id, role="implementation")

    store.transition_run(
        run.id,
        "succeeded",
        expected_state="running",
        exit_code=0,
        result_summary="done",
    )

    execution = store.get_execution(task.id)
    assert execution.owning_pipeline_id == parent.id
    assert execution.active_session_id is None
    assert execution.active_run_id is None

    store.transition_pipeline(parent.id, "superseded")
    child = store.create_pipeline(
        task.id,
        execution_id=parent.execution_id,
        trigger="validation-repair",
        parent_pipeline_id=parent.id,
    )
    assert child.parent_pipeline_id == parent.id
    assert store.get_execution(task.id).owning_pipeline_id == child.id


def test_stale_pipeline_cannot_reclaim_execution_owner(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="owner", prompt="p")
    )
    parent = store.list_pipelines(task.id)[0]
    child = store.create_pipeline(
        task.id,
        execution_id=parent.execution_id,
        trigger="validation-repair",
        parent_pipeline_id=parent.id,
    )

    before = store.list_pipelines(task.id)
    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        store.create_pipeline(
            task.id,
            execution_id=parent.execution_id,
            trigger="validation-repair",
            parent_pipeline_id=parent.id,
        )
    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        store.create_session(task.id, parent.id)

    assert store.get_execution(task.id).owning_pipeline_id == child.id
    assert store.list_pipelines(task.id) == before
    assert store.list_sessions(task.id, pipeline_id=parent.id) == []


def test_pipeline_identity_update_persists_mirrors_and_reopens(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="identity", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    worktree = (config.db_path.parent / "worktrees" / task.id).resolve()

    updated = store.update_pipeline_identity(
        pipeline.id,
        base_identity="base-identity",
        input_identity="input-identity",
        output_identity="output-identity",
        patch_identity="patch-identity",
        phase=PipelinePhase.validation,
        expected_tree="expected-tree",
        worktree_path=worktree,
    )

    assert updated.base_identity == "base-identity"
    assert updated.input_identity == "input-identity"
    assert updated.output_identity == "output-identity"
    assert updated.patch_identity == "patch-identity"
    assert updated.phase == PipelinePhase.validation.value
    execution = store.get_execution(task.id)
    assert execution.base_commit == "base-identity"
    assert execution.expected_tree == "expected-tree"
    assert execution.worktree_path == worktree
    assert execution.current_phase == PipelinePhase.planning.value
    assert execution.updated_at == updated.updated_at
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute(
            "SELECT worktree_path FROM task_executions WHERE id = ?",
            (execution.id,),
        ).fetchone()[0] == f"worktrees/{task.id}"

    updated_again = store.update_pipeline_identity(
        pipeline.id,
        output_identity="output-identity-2",
        expected_tree=None,
    )
    assert updated_again.output_identity == "output-identity-2"
    assert updated_again.input_identity == updated.input_identity
    assert store.get_execution(task.id).expected_tree == execution.expected_tree

    before_pipeline = store.get_pipeline(pipeline.id)
    before_execution = store.get_execution(task.id)
    assert store.update_pipeline_identity(
        pipeline.id,
        input_identity=None,
        expected_tree=None,
        worktree_path=None,
    ) == before_pipeline
    assert store.get_execution(task.id) == before_execution

    reopened = TaskStore.open(config.db_path)
    try:
        assert reopened.get_pipeline(pipeline.id) == updated_again
        reopened_execution = reopened.get_execution(task.id)
        assert reopened_execution.base_commit == execution.base_commit
        assert reopened_execution.expected_tree == execution.expected_tree
        assert reopened_execution.worktree_path == execution.worktree_path
        assert reopened_execution.current_phase == execution.current_phase
    finally:
        reopened.engine.dispose()


def test_pipeline_identity_update_rejects_stale_owner_without_partial_write(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="owner", prompt="p")
    )
    parent = store.list_pipelines(task.id)[0]
    store.create_pipeline(
        task.id,
        execution_id=parent.execution_id,
        trigger="validation-repair",
        parent_pipeline_id=parent.id,
    )
    before_pipeline = store.get_pipeline(parent.id)
    before_execution = store.get_execution(task.id)

    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        store.update_pipeline_identity(
            parent.id,
            base_identity="should-not-persist",
            output_identity="should-not-persist",
            expected_tree="should-not-persist",
            worktree_path=config.db_path.parent / "worktrees" / task.id,
        )

    assert store.get_pipeline(parent.id) == before_pipeline
    assert store.get_execution(task.id) == before_execution


def test_terminal_finalization_persists_provider_and_checkpoint_atomically(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="finalize", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id, checkpoint_id="before")
    run = store.create_run(
        task.id,
        pipeline.id,
        session.id,
        role="implementation",
        checkpoint_id="before",
    )

    store.transition_run(
        run.id,
        "interrupted",
        expected_state="running",
        exit_code=130,
        provider_session_id="provider-final",
        checkpoint_id="after",
    )

    saved_session = store.get_session(session.id)
    saved_run = store.get_run(run.id)
    assert saved_session.provider_session_id == "provider-final"
    assert saved_session.checkpoint_id == "after"
    assert saved_run.checkpoint_id == "after"
    assert saved_run.state == "interrupted"


def _pipeline_claim_data(
    task_id: str,
    pipeline_id: str,
    action_id: str,
    phase: PipelineCursorPhase = PipelineCursorPhase.implementation,
) -> dict[str, object]:
    return {
        "pipeline_id": pipeline_id,
        "phase": phase.value,
        "action_id": action_id,
        "input": {"payload": {"attempt": 1}},
    }


def test_pipeline_action_claim_persists_event_after_commit(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    data = _pipeline_claim_data(task.id, pipeline.id, action)
    observed_event_counts: list[int] = []

    def on_change() -> None:
        with sqlite3.connect(config.db_path) as connection:
            observed_event_counts.append(
                connection.execute(
                    "SELECT count(*) FROM events WHERE kind = ?", (
                        "pipeline.phase.started",
                    )
                ).fetchone()[0]
            )

    store.on_change = on_change

    assert store.claim_pipeline_action(
        task.id, pipeline.id, PipelineCursorPhase.implementation, action, data
    ) is True
    assert observed_event_counts == [1]
    starts = [
        event
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.started"
    ]
    assert len(starts) == 1
    assert starts[0].message == "implementation"
    assert starts[0].data == data


def test_pipeline_action_claim_rejects_active_phase_without_notification(
    config: StewardConfig,
) -> None:
    notifications: list[str] = []
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    store.on_change = lambda: notifications.append("changed")
    data = _pipeline_claim_data(task.id, pipeline.id, action)

    assert store.claim_pipeline_action(
        task.id, pipeline.id, PipelineCursorPhase.implementation, action, data
    ) is True
    notifications.clear()
    assert store.claim_pipeline_action(
        task.id, pipeline.id, PipelineCursorPhase.implementation, action, data
    ) is False
    assert store.claim_pipeline_action(
        task.id,
        pipeline.id,
        PipelineCursorPhase.implementation,
        f"{action}:other",
        _pipeline_claim_data(
            task.id, pipeline.id, f"{action}:other"
        ),
    ) is False
    assert notifications == []


def test_pipeline_action_claim_allows_interrupted_retry(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    data = _pipeline_claim_data(task.id, pipeline.id, action)

    assert store.claim_pipeline_action(
        task.id, pipeline.id, PipelineCursorPhase.implementation, action, data
    ) is True
    store.add_event(
        task.id,
        "pipeline.phase.interrupted",
        "implementation interrupted",
        {
            "pipeline_id": pipeline.id,
            "phase": PipelineCursorPhase.implementation.value,
            "action_id": action,
        },
    )

    assert store.claim_pipeline_action(
        task.id, pipeline.id, "implementation", action, data
    ) is True
    starts = [
        event
        for event in store.events(task.id)
        if event.kind == "pipeline.phase.started"
    ]
    assert len(starts) == 2
    assert all(event.data == data for event in starts)


def test_pipeline_action_claim_rejects_finished_action(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    store.add_event(
        task.id,
        "pipeline.phase.finished",
        "implementation",
        {
            "pipeline_id": pipeline.id,
            "phase": PipelineCursorPhase.implementation.value,
            "output": {"action_id": action},
        },
    )

    assert store.claim_pipeline_action(
        task.id,
        pipeline.id,
        PipelineCursorPhase.implementation,
        action,
        _pipeline_claim_data(task.id, pipeline.id, action),
    ) is False
    assert not any(
        event.kind == "pipeline.phase.started" for event in store.events(task.id)
    )


def test_pipeline_action_claim_skips_malformed_history(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    with sqlite3.connect(config.db_path) as connection:
        connection.execute(
            "INSERT INTO events (task_id, kind, message, created_at, data_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                task.id,
                "pipeline.phase.started",
                "implementation",
                "2026-01-01T00:00:00+00:00",
                "{malformed",
            ),
        )

    assert store.claim_pipeline_action(
        task.id,
        pipeline.id,
        PipelineCursorPhase.implementation,
        action,
        _pipeline_claim_data(task.id, pipeline.id, action),
    ) is True


def test_pipeline_action_claim_rolls_back_without_notification_on_error(
    config: StewardConfig,
) -> None:
    notifications: list[str] = []
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="claim", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    action = f"{task.id}:{pipeline.id}:implementation"
    store.on_change = lambda: notifications.append("changed")

    with patch(
        "coquic_steward.storage.sqlite.EventRow.__table__.insert",
        side_effect=RuntimeError("insert failed"),
    ), pytest.raises(RuntimeError, match="insert failed"):
        store.claim_pipeline_action(
            task.id,
            pipeline.id,
            PipelineCursorPhase.implementation,
            action,
            _pipeline_claim_data(task.id, pipeline.id, action),
        )

    assert notifications == []
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM events WHERE kind = ?", ("pipeline.phase.started",)
        ).fetchone() == (0,)


def test_concurrent_pipeline_ordinals_are_unique(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )

    def allocate(_: int) -> int:
        return store.create_pipeline(task.id, trigger="validation-repair").ordinal

    with ThreadPoolExecutor(max_workers=4) as executor:
        ordinals = list(executor.map(allocate, range(8)))
    assert sorted(ordinals) == list(range(2, 10))


def test_concurrent_live_rerun_allocations_have_one_owner_and_wakeup(
    config: StewardConfig,
) -> None:
    dry_store = TaskStore.create(config.db_path, dry_run=True)
    source, _ = dry_store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="planned source",
            prompt="implement",
        )
    )
    dry_store.finish_task(source.id, TaskStatus.no_changes, "no changes")
    store = TaskStore.open(config.db_path, dry_run=False)

    def allocate(_: int):
        return store.allocate_live_rerun(source.id)

    with ThreadPoolExecutor(max_workers=4) as executor:
        allocations = list(executor.map(allocate, range(8)))

    assert sum(allocation.created for allocation in allocations) == 1
    task_ids = {allocation.task.id for allocation in allocations}
    assert len(task_ids) == 1
    descendants = [task for task in store.list_tasks() if task.id != source.id]
    assert [task.id for task in descendants] == list(task_ids)
    assert [
        wakeup for wakeup in store.pending_wakeups() if wakeup.reason == "task.live_rerun"
    ]
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM control_loop_edges "
            "WHERE edge_type = ? AND source_id = ?",
            ("task_rerun", source.id),
        ).fetchone() == (1,)


def test_pipeline_creation_requires_persisted_execution_owner(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    execution = store.get_execution(task.id)
    before = store.list_pipelines(task.id)
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE task_executions SET owning_pipeline_id = NULL WHERE id = ?",
            (execution.id,),
        )

    with pytest.raises(TaskLedgerOwnershipError, match="owning pipeline"):
        store.create_pipeline(task.id, execution_id=execution.id, trigger="repair")

    assert store.list_pipelines(task.id) == before
    assert store.get(task.id).status == TaskStatus.queued
    assert store.get_execution(task.id).owning_pipeline_id is None


def test_terminal_cas_loser_persists_exact_provider_identity(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="cas", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")
    store.mark_run_interrupted(run.id)

    with pytest.raises(ValueError, match="compare-and-set"):
        store.transition_run(
            run.id,
            "succeeded",
            expected_state="running",
            provider_session_id="provider-exact",
        )

    assert store.get_session(session.id).provider_session_id == "provider-exact"
    with pytest.raises(ValueError, match="conflicts with persisted"):
        store.transition_run(
            run.id,
            "succeeded",
            expected_state="running",
            provider_session_id="provider-conflict",
        )
    assert store.get_session(session.id).provider_session_id == "provider-exact"


def test_checkpoint_round_trip(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    execution = store.get_execution(task.id)
    pipeline = store.list_pipelines(task.id)[0]
    checkpoint = WorktreeCheckpoint(
        task_id=task.id,
        execution_id=execution.id,
        base_commit="a" * 40,
        expected_tree="b" * 40,
        phase="implementation",
        owning_pipeline_id=pipeline.id,
    )
    store.upsert_checkpoint(checkpoint)
    assert store.checkpoint_matches(
        execution.id, base_commit="a" * 40, expected_tree="b" * 40
    )


def test_execution_and_checkpoint_pointers_are_task_scoped(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)

    def allocate(title: str):
        task, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=title,
                prompt="prompt",
            )
        )
        execution = store.get_execution(task.id)
        pipeline = store.list_pipelines(task.id)[0]
        session = store.create_session(task.id, pipeline.id)
        run = store.create_run(
            task.id, pipeline.id, session.id, role="implementation"
        )
        return task, execution, pipeline, session, run

    first = allocate("first")
    second = allocate("second")
    first_task, first_execution, first_pipeline, _, _ = first
    _, _, second_pipeline, second_session, second_run = second

    with pytest.raises(ValueError, match="pipeline does not belong"):
        store.transition_execution(
            first_execution.id,
            "active",
            pipeline_id=second_pipeline.id,
            session_id=second_session.id,
            run_id=second_run.id,
        )
    with pytest.raises(ValueError, match="session does not belong"):
        store.upsert_checkpoint(
            WorktreeCheckpoint(
                task_id=first_task.id,
                execution_id=first_execution.id,
                base_commit="a" * 40,
                expected_tree="b" * 40,
                phase="implementation",
                owning_pipeline_id=first_pipeline.id,
                active_session_id=second_session.id,
                active_run_id=second_run.id,
            )
        )
    checkpoint = store.upsert_checkpoint(
        WorktreeCheckpoint(
            task_id=first_task.id,
            execution_id=first_execution.id,
            base_commit="a" * 40,
            expected_tree="b" * 40,
            phase="implementation",
            owning_pipeline_id=first_pipeline.id,
        )
    )

    with sqlite3.connect(config.db_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError, match="ownership"):
            connection.execute(
                "UPDATE task_executions SET owning_pipeline_id = ? WHERE id = ?",
                (second_pipeline.id, first_execution.id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="ownership"):
            connection.execute(
                "UPDATE task_worktree_checkpoints SET owning_pipeline_id = ? WHERE id = ?",
                (second_pipeline.id, checkpoint.id),
            )


def test_referenced_pipeline_cannot_be_reassigned_to_another_task(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)

    def allocate(title: str):
        task, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=title,
                prompt="prompt",
            )
        )
        return task, store.get_execution(task.id)

    first_task, first_execution = allocate("first")
    second_task, _ = allocate("second")
    pipeline = store.create_pipeline(
        first_task.id,
        execution_id=first_execution.id,
        trigger="validation-repair",
    )
    store.transition_execution(
        first_execution.id,
        "active",
        pipeline_id=pipeline.id,
    )
    store.upsert_checkpoint(
        WorktreeCheckpoint(
            task_id=first_task.id,
            execution_id=first_execution.id,
            base_commit="a" * 40,
            expected_tree="b" * 40,
            phase="implementation",
            owning_pipeline_id=pipeline.id,
        )
    )

    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (0,)
        connection.execute(
            "UPDATE task_pipelines SET phase = ? WHERE id = ?",
            ("implementation", pipeline.id),
        )
        with pytest.raises(sqlite3.IntegrityError, match="ownership"):
            connection.execute(
                "UPDATE task_pipelines SET task_id = ? WHERE id = ?",
                (second_task.id, pipeline.id),
            )

    assert store.get_pipeline(pipeline.id).task_id == first_task.id
    assert store.get_pipeline(pipeline.id).phase == "implementation"


def test_task_allocation_rolls_back_execution_pipeline_failure(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    from coquic_steward.storage.sqlite import Session

    real_flush = Session.flush
    flushes = 0

    def crash_after_task_flush(session: Session, *args: object, **kwargs: object) -> None:
        nonlocal flushes
        real_flush(session, *args, **kwargs)
        flushes += 1
        if flushes == 1:
            raise RuntimeError("injected pipeline allocation failure")

    with patch(
        "coquic_steward.storage.sqlite.Session.flush",
        new=crash_after_task_flush,
    ), pytest.raises(RuntimeError, match="pipeline allocation"):
        store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title="atomic allocation",
                prompt="prompt",
            )
        )

    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT count(*) FROM tasks").fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM task_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM task_pipelines"
        ).fetchone() == (0,)


def test_invalid_recovery_lineage_is_rejected(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")
    with pytest.raises(ValueError, match="interrupted"):
        store.link_recovery_run(run.id)


def test_run_lineage_and_idempotency_are_task_scoped(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)

    def create_task(title: str):
        return store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=title,
                prompt="prompt",
            )
        )[0]

    first = create_task("first")
    second = create_task("second")
    first_pipeline = store.list_pipelines(first.id)[0]
    second_pipeline = store.list_pipelines(second.id)[0]
    first_session = store.create_session(
        first.id, first_pipeline.id, idempotency_key="shared-key"
    )
    second_session = store.create_session(
        second.id, second_pipeline.id, idempotency_key="shared-key"
    )
    second_run = store.create_run(
        second.id,
        second_pipeline.id,
        second_session.id,
        role="implementation",
    )

    assert first_session.task_id == first.id
    assert second_session.task_id == second.id
    with pytest.raises(ValueError, match="parent run"):
        store.create_run(
            first.id,
            first_pipeline.id,
            first_session.id,
            role="implementation",
            parent_run_id=second_run.id,
        )


def test_session_and_first_run_allocation_rolls_back_together(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="atomic allocation",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    arguments = {
        "session_id": "session-atomic",
        "private_home_path": config.private_sessions_dir / task.id / "session-atomic",
        "private_home_relative_path": f"{task.id}/session-atomic",
        "image_digest": "sha256:" + "a" * 64,
        "codex_identity": "codex-0.144.6",
        "cwd": config.repo_root,
        "checkpoint_id": None,
        "provider_store_identity": "codex-sessions-v1",
        "owner_role": "implementation",
        "session_idempotency_key": None,
        "role": "implementation",
        "model": None,
        "reasoning": None,
        "image_version": "sha256:" + "a" * 64,
        "runtime_version": "task-runtime-v1",
        "run_checkpoint_id": None,
        "run_provider_store_identity": "codex-sessions-v1",
    }
    with patch(
        "coquic_steward.storage.sqlite.run_to_row",
        side_effect=RuntimeError("simulated first-run failure"),
    ), pytest.raises(RuntimeError, match="first-run"):
        store.create_session_with_run(task.id, pipeline.id, **arguments)
    assert store.list_sessions(task.id) == []
    assert store.list_runs(task.id) == []

    session, run = store.create_session_with_run(task.id, pipeline.id, **arguments)
    assert run.session_id == session.id
    assert session.home_uid is not None


def test_stale_run_allocation_rolls_back_without_ledger_rows(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="stale", prompt="p")
    )
    parent = store.list_pipelines(task.id)[0]
    stale_session = store.create_session(task.id, parent.id)
    child = store.create_pipeline(
        task.id,
        execution_id=parent.execution_id,
        trigger="validation-repair",
        parent_pipeline_id=parent.id,
    )

    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        store.create_run(
            task.id,
            parent.id,
            stale_session.id,
            role="implementation",
        )
    assert store.list_runs(task.id, pipeline_id=parent.id) == []

    arguments = {
        "session_id": "stale-allocation-session",
        "private_home_path": config.private_sessions_dir / task.id / "stale-allocation-session",
        "private_home_relative_path": f"{task.id}/stale-allocation-session",
        "image_digest": "sha256:" + "a" * 64,
        "codex_identity": "codex-test",
        "cwd": config.repo_root,
        "checkpoint_id": None,
        "provider_store_identity": "codex-sessions-v1",
        "owner_role": "implementation",
        "session_idempotency_key": None,
        "role": "implementation",
        "model": None,
        "reasoning": None,
        "image_version": "sha256:" + "a" * 64,
        "runtime_version": "task-runtime-v1",
        "run_checkpoint_id": None,
        "run_provider_store_identity": "codex-sessions-v1",
    }
    with pytest.raises(TaskLedgerOwnershipError, match="current execution owner"):
        store.create_session_with_run(task.id, parent.id, **arguments)

    assert store.list_sessions(task.id, pipeline_id=parent.id) == [stale_session]
    assert store.list_runs(task.id, pipeline_id=parent.id) == []
    assert store.get_execution(task.id).owning_pipeline_id == child.id


def test_interrupted_run_has_only_one_recovery(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="recover",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(
        task.id, pipeline.id, session.id, role="implementation"
    )
    store.mark_run_interrupted(run.id)

    def recover(_: int):
        try:
            return store.link_recovery_run(run.id)
        except ValueError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(recover, range(2)))

    assert sum(not isinstance(result, ValueError) for result in results) == 1
    errors = [result for result in results if isinstance(result, ValueError)]
    assert len(errors) == 1
    assert "already has a recovery" in str(errors[0])


def test_database_rejects_cross_task_run_parent(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)

    def create_run(title: str):
        task, _ = store.add_task(
            TaskSpec(
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=title,
                prompt="prompt",
            )
        )
        pipeline = store.list_pipelines(task.id)[0]
        session = store.create_session(task.id, pipeline.id)
        return store.create_run(
            task.id, pipeline.id, session.id, role="implementation"
        )

    first = create_run("first")
    second = create_run("second")
    with sqlite3.connect(config.db_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE task_runs SET parent_run_id = ? WHERE id = ?",
                (second.id, first.id),
            )


def test_checkpoint_rejects_dirty_worktree(config: StewardConfig) -> None:
    worktrees = Worktrees(config)
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="checkpoint",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    path, _ = worktrees.create(task)
    identity = worktrees.identity(
        task,
        path,
        owning_pipeline_id=pipeline.id,
        phase="implementation",
    )
    store.upsert_checkpoint(
        WorktreeCheckpoint(
            task_id=identity.task_id,
            execution_id=identity.execution_id,
            base_commit=identity.base_commit,
            expected_tree=identity.expected_tree,
            phase=identity.phase,
            owning_pipeline_id=identity.owning_pipeline_id,
            worktree_path=identity.path,
        )
    )
    (path / "README.md").write_text("changed\n", encoding="utf-8")

    assert not worktrees.validate_checkpoint(path, identity)

    (path / "README.md").write_text("hello\n", encoding="utf-8")
    (path / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    assert not worktrees.validate_checkpoint(path, identity)


def test_checkpoint_recovery_binds_durable_runtime_identity(
    config: StewardConfig,
) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="checkpoint identity",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
    worktrees = Worktrees(config)
    path, _ = worktrees.create(task)
    identity = worktrees.identity(
        task,
        path,
        owning_pipeline_id=pipeline.id,
        phase="implementation",
        image_version="image-v1",
        runtime_version="runtime-v1",
    )
    store.upsert_checkpoint(
        WorktreeCheckpoint(
            task_id=identity.task_id,
            execution_id=identity.execution_id,
            base_commit=identity.base_commit,
            expected_tree=identity.expected_tree,
            phase=identity.phase,
            owning_pipeline_id=identity.owning_pipeline_id,
            active_session_id=identity.active_session_id,
            active_run_id=identity.active_run_id,
            worktree_path=identity.path,
            image_version=identity.image_version,
            runtime_version=identity.runtime_version,
        )
    )

    assert worktrees.validate_checkpoint(path, identity)
    assert not worktrees.validate_checkpoint(
        path, replace(identity, task_id="task-wrong")
    )
    assert not worktrees.validate_checkpoint(
        path, replace(identity, owning_pipeline_id="pipeline-wrong")
    )
    assert not worktrees.validate_checkpoint(
        path, replace(identity, runtime_version="runtime-wrong")
    )
    assert not worktrees.validate_checkpoint(config.worktrees_dir, identity)
