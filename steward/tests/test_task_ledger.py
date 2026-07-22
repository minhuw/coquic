from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import (
    TaskKind,
    TaskSpec,
    WorkerKind,
    WorktreeCheckpoint,
)
from coquic_steward.storage import TaskStore


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


def test_legacy_database_migration_preserves_source_and_marks_backup(
    repo: Path, coquic_home: Path
) -> None:
    config = StewardConfig(repo_root=repo)
    config.ensure_dirs()
    with sqlite3.connect(config.legacy_db_path) as connection:
        connection.execute("CREATE TABLE fixture (value TEXT)")
        connection.execute("INSERT INTO fixture VALUES ('kept')")
    config.migrate_legacy_database()
    assert config.db_path.exists()
    assert config.legacy_backup_path.exists()
    assert config.migration_marker_path.exists()
    with sqlite3.connect(config.db_path) as connection:
        assert connection.execute("SELECT value FROM fixture").fetchone() == ("kept",)


def test_ledger_allocates_ordered_lineage_and_private_fields(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="ledger",
            prompt="prompt",
        )
    )
    pipeline = store.list_pipelines(task.id)[0]
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


def test_concurrent_pipeline_ordinals_are_unique(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )

    def allocate(_: int) -> int:
        return store.create_pipeline(task.id, trigger="validation-repair").ordinal

    with ThreadPoolExecutor(max_workers=4) as executor:
        ordinals = list(executor.map(allocate, range(8)))
    assert sorted(ordinals) == list(range(2, 10))


def test_checkpoint_round_trip(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
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
    store.save_checkpoint(checkpoint)
    assert store.checkpoint_matches(
        execution.id, base_commit="a" * 40, expected_tree="b" * 40
    )


def test_invalid_recovery_lineage_is_rejected(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="x", prompt="p")
    )
    pipeline = store.list_pipelines(task.id)[0]
    session = store.create_session(task.id, pipeline.id)
    run = store.create_run(task.id, pipeline.id, session.id, role="implementation")
    with pytest.raises(ValueError, match="interrupted"):
        store.link_recovery_run(run.id)
