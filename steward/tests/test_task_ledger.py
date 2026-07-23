from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from coquic_steward.core.config import StewardConfig, load_config
from coquic_steward.core.models import (
    TaskKind,
    TaskSpec,
    WorkerKind,
    WorktreeCheckpoint,
)
from coquic_steward.storage import TaskStore
from coquic_steward.execution.worktree import Worktrees


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


def test_normal_startup_migrates_legacy_database(
    repo: Path, coquic_home: Path
) -> None:
    config = StewardConfig(repo_root=repo)
    config.ensure_dirs()
    legacy_store = TaskStore(config.legacy_db_path)
    task, _ = legacy_store.add_task(
        TaskSpec(
            kind=TaskKind.custom,
            worker=WorkerKind.custom,
            title="legacy",
            prompt="prompt",
        )
    )
    legacy_store.engine.dispose()

    startup_config = load_config(repo_root=repo)
    current_store = TaskStore(startup_config.db_path)

    assert current_store.get(task.id).id == task.id
    assert not startup_config.legacy_db_path.exists()
    assert startup_config.legacy_backup_path.exists()


def test_migration_restart_reconciles_stranded_wal(
    repo: Path, coquic_home: Path
) -> None:
    config = StewardConfig(repo_root=repo)
    config.ensure_dirs()
    connection = sqlite3.connect(config.legacy_db_path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE fixture (value TEXT)")
    connection.commit()
    connection.execute("INSERT INTO fixture VALUES ('wal-only')")
    connection.commit()
    real_replace = os.replace

    def crash_after_database_rename(source: Path, destination: Path) -> None:
        real_replace(source, destination)
        if Path(source) == config.legacy_db_path:
            raise RuntimeError("simulated migration interruption")

    with patch(
        "coquic_steward.core.config.os.replace",
        side_effect=crash_after_database_rename,
    ), pytest.raises(RuntimeError, match="interruption"):
        config.migrate_legacy_database()
    connection.close()

    config.migrate_legacy_database()

    with sqlite3.connect(config.legacy_backup_path) as backup:
        assert backup.execute("SELECT value FROM fixture").fetchall() == [
            ("wal-only",)
        ]
    assert config.migration_marker_path.exists()


def test_migration_restart_rebuilds_incomplete_read_only_backup(
    repo: Path, coquic_home: Path
) -> None:
    config = StewardConfig(repo_root=repo)
    config.ensure_dirs()
    with sqlite3.connect(config.legacy_db_path) as source:
        source.execute("CREATE TABLE fixture (value TEXT)")
        source.execute("INSERT INTO fixture VALUES ('committed')")
        source.commit()
        with sqlite3.connect(config.db_path) as destination:
            source.backup(destination)
    config.legacy_db_path.unlink()
    for suffix in ("-wal", "-shm"):
        config.legacy_db_path.with_name(
            config.legacy_db_path.name + suffix
        ).unlink(missing_ok=True)
    with sqlite3.connect(config.legacy_backup_path):
        pass
    os.chmod(config.legacy_backup_path, 0o440)
    config.migration_marker_path.write_text("{}\n", encoding="utf-8")

    config = load_config(repo_root=repo)

    with sqlite3.connect(config.legacy_backup_path) as backup:
        assert backup.execute("SELECT value FROM fixture").fetchall() == [
            ("committed",)
        ]
    assert config.legacy_backup_path.with_name(
        config.legacy_backup_path.name + ".interrupted"
    ).exists()


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


def test_execution_and_checkpoint_pointers_are_task_scoped(
    config: StewardConfig,
) -> None:
    store = TaskStore(config.db_path)

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
        store.save_checkpoint(
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
    checkpoint = store.save_checkpoint(
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
    store = TaskStore(config.db_path)

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
    store.save_checkpoint(
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
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)

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
    store = TaskStore(config.db_path)
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


def test_interrupted_run_has_only_one_recovery(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
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
    store = TaskStore(config.db_path)

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
    store = TaskStore(config.db_path)
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
    store.save_checkpoint(
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
    store = TaskStore(config.db_path)
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
    store.save_checkpoint(
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
