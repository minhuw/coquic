from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import coquic_steward.storage.sqlite as sqlite_module
from coquic_steward.execution.task_archive import TaskArchive
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    PublicationGeneration,
    PublicationState,
)
from coquic_steward.storage import SQLiteStoreLifecycleError, StoreRecoveryResult, TaskStore
from coquic_steward.storage.sqlite import (
    CURRENT_SCHEMA_CATALOG_DIGEST,
    SQLITE_USER_VERSION,
)


def _catalog_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    payload = [
        [str(kind), str(name), str(table), sql]
        for kind, name, table, sql in rows
    ]
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    ).hexdigest()


def test_current_schema_oracle_is_complete_and_seeded(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (
            SQLITE_USER_VERSION,
        )
        assert _catalog_digest(connection) == CURRENT_SCHEMA_CATALOG_DIGEST
        assert connection.execute(
            "SELECT value FROM control_loop_meta WHERE key='epoch_id'"
        ).fetchone() == (store.control_loop.epoch_id,)
        assert connection.execute(
            "SELECT value FROM control_loop_meta WHERE key='next_sequence'"
        ).fetchone() == ("0",)
        assert connection.execute(
            "SELECT value FROM control_loop_meta WHERE key='planning_blocked'"
        ).fetchone() == ("0",)
        assert connection.execute(
            "SELECT id,queued_count,blocked_count,cleanup_pending_count,cleanup_pending_bytes "
            "FROM publication_health"
        ).fetchone()[:5] == (1, 0, 0, 0, 0)

        overhead_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(control_loop_overhead_usage)"
            )
        ]
        assert overhead_columns == [
            "usage_date",
            "model",
            "owner_class",
            "tokens_json",
            "costs_json",
            "coverage_json",
        ]
        marker_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(control_loop_overhead_usage_runs)"
            )
        ]
        assert marker_columns == [
            "planner_run_id",
            "archive_digest",
            "processed_at",
            "rows_json",
            "cost_pending",
        ]
        index_names = {
            row[1]
            for row in connection.execute(
                "PRAGMA index_list(control_loop_overhead_usage_runs)"
            )
        }
        assert "ix_control_loop_overhead_pending" in index_names


def test_create_and_open_bind_the_immutable_task_epoch_and_callback(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    calls: list[str] = []

    def on_change() -> None:
        calls.append("changed")

    created = TaskStore.create(database, on_change=on_change)
    reopened = TaskStore.open(database, on_change=on_change)

    assert created.on_change is on_change
    assert reopened.on_change is on_change
    assert created.control_loop.epoch_id == reopened.control_loop.epoch_id
    assert json.loads(
        (tmp_path / "tasks" / "epoch.json").read_text(encoding="utf-8")
    )["epochId"] == created.control_loop.epoch_id
    assert calls == []


def test_publication_leaves_an_exact_store_if_database_link_is_interrupted(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "steward.sqlite"
    original_link = sqlite_module.os.link

    def interrupted_link(source, target, *args, **kwargs):
        result = original_link(source, target, *args, **kwargs)
        if Path(target) == database:
            raise RuntimeError("interrupted after database publication")
        return result

    monkeypatch.setattr(sqlite_module.os, "link", interrupted_link)
    with pytest.raises(RuntimeError, match="interrupted"):
        TaskStore.create(database)

    assert database.is_file()
    assert database.with_name(database.name + "-wal").is_file()
    assert database.with_name(database.name + "-shm").is_file()
    reopened = TaskStore.open(database)
    reopened.engine.dispose()
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)


def test_create_refuses_partial_sidecar_publication_without_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "steward.sqlite"
    original_link = sqlite_module.os.link
    interrupted = False

    def interrupted_link(source, target, *args, **kwargs):
        nonlocal interrupted
        result = original_link(source, target, *args, **kwargs)
        if not interrupted and Path(target) == database.with_name(database.name + "-wal"):
            interrupted = True
            raise RuntimeError("interrupted after sidecar publication")
        return result

    monkeypatch.setattr(sqlite_module.os, "link", interrupted_link)
    with pytest.raises(RuntimeError, match="sidecar"):
        TaskStore.create(database)

    assert not database.exists()
    assert database.with_name(database.name + "-wal").is_file()

    def snapshot() -> dict[str, tuple[int, int, int, bytes | None]]:
        return {
            path.name: (
                path.stat().st_ino,
                path.stat().st_size,
                path.stat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None,
            )
            for path in tmp_path.iterdir()
        }

    before = snapshot()
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)
    assert snapshot() == before


def test_concurrent_create_does_not_remove_a_live_sidecar(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "steward.sqlite"
    wal = database.with_name(database.name + "-wal")
    original_link = sqlite_module.os.link
    original_new_temporary = sqlite_module.SQLiteTaskStore._new_database_temporary
    wal_linked = threading.Event()
    allow_creator_a = threading.Event()
    creator_b_done = threading.Event()
    outcomes: dict[str, object] = {}

    def paused_link(source, target, *args, **kwargs):
        result = original_link(source, target, *args, **kwargs)
        if threading.current_thread().name == "store-creator-a" and Path(target) == wal:
            wal_linked.set()
            if not allow_creator_a.wait(timeout=5):
                raise RuntimeError("timed out waiting for the competing creator")
        return result

    def stop_creator_b(cls, path, epoch_id):
        if threading.current_thread().name == "store-creator-b":
            raise RuntimeError("creator B stopped before publication")
        return original_new_temporary(path, epoch_id)

    monkeypatch.setattr(sqlite_module.os, "link", paused_link)
    monkeypatch.setattr(
        sqlite_module.SQLiteTaskStore,
        "_new_database_temporary",
        classmethod(stop_creator_b),
    )

    def create_store(key: str) -> None:
        try:
            store = TaskStore.create(database)
            store.engine.dispose()
            outcomes[key] = "ok"
        except BaseException as exc:
            outcomes[key] = exc
        finally:
            if key == "store-creator-b":
                creator_b_done.set()

    creator_a = threading.Thread(
        target=create_store, args=("store-creator-a",), name="store-creator-a"
    )
    creator_b = threading.Thread(
        target=create_store, args=("store-creator-b",), name="store-creator-b"
    )
    creator_a.start()
    assert wal_linked.wait(timeout=5)
    wal_inode = wal.stat().st_ino
    try:
        creator_b.start()
        assert creator_b_done.wait(timeout=5)
        assert isinstance(outcomes.get("store-creator-b"), SQLiteStoreLifecycleError)
        assert wal.is_file()
        assert wal.stat().st_ino == wal_inode
    finally:
        allow_creator_a.set()
        creator_a.join(timeout=10)
        creator_b.join(timeout=10)

    assert not creator_a.is_alive()
    assert not creator_b.is_alive()
    assert outcomes["store-creator-a"] == "ok"
    assert database.is_file()
    assert wal.is_file()
    assert database.with_name(database.name + "-shm").is_file()


def test_open_validation_does_not_repair_or_write(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    TaskStore.create(database).engine.dispose()
    tracked = [database, database.with_name("steward.sqlite-wal"), database.with_name("steward.sqlite-shm")]
    before = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in tracked}

    opened = TaskStore.open(database)
    opened.engine.dispose()

    after = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in tracked}
    assert after == before


def test_create_rejects_existing_target_and_extra_archive_state(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    TaskStore.create(database).engine.dispose()
    before = {path: path.stat().st_mtime_ns for path in tmp_path.iterdir()}
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)
    assert {path: path.stat().st_mtime_ns for path in tmp_path.iterdir()} == before

    other_root = tmp_path / "other"
    tasks = other_root / "tasks"
    tasks.mkdir(parents=True)
    (tasks / "visible-state").write_text("not an epoch", encoding="utf-8")
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(other_root / "steward.sqlite")
    assert not (tasks / "epoch.json").exists()
    assert not (other_root / "steward.sqlite").exists()


def test_create_rejects_a_database_rollback_journal_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    journal = database.with_name(database.name + "-journal")
    journal.write_bytes(b"journal-remnant")

    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)

    assert journal.read_bytes() == b"journal-remnant"
    assert not database.exists()
    assert not (tmp_path / "tasks").exists()


def test_create_rebuilds_instead_of_adopting_recognized_database_temporary(
    tmp_path: Path,
) -> None:
    tasks = tmp_path / "tasks"
    epoch_id = TaskArchive(tasks).ensure_epoch()["epochId"]
    remnant = tmp_path / f".steward.sqlite.create-{epoch_id}-interrupted.tmp"
    remnant.write_bytes(b"not a database")

    store = TaskStore.create(tmp_path / "steward.sqlite")

    assert store.control_loop.epoch_id == epoch_id
    assert remnant.exists()
    assert (tmp_path / "steward.sqlite").is_file()


def test_open_rejects_version_corruption_without_repair(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    TaskStore.create(database).engine.dispose()
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 999")
        connection.commit()
    before = database.read_bytes()

    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.open(database)

    assert database.read_bytes() == before


def test_open_rejects_a_sequence_seed_inconsistent_with_an_empty_ledger(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    TaskStore.create(database).engine.dispose()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE control_loop_meta SET value='7' WHERE key='next_sequence'"
        )
        connection.commit()
    before = database.read_bytes()

    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.open(database)

    assert database.read_bytes() == before


def test_open_accepts_a_sequence_seed_for_a_valid_evolved_ledger(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    event = store.control_loop.record_runtime("running")
    store.engine.dispose()

    reopened = TaskStore.open(database)
    try:
        assert event.sequence == 0
        assert reopened.control_loop.list_events()[0].sequence == 0
    finally:
        reopened.engine.dispose()


def _stale_publication_generation() -> tuple[PublicationGeneration, datetime]:
    now = datetime.now(timezone.utc) - timedelta(days=2)
    identity = GenerationIdentity("task-recovery", "boundary-recovery")
    return (
        PublicationGeneration(
            publication_id=identity.publication_id,
            task_id=identity.task_id,
            run_id="run-recovery",
            generation_boundary=identity.stable_boundary,
            metadata_digest="a" * 64,
            idempotency_key=identity.idempotency_key,
            created_at=now,
            updated_at=now,
        ),
        now,
    )


def test_open_defers_stale_lease_recovery_to_explicit_recover(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    generation, now = _stale_publication_generation()
    store.enqueue_publication(generation)
    store.claim_publication("recovery-worker", now=now)
    store.engine.dispose()

    opened = TaskStore.open(database)
    try:
        before = opened.get_publication_generation(generation.publication_id)
        assert before is not None
        assert before.state is PublicationState.claimed
        result = opened.recover()
        assert result == StoreRecoveryResult(
            expired_leases=1, health_changed=True, changed=True
        )
        recovered = opened.get_publication_generation(generation.publication_id)
        assert recovered is not None
        assert recovered.state is PublicationState.retry_wait
        assert recovered.lease_owner is None
    finally:
        opened.engine.dispose()

    committed = TaskStore.open(database)
    try:
        recovered = committed.get_publication_generation(generation.publication_id)
        assert recovered is not None
        assert recovered.state is PublicationState.retry_wait
        assert committed.get_publication_health().queued_count == 1
    finally:
        committed.engine.dispose()


def test_recover_current_state_is_write_free(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    TaskStore.create(database).engine.dispose()
    tracked = [
        database,
        database.with_name("steward.sqlite-wal"),
        database.with_name("steward.sqlite-shm"),
    ]
    before = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in tracked}

    opened = TaskStore.open(database)
    try:
        assert opened.recover() == StoreRecoveryResult()
    finally:
        opened.engine.dispose()

    after = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in tracked}
    assert after == before


def test_recover_repairs_derived_health_without_lease_changes(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE publication_health SET queued_count=7 WHERE id=1"
        )
        connection.commit()
    store.engine.dispose()

    opened = TaskStore.open(database)
    try:
        result = opened.recover()
        assert result == StoreRecoveryResult(
            expired_leases=0, health_changed=True, changed=True
        )
        assert opened.get_publication_health().queued_count == 0
        assert opened.recover() == StoreRecoveryResult()
    finally:
        opened.engine.dispose()


def test_recover_rolls_back_lease_and_health_changes_on_failure(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    generation, now = _stale_publication_generation()
    store.enqueue_publication(generation)
    store.claim_publication("recovery-worker", now=now)
    before_health = store.get_publication_health()

    def fail_refresh(*_args, **_kwargs):
        raise RuntimeError("health refresh failed")

    monkeypatch.setattr(store, "_refresh_publication_health", fail_refresh)
    with pytest.raises(RuntimeError, match="health refresh"):
        store.recover()
    store.engine.dispose()

    reopened = TaskStore.open(database)
    try:
        unchanged = reopened.get_publication_generation(generation.publication_id)
        assert unchanged is not None
        assert unchanged.state is PublicationState.claimed
        assert unchanged.lease_owner == "recovery-worker"
        after_health = reopened.get_publication_health()
        assert after_health.queued_count == before_health.queued_count
        assert after_health.blocked_count == before_health.blocked_count
        assert after_health.cleanup_pending_count == before_health.cleanup_pending_count
        assert after_health.cleanup_pending_bytes == before_health.cleanup_pending_bytes
    finally:
        reopened.engine.dispose()
