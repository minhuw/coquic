from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

import coquic_steward.storage.sqlite as sqlite_module
from coquic_steward.core.models import (
    Priority,
    Risk,
    TaskKind,
    TaskSpec,
    TaskWorkflow,
    WorkerKind,
    utc_now,
)
from coquic_steward.execution.task_archive import TaskArchive
from coquic_steward.publication.outbox import (
    GenerationIdentity,
    OutboxValidationError,
    PublicationGeneration,
    PublicationRetryPolicy,
    PublicationState,
    _PERSISTED_REASON_VALUES,
)
from coquic_steward.storage import (
    SQLiteStoreLifecycleError,
    StoreRecoveryResult,
    TaskStore,
)
from coquic_steward.core.config import StewardConfig
from coquic_steward.storage.schema import EventRow, TaskIterationRow, TaskRow, ValidationRow
from coquic_steward.storage.sqlite import (
    CURRENT_SCHEMA_CATALOG_DIGEST,
    SQLITE_USER_VERSION,
)
from publication_harness import enqueue_publication as _enqueue_publication


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


def _create_pre_018_empty_catalog(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        for name in (
            "ix_signal_items_provider",
            "ix_signal_items_kind",
            "ix_signal_items_created_at",
            "ix_signal_items_updated_at",
            "ix_signal_items_status",
            "ix_signal_items_provider_fingerprint_status",
        ):
            connection.execute(f'DROP INDEX "{name}"')
        connection.execute("ALTER TABLE signal_items RENAME TO signal_items_pre_018")
        connection.execute(
            """
            CREATE TABLE signal_items (
                id VARCHAR NOT NULL,
                provider VARCHAR NOT NULL,
                kind VARCHAR NOT NULL,
                fingerprint VARCHAR NOT NULL,
                title VARCHAR NOT NULL,
                summary TEXT NOT NULL,
                severity VARCHAR,
                location_json TEXT,
                links_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status VARCHAR NOT NULL,
                created_at VARCHAR NOT NULL,
                updated_at VARCHAR NOT NULL,
                planned_at VARCHAR,
                planner_run_id VARCHAR,
                planned_task_id VARCHAR,
                source_fetch_id VARCHAR,
                PRIMARY KEY (id)
            )
            """
        )
        connection.execute("DROP TABLE signal_items_pre_018")
        connection.execute(
            "CREATE INDEX ix_signal_items_provider ON signal_items (provider)"
        )
        connection.execute("CREATE INDEX ix_signal_items_kind ON signal_items (kind)")
        connection.execute(
            "CREATE INDEX ix_signal_items_created_at ON signal_items (created_at)"
        )
        connection.execute(
            "CREATE INDEX ix_signal_items_updated_at ON signal_items (updated_at)"
        )
        connection.execute("CREATE INDEX ix_signal_items_status ON signal_items (status)")
        connection.execute(
            "CREATE UNIQUE INDEX ix_signal_items_provider_fingerprint_status "
            "ON signal_items (provider, fingerprint) WHERE status = 'pending'"
        )
        connection.execute("PRAGMA user_version = 1")
        connection.commit()


def _file_snapshot(root: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and path.name != "steward.sqlite-shm"
    }


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

        signal_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(signal_items)")
        ]
        assert signal_columns == [
            "id",
            "provider",
            "kind",
            "fingerprint",
            "workflow_run_id",
            "workflow_run_attempt",
            "title",
            "summary",
            "severity",
            "location_json",
            "links_json",
            "payload_json",
            "status",
            "created_at",
            "updated_at",
            "planned_at",
            "planner_run_id",
            "planned_task_id",
            "source_fetch_id",
        ]
        workflow_index = next(
            row
            for row in connection.execute("PRAGMA index_list(signal_items)")
            if row[1] == "ix_signal_items_provider_workflow_identity"
        )
        assert workflow_index[2] == 0
        assert [
            row[2]
            for row in sorted(
                connection.execute(
                    "PRAGMA index_info(ix_signal_items_provider_workflow_identity)"
                ),
                key=lambda row: row[0],
            )
        ] == [
            "provider",
            "workflow_run_id",
            "workflow_run_attempt",
            "updated_at",
        ]


def test_sqlite_reason_vocabulary_matches_outbox() -> None:
    assert sqlite_module._PERSISTED_REASON_SET == frozenset(_PERSISTED_REASON_VALUES)

    for reason in _PERSISTED_REASON_VALUES:
        assert sqlite_module._publication_reason(reason) == reason

    with pytest.raises(OutboxValidationError):
        sqlite_module._publication_reason("arbitrary")


def test_create_and_open_bind_the_immutable_task_epoch_and_callback(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    calls: list[str] = []

    def on_change() -> None:
        calls.append("changed")

    created = TaskStore.create(database, on_change=on_change)
    reopened = TaskStore.open(database, on_change=on_change)

    assert created.on_change is on_change
    assert reopened.on_change is on_change
    assert created.control_loop is created.control_loop_ledger
    assert reopened.control_loop is reopened.control_loop_ledger
    assert created.control_loop.epoch_id == reopened.control_loop.epoch_id
    assert json.loads(
        (tmp_path / "tasks" / "epoch.json").read_text(encoding="utf-8")
    )["epochId"] == created.control_loop_ledger.epoch_id
    with pytest.raises(AttributeError):
        created.control_loop = None
    with pytest.raises(AttributeError):
        created.control_loop_ledger = None
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


def test_finalization_keeps_a_concurrent_wal_commit_authoritative(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    created = TaskStore.create(database, dry_run=True)
    created._finalize_exact_store()
    observer = TaskStore.open(database)
    writer = TaskStore.open(database)
    try:
        writer.add_task(
            TaskSpec(
                id="task-finalize-concurrent",
                kind=TaskKind.custom,
                workflow=TaskWorkflow.fix,
                worker=WorkerKind.custom,
                title="concurrent commit",
                prompt="preserve the current WAL",
            )
        )
        wal = database.with_name(database.name + "-wal")
        wal_before = wal.read_bytes()
        assert wal_before
        writer.engine.dispose()

        observer._finalize_exact_store()

        assert wal.read_bytes() == wal_before
        reopened = TaskStore.open(database)
        try:
            assert reopened.get("task-finalize-concurrent").id == (
                "task-finalize-concurrent"
            )
        finally:
            reopened.engine.dispose()
    finally:
        writer.engine.dispose()


def test_finalized_store_is_reopenable_from_a_new_process(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database, dry_run=True)
    store._finalize_exact_store()

    epoch = database.parent / "tasks" / "epoch.json"
    tracked = (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
        epoch,
    )

    def snapshot() -> dict[Path, tuple[bytes, int, int]]:
        return {
            path: (
                path.read_bytes(),
                path.stat().st_mode & 0o777,
                path.stat().st_mtime_ns,
            )
            for path in tracked
        }

    before = snapshot()
    source_root = Path(__file__).resolve().parents[1] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(source_root), environment.get("PYTHONPATH")))
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from pathlib import Path
import sys
from coquic_steward.storage import TaskStore
store = TaskStore.open(Path(sys.argv[1]), dry_run=True)
store._finalize_exact_store()
print("reopenable")
""",
            str(database),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.stdout.strip() == "reopenable"
    assert snapshot() == before

    reopened = TaskStore.open(database, dry_run=False)
    reopened.engine.dispose()


def test_open_ignores_valid_sibling_json_without_mutation(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    created = TaskStore.create(database)
    created.engine.dispose()

    sibling = database.parent / "steward.json"
    sibling.write_text(
        json.dumps(
            {
                "tasks": [
                    {
                        "spec": {
                            "id": "task-legacy-import",
                            "kind": "custom",
                            "workflow": "fix",
                            "worker": "custom",
                            "title": "legacy task",
                            "prompt": "legacy prompt",
                        }
                    }
                ],
                "events": [
                    {
                        "task_id": "task-legacy-import",
                        "kind": "task.created",
                        "message": "legacy task",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    before = sibling.read_bytes()

    opened = TaskStore.open(database)
    try:
        assert opened.list_tasks() == []
        assert opened.events("task-legacy-import") == []
    finally:
        opened.engine.dispose()

    assert sibling.read_bytes() == before


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


def test_open_rejects_pre_018_empty_catalog_without_mutation(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    store.engine.dispose()
    (tmp_path / "control-loop").mkdir()
    _create_pre_018_empty_catalog(database)

    before = _file_snapshot(tmp_path)
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.open(database)
    assert _file_snapshot(tmp_path) == before

    for path in (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    ):
        path.unlink(missing_ok=True)
    shutil.rmtree(tmp_path / "tasks")
    shutil.rmtree(tmp_path / "control-loop")

    recreated = TaskStore.create(database)
    try:
        with sqlite3.connect(database) as connection:
            assert connection.execute("PRAGMA user_version").fetchone() == (
                SQLITE_USER_VERSION,
            )
    finally:
        recreated.engine.dispose()


def test_create_rejects_sqlite_only_deleted_root_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    store.engine.dispose()
    for path in (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    ):
        path.unlink(missing_ok=True)

    before = _file_snapshot(tmp_path)
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)
    assert _file_snapshot(tmp_path) == before


def test_create_rejects_populated_deleted_target_with_a_valid_sibling(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.sqlite"
    target_store = TaskStore.create(target)
    target_store.control_loop.record_runtime("running", {"evidence": "durable-evidence"})
    sibling = tmp_path / "sibling.sqlite"
    sibling_store = TaskStore.create(sibling)
    target_store.engine.dispose()
    sibling_store.engine.dispose()

    for path in (
        target,
        target.with_name(target.name + "-wal"),
        target.with_name(target.name + "-shm"),
    ):
        path.unlink(missing_ok=True)

    before = _file_snapshot(tmp_path)
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(target)

    assert _file_snapshot(tmp_path) == before
    assert not target.exists()
    reopened_sibling = TaskStore.open(sibling)
    reopened_sibling.engine.dispose()


def test_create_rejects_populated_control_loop_root_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    store.engine.dispose()
    control_loop = tmp_path / "control-loop"
    control_loop.mkdir()
    (control_loop / "retained-state").write_bytes(b"evidence")
    for path in (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    ):
        path.unlink(missing_ok=True)

    before = _file_snapshot(tmp_path)
    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)
    assert _file_snapshot(tmp_path) == before


def test_create_rejects_retained_state_despite_an_unrelated_sibling_store(
    tmp_path: Path,
) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)
    epoch_id = store.control_loop.epoch_id
    store.engine.dispose()

    control_loop = tmp_path / "control-loop"
    control_loop.mkdir()
    retained_state = control_loop / "retained-state"
    retained_state.write_bytes(b"evidence")
    for path in (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    ):
        path.unlink(missing_ok=True)

    sibling = tmp_path / "other.sqlite"
    sibling.write_bytes(b"unrelated")
    (tmp_path / "other.sqlite-wal").write_bytes(b"wal")
    (tmp_path / "other.sqlite-shm").write_bytes(b"shm")
    before = _file_snapshot(tmp_path)

    with pytest.raises(SQLiteStoreLifecycleError):
        TaskStore.create(database)

    assert _file_snapshot(tmp_path) == before
    assert json.loads(
        (tmp_path / "tasks" / "epoch.json").read_text(encoding="utf-8")
    )["epochId"] == epoch_id
    assert retained_state.read_bytes() == b"evidence"


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
    _enqueue_publication(store, generation)
    store.claim_publication(
        "recovery-worker", retry_policy=PublicationRetryPolicy(), now=now
    )
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
    _enqueue_publication(store, generation)
    store.claim_publication(
        "recovery-worker", retry_policy=PublicationRetryPolicy(), now=now
    )
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

def test_store_persists_tasks_in_sqlite(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.ci,
            worker=WorkerKind.ci_doctor,
            title="CI",
            prompt="fix",
            priority=Priority.high,
            risk=Risk.medium,
        )
    )

    reopened = TaskStore.open(config.db_path)
    saved = reopened.get(task.id)
    assert saved.spec.title == "CI"
    assert reopened.count_events("task.created") == 1

def test_store_persists_state_artifact_paths_relative(config: StewardConfig) -> None:
    from coquic_steward.core.models import ValidationResult

    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    task.worktree_path = config.worktrees_dir / task.id
    task.transcript_path = config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    task.last_message_path = (
        config.transcripts_dir / task.id / "worker" / "last-message.md"
    )
    task.patch_path = config.patches_dir / task.id / "iteration-0.patch"
    task.spec.metadata = {
        "source_patch_path": str(task.patch_path),
        "source_worktree_path": str(task.worktree_path),
        "note": "patches/looks-like-text",
    }
    validation_log = config.logs_dir / task.id / "iteration-0" / "validation.txt"
    task.validations.append(
        ValidationResult(
            command=["fake"],
            cwd=config.repo_root,
            passed=True,
            exit_code=0,
            output_path=validation_log,
        )
    )
    store.save(task)
    store.add_event(
        task.id,
        "artifact.ready",
        str(task.patch_path),
        {
            "patch_path": str(task.patch_path),
            "failed": [{"output_path": str(validation_log)}],
            "note": "patches/looks-like-text",
        },
    )
    store.begin_iteration(
        task.id,
        0,
        "Initial attempt",
        worker_name="worker",
        worker_prompt_path=config.prompts_dir / task.id / "worker.md",
        worker_transcript_path=task.transcript_path,
        worker_last_message_path=task.last_message_path,
    )
    store.record_iteration_patch(task.id, 0, task.patch_path)

    with Session(store.engine) as session:
        row = session.get(TaskRow, task.id)
        assert row is not None
        validation = session.query(ValidationRow).filter_by(task_id=task.id).one()
        iteration = session.query(TaskIterationRow).filter_by(task_id=task.id).one()
        assert row.worktree_path == f"worktrees/{task.id}"
        assert row.transcript_path == f"steward/transcripts/{task.id}/worker/codex.jsonl"
        assert row.last_message_path == f"steward/transcripts/{task.id}/worker/last-message.md"
        assert row.patch_path == f"steward/patches/{task.id}/iteration-0.patch"
        assert json.loads(row.metadata_json) == {
            "execution_mode": "live",
            "note": "patches/looks-like-text",
            "source_patch_path": f"steward/patches/{task.id}/iteration-0.patch",
            "source_worktree_path": f"worktrees/{task.id}",
        }
        assert validation.output_path == f"steward/logs/{task.id}/iteration-0/validation.txt"
        assert validation.cwd == str(config.repo_root)
        assert iteration.worker_prompt_path == f"steward/prompts/{task.id}/worker.md"
        assert iteration.worker_transcript_path == f"steward/transcripts/{task.id}/worker/codex.jsonl"
        assert iteration.worker_last_message_path == f"steward/transcripts/{task.id}/worker/last-message.md"
        assert iteration.patch_path == f"steward/patches/{task.id}/iteration-0.patch"
        event = session.query(EventRow).filter_by(kind="artifact.ready").one()
        assert event.message == f"steward/patches/{task.id}/iteration-0.patch"
        assert json.loads(event.data_json) == {
            "failed": [{"output_path": f"steward/logs/{task.id}/iteration-0/validation.txt"}],
            "note": "patches/looks-like-text",
            "patch_path": f"steward/patches/{task.id}/iteration-0.patch",
        }

    reopened = TaskStore.open(config.db_path)
    saved = reopened.get(task.id)
    iteration = reopened.get_iteration(task.id, 0)
    assert saved.worktree_path == config.worktrees_dir / task.id
    assert saved.transcript_path == config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    assert saved.spec.metadata["source_patch_path"] == str(task.patch_path)
    assert saved.spec.metadata["source_worktree_path"] == str(task.worktree_path)
    assert saved.spec.metadata["note"] == "patches/looks-like-text"
    assert saved.validations[0].output_path == validation_log
    assert saved.validations[0].cwd == config.repo_root
    event_data = next(
        event.data for event in reopened.events(task.id) if event.kind == "artifact.ready"
    )
    event = next(event for event in reopened.events(task.id) if event.kind == "artifact.ready")
    assert event.message == str(task.patch_path)
    assert event_data["patch_path"] == str(task.patch_path)
    assert event_data["failed"][0]["output_path"] == str(validation_log)
    assert event_data["note"] == "patches/looks-like-text"
    assert iteration.worker_prompt_path == config.prompts_dir / task.id / "worker.md"
    assert iteration.patch_path == config.patches_dir / task.id / "iteration-0.patch"

def test_store_leaves_external_paths_absolute(config: StewardConfig, tmp_path: Path) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    external = tmp_path / "external-worktree"
    task.worktree_path = external

    store.save(task)

    with Session(store.engine) as session:
        row = session.get(TaskRow, task.id)
        assert row is not None
        assert row.worktree_path == str(external)
    assert TaskStore.open(config.db_path).get(task.id).worktree_path == external

def test_store_ignores_historic_relative_path_root(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    historic = config.state_dir / "logs" / task.id / "historic.txt"
    historic.parent.mkdir(parents=True, exist_ok=True)
    historic.write_text("historic\n", encoding="utf-8")
    relative = f"logs/{task.id}/historic.txt"
    current = config.db_path.parent / relative

    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.patch_path = relative
        row.metadata_json = json.dumps({"source_patch_path": relative})

    reopened = TaskStore.open(config.db_path)
    saved = reopened.get(task.id)
    assert saved.patch_path == current
    assert saved.patch_path != historic
    assert saved.spec.metadata["source_patch_path"] == str(current)

def test_store_open_preserves_existing_absolute_state_paths(config: StewardConfig) -> None:
    store = TaskStore.create(config.db_path)
    task, _ = store.add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )
    absolute_patch = config.patches_dir / task.id / "iteration-0.patch"
    with Session(store.engine) as session, session.begin():
        row = session.get(TaskRow, task.id)
        assert row is not None
        row.patch_path = str(absolute_patch)
        row.metadata_json = json.dumps(
            {
                "source_patch_path": str(absolute_patch),
                "source_worktree_path": str(config.worktrees_dir / task.id),
            }
        )
        session.add(
            TaskIterationRow(
                task_id=task.id,
                iteration=0,
                label="Initial attempt",
                worker_name="worker",
                worker_prompt_path=str(config.prompts_dir / task.id / "worker.md"),
                worker_transcript_path=str(
                    config.transcripts_dir / task.id / "worker" / "codex.jsonl"
                ),
                worker_last_message_path=str(
                    config.transcripts_dir / task.id / "worker" / "last-message.md"
                ),
                patch_path=str(absolute_patch),
                started_at=utc_now().isoformat(),
                updated_at=utc_now().isoformat(),
            )
        )
        session.add(
            ValidationRow(
                task_id=task.id,
                iteration=0,
                position=0,
                command_json="[]",
                cwd=str(config.worktrees_dir / task.id),
                passed=True,
                exit_code=0,
                output_path=str(config.logs_dir / task.id / "validation.txt"),
                summary="",
                started_at=utc_now().isoformat(),
                completed_at=utc_now().isoformat(),
            )
        )
        session.add(
            EventRow(
                task_id=task.id,
                kind="artifact.ready",
                message=str(absolute_patch),
                created_at=utc_now().isoformat(),
                data_json=json.dumps({"patch_path": str(absolute_patch)}),
            )
        )

    reopened = TaskStore.open(config.db_path)

    with Session(reopened.engine) as session:
        row = session.get(TaskRow, task.id)
        iteration = session.query(TaskIterationRow).filter_by(task_id=task.id).one()
        validation = session.query(ValidationRow).filter_by(task_id=task.id).one()
        event = session.query(EventRow).filter_by(task_id=task.id, kind="artifact.ready").one()
        assert row is not None
        assert row.patch_path == str(absolute_patch)
        assert json.loads(row.metadata_json) == {
            "source_patch_path": str(absolute_patch),
            "source_worktree_path": str(config.worktrees_dir / task.id),
        }
        assert iteration.worker_prompt_path == str(
            config.prompts_dir / task.id / "worker.md"
        )
        assert iteration.patch_path == str(absolute_patch)
        assert validation.cwd == str(config.worktrees_dir / task.id)
        assert validation.output_path == str(
            config.logs_dir / task.id / "validation.txt"
        )
        assert event.message == str(absolute_patch)
        assert json.loads(event.data_json) == {"patch_path": str(absolute_patch)}
    assert reopened.get(task.id).patch_path == absolute_patch
    assert reopened.get(task.id).spec.metadata["source_patch_path"] == str(absolute_patch)
    assert (
        reopened.get_iteration(task.id, 0).worker_transcript_path
        == config.transcripts_dir / task.id / "worker" / "codex.jsonl"
    )
    assert reopened.get(task.id).validations[0].cwd == config.worktrees_dir / task.id
    assert reopened.events(task.id)[1].message == str(absolute_patch)
    assert reopened.events(task.id)[1].data["patch_path"] == str(absolute_patch)
