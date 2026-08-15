from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from coquic_steward.core.config import StewardConfig
from coquic_steward.core.models import SchedulerWakeupStatus
from coquic_steward.storage import TaskStore
from coquic_steward.storage import sqlite as sqlite_module


NOW = datetime(2026, 1, 8, 12, tzinfo=timezone.utc)


def _insert_wakeup(
    store: TaskStore,
    wakeup_id: str,
    *,
    status: SchedulerWakeupStatus,
    created_at: datetime,
    consumed_at: datetime | None,
) -> None:
    with store.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            INSERT INTO scheduler_wakeups
                (id, reason, status, created_at, consumed_at, data_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                wakeup_id,
                "test.retention",
                status.value,
                created_at.isoformat(),
                consumed_at.isoformat() if consumed_at is not None else None,
                "{}",
            ),
        )


def _freeze_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sqlite_module, "utc_now", lambda: NOW)


def _statuses(store: TaskStore) -> dict[str, tuple[str, str | None]]:
    with store.engine.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT id, status, consumed_at FROM scheduler_wakeups"
        ).fetchall()
    return {row[0]: (row[1], row[2]) for row in rows}


def test_prune_consumed_wakeups_respects_strict_cutoff_and_pending_rows(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch)
    store = TaskStore.create(config.db_path)
    old = NOW - timedelta(days=7, microseconds=1)
    exact = NOW - timedelta(days=7)
    recent = NOW - timedelta(days=6)
    _insert_wakeup(
        store,
        "old-consumed",
        status=SchedulerWakeupStatus.consumed,
        created_at=old,
        consumed_at=old,
    )
    _insert_wakeup(
        store,
        "exact-cutoff",
        status=SchedulerWakeupStatus.consumed,
        created_at=exact,
        consumed_at=exact,
    )
    _insert_wakeup(
        store,
        "recent-consumed",
        status=SchedulerWakeupStatus.consumed,
        created_at=recent,
        consumed_at=recent,
    )
    _insert_wakeup(
        store,
        "old-pending",
        status=SchedulerWakeupStatus.pending,
        created_at=old,
        consumed_at=None,
    )

    assert store.prune_consumed_wakeups() == 1

    assert _statuses(store) == {
        "exact-cutoff": (SchedulerWakeupStatus.consumed.value, exact.isoformat()),
        "recent-consumed": (SchedulerWakeupStatus.consumed.value, recent.isoformat()),
        "old-pending": (SchedulerWakeupStatus.pending.value, None),
    }


def test_prune_consumed_wakeups_uses_one_bulk_delete_without_loading_rows(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch)
    store = TaskStore.create(config.db_path)
    old = NOW - timedelta(days=8)
    for index in range(3):
        _insert_wakeup(
            store,
            f"old-{index}",
            status=SchedulerWakeupStatus.consumed,
            created_at=old,
            consumed_at=old,
        )

    statements: list[str] = []

    def capture_sql(_connection, _cursor, statement, _parameters, _context, _executemany):
        normalized = statement.lstrip().upper()
        if normalized.startswith(("SELECT", "DELETE")):
            statements.append(normalized)

    event.listen(store.engine, "before_cursor_execute", capture_sql)
    try:
        assert store.prune_consumed_wakeups() == 3
    finally:
        event.remove(store.engine, "before_cursor_execute", capture_sql)

    assert sum(statement.startswith("DELETE") for statement in statements) == 1
    assert not any(statement.startswith("SELECT") for statement in statements)


def test_consumption_activates_retention_once_and_notifies_once(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch)
    store = TaskStore.create(config.db_path)
    old = NOW - timedelta(days=8)
    _insert_wakeup(
        store,
        "old-consumed",
        status=SchedulerWakeupStatus.consumed,
        created_at=old,
        consumed_at=old,
    )
    _insert_wakeup(
        store,
        "pending",
        status=SchedulerWakeupStatus.pending,
        created_at=NOW,
        consumed_at=None,
    )
    prune_calls: list[object] = []
    original_prune = store.prune_consumed_wakeups

    def record_prune(**kwargs: object) -> int:
        prune_calls.append(kwargs)
        return original_prune(**kwargs)

    monkeypatch.setattr(store, "prune_consumed_wakeups", record_prune)
    changes: list[str] = []
    store.on_change = lambda: changes.append("changed")

    assert store.consume_wakeups(["pending"]) == 1
    assert len(prune_calls) == 1
    assert len(changes) == 1
    assert "old-consumed" not in _statuses(store)
    assert _statuses(store)["pending"][0] == SchedulerWakeupStatus.consumed.value

    _insert_wakeup(
        store,
        "old-after-empty",
        status=SchedulerWakeupStatus.consumed,
        created_at=old,
        consumed_at=old,
    )
    assert store.consume_wakeups([]) == 0
    assert len(prune_calls) == 1
    assert len(changes) == 1
    assert "old-after-empty" in _statuses(store)


def test_consumption_commits_before_retention_failure(
    config: StewardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch)
    store = TaskStore.create(config.db_path)
    _insert_wakeup(
        store,
        "pending",
        status=SchedulerWakeupStatus.pending,
        created_at=NOW,
        consumed_at=None,
    )

    def fail_prune(**_kwargs: object) -> int:
        raise RuntimeError("retention failed")

    monkeypatch.setattr(store, "prune_consumed_wakeups", fail_prune)
    with pytest.raises(RuntimeError, match="retention failed"):
        store.consume_wakeups(["pending"])

    assert _statuses(store)["pending"][0] == SchedulerWakeupStatus.consumed.value
