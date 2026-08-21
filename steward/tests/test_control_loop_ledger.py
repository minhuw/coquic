from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.control_loop import (
    ControlLoopLedger,
    LedgerConflictError,
    ProposalDisposition,
    Wakeup,
    timestamp,
)
from coquic_steward.core.models import (
    SignalFetchRun,
    SignalFetchStatus,
    SignalItem,
    TaskKind,
    TaskSpec,
    WorkerKind,
)
from coquic_steward.storage import TaskStore


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


def _fetch(fetch_id: str) -> SignalFetchRun:
    return SignalFetchRun(
        id=fetch_id,
        provider="synthetic-provider",
        status=SignalFetchStatus.ok,
        started_at=NOW,
        completed_at=NOW,
        item_count=1,
        new_item_count=1,
    )


def _item(item_id: str, fingerprint: str) -> SignalItem:
    return SignalItem(
        id=item_id,
        provider="synthetic-provider",
        kind="synthetic.alert",
        fingerprint=fingerprint,
        title=f"Synthetic alert {item_id}",
        summary="raw fixture content",
        payload={"fake": True},
    )


def _ledger(tmp_path: Path) -> ControlLoopLedger:
    store = TaskStore.create(tmp_path / "steward.sqlite")
    for task_id in ("task-active-1", "task-created-1"):
        store.add_task(
            TaskSpec(
                id=task_id,
                kind=TaskKind.custom,
                worker=WorkerKind.custom,
                title=f"Fixture task {task_id}",
                prompt="Fixture task for control-loop relations.",
            )
        )
    return store.control_loop


def test_blank_direct_ledger_rejects_without_schema_side_effect(tmp_path: Path) -> None:
    database = tmp_path / "blank.sqlite"
    with sqlite3.connect(database):
        pass
    before = database.read_bytes()

    with pytest.raises(LedgerConflictError, match="schema"):
        ControlLoopLedger(database, epoch_id="epoch-blank-test")

    assert database.read_bytes() == before
    with sqlite3.connect(database) as connection:
        objects = connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'control_loop_%'"
        ).fetchall()
    assert objects == []


def test_record_wakeup_uses_caller_transaction(tmp_path: Path) -> None:
    store = TaskStore.create(tmp_path / "steward.sqlite")
    ledger = store.control_loop
    wakeup = Wakeup(wakeupId="wakeup-caller-transaction", reason="manual")

    with sqlite3.connect(ledger.path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        ledger.record_wakeup(wakeup, connection=connection)
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_wakeups"
        ).fetchone()[0] == 1
        connection.rollback()

    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_wakeups"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_events"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM control_loop_outbox"
        ).fetchone()[0] == 0


def test_store_wakeup_preserves_data_and_extracts_input_ids(config) -> None:
    store = TaskStore.create(config.db_path)
    wakeup = store.request_wakeup(
        "signal.fetch",
        {
            "providers": ["synthetic-provider"],
            "signal_ids": ["signal-a", 7, "signal-b"],
            "input_signal_ids": ["fallback"],
        },
    )

    with sqlite3.connect(store.path) as connection:
        scheduler = connection.execute(
            "SELECT id,reason,data_json FROM scheduler_wakeups WHERE id=?",
            (wakeup.id,),
        ).fetchone()
        control = connection.execute(
            "SELECT wakeup_id,reason,created_at,input_signal_ids_json "
            "FROM control_loop_wakeups WHERE wakeup_id=?",
            (wakeup.id,),
        ).fetchone()
        event = connection.execute(
            "SELECT payload_json FROM control_loop_events "
            "WHERE kind='scheduler.wakeup'"
        ).fetchone()

    assert scheduler[0] == wakeup.id
    assert scheduler[1] == "signal.fetch"
    assert json.loads(scheduler[2]) == wakeup.data
    assert control[0] == scheduler[0]
    assert control[1] == scheduler[1]
    assert control[2] == timestamp(wakeup.created_at)
    assert json.loads(control[3]) == ["signal-a", "signal-b"]
    assert json.loads(event[0])["wakeup"]["inputSignalIds"] == [
        "signal-a",
        "signal-b",
    ]


def test_fetch_retains_repeated_observations_and_deduplicates_signal(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    first, first_signals = ledger.ingest_fetch(
        _fetch("fetch-1"),
        [_item("observation-1", "same-fingerprint")],
        wakeup=Wakeup(
            wakeupId="wakeup-1",
            reason="signal-fetch",
            inputSignalIds=[],
        ),
    )
    item_two = _item("observation-2", "same-fingerprint")
    second, second_signals = ledger.ingest_fetch(_fetch("fetch-2"), [item_two])

    assert first[0].canonical_signal_id == second[0].canonical_signal_id
    assert first[0].dedupe_result == "new"
    assert second[0].dedupe_result == "existing"
    assert first_signals[0].signal_id == second_signals[0].signal_id
    assert len(ledger.list_events()) >= 7
    assert len({event.sequence for event in ledger.list_events()}) == len(ledger.list_events())
    assert ledger.canonical_signal_id("synthetic-provider", "same-fingerprint") == first_signals[0].signal_id

    # Replaying the exact provider fetch is idempotent and does not publish a
    # second observation or fetch event.
    before = len(ledger.list_events())
    replayed, _ = ledger.ingest_fetch(
        _fetch("fetch-2"),
        [item_two],
    )
    assert replayed[0].canonical_signal_id == first[0].canonical_signal_id
    assert len(ledger.list_events()) == before


def test_planner_claim_completion_persists_dispositions_edges_and_outbox(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _, signals = ledger.ingest_fetch(
        _fetch("fetch-1"),
        [_item("observation-1", "planner-fingerprint")],
    )
    signal_id = signals[0].signal_id
    claimed = ledger.claim_planner_run(
        "planner-run-1",
        [signal_id],
        ["task-active-1"],
        prompt={"signalIds": [signal_id]},
    )
    assert claimed.state == "claimed"
    assert ledger.claim_planner_run(
        "planner-run-1",
        [signal_id],
        ["task-active-1"],
        prompt={"signalIds": [signal_id]},
    ).planner_run_id == claimed.planner_run_id

    disposition = ProposalDisposition(
        proposalId="proposal-1",
        plannerRunId="planner-run-1",
        ordinal=1,
        outcome="accepted",
        reasonCode="accepted",
        signalIds=[signal_id],
        dedupeKey="synthetic:planner-fingerprint",
        taskId="task-created-1",
        proposal={"title": "Synthetic task"},
    )
    completed = ledger.complete_planner_run(
        "planner-run-1",
        [disposition],
        result={"acceptedCount": 1},
        consume_signal_ids=[signal_id],
    )
    assert completed.state == "succeeded"
    assert ledger.list_proposals("planner-run-1")[0].outcome == "accepted"
    edge_types = {edge.edge_type for edge in ledger.list_edges()}
    assert {"signal_planner_run", "planner_proposal", "signal_proposal", "proposal_task"} <= edge_types
    assert any(event.kind == "planner.finished" for event in ledger.list_events())
    assert any(event.kind == "signal.transition" for event in ledger.list_events())

    with sqlite3.connect(ledger.path) as connection:
        status = connection.execute(
            "SELECT status FROM control_loop_signals WHERE signal_id=?", (signal_id,)
        ).fetchone()[0]
    assert status == "planned"
    pending = ledger.outbox()
    assert pending
    first = pending[0]
    assert ledger.mark_materialized(first["sequence"], event_id=first["event_id"])
    assert not ledger.mark_materialized(first["sequence"], event_id=first["event_id"])


def test_failed_planner_keeps_signal_pending_and_retry_is_bounded(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _, signals = ledger.ingest_fetch(
        _fetch("fetch-1"),
        [_item("observation-1", "failed-fingerprint")],
    )
    signal_id = signals[0].signal_id
    ledger.claim_planner_run("planner-run-failed", [signal_id])
    failed = ledger.complete_planner_run(
        "planner-run-failed",
        [],
        state="failed",
        diagnostics={"reasonCode": "invalid_output"},
        retry_after=timedelta(seconds=30),
    )
    assert failed.state == "failed"
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            "SELECT status FROM control_loop_signals WHERE signal_id=?", (signal_id,)
        ).fetchone()[0] == "pending"

    attempt_one, eligible_one = ledger.schedule_retry("planner", now=NOW)
    attempt_two, eligible_two = ledger.schedule_retry("planner", now=NOW)
    assert attempt_one == 1
    assert attempt_two == 2
    assert eligible_one == NOW + timedelta(seconds=30)
    assert eligible_two == NOW + timedelta(seconds=60)
    ledger.reset_retry("planner")
    assert ledger.pending_retry("planner") is None


def test_claim_rejects_unknown_input_and_noncontiguous_proposals(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerConflictError, match="does not exist"):
        ledger.claim_planner_run("planner-run-missing", ["signal-missing"])

    _, signals = ledger.ingest_fetch(
        _fetch("fetch-1"),
        [_item("observation-1", "ordinal-fingerprint")],
    )
    signal_id = signals[0].signal_id
    ledger.claim_planner_run("planner-run-ordinal", [signal_id])
    with pytest.raises(LedgerConflictError, match="ordinals"):
        ledger.complete_planner_run(
            "planner-run-ordinal",
            [
                ProposalDisposition(
                    proposalId="proposal-2",
                    plannerRunId="planner-run-ordinal",
                    ordinal=2,
                    outcome="invalid",
                    reasonCode="invalid_shape",
                )
            ],
        )


def test_normalized_graph_relations_and_state_checks_are_enforced(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _, signals = ledger.ingest_fetch(
        _fetch("fetch-constraints"),
        [_item("observation-constraints", "constraint-fingerprint")],
    )
    signal_id = signals[0].signal_id
    ledger.claim_planner_run(
        "planner-run-constraints", [signal_id], ["task-active-1"]
    )

    with sqlite3.connect(ledger.path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        relations = {
            row[2]
            for table in (
                "control_loop_planner_signals",
                "control_loop_planner_tasks",
                "control_loop_proposal_signals",
                "control_loop_proposal_tasks",
            )
            for row in connection.execute(f"PRAGMA foreign_key_list({table})")
        }
        assert {"control_loop_signals", "control_loop_planner_runs", "tasks"} <= relations
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO control_loop_planner_signals(planner_run_id,ordinal,signal_id) VALUES(?,?,?)",
                ("planner-run-constraints", 2, "signal-missing"),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO control_loop_retry(key,attempt,eligible_at,updated_at) VALUES(?,?,?,?)",
                ("invalid", 1, None, NOW.isoformat()),
            )


def test_task_and_signal_mutations_roll_back_when_completion_fails(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _item("observation-atomic", "atomic-fingerprint")
    store.ingest_signal_collection(_fetch("fetch-atomic"), [item])
    signal_id = store.control_loop.canonical_signal_id(item.provider, item.fingerprint)
    assert signal_id is not None
    store.control_loop.claim_planner_run("planner-run-atomic", [signal_id])
    spec = TaskSpec(
        kind=TaskKind.custom,
        worker=WorkerKind.custom,
        title="Atomic planner task",
        prompt="Prove planner completion rollback.",
        metadata={"selected_signal_item_ids": [item.id]},
    )

    def fail_completion(*_args, **_kwargs):
        raise RuntimeError("injected ledger failure")

    monkeypatch.setattr(store.control_loop, "complete_planner_run", fail_completion)
    with pytest.raises(RuntimeError, match="injected ledger failure"):
        store.commit_planner_decision(
            "planner-run-atomic",
            planned=[(spec, "atomic-dedupe")],
            planner_dispositions=[
                SimpleNamespace(
                    outcome="accepted",
                    reason_code="accepted",
                    dedupe_key="atomic-dedupe",
                    signal_ids=[item.id],
                    proposal={"title": spec.title},
                )
            ],
            consumed_item_ids=[item.id],
            selected_item_ids_by_dedupe={"atomic-dedupe": [item.id]},
            canonical_signal_by_item={item.id: signal_id},
            state="succeeded",
            result={},
            diagnostics={},
            retry_after=None,
            artifact_sources={},
        )

    assert store.list_tasks() == []
    assert store.pending_signal_items(limit=10)[0].id == item.id
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM control_loop_proposals").fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM control_loop_planner_runs WHERE planner_run_id='planner-run-atomic'"
        ).fetchone()[0] == "claimed"


def test_signal_collection_rolls_back_legacy_and_control_rows_together(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _item("observation-ingest-atomic", "ingest-atomic-fingerprint")

    def fail_fetch_row(*_args, **_kwargs):
        raise RuntimeError("injected public fetch row failure")

    monkeypatch.setattr(store, "add_signal_fetch_run", fail_fetch_row)
    with pytest.raises(RuntimeError, match="injected public fetch row failure"):
        store.ingest_signal_collection(_fetch("fetch-ingest-atomic"), [item])

    with sqlite3.connect(store.path) as connection:
        for table in (
            "control_loop_fetches",
            "control_loop_observations",
            "control_loop_signals",
            "control_loop_events",
            "control_loop_outbox",
            "control_loop_wakeups",
            "signal_fetch_runs",
            "signal_items",
            "scheduler_wakeups",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_signal_collection_rolls_back_when_control_wakeup_insertion_fails(
    config, monkeypatch
) -> None:
    store = TaskStore.create(config.db_path)
    item = _item("observation-wakeup-atomic", "wakeup-atomic-fingerprint")

    def fail_control_wakeup(*_args, **_kwargs):
        raise RuntimeError("injected control wakeup failure")

    monkeypatch.setattr(store.control_loop, "record_wakeup", fail_control_wakeup)
    with pytest.raises(RuntimeError, match="injected control wakeup failure"):
        store.ingest_signal_collection(_fetch("fetch-wakeup-atomic"), [item])

    with sqlite3.connect(store.path) as connection:
        for table in (
            "control_loop_fetches",
            "control_loop_observations",
            "control_loop_signals",
            "control_loop_events",
            "control_loop_outbox",
            "control_loop_wakeups",
            "signal_fetch_runs",
            "signal_items",
            "scheduler_wakeups",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_signal_collection_exact_replay_is_idempotent_across_both_ledgers(
    config,
) -> None:
    store = TaskStore.create(config.db_path)
    items = [
        _item("observation-ingest-replay-1", "ingest-replay-fingerprint-1"),
        _item("observation-ingest-replay-2", "ingest-replay-fingerprint-2"),
    ]
    fetch = _fetch("fetch-ingest-replay")

    first_items, first_signals, first_created = store.ingest_signal_collection(
        fetch, items
    )
    with sqlite3.connect(store.path) as connection:
        first_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "signal_items",
                "control_loop_observations",
                "scheduler_wakeups",
                "control_loop_wakeups",
                "control_loop_events",
                "control_loop_outbox",
            )
        }
    second_items, second_signals, second_created = store.ingest_signal_collection(
        fetch, items
    )

    assert first_created == 2
    assert second_created == 0
    assert [item.id for item in first_items] == [item.id for item in second_items]
    assert [signal.signal_id for signal in first_signals] == [
        signal.signal_id for signal in second_signals
    ]
    with sqlite3.connect(store.path) as connection:
        second_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in first_counts
        }
    assert second_counts == first_counts


def test_retry_state_rolls_back_when_planner_completion_fails(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _, signals = ledger.ingest_fetch(
        _fetch("fetch-retry-atomic"),
        [_item("observation-retry-atomic", "retry-atomic-fingerprint")],
    )
    run_id = "planner-run-retry-atomic"
    ledger.claim_planner_run(run_id, [signals[0].signal_id])
    with sqlite3.connect(ledger.path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_planner_completion BEFORE UPDATE ON "
            "control_loop_planner_runs BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
        connection.commit()

    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        ledger.complete_planner_run(
            run_id,
            [],
            state="failed",
            schedule_retry_key="planner",
        )

    assert ledger.pending_retry("planner") is None
    assert ledger.list_planner_runs()[-1].state == "claimed"


def test_events_at_requires_ordered_unique_sequences_and_preserves_compatibility(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    first_sequence = len(ledger.list_events())
    with ledger.transaction() as connection:
        for ordinal in range(3):
            ledger._event(connection, "synthetic.event", {"ordinal": ordinal}, occurred_at=NOW)
    sequences = list(range(first_sequence, first_sequence + 3))

    assert ledger.events_at([]) == {}
    events = ledger.events_at(sequences)
    assert list(events) == sequences
    assert [event.sequence for event in events.values()] == sequences
    assert ledger.event_at(sequences[1]) == events[sequences[1]]
    assert ledger.event_at(99) is None

    with pytest.raises(LedgerConflictError, match="missing"):
        ledger.events_at([sequences[0], sequences[-1] + 1])
    with pytest.raises(LedgerConflictError, match="duplicate"):
        ledger.events_at([sequences[0], sequences[1], sequences[1]])
    with pytest.raises(LedgerConflictError, match="out of order"):
        ledger.events_at([sequences[1], sequences[0]])


def test_events_at_uses_one_connection_and_bounded_chunks(
    tmp_path: Path, monkeypatch
) -> None:
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        for ordinal in range(501):
            ledger._event(connection, "synthetic.event", {"ordinal": ordinal}, occurred_at=NOW)

    original_connect = ledger._connect
    connection_count = 0

    def counted_connect():
        nonlocal connection_count
        connection_count += 1
        return original_connect()

    monkeypatch.setattr(ledger, "_connect", counted_connect)
    events = ledger.events_at(list(range(501)))

    assert connection_count == 1
    assert len(events) == 501
    assert events[500].sequence == 500


def test_exact_store_factory_binds_ledger_before_control_loop_use(tmp_path: Path) -> None:
    database = tmp_path / "steward.sqlite"
    store = TaskStore.create(database)

    assert store.control_loop.epoch_id == (
        json.loads(
            (tmp_path / "tasks" / "epoch.json").read_text(encoding="utf-8")
        )["epochId"]
    )
    store.control_loop.set_planning_blocked(True, reason="test")

    reopened = TaskStore.open(database)
    assert reopened.control_loop.epoch_id == store.control_loop.epoch_id
    assert reopened.control_loop.planning_blocked
