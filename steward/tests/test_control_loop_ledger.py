from __future__ import annotations

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
    ledger = ControlLoopLedger(
        tmp_path / "steward.sqlite", epoch_id="epoch-ledger-test"
    )
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY)")
        connection.executemany(
            "INSERT OR IGNORE INTO tasks(id) VALUES(?)",
            [("task-active-1",), ("task-created-1",)],
        )
    return ledger


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
    store = TaskStore(config.db_path)
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
