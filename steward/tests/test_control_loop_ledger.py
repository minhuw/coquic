from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from coquic_steward.control_loop import (
    ControlLoopLedger,
    LedgerConflictError,
    ProposalDisposition,
    Wakeup,
)
from coquic_steward.core.models import SignalFetchRun, SignalFetchStatus, SignalItem


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
    return ControlLoopLedger(tmp_path / "steward.sqlite", epoch_id="epoch-ledger-test")


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
