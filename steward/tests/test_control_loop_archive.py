from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.control_loop import (
    ArchiveConflictError,
    ControlLoopArchive,
    CurrentState,
    Event,
    PlannerRun,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


def _archive(tmp_path: Path) -> ControlLoopArchive:
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    (tasks / "epoch.json").write_text(
        json.dumps(
            {
                "epochId": "epoch-archive-test",
                "formatVersion": "1.0",
                "policy": "post-steward-2.0",
                "startedAt": "2026-07-24T12:00:00Z",
                "endedAt": None,
            }
        ),
        encoding="utf-8",
    )
    archive = ControlLoopArchive(tmp_path / "control-loop", task_root=tasks)
    archive.ensure_epoch()
    return archive


def _event(archive: ControlLoopArchive, sequence: int, event_id: str) -> Event:
    return Event(
        eventId=event_id,
        epochId=archive._require_epoch().epoch_id,
        sequence=sequence,
        occurredAt=NOW,
        kind="synthetic.event",
        payload={"raw": "unredacted synthetic fixture"},
    )


def test_epoch_current_and_daily_events_are_atomic_and_idempotent(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    first = _event(archive, 0, "event-0")
    archive.append_event(first)
    path = archive.events_root / "2026" / "07" / "24.jsonl"
    with path.open("ab") as handle:
        handle.write(b'{"torn":true')
    archive.append_event(_event(archive, 1, "event-1"))
    archive.append_event(first)
    lines = path.read_bytes().splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["sequence"] for line in lines] == [0, 1]

    current = archive.write_current(
        CurrentState(
            epochId="epoch-archive-test",
            counts={"pendingSignals": 1},
            pendingSignalIds=["signal-current"],
            archive={"lag": 0},
        )
    )
    assert current == archive.current_path
    assert json.loads(current.read_text(encoding="utf-8"))["epochId"] == "epoch-archive-test"


def test_sealed_planner_run_manifest_preserves_raw_bytes_and_rejects_conflicts(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    run = PlannerRun(
        plannerRunId="planner-run-sealed",
        epochId="epoch-archive-test",
        state="failed",
        startedAt=NOW,
        completedAt=NOW,
        result={"reason": "synthetic"},
    )
    artifacts = {
        "prompt.md": b"prompt with raw synthetic token FAKE_TOKEN\n",
        "codex.jsonl": b'{"type":"incomplete"',
        "result.json": b'{"state":"failed"}\n',
    }
    published = archive.publish_planner_run(run, artifacts)
    assert archive.verify_planner_run("planner-run-sealed")
    assert (published / "codex.jsonl").read_bytes() == artifacts["codex.jsonl"]
    assert archive.publish_planner_run(run, artifacts) == published

    with pytest.raises(ArchiveConflictError):
        archive.publish_planner_run(run, {**artifacts, "result.json": b"different\n"})


def test_archive_rejects_epoch_and_path_conflicts(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    with pytest.raises(ArchiveConflictError):
        archive.write_current(CurrentState(epochId="epoch-other"))
    with pytest.raises(ValueError):
        archive.publish_planner_run(
            PlannerRun(
                plannerRunId="planner-run-path",
                epochId="epoch-archive-test",
                state="succeeded",
                startedAt=NOW,
                completedAt=NOW,
            ),
            {"../escape": b"no"},
        )


def test_reconcile_stops_at_temporary_outbox_gap(tmp_path: Path, monkeypatch) -> None:
    archive = _archive(tmp_path)
    from coquic_steward.control_loop import ControlLoopLedger

    ledger = ControlLoopLedger(tmp_path / "steward.sqlite", epoch_id="epoch-archive-test")
    with ledger.transaction() as connection:
        ledger._event(connection, "synthetic.event", {"ordinal": 0})
        ledger._event(connection, "synthetic.event", {"ordinal": 1})

    original = archive.append_event
    failed = False

    def fail_first(event):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("temporary write failure")
        return original(event)

    monkeypatch.setattr(archive, "append_event", fail_first)
    first = archive.reconcile(ledger)
    assert first["materialized"] == 0
    assert [row["sequence"] for row in ledger.outbox()] == [0, 1]

    monkeypatch.setattr(archive, "append_event", original)
    second = archive.reconcile(ledger)
    assert second["materialized"] == 2
    path = archive.events_root / "2026" / "07" / "24.jsonl"
    assert [json.loads(line)["sequence"] for line in path.read_bytes().splitlines()] == [0, 1]
