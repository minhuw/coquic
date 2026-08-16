from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.control_loop import (
    ArchiveConflictError,
    ArchiveValidationError,
    ControlLoopArchive,
    ControlLoopLedger,
    CurrentState,
    Event,
    PlannerRun,
)
from coquic_steward.storage import TaskStore


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


def _archive(tmp_path: Path) -> ControlLoopArchive:
    TaskStore.create(tmp_path / "steward.sqlite")
    task_epoch = json.loads(
        (tmp_path / "tasks" / "epoch.json").read_text(encoding="utf-8")
    )
    archive = ControlLoopArchive(
        tmp_path / "control-loop", task_root=tmp_path / "tasks"
    )
    archive.ensure_epoch(
        authoritative={
            "epochId": task_epoch["epochId"],
            "formatVersion": "1.0",
            "taskFormatVersion": task_epoch["formatVersion"],
            "policy": task_epoch["policy"],
            "startedAt": "2026-07-24T12:00:00Z",
        }
    )
    return archive


def _ledger(tmp_path: Path) -> ControlLoopLedger:
    return TaskStore.open(tmp_path / "steward.sqlite").control_loop


def _epoch_id(archive: ControlLoopArchive) -> str:
    return archive._require_epoch().epoch_id


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
    epoch = json.loads(archive.epoch_path.read_text(encoding="utf-8"))
    assert epoch["taskFormatVersion"] == "1.0"
    assert "endedAt" not in epoch
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
            epochId=_epoch_id(archive),
            counts={"pendingSignals": 1},
            pendingSignalIds=["signal-current"],
            archive={"lag": 0},
        )
    )
    assert current == archive.current_path
    assert json.loads(current.read_text(encoding="utf-8"))["epochId"] == _epoch_id(archive)


def test_sealed_planner_run_manifest_preserves_raw_bytes_and_rejects_conflicts(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    run = PlannerRun(
        plannerRunId="planner-run-sealed",
        epochId=_epoch_id(archive),
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
                epochId=_epoch_id(archive),
                state="succeeded",
                startedAt=NOW,
                completedAt=NOW,
            ),
            {"../escape": b"no"},
        )


def test_reconcile_stops_at_temporary_outbox_gap(tmp_path: Path, monkeypatch) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)
        ledger._event(connection, "synthetic.event", {"ordinal": 1}, occurred_at=NOW)

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


def test_reconcile_does_not_drain_outbox_after_archive_validation_failure(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)

    malformed = archive.events_root / "2026" / "07" / "23.jsonl"
    malformed.parent.mkdir(parents=True)
    malformed.write_bytes(b'{"sequence":"not-an-event"}\n')

    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)

    result = archive.reconcile(ledger)

    assert result["materialized"] == 0
    assert result["conflicts"] == 1
    assert [row["sequence"] for row in ledger.outbox()] == [0]
    assert not (archive.events_root / "2026" / "07" / "24.jsonl").exists()
    assert ledger.planning_blocked


def test_reconcile_blocks_planning_when_hidden_planner_stage_survives(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    stage = archive.planner_runs_root / ".planner-run-hidden.stage-interrupted"
    stage.mkdir()
    (stage / "prompt.md").write_text("unsealed evidence\n", encoding="utf-8")

    result = archive.reconcile(ledger)

    assert result["conflicts"] == 1
    assert result["hiddenStages"] == [stage.name]
    assert ledger.planning_blocked
    assert stage.exists()


def test_confirmed_event_file_uses_one_bulk_lookup_and_returns_verified_facts(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        event = ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)
    path = archive.events_root / "2026" / "07" / "24.jsonl"
    path.parent.mkdir(parents=True)
    line = json.dumps(
        event.model_dump(by_alias=True, mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    path.write_bytes(line + b"\n")

    original_connect = ledger._connect
    connection_count = 0

    def counted_connect():
        nonlocal connection_count
        connection_count += 1
        return original_connect()

    monkeypatch.setattr(ledger, "_connect", counted_connect)
    facts = archive._assert_confirmed_event_file(path, ledger)

    assert connection_count == 1
    assert facts["path"] == "2026/07/24.jsonl"
    assert facts["sha256"]
    assert facts["eventCount"] == 1
    assert facts["sequenceStart"] == 0
    assert facts["sequenceEnd"] == 0
    assert facts["highWatermark"] == 0


def test_reconcile_reuses_verified_file_for_outbox_prefixes(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        events = [
            ledger._event(connection, "synthetic.event", {"ordinal": ordinal}, occurred_at=NOW)
            for ordinal in range(2)
        ]
    path = archive.events_root / "2026" / "07" / "24.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(
        b"".join(
            json.dumps(
                event.model_dump(by_alias=True, mode="json"),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
            for event in events
        )
    )

    original_verify = archive._assert_confirmed_event_file
    verification_count = 0

    def counted_verify(*args, **kwargs):
        nonlocal verification_count
        verification_count += 1
        return original_verify(*args, **kwargs)

    monkeypatch.setattr(archive, "_assert_confirmed_event_file", counted_verify)
    result = archive.reconcile(ledger)

    assert result["materialized"] == 2
    assert verification_count == 1


def test_reconcile_parses_an_accepted_file_once_for_pending_rows(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    import coquic_steward.control_loop.archive as archive_module

    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        events = [
            ledger._event(connection, "synthetic.event", {"ordinal": ordinal}, occurred_at=NOW)
            for ordinal in range(5)
        ]
    archive.append_event(events[0])
    archive.append_event(events[1])
    ledger.mark_materialized(events[0].sequence, event_id=events[0].event_id)
    ledger.mark_materialized(events[1].sequence, event_id=events[1].event_id)

    original_loads = archive_module.json.loads
    byte_line_parses = 0

    def counted_loads(value, *args, **kwargs):
        nonlocal byte_line_parses
        if isinstance(value, bytes):
            byte_line_parses += 1
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(archive_module.json, "loads", counted_loads)
    result = archive.reconcile(ledger)

    assert result["materialized"] == 3
    assert result["conflicts"] == 0
    assert byte_line_parses == 2


def test_reconcile_invalidates_verified_file_when_accepted_bytes_change(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        events = [
            ledger._event(connection, "synthetic.event", {"ordinal": ordinal}, occurred_at=NOW)
            for ordinal in range(3)
        ]

    original_append = archive.append_event
    path = archive.events_root / "2026" / "07" / "24.jsonl"

    def append_and_tamper(event):
        result = original_append(event)
        if event["sequence"] == 0:
            lines = path.read_bytes().splitlines()
            payload = json.loads(lines[0])
            payload["payload"]["tampered"] = True
            lines[0] = json.dumps(
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            path.write_bytes(b"\n".join(lines) + b"\n")
        return result

    monkeypatch.setattr(archive, "append_event", append_and_tamper)
    result = archive.reconcile(ledger)

    assert result["materialized"] == 1
    assert result["conflicts"] == 1
    assert [row["sequence"] for row in ledger.outbox()] == [1, 2]
    assert json.loads(path.read_bytes().splitlines()[0])["payload"]["tampered"] is True


def test_unchanged_reconcile_is_byte_idle_and_append_uses_cached_high_watermark(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        first = ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)
        second = ledger._event(
            connection,
            "synthetic.event",
            {"ordinal": 1},
            occurred_at=NOW.replace(day=25),
        )
    archive.append_event(first)
    ledger.mark_materialized(first.sequence, event_id=first.event_id)
    initial = archive.reconcile(ledger)
    assert initial["verification"]["eventBytes"] > 0

    monkeypatch.setattr(
        archive,
        "_assert_confirmed_event_file",
        lambda *_args, **_kwargs: pytest.fail("unchanged event file was reverified"),
    )
    archive.reset_verification_counters()
    idle = archive.reconcile(ledger)
    assert idle["verification"] == {
        "eventFiles": 0,
        "eventBytes": 0,
        "eventHashes": 0,
        "plannerRuns": 0,
        "plannerBytes": 0,
        "plannerHashes": 0,
    }

    first_path = archive.events_root / "2026" / "07" / "24.jsonl"
    original_read_bytes = Path.read_bytes

    def reject_unrelated_file(path: Path) -> bytes:
        if path == first_path:
            raise AssertionError("append scanned an unrelated event file")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_unrelated_file)
    archive.append_event(second)
    second_path = archive.events_root / "2026" / "07" / "25.jsonl"
    assert [json.loads(line)["sequence"] for line in second_path.read_bytes().splitlines()] == [1]


def test_reconcile_carries_materialized_watermark_into_snapshot_and_append(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        first = ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)

    result = archive.reconcile(ledger)

    assert result["materialized"] == 1
    assert result["highWatermark"] == 0
    assert archive._verified_snapshot is not None
    assert archive._verified_snapshot["highWatermark"] == 0

    lower = first.model_copy(
        update={
            "event_id": "event-lower-day",
            "occurred_at": NOW.replace(day=25),
        }
    )
    with pytest.raises(ArchiveConflictError):
        archive.append_event(lower)


def test_verified_duplicate_requires_exact_canonical_bytes(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        event = ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)

    archive.reconcile(ledger)
    path = archive.events_root / "2026" / "07" / "24.jsonl"
    original = path.read_bytes()
    conflicting = event.model_copy(update={"payload": {"ordinal": 99}})

    with pytest.raises(ArchiveConflictError):
        archive.append_event(conflicting)

    assert path.read_bytes() == original
    assert archive.append_event(event) == len(original)


def test_fresh_archive_process_fails_closed_without_verified_watermark(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    retained = _event(archive, 10, "event-retained")
    archive.append_event(retained)

    fresh = ControlLoopArchive(archive.root, task_root=archive.task_root)
    fresh.ensure_epoch(archive._require_epoch())
    candidate = _event(fresh, 1, "event-unverified").model_copy(
        update={"occurred_at": NOW.replace(day=25)}
    )

    with pytest.raises(ArchiveConflictError):
        fresh.append_event(candidate)

    retained_path = fresh.events_root / "2026" / "07" / "24.jsonl"
    assert [json.loads(line) for line in retained_path.read_bytes().splitlines()] == [
        retained.model_dump(by_alias=True, mode="json")
    ]
    assert not (fresh.events_root / "2026" / "07" / "25.jsonl").exists()


def test_fresh_archive_accepts_exact_duplicate_before_watermark_check(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    retained = _event(archive, 10, "event-retained")
    archive.append_event(retained)
    archive.append_event(
        retained.model_copy(
            update={
                "event_id": "event-later",
                "sequence": 20,
                "occurred_at": NOW.replace(day=25),
            }
        )
    )
    retained_path = archive.events_root / "2026" / "07" / "24.jsonl"
    original = retained_path.read_bytes()

    fresh = ControlLoopArchive(archive.root, task_root=archive.task_root)
    fresh.ensure_epoch(archive._require_epoch())

    assert fresh.append_event(retained) == len(original)

    conflicting = retained.model_copy(update={"payload": {"raw": "changed"}})
    with pytest.raises(ArchiveConflictError):
        fresh.append_event(conflicting)

    lower = retained.model_copy(
        update={
            "event_id": "event-lower",
            "sequence": 11,
            "occurred_at": NOW.replace(day=26),
        }
    )
    with pytest.raises(ArchiveConflictError):
        fresh.append_event(lower)

    assert retained_path.read_bytes() == original
    assert not (fresh.events_root / "2026" / "07" / "26.jsonl").exists()


def test_verified_append_does_not_walk_unrelated_event_files(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    with ledger.transaction() as connection:
        first = ledger._event(connection, "synthetic.event", {"ordinal": 0}, occurred_at=NOW)
        second = ledger._event(
            connection,
            "synthetic.event",
            {"ordinal": 1},
            occurred_at=NOW.replace(day=25),
        )
    archive.append_event(first)
    ledger.mark_materialized(first.sequence, event_id=first.event_id)
    archive.reconcile(ledger)

    monkeypatch.setattr(
        archive,
        "_event_file_identities",
        lambda: pytest.fail("verified append performed a global event walk"),
    )
    archive.append_event(second)


def test_disappearing_verified_planner_run_blocks_and_discards_trust(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    run = PlannerRun(
        plannerRunId="planner-run-disappearing",
        epochId=_epoch_id(archive),
        state="failed",
        startedAt=NOW,
        completedAt=NOW,
    )
    archive.publish_planner_run(run, {"result.json": b"{}\n"})
    archive.reconcile(ledger)
    shutil.rmtree(archive.planner_runs_root / run.planner_run_id)

    result = archive.reconcile(ledger)

    assert result["plannerAuditIncomplete"] is True
    assert result["error"] == "ArchiveConflictError"
    assert ledger.planning_blocked
    assert archive._verified_snapshot is not None
    assert archive._verified_snapshot["plannerRuns"] == {}


def test_planner_audit_oserror_is_incomplete_and_blocks_planning(
    tmp_path: Path, monkeypatch
) -> None:
    archive = _archive(tmp_path)
    ledger = _ledger(tmp_path)
    run = PlannerRun(
        plannerRunId="planner-run-audit-error",
        epochId=_epoch_id(archive),
        state="failed",
        startedAt=NOW,
        completedAt=NOW,
    )
    archive.publish_planner_run(run, {"result.json": b"{}\n"})
    archive.reconcile(ledger)

    def fail_audit(*_args, **_kwargs):
        raise OSError("planner bytes unavailable")

    monkeypatch.setattr(archive, "_verify_planner_run_facts", fail_audit)
    result = archive.full_audit(ledger)

    assert result["plannerAuditIncomplete"] is True
    assert result["auditIncomplete"] is True
    assert result["error"] == "OSError"
    assert ledger.planning_blocked


def test_full_audit_requires_ledger_authority(tmp_path: Path) -> None:
    archive = _archive(tmp_path)

    with pytest.raises(ArchiveValidationError):
        archive.full_audit()
