from __future__ import annotations

from pathlib import Path

import pytest

from coquic_steward.agents.tool_changes import (
    MAX_COMPLETED_RECORDS,
    is_safe_public_tool_id,
    tool_change_run_directories,
    validate_tool_timing_record,
)


def _record(
    sequence: int,
    *,
    status: str = "empty",
    tool_id: str | None = None,
    duration_ms: int | float | None = 7,
    completion_sequence: int | None = None,
) -> dict[str, object]:
    if completion_sequence is None and status != "incomplete":
        completion_sequence = sequence
    if status == "incomplete":
        duration_ms = None
    return {
        "tool_use_id": tool_id or f"tool_{sequence}",
        "tool_name": "Bash",
        "start_sequence": sequence,
        "start_order": sequence,
        "start_monotonic_ns": sequence,
        "started_at": "2026-07-13T12:00:00+00:00",
        "completion_sequence": completion_sequence,
        "completion_order": completion_sequence,
        "completed_at": (
            None if status == "incomplete" else "2026-07-13T12:00:01+00:00"
        ),
        "duration_ms": duration_ms,
        "status": status,
        "error_category": (
            "missing_post"
            if status == "incomplete"
            else "tool_failed"
            if status == "failed"
            else None
        ),
    }


def test_timing_validation_preserves_success_empty_and_failed_durations() -> None:
    records = [
        _record(1, status="empty", duration_ms=0),
        _record(2, status="empty", duration_ms=3),
        _record(3, status="failed", duration_ms=11),
    ]

    validated = [validate_tool_timing_record(record) for record in records]

    assert [item.duration_ms for item in validated] == [0, 3, 11]
    assert [item.status for item in validated] == ["empty", "empty", "failed"]
    assert [item.completion_sequence for item in validated] == [1, 2, 3]


def test_timing_validation_retains_missing_post_as_incomplete() -> None:
    validated = validate_tool_timing_record(_record(1, status="incomplete"))

    assert validated.status == "incomplete"
    assert validated.duration_ms is None
    assert validated.completion_sequence is None
    assert validated.unavailable_reason == "missing_post"


def test_retry_directories_are_ordered_and_reused_tool_ids_are_valid(tmp_path: Path) -> None:
    transcript = tmp_path / "codex.jsonl"
    for name in ("tool-changes.retry-2", "tool-changes", "tool-changes.retry-1"):
        (tmp_path / name).mkdir()

    directories = tool_change_run_directories(transcript)

    assert [path.name for path in directories] == [
        "tool-changes",
        "tool-changes.retry-1",
        "tool-changes.retry-2",
    ]
    assert validate_tool_timing_record(_record(1, tool_id="tool_1")).tool_use_id == "tool_1"
    assert validate_tool_timing_record(_record(1, tool_id="tool_1")).tool_use_id == "tool_1"


@pytest.mark.parametrize("duration", [True, -1, 24 * 60 * 60 * 1000 + 1])
def test_timing_validation_rejects_invalid_durations(duration: object) -> None:
    with pytest.raises(ValueError):
        validate_tool_timing_record(_record(1, duration_ms=duration))


def test_timing_validation_rejects_out_of_bounds_sequences() -> None:
    with pytest.raises(ValueError):
        validate_tool_timing_record(_record(MAX_COMPLETED_RECORDS + 1))


@pytest.mark.parametrize(
    "tool_id",
    [
        "tool_ghp_0123456789abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "sk_live_51N4Y0ExampleCredential",
    ],
)
def test_public_tool_identity_rejects_credential_shaped_ids(tool_id: str) -> None:
    assert not is_safe_public_tool_id(tool_id)
