from __future__ import annotations

import json
from pathlib import Path

import pytest

from coquic_steward.agents.tool_changes import validate_tool_timing_record
from coquic_steward.public_mirror import _public_tool_timing


TREE = "a" * 40


def _record(
    sequence: int,
    *,
    status: str = "empty",
    tool_id: str | None = None,
    duration_ms: int | float | None = 7,
    completion_sequence: int | None = None,
    started_at: str = "2026-07-13T12:00:00+00:00",
    completed_at: str | None = "2026-07-13T12:00:01+00:00",
) -> dict[str, object]:
    if completion_sequence is None and status != "incomplete":
        completion_sequence = sequence
    if status == "incomplete":
        completed_at = None
        duration_ms = None
    return {
        "tool_use_id": tool_id or f"tool_{sequence}",
        "tool_name": "Bash",
        "session_id": "private-session",
        "turn_id": "private-turn",
        "start_sequence": sequence,
        "start_order": sequence,
        "start_monotonic_ns": sequence,
        "started_at": started_at,
        "base_tree": TREE,
        "base_tree_id": TREE,
        "gap_before": False,
        "overlap": False,
        "input": {"path": "inputs/private.json", "bytes": 1, "sha256": "b" * 64},
        "input_artifact": {"path": "inputs/private.json", "bytes": 1, "sha256": "b" * 64},
        "completion_sequence": completion_sequence,
        "completion_order": completion_sequence,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "result_tree": None if status == "incomplete" else TREE if status != "captured" else "b" * 40,
        "result_tree_id": None if status == "incomplete" else TREE if status != "captured" else "b" * 40,
        "status": status,
        "paths": ["README.md"] if status == "captured" else [],
        "patch": None,
        "patch_path": None,
        "patch_size_bytes": 0,
        "patch_sha256": None,
        "response": {"path": "responses/private.json"},
        "response_artifact": {"path": "responses/private.json"},
        "error_category": "missing_post" if status == "incomplete" else "tool_failed" if status == "failed" else None,
    }


def _write_run(
    config,
    task_id: str,
    records: list[dict[str, object]],
    *,
    retry: int | None = None,
    state: str | None = None,
    omitted: int = 0,
    discovered: int | None = None,
) -> Path:
    transcript = config.transcripts_dir / task_id / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("worker\n", encoding="utf-8")
    run_name = "tool-changes" if retry is None else f"tool-changes.retry-{retry}"
    run_dir = transcript.parent / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    counts = {name: sum(record["status"] == name for record in records) for name in ("captured", "empty", "failed", "incomplete")}
    if state is None:
        state = "partial" if counts["failed"] or counts["incomplete"] or omitted else "complete"
    discovered = len(records) + omitted if discovered is None else discovered
    summary = {
        "schema_version": 1,
        "state": state,
        "completeness": state,
        "discovered": discovered,
        "captured": counts["captured"],
        "empty": counts["empty"],
        "failed": counts["failed"],
        "incomplete": counts["incomplete"],
        "gaps": 0,
        "overlaps": 0,
        "omitted": omitted,
        "reasons": ["record_limit"] if omitted else ["missing_post"] if counts["incomplete"] else ["tool_failed"] if counts["failed"] else [],
        "reason_categories": ["record_limit"] if omitted else ["missing_post"] if counts["incomplete"] else ["tool_failed"] if counts["failed"] else [],
        "run_start_tree": TREE,
        "final_tree": TREE,
        "replayed_tree": TREE,
        "run_start_tree_id": TREE,
        "final_tree_id": TREE,
        "replayed_tree_id": TREE,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (run_dir / "manifest.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    return transcript


def test_hook_timing_keeps_success_empty_and_failed_durations(config) -> None:
    task_id = "task-tool-timing-basic"
    records = [
        _record(1, status="empty", duration_ms=0),
        _record(2, status="empty", duration_ms=3),
        _record(3, status="failed", duration_ms=11),
    ]
    transcript = _write_run(config, task_id, records)

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "available"
    assert timing["source"] == "codex_hook_boundary"
    assert timing["coverage"] == "partial"
    assert timing["completed_count"] == 2
    assert timing["failed_count"] == 1
    assert [item["duration_ms"] for item in timing["records"]] == [0, 3, 11]
    assert timing["records"][0]["started_at"].endswith("Z")
    assert timing["records"][2]["unavailable_reason"] is None


def test_hook_timing_marks_missing_post_without_zero_duration(config) -> None:
    task_id = "task-tool-timing-incomplete"
    transcript = _write_run(
        config,
        task_id,
        [_record(1, status="incomplete")],
        state="partial",
    )

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "available"
    assert timing["coverage"] == "partial"
    assert timing["incomplete_count"] == 1
    assert timing["records"][0]["duration_ms"] is None
    assert timing["records"][0]["unavailable_reason"] == "missing_post"


def test_hook_timing_joins_retries_before_final_and_allows_reused_ids(config) -> None:
    task_id = "task-tool-timing-retry"
    _write_run(config, task_id, [_record(1, tool_id="tool_1", duration_ms=2)], retry=1)
    _write_run(config, task_id, [_record(1, tool_id="tool_1", duration_ms=4)], retry=2)
    transcript = _write_run(config, task_id, [_record(1, tool_id="tool_1", duration_ms=8)])

    timing = _public_tool_timing(config, transcript)

    assert timing["published_count"] == 3
    assert [(item["retry_ordinal"], item["sequence"], item["tool_call_id"]) for item in timing["records"]] == [
        (0, 1, "tool_1"),
        (1, 1, "tool_1"),
        (2, 1, "tool_1"),
    ]
    assert [item["duration_ms"] for item in timing["records"]] == [2, 4, 8]


def test_hook_timing_orders_by_start_and_retains_out_of_order_completion(config) -> None:
    transcript = _write_run(
        config,
        "task-tool-timing-order",
        [
            _record(2, completion_sequence=1, duration_ms=2),
            _record(1, completion_sequence=2, duration_ms=4),
        ],
    )

    timing = _public_tool_timing(config, transcript)

    assert [item["sequence"] for item in timing["records"]] == [1, 2]
    assert [item["completion_order"] for item in timing["records"]] == [2, 1]


def test_legacy_run_is_unavailable_and_not_recorded(config) -> None:
    transcript = config.transcripts_dir / "task-tool-timing-legacy" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("legacy\n", encoding="utf-8")

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "unavailable"
    assert timing["coverage"] == "not_recorded"
    assert timing["unavailable_reason"] == "not_recorded"
    assert timing["records"] == []


def test_timing_rejects_malformed_duration_without_public_snapshot_failure(config) -> None:
    transcript = _write_run(
        config,
        "task-tool-timing-malformed",
        [_record(1, duration_ms=-1)],
    )

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "unavailable"
    assert timing["coverage"] == "unavailable"
    assert timing["unavailable_reason"] == "invalid_evidence"
    assert timing["records"] == []


def test_timing_bound_is_aggregate_across_retries(config) -> None:
    task_id = "task-tool-timing-bound"
    _write_run(config, task_id, [_record(index) for index in range(1, 2051)], retry=1)
    transcript = _write_run(config, task_id, [_record(index) for index in range(1, 2051)])

    timing = _public_tool_timing(config, transcript)

    assert timing["discovered_count"] == 4100
    assert timing["supported_count"] == 4100
    assert timing["published_count"] == 4096
    assert timing["omitted_count"] == 4
    assert timing["truncated"] is True
    assert timing["coverage"] == "partial"
    assert timing["records"][0]["retry_ordinal"] == 0
    assert timing["records"][-1]["retry_ordinal"] == 1


@pytest.mark.parametrize("duration", [True, float("nan"), float("inf"), 24 * 60 * 60 * 1000 + 1])
def test_timing_rejects_non_finite_boolean_and_overflow_duration(config, duration) -> None:
    transcript = _write_run(
        config,
        "task-tool-timing-invalid-duration",
        [_record(1, duration_ms=duration)],
    )

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "unavailable"
    assert timing["records"] == []


@pytest.mark.parametrize(
    "credential",
    [
        "tool_ghp_0123456789abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "sk_live_51N4Y0ExampleCredential",
    ],
)
def test_timing_value_model_rejects_credential_shaped_identity(
    credential: str,
) -> None:
    record = _record(1, tool_id=credential)

    with pytest.raises(ValueError):
        validate_tool_timing_record(record)


@pytest.mark.parametrize(
    "credential",
    [
        "api_key_contract-seeded-secret",
        "AKIAIOSFODNN7EXAMPLE",
        "sk_live_51N4Y0ExampleCredential",
    ],
)
def test_timing_rejects_credential_shaped_id_without_publication(
    config, credential: str
) -> None:
    transcript = _write_run(
        config,
        "task-tool-timing-credential-id",
        [_record(1, tool_id=credential)],
    )

    timing = _public_tool_timing(config, transcript)

    assert timing["availability"] == "unavailable"
    assert timing["unavailable_reason"] == "invalid_evidence"
    assert credential not in json.dumps(timing)
