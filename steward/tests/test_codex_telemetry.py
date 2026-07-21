from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.agents.telemetry import (
    BillingMode,
    CostStatus,
    PriceCatalog,
    TelemetryAggregate,
    TelemetryRecorder,
    TelemetryTurn,
    aggregate_sidecars,
    estimate_cost,
    load_sidecar,
)
from coquic_steward.public_mirror import _public_telemetry, model_telemetry_payload


UTC = timezone.utc


def _usage(
    input_tokens: int = 8,
    cached_input_tokens: int = 3,
    output_tokens: int = 5,
    reasoning_output_tokens: int = 2,
) -> dict[str, int]:
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "reasoning_output_tokens": reasoning_output_tokens,
    }


def _recorder(path: Path, *, retry_ordinal: int = 0, **kwargs) -> TelemetryRecorder:
    return TelemetryRecorder(
        path,
        task_id="task-telemetry",
        run_name="worker",
        stage="code",
        retry_ordinal=retry_ordinal,
        configured_model="fictional-example-model",
        reasoning_effort="low",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        started_monotonic_ns=1_000_000_000,
        **kwargs,
    )


def test_turn_math_rejects_invalid_counter_types_and_subsets() -> None:
    turn = TelemetryTurn.from_usage(_usage())
    assert turn.uncached_input_tokens == 5
    assert turn.total_tokens == 13
    for invalid in (
        {**_usage(), "input_tokens": True},
        {**_usage(), "output_tokens": 1.5},
        {**_usage(), "cached_input_tokens": -1},
        {**_usage(), "cached_input_tokens": 9},
        {**_usage(), "reasoning_output_tokens": 6},
    ):
        with pytest.raises(ValueError):
            TelemetryTurn.from_usage(invalid)


def test_recorder_captures_all_turns_and_first_completed_message(tmp_path: Path) -> None:
    monotonic = [1_125_000_000, 1_900_000_000]
    recorder = _recorder(tmp_path / "telemetry.json", monotonic_ns=lambda: monotonic.pop(0))
    assert recorder.observe({"type": "turn.completed", "usage": _usage()})
    assert recorder.observe({"type": "turn.completed", "usage": _usage(2, 1, 4, 1)})
    assert not recorder.observe(
        {"type": "item.completed", "item": {"type": "agent_message"}}
    )
    payload = recorder.finalize(process_outcome="completed")
    assert payload["aggregate"] == {
        "completed_turns": 2,
        "input_tokens": 10,
        "cached_input_tokens": 4,
        "uncached_input_tokens": 6,
        "output_tokens": 9,
        "reasoning_output_tokens": 3,
        "total_tokens": 19,
    }
    assert payload["first_agent_message_completed_ms"] == 125
    assert len(payload["turns"]) == 2
    assert load_sidecar(tmp_path / "telemetry.json")["aggregate"] == payload["aggregate"]


def test_catalog_intervals_and_integer_cost() -> None:
    catalog = PriceCatalog.from_dict(
        {
            "schema_version": 1,
            "entries": [
                {
                    "id": "model-2026",
                    "model": "m",
                    "effective_from": "2026-01-01T00:00:00Z",
                    "effective_until": None,
                    "input_micro_usd_per_million": 1_000_000,
                    "cached_input_micro_usd_per_million": 500_000,
                    "output_micro_usd_per_million": 2_000_000,
                    "source": {"label": "Example", "url": "https://example.invalid/p"},
                }
            ],
        }
    )
    estimate = estimate_cost(
        TelemetryAggregate(
            completed_turns=1,
            input_tokens=8,
            cached_input_tokens=3,
            uncached_input_tokens=5,
            output_tokens=5,
            reasoning_output_tokens=2,
            total_tokens=13,
        ),
        billing_mode=BillingMode.api,
        configured_model="m",
        started_at=datetime(2026, 2, 1, tzinfo=UTC),
        catalog=catalog,
    )
    assert estimate.status is CostStatus.estimated
    assert estimate.micro_usd == 5 + 2 + 10
    assert catalog.find("m", datetime(2025, 1, 1, tzinfo=UTC)) is None

    with pytest.raises(ValueError):
        PriceCatalog.from_dict(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "id": "a",
                        "model": "m",
                        "effective_from": "2026-01-01T00:00:00Z",
                        "effective_until": None,
                        "input_micro_usd_per_million": 1,
                        "cached_input_micro_usd_per_million": 1,
                        "output_micro_usd_per_million": 1,
                        "source": {"label": "x", "url": "https://example.invalid/a"},
                    },
                    {
                        "id": "b",
                        "model": "m",
                        "effective_from": "2026-02-01T00:00:00Z",
                        "effective_until": None,
                        "input_micro_usd_per_million": 1,
                        "cached_input_micro_usd_per_million": 1,
                        "output_micro_usd_per_million": 1,
                        "source": {"label": "x", "url": "https://example.invalid/b"},
                    },
                ],
            }
        )


def test_chatgpt_and_unknown_cost_are_explicitly_unavailable() -> None:
    aggregate = TelemetryAggregate()
    for mode, reason in (
        (BillingMode.chatgpt, "chatgpt_cost_unavailable"),
        (BillingMode.unknown, "billing_mode_unknown"),
    ):
        estimate = estimate_cost(
            aggregate,
            billing_mode=mode,
            configured_model="m",
            started_at=datetime.now(UTC),
            catalog=PriceCatalog.empty(),
        )
        assert estimate.status is CostStatus.unavailable
        assert estimate.reason == reason


def test_public_reader_caps_turns_and_global_reports_legacy(config) -> None:
    transcript_dir = config.transcripts_dir / "task-telemetry" / "worker"
    transcript_dir.mkdir(parents=True)
    transcript = transcript_dir / "codex.jsonl"
    transcript.write_text("legacy\n", encoding="utf-8")
    recorder = _recorder(transcript_dir / "telemetry.json")
    for _ in range(101):
        recorder.observe({"type": "turn.completed", "usage": _usage()})
    recorder.finalize(process_outcome="completed")
    public = _public_telemetry(config, transcript)
    assert public["availability"] == "available"
    assert public["aggregate"]["completed_turns"] == 101
    assert len(public["turns"]) == 100
    assert public["unavailable"]["ttft_ms"]["reason"] == "not_exposed_by_codex_exec"

    legacy = config.transcripts_dir / "legacy-task" / "worker" / "codex.jsonl"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy\n", encoding="utf-8")
    global_payload = model_telemetry_payload(config)
    assert global_payload["schema_version"] == 1
    assert global_payload["coverage"]["legacy_without_telemetry"] >= 1
    assert global_payload["coverage"]["complete"] is False


def test_sidecar_write_failure_does_not_raise(monkeypatch, tmp_path: Path) -> None:
    recorder = _recorder(tmp_path / "telemetry.json")
    recorder.observe({"type": "turn.completed", "usage": _usage()})
    monkeypatch.setattr(
        "coquic_steward.agents.telemetry.os.replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )
    payload = recorder.finalize(process_outcome="failed")
    assert payload["completeness"] == "unavailable"
    assert any(issue["category"] == "sidecar_write_failure" for issue in payload["issues"])
