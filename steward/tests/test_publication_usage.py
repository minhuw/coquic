from __future__ import annotations

from datetime import datetime, timezone

import pytest

from coquic_steward.agents.telemetry import PriceCatalog, PriceEntry
from coquic_steward.publication import (
    TaskUsageProjection,
    UsageCoverage,
    UsageCosts,
    UsageProjectionError,
    UsageTokens,
    build_task_usage_projection,
)


def _catalog() -> PriceCatalog:
    return PriceCatalog(
        (
            PriceEntry(
                "price-old",
                "gpt-old",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 1, tzinfo=timezone.utc),
                1_000_000,
                500_000,
                2_000_000,
                "committed test authority",
                "https://example.test/prices-old",
            ),
            PriceEntry(
                "price-new",
                "gpt-new",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                None,
                1_000_000,
                500_000,
                2_000_000,
                "committed test authority",
                "https://example.test/prices-new",
            ),
        )
    )


def _invocation(
    run_id: str,
    invocation_id: str | None,
    retry: int,
    *,
    model: str | None = "gpt-new",
    coverage: str = "complete",
    with_turn: bool = True,
) -> dict[str, object]:
    turn = {
        "ordinal": 1,
        "prompt": 11,
        "cached": 2,
        "uncached": 9,
        "completion": 7,
        "reasoning": 3,
        "total": 18,
    }
    return {
        "invocationId": invocation_id,
        "taskId": "task-usage",
        "pipelineId": "pipeline-usage",
        "runId": run_id,
        "retryOrdinal": retry,
        "startedAt": "2026-07-28T12:00:00.123Z" if with_turn else None,
        "completedAt": "2026-07-28T12:00:01.123Z" if with_turn else None,
        "model": model,
        "billingMode": "api",
        "processOutcome": "success" if with_turn else None,
        "coverage": coverage,
        "issues": [],
        "aggregate": {"usage": {key: value for key, value in turn.items() if key != "ordinal"}}
        if with_turn
        else None,
        "turns": [turn] if with_turn else [],
    }


def _run(run_id: str, invocations: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "ATIF-v1.7",
        "extra": {
            "coquic": {
                "taskId": "task-usage",
                "pipelineId": "pipeline-usage",
                "runId": run_id,
                "role": "implementation",
                "source": {"invocations": invocations},
            }
        },
    }


def test_projection_prices_turns_rolls_up_and_is_order_independent() -> None:
    first = _run(
        "run-two",
        [_invocation("run-two", "inv-two", 0)],
    )
    second = _run(
        "run-one",
        [
            _invocation("run-one", "inv-one", 1, coverage="partial"),
            _invocation("run-one", None, 0, coverage="unavailable", with_turn=False),
        ],
    )

    left = build_task_usage_projection([first, second], _catalog())
    right = build_task_usage_projection([second, first], _catalog())

    assert isinstance(left, TaskUsageProjection)
    assert left.as_dict() == right.as_dict()
    assert [run.run_id for run in left.runs] == ["run-one", "run-two"]
    assert [item.retry_ordinal for item in left.invocations] == [0, 1, 0]
    assert len(left.turns) == 2
    assert left.summary.coverage.covered_invocations == 2
    assert left.summary.coverage.expected_invocations == 3
    assert left.summary.coverage.status == "Partial"
    assert left.summary.tokens.total_tokens == 36
    assert left.summary.cost.total_micro_usd == 48
    assert left.summary.cost.status == "Partial"
    assert left.invocations[1].tokens.total_tokens == 18
    assert left.invocations[1].cost.status == "Partial"
    assert left.invocations[1].turns[0].cost.status == "Partial"
    assert left.invocations[0].tokens.total_tokens is None
    assert left.invocations[0].cost.total_micro_usd is None


def test_projection_uses_exact_invocation_start_price_and_catalog_provenance() -> None:
    catalog = PriceCatalog(
        (
            PriceEntry(
                "before",
                "gpt-new",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 28, 12, tzinfo=timezone.utc),
                1_000_000,
                0,
                0,
                "before",
                "https://example.test/before",
            ),
            PriceEntry(
                "after",
                "gpt-new",
                datetime(2026, 7, 28, 12, tzinfo=timezone.utc),
                None,
                2_000_000,
                0,
                0,
                "after",
                "https://example.test/after",
            ),
        )
    )
    document = _run("run-boundary", [_invocation("run-boundary", "inv-boundary", 0)])
    projection = build_task_usage_projection(document, catalog)
    turn = projection.turns[0]
    assert turn.price is not None
    assert turn.price.entry_id == "after"
    assert turn.cost.uncached_input_micro_usd == 18
    assert turn.cost.total_micro_usd == 18
    assert turn.price.catalog_digest == catalog.digest


def test_models_reject_extra_fields_unsafe_values_and_invalid_coverage() -> None:
    with pytest.raises(ValueError):
        UsageTokens.from_dict(
            {
                "inputTokens": 1,
                "cachedInputTokens": 0,
                "uncachedInputTokens": 1,
                "outputTokens": 0,
                "reasoningOutputTokens": 0,
                "totalTokens": 1,
                "unexpected": 1,
            }
        )
    with pytest.raises(ValueError):
        UsageTokens(inputTokens=True)
    with pytest.raises(ValueError):
        UsageCoverage(coveredInvocations=2, expectedInvocations=1, status="Complete")
    with pytest.raises(ValueError):
        UsageCosts(totalMicroUsd=1, status="N.A.")


def test_projection_rejects_cross_owner_and_duplicate_identity() -> None:
    duplicate = _run(
        "run-duplicate",
        [_invocation("run-duplicate", "inv-duplicate", 0), _invocation("run-duplicate", "inv-duplicate", 1)],
    )
    with pytest.raises(UsageProjectionError):
        build_task_usage_projection(duplicate, _catalog())

    cross_owner = _run("run-cross", [_invocation("run-cross", "inv-cross", 0)])
    cross_owner["extra"]["coquic"]["source"]["invocations"][0]["taskId"] = "other-task"  # type: ignore[index]
    with pytest.raises(UsageProjectionError):
        build_task_usage_projection(cross_owner, _catalog())
