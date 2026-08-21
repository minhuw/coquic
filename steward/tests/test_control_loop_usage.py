from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.agents.telemetry import PriceCatalog, PriceEntry
from coquic_steward.control_loop import ControlLoopArchive, ControlLoopLedger
from coquic_steward.control_loop.models import (
    PlannerRun,
    StewardOverheadUsage,
    UsageCosts,
    UsageCoverage,
    UsageTokens,
)
from coquic_steward.control_loop.usage_algebra import (
    fill_usage_costs,
    merge_usage_costs,
    merge_usage_coverage,
    merge_usage_tokens,
)
from coquic_steward.storage import TaskStore
from coquic_steward.control_loop.usage import (
    STEWARD_OVERHEAD_OWNER,
    StewardOverheadReducer,
    UsageReductionError,
)


UTC = timezone.utc


def _catalog(*models: str) -> PriceCatalog:
    if not models:
        models = ("gpt-overhead",)
    return PriceCatalog(
        entries=tuple(
            PriceEntry(
                entry_id=f"fixture-price-{model}",
                model=model,
                effective_from=datetime(2026, 1, 1, tzinfo=UTC),
                effective_until=None,
                input_micro_usd_per_million=500_000,
                cached_input_micro_usd_per_million=500_000,
                output_micro_usd_per_million=500_000,
                source_label="fixture",
                source_url="https://example.test/price",
            )
            for model in models
        )
    )


def _archive(tmp_path: Path) -> tuple[ControlLoopArchive, ControlLoopLedger]:
    store = TaskStore.create(tmp_path / "steward.sqlite")
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
            "startedAt": "2026-07-24T00:00:00Z",
        }
    )
    return archive, store.control_loop


def test_current_store_preserves_overhead_usage_schema(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "steward.sqlite"
    observed: dict[str, set[str]] = {}
    original_init = ControlLoopLedger.__init__

    def inspect_before_ledger_open(
        ledger: ControlLoopLedger,
        path: Path | str,
        *,
        epoch_id: str | None = None,
    ) -> None:
        with sqlite3.connect(path) as connection:
            observed["tables"] = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            observed["columns"] = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(control_loop_overhead_usage_runs)"
                )
            }
        original_init(ledger, path, epoch_id=epoch_id)

    monkeypatch.setattr(ControlLoopLedger, "__init__", inspect_before_ledger_open)
    store = TaskStore.create(database)

    assert {
        "control_loop_overhead_usage",
        "control_loop_overhead_usage_runs",
    } <= observed["tables"]
    assert {"rows_json", "cost_pending"} <= observed["columns"]
    assert store.control_loop.epoch_id


def _sidecar(
    *,
    invocation_id: str,
    started_at: str,
    model: str = "gpt-overhead",
    task_id: str = "steward-planner",
    input_tokens: int = 10,
    cached_tokens: int = 2,
    output_tokens: int = 4,
    completeness: str = "complete",
    cost: dict[str, object] | None = None,
) -> bytes:
    uncached = input_tokens - cached_tokens
    total = input_tokens + output_tokens
    turns = (
        [
            {
                "ordinal": 1,
                "input_tokens": input_tokens,
                "cached_input_tokens": cached_tokens,
                "uncached_input_tokens": uncached,
                "output_tokens": output_tokens,
                "reasoning_output_tokens": 1,
                "total_tokens": total,
            }
        ]
        if completeness != "unavailable"
        else []
    )
    payload = {
        "schema_version": 1,
        "provenance": "codex_exec_jsonl",
        "invocation_id": invocation_id,
        "task_id": task_id,
        "run_name": "planner",
        "stage": "signal_planner",
        "retry_ordinal": 0,
        "configured_model": model,
        "reasoning_effort": None,
        "billing_mode": "api",
        "started_at": started_at,
        "completed_at": started_at,
        "duration_ms": 0,
        "first_agent_message_completed_ms": None,
        "process_outcome": "success",
        "turns": turns,
        "aggregate": {
            "completed_turns": len(turns),
            "input_tokens": input_tokens if turns else 0,
            "cached_input_tokens": cached_tokens if turns else 0,
            "uncached_input_tokens": uncached if turns else 0,
            "output_tokens": output_tokens if turns else 0,
            "reasoning_output_tokens": 1 if turns else 0,
            "total_tokens": total if turns else 0,
        },
        "cost": cost
        or {
            "status": "estimated",
            "micro_usd": 7,
            "uncached_input_micro_usd": 4,
            "cached_input_micro_usd": 1,
            "output_micro_usd": 2,
            "price_entry": {},
        },
        "completeness": completeness,
        "issues": [],
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _run(
    archive: ControlLoopArchive,
    ledger: ControlLoopLedger,
    run_id: str,
    artifacts: dict[str, bytes],
    *,
    state: str = "succeeded",
) -> PlannerRun:
    ledger.claim_planner_run(run_id, [])
    completed = ledger.complete_planner_run(run_id, [], state=state)
    archive.publish_planner_run(completed, artifacts)
    return completed


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            UsageTokens(
                inputTokens=10,
                cachedInputTokens=2,
                uncachedInputTokens=8,
                outputTokens=4,
                totalTokens=14,
            ),
            UsageTokens(uncachedInputTokens=3),
            UsageTokens(
                inputTokens=10,
                cachedInputTokens=2,
                outputTokens=4,
                totalTokens=14,
            ),
        ),
        (
            UsageTokens(outputTokens=None, reasoningOutputTokens=3),
            UsageTokens(outputTokens=2),
            UsageTokens(outputTokens=2),
        ),
        (
            UsageTokens(),
            UsageTokens(),
            UsageTokens(),
        ),
    ],
)
def test_usage_algebra_merges_partial_tokens(
    left: UsageTokens, right: UsageTokens, expected: UsageTokens
) -> None:
    assert merge_usage_tokens(left, right) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            UsageCosts(
                uncachedInputMicroUsd=4,
                cachedInputMicroUsd=1,
                outputMicroUsd=2,
                totalMicroUsd=7,
                status="Complete",
            ),
            UsageCosts(
                uncachedInputMicroUsd=3,
                cachedInputMicroUsd=2,
                outputMicroUsd=1,
                totalMicroUsd=6,
                status="Complete",
            ),
            UsageCosts(
                uncachedInputMicroUsd=7,
                cachedInputMicroUsd=3,
                outputMicroUsd=3,
                totalMicroUsd=13,
                status="Complete",
            ),
        ),
        (
            UsageCosts(totalMicroUsd=5, status="Partial"),
            UsageCosts(outputMicroUsd=2, status="Partial"),
            UsageCosts(outputMicroUsd=2, totalMicroUsd=5, status="Partial"),
        ),
        (UsageCosts(), UsageCosts(), UsageCosts()),
    ],
)
def test_usage_algebra_merges_partial_costs(
    left: UsageCosts, right: UsageCosts, expected: UsageCosts
) -> None:
    assert merge_usage_costs(left, right) == expected


def test_usage_algebra_fill_preserves_left_values_and_partial_status() -> None:
    left = UsageCosts(
        uncachedInputMicroUsd=4,
        totalMicroUsd=8,
        status="Partial",
    )
    right = UsageCosts(
        uncachedInputMicroUsd=99,
        cachedInputMicroUsd=1,
        outputMicroUsd=2,
        totalMicroUsd=102,
        status="Complete",
    )

    assert fill_usage_costs(left, right) == UsageCosts(
        uncachedInputMicroUsd=4,
        cachedInputMicroUsd=1,
        outputMicroUsd=2,
        totalMicroUsd=None,
        status="Partial",
    )


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            UsageCoverage(coveredInvocations=1, expectedInvocations=1, status="Complete"),
            UsageCoverage(coveredInvocations=1, expectedInvocations=1, status="Complete"),
            UsageCoverage(coveredInvocations=2, expectedInvocations=2, status="Complete"),
        ),
        (
            UsageCoverage(),
            UsageCoverage(),
            UsageCoverage(),
        ),
        (
            UsageCoverage(coveredInvocations=0, expectedInvocations=1, status="N.A."),
            UsageCoverage(coveredInvocations=1, expectedInvocations=1, status="Complete"),
            UsageCoverage(coveredInvocations=1, expectedInvocations=2, status="Partial"),
        ),
    ],
)
def test_usage_algebra_merges_coverage(
    left: UsageCoverage, right: UsageCoverage, expected: UsageCoverage
) -> None:
    assert merge_usage_coverage(left, right) == expected


def test_incremental_and_rebuild_usage_algebra_match_for_partial_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, ledger = _archive(tmp_path)
    first = _run(
        archive,
        ledger,
        "planner-usage-partial-one",
        {"result.json": b"{}\\n"},
    )
    second = _run(
        archive,
        ledger,
        "planner-usage-partial-two",
        {"result.json": b"{}\\n"},
    )
    rows = [
        StewardOverheadUsage(
            date="2026-07-24",
            model="gpt-overhead",
            tokens=UsageTokens(
                inputTokens=10,
                cachedInputTokens=2,
                uncachedInputTokens=8,
            ),
            cost=UsageCosts(uncachedInputMicroUsd=4, status="Partial"),
            coverage=UsageCoverage(
                coveredInvocations=1,
                expectedInvocations=2,
                status="Partial",
            ),
        ),
        StewardOverheadUsage(
            date="2026-07-24",
            model="gpt-overhead",
            tokens=UsageTokens(
                uncachedInputTokens=5,
                outputTokens=3,
                reasoningOutputTokens=1,
                totalTokens=8,
            ),
            cost=UsageCosts(
                cachedInputMicroUsd=1,
                outputMicroUsd=2,
                totalMicroUsd=3,
                status="Partial",
            ),
            coverage=UsageCoverage(
                coveredInvocations=1,
                expectedInvocations=1,
                status="Complete",
            ),
        ),
    ]
    original_rebuild = ledger._rebuild_overhead_usage
    monkeypatch.setattr(ledger, "_rebuild_overhead_usage", lambda db: None)
    ledger.record_overhead_usage(first.planner_run_id, [rows[0]], archive_digest="1" * 64)
    ledger.record_overhead_usage(second.planner_run_id, [rows[1]], archive_digest="2" * 64)
    incremental = ledger.list_overhead_usage()

    monkeypatch.setattr(ledger, "_rebuild_overhead_usage", original_rebuild)
    with ledger.transaction() as db:
        ledger._rebuild_overhead_usage(db)
    rebuilt = ledger.list_overhead_usage()

    assert incremental == rebuilt
    assert rebuilt[0].tokens.uncached_input_tokens is None
    assert rebuilt[0].tokens.total_tokens is None
    assert rebuilt[0].cost.total_micro_usd is None
    assert rebuilt[0].coverage == UsageCoverage(
        coveredInvocations=2,
        expectedInvocations=3,
        status="Partial",
    )


def test_reducer_groups_exact_utc_date_and_model_and_replays_idempotently(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    first = _run(
        archive,
        ledger,
        "planner-usage-one",
        {
            "telemetry.json": _sidecar(
                invocation_id="inv-one",
                started_at="2026-07-24T23:59:59Z",
            )
        },
    )
    second = _run(
        archive,
        ledger,
        "planner-usage-two",
        {
            "telemetry.json": _sidecar(
                invocation_id="inv-two",
                started_at="2026-07-25T00:00:00Z",
            )
        },
    )
    reducer = StewardOverheadReducer(archive, ledger, catalog=_catalog())
    assert reducer.reconcile()["processed"] == 2
    rows = ledger.list_overhead_usage()
    assert [(row.date, row.model) for row in rows] == [
        ("2026-07-24", "gpt-overhead"),
        ("2026-07-25", "gpt-overhead"),
    ]
    assert rows[0].tokens.total_tokens == 14
    assert rows[1].cost.total_micro_usd == 7
    assert rows[0].owner_class == STEWARD_OVERHEAD_OWNER
    assert reducer.reconcile()["processed"] == 0
    assert reducer.reconcile()["skipped"] == 0
    assert first.planner_run_id != second.planner_run_id


def test_sidecar_aggregate_cost_is_not_public_without_catalog(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    run = _run(
        archive,
        ledger,
        "planner-usage-raw-cost",
        {"telemetry.json": _sidecar(invocation_id="inv-raw-cost", started_at="2026-07-24T01:00:00Z")},
    )

    reduced = StewardOverheadReducer(archive, ledger).reduce_run(run)

    assert reduced.rows[0].cost.status == "N.A."
    assert reduced.rows[0].cost.total_micro_usd is None


def test_catalog_fill_sums_each_delayed_run_contribution(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    _run(
        archive,
        ledger,
        "planner-usage-delayed-one",
        {"telemetry.json": _sidecar(invocation_id="inv-delayed-one", started_at="2026-07-24T01:00:00Z")},
    )
    _run(
        archive,
        ledger,
        "planner-usage-delayed-two",
        {"telemetry.json": _sidecar(invocation_id="inv-delayed-two", started_at="2026-07-24T02:00:00Z", input_tokens=3, cached_tokens=1, output_tokens=2)},
    )
    StewardOverheadReducer(archive, ledger).reconcile()

    result = StewardOverheadReducer(archive, ledger, catalog=_catalog()).reconcile()

    assert result["processed"] == 0
    row = ledger.list_overhead_usage()[0]
    assert row.cost.status == "Complete"
    assert row.cost.total_micro_usd == 10


def test_catalog_fill_rejects_changed_manifest_digest(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    run = _run(
        archive,
        ledger,
        "planner-usage-digest",
        {"telemetry.json": _sidecar(invocation_id="inv-digest", started_at="2026-07-24T01:00:00Z")},
    )
    StewardOverheadReducer(archive, ledger).reconcile()
    marker_before = ledger.overhead_usage_processed(run.planner_run_id)
    assert marker_before is not None

    target = archive.planner_runs_root / run.planner_run_id
    sidecar_path = target / "telemetry.json"
    changed = json.loads(sidecar_path.read_text(encoding="utf-8"))
    changed["turns"][0]["output_tokens"] += 1
    changed["turns"][0]["total_tokens"] += 1
    changed["aggregate"]["output_tokens"] += 1
    changed["aggregate"]["total_tokens"] += 1
    changed_bytes = json.dumps(changed, sort_keys=True).encode("utf-8")
    sidecar_path.write_bytes(changed_bytes)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["byteSize"] = len(changed_bytes)
    manifest["files"][0]["sha256"] = hashlib.sha256(changed_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    result = StewardOverheadReducer(archive, ledger, catalog=_catalog()).reconcile()

    assert result["errors"] == [f"{run.planner_run_id}:LedgerConflictError"]
    assert ledger.overhead_usage_processed(run.planner_run_id) == marker_before


def test_reconcile_uses_incremental_unprocessed_query(tmp_path: Path, monkeypatch) -> None:
    archive, ledger = _archive(tmp_path)
    _run(
        archive,
        ledger,
        "planner-usage-incremental",
        {"telemetry.json": _sidecar(invocation_id="inv-incremental", started_at="2026-07-24T01:00:00Z")},
    )
    reducer = StewardOverheadReducer(archive, ledger)
    reducer.reconcile()
    monkeypatch.setattr(
        ledger,
        "list_planner_runs",
        lambda **_: pytest.fail("normal usage drain scanned all planner runs"),
    )

    assert reducer.reconcile()["processed"] == 0


def test_reducer_merges_same_date_and_model_and_keeps_private_ids_out(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    _run(
        archive,
        ledger,
        "planner-usage-merge-one",
        {"telemetry.json": _sidecar(invocation_id="inv-merge-one", started_at="2026-07-24T01:00:00Z")},
    )
    _run(
        archive,
        ledger,
        "planner-usage-merge-two",
        {"telemetry.json": _sidecar(invocation_id="inv-merge-two", started_at="2026-07-24T12:00:00Z", input_tokens=3, cached_tokens=1, output_tokens=2)},
    )
    StewardOverheadReducer(archive, ledger).reconcile()
    row = ledger.list_overhead_usage()[0]
    assert row.tokens.total_tokens == 19
    public = row.public_dict()
    assert set(public) == {"date", "model", "ownerClass", "tokens", "cost", "coverage"}
    serialized = json.dumps(public)
    for private in ("plannerRunId", "invocationId", "taskId", "runId", "turns", "transcript"):
        assert private not in serialized


def test_missing_telemetry_and_price_preserve_na_coverage(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    missing = _run(archive, ledger, "planner-usage-missing", {"result.json": b"{}\n"}, state="interrupted")
    priced = _run(
        archive,
        ledger,
        "planner-usage-no-price",
        {
            "telemetry.json": _sidecar(
                invocation_id="inv-no-price",
                started_at="2026-07-24T01:00:00Z",
                cost={"status": "unavailable", "reason": "price_entry_unmatched"},
            )
        },
    )
    reducer = StewardOverheadReducer(archive, ledger)
    assert reducer.reduce_run(missing).rows[0].coverage.status == "N.A."
    reducer.reconcile()
    rows = ledger.list_overhead_usage()
    assert any(row.coverage.status == "N.A." for row in rows)
    priced_row = next(row for row in rows if row.model == "gpt-overhead")
    assert priced_row.tokens.total_tokens == 14
    assert priced_row.cost.status == "N.A."
    assert priced.planner_run_id != missing.planner_run_id


def test_task_shaped_sidecar_is_unavailable_not_allocated(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    run = _run(
        archive,
        ledger,
        "planner-usage-task-shaped",
        {"telemetry.json": _sidecar(invocation_id="inv-task", started_at="2026-07-24T01:00:00Z", task_id="task-private")},
    )
    reduced = StewardOverheadReducer(archive, ledger).reduce_run(run)
    assert reduced.rows[0].coverage.status == "N.A."
    assert reduced.rows[0].model == "N.A."
    with pytest.raises(UsageReductionError):
        StewardOverheadReducer(archive, ledger).reduce_run(
            run.model_copy(update={"state": "claimed", "completed_at": None})
        )


def test_later_catalog_fills_only_na_costs(tmp_path: Path) -> None:
    archive, ledger = _archive(tmp_path)
    _run(
        archive,
        ledger,
        "planner-usage-fill-cost",
        {
            "telemetry.json": _sidecar(
                invocation_id="inv-fill-cost",
                started_at="2026-07-24T01:00:00Z",
                cost={"status": "unavailable", "reason": "price_entry_unmatched"},
            )
        },
    )
    first = StewardOverheadReducer(archive, ledger).reconcile()
    assert first["rows"][0].cost.status == "N.A."
    catalog = PriceCatalog(
        entries=(
            PriceEntry(
                entry_id="fixture-price",
                model="gpt-overhead",
                effective_from=datetime(2026, 1, 1, tzinfo=UTC),
                effective_until=None,
                input_micro_usd_per_million=100_000,
                cached_input_micro_usd_per_million=50_000,
                output_micro_usd_per_million=200_000,
                source_label="fixture",
                source_url="https://example.test/price",
            ),
        )
    )
    second = StewardOverheadReducer(archive, ledger, catalog=catalog).reconcile()
    assert second["processed"] == 0
    assert ledger.list_overhead_usage()[0].tokens.total_tokens == 14
    assert ledger.list_overhead_usage()[0].cost.status == "Complete"
