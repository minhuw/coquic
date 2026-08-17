"""Bounded aggregate usage reduction for non-task Steward planner calls.

Only a terminal control-loop manifest is an authentication boundary.  This
module intentionally keeps invocation and turn evidence private while
materializing rows keyed by UTC date, exact model, and the fixed
``Steward overhead`` ownership class.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Iterable, Mapping, TYPE_CHECKING

from ..agents.telemetry import (
    PriceCatalog,
    TELEMETRY_MAX_SIDECAR_BYTES,
    TelemetryAggregate,
    TelemetryTurn,
    estimate_cost,
    validate_sidecar,
)
from .models import (
    PlannerRun,
    StewardOverheadUsage,
    UsageCosts,
    UsageCoverage,
    UsageTokens,
)

if TYPE_CHECKING:
    from .archive import ControlLoopArchive
    from .ledger import ControlLoopLedger


STEWARD_OVERHEAD_OWNER = "Steward overhead"
STEWARD_PLANNER_TASK_ID = "steward-planner"
STEWARD_PLANNER_RUN_NAME = "planner"
STEWARD_PLANNER_STAGE = "signal_planner"
TERMINAL_PLANNER_STATES = frozenset(
    {"succeeded", "failed", "interrupted", "cancelled"}
)
_TELEMETRY_NAME = re.compile(
    r"^(?:telemetry|telemetry\.retry-[1-9][0-9]*|telemetry\.unavailable-[1-9][0-9]*)\.json$"
)
_MISSING_MODEL = "N.A."


class UsageReductionError(RuntimeError):
    """A sealed planner run does not contain trustworthy usage evidence."""


@dataclass(frozen=True)
class UsageReduction:
    """Private reducer result; ``rows`` are the only public-safe values."""

    rows: tuple[StewardOverheadUsage, ...]
    archive_digest: str

    def __iter__(self):
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> StewardOverheadUsage:
        return self.rows[index]


@dataclass
class _Evidence:
    invocation_id: str
    date: str
    model: str
    tokens: UsageTokens
    cost: UsageCosts
    covered: int
    expected: int
    coverage_status: str


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise UsageReductionError("telemetry start time is unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageReductionError("telemetry start time is invalid") from exc
    if parsed.tzinfo is None:
        raise UsageReductionError("telemetry start time has no timezone")
    return parsed.astimezone(timezone.utc)


def _merge_optional(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return left + right


def _merge_tokens(left: UsageTokens, right: UsageTokens) -> UsageTokens:
    values = {
        "inputTokens": _merge_optional(left.input_tokens, right.input_tokens),
        "cachedInputTokens": _merge_optional(
            left.cached_input_tokens, right.cached_input_tokens
        ),
        "uncachedInputTokens": _merge_optional(
            left.uncached_input_tokens, right.uncached_input_tokens
        ),
        "outputTokens": _merge_optional(left.output_tokens, right.output_tokens),
        "reasoningOutputTokens": _merge_optional(
            left.reasoning_output_tokens, right.reasoning_output_tokens
        ),
        "totalTokens": _merge_optional(left.total_tokens, right.total_tokens),
    }
    # A partial sidecar may carry only a subset of counters.  Preserve known
    # subtotals without fabricating a reconciliation among unknown categories.
    if values["inputTokens"] is not None and values["cachedInputTokens"] is not None:
        expected = values["inputTokens"] - values["cachedInputTokens"]
        if values["uncachedInputTokens"] != expected:
            values["uncachedInputTokens"] = None
    if values["outputTokens"] is not None and values["reasoningOutputTokens"] is not None:
        if values["reasoningOutputTokens"] > values["outputTokens"]:
            values["reasoningOutputTokens"] = None
    if (
        values["inputTokens"] is not None
        and values["outputTokens"] is not None
        and values["totalTokens"] is not None
        and values["totalTokens"] != values["inputTokens"] + values["outputTokens"]
    ):
        values["totalTokens"] = None
    return UsageTokens(**values)


def _merge_costs(left: UsageCosts, right: UsageCosts) -> UsageCosts:
    values = {
        "uncachedInputMicroUsd": _merge_optional(
            left.uncached_input_micro_usd, right.uncached_input_micro_usd
        ),
        "cachedInputMicroUsd": _merge_optional(
            left.cached_input_micro_usd, right.cached_input_micro_usd
        ),
        "outputMicroUsd": _merge_optional(
            left.output_micro_usd, right.output_micro_usd
        ),
        "totalMicroUsd": _merge_optional(left.total_micro_usd, right.total_micro_usd),
    }
    components = (
        values["uncachedInputMicroUsd"],
        values["cachedInputMicroUsd"],
        values["outputMicroUsd"],
    )
    if values["totalMicroUsd"] is not None and all(item is not None for item in components):
        if values["totalMicroUsd"] != sum(item for item in components if item is not None):
            values["totalMicroUsd"] = None
    present = [item is not None for item in values.values()]
    if all(present) and left.status == right.status == "Complete":
        status = "Complete"
    elif any(present):
        status = "Partial"
    else:
        status = "N.A."
    return UsageCosts(status=status, **values)


def _merge_coverage(left: UsageCoverage, right: UsageCoverage) -> UsageCoverage:
    covered = left.covered_invocations + right.covered_invocations
    expected = left.expected_invocations + right.expected_invocations
    if expected == 0 or covered == 0:
        status = "N.A."
    elif covered == expected and left.status == right.status == "Complete":
        status = "Complete"
    else:
        status = "Partial"
    return UsageCoverage(
        coveredInvocations=covered,
        expectedInvocations=expected,
        status=status,
    )


def _aggregate_tokens(value: Mapping[str, Any]) -> UsageTokens:
    aggregate = TelemetryAggregate.from_dict(value)
    return UsageTokens(
        inputTokens=aggregate.input_tokens,
        cachedInputTokens=aggregate.cached_input_tokens,
        uncachedInputTokens=aggregate.uncached_input_tokens,
        outputTokens=aggregate.output_tokens,
        reasoningOutputTokens=aggregate.reasoning_output_tokens,
        totalTokens=aggregate.total_tokens,
    )


def _cost_from_sidecar(
    payload: Mapping[str, Any], *, catalog: PriceCatalog | None, turns: list[TelemetryTurn]
) -> UsageCosts:
    raw_cost = payload.get("cost")
    if not isinstance(raw_cost, Mapping):
        return UsageCosts()
    if payload.get("completeness") == "unavailable":
        return UsageCosts()
    if not turns:
        return UsageCosts()
    # When the repository catalog is available, recompute from every
    # validated turn.  This preserves plan-027's exact invocation-start price
    # interval and never trusts a mutable-looking aggregate amount.
    if catalog is not None and turns:
        try:
            estimate = estimate_cost(
                turns,
                billing_mode=str(payload.get("billing_mode") or "unknown"),
                configured_model=payload.get("configured_model"),
                started_at=_parse_utc(payload.get("started_at")),
                catalog=catalog,
            )
        except Exception:
            estimate = None
        if estimate is not None and estimate.status.value == "estimated":
            return UsageCosts(
                uncachedInputMicroUsd=estimate.uncached_input_micro_usd,
                cachedInputMicroUsd=estimate.cached_input_micro_usd,
                outputMicroUsd=estimate.output_micro_usd,
                totalMicroUsd=estimate.micro_usd,
                status=(
                    "Complete"
                    if payload.get("completeness") == "complete"
                    else "Partial"
                ),
            )
        return UsageCosts()
    # The private aggregate amount is not a billing authority.  It may be
    # retained for diagnostics, but public costs are emitted only when every
    # validated turn succeeds against the exact effective-dated catalog above.
    return UsageCosts()


def _sidecar_evidence(
    raw: bytes,
    *,
    expected_epoch_started_at: datetime,
    catalog: PriceCatalog | None,
) -> _Evidence:
    if len(raw) > TELEMETRY_MAX_SIDECAR_BYTES:
        raise UsageReductionError("telemetry sidecar exceeds bound")
    try:
        payload = validate_sidecar(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise UsageReductionError("telemetry sidecar is not valid evidence") from exc
    if (
        payload.get("task_id") != STEWARD_PLANNER_TASK_ID
        or payload.get("run_name") != STEWARD_PLANNER_RUN_NAME
        or payload.get("stage") != STEWARD_PLANNER_STAGE
    ):
        # A task-shaped sidecar is deliberately unavailable rather than being
        # guessed into an overhead bucket.
        raise UsageReductionError("telemetry sidecar is not owned by the control-loop planner")
    started_at = _parse_utc(payload.get("started_at"))
    if started_at < expected_epoch_started_at:
        raise UsageReductionError("telemetry sidecar crosses the control-loop epoch")
    turns: list[TelemetryTurn] = []
    raw_turns = payload.get("turns")
    if isinstance(raw_turns, list):
        for item in raw_turns:
            if isinstance(item, Mapping):
                turns.append(
                    TelemetryTurn.from_usage(
                        {
                            key: item.get(key)
                            for key in (
                                "input_tokens",
                                "cached_input_tokens",
                                "output_tokens",
                                "reasoning_output_tokens",
                            )
                        },
                        ordinal=item.get("ordinal", len(turns) + 1),
                    )
                )
    complete = payload.get("completeness") == "complete"
    tokens = (
        _aggregate_tokens(payload["aggregate"])
        if isinstance(payload.get("aggregate"), Mapping)
        and payload.get("completeness") in {"complete", "partial"}
        and (turns or complete)
        else UsageTokens()
    )
    cost = _cost_from_sidecar(payload, catalog=catalog, turns=turns)
    return _Evidence(
        invocation_id=str(payload["invocation_id"]),
        date=started_at.date().isoformat(),
        model=(
            str(payload["configured_model"])
            if isinstance(payload.get("configured_model"), str)
            and payload.get("configured_model")
            else _MISSING_MODEL
        ),
        tokens=tokens,
        cost=cost,
        covered=1,
        expected=1,
        coverage_status="Complete" if complete else "Partial",
    )


class StewardOverheadReducer:
    """Reduce sealed control-loop planner telemetry and persist idempotently."""

    def __init__(
        self,
        archive: ControlLoopArchive,
        ledger: ControlLoopLedger | None = None,
        *,
        catalog: PriceCatalog | None = None,
    ) -> None:
        self.archive = archive
        self.ledger = ledger
        self.catalog = catalog

    def reduce_run(
        self,
        run: PlannerRun | Mapping[str, Any],
    ) -> UsageReduction:
        item = run if isinstance(run, PlannerRun) else PlannerRun.model_validate(run)
        if item.state not in TERMINAL_PLANNER_STATES or item.completed_at is None:
            raise UsageReductionError("only terminal planner runs may be reduced")
        manifest, artifacts, manifest_digest = self.archive.read_verified_planner_run(
            item.planner_run_id,
            expected_run=item,
        )
        del manifest
        names = sorted(
            path
            for path in artifacts
            if "/" not in path and _TELEMETRY_NAME.fullmatch(path)
        )
        evidence: list[_Evidence] = []
        invalid = sum(
            1
            for path in artifacts
            if "/" not in path
            and path.startswith("telemetry")
            and _TELEMETRY_NAME.fullmatch(path) is None
        )
        seen_invocations: dict[str, str] = {}
        for name in names:
            try:
                current = _sidecar_evidence(
                    artifacts[name],
                    expected_epoch_started_at=self.archive._require_epoch().started_at,
                    catalog=self.catalog,
                )
                sidecar_digest = sha256(artifacts[name]).hexdigest()
                previous = seen_invocations.get(current.invocation_id)
                if previous is not None:
                    if previous != sidecar_digest:
                        invalid += 1
                    continue
                seen_invocations[current.invocation_id] = sidecar_digest
                evidence.append(current)
            except UsageReductionError:
                invalid += 1
        expected = max(1, len(evidence) + invalid)
        if not evidence:
            evidence = [
                _Evidence(
                    invocation_id="unavailable",
                    date=item.started_at.astimezone(timezone.utc).date().isoformat(),
                    model=_MISSING_MODEL,
                    tokens=UsageTokens(),
                    cost=UsageCosts(),
                    covered=0,
                    expected=expected,
                    coverage_status="N.A.",
                )
            ]
        elif invalid:
            evidence.append(
                _Evidence(
                    invocation_id="unavailable",
                    date=item.started_at.astimezone(timezone.utc).date().isoformat(),
                    model=_MISSING_MODEL,
                    tokens=UsageTokens(),
                    cost=UsageCosts(),
                    covered=0,
                    expected=invalid,
                    coverage_status="N.A.",
                )
            )
        grouped: dict[tuple[str, str], StewardOverheadUsage] = {}
        for current in evidence:
            key = (current.date, current.model)
            coverage = UsageCoverage(
                coveredInvocations=current.covered,
                expectedInvocations=current.expected,
                status=current.coverage_status,
            )
            row = StewardOverheadUsage(
                date=current.date,
                model=current.model,
                ownerClass=STEWARD_OVERHEAD_OWNER,
                tokens=current.tokens,
                cost=current.cost,
                coverage=coverage,
            )
            previous = grouped.get(key)
            if previous is None:
                grouped[key] = row
            else:
                grouped[key] = StewardOverheadUsage(
                    date=row.date,
                    model=row.model,
                    ownerClass=STEWARD_OVERHEAD_OWNER,
                    tokens=_merge_tokens(previous.tokens, row.tokens),
                    cost=_merge_costs(previous.cost, row.cost),
                    coverage=_merge_coverage(previous.coverage, row.coverage),
                )
        return UsageReduction(
            rows=tuple(grouped[key] for key in sorted(grouped)),
            archive_digest=manifest_digest,
        )

    def reconcile(
        self,
        ledger: ControlLoopLedger | None = None,
        *,
        runs: Iterable[PlannerRun] | None = None,
    ) -> dict[str, Any]:
        selected_ledger = ledger or self.ledger
        if selected_ledger is None:
            raise UsageReductionError("usage reconciliation requires a ledger")
        page_size = 128
        bounded_page = runs is None
        if runs is not None:
            selected_runs = list(runs)
        else:
            # Marker rows form a durable per-run cursor.  A bounded query keeps
            # normal drains incremental while still admitting late terminal
            # transitions whose completion time falls before the last page.
            selected_runs = selected_ledger.list_unprocessed_planner_runs(limit=page_size)
            if self.catalog is not None:
                selected_runs.extend(
                    selected_ledger.list_overhead_usage_runs_needing_cost(limit=page_size)
                )
        selected_runs = list({run.planner_run_id: run for run in selected_runs}.values())
        selected_runs.sort(key=lambda value: (value.completed_at or value.started_at, value.planner_run_id))
        processed = 0
        skipped = 0
        errors: list[str] = []
        for run in selected_runs:
            if run.state not in TERMINAL_PLANNER_STATES or run.completed_at is None:
                continue
            existing = selected_ledger.overhead_usage_processed(run.planner_run_id)
            if existing is not None:
                if self.catalog is not None:
                    try:
                        reduced = self.reduce_run(run)
                        selected_ledger.record_overhead_usage(
                            run.planner_run_id,
                            reduced.rows,
                            archive_digest=reduced.archive_digest,
                            fill_missing_costs=True,
                        )
                    except Exception as exc:
                        errors.append(f"{run.planner_run_id}:{exc.__class__.__name__}")
                skipped += 1
                continue
            try:
                reduced = self.reduce_run(run)
                if selected_ledger.record_overhead_usage(
                    run.planner_run_id,
                    reduced.rows,
                    archive_digest=reduced.archive_digest,
                ):
                    processed += 1
            except Exception as exc:
                errors.append(f"{run.planner_run_id}:{exc.__class__.__name__}")
        return {
            "processed": processed,
            "skipped": skipped,
            "errors": errors,
            "pending": bounded_page and len(selected_runs) >= page_size,
            "watermark": selected_ledger.overhead_usage_watermark(),
            "rows": selected_ledger.list_overhead_usage(),
        }


def reduce_steward_overhead(
    archive: ControlLoopArchive,
    run: PlannerRun | Mapping[str, Any],
    *,
    catalog: PriceCatalog | None = None,
) -> UsageReduction:
    return StewardOverheadReducer(archive, catalog=catalog).reduce_run(run)


__all__ = [
    "STEWARD_OVERHEAD_OWNER",
    "STEWARD_PLANNER_RUN_NAME",
    "STEWARD_PLANNER_STAGE",
    "STEWARD_PLANNER_TASK_ID",
    "StewardOverheadReducer",
    "TERMINAL_PLANNER_STATES",
    "UsageReduction",
    "UsageReductionError",
    "reduce_steward_overhead",
]
