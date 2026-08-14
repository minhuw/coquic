"""Detached deterministic task usage projections.

The builder accepts only the public invocation evidence already emitted by the
ATIF mapper.  It has no archive, transport, or daemon dependencies and is safe
to call repeatedly for the same immutable evidence set.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any

from ..agents.telemetry import (
    BillingMode,
    PriceCatalog,
    TelemetryTurn,
    estimate_cost,
)
from .outbox import PublicationCounts
from .models import (
    AtifDocument,
    MAX_USAGE_INVOCATIONS,
    MAX_USAGE_TURNS,
    PriceProvenance,
    TaskUsageDaily,
    TaskUsageLifetime,
    TaskUsageProjection,
    TaskUsageSummary,
    UsageCoverage,
    UsageCosts,
    UsageInvocation,
    UsageRun,
    UsageSummary,
    UsageTokens,
    UsageTurn,
    _merge_usage_costs,
    _merge_usage_coverage,
    _merge_usage_tokens,
    _fold_usage_costs,
    _usage_counter,
    _usage_identifier,
    _usage_model,
    _usage_timestamp,
    _usage_timestamp_text,
    _usage_thaw,
)


class UsageProjectionError(ValueError):
    """Raised when sanitized evidence cannot be authenticated or projected."""


UsageValidationError = UsageProjectionError


_ATIF_SCHEMA_VERSION = "ATIF-v1.7"
_INVOCATION_KEYS = frozenset(
    {
        "invocationId",
        "taskId",
        "pipelineId",
        "runId",
        "retryOrdinal",
        "startedAt",
        "completedAt",
        "model",
        "billingMode",
        "processOutcome",
        "coverage",
        "issues",
        "aggregate",
        "turns",
    }
)
_TURN_KEYS = frozenset(
    {"ordinal", "prompt", "cached", "uncached", "completion", "reasoning", "total"}
)
_USAGE_KEYS = frozenset(
    {"prompt", "cached", "uncached", "completion", "reasoning", "total"}
)
_COVERAGE_VALUES = {
    "complete": "Complete",
    "Complete": "Complete",
    "partial": "Partial",
    "Partial": "Partial",
    "unavailable": "N.A.",
    "N.A.": "N.A.",
    "na": "N.A.",
}

_MAPPING_VALUES = (
    AtifDocument,
    PublicationCounts,
    UsageSummary,
    UsageTokens,
    UsageCosts,
    UsageCoverage,
    PriceProvenance,
    UsageTurn,
    UsageInvocation,
    UsageRun,
    TaskUsageSummary,
    TaskUsageDaily,
    TaskUsageLifetime,
    TaskUsageProjection,
)


def _fail(message: str) -> None:
    # Do not include evidence values in validation errors: sanitized input is
    # public, but keeping errors categorical makes this boundary future-proof.
    raise UsageProjectionError(message) from None


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _usage_thaw(item) for key, item in value.items()}
    if type(value) is AtifDocument:
        mapped = AtifDocument.as_dict(value)
    elif isinstance(value, PublicationCounts):
        mapped = PublicationCounts.as_dict(value)
    elif isinstance(value, UsageSummary):
        mapped = UsageSummary.as_dict(value)
    elif isinstance(value, UsageTokens):
        mapped = UsageTokens.as_dict(value)
    elif isinstance(value, UsageCosts):
        mapped = UsageCosts.as_dict(value)
    elif isinstance(value, UsageCoverage):
        mapped = UsageCoverage.as_dict(value)
    elif isinstance(value, PriceProvenance):
        mapped = PriceProvenance.as_dict(value)
    elif isinstance(value, UsageTurn):
        mapped = UsageTurn.as_dict(value)
    elif isinstance(value, UsageInvocation):
        mapped = UsageInvocation.as_dict(value)
    elif isinstance(value, UsageRun):
        mapped = UsageRun.as_dict(value)
    elif isinstance(value, TaskUsageSummary):
        mapped = TaskUsageSummary.as_dict(value)
    elif isinstance(value, TaskUsageDaily):
        mapped = TaskUsageDaily.as_dict(value)
    elif isinstance(value, TaskUsageLifetime):
        mapped = TaskUsageLifetime.as_dict(value)
    elif isinstance(value, TaskUsageProjection):
        mapped = TaskUsageProjection.as_dict(value)
    else:
        _fail("evidence is not a detached mapping")
    if isinstance(mapped, Mapping):
        return {str(key): _usage_thaw(item) for key, item in mapped.items()}
    _fail("evidence is not a detached mapping")


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, datetime):
        return _usage_timestamp_text(value)
    if isinstance(value, date):
        return value.isoformat()
    return value


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            _canonical_value(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        _fail("evidence is not canonical JSON")


def _source_document(value: object) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    document = _mapping(value)
    if "evidence" in document:
        nested = document["evidence"]
        if not isinstance(nested, Mapping):
            _fail("evidence envelope is invalid")
        document = _mapping(nested)
    if "schema_version" in document and document["schema_version"] != _ATIF_SCHEMA_VERSION:
        _fail("unsupported evidence schema")
    provenance: Mapping[str, Any] | None = None
    extra = document.get("extra")
    if isinstance(extra, Mapping):
        coqui = extra.get("coquic")
        if isinstance(coqui, Mapping):
            provenance = coqui
    if provenance is None and isinstance(document.get("coquic"), Mapping):
        provenance = document["coquic"]
    if provenance is None:
        provenance = document
    source = provenance.get("source")
    if not isinstance(source, Mapping):
        source = document.get("source")
    if not isinstance(source, Mapping):
        source = document
    source_value = {str(key): _usage_thaw(item) for key, item in source.items()}
    # ATIF keeps task/run identity on ``extra.coquic`` and usage evidence under
    # its nested ``source`` object.  Carry only those authenticated identity
    # witnesses into the detached source view.
    for key in ("taskId", "pipelineId", "runId"):
        if key not in source_value and key in provenance:
            source_value[key] = _usage_thaw(provenance[key])
    return document, source_value, (
        str(provenance.get("role")) if isinstance(provenance.get("role"), str) else None
    )


def _identity(value: Mapping[str, Any], *, task_id: str | None = None) -> tuple[str, str, str]:
    selected_task = value.get("taskId", task_id)
    if selected_task is None:
        _fail("task ownership is missing")
    if task_id is not None and value.get("taskId", task_id) != task_id:
        _fail("task ownership is invalid")
    selected_pipeline = value.get("pipelineId")
    selected_run = value.get("runId")
    if selected_pipeline is None or selected_run is None:
        _fail("run ownership is missing")
    try:
        return (
            _usage_identifier(selected_task),
            _usage_identifier(selected_pipeline),
            _usage_identifier(selected_run),
        )
    except Exception:
        _fail("run ownership is invalid")


def _normalise_coverage(value: object) -> str:
    if not isinstance(value, str) or value not in _COVERAGE_VALUES:
        _fail("invocation coverage is invalid")
    return _COVERAGE_VALUES[value]


def _usage_from_mapping(value: object) -> UsageTokens:
    if value is None:
        return UsageTokens()
    if not isinstance(value, Mapping):
        _fail("usage aggregate is invalid")
    if set(value) - _USAGE_KEYS:
        _fail("usage aggregate has unknown fields")
    try:
        return UsageTokens(
            input_tokens=value.get("prompt"),
            cached_input_tokens=value.get("cached"),
            uncached_input_tokens=value.get("uncached"),
            output_tokens=value.get("completion"),
            reasoning_output_tokens=value.get("reasoning"),
            total_tokens=value.get("total"),
        )
    except Exception:
        _fail("usage aggregate is invalid")


def _aggregate_value(value: object) -> UsageTokens:
    if value is None:
        return UsageTokens()
    if not isinstance(value, Mapping) or set(value) != {"usage"}:
        # Accepting the six-field form is useful for already detached tests,
        # while ATIF itself always wraps it in ``aggregate.usage``.
        if isinstance(value, Mapping) and not set(value) - _USAGE_KEYS:
            return _usage_from_mapping(value)
        _fail("usage aggregate is invalid")
    return _usage_from_mapping(value.get("usage"))


def _turn_values(value: object) -> tuple[tuple[int, UsageTokens], ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail("turn evidence is invalid")
    if len(value) > MAX_USAGE_TURNS:
        _fail("turn evidence exceeds bound")
    parsed: list[tuple[int, UsageTokens]] = []
    for expected, raw in enumerate(value, start=1):
        if not isinstance(raw, Mapping) or set(raw) != _TURN_KEYS:
            _fail("turn evidence has unknown fields")
        ordinal = raw.get("ordinal")
        try:
            _usage_counter(ordinal, allow_none=False)
        except Exception:
            _fail("turn ordinal is invalid")
        if ordinal != expected or ordinal < 1:
            _fail("turn ordinals are not contiguous")
        tokens = _usage_from_mapping(
            {
                "prompt": raw.get("prompt"),
                "cached": raw.get("cached"),
                "uncached": raw.get("uncached"),
                "completion": raw.get("completion"),
                "reasoning": raw.get("reasoning"),
                "total": raw.get("total"),
            }
        )
        if any(item is None for item in tokens.as_dict().values()):
            _fail("turn token evidence is incomplete")
        parsed.append((ordinal, tokens))
    return tuple(parsed)


def _turn_telemetry(value: UsageTokens, ordinal: int) -> TelemetryTurn:
    try:
        return TelemetryTurn.from_usage(
            {
                "input_tokens": value.input_tokens,
                "cached_input_tokens": value.cached_input_tokens,
                "output_tokens": value.output_tokens,
                "reasoning_output_tokens": value.reasoning_output_tokens,
            },
            ordinal=ordinal,
        )
    except (TypeError, ValueError):
        _fail("turn token evidence is invalid")


def _cost_for_turn(
    tokens: UsageTokens,
    *,
    model: str,
    started_at: datetime,
    billing_mode: str,
    catalog: PriceCatalog,
    coverage: str,
) -> tuple[UsageCosts, PriceProvenance | None]:
    telemetry_turn = _turn_telemetry(tokens, 1)
    try:
        estimate = estimate_cost(
            [telemetry_turn],
            billing_mode=billing_mode,
            configured_model=model,
            started_at=started_at,
            catalog=catalog,
        )
    except Exception:
        estimate = None
    if estimate is None or estimate.status.value != "estimated":
        reason = estimate.reason if estimate is not None else "price_unavailable"
        return UsageCosts(reason=reason), None
    entry = catalog.find(model, started_at)
    if entry is None:
        return UsageCosts(reason="price_entry_unmatched"), None
    status = "Complete" if coverage == "Complete" else "Partial"
    return (
        UsageCosts(
            uncached_input_micro_usd=estimate.uncached_input_micro_usd,
            cached_input_micro_usd=estimate.cached_input_micro_usd,
            output_micro_usd=estimate.output_micro_usd,
            total_micro_usd=estimate.micro_usd,
            status=status,
        ),
        PriceProvenance.from_entry(entry, catalog.digest),
    )


def _run_source(
    document: Mapping[str, Any],
    source: Mapping[str, Any],
    role: str | None,
    *,
    task_id_override: str | None,
    catalog: PriceCatalog,
) -> UsageRun:
    root_identity = dict(source)
    for key in ("taskId", "pipelineId", "runId"):
        if key not in root_identity and key in document:
            root_identity[key] = document[key]
    task_id, pipeline_id, run_id = _identity(root_identity, task_id=task_id_override)
    raw_invocations = source.get("invocations")
    if isinstance(raw_invocations, (str, bytes)) or not isinstance(raw_invocations, Sequence) or not raw_invocations:
        _fail("invocation evidence is missing")
    if len(raw_invocations) > MAX_USAGE_INVOCATIONS:
        _fail("invocation evidence exceeds bound")
    invocations: list[UsageInvocation] = []
    seen_ids: set[str] = set()
    seen_ordinals: set[int] = set()
    for raw in raw_invocations:
        if not isinstance(raw, Mapping) or set(raw) - _INVOCATION_KEYS:
            _fail("invocation evidence has unknown fields")
        if any(raw.get(key) != expected for key, expected in (("taskId", task_id), ("pipelineId", pipeline_id), ("runId", run_id))):
            _fail("invocation ownership is invalid")
        try:
            retry_ordinal = _usage_counter(raw.get("retryOrdinal"), allow_none=False)
        except Exception:
            _fail("retry ordinal is invalid")
        if retry_ordinal in seen_ordinals:
            _fail("duplicate retry ordinal")
        seen_ordinals.add(retry_ordinal)
        if retry_ordinal < 0 or retry_ordinal >= MAX_USAGE_INVOCATIONS:
            _fail("retry ordinal exceeds bound")
        invocation_id = raw.get("invocationId")
        if invocation_id is not None:
            try:
                invocation_id = _usage_identifier(invocation_id)
            except Exception:
                _fail("invocation identity is invalid")
            if invocation_id in seen_ids:
                _fail("duplicate invocation identity")
            seen_ids.add(invocation_id)
        coverage = _normalise_coverage(raw.get("coverage"))
        started_at = _usage_timestamp(raw.get("startedAt"), allow_none=True)
        completed_at = _usage_timestamp(raw.get("completedAt"), allow_none=True)
        if (started_at is None) != (completed_at is None):
            _fail("invocation timing is incomplete")
        if started_at is not None and completed_at is not None and completed_at < started_at:
            _fail("invocation timing is invalid")
        model = raw.get("model")
        try:
            model = _usage_model(model)
        except Exception:
            _fail("invocation model is invalid")
        billing_mode = raw.get("billingMode", "unknown")
        if billing_mode is None:
            if coverage != "N.A." or raw.get("turns") or raw.get("aggregate") is not None:
                _fail("billing mode is invalid")
        elif billing_mode not in {item.value for item in BillingMode}:
            _fail("billing mode is invalid")
        process_outcome = raw.get("processOutcome")
        if process_outcome is not None:
            if not isinstance(process_outcome, str) or not process_outcome or len(process_outcome) > 64:
                _fail("process outcome is invalid")
        issues = raw.get("issues", [])
        if not isinstance(issues, Sequence) or isinstance(issues, (str, bytes)) or len(issues) > 32:
            _fail("invocation issues are invalid")
        for issue in issues:
            if (
                not isinstance(issue, Mapping)
                or set(issue) != {"category", "count"}
                or not isinstance(issue.get("category"), str)
                or not issue["category"]
            ):
                _fail("invocation issues are invalid")
            try:
                count = _usage_counter(issue.get("count"), allow_none=False)
            except Exception:
                _fail("invocation issues are invalid")
            if count < 1:
                _fail("invocation issues are invalid")
        turn_values = _turn_values(raw.get("turns"))
        aggregate = _aggregate_value(raw.get("aggregate"))
        if turn_values:
            expected = UsageTokens()
            for _, tokens in turn_values:
                expected = _merge_usage_tokens(expected, tokens)
            if raw.get("aggregate") is not None and aggregate != expected:
                _fail("invocation aggregate does not match turns")
            aggregate = expected
            if invocation_id is None or model is None or started_at is None:
                _fail("priced turn ownership is incomplete")
            turn_rows: list[UsageTurn] = []
            turn_costs: list[UsageCosts] = []
            provenance: PriceProvenance | None = None
            for ordinal, tokens in turn_values:
                cost, current_provenance = _cost_for_turn(
                    tokens,
                    model=model,
                    started_at=started_at,
                    billing_mode=billing_mode,
                    catalog=catalog,
                    coverage=coverage,
                )
                turn_costs.append(cost)
                if current_provenance is not None:
                    if provenance is not None and provenance != current_provenance:
                        _fail("invocation price provenance is mixed")
                    provenance = current_provenance
                turn_rows.append(
                    UsageTurn(
                        task_id=task_id,
                        pipeline_id=pipeline_id,
                        run_id=run_id,
                        invocation_id=invocation_id,
                        retry_ordinal=retry_ordinal,
                        turn_ordinal=ordinal,
                        model=model,
                        started_at=started_at,
                        tokens=tokens,
                        cost=cost,
                        price=current_provenance,
                    )
                )
            invocation_tokens = aggregate
            cost = _fold_usage_costs(turn_costs)
        else:
            turn_rows = []
            invocation_tokens = aggregate
            cost = UsageCosts(reason="turn_evidence_missing")
            provenance = None
        if coverage == "N.A.":
            invocation_coverage = UsageCoverage(0, 1, "N.A.")
        elif coverage == "Complete":
            if invocation_id is None or not (turn_rows or any(item is not None for item in invocation_tokens.as_dict().values())):
                _fail("complete invocation evidence is missing")
            invocation_coverage = UsageCoverage(1, 1, "Complete")
        else:
            invocation_coverage = UsageCoverage(
                1 if turn_rows or any(item is not None for item in invocation_tokens.as_dict().values()) else 0,
                1,
                "Partial" if turn_rows or any(item is not None for item in invocation_tokens.as_dict().values()) else "N.A.",
            )
        invocations.append(
            UsageInvocation(
                task_id=task_id,
                pipeline_id=pipeline_id,
                run_id=run_id,
                invocation_id=invocation_id,
                retry_ordinal=retry_ordinal,
                model=model,
                started_at=started_at,
                completed_at=completed_at,
                coverage=invocation_coverage,
                tokens=invocation_tokens,
                cost=cost,
                turns=tuple(turn_rows),
                process_outcome=process_outcome,
                price=provenance,
            )
        )
    invocations.sort(key=lambda item: (item.retry_ordinal, item.invocation_id or ""))
    if {item.retry_ordinal for item in invocations} != set(range(max(item.retry_ordinal for item in invocations) + 1)):
        _fail("retry ordinals have gaps")
    tokens = UsageTokens()
    coverage = UsageCoverage()
    costs = _fold_usage_costs(item.cost for item in invocations)
    for item in invocations:
        tokens = _merge_usage_tokens(tokens, item.tokens)
        coverage = _merge_usage_coverage(coverage, item.coverage)
    return UsageRun(
        task_id=task_id,
        pipeline_id=pipeline_id,
        run_id=run_id,
        role=role,
        invocations=tuple(invocations),
        tokens=tokens,
        cost=costs,
        coverage=coverage,
    )


def _group_daily(task_id: str, invocations: Sequence[UsageInvocation]) -> tuple[TaskUsageDaily, ...]:
    grouped: dict[tuple[str, str | None], TaskUsageDaily] = {}
    for invocation in invocations:
        if invocation.started_at is None:
            continue
        key = (invocation.started_at.astimezone(timezone.utc).date().isoformat(), invocation.model)
        row = TaskUsageDaily(
            task_id=task_id,
            date=key[0],
            model=key[1],
            tokens=invocation.tokens,
            cost=invocation.cost,
            coverage=invocation.coverage,
        )
        previous = grouped.get(key)
        if previous is None:
            grouped[key] = row
        else:
            grouped[key] = TaskUsageDaily(
                task_id=task_id,
                date=key[0],
                model=key[1],
                tokens=_merge_usage_tokens(previous.tokens, row.tokens),
                cost=_merge_usage_costs(previous.cost, row.cost),
                coverage=_merge_usage_coverage(previous.coverage, row.coverage),
            )
    return tuple(grouped[key] for key in sorted(grouped, key=lambda item: (item[0], item[1] or "")))


def _group_lifetime(task_id: str, invocations: Sequence[UsageInvocation]) -> tuple[TaskUsageLifetime, ...]:
    grouped: dict[str | None, TaskUsageLifetime] = {}
    for invocation in invocations:
        key = invocation.model
        row = TaskUsageLifetime(
            task_id=task_id,
            model=key,
            tokens=invocation.tokens,
            cost=invocation.cost,
            coverage=invocation.coverage,
        )
        previous = grouped.get(key)
        if previous is None:
            grouped[key] = row
        else:
            grouped[key] = TaskUsageLifetime(
                task_id=task_id,
                model=key,
                tokens=_merge_usage_tokens(previous.tokens, row.tokens),
                cost=_merge_usage_costs(previous.cost, row.cost),
                coverage=_merge_usage_coverage(previous.coverage, row.coverage),
            )
    return tuple(grouped[key] for key in sorted(grouped, key=lambda item: item or ""))


def build_task_usage_projection(
    evidence: Mapping[str, Any] | Sequence[object] | object,
    catalog: PriceCatalog | None = None,
    *,
    task_id: str | None = None,
    price_catalog: PriceCatalog | None = None,
) -> TaskUsageProjection:
    """Build one deterministic task projection from sanitized ATIF evidence.

    ``evidence`` may be one ATIF document, a sequence of run documents, or a
    detached ``AtifDocument`` value.  The optional task ID is only a fallback
    for direct source mappings that carry no outer provenance.
    """

    if catalog is not None and price_catalog is not None and catalog != price_catalog:
        _fail("conflicting price catalogs")
    selected_catalog = price_catalog if price_catalog is not None else catalog
    if selected_catalog is None:
        selected_catalog = PriceCatalog.empty()
    if not isinstance(selected_catalog, PriceCatalog):
        _fail("price catalog is invalid")
    if isinstance(evidence, (str, bytes)):
        _fail("evidence is not a sequence")
    if isinstance(evidence, Mapping) or isinstance(evidence, _MAPPING_VALUES):
        values = (evidence,)
    elif isinstance(evidence, Sequence):
        values = tuple(evidence)
    else:
        _fail("evidence is not a sequence")
    if not values or len(values) > MAX_USAGE_INVOCATIONS:
        _fail("evidence set is empty or oversized")
    runs: list[UsageRun] = []
    canonical_documents: list[dict[str, Any]] = []
    seen_runs: set[tuple[str, str, str]] = set()
    resolved_task: str | None = None
    for value in values:
        document, source, role = _source_document(value)
        canonical_documents.append(document)
        run = _run_source(
            document,
            source,
            role,
            task_id_override=task_id,
            catalog=selected_catalog,
        )
        if resolved_task is None:
            resolved_task = run.task_id
        if run.task_id != resolved_task:
            _fail("evidence crosses task owners")
        identity = (run.task_id, run.pipeline_id, run.run_id)
        if identity in seen_runs:
            _fail("duplicate run identity")
        seen_runs.add(identity)
        runs.append(run)
    if resolved_task is None:
        _fail("task ownership is missing")
    runs.sort(key=lambda item: (item.pipeline_id, item.run_id))
    invocations = tuple(
        item
        for run in runs
        for item in run.invocations
    )
    turns = tuple(item for invocation in invocations for item in invocation.turns)
    summary_tokens = UsageTokens()
    summary_coverage = UsageCoverage()
    summary_cost = _fold_usage_costs(run.cost for run in runs)
    for run in runs:
        summary_tokens = _merge_usage_tokens(summary_tokens, run.tokens)
        summary_coverage = _merge_usage_coverage(summary_coverage, run.coverage)
    summary = TaskUsageSummary(
        task_id=resolved_task,
        tokens=summary_tokens,
        cost=summary_cost,
        coverage=summary_coverage,
        run_count=len(runs),
    )
    daily = _group_daily(resolved_task, invocations)
    lifetime = _group_lifetime(resolved_task, invocations)
    evidence_digest = hashlib.sha256(
        _canonical_bytes(sorted(canonical_documents, key=lambda item: _canonical_bytes(item)))
    ).hexdigest()
    catalog_digest = selected_catalog.digest
    base = {
        "schemaVersion": "1.0",
        "taskId": resolved_task,
        "evidenceDigest": evidence_digest,
        "catalogDigest": catalog_digest,
        "summary": summary.as_dict(),
        "runs": [item.as_dict() for item in runs],
        "invocations": [item.as_dict() for item in invocations],
        "turns": [item.as_dict() for item in turns],
        "daily": [item.as_dict() for item in daily],
        "lifetime": [item.as_dict() for item in lifetime],
    }
    projection_digest = hashlib.sha256(_canonical_bytes(base)).hexdigest()
    usage_generation_id = hashlib.sha256(
        _canonical_bytes(
            {
                "schemaVersion": "1.0",
                "evidenceDigest": evidence_digest,
                "catalogDigest": catalog_digest,
                "projectionDigest": projection_digest,
            }
        )
    ).hexdigest()
    return TaskUsageProjection(
        task_id=resolved_task,
        summary=summary,
        runs=tuple(runs),
        invocations=invocations,
        turns=turns,
        daily=daily,
        lifetime=lifetime,
        evidence_digest=evidence_digest,
        catalog_digest=catalog_digest,
        projection_digest=projection_digest,
        usage_generation_id=usage_generation_id,
    )


# Keep the builder discoverable under the short names likely used by later
# publication stages.  It remains unused by generation.py in this plan.
build_usage_projection = build_task_usage_projection
project_task_usage = build_task_usage_projection
build_usage = build_task_usage_projection
project_usage = build_task_usage_projection


__all__ = [
    "UsageProjectionError",
    "UsageValidationError",
    "build_task_usage_projection",
    "build_usage_projection",
    "project_task_usage",
    "build_usage",
    "project_usage",
]
