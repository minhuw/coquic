"""Bounded, public-safe staging for the Steward Cloudflare D1 schema.

The publisher hands this module one already-sanitized publication envelope.  This
module owns the transport boundary and the visibility protocol only: SQL is fixed
in this file, all values are bound parameters, staging is replayable, and the
single final batch is the only operation that can change a public head.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, TypeAlias
from urllib.parse import quote

import httpx

from ..agents.telemetry import (
    CostStatus,
    PriceCatalog,
    PriceEntry,
    TelemetryTurn,
    estimate_cost,
)


MAX_BATCH_PARAMETERS = 99
MAX_BATCH_BYTES = 100_000
MAX_BATCH_STATEMENTS = 64
MAX_RESPONSE_BYTES = 1_048_576
MAX_RESULT_SETS = MAX_BATCH_STATEMENTS
MAX_RESULT_ROWS = 4_096
MAX_TOKEN_LENGTH = 4_096
MAX_TIMEOUT_SECONDS = 120.0

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")
_MEDIA = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")
_PATH = re.compile(r"^(?!/)(?!.*://)(?!.*\.\.)[^\x00-\x1f]{1,1024}$")
_PUBLIC_KEY = re.compile(r"^v1/tasks/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PRIVATE_LOCATOR = re.compile(
    r"(?:"
    r"[a-z][a-z0-9+.-]*://|"
    r"(?:^|[\\/])(?:private|credential|credentials|secret|token)(?:[\\/]|$)|"
    r"(?:^|[A-Za-z]:)[\\/]|"
    r"^(?:~[/\\]|\\\\)|"
    r"(?:^|[-_])(?:private|internal|secret)[-_](?:bucket|object(?:[-_]key)?|url|path)(?:$|[-_])"
    r")",
    re.IGNORECASE,
)

_METADATA_FIELDS = ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts", "usage")


class D1ErrorCode(StrEnum):
    """Stable, non-sensitive failure categories for the D1 boundary."""

    invalid_request = "invalid_request"
    private_value = "private_value"
    authentication = "authentication"
    quota = "quota"
    timeout = "timeout"
    network = "network"
    # HTTP 5xx uses the existing transport-safe transient vocabulary.  The
    # aliases make the classification explicit to callers without creating a
    # second serialized category.
    transient = "network"
    server_error = "network"
    http_5xx = "network"
    provider = "provider"
    malformed_response = "malformed_response"
    response_too_large = "response_too_large"
    result_limit = "result_limit"
    generation_conflict = "generation_conflict"
    generation_state = "generation_state"
    count_mismatch = "count_mismatch"
    digest_mismatch = "digest_mismatch"

    # Descriptive aliases used by transport callers.
    auth = "authentication"
    unauthorized = "authentication"
    rate_limited = "quota"
    network_error = "network"
    provider_error = "provider"
    malformed = "malformed_response"


class D1Error(RuntimeError):
    """An error whose text contains only an enumerated category."""

    def __init__(self, code: D1ErrorCode | str):
        try:
            normalized = D1ErrorCode(code)
        except (TypeError, ValueError):
            normalized = D1ErrorCode.provider
        self.code = normalized
        self.category = normalized
        self.reason_code = normalized
        self.kind = normalized
        super().__init__(normalized.value)


Scalar: TypeAlias = str | int | float | bool | None
Statement: TypeAlias = tuple[str, tuple[Scalar, ...]]


class D1Response(Protocol):
    status_code: int
    headers: Mapping[str, str]

    @property
    def content(self) -> bytes: ...


class D1HttpClient(Protocol):
    """The complete adapter surface used at the third-party HTTP boundary."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes,
        timeout: float,
    ) -> D1Response: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class StageReceipt:
    publication_id: str
    task_id: str
    run_id: str
    staged: bool = True
    usage_generation_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExposureReceipt:
    publication_id: str
    task_id: str
    state: str = "visible"
    usage_generation_id: str | None = None


@dataclass(frozen=True, slots=True)
class HideReceipt:
    task_id: str
    publication_id: str | None
    state: str = "hidden"
    changed: bool = True


@dataclass(frozen=True, slots=True)
class OverheadReceipt:
    """Receipt for one aggregate-only Steward-overhead reconciliation."""

    date: str | None = None
    model: str | None = None
    digest: str | None = None
    state: str = "visible"
    changed: bool = True


@dataclass(frozen=True, slots=True)
class UsageBackfillReceipt:
    """Bounded result from a cached-D1 N.A.-cost backfill."""

    task_id: str | None = None
    old_usage_generation_id: str | None = None
    usage_generation_id: str | None = None
    processed_turns: int = 0
    changed: bool = False
    next_cursor: str | None = None
    blocked_reason: str | None = None


_TOP_LEVEL = frozenset(
    {
        "schemaVersion",
        "publicationId",
        "taskId",
        "generation",
        "headIntent",
        "task",
        "pipelines",
        "runs",
        "events",
        "artifacts",
        "usage",
    }
)
_GENERATION = frozenset(
    {
        "publicationId",
        "taskId",
        "runId",
        "metadataDigest",
        "idempotencyKey",
        "state",
        "expectedCounts",
        "createdAt",
    }
)
_COUNTS = frozenset({"tasks", "pipelines", "runs", "events", "artifacts"})
_HEAD = frozenset({"publicationId", "taskId", "state", "updatedAt"})
_TASK = frozenset({"taskId", "title", "lifecycleState", "createdAt", "completedAt"})
_PIPELINE = frozenset({"pipelineId", "taskId", "name", "createdAt"})
_RUN = frozenset(
    {
        "runId",
        "taskId",
        "pipelineId",
        "role",
        "runState",
        "startedAt",
        "completedAt",
        "durationMs",
        "atifDigest",
        "atifArtifactId",
    }
)
_EVENT = frozenset({"taskId", "sequence", "eventType", "occurredAt", "summary"})
_ARTIFACT = frozenset(
    {
        "artifactId",
        "taskId",
        "runId",
        "logicalPath",
        "publicKey",
        "mediaType",
        "byteSize",
        "sha256",
        "availability",
        "disclosure",
    }
)
_DISCLOSURE = frozenset({"redactionApplied", "originalRetained"})
_USAGE = frozenset({"schemaVersion", "generation", "summaries", "invocations", "turns", "prices", "globals"})
_USAGE_GENERATION = frozenset(
    {
        "usageGenerationId",
        "publicationId",
        "taskId",
        "schemaVersion",
        "metadataDigest",
        "state",
        "expectedCounts",
        "createdAt",
    }
)
_USAGE_COUNTS = frozenset({"summaries", "invocations", "turns", "prices", "globals"})
_SUMMARY = frozenset(
    {
        "summaryId",
        "usageGenerationId",
        "publicationId",
        "taskId",
        "runId",
        "scope",
        "coverage",
        "coveredInvocations",
        "expectedInvocations",
        "knownTokenSubtotal",
        "knownCostSubtotalMicroUsd",
        "promptTokens",
        "cachedTokens",
        "uncachedTokens",
        "completionTokens",
        "reasoningTokens",
        "totalTokens",
        "uncachedInputCostMicroUsd",
        "cachedInputCostMicroUsd",
        "outputCostMicroUsd",
        "totalCostMicroUsd",
        "priceProvenanceDigest",
    }
)
_INVOCATION = frozenset(
    {
        "invocationId",
        "usageGenerationId",
        "publicationId",
        "taskId",
        "pipelineId",
        "runId",
        "ownershipClass",
        "retryOrdinal",
        "startedAt",
        "completedAt",
        "model",
        "billingMode",
        "processOutcome",
        "coverage",
        "issueCount",
        "coveredTurns",
        "expectedTurns",
        "promptTokens",
        "cachedTokens",
        "uncachedTokens",
        "completionTokens",
        "reasoningTokens",
        "totalTokens",
        "uncachedInputCostMicroUsd",
        "cachedInputCostMicroUsd",
        "outputCostMicroUsd",
        "totalCostMicroUsd",
        "priceEntryDigest",
    }
)
_TURN = frozenset(
    {
        "turnId",
        "usageGenerationId",
        "invocationId",
        "publicationId",
        "taskId",
        "runId",
        "ordinal",
        "promptTokens",
        "cachedTokens",
        "uncachedTokens",
        "completionTokens",
        "reasoningTokens",
        "totalTokens",
        "uncachedInputCostMicroUsd",
        "cachedInputCostMicroUsd",
        "outputCostMicroUsd",
        "totalCostMicroUsd",
        "priceEntryDigest",
    }
)
_PRICE = frozenset({"priceEntryDigest", "usageGenerationId", "catalogDigest", "model", "effectiveAt", "effectiveUntil"})
_GLOBAL = frozenset(
    {
        "globalId",
        "usageGenerationId",
        "periodKind",
        "periodKey",
        "model",
        "ownershipClass",
        "coverage",
        "coveredInvocations",
        "expectedInvocations",
        "knownTokenSubtotal",
        "knownCostSubtotalMicroUsd",
        "promptTokens",
        "cachedTokens",
        "uncachedTokens",
        "completionTokens",
        "reasoningTokens",
        "totalTokens",
        "uncachedInputCostMicroUsd",
        "cachedInputCostMicroUsd",
        "outputCostMicroUsd",
        "totalCostMicroUsd",
        "priceProvenanceDigest",
        "aggregateOnly",
    }
)
_TOKEN_FIELDS = ("promptTokens", "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens")
_COST_FIELDS = ("uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd")
_USAGE_FIELDS = _TOKEN_FIELDS + _COST_FIELDS
_TOKEN_DB_FIELDS = ("prompt_tokens", "cached_tokens", "uncached_tokens", "completion_tokens", "reasoning_tokens", "total_tokens")
_COST_DB_FIELDS = ("uncached_input_cost_micro_usd", "cached_input_cost_micro_usd", "output_cost_micro_usd", "total_cost_micro_usd")
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_GLOBAL_KEY_FIELDS = ("periodKind", "periodKey", "model", "ownershipClass")
_GLOBAL_VALUE_FIELDS = (
    "coverage",
    "coveredInvocations",
    "expectedInvocations",
    "knownTokenSubtotal",
    "knownCostSubtotalMicroUsd",
    *_USAGE_FIELDS,
    "priceProvenanceDigest",
    "aggregateOnly",
)


def _invalid(code: D1ErrorCode = D1ErrorCode.invalid_request) -> None:
    raise D1Error(code)


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _invalid()
    return value


def _keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        _invalid()


def _text(value: object, *, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        _invalid()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        _invalid()
    if _PRIVATE_LOCATOR.search(value):
        _invalid(D1ErrorCode.private_value)
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _invalid()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _invalid()
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid()
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _invalid()
    return value


def _integer(value: object, *, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _invalid()
    return value


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        _invalid()
    return value


def _safe_value(value: object, *, key: str = "") -> None:
    """Reject private locator-shaped leaves without treating prose as a locator."""

    if isinstance(value, str):
        if key and any(token in key.lower() for token in ("credential", "private", "secret", "token", "url", "uri", "endpoint")):
            _invalid(D1ErrorCode.private_value)
        if _PRIVATE_LOCATOR.search(value):
            _invalid(D1ErrorCode.private_value)
    elif isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                _invalid()
            _safe_value(child_value, key=child_key)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        for child in value:
            _safe_value(child, key=key)


def _metadata_digest(payload: Mapping[str, Any]) -> str:
    metadata = {key: payload[key] for key in _METADATA_FIELDS}
    canonical = (
        json.dumps(metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _usage_metadata_digest(payload: Mapping[str, Any]) -> str:
    usage = _mapping(payload["usage"])
    generation = dict(_mapping(usage["generation"]))
    generation["metadataDigest"] = ""
    metadata = {
        "publicationId": payload["publicationId"],
        "taskId": payload["taskId"],
        "generation": generation,
        "summaries": usage["summaries"],
        "invocations": usage["invocations"],
        "turns": usage["turns"],
        "prices": usage["prices"],
        "globals": usage["globals"],
    }
    canonical = (
        json.dumps(metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _usage_integer(value: object, *, allow_none: bool = True, maximum: int = _SAFE_INTEGER_MAX) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        _invalid(D1ErrorCode.generation_conflict)
    return value


def _usage_math(row: Mapping[str, Any], *, nullable: bool = True) -> None:
    values: dict[str, int | None] = {}
    for field in _USAGE_FIELDS:
        values[field] = _usage_integer(row[field], allow_none=nullable)
    tokens = tuple(values[field] for field in _TOKEN_FIELDS)
    if all(value is not None for value in tokens):
        prompt, cached, uncached, completion, reasoning, total = tokens
        if cached > prompt or uncached != prompt - cached or reasoning > completion or total != prompt + completion:
            _invalid(D1ErrorCode.generation_conflict)
    costs = tuple(values[field] for field in _COST_FIELDS)
    if any(value is None for value in costs) and any(value is not None for value in costs):
        _invalid(D1ErrorCode.generation_conflict)


def _usage_price_in_range(price: Mapping[str, Any], started_at: str | None) -> None:
    if started_at is None:
        return
    effective_at = datetime.fromisoformat(price["effectiveAt"].replace("Z", "+00:00"))
    effective_until = price["effectiveUntil"]
    started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    if started < effective_at or (effective_until is not None and started >= datetime.fromisoformat(effective_until.replace("Z", "+00:00"))):
        _invalid(D1ErrorCode.generation_conflict)


def _verified_global_rollups(invocations: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Build only the task-owned global facts that invocation evidence proves."""

    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for row in invocations:
        if row.get("ownershipClass") != "task-owned" or not isinstance(row.get("model"), str):
            continue
        model = row["model"]
        grouped.setdefault(("lifetime", "lifetime", model, "task-owned"), []).append(row)
        started_at = row.get("startedAt")
        if isinstance(started_at, str):
            try:
                day = datetime.fromisoformat(started_at.replace("Z", "+00:00")).date().isoformat()
            except ValueError:
                day = None
            if day is not None:
                grouped.setdefault(("daily", day, model, "task-owned"), []).append(row)

    result: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for key, entries in grouped.items():
        aggregate: dict[str, Any] = {
            "periodKind": key[0],
            "periodKey": key[1],
            "model": key[2],
            "ownershipClass": key[3],
            "coveredInvocations": sum(row["coverage"] != "unavailable" for row in entries),
            "expectedInvocations": len(entries),
            "aggregateOnly": True,
        }
        for field in _USAGE_FIELDS:
            values = [row[field] for row in entries]
            aggregate[field] = sum(values) if all(value is not None for value in values) else None
        aggregate["knownTokenSubtotal"] = aggregate["totalTokens"]
        aggregate["knownCostSubtotalMicroUsd"] = aggregate["totalCostMicroUsd"]
        aggregate["coverage"] = (
            "unavailable"
            if all(aggregate[field] is None for field in _USAGE_FIELDS)
            else "complete"
            if aggregate["coveredInvocations"] == aggregate["expectedInvocations"]
            and all(aggregate[field] is not None for field in _USAGE_FIELDS)
            else "partial"
        )
        price_digests = {row.get("priceEntryDigest") for row in entries}
        aggregate["priceProvenanceDigest"] = next(iter(price_digests)) if len(price_digests) == 1 else None
        result[key] = aggregate
    return result


def _object_mapping(value: object) -> Mapping[str, Any] | None:
    """Accept only the owner-detached mapping contract."""

    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return value
    return None


_OVERHEAD_PUBLIC_KEYS = frozenset({"date", "model", "ownerClass", "tokens", "cost", "coverage"})
_OVERHEAD_TOKEN_KEYS = frozenset({
    "inputTokens", "cachedInputTokens", "uncachedInputTokens", "outputTokens", "reasoningOutputTokens", "totalTokens",
})
_OVERHEAD_COST_KEYS = frozenset({"uncachedInputMicroUsd", "cachedInputMicroUsd", "outputMicroUsd", "totalMicroUsd"})
_OVERHEAD_COVERAGE_KEYS = frozenset({"status", "coveredInvocations", "expectedInvocations"})


def _overhead_public_mapping(value: object) -> dict[str, Any]:
    """Return the strict public allowlist used for producer/D1 digesting."""

    row = _object_mapping(value)
    if row is None:
        _invalid(D1ErrorCode.generation_conflict)
    if _OVERHEAD_PUBLIC_KEYS <= frozenset(row):
        if frozenset(row) != _OVERHEAD_PUBLIC_KEYS:
            _invalid(D1ErrorCode.generation_conflict)
        tokens = _object_mapping(row["tokens"])
        costs = _object_mapping(row["cost"])
        coverage = _object_mapping(row["coverage"])
        if tokens is None or costs is None or coverage is None:
            _invalid(D1ErrorCode.generation_conflict)
        if frozenset(tokens) != _OVERHEAD_TOKEN_KEYS or frozenset(costs) != _OVERHEAD_COST_KEYS or frozenset(coverage) != _OVERHEAD_COVERAGE_KEYS:
            _invalid(D1ErrorCode.generation_conflict)
        if not isinstance(row["date"], str) or not isinstance(row["model"], str):
            _invalid(D1ErrorCode.generation_conflict)
        if row["ownerClass"] != "Steward overhead":
            _invalid(D1ErrorCode.generation_conflict)
        return {
            "date": row["date"],
            "model": row["model"],
            "ownerClass": "Steward overhead",
            "tokens": dict(tokens),
            "cost": dict(costs),
            "coverage": dict(coverage),
        }
    # Normalized rows are accepted only by the local helper/tests.  They are
    # never accepted as a model-like producer value and retain their exact
    # allowlist for deterministic replay.
    normalized_keys = {
        "periodKind", "periodKey", "model", "ownershipClass", "coverage", "coveredInvocations", "expectedInvocations",
        "knownTokenSubtotal", "knownCostSubtotalMicroUsd", *_USAGE_FIELDS, "priceProvenanceDigest", "aggregateOnly",
    }
    if frozenset(row) != normalized_keys:
        _invalid(D1ErrorCode.generation_conflict)
    normalized = dict(row)
    if normalized.get("periodKind") not in {"daily", "lifetime"}:
        _invalid(D1ErrorCode.generation_conflict)
    period_key = normalized.get("periodKey")
    if normalized["periodKind"] == "lifetime":
        if period_key != "lifetime":
            _invalid(D1ErrorCode.generation_conflict)
    elif not isinstance(period_key, str) or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", period_key) is None:
        _invalid(D1ErrorCode.generation_conflict)
    try:
        if normalized["periodKind"] == "daily":
            datetime.fromisoformat(period_key).date()
    except (TypeError, ValueError):
        _invalid(D1ErrorCode.generation_conflict)
    _text(normalized.get("model"), maximum=256)
    if normalized.get("ownershipClass") != "steward-overhead" or normalized.get("aggregateOnly") is not True:
        _invalid(D1ErrorCode.generation_conflict)
    covered = _usage_integer(normalized.get("coveredInvocations"), allow_none=False)
    expected = _usage_integer(normalized.get("expectedInvocations"), allow_none=False)
    if covered > expected or (normalized.get("coverage") == "complete" and covered != expected):
        _invalid(D1ErrorCode.generation_conflict)
    if normalized.get("coverage") not in {"complete", "partial", "unavailable"}:
        _invalid(D1ErrorCode.generation_conflict)
    _usage_math(normalized)
    if normalized.get("coverage") == "unavailable" and any(normalized.get(field) is not None for field in _USAGE_FIELDS):
        _invalid(D1ErrorCode.generation_conflict)
    if normalized.get("knownTokenSubtotal") is not None:
        _usage_integer(normalized["knownTokenSubtotal"])
    if normalized.get("knownCostSubtotalMicroUsd") is not None:
        _usage_integer(normalized["knownCostSubtotalMicroUsd"])
    if normalized.get("totalTokens") is not None and normalized.get("knownTokenSubtotal") != normalized.get("totalTokens"):
        _invalid(D1ErrorCode.generation_conflict)
    if normalized.get("totalCostMicroUsd") is not None and normalized.get("knownCostSubtotalMicroUsd") != normalized.get("totalCostMicroUsd"):
        _invalid(D1ErrorCode.generation_conflict)
    if normalized.get("priceProvenanceDigest") is not None:
        _invalid(D1ErrorCode.generation_conflict)
    return normalized


def _overhead_row(value: object) -> dict[str, Any]:
    """Normalize one aggregate overhead row to the public global shape."""

    row = _overhead_public_mapping(value)
    if "periodKey" in row:
        # A normalized row is already in the D1 global shape.
        return dict(row)
    date = row.get("date", row.get("periodKey"))
    model = row.get("model")
    owner = row.get("ownerClass", row.get("owner_class", row.get("ownershipClass")))
    if not isinstance(date, str) or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", date) is None:
        _invalid(D1ErrorCode.generation_conflict)
    try:
        datetime.fromisoformat(date).date()
    except ValueError:
        _invalid(D1ErrorCode.generation_conflict)
    model = _text(model, maximum=256)
    if owner not in {None, "Steward overhead", "steward-overhead"}:
        _invalid(D1ErrorCode.generation_conflict)
    tokens = _object_mapping(row.get("tokens")) or row
    costs = _object_mapping(row.get("cost")) or row
    coverage = _object_mapping(row.get("coverage")) or row
    def pick(values: Mapping[str, Any], *names: str) -> Any:
        for name in names:
            if name in values:
                return values[name]
        return None

    token_values = {
        "promptTokens": pick(tokens, "inputTokens", "input_tokens", "promptTokens", "prompt_tokens"),
        "cachedTokens": pick(tokens, "cachedInputTokens", "cached_input_tokens", "cachedTokens", "cached_tokens"),
        "uncachedTokens": pick(tokens, "uncachedInputTokens", "uncached_input_tokens", "uncachedTokens", "uncached_tokens"),
        "completionTokens": pick(tokens, "outputTokens", "output_tokens", "completionTokens", "completion_tokens"),
        "reasoningTokens": pick(tokens, "reasoningOutputTokens", "reasoning_output_tokens", "reasoningTokens", "reasoning_tokens"),
        "totalTokens": pick(tokens, "totalTokens", "total_tokens"),
    }
    cost_values = {
        "uncachedInputCostMicroUsd": pick(costs, "uncachedInputMicroUsd", "uncached_input_micro_usd", "uncachedInputCostMicroUsd", "uncached_input_cost_micro_usd"),
        "cachedInputCostMicroUsd": pick(costs, "cachedInputMicroUsd", "cached_input_micro_usd", "cachedInputCostMicroUsd", "cached_input_cost_micro_usd"),
        "outputCostMicroUsd": pick(costs, "outputMicroUsd", "output_micro_usd", "outputCostMicroUsd", "output_cost_micro_usd"),
        "totalCostMicroUsd": pick(costs, "totalMicroUsd", "total_micro_usd", "totalCostMicroUsd", "total_cost_micro_usd"),
    }
    status = coverage.get("status", coverage.get("coverage"))
    status_map = {"Complete": "complete", "Partial": "partial", "N.A.": "unavailable", "complete": "complete", "partial": "partial", "unavailable": "unavailable"}
    if status is not None and status not in status_map:
        _invalid(D1ErrorCode.generation_conflict)
    normalized_status = status_map.get(status, "unavailable")
    covered = coverage.get("coveredInvocations", coverage.get("covered_invocations", 0))
    expected = coverage.get("expectedInvocations", coverage.get("expected_invocations", 0))
    covered = _usage_integer(covered, allow_none=False)
    expected = _usage_integer(expected, allow_none=False)
    if covered > expected:
        _invalid(D1ErrorCode.generation_conflict)
    if normalized_status == "complete" and covered != expected:
        _invalid(D1ErrorCode.generation_conflict)
    for field, item in (*token_values.items(), *cost_values.items()):
        _usage_integer(item)
    if normalized_status == "unavailable":
        for field in (*token_values, *cost_values):
            token_values[field] = None
        known_token = None
        known_cost = None
    else:
        known_token = token_values["totalTokens"]
        known_cost = cost_values["totalCostMicroUsd"]
    normalized = {
        "periodKind": "daily",
        "periodKey": date,
        "model": model,
        "ownershipClass": "steward-overhead",
        "coverage": normalized_status,
        "coveredInvocations": covered,
        "expectedInvocations": expected,
        "knownTokenSubtotal": known_token,
        "knownCostSubtotalMicroUsd": known_cost,
        **token_values,
        **cost_values,
        "priceProvenanceDigest": None,
        "aggregateOnly": True,
    }
    _usage_math(normalized)
    return normalized


def _overhead_public_value(normalized: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "date": normalized["periodKey"],
        "model": normalized["model"],
        "ownerClass": "Steward overhead",
        "tokens": {
            "inputTokens": normalized["promptTokens"],
            "cachedInputTokens": normalized["cachedTokens"],
            "uncachedInputTokens": normalized["uncachedTokens"],
            "outputTokens": normalized["completionTokens"],
            "reasoningOutputTokens": normalized["reasoningTokens"],
            "totalTokens": normalized["totalTokens"],
        },
        "cost": {
            "uncachedInputMicroUsd": normalized["uncachedInputCostMicroUsd"],
            "cachedInputMicroUsd": normalized["cachedInputCostMicroUsd"],
            "outputMicroUsd": normalized["outputCostMicroUsd"],
            "totalMicroUsd": normalized["totalCostMicroUsd"],
        },
        "coverage": {
            "status": {"complete": "Complete", "partial": "Partial", "unavailable": "N.A."}[normalized["coverage"]],
            "coveredInvocations": normalized["coveredInvocations"],
            "expectedInvocations": normalized["expectedInvocations"],
        },
    }


def _overhead_digest(rows: Sequence[Mapping[str, Any]], supplied: object | None = None) -> str:
    canonical_rows: list[dict[str, Any]] = []
    for row in rows:
        mapping = _overhead_public_mapping(row)
        if "periodKey" in mapping:
            canonical_rows.append(_overhead_public_value(_overhead_row(mapping)))
        else:
            # Digest the producer allowlist before semantic math validation so
            # a supplied digest mismatch remains the reported failure class.
            canonical_rows.append(dict(mapping))
    canonical_rows.sort(key=lambda row: (row["date"], row["model"]))
    # A single row is the producer's public_dict representation.  A bounded
    # multi-row call is represented as a canonical sorted list of those rows.
    value: object = canonical_rows[0] if len(canonical_rows) == 1 else canonical_rows
    try:
        canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        _invalid(D1ErrorCode.generation_conflict)
    computed = hashlib.sha256(canonical).hexdigest()
    if supplied is not None:
        supplied_digest = _digest(supplied)
        if not hmac.compare_digest(supplied_digest, computed):
            _invalid(D1ErrorCode.digest_mismatch)
    return computed


def _validate_usage(
    payload: Mapping[str, Any],
    pipeline_ids: set[str],
    run_ids: set[str],
) -> None:
    usage = _mapping(payload["usage"])
    _keys(usage, _USAGE)
    if usage["schemaVersion"] != "1.0":
        _invalid(D1ErrorCode.generation_conflict)
    usage_generation = _mapping(usage["generation"])
    _keys(usage_generation, _USAGE_GENERATION)
    publication_id = payload["publicationId"]
    task_id = payload["taskId"]
    usage_generation_id = _id(usage_generation["usageGenerationId"])
    if _id(usage_generation["publicationId"]) != publication_id or _id(usage_generation["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    if usage_generation["schemaVersion"] != "1.0" or usage_generation["state"] != "staged":
        _invalid(D1ErrorCode.generation_state)
    _digest(usage_generation["metadataDigest"])
    _timestamp(usage_generation["createdAt"])
    counts = _mapping(usage_generation["expectedCounts"])
    _keys(counts, _USAGE_COUNTS)
    limits = {"summaries": 4096, "invocations": 128, "turns": 4096, "prices": 4096, "globals": 4096}
    for name, maximum in limits.items():
        _usage_integer(counts[name], allow_none=False, maximum=maximum)
    if counts["summaries"] < 1:
        _invalid(D1ErrorCode.count_mismatch)
    if usage_generation["metadataDigest"] != _usage_metadata_digest(payload):
        _invalid(D1ErrorCode.digest_mismatch)

    collections = {name: usage[name] for name in ("summaries", "invocations", "turns", "prices", "globals")}
    for name, values in collections.items():
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            _invalid(D1ErrorCode.invalid_request)
        if len(values) != counts[name]:
            _invalid(D1ErrorCode.count_mismatch)
        if name == "summaries" and not values:
            _invalid(D1ErrorCode.count_mismatch)

    summaries = collections["summaries"]
    invocations = collections["invocations"]
    turns = collections["turns"]
    prices = collections["prices"]
    globals_ = collections["globals"]

    summary_ids: set[str] = set()
    summary_rows: list[Mapping[str, Any]] = []
    for item in summaries:
        row = _mapping(item)
        _keys(row, _SUMMARY)
        summary_id = _id(row["summaryId"])
        if summary_id in summary_ids:
            _invalid(D1ErrorCode.generation_conflict)
        summary_ids.add(summary_id)
        if _id(row["usageGenerationId"]) != usage_generation_id or _id(row["publicationId"]) != publication_id or _id(row["taskId"]) != task_id:
            _invalid(D1ErrorCode.generation_conflict)
        if row["scope"] not in {"task", "run"}:
            _invalid(D1ErrorCode.generation_conflict)
        if row["scope"] == "task":
            if row["runId"] is not None:
                _invalid(D1ErrorCode.generation_conflict)
        elif row["runId"] is None or _id(row["runId"]) not in run_ids:
            _invalid(D1ErrorCode.generation_conflict)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(D1ErrorCode.generation_conflict)
        covered = _usage_integer(row["coveredInvocations"], allow_none=False)
        expected = _usage_integer(row["expectedInvocations"], allow_none=False)
        if covered > expected:
            _invalid(D1ErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "complete" and covered != expected:
            _invalid(D1ErrorCode.generation_conflict)
        if row["coverage"] == "unavailable" and (row["knownTokenSubtotal"] is not None or row["knownCostSubtotalMicroUsd"] is not None):
            _invalid(D1ErrorCode.generation_conflict)
        if row["knownTokenSubtotal"] is not None:
            _usage_integer(row["knownTokenSubtotal"])
        if row["knownCostSubtotalMicroUsd"] is not None:
            _usage_integer(row["knownCostSubtotalMicroUsd"])
        if row["priceProvenanceDigest"] is not None:
            _digest(row["priceProvenanceDigest"])
        if row["totalTokens"] is not None and row["knownTokenSubtotal"] is not None and row["totalTokens"] != row["knownTokenSubtotal"]:
            _invalid(D1ErrorCode.generation_conflict)
        if row["totalCostMicroUsd"] is not None and row["knownCostSubtotalMicroUsd"] is not None and row["totalCostMicroUsd"] != row["knownCostSubtotalMicroUsd"]:
            _invalid(D1ErrorCode.generation_conflict)
        summary_rows.append(row)

    invocation_ids: set[str] = set()
    invocation_by_id: dict[str, Mapping[str, Any]] = {}
    ordinal_groups: dict[tuple[str, str], list[int]] = {}
    invocation_rows: list[Mapping[str, Any]] = []
    for item in invocations:
        row = _mapping(item)
        _keys(row, _INVOCATION)
        invocation_id = row["invocationId"]
        if invocation_id is not None:
            invocation_id = _id(invocation_id)
            if invocation_id in invocation_ids:
                _invalid(D1ErrorCode.generation_conflict)
            invocation_ids.add(invocation_id)
            invocation_by_id[invocation_id] = row
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(D1ErrorCode.generation_conflict)
        ownership = row["ownershipClass"]
        if ownership == "task-owned":
            if _id(row["publicationId"]) != publication_id or _id(row["taskId"]) != task_id or _id(row["pipelineId"]) not in pipeline_ids or _id(row["runId"]) not in run_ids:
                _invalid(D1ErrorCode.generation_conflict)
            group = (row["runId"], ownership)
        elif ownership == "steward-overhead":
            if any(row[field] is not None for field in ("publicationId", "taskId", "pipelineId", "runId")) or row["coveredTurns"] != 0 or row["expectedTurns"] != 0:
                _invalid(D1ErrorCode.generation_conflict)
            group = ("overhead", ownership)
        else:
            _invalid(D1ErrorCode.generation_conflict)
        ordinal = _usage_integer(row["retryOrdinal"], allow_none=False)
        ordinal_groups.setdefault(group, []).append(ordinal)
        started_at = row["startedAt"]
        completed_at = row["completedAt"]
        if (started_at is None) != (completed_at is None):
            _invalid(D1ErrorCode.generation_conflict)
        if started_at is not None:
            _timestamp(started_at)
            _timestamp(completed_at)
            if datetime.fromisoformat(completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(started_at.replace("Z", "+00:00")):
                _invalid(D1ErrorCode.generation_conflict)
        if row["model"] is not None:
            _text(row["model"], maximum=256)
        if row["billingMode"] not in {None, "unknown", "chatgpt", "api"}:
            _invalid(D1ErrorCode.generation_conflict)
        if row["processOutcome"] is not None:
            _text(row["processOutcome"], maximum=48)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(D1ErrorCode.generation_conflict)
        _usage_integer(row["issueCount"], allow_none=False)
        covered_turns = _usage_integer(row["coveredTurns"], allow_none=False, maximum=4096)
        expected_turns = _usage_integer(row["expectedTurns"], allow_none=False, maximum=4096)
        if covered_turns > expected_turns or (row["coverage"] == "complete" and covered_turns != expected_turns):
            _invalid(D1ErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "unavailable" and any(row[field] is not None for field in _USAGE_FIELDS):
            _invalid(D1ErrorCode.generation_conflict)
        costs_known = all(row[field] is not None for field in _COST_FIELDS)
        if costs_known != (row["priceEntryDigest"] is not None):
            _invalid(D1ErrorCode.generation_conflict)
        if row["priceEntryDigest"] is not None:
            _digest(row["priceEntryDigest"])
        if invocation_id is None and row["coverage"] != "unavailable":
            _invalid(D1ErrorCode.generation_conflict)
        invocation_rows.append(row)
    for ordinals in ordinal_groups.values():
        if sorted(ordinals) != list(range(len(ordinals))):
            _invalid(D1ErrorCode.generation_conflict)

    price_map: dict[str, Mapping[str, Any]] = {}
    intervals: dict[str, list[tuple[datetime, datetime | None]]] = {}
    for item in prices:
        row = _mapping(item)
        _keys(row, _PRICE)
        digest = _digest(row["priceEntryDigest"])
        if digest in price_map:
            _invalid(D1ErrorCode.generation_conflict)
        price_map[digest] = row
        _digest(row["catalogDigest"])
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(D1ErrorCode.generation_conflict)
        _text(row["model"], maximum=256)
        _timestamp(row["effectiveAt"])
        if row["effectiveUntil"] is not None:
            _timestamp(row["effectiveUntil"])
            if datetime.fromisoformat(row["effectiveUntil"].replace("Z", "+00:00")) <= datetime.fromisoformat(row["effectiveAt"].replace("Z", "+00:00")):
                _invalid(D1ErrorCode.generation_conflict)
        start = datetime.fromisoformat(row["effectiveAt"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(row["effectiveUntil"].replace("Z", "+00:00")) if row["effectiveUntil"] is not None else None
        intervals.setdefault(row["model"], []).append((start, end))
    for entries in intervals.values():
        entries.sort(key=lambda item: item[0])
        for previous, current in zip(entries, entries[1:]):
            if previous[1] is None or current[0] < previous[1]:
                _invalid(D1ErrorCode.generation_conflict)

    for row in invocation_rows:
        if row["priceEntryDigest"] is not None:
            price = price_map.get(row["priceEntryDigest"])
            if price is None or row["model"] != price["model"]:
                _invalid(D1ErrorCode.generation_conflict)
            _usage_price_in_range(price, row["startedAt"])

    turn_ids: set[str] = set()
    turns_by_invocation: dict[str, list[Mapping[str, Any]]] = {}
    for item in turns:
        row = _mapping(item)
        _keys(row, _TURN)
        turn_id = _id(row["turnId"])
        if turn_id in turn_ids:
            _invalid(D1ErrorCode.generation_conflict)
        turn_ids.add(turn_id)
        invocation_id = _id(row["invocationId"])
        invocation = invocation_by_id.get(invocation_id)
        if invocation is None or invocation["ownershipClass"] != "task-owned":
            _invalid(D1ErrorCode.generation_conflict)
        if any(_id(row[field]) != invocation[field] for field in ("usageGenerationId", "publicationId", "taskId", "runId")):
            _invalid(D1ErrorCode.generation_conflict)
        ordinal = _usage_integer(row["ordinal"], allow_none=False, maximum=4096)
        for field in _TOKEN_FIELDS:
            _usage_integer(row[field], allow_none=False)
        _usage_math(row)
        costs_known = all(row[field] is not None for field in _COST_FIELDS)
        if costs_known != (row["priceEntryDigest"] is not None):
            _invalid(D1ErrorCode.generation_conflict)
        if row["priceEntryDigest"] is not None:
            _digest(row["priceEntryDigest"])
            price = price_map.get(row["priceEntryDigest"])
            if price is None or invocation["model"] != price["model"]:
                _invalid(D1ErrorCode.generation_conflict)
            _usage_price_in_range(price, invocation["startedAt"])
        turns_by_invocation.setdefault(invocation_id, []).append(row)
    for invocation_id, invocation_turns in turns_by_invocation.items():
        if sorted(turn["ordinal"] for turn in invocation_turns) != list(range(1, len(invocation_turns) + 1)):
            _invalid(D1ErrorCode.generation_conflict)
        invocation = invocation_by_id[invocation_id]
        if invocation["coveredTurns"] != len(invocation_turns):
            _invalid(D1ErrorCode.generation_conflict)
        if invocation["coverage"] == "complete":
            totals = {field: sum(turn[field] for turn in invocation_turns) for field in _USAGE_FIELDS}
            if any(invocation[field] != totals[field] for field in _USAGE_FIELDS):
                _invalid(D1ErrorCode.generation_conflict)
    for invocation in invocation_rows:
        if invocation["invocationId"] is not None and invocation["invocationId"] not in turns_by_invocation and invocation["coveredTurns"] != 0:
            _invalid(D1ErrorCode.generation_conflict)

    verified_globals = _verified_global_rollups(invocation_rows)

    for row in summary_rows:
        selected = [
            invocation
            for invocation in invocation_rows
            if invocation["ownershipClass"] == "task-owned" and (row["scope"] == "task" or invocation["runId"] == row["runId"])
        ]
        # The expected denominator counts represented task-owned rows.  The
        # covered count is detached evidence coverage and may be lower when a
        # represented invocation is unavailable.
        if row["expectedInvocations"] != len(selected):
            _invalid(D1ErrorCode.generation_conflict)
        totals = {field: sum(invocation[field] for invocation in selected if invocation[field] is not None) if any(invocation[field] is not None for invocation in selected) else None for field in _USAGE_FIELDS}
        if row["coverage"] == "complete" or any(row[field] is not None for field in _TOKEN_FIELDS):
            for field in _USAGE_FIELDS:
                if row[field] is not None and row[field] != totals[field]:
                    _invalid(D1ErrorCode.generation_conflict)

    global_keys: set[tuple[object, ...]] = set()
    task_owned_global_keys: set[tuple[object, ...]] = set()
    for item in globals_:
        row = _mapping(item)
        _keys(row, _GLOBAL)
        key = (row["periodKind"], row["periodKey"], row["model"], row["ownershipClass"])
        if key in global_keys:
            _invalid(D1ErrorCode.generation_conflict)
        global_keys.add(key)
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(D1ErrorCode.generation_conflict)
        if row["periodKind"] == "lifetime" and row["periodKey"] != "lifetime":
            _invalid(D1ErrorCode.generation_conflict)
        if row["periodKind"] == "daily" and (not isinstance(row["periodKey"], str) or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", row["periodKey"]) is None):
            _invalid(D1ErrorCode.generation_conflict)
        if row["periodKind"] not in {"lifetime", "daily"}:
            _invalid(D1ErrorCode.generation_conflict)
        _text(row["model"], maximum=256)
        if row["ownershipClass"] not in {"task-owned", "steward-overhead"}:
            _invalid(D1ErrorCode.generation_conflict)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(D1ErrorCode.generation_conflict)
        covered = _usage_integer(row["coveredInvocations"], allow_none=False)
        expected = _usage_integer(row["expectedInvocations"], allow_none=False)
        if covered > expected or (row["coverage"] == "complete" and covered != expected):
            _invalid(D1ErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "unavailable" and (row["knownTokenSubtotal"] is not None or row["knownCostSubtotalMicroUsd"] is not None):
            _invalid(D1ErrorCode.generation_conflict)
        if row["knownTokenSubtotal"] is not None:
            _usage_integer(row["knownTokenSubtotal"])
        if row["knownCostSubtotalMicroUsd"] is not None:
            _usage_integer(row["knownCostSubtotalMicroUsd"])
        if row["totalTokens"] is not None and row["knownTokenSubtotal"] is not None and row["totalTokens"] != row["knownTokenSubtotal"]:
            _invalid(D1ErrorCode.generation_conflict)
        if row["totalCostMicroUsd"] is not None and row["knownCostSubtotalMicroUsd"] is not None and row["totalCostMicroUsd"] != row["knownCostSubtotalMicroUsd"]:
            _invalid(D1ErrorCode.generation_conflict)
        if row["ownershipClass"] == "steward-overhead" and row["aggregateOnly"] is not True:
            _invalid(D1ErrorCode.generation_conflict)
        if row["ownershipClass"] == "task-owned" and row["aggregateOnly"] is not True:
            _invalid(D1ErrorCode.generation_conflict)
        if row["ownershipClass"] == "task-owned":
            task_owned_global_keys.add(key)
        _bool(row["aggregateOnly"])
        if row["priceProvenanceDigest"] is not None:
            _digest(row["priceProvenanceDigest"])
        if row["ownershipClass"] == "task-owned":
            key = (row["periodKind"], row["periodKey"], row["model"], row["ownershipClass"])
            expected = verified_globals.get(key)
            if expected is not None:
                if any(
                    row[field] != expected[field]
                    and not (
                        field == "coverage"
                        and {row[field], expected[field]} == {"partial", "complete"}
                    )
                    for field in _GLOBAL_VALUE_FIELDS
                ):
                    _invalid(D1ErrorCode.generation_conflict)
            elif row["coverage"] != "unavailable" or any(row[field] is not None for field in _USAGE_FIELDS):
                # A numeric task-owned aggregate without a matching, verified
                # invocation would otherwise bypass the rollup boundary.
                _invalid(D1ErrorCode.generation_conflict)

    # Every derived task-owned lifetime/daily key must be represented.  The
    # unavailable-only case has no model/date evidence from which to derive a
    # key, so its explicitly unavailable rows remain valid without inventing
    # zero-valued evidence.
    if verified_globals and task_owned_global_keys != set(verified_globals):
        _invalid(D1ErrorCode.generation_conflict)


def _validate_payload(source: Mapping[str, Any], *, allow_usage_replacement: bool = False) -> dict[str, Any]:
    payload = _mapping(source)
    _keys(payload, _TOP_LEVEL)
    _safe_value(payload)
    if payload["schemaVersion"] != "2.0":
        _invalid()
    publication_id = _id(payload["publicationId"])
    task_id = _id(payload["taskId"])

    generation = _mapping(payload["generation"])
    _keys(generation, _GENERATION)
    if _id(generation["publicationId"]) != publication_id or _id(generation["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    generation_run_id = _id(generation["runId"])
    if generation["state"] != "staged":
        _invalid(D1ErrorCode.generation_state)
    _digest(generation["metadataDigest"])
    _id(generation["idempotencyKey"])
    _timestamp(generation["createdAt"])
    counts = _mapping(generation["expectedCounts"])
    _keys(counts, _COUNTS)
    if _integer(counts["tasks"]) != 1:
        _invalid()
    for key in ("pipelines", "runs", "events", "artifacts"):
        _integer(counts[key])

    head = _mapping(payload["headIntent"])
    _keys(head, _HEAD)
    if _id(head["publicationId"]) != publication_id or _id(head["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    if head["state"] not in {"visible", "hidden"}:
        _invalid()
    _timestamp(head["updatedAt"])

    task = _mapping(payload["task"])
    _keys(task, _TASK)
    if _id(task["taskId"]) != task_id:
        _invalid(D1ErrorCode.generation_conflict)
    _text(task["title"], maximum=512)
    if task["lifecycleState"] not in {"active", "completed", "failed", "cancelled"}:
        _invalid()
    _timestamp(task["createdAt"])
    if task["completedAt"] is not None:
        _timestamp(task["completedAt"])

    pipelines = payload["pipelines"]
    runs = payload["runs"]
    events = payload["events"]
    artifacts = payload["artifacts"]
    for values in (pipelines, runs, events, artifacts):
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
            _invalid()
    if len(pipelines) != counts["pipelines"] or len(runs) != counts["runs"] or len(events) != counts["events"] or len(artifacts) != counts["artifacts"]:
        _invalid(D1ErrorCode.count_mismatch)

    pipeline_ids: set[str] = set()
    for item in pipelines:
        row = _mapping(item)
        _keys(row, _PIPELINE)
        pipeline_id = _id(row["pipelineId"])
        if pipeline_id in pipeline_ids or _id(row["taskId"]) != task_id:
            _invalid(D1ErrorCode.generation_conflict)
        pipeline_ids.add(pipeline_id)
        _text(row["name"], maximum=256)
        _timestamp(row["createdAt"])

    run_ids: set[str] = set()
    atif_artifact_ids: set[str] = set()
    for item in runs:
        row = _mapping(item)
        _keys(row, _RUN)
        run_id = _id(row["runId"])
        if run_id in run_ids or _id(row["taskId"]) != task_id or _id(row["pipelineId"]) not in pipeline_ids:
            _invalid(D1ErrorCode.generation_conflict)
        run_ids.add(run_id)
        _text(row["role"], maximum=128)
        if row["runState"] not in {"completed", "failed", "cancelled"}:
            _invalid()
        _timestamp(row["startedAt"])
        _timestamp(row["completedAt"])
        if datetime.fromisoformat(row["completedAt"].replace("Z", "+00:00")) < datetime.fromisoformat(row["startedAt"].replace("Z", "+00:00")):
            _invalid()
        _integer(row["durationMs"])
        _digest(row["atifDigest"])
        atif_artifact_ids.add(_id(row["atifArtifactId"]))

    sequences: set[int] = set()
    for item in events:
        row = _mapping(item)
        _keys(row, _EVENT)
        if _id(row["taskId"]) != task_id:
            _invalid(D1ErrorCode.generation_conflict)
        sequence = _integer(row["sequence"], minimum=1)
        if sequence in sequences:
            _invalid(D1ErrorCode.generation_conflict)
        sequences.add(sequence)
        _text(row["eventType"], maximum=128)
        _timestamp(row["occurredAt"])
        _text(row["summary"], maximum=4096, allow_empty=True)

    artifact_ids: set[str] = set()
    logical_paths: set[str] = set()
    for item in artifacts:
        row = _mapping(item)
        _keys(row, _ARTIFACT)
        artifact_id = _id(row["artifactId"])
        logical_path = _text(row["logicalPath"], maximum=1024)
        if _PATH.fullmatch(logical_path) is None:
            _invalid()
        if artifact_id in artifact_ids or logical_path in logical_paths:
            _invalid(D1ErrorCode.generation_conflict)
        artifact_ids.add(artifact_id)
        logical_paths.add(logical_path)
        if _id(row["taskId"]) != task_id or _id(row["runId"]) not in run_ids:
            _invalid(D1ErrorCode.generation_conflict)
        public_key = _text(row["publicKey"], maximum=256)
        key_match = _PUBLIC_KEY.fullmatch(public_key)
        if key_match is None or key_match.group(1) != task_id or key_match.group(2) != key_match.group(3)[:2]:
            _invalid(D1ErrorCode.private_value if _PRIVATE_LOCATOR.search(public_key) else D1ErrorCode.invalid_request)
        _text(row["mediaType"], maximum=128)
        if _MEDIA.fullmatch(row["mediaType"]) is None:
            _invalid()
        _integer(row["byteSize"])
        _digest(row["sha256"])
        if key_match.group(3) != row["sha256"]:
            _invalid(D1ErrorCode.digest_mismatch)
        if row["availability"] not in {"available", "unavailable"}:
            _invalid()
        disclosure = _mapping(row["disclosure"])
        _keys(disclosure, _DISCLOSURE)
        _bool(disclosure["redactionApplied"])
        _bool(disclosure["originalRetained"])

    artifact_by_id = {item["artifactId"]: item for item in artifacts}
    for item in runs:
        atif = artifact_by_id.get(item["atifArtifactId"])
        if atif is None or atif["runId"] != item["runId"] or atif["sha256"] != item["atifDigest"]:
            _invalid(D1ErrorCode.digest_mismatch)
    if not atif_artifact_ids.issubset(artifact_ids):
        _invalid(D1ErrorCode.generation_conflict)
    if generation_run_id not in run_ids:
        _invalid(D1ErrorCode.generation_conflict)
    _validate_usage(payload, pipeline_ids, run_ids)
    if not allow_usage_replacement and generation["metadataDigest"] != _metadata_digest(payload):
        _invalid(D1ErrorCode.digest_mismatch)
    # Keep the returned object detached from mutable caller containers.
    return json.loads(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _statement(sql: str, *params: Scalar) -> Statement:
    if len(params) > MAX_BATCH_PARAMETERS:
        _invalid()
    return sql, tuple(params)


_GENERATION_INSERT = (
    "INSERT INTO publication_generations "
    "(publication_id, task_id, run_id, metadata_digest, idempotency_key, state, "
    "expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, "
    "expected_artifact_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(publication_id) DO NOTHING"
)
_USAGE_GENERATION_INSERT = (
    "INSERT INTO usage_generations "
    "(usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, "
    "expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, "
    "expected_global_count, created_at) VALUES (?, ?, ?, 'task-owned', ?, ?, 'staged', ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(usage_generation_id) DO NOTHING"
)
_TASK_INSERT = (
    "INSERT INTO tasks (publication_id, task_id, title, lifecycle_state, created_at, completed_at) "
    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, task_id) DO NOTHING"
)
_PIPELINE_INSERT = (
    "INSERT INTO pipelines (publication_id, pipeline_id, task_id, name, created_at) "
    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(publication_id, pipeline_id) DO NOTHING"
)
_RUN_INSERT = (
    "INSERT INTO runs (publication_id, run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, run_id) DO NOTHING"
)
_EVENT_INSERT = (
    "INSERT INTO task_events (publication_id, task_id, sequence, event_type, occurred_at, summary) "
    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, task_id, sequence) DO NOTHING"
)
_ARTIFACT_INSERT = (
    "INSERT INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(publication_id, artifact_id) DO NOTHING"
)
_USAGE_PRICE_INSERT = (
    "INSERT INTO usage_prices "
    "(price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until) "
    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(price_entry_digest) DO NOTHING"
)
_USAGE_SUMMARY_INSERT = (
    "INSERT INTO usage_summaries "
    "(summary_id, usage_generation_id, publication_id, task_id, run_id, scope, coverage, "
    "covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(summary_id) DO NOTHING"
)
_USAGE_INVOCATION_INSERT = (
    "INSERT INTO usage_invocations "
    "(invocation_id, usage_generation_id, publication_id, task_id, pipeline_id, run_id, ownership_class, "
    "retry_ordinal, started_at, completed_at, model, billing_mode, process_outcome, coverage, issue_count, "
    "covered_turns, expected_turns, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, "
    "reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, "
    "output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(invocation_id) DO NOTHING"
)
_USAGE_TURN_INSERT = (
    "INSERT INTO usage_turns "
    "(turn_id, usage_generation_id, invocation_id, publication_id, task_id, run_id, ordinal, prompt_tokens, "
    "cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(turn_id) DO NOTHING"
)
_USAGE_GLOBAL_INSERT = (
    "INSERT INTO usage_globals "
    "(global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest, aggregate_only) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(global_id) DO NOTHING"
)
_GENERATION_SELECT = (
    "SELECT task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, "
    "expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at "
    "FROM publication_generations WHERE publication_id = ? AND task_id = ?"
)
_USAGE_GENERATION_SELECT = (
    "SELECT usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, "
    "expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, "
    "expected_global_count, created_at FROM usage_generations "
    "WHERE usage_generation_id = ? AND publication_id = ? AND task_id = ?"
)
_USAGE_GENERATION_ID_SELECT = "SELECT usage_generation_id, publication_id, task_id FROM usage_generations WHERE usage_generation_id = ?"
_GENERATION_RUN_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND run_id = ?"
_GENERATION_KEY_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND idempotency_key = ?"
_VERIFY_COUNTS = (
    "SELECT p.state, p.metadata_digest, p.expected_task_count, p.expected_pipeline_count, "
    "p.expected_run_count, p.expected_event_count, p.expected_artifact_count, "
    "(SELECT count(*) FROM tasks WHERE publication_id = p.publication_id) AS task_count, "
    "(SELECT count(*) FROM pipelines WHERE publication_id = p.publication_id) AS pipeline_count, "
    "(SELECT count(*) FROM runs WHERE publication_id = p.publication_id) AS run_count, "
    "(SELECT count(*) FROM task_events WHERE publication_id = p.publication_id) AS event_count, "
    "(SELECT count(*) FROM artifacts WHERE publication_id = p.publication_id) AS artifact_count "
    "FROM publication_generations AS p WHERE p.publication_id = ? AND p.task_id = ?"
)
_VERIFY_USAGE_COUNTS = (
    "SELECT u.state, u.ownership_class, u.metadata_digest, u.expected_summary_count, u.expected_invocation_count, "
    "u.expected_turn_count, u.expected_price_count, u.expected_global_count, "
    "(SELECT count(*) FROM usage_summaries WHERE usage_generation_id = u.usage_generation_id) AS summary_count, "
    "(SELECT count(*) FROM usage_invocations WHERE usage_generation_id = u.usage_generation_id) AS invocation_count, "
    "(SELECT count(*) FROM usage_turns WHERE usage_generation_id = u.usage_generation_id) AS turn_count, "
    "(SELECT count(*) FROM usage_prices AS p WHERE p.price_entry_digest IN ("
    "SELECT price_entry_digest FROM usage_invocations WHERE usage_generation_id = u.usage_generation_id AND price_entry_digest IS NOT NULL "
    "UNION SELECT price_entry_digest FROM usage_turns WHERE usage_generation_id = u.usage_generation_id AND price_entry_digest IS NOT NULL "
    "UNION SELECT price_provenance_digest FROM usage_summaries WHERE usage_generation_id = u.usage_generation_id AND price_provenance_digest IS NOT NULL "
    "UNION SELECT price_provenance_digest FROM usage_globals WHERE usage_generation_id = u.usage_generation_id AND price_provenance_digest IS NOT NULL"
    ")) AS price_count, "
    "(SELECT count(*) FROM usage_globals WHERE usage_generation_id = u.usage_generation_id) AS global_count "
    "FROM usage_generations AS u WHERE u.usage_generation_id = ? AND u.publication_id = ? AND u.task_id = ?"
)
_TASK_SELECT = "SELECT task_id, title, lifecycle_state, created_at, completed_at FROM tasks WHERE publication_id = ? ORDER BY task_id"
_PIPELINE_SELECT = "SELECT pipeline_id, task_id, name, created_at FROM pipelines WHERE publication_id = ? ORDER BY pipeline_id"
_RUN_SELECT = "SELECT run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest FROM runs WHERE publication_id = ? ORDER BY run_id"
_EVENT_SELECT = "SELECT task_id, sequence, event_type, occurred_at, summary FROM task_events WHERE publication_id = ? ORDER BY task_id, sequence"
_ARTIFACT_SELECT = "SELECT artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained FROM artifacts WHERE publication_id = ? ORDER BY artifact_id"
_USAGE_SUMMARY_SELECT = "SELECT summary_id, usage_generation_id, publication_id, task_id, run_id, scope, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest FROM usage_summaries WHERE usage_generation_id = ? ORDER BY summary_id"
_USAGE_INVOCATION_SELECT = "SELECT invocation_id, usage_generation_id, publication_id, task_id, pipeline_id, run_id, ownership_class, retry_ordinal, started_at, completed_at, model, billing_mode, process_outcome, coverage, issue_count, covered_turns, expected_turns, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest FROM usage_invocations WHERE usage_generation_id = ? ORDER BY invocation_id"
_USAGE_TURN_SELECT = "SELECT turn_id, usage_generation_id, invocation_id, publication_id, task_id, run_id, ordinal, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest FROM usage_turns WHERE usage_generation_id = ? ORDER BY turn_id"
_USAGE_PRICE_SELECT = (
    "SELECT price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until "
    "FROM usage_prices WHERE price_entry_digest IN ("
    "SELECT price_entry_digest FROM usage_invocations WHERE usage_generation_id = ? AND price_entry_digest IS NOT NULL "
    "UNION SELECT price_entry_digest FROM usage_turns WHERE usage_generation_id = ? AND price_entry_digest IS NOT NULL "
    "UNION SELECT price_provenance_digest FROM usage_summaries WHERE usage_generation_id = ? AND price_provenance_digest IS NOT NULL "
    "UNION SELECT price_provenance_digest FROM usage_globals WHERE usage_generation_id = ? AND price_provenance_digest IS NOT NULL"
    ") ORDER BY price_entry_digest"
)
_PRICE_ENTRY_SELECT = (
    "SELECT price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until "
    "FROM usage_prices WHERE price_entry_digest = ?"
)
_PRICE_PREVIOUS_SELECT = (
    "SELECT price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until "
    "FROM usage_prices WHERE model = ? AND effective_at < ? "
    "ORDER BY effective_at DESC, price_entry_digest DESC LIMIT 1"
)
_PRICE_NEXT_SELECT = (
    "SELECT price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until "
    "FROM usage_prices WHERE model = ? AND effective_at >= ? "
    "ORDER BY effective_at, price_entry_digest LIMIT 2"
)
_USAGE_GLOBAL_SELECT = "SELECT global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only FROM usage_globals WHERE usage_generation_id = ? ORDER BY global_id"
_HEAD_SELECT = "SELECT publication_id, usage_generation_id, state, updated_at FROM task_heads WHERE task_id = ?"
_VISIBLE_TASK_GLOBAL_SELECT = (
    "SELECT g.global_id, g.usage_generation_id, g.period_kind, g.period_key, g.model, g.ownership_class, g.coverage, "
    "g.covered_invocations, g.expected_invocations, g.known_token_subtotal, g.known_cost_subtotal_micro_usd, "
    "g.prompt_tokens, g.cached_tokens, g.uncached_tokens, g.completion_tokens, g.reasoning_tokens, g.total_tokens, "
    "g.uncached_input_cost_micro_usd, g.cached_input_cost_micro_usd, g.output_cost_micro_usd, "
    "g.total_cost_micro_usd, g.price_provenance_digest, g.aggregate_only "
    "FROM usage_globals AS g JOIN usage_generations AS generation "
    "ON generation.usage_generation_id = g.usage_generation_id "
    "WHERE generation.ownership_class = 'task-owned' AND generation.state = 'visible' "
    "AND generation.task_id <> ?"
)
_GLOBAL_HEAD_KEY_SELECT = (
    "SELECT h.period_kind, h.period_key, h.model, h.ownership_class, h.usage_generation_id, h.global_id, h.state, "
    "g.coverage, g.covered_invocations, g.expected_invocations, g.known_token_subtotal, "
    "g.known_cost_subtotal_micro_usd, g.prompt_tokens, g.cached_tokens, g.uncached_tokens, "
    "g.completion_tokens, g.reasoning_tokens, g.total_tokens, g.uncached_input_cost_micro_usd, "
    "g.cached_input_cost_micro_usd, g.output_cost_micro_usd, g.total_cost_micro_usd, "
    "g.price_provenance_digest, g.aggregate_only "
    "FROM usage_global_heads AS h JOIN usage_globals AS g ON g.global_id = h.global_id "
    "WHERE h.period_kind = ? AND h.period_key = ? AND h.model = ? AND h.ownership_class = ? "
    "AND h.state = 'visible'"
)
_GLOBAL_UPDATE = (
    "UPDATE usage_globals SET coverage = ?, covered_invocations = ?, expected_invocations = ?, "
    "known_token_subtotal = ?, known_cost_subtotal_micro_usd = ?, prompt_tokens = ?, cached_tokens = ?, "
    "uncached_tokens = ?, completion_tokens = ?, reasoning_tokens = ?, total_tokens = ?, "
    "uncached_input_cost_micro_usd = ?, cached_input_cost_micro_usd = ?, output_cost_micro_usd = ?, "
    "total_cost_micro_usd = ?, price_provenance_digest = ?, aggregate_only = ? "
    "WHERE global_id = ?"
)
# The global transition is deliberately expressed as two set operations.  The
# first materializes one aggregate row per incoming key from all surviving
# task-owned contributions; the second switches all matching heads in one
# INSERT ... SELECT.  Aggregate rows have no usage-generation ownership so the
# validated contribution rows stay immutable and exact-replayable.
_GLOBAL_TRANSITION_UPDATE = (
    "WITH transition_context AS ("
    "SELECT ? AS old_usage_id, ? AS old_usage_missing, ? AS task_id"
    "), new_rows AS ("
    "SELECT period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, prompt_tokens, cached_tokens, "
    "uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, "
    "output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, global_id "
    "FROM usage_globals WHERE usage_generation_id = ? AND ownership_class = 'task-owned'"
    "), contributions AS ("
    "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, g.coverage, "
    "g.covered_invocations, g.expected_invocations, g.prompt_tokens, g.cached_tokens, "
    "g.uncached_tokens, g.completion_tokens, g.reasoning_tokens, g.total_tokens, "
    "g.uncached_input_cost_micro_usd, g.cached_input_cost_micro_usd, "
    "g.output_cost_micro_usd, g.total_cost_micro_usd, g.price_provenance_digest "
    "FROM usage_globals AS g "
    "JOIN usage_generations AS generation ON generation.usage_generation_id = g.usage_generation_id "
    "WHERE generation.ownership_class = 'task-owned' AND generation.state = 'visible' "
    "UNION ALL "
    "SELECT period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, prompt_tokens, cached_tokens, "
    "uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, "
    "output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest "
    "FROM new_rows"
    "), grouped AS ("
    "SELECT period_kind, period_key, model, ownership_class, "
    "CASE WHEN SUM(CASE WHEN coverage = 'unavailable' THEN 1 ELSE 0 END) > 0 "
    "THEN 'unavailable' "
    "WHEN SUM(CASE WHEN coverage = 'complete' THEN 1 ELSE 0 END) = COUNT(*) "
    "THEN 'complete' ELSE 'partial' END AS coverage, "
    "SUM(covered_invocations) AS covered_invocations, "
    "SUM(expected_invocations) AS expected_invocations, "
    "CASE WHEN COUNT(prompt_tokens) = COUNT(*) THEN SUM(prompt_tokens) END AS prompt_tokens, "
    "CASE WHEN COUNT(cached_tokens) = COUNT(*) THEN SUM(cached_tokens) END AS cached_tokens, "
    "CASE WHEN COUNT(uncached_tokens) = COUNT(*) THEN SUM(uncached_tokens) END AS uncached_tokens, "
    "CASE WHEN COUNT(completion_tokens) = COUNT(*) THEN SUM(completion_tokens) END AS completion_tokens, "
    "CASE WHEN COUNT(reasoning_tokens) = COUNT(*) THEN SUM(reasoning_tokens) END AS reasoning_tokens, "
    "CASE WHEN COUNT(total_tokens) = COUNT(*) THEN SUM(total_tokens) END AS total_tokens, "
    "CASE WHEN COUNT(uncached_input_cost_micro_usd) = COUNT(*) THEN SUM(uncached_input_cost_micro_usd) END AS uncached_input_cost_micro_usd, "
    "CASE WHEN COUNT(cached_input_cost_micro_usd) = COUNT(*) THEN SUM(cached_input_cost_micro_usd) END AS cached_input_cost_micro_usd, "
    "CASE WHEN COUNT(output_cost_micro_usd) = COUNT(*) THEN SUM(output_cost_micro_usd) END AS output_cost_micro_usd, "
    "CASE WHEN COUNT(total_cost_micro_usd) = COUNT(*) THEN SUM(total_cost_micro_usd) END AS total_cost_micro_usd, "
    "CASE WHEN COUNT(DISTINCT price_provenance_digest) = 1 THEN MIN(price_provenance_digest) END AS price_provenance_digest "
    "FROM contributions GROUP BY period_kind, period_key, model, ownership_class"
    "), calculated AS ("
    "SELECT ? || ':' || new.global_id AS global_id, grouped.* "
    "FROM grouped JOIN new_rows AS new ON new.period_kind = grouped.period_kind "
    "AND new.period_key = grouped.period_key AND new.model = grouped.model "
    "AND new.ownership_class = grouped.ownership_class "
    "CROSS JOIN transition_context AS context "
    "WHERE ("
    "(context.old_usage_missing = 1 AND NOT EXISTS ("
    "SELECT 1 FROM task_heads AS current_task "
    "WHERE current_task.task_id = context.task_id AND current_task.state = 'visible'"
    ")) OR (context.old_usage_missing = 0 AND EXISTS ("
    "SELECT 1 FROM task_heads AS current_task "
    "JOIN usage_heads AS current_usage ON current_usage.task_id = current_task.task_id "
    "AND current_usage.usage_generation_id = current_task.usage_generation_id "
    "AND current_usage.state = 'visible' "
    "WHERE current_task.task_id = context.task_id "
    "AND current_task.usage_generation_id = context.old_usage_id "
    "AND current_task.state = 'visible'"
    "))"
    ")"
    ") INSERT INTO usage_globals ("
    "global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest, aggregate_only) "
    "SELECT global_id, NULL, period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, total_tokens, total_cost_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest, 1 FROM calculated"
)
_GLOBAL_HEAD_UPSERT_SET = (
    "INSERT INTO usage_global_heads "
    "(period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) "
    "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, ?, g.global_id, 'visible', ? "
    "FROM usage_globals AS g WHERE g.usage_generation_id IS NULL AND instr(g.global_id, ?) = 1 "
    "ON CONFLICT(period_kind, period_key, model, ownership_class) DO UPDATE SET "
    "usage_generation_id = excluded.usage_generation_id, global_id = excluded.global_id, "
    "state = 'visible', updated_at = excluded.updated_at"
)
_GLOBAL_HEAD_UPSERT_SET_GUARDED = (
    "INSERT INTO usage_global_heads "
    "(period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) "
    "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, ?, g.global_id, 'visible', ? "
    "FROM usage_globals AS g "
    "JOIN task_heads AS t ON t.task_id = ? AND t.usage_generation_id = ? AND t.state = 'visible' "
    "JOIN usage_heads AS h ON h.task_id = t.task_id AND h.usage_generation_id = t.usage_generation_id "
    "AND h.state = 'visible' "
    "WHERE g.usage_generation_id IS NULL AND instr(g.global_id, ?) = 1 "
    "ON CONFLICT(period_kind, period_key, model, ownership_class) DO UPDATE SET "
    "usage_generation_id = excluded.usage_generation_id, global_id = excluded.global_id, "
    "state = 'visible', updated_at = excluded.updated_at"
)
_GLOBAL_HEAD_UPSERT = (
    "INSERT INTO usage_global_heads "
    "(period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) "
    "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, ?, g.global_id, 'visible', ? "
    "FROM usage_globals AS g WHERE g.global_id = ? "
    "AND (g.usage_generation_id = ? OR g.usage_generation_id IS NULL) "
    "ON CONFLICT(period_kind, period_key, model, ownership_class) DO UPDATE SET "
    "usage_generation_id = excluded.usage_generation_id, global_id = excluded.global_id, "
    "state = 'visible', updated_at = excluded.updated_at"
)
_GLOBAL_HEAD_HIDE = (
    "UPDATE usage_global_heads SET state = 'hidden', updated_at = ? "
    "WHERE period_kind = ? AND period_key = ? AND model = ? AND ownership_class = ? "
    "AND usage_generation_id = ? AND global_id = ? AND state = 'visible'"
)
_VISIBLE_GENERATION_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, publication_id DESC LIMIT 1"
_VISIBLE_USAGE_GENERATION_SELECT = "SELECT usage_generation_id FROM usage_generations WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, usage_generation_id DESC LIMIT 1"
_EXPOSE_OLD = (
    "UPDATE publication_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' AND publication_id <> ? "
    "AND EXISTS (SELECT 1 FROM publication_generations "
    "WHERE publication_id = ? AND task_id = ? AND state IN ('staged', 'visible'))"
)
_EXPOSE_NEW = "UPDATE publication_generations SET state = 'visible', exposed_at = ? WHERE publication_id = ? AND task_id = ? AND state = 'staged'"
_EXPOSE_OLD_USAGE = (
    "UPDATE usage_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' AND usage_generation_id <> ? "
    "AND EXISTS (SELECT 1 FROM usage_generations WHERE usage_generation_id = ? AND task_id = ? AND state IN ('staged', 'visible'))"
)
_EXPOSE_NEW_USAGE = "UPDATE usage_generations SET state = 'visible', exposed_at = ? WHERE usage_generation_id = ? AND task_id = ? AND state = 'staged'"
_HEAD_UPSERT = (
    "INSERT INTO task_heads (task_id, publication_id, usage_generation_id, state, updated_at) "
    "SELECT task_id, publication_id, ?, 'visible', ? FROM publication_generations "
    "WHERE publication_id = ? AND task_id = ? AND state = 'visible' "
    "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, usage_generation_id = excluded.usage_generation_id, state = 'visible', updated_at = excluded.updated_at"
)
_USAGE_HEAD_UPSERT = (
    "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) VALUES (?, ?, 'visible', ?) "
    "ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, state = 'visible', updated_at = excluded.updated_at"
)
_HIDE_UPSERT = (
    "INSERT INTO task_heads (task_id, publication_id, usage_generation_id, state, updated_at) "
    "SELECT p.task_id, p.publication_id, u.usage_generation_id, 'hidden', ? FROM publication_generations AS p "
    "JOIN usage_generations AS u ON u.publication_id = p.publication_id AND u.task_id = p.task_id AND u.state = 'visible' "
    "WHERE p.task_id = ? AND p.state = 'visible' ORDER BY p.exposed_at DESC, p.publication_id DESC LIMIT 1 "
    "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, state = 'hidden', usage_generation_id = excluded.usage_generation_id, updated_at = excluded.updated_at"
)
_USAGE_HIDE_UPSERT = (
    "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) "
    "SELECT task_id, usage_generation_id, 'hidden', ? FROM usage_generations "
    "WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, usage_generation_id DESC LIMIT 1 "
    "ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, state = 'hidden', updated_at = excluded.updated_at"
)
_HIDE_STAGED = "UPDATE publication_generations SET state = 'superseded' WHERE task_id = ? AND state = 'staged'"
_HIDE_USAGE_STAGED = "UPDATE usage_generations SET state = 'superseded' WHERE task_id = ? AND state = 'staged'"
_HIDE_USAGE_GENERATION = (
    "UPDATE usage_generations SET state = 'superseded' "
    "WHERE usage_generation_id = ? AND task_id = ? AND state = 'visible'"
)
_HIDE_RACED_VISIBLE_WITH_HEAD = (
    "UPDATE publication_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' "
    "AND NOT EXISTS (SELECT 1 FROM task_heads "
    "WHERE task_id = ? AND state = 'visible' AND publication_id = ?)"
)
_HIDE_RACED_VISIBLE_WITHOUT_HEAD = (
    "UPDATE publication_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' "
    "AND EXISTS (SELECT 1 FROM task_heads WHERE task_id = ? AND state = 'visible')"
)
_HIDE_USAGE_RACED_VISIBLE_WITH_HEAD = (
    "UPDATE usage_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' "
    "AND NOT EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND state = 'visible' AND usage_generation_id = ?)"
)
_HIDE_USAGE_RACED_VISIBLE_WITHOUT_HEAD = (
    "UPDATE usage_generations SET state = 'superseded' "
    "WHERE task_id = ? AND state = 'visible' "
    "AND EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND state = 'visible')"
)
_HIDE_HEAD = "UPDATE task_heads SET state = 'hidden', updated_at = ? WHERE task_id = ? AND state = 'visible'"
_HIDE_USAGE_HEAD = "UPDATE usage_heads SET state = 'hidden', updated_at = ? WHERE task_id = ? AND state = 'visible'"
_VISIBLE_HEAD_SELECT = "SELECT publication_id, usage_generation_id, state FROM task_heads WHERE task_id = ?"
_USAGE_HEAD_SELECT = "SELECT usage_generation_id, state FROM usage_heads WHERE task_id = ?"
_USAGE_SWAP_OLD = (
    "UPDATE usage_generations SET state = 'superseded' WHERE usage_generation_id = ? AND task_id = ? AND state = 'visible' "
    "AND EXISTS (SELECT 1 FROM task_heads WHERE task_id = ? AND publication_id = ? "
    "AND usage_generation_id = ? AND state = 'visible') "
    "AND EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND usage_generation_id = ? AND state = 'visible')"
)
_USAGE_SWAP_NEW = (
    "UPDATE usage_generations SET state = 'visible', exposed_at = ? "
    "WHERE usage_generation_id = ? AND task_id = ? AND state = 'staged' "
    "AND EXISTS (SELECT 1 FROM task_heads WHERE task_id = ? AND publication_id = ? "
    "AND usage_generation_id = ? AND state = 'visible') "
    "AND EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND usage_generation_id = ? AND state = 'visible')"
)
_USAGE_SWAP_HEAD = (
    "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) "
    "SELECT task_id, ?, 'visible', ? FROM task_heads WHERE task_id = ? AND publication_id = ? "
    "AND usage_generation_id = ? AND state = 'visible' "
    "AND EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND usage_generation_id = ? AND state = 'visible') "
    "ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, "
    "state = 'visible', updated_at = excluded.updated_at "
    "WHERE usage_heads.state = 'visible' AND usage_heads.usage_generation_id = ?"
)
_TASK_USAGE_SWAP = (
    "UPDATE task_heads SET usage_generation_id = ?, updated_at = ? WHERE task_id = ? "
    "AND publication_id = ? AND usage_generation_id = ? AND state = 'visible' "
    "AND EXISTS (SELECT 1 FROM usage_heads WHERE task_id = ? AND usage_generation_id = ? AND state = 'visible')"
)
_STAGED_GENERATION_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND state = 'staged'"
_STAGED_USAGE_GENERATION_SELECT = "SELECT usage_generation_id FROM usage_generations WHERE task_id = ? AND state = 'staged'"

# Overhead has an independently owned generation with no task/publication
# identity.  Its one global is exposed through the shared global-head table,
# never through task or usage heads.
_OVERHEAD_GENERATION_INSERT = (
    "INSERT INTO usage_generations "
    "(usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, "
    "expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, "
    "expected_global_count, created_at) VALUES (?, NULL, NULL, 'steward-overhead', '1.0', ?, 'staged', 0, 0, 0, 0, 1, ?) "
    "ON CONFLICT(usage_generation_id) DO NOTHING"
)
_OVERHEAD_GENERATION_SELECT = (
    "SELECT usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, "
    "expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at, "
    "(SELECT count(*) FROM usage_summaries WHERE usage_generation_id = g.usage_generation_id) AS summary_count, "
    "(SELECT count(*) FROM usage_invocations WHERE usage_generation_id = g.usage_generation_id) AS invocation_count, "
    "(SELECT count(*) FROM usage_turns WHERE usage_generation_id = g.usage_generation_id) AS turn_count, "
    "(SELECT count(*) FROM usage_prices WHERE usage_generation_id = g.usage_generation_id) AS price_count, "
    "(SELECT count(*) FROM usage_globals WHERE usage_generation_id = g.usage_generation_id) AS global_count "
    "FROM usage_generations AS g WHERE g.usage_generation_id = ?"
)
_OVERHEAD_GLOBAL_SELECT = (
    "SELECT global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest, aggregate_only FROM usage_globals WHERE usage_generation_id = ?"
)
_OVERHEAD_GLOBAL_INSERT = (
    "INSERT INTO usage_globals "
    "(global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, "
    "covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, "
    "prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, "
    "uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, "
    "price_provenance_digest, aggregate_only) VALUES (?, ?, ?, ?, ?, 'steward-overhead', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 1) "
    "ON CONFLICT(global_id) DO NOTHING"
)
_VISIBLE_NA_TURNS_SELECT = (
    "SELECT t.turn_id, t.usage_generation_id, t.invocation_id, t.publication_id, t.task_id, t.run_id, "
    "t.ordinal, t.prompt_tokens, t.cached_tokens, t.uncached_tokens, t.completion_tokens, "
    "t.reasoning_tokens, t.total_tokens, t.uncached_input_cost_micro_usd, t.cached_input_cost_micro_usd, "
    "t.output_cost_micro_usd, t.total_cost_micro_usd, t.price_entry_digest, i.model, i.started_at, "
    "i.billing_mode, i.coverage AS invocation_coverage, h.usage_generation_id AS head_usage_generation_id "
    "FROM usage_turns AS t JOIN usage_invocations AS i ON i.invocation_id = t.invocation_id "
    "JOIN task_heads AS h ON h.task_id = t.task_id AND h.usage_generation_id = t.usage_generation_id "
    "WHERE h.state = 'visible' AND t.usage_generation_id = h.usage_generation_id "
    "AND (t.total_cost_micro_usd IS NULL OR t.uncached_input_cost_micro_usd IS NULL "
    "OR t.cached_input_cost_micro_usd IS NULL OR t.output_cost_micro_usd IS NULL) "
    "AND (t.turn_id > ? OR ? IS NULL) ORDER BY t.turn_id LIMIT ?"
)


def _row_values(row: object) -> Mapping[str, Any]:
    if not isinstance(row, Mapping):
        _invalid(D1ErrorCode.malformed_response)
    return row


class D1PublicationClient:
    """A narrow D1 REST client for one staged publication envelope."""

    def __init__(
        self,
        config: object | None = None,
        database_id: str | None = None,
        token: str | None = None,
        *,
        account_id: str | None = None,
        transport: httpx.BaseTransport | None = None,
        http_client: D1HttpClient | None = None,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        account, database, credential = self._config_values(config, account_id, database_id, token)
        if not isinstance(account, str) or re.fullmatch(r"[0-9a-fA-F]{32}", account) is None:
            _invalid()
        if not isinstance(database, str) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", database) is None:
            _invalid()
        if not isinstance(credential, str) or not 1 <= len(credential.strip()) <= MAX_TOKEN_LENGTH or any(ord(char) <= 0x20 for char in credential):
            _invalid()
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < float(timeout_seconds) <= MAX_TIMEOUT_SECONDS:
            _invalid()
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 0 < max_response_bytes <= MAX_RESPONSE_BYTES:
            _invalid()
        self.account_id = account.lower()
        self.database_id = database.lower()
        self._token = credential
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self._owned_client = http_client is None
        self._closed = False
        self._client: D1HttpClient = (
            http_client
            if http_client is not None
            else httpx.Client(transport=transport, timeout=self.timeout_seconds)
        )

    @staticmethod
    def _config_values(config: object | None, account_id: str | None, database_id: str | None, token: str | None) -> tuple[object, object, object]:
        if account_id is not None or database_id is not None or token is not None:
            if config is not None:
                _invalid()
            return account_id, database_id, token
        if isinstance(config, Mapping):
            values = config
            credential = values.get("d1_token", values.get("token"))
            if credential is None and values.get("d1_token_path") is not None:
                try:
                    credential = Path(values["d1_token_path"]).read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError):
                    _invalid()
            return (
                values.get("account_id", values.get("cloudflare_account_id")),
                values.get("d1_database_id", values.get("database_id", values.get("cloudflare_database_id"))),
                credential,
            )
        account = getattr(config, "account_id", getattr(config, "cloudflare_account_id", None))
        database = getattr(config, "d1_database_id", getattr(config, "database_id", getattr(config, "cloudflare_database_id", None)))
        credential = getattr(config, "d1_token", getattr(config, "token", None))
        path = getattr(config, "d1_token_path", None)
        if credential is None and path is not None:
            try:
                credential = Path(path).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                _invalid()
        return account, database, credential

    @property
    def endpoint(self) -> str:
        return (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{quote(self.account_id, safe='')}/d1/database/{quote(self.database_id, safe='')}/query"
        )

    def close(self) -> None:
        if self._owned_client and not self._closed:
            self._client.close()
            self._closed = True

    def __enter__(self) -> "D1PublicationClient":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _post(self, statements: Sequence[Statement]) -> list[Mapping[str, Any]]:
        if not statements or len(statements) > MAX_BATCH_STATEMENTS:
            _invalid()
        total_params = sum(len(params) for _, params in statements)
        if total_params > MAX_BATCH_PARAMETERS:
            _invalid()
        body: dict[str, Any]
        if len(statements) == 1:
            sql, params = statements[0]
            body = {"sql": sql, "params": list(params)}
        else:
            body = {"batch": [{"sql": sql, "params": list(params)} for sql, params in statements]}
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > self.max_response_bytes or len(encoded) > MAX_BATCH_BYTES:
            _invalid()
        try:
            response = self._client.post(
                self.endpoint,
                headers={"Accept": "application/json", "Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
                content=encoded,
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException:
            raise D1Error(D1ErrorCode.timeout) from None
        except httpx.HTTPError:
            raise D1Error(D1ErrorCode.network) from None
        except (TimeoutError, OSError):
            raise D1Error(D1ErrorCode.network) from None
        status = int(response.status_code)
        if status in {401, 403}:
            _invalid(D1ErrorCode.authentication)
        if status == 408:
            _invalid(D1ErrorCode.timeout)
        if status in {425, 429, 509}:
            _invalid(D1ErrorCode.quota)
        if status >= 500:
            # HTTP 5xx is the only provider response that is explicitly
            # retryable.  Keep it distinct from successful-HTTP error
            # envelopes, which are permanent provider failures.
            _invalid(D1ErrorCode.network)
        if status < 200 or status >= 300:
            # Authentication, timeout, and quota statuses were classified
            # above.  Other HTTP errors are permanent and must never enter a
            # retry loop.
            _invalid(D1ErrorCode.provider)
        try:
            content_length = response.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > self.max_response_bytes:
                _invalid(D1ErrorCode.response_too_large)
            raw = bytes(response.content)
        except D1Error:
            raise
        except Exception:
            _invalid(D1ErrorCode.malformed_response)
        if len(raw) > self.max_response_bytes:
            _invalid(D1ErrorCode.response_too_large)
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _invalid(D1ErrorCode.malformed_response)
        if not isinstance(document, Mapping):
            _invalid(D1ErrorCode.malformed_response)
        if document.get("success") is False:
            _invalid(D1ErrorCode.provider)
        if document.get("success") is not True or not isinstance(document.get("errors"), list):
            _invalid(D1ErrorCode.malformed_response)
        if document["errors"]:
            _invalid(D1ErrorCode.provider)
        result = document.get("result")
        if not isinstance(result, list) or len(result) != len(statements) or len(result) > MAX_RESULT_SETS:
            _invalid(D1ErrorCode.malformed_response)
        rows: list[Mapping[str, Any]] = []
        for entry in result:
            if not isinstance(entry, Mapping):
                _invalid(D1ErrorCode.malformed_response)
            if "errors" in entry and not isinstance(entry["errors"], list):
                _invalid(D1ErrorCode.malformed_response)
            if entry.get("success") is False or (
                isinstance(entry.get("errors"), list) and entry["errors"]
            ):
                _invalid(D1ErrorCode.provider)
            if entry.get("success") is not True or not isinstance(entry.get("results"), list) or not isinstance(entry.get("meta"), Mapping):
                _invalid(D1ErrorCode.malformed_response)
            for row in entry["results"]:
                rows.append(_row_values(row))
                if len(rows) > MAX_RESULT_ROWS:
                    _invalid(D1ErrorCode.result_limit)
        return [entry for entry in result]  # type: ignore[return-value]

    def _query(self, statement: Statement) -> list[Mapping[str, Any]]:
        result = self._post((statement,))
        entry = result[0]
        return [_row_values(row) for row in entry["results"]]

    def _batch(self, statements: Sequence[Statement]) -> list[Mapping[str, Any]]:
        return self._post(statements)

    @staticmethod
    def _chunks(statements: Sequence[Statement]) -> tuple[tuple[Statement, ...], ...]:
        chunks: list[tuple[Statement, ...]] = []
        current: list[Statement] = []
        params = 0
        for item in statements:
            candidate = current + [item]
            encoded = json.dumps(
                {"batch": [{"sql": sql, "params": list(values)} for sql, values in candidate]},
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            if current and (len(candidate) > MAX_BATCH_STATEMENTS or params + len(item[1]) > MAX_BATCH_PARAMETERS or len(encoded) > MAX_BATCH_BYTES):
                chunks.append(tuple(current))
                current = []
                params = 0
            if len(item[1]) > MAX_BATCH_PARAMETERS:
                _invalid()
            current.append(item)
            params += len(item[1])
        if current:
            chunks.append(tuple(current))
        return tuple(chunks)

    @staticmethod
    def _generation_expected(payload: Mapping[str, Any]) -> tuple[Any, ...]:
        generation = payload["generation"]
        counts = generation["expectedCounts"]
        return (
            payload["taskId"],
            generation["runId"],
            generation["metadataDigest"],
            generation["idempotencyKey"],
            "staged",
            counts["tasks"],
            counts["pipelines"],
            counts["runs"],
            counts["events"],
            counts["artifacts"],
            generation["createdAt"],
        )

    @staticmethod
    def _usage_generation_expected(payload: Mapping[str, Any]) -> tuple[Any, ...]:
        generation = payload["usage"]["generation"]
        counts = generation["expectedCounts"]
        return (
            generation["usageGenerationId"],
            payload["publicationId"],
            payload["taskId"],
            "task-owned",
            generation["schemaVersion"],
            generation["metadataDigest"],
            "staged",
            counts["summaries"],
            counts["invocations"],
            counts["turns"],
            counts["prices"],
            counts["globals"],
            generation["createdAt"],
        )

    def _verify_generation(self, payload: Mapping[str, Any]) -> str:
        rows = self._query(_statement(_GENERATION_SELECT, payload["publicationId"], payload["taskId"]))
        if not rows:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        actual = tuple(row.get(key) for key in ("task_id", "run_id", "metadata_digest", "idempotency_key", "state", "expected_task_count", "expected_pipeline_count", "expected_run_count", "expected_event_count", "expected_artifact_count", "created_at"))
        expected = self._generation_expected(payload)
        if actual[4] == "superseded":
            _invalid(D1ErrorCode.generation_state)
        if actual != expected and not (actual[:4] == expected[:4] and actual[5:] == expected[5:] and actual[4] == "visible"):
            _invalid(D1ErrorCode.generation_conflict)
        if actual[4] not in {"staged", "visible"}:
            _invalid(D1ErrorCode.generation_state)
        return actual[4]

    def _verify_usage_generation(self, payload: Mapping[str, Any], *, allow_superseded: bool = False) -> str:
        generation = payload["usage"]["generation"]
        rows = self._query(
            _statement(
                _USAGE_GENERATION_SELECT,
                generation["usageGenerationId"],
                payload["publicationId"],
                payload["taskId"],
            )
        )
        if not rows:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        actual = tuple(
            row.get(key)
            for key in (
                "usage_generation_id",
                "publication_id",
                "task_id",
                "ownership_class",
                "schema_version",
                "metadata_digest",
                "state",
                "expected_summary_count",
                "expected_invocation_count",
                "expected_turn_count",
                "expected_price_count",
                "expected_global_count",
                "created_at",
            )
        )
        expected = self._usage_generation_expected(payload)
        if actual[6] == "superseded":
            if not allow_superseded or actual[:6] != expected[:6] or actual[7:] != expected[7:]:
                _invalid(D1ErrorCode.generation_state)
            return "superseded"
        if actual != expected and not (actual[:6] == expected[:6] and actual[7:] == expected[7:] and actual[6] == "visible"):
            _invalid(D1ErrorCode.generation_conflict)
        if actual[6] not in {"staged", "visible"}:
            _invalid(D1ErrorCode.generation_state)
        return actual[6]

    def _usage_stage_statements(self, payload: Mapping[str, Any]) -> tuple[Statement, ...]:
        """Build only the bounded rows belonging to a detached usage generation."""

        publication_id = payload["publicationId"]
        task_id = payload["taskId"]
        usage = payload["usage"]
        usage_generation = usage["generation"]
        counts = usage_generation["expectedCounts"]
        statements: list[Statement] = [
            _statement(
                _USAGE_GENERATION_INSERT,
                usage_generation["usageGenerationId"],
                publication_id,
                task_id,
                usage_generation["schemaVersion"],
                usage_generation["metadataDigest"],
                counts["summaries"],
                counts["invocations"],
                counts["turns"],
                counts["prices"],
                counts["globals"],
                usage_generation["createdAt"],
            )
        ]
        for item in usage["prices"]:
            statements.append(
                _statement(
                    _USAGE_PRICE_INSERT,
                    item["priceEntryDigest"],
                    item["usageGenerationId"],
                    item["catalogDigest"],
                    item["model"],
                    item["effectiveAt"],
                    item["effectiveUntil"],
                )
            )
        for item in usage["summaries"]:
            statements.append(
                _statement(
                    _USAGE_SUMMARY_INSERT,
                    item["summaryId"],
                    item["usageGenerationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["runId"],
                    item["scope"],
                    item["coverage"],
                    item["coveredInvocations"],
                    item["expectedInvocations"],
                    item["knownTokenSubtotal"],
                    item["knownCostSubtotalMicroUsd"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceProvenanceDigest"],
                )
            )
        for item in usage["invocations"]:
            statements.append(
                _statement(
                    _USAGE_INVOCATION_INSERT,
                    item["invocationId"],
                    item["usageGenerationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["pipelineId"],
                    item["runId"],
                    item["ownershipClass"],
                    item["retryOrdinal"],
                    item["startedAt"],
                    item["completedAt"],
                    item["model"],
                    item["billingMode"],
                    item["processOutcome"],
                    item["coverage"],
                    item["issueCount"],
                    item["coveredTurns"],
                    item["expectedTurns"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceEntryDigest"],
                )
            )
        for item in usage["turns"]:
            statements.append(
                _statement(
                    _USAGE_TURN_INSERT,
                    item["turnId"],
                    item["usageGenerationId"],
                    item["invocationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["runId"],
                    item["ordinal"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceEntryDigest"],
                )
            )
        for item in usage["globals"]:
            statements.append(
                _statement(
                    _USAGE_GLOBAL_INSERT,
                    item["globalId"],
                    item["usageGenerationId"],
                    item["periodKind"],
                    item["periodKey"],
                    item["model"],
                    item["ownershipClass"],
                    item["coverage"],
                    item["coveredInvocations"],
                    item["expectedInvocations"],
                    item["knownTokenSubtotal"],
                    item["knownCostSubtotalMicroUsd"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceProvenanceDigest"],
                    int(item["aggregateOnly"]),
                )
            )
        return tuple(statements)

    def _stage_statements(self, payload: Mapping[str, Any]) -> tuple[Statement, ...]:
        publication_id = payload["publicationId"]
        generation = payload["generation"]
        counts = generation["expectedCounts"]
        statements: list[Statement] = [
            _statement(
                _GENERATION_INSERT,
                publication_id,
                payload["taskId"],
                generation["runId"],
                generation["metadataDigest"],
                generation["idempotencyKey"],
                counts["tasks"],
                counts["pipelines"],
                counts["runs"],
                counts["events"],
                counts["artifacts"],
                generation["createdAt"],
            )
        ]
        usage = payload["usage"]
        usage_generation = usage["generation"]
        usage_counts = usage_generation["expectedCounts"]
        statements.append(
            _statement(
                _USAGE_GENERATION_INSERT,
                usage_generation["usageGenerationId"],
                publication_id,
                payload["taskId"],
                usage_generation["schemaVersion"],
                usage_generation["metadataDigest"],
                usage_counts["summaries"],
                usage_counts["invocations"],
                usage_counts["turns"],
                usage_counts["prices"],
                usage_counts["globals"],
                usage_generation["createdAt"],
            )
        )
        task = payload["task"]
        statements.append(_statement(_TASK_INSERT, publication_id, task["taskId"], task["title"], task["lifecycleState"], task["createdAt"], task["completedAt"]))
        for item in payload["pipelines"]:
            statements.append(_statement(_PIPELINE_INSERT, publication_id, item["pipelineId"], item["taskId"], item["name"], item["createdAt"]))
        for item in payload["runs"]:
            statements.append(_statement(_RUN_INSERT, publication_id, item["runId"], item["taskId"], item["pipelineId"], item["role"], item["runState"], item["startedAt"], item["completedAt"], item["durationMs"], item["atifDigest"]))
        for item in payload["events"]:
            statements.append(_statement(_EVENT_INSERT, publication_id, item["taskId"], item["sequence"], item["eventType"], item["occurredAt"], item["summary"]))
        for item in payload["artifacts"]:
            disclosure = item["disclosure"]
            statements.append(_statement(_ARTIFACT_INSERT, publication_id, item["artifactId"], item["taskId"], item["runId"], item["logicalPath"], item["publicKey"], item["mediaType"], item["byteSize"], item["sha256"], item["availability"], int(disclosure["redactionApplied"]), int(disclosure["originalRetained"])))
        for item in usage["prices"]:
            statements.append(
                _statement(
                    _USAGE_PRICE_INSERT,
                    item["priceEntryDigest"],
                    item["usageGenerationId"],
                    item["catalogDigest"],
                    item["model"],
                    item["effectiveAt"],
                    item["effectiveUntil"],
                )
            )
        for item in usage["summaries"]:
            statements.append(
                _statement(
                    _USAGE_SUMMARY_INSERT,
                    item["summaryId"],
                    item["usageGenerationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["runId"],
                    item["scope"],
                    item["coverage"],
                    item["coveredInvocations"],
                    item["expectedInvocations"],
                    item["knownTokenSubtotal"],
                    item["knownCostSubtotalMicroUsd"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceProvenanceDigest"],
                )
            )
        for item in usage["invocations"]:
            statements.append(
                _statement(
                    _USAGE_INVOCATION_INSERT,
                    item["invocationId"],
                    item["usageGenerationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["pipelineId"],
                    item["runId"],
                    item["ownershipClass"],
                    item["retryOrdinal"],
                    item["startedAt"],
                    item["completedAt"],
                    item["model"],
                    item["billingMode"],
                    item["processOutcome"],
                    item["coverage"],
                    item["issueCount"],
                    item["coveredTurns"],
                    item["expectedTurns"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceEntryDigest"],
                )
            )
        for item in usage["turns"]:
            statements.append(
                _statement(
                    _USAGE_TURN_INSERT,
                    item["turnId"],
                    item["usageGenerationId"],
                    item["invocationId"],
                    item["publicationId"],
                    item["taskId"],
                    item["runId"],
                    item["ordinal"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceEntryDigest"],
                )
            )
        for item in usage["globals"]:
            statements.append(
                _statement(
                    _USAGE_GLOBAL_INSERT,
                    item["globalId"],
                    item["usageGenerationId"],
                    item["periodKind"],
                    item["periodKey"],
                    item["model"],
                    item["ownershipClass"],
                    item["coverage"],
                    item["coveredInvocations"],
                    item["expectedInvocations"],
                    item["knownTokenSubtotal"],
                    item["knownCostSubtotalMicroUsd"],
                    *(item[field] for field in _TOKEN_FIELDS),
                    *(item[field] for field in _COST_FIELDS),
                    item["priceProvenanceDigest"],
                    int(item["aggregateOnly"]),
                )
            )
        return tuple(statements)

    def _verify_rows(self, payload: Mapping[str, Any]) -> None:
        publication_id = payload["publicationId"]
        generation = payload["generation"]
        rows = self._query(_statement(_VERIFY_COUNTS, publication_id, payload["taskId"]))
        if len(rows) != 1:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        expected = generation["expectedCounts"]
        if row.get("state") not in {"staged", "visible"} or row.get("metadata_digest") != generation["metadataDigest"]:
            _invalid(D1ErrorCode.generation_state)
        for column, actual_column, key in (
            ("expected_task_count", "task_count", "tasks"),
            ("expected_pipeline_count", "pipeline_count", "pipelines"),
            ("expected_run_count", "run_count", "runs"),
            ("expected_event_count", "event_count", "events"),
            ("expected_artifact_count", "artifact_count", "artifacts"),
        ):
            if row.get(column) != expected[key] or row.get(actual_column) != expected[key]:
                _invalid(D1ErrorCode.count_mismatch)
        checks: tuple[tuple[str, Statement, tuple[tuple[Any, ...], ...]], ...] = (
            ("tasks", _statement(_TASK_SELECT, publication_id), tuple((item["taskId"], item["title"], item["lifecycleState"], item["createdAt"], item["completedAt"]) for item in (payload["task"],))),
            ("pipelines", _statement(_PIPELINE_SELECT, publication_id), tuple((item["pipelineId"], item["taskId"], item["name"], item["createdAt"]) for item in payload["pipelines"])),
            ("runs", _statement(_RUN_SELECT, publication_id), tuple((item["runId"], item["taskId"], item["pipelineId"], item["role"], item["runState"], item["startedAt"], item["completedAt"], item["durationMs"], item["atifDigest"]) for item in payload["runs"])),
            ("events", _statement(_EVENT_SELECT, publication_id), tuple((item["taskId"], item["sequence"], item["eventType"], item["occurredAt"], item["summary"]) for item in payload["events"])),
            ("artifacts", _statement(_ARTIFACT_SELECT, publication_id), tuple((item["artifactId"], item["taskId"], item["runId"], item["logicalPath"], item["publicKey"], item["mediaType"], item["byteSize"], item["sha256"], item["availability"], int(item["disclosure"]["redactionApplied"]), int(item["disclosure"]["originalRetained"])) for item in payload["artifacts"])),
        )
        for name, statement, expected_rows in checks:
            actual_rows = self._query(statement)
            actual = tuple(tuple(item.get(column) for column in self._columns(statement[0])) for item in actual_rows)
            if name == "events":
                expected_rows = tuple(sorted(expected_rows, key=lambda row: (row[0], row[1])))
            else:
                expected_rows = tuple(sorted(expected_rows, key=lambda row: row[0]))
            if actual != expected_rows:
                _invalid(D1ErrorCode.generation_conflict)

    def _verify_usage_rows(self, payload: Mapping[str, Any]) -> None:
        usage = payload["usage"]
        generation = usage["generation"]
        usage_id = generation["usageGenerationId"]
        rows = self._query(
            _statement(_VERIFY_USAGE_COUNTS, usage_id, payload["publicationId"], payload["taskId"])
        )
        if len(rows) != 1:
            _invalid(D1ErrorCode.generation_state)
        row = rows[0]
        if row.get("state") not in {"staged", "visible"} or row.get("metadata_digest") != generation["metadataDigest"]:
            _invalid(D1ErrorCode.generation_state)
        expected_counts = generation["expectedCounts"]
        for expected_column, actual_column, key in (
            ("expected_summary_count", "summary_count", "summaries"),
            ("expected_invocation_count", "invocation_count", "invocations"),
            ("expected_turn_count", "turn_count", "turns"),
            ("expected_price_count", "price_count", "prices"),
            ("expected_global_count", "global_count", "globals"),
        ):
            if row.get(expected_column) != expected_counts[key] or row.get(actual_column) != expected_counts[key]:
                _invalid(D1ErrorCode.count_mismatch)

        checks: tuple[tuple[str, Statement, tuple[tuple[Any, ...], ...]], ...] = (
            (
                "summaries",
                _statement(_USAGE_SUMMARY_SELECT, usage_id),
                tuple(
                    (
                        item["summaryId"],
                        item["usageGenerationId"],
                        item["publicationId"],
                        item["taskId"],
                        item["runId"],
                        item["scope"],
                        item["coverage"],
                        item["coveredInvocations"],
                        item["expectedInvocations"],
                        item["knownTokenSubtotal"],
                        item["knownCostSubtotalMicroUsd"],
                        *(item[field] for field in _TOKEN_FIELDS),
                        *(item[field] for field in _COST_FIELDS),
                        item["priceProvenanceDigest"],
                    )
                    for item in usage["summaries"]
                ),
            ),
            (
                "invocations",
                _statement(_USAGE_INVOCATION_SELECT, usage_id),
                tuple(
                    (
                        item["invocationId"],
                        item["usageGenerationId"],
                        item["publicationId"],
                        item["taskId"],
                        item["pipelineId"],
                        item["runId"],
                        item["ownershipClass"],
                        item["retryOrdinal"],
                        item["startedAt"],
                        item["completedAt"],
                        item["model"],
                        item["billingMode"],
                        item["processOutcome"],
                        item["coverage"],
                        item["issueCount"],
                        item["coveredTurns"],
                        item["expectedTurns"],
                        *(item[field] for field in _TOKEN_FIELDS),
                        *(item[field] for field in _COST_FIELDS),
                        item["priceEntryDigest"],
                    )
                    for item in usage["invocations"]
                ),
            ),
            (
                "turns",
                _statement(_USAGE_TURN_SELECT, usage_id),
                tuple(
                    (
                        item["turnId"],
                        item["usageGenerationId"],
                        item["invocationId"],
                        item["publicationId"],
                        item["taskId"],
                        item["runId"],
                        item["ordinal"],
                        *(item[field] for field in _TOKEN_FIELDS),
                        *(item[field] for field in _COST_FIELDS),
                        item["priceEntryDigest"],
                    )
                    for item in usage["turns"]
                ),
            ),
            (
                "prices",
                _statement(_USAGE_PRICE_SELECT, usage_id, usage_id, usage_id, usage_id),
                tuple(),
            ),
            (
                "globals",
                _statement(_USAGE_GLOBAL_SELECT, usage_id),
                tuple(
                    (
                        item["globalId"],
                        item["usageGenerationId"],
                        item["periodKind"],
                        item["periodKey"],
                        item["model"],
                        item["ownershipClass"],
                        item["coverage"],
                        item["coveredInvocations"],
                        item["expectedInvocations"],
                        item["knownTokenSubtotal"],
                        item["knownCostSubtotalMicroUsd"],
                        *(item[field] for field in _TOKEN_FIELDS),
                        *(item[field] for field in _COST_FIELDS),
                        item["priceProvenanceDigest"],
                        int(item["aggregateOnly"]),
                    )
                    for item in usage["globals"]
                ),
            ),
        )
        for name, statement, expected_rows in checks:
            actual_rows = self._query(statement)
            actual = tuple(tuple(item.get(column) for column in self._columns(statement[0])) for item in actual_rows)
            if name == "prices":
                expected_by_digest = {
                    item["priceEntryDigest"]: (
                        item["catalogDigest"],
                        item["model"],
                        item["effectiveAt"],
                        item["effectiveUntil"],
                    )
                    for item in usage["prices"]
                }
                actual_by_digest = {
                    value[0]: (value[2], value[3], value[4], value[5])
                    for value in actual
                }
                if actual_by_digest != expected_by_digest:
                    _invalid(D1ErrorCode.generation_conflict)
                continue
            if name == "invocations":
                def sort_key(value: tuple[Any, ...]) -> tuple[bool, Any]:
                    return value[0] is not None, value[0] or ""
            else:
                def sort_key(value: tuple[Any, ...]) -> Any:
                    return value[0]
            if tuple(sorted(actual, key=sort_key)) != tuple(sorted(expected_rows, key=sort_key)):
                _invalid(D1ErrorCode.generation_conflict)

    @staticmethod
    def _columns(sql: str) -> tuple[str, ...]:
        if sql == _TASK_SELECT:
            return ("task_id", "title", "lifecycle_state", "created_at", "completed_at")
        if sql == _PIPELINE_SELECT:
            return ("pipeline_id", "task_id", "name", "created_at")
        if sql == _RUN_SELECT:
            return ("run_id", "task_id", "pipeline_id", "role", "run_state", "started_at", "completed_at", "duration_ms", "atif_digest")
        if sql == _EVENT_SELECT:
            return ("task_id", "sequence", "event_type", "occurred_at", "summary")
        if sql == _USAGE_SUMMARY_SELECT:
            return ("summary_id", "usage_generation_id", "publication_id", "task_id", "run_id", "scope", "coverage", "covered_invocations", "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", *_TOKEN_DB_FIELDS, *_COST_DB_FIELDS, "price_provenance_digest")
        if sql == _USAGE_INVOCATION_SELECT:
            return ("invocation_id", "usage_generation_id", "publication_id", "task_id", "pipeline_id", "run_id", "ownership_class", "retry_ordinal", "started_at", "completed_at", "model", "billing_mode", "process_outcome", "coverage", "issue_count", "covered_turns", "expected_turns", *_TOKEN_DB_FIELDS, *_COST_DB_FIELDS, "price_entry_digest")
        if sql == _USAGE_TURN_SELECT:
            return ("turn_id", "usage_generation_id", "invocation_id", "publication_id", "task_id", "run_id", "ordinal", *_TOKEN_DB_FIELDS, *_COST_DB_FIELDS, "price_entry_digest")
        if sql == _USAGE_PRICE_SELECT:
            return ("price_entry_digest", "usage_generation_id", "catalog_digest", "model", "effective_at", "effective_until")
        if sql == _USAGE_GLOBAL_SELECT:
            return ("global_id", "usage_generation_id", "period_kind", "period_key", "model", "ownership_class", "coverage", "covered_invocations", "expected_invocations", "known_token_subtotal", "known_cost_subtotal_micro_usd", *_TOKEN_DB_FIELDS, *_COST_DB_FIELDS, "price_provenance_digest", "aggregate_only")
        return ("artifact_id", "task_id", "run_id", "logical_path", "public_key", "media_type", "byte_size", "sha256", "availability", "redaction_applied", "original_retained")

    def _verify_price_ledger(self, payload: Mapping[str, Any], *, check_overlap: bool = False) -> None:
        """Reject price-entry mutation and overlapping effective intervals."""
        candidates: list[tuple[str, str, str, str, str | None]] = []
        for item in payload["usage"]["prices"]:
            digest = item["priceEntryDigest"]
            facts = (item["catalogDigest"], item["model"], item["effectiveAt"], item["effectiveUntil"])
            rows = self._query(_statement(_PRICE_ENTRY_SELECT, digest))
            if len(rows) > 1:
                _invalid(D1ErrorCode.generation_conflict)
            if rows:
                existing = rows[0]
                actual = (
                    existing.get("catalog_digest"),
                    existing.get("model"),
                    existing.get("effective_at"),
                    existing.get("effective_until"),
                )
                if actual != facts:
                    _invalid(D1ErrorCode.generation_conflict)
            candidates.append((digest, *facts))
        if not check_overlap:
            return

        for digest, _catalog, model, effective_at, effective_until in candidates:
            if not isinstance(model, str) or not isinstance(effective_at, str):
                _invalid(D1ErrorCode.generation_conflict)
            try:
                start = datetime.fromisoformat(effective_at.replace("Z", "+00:00"))
                end = (
                    datetime.fromisoformat(effective_until.replace("Z", "+00:00"))
                    if effective_until is not None
                    else None
                )
            except (AttributeError, TypeError, ValueError):
                _invalid(D1ErrorCode.generation_conflict)

            previous = self._query(_statement(_PRICE_PREVIOUS_SELECT, model, effective_at))
            if previous:
                row = previous[0]
                previous_end = row.get("effective_until")
                try:
                    previous_end_at = (
                        datetime.fromisoformat(previous_end.replace("Z", "+00:00"))
                        if isinstance(previous_end, str)
                        else None
                    )
                except ValueError:
                    _invalid(D1ErrorCode.generation_conflict)
                if row.get("price_entry_digest") != digest and (previous_end_at is None or start < previous_end_at):
                    _invalid(D1ErrorCode.generation_conflict)

            following = self._query(_statement(_PRICE_NEXT_SELECT, model, effective_at))
            for row in following:
                if row.get("price_entry_digest") == digest:
                    continue
                following_start = row.get("effective_at")
                try:
                    following_start_at = (
                        datetime.fromisoformat(following_start.replace("Z", "+00:00"))
                        if isinstance(following_start, str)
                        else None
                    )
                except ValueError:
                    _invalid(D1ErrorCode.generation_conflict)
                if following_start_at is not None and (end is None or following_start_at < end):
                    _invalid(D1ErrorCode.generation_conflict)

    @staticmethod
    def _numeric_cost(row: Mapping[str, Any]) -> bool:
        return all(row.get(field) is not None for field in _COST_FIELDS)

    @staticmethod
    def _normalize_usage_row(row: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        for public, database in zip(_TOKEN_FIELDS, _TOKEN_DB_FIELDS):
            normalized[public] = row.get(database)
        for public, database in zip(_COST_FIELDS, _COST_DB_FIELDS):
            normalized[public] = row.get(database)
        normalized["priceEntryDigest"] = row.get("price_entry_digest")
        normalized["priceProvenanceDigest"] = row.get("price_provenance_digest")
        for public, database in (
            ("usageGenerationId", "usage_generation_id"),
            ("publicationId", "publication_id"),
            ("taskId", "task_id"),
            ("pipelineId", "pipeline_id"),
            ("runId", "run_id"),
            ("invocationId", "invocation_id"),
            ("retryOrdinal", "retry_ordinal"),
            ("startedAt", "started_at"),
            ("completedAt", "completed_at"),
            ("periodKind", "period_kind"),
            ("periodKey", "period_key"),
            ("ownershipClass", "ownership_class"),
        ):
            normalized[public] = row.get(database)
        return normalized

    def _verify_monotonic_usage(self, old_usage_id: str, payload: Mapping[str, Any]) -> None:
        """Keep every already numeric leaf and its price provenance unchanged."""

        usage = payload["usage"]
        old_rows = {
            name: [self._normalize_usage_row(row) for row in rows]
            for name, rows in (
                ("summaries", self._query(_statement(_USAGE_SUMMARY_SELECT, old_usage_id))),
                ("invocations", self._query(_statement(_USAGE_INVOCATION_SELECT, old_usage_id))),
                ("turns", self._query(_statement(_USAGE_TURN_SELECT, old_usage_id))),
            )
        }
        new_rows = {
            "summaries": usage["summaries"],
            "invocations": usage["invocations"],
            "turns": usage["turns"],
        }
        old_invocation_keys = {
            row.get("invocationId"): (row.get("runId"), row.get("retryOrdinal"), row.get("ownershipClass"))
            for row in old_rows["invocations"]
            if row.get("invocationId") is not None
        }
        new_invocation_keys = {
            row.get("invocationId"): (row.get("runId"), row.get("retryOrdinal"), row.get("ownershipClass"))
            for row in new_rows["invocations"]
            if row.get("invocationId") is not None
        }
        for row in old_rows["turns"]:
            row["_logicalTurnKey"] = (*old_invocation_keys.get(row.get("invocationId"), (None, None, None)), row.get("ordinal"))
        for row in new_rows["turns"]:
            row["_logicalTurnKey"] = (*new_invocation_keys.get(row.get("invocationId"), (None, None, None)), row.get("ordinal"))
        key_fields = {
            "summaries": ("scope", "run_id"),
            "invocations": ("run_id", "retry_ordinal", "ownership_class"),
            "turns": ("_logicalTurnKey",),
        }
        for name, previous in old_rows.items():
            old_map = {tuple(row.get(field) for field in key_fields[name]): row for row in previous}
            new_map = {
                tuple(
                    row.get(
                        {
                            "scope": "scope",
                            "run_id": "runId",
                            "retry_ordinal": "retryOrdinal",
                            "ownership_class": "ownershipClass",
                            "invocation_id": "invocationId",
                            "ordinal": "ordinal",
                            "period_kind": "periodKind",
                            "period_key": "periodKey",
                            "model": "model",
                        }.get(field, field)
                    )
                    for field in key_fields[name]
                ): row
                for row in new_rows[name]
            }
            for key, old in old_map.items():
                if not self._numeric_cost(old):
                    continue
                current = new_map.get(key)
                if current is None or not self._numeric_cost(current):
                    _invalid(D1ErrorCode.generation_conflict)
                if tuple(old.get(field) for field in _COST_FIELDS) != tuple(current.get(_camel) for _camel in _COST_FIELDS):
                    _invalid(D1ErrorCode.generation_conflict)
                old_price = old.get("price_entry_digest") or old.get("price_provenance_digest")
                new_price = current.get("priceEntryDigest") or current.get("priceProvenanceDigest")
                if old_price != new_price:
                    _invalid(D1ErrorCode.generation_conflict)

    @staticmethod
    def _global_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple(
            row.get(field)
            if field in row
            else row.get(
                {
                    "periodKind": "period_kind",
                    "periodKey": "period_key",
                    "ownershipClass": "ownership_class",
                }.get(field, field)
            )
            for field in _GLOBAL_KEY_FIELDS
        )

    @staticmethod
    def _global_db_row(row: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            "periodKind": row.get("period_kind"),
            "periodKey": row.get("period_key"),
            "model": row.get("model"),
            "ownershipClass": row.get("ownership_class"),
            "usageGenerationId": row.get("usage_generation_id"),
            "globalId": row.get("global_id"),
            "coverage": row.get("coverage"),
            "coveredInvocations": row.get("covered_invocations"),
            "expectedInvocations": row.get("expected_invocations"),
            "knownTokenSubtotal": row.get("known_token_subtotal"),
            "knownCostSubtotalMicroUsd": row.get("known_cost_subtotal_micro_usd"),
            "promptTokens": row.get("prompt_tokens"),
            "cachedTokens": row.get("cached_tokens"),
            "uncachedTokens": row.get("uncached_tokens"),
            "completionTokens": row.get("completion_tokens"),
            "reasoningTokens": row.get("reasoning_tokens"),
            "totalTokens": row.get("total_tokens"),
            "uncachedInputCostMicroUsd": row.get("uncached_input_cost_micro_usd"),
            "cachedInputCostMicroUsd": row.get("cached_input_cost_micro_usd"),
            "outputCostMicroUsd": row.get("output_cost_micro_usd"),
            "totalCostMicroUsd": row.get("total_cost_micro_usd"),
            "priceProvenanceDigest": row.get("price_provenance_digest"),
            "aggregateOnly": bool(row.get("aggregate_only")),
        }
        return result

    @classmethod
    def _global_delta(
        cls,
        old_aggregate: Mapping[str, Any] | None,
        old_task: Mapping[str, Any] | None,
        new_task: Mapping[str, Any],
    ) -> dict[str, Any]:
        if old_aggregate is None:
            result = dict(new_task)
            result["aggregateOnly"] = True
            return result
        result = dict(new_task)
        old_task = old_task or {}
        for field in ("coveredInvocations", "expectedInvocations"):
            value = (
                (old_aggregate.get(field) or 0)
                - (old_task.get(field) or 0)
                + (new_task.get(field) or 0)
            )
            if value < 0:
                _invalid(D1ErrorCode.generation_conflict)
            result[field] = value
        for field in ("knownTokenSubtotal", "knownCostSubtotalMicroUsd", *_USAGE_FIELDS):
            aggregate = old_aggregate.get(field)
            previous = old_task.get(field)
            current = new_task.get(field)
            if aggregate is None:
                result[field] = current if previous is None else None
            else:
                # Unknown evidence contributes no known subtotal.  Preserve a
                # known aggregate when the replaced/removed task has no value,
                # while retaining NULL for aggregates that were already
                # incomplete.
                value = aggregate - (previous or 0) + (current or 0)
                if value < 0:
                    _invalid(D1ErrorCode.generation_conflict)
                result[field] = value
        result["coverage"] = (
            "unavailable"
            if all(result[field] is None for field in _USAGE_FIELDS)
            else "complete"
            if result["coveredInvocations"] == result["expectedInvocations"]
            else "partial"
        )
        result["knownTokenSubtotal"] = result["totalTokens"]
        result["knownCostSubtotalMicroUsd"] = result["totalCostMicroUsd"]
        result["priceProvenanceDigest"] = (
            new_task.get("priceProvenanceDigest")
            if cls._numeric_cost(new_task)
            else old_aggregate.get("priceProvenanceDigest")
            if cls._numeric_cost(result)
            else None
        )
        result["aggregateOnly"] = True
        return result

    @classmethod
    def _global_remove(
        cls,
        aggregate: Mapping[str, Any],
        removed_task: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Subtract one task contribution while retaining a correction anchor."""

        empty = cls._empty_global_contribution(removed_task)
        result = cls._global_delta(aggregate, removed_task, empty)
        if result.get("expectedInvocations") == 0:
            result["priceProvenanceDigest"] = None
        elif cls._numeric_cost(result):
            removed_price = removed_task.get("priceProvenanceDigest")
            aggregate_price = aggregate.get("priceProvenanceDigest")
            result["priceProvenanceDigest"] = (
                aggregate_price
                if removed_price is None or removed_price == aggregate_price
                else None
            )
        else:
            result["priceProvenanceDigest"] = None
        return result

    @staticmethod
    def _empty_global_contribution(row: Mapping[str, Any]) -> dict[str, Any]:
        empty = dict(row)
        empty["coverage"] = "complete"
        empty["coveredInvocations"] = 0
        empty["expectedInvocations"] = 0
        empty["knownTokenSubtotal"] = 0
        empty["knownCostSubtotalMicroUsd"] = 0
        for field in _USAGE_FIELDS:
            empty[field] = 0
        empty["priceProvenanceDigest"] = None
        empty["aggregateOnly"] = True
        return empty

    @classmethod
    def _aggregate_global_rows(cls, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if not rows:
            _invalid(D1ErrorCode.generation_conflict)
        first = dict(rows[0])
        result = {
            "periodKind": first.get("periodKind"),
            "periodKey": first.get("periodKey"),
            "model": first.get("model"),
            "ownershipClass": first.get("ownershipClass"),
            "coveredInvocations": sum(row.get("coveredInvocations", 0) for row in rows),
            "expectedInvocations": sum(row.get("expectedInvocations", 0) for row in rows),
            "aggregateOnly": True,
        }
        for field in _USAGE_FIELDS:
            values = [row.get(field) for row in rows]
            result[field] = sum(values) if all(value is not None for value in values) else None
        result["knownTokenSubtotal"] = result["totalTokens"]
        result["knownCostSubtotalMicroUsd"] = result["totalCostMicroUsd"]
        result["coverage"] = (
            "unavailable"
            if any(row.get("coverage") == "unavailable" for row in rows)
            else "complete"
            if all(row.get("coverage") == "complete" for row in rows)
            else "partial"
        )
        price_digests = {row.get("priceProvenanceDigest") for row in rows if row.get("priceProvenanceDigest") is not None}
        result["priceProvenanceDigest"] = next(iter(price_digests)) if len(price_digests) == 1 else None
        return result

    def _usage_global_contributions(self, usage_generation_id: str) -> dict[tuple[Any, ...], dict[str, Any]]:
        grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
        rows = self._query(_statement(_USAGE_INVOCATION_SELECT, usage_generation_id))
        for raw in rows:
            row = self._normalize_usage_row(raw)
            if row.get("ownershipClass") != "task-owned":
                continue
            model = row.get("model") or "unknown"
            grouped.setdefault(("lifetime", "lifetime", model, "task-owned"), []).append(row)
            started_at = row.get("startedAt")
            if isinstance(started_at, str):
                try:
                    date = datetime.fromisoformat(started_at.replace("Z", "+00:00")).date().isoformat()
                except ValueError:
                    date = None
                if date is not None:
                    grouped.setdefault(("daily", date, model, "task-owned"), []).append(row)
        contributions: dict[tuple[Any, ...], dict[str, Any]] = {}
        for key, entries in grouped.items():
            result: dict[str, Any] = {
                "periodKind": key[0],
                "periodKey": key[1],
                "model": key[2],
                "ownershipClass": key[3],
                "coveredInvocations": sum(row.get("coverage") != "unavailable" for row in entries),
                "expectedInvocations": len(entries),
                "aggregateOnly": True,
            }
            for field in _USAGE_FIELDS:
                values = [row.get(field) for row in entries]
                result[field] = sum(values) if all(value is not None for value in values) else None
            result["knownTokenSubtotal"] = result["totalTokens"]
            result["knownCostSubtotalMicroUsd"] = result["totalCostMicroUsd"]
            result["coverage"] = (
                "unavailable"
                if all(result[field] is None for field in _USAGE_FIELDS)
                else "complete"
                if result["coveredInvocations"] == result["expectedInvocations"]
                and all(result[field] is not None for field in _USAGE_FIELDS)
                else "partial"
            )
            price_digests = {row.get("priceEntryDigest") for row in entries}
            result["priceProvenanceDigest"] = next(iter(price_digests)) if len(price_digests) == 1 else None
            contributions[key] = result
        return contributions

    def _usage_unavailable_invocation_count(self, usage_generation_id: str) -> int:
        rows = self._query(_statement(_USAGE_INVOCATION_SELECT, usage_generation_id))
        return sum(
            row.get("coverage") == "unavailable" and row.get("ownership_class") == "task-owned"
            for row in rows
        )

    def _global_transition_statements(
        self,
        *,
        task_id: str,
        publication_id: str,
        old_usage_id: str | None,
        new_usage_id: str,
        new_rows: Sequence[Mapping[str, Any]],
        updated_at: str,
        guarded: bool,
    ) -> tuple[Statement, ...]:
        """Compose one fixed-size set-based global visibility transition.

        ``new_rows`` is accepted to keep the transition call site aligned with
        the validated envelope; SQL reads the staged rows directly so the
        number of global keys never changes the number of provider statements
        or bound parameters.  The old task contribution is reconstructed from
        its invocation rows in the same UPDATE because visible global rows may
        contain an aggregate shared by several tasks.
        """

        # Keep the arguments explicit at this boundary: they document the CAS
        # identities used by callers even though the set-based SQL only needs
        # the generation IDs.  Validation has already restricted new_rows to
        # the task-owned global shape.
        del publication_id, new_rows
        rollup_prefix = f"global-rollup-{new_usage_id}"
        # The ID grammar admits "_"; this is an identity prefix, not a LIKE pattern.
        head_prefix = f"{rollup_prefix}:"
        update = _statement(
            _GLOBAL_TRANSITION_UPDATE,
            old_usage_id,
            int(old_usage_id is None),
            task_id,
            new_usage_id,
            rollup_prefix,
        )
        if guarded:
            heads = _statement(
                _GLOBAL_HEAD_UPSERT_SET_GUARDED,
                new_usage_id,
                updated_at,
                task_id,
                old_usage_id,
                head_prefix,
            )
        else:
            heads = _statement(_GLOBAL_HEAD_UPSERT_SET, new_usage_id, updated_at, head_prefix)
        return update, heads

    def stage(self, source: Mapping[str, Any]) -> StageReceipt:
        payload = _validate_payload(source)
        self._verify_price_ledger(payload, check_overlap=True)
        self._verify_existing_generation(payload)
        existing_usage_state = self._verify_existing_usage_generation(payload)
        self._verify_unique_generation_keys(payload)
        self._verify_unique_usage_keys(payload)
        if existing_usage_state == "superseded":
            self._verify_generation(payload)
            self._verify_rows(payload)
            return StageReceipt(payload["publicationId"], payload["taskId"], payload["generation"]["runId"])
        for chunk in self._chunks(self._stage_statements(payload)):
            self._batch(chunk)
        self._verify_generation(payload)
        self._verify_rows(payload)
        self._verify_usage_generation(payload)
        self._verify_usage_rows(payload)
        return StageReceipt(payload["publicationId"], payload["taskId"], payload["generation"]["runId"])

    def replace_usage(
        self,
        source: Mapping[str, Any],
        base_usage_generation_id: str | None = None,
        *,
        expected_usage_generation_id: str | None = None,
    ) -> ExposureReceipt:
        """Stage and atomically expose a usage-only replacement.

        The metadata generation and its task/R2 identity must already be
        visible. The optional base ID is a compare-and-set fence for callers
        that may have prepared more than one replacement concurrently.
        """

        if (
            base_usage_generation_id is not None
            and expected_usage_generation_id is not None
            and base_usage_generation_id != expected_usage_generation_id
        ):
            _invalid(D1ErrorCode.generation_conflict)
        expected_base = base_usage_generation_id or expected_usage_generation_id
        if expected_base is not None:
            expected_base = _id(expected_base)
        payload = _validate_payload(source, allow_usage_replacement=True)
        if payload["headIntent"]["state"] != "visible":
            _invalid(D1ErrorCode.generation_state)
        task_id = payload["taskId"]
        publication_id = payload["publicationId"]
        head_rows = self._query(_statement(_HEAD_SELECT, task_id))
        if len(head_rows) != 1 or head_rows[0].get("state") != "visible":
            _invalid(D1ErrorCode.generation_state)
        head = head_rows[0]
        if head.get("publication_id") != publication_id or head.get("usage_generation_id") is None:
            _invalid(D1ErrorCode.generation_conflict)
        old_usage_id = _id(head.get("usage_generation_id"))
        usage_heads = self._query(_statement(_USAGE_HEAD_SELECT, task_id))
        if len(usage_heads) != 1 or usage_heads[0].get("state") != "visible" or usage_heads[0].get("usage_generation_id") != old_usage_id:
            _invalid(D1ErrorCode.generation_state)
        if expected_base is not None and expected_base != old_usage_id:
            _invalid(D1ErrorCode.generation_conflict)
        self._verify_generation(payload)
        self._verify_rows(payload)
        self._verify_price_ledger(payload, check_overlap=True)
        new_usage_id = payload["usage"]["generation"]["usageGenerationId"]
        if new_usage_id == old_usage_id:
            self._verify_usage_generation(payload)
            self._verify_usage_rows(payload)
            return ExposureReceipt(publication_id, task_id, usage_generation_id=old_usage_id)
        self._verify_monotonic_usage(old_usage_id, payload)
        self._verify_existing_usage_generation(payload)
        self._verify_unique_usage_keys(payload)
        for chunk in self._chunks(self._usage_stage_statements(payload)):
            self._batch(chunk)
        self._verify_usage_generation(payload)
        self._verify_usage_rows(payload)
        updated_at = payload["headIntent"]["updatedAt"]
        statements: list[Statement] = [
            _statement(_USAGE_SWAP_OLD, old_usage_id, task_id, task_id, publication_id, old_usage_id, task_id, old_usage_id),
        ]
        statements.extend(
            self._global_transition_statements(
                task_id=task_id,
                publication_id=publication_id,
                old_usage_id=old_usage_id,
                new_usage_id=new_usage_id,
                new_rows=payload["usage"]["globals"],
                updated_at=updated_at,
                guarded=True,
            )
        )
        statements.extend(
            (
                _statement(_USAGE_SWAP_NEW, updated_at, new_usage_id, task_id, task_id, publication_id, old_usage_id, task_id, old_usage_id),
                _statement(_USAGE_SWAP_HEAD, new_usage_id, updated_at, task_id, publication_id, old_usage_id, task_id, old_usage_id, old_usage_id),
                _statement(_TASK_USAGE_SWAP, new_usage_id, updated_at, task_id, publication_id, old_usage_id, task_id, new_usage_id),
            )
        )
        self._batch(tuple(statements))
        head = self._query(_statement(_HEAD_SELECT, task_id))
        usage_head = self._query(_statement(_USAGE_HEAD_SELECT, task_id))
        usage_state = self._query(
            _statement(
                _USAGE_GENERATION_SELECT,
                new_usage_id,
                publication_id,
                task_id,
            )
        )
        if (
            len(head) != 1
            or head[0].get("publication_id") != publication_id
            or head[0].get("usage_generation_id") != new_usage_id
            or head[0].get("state") != "visible"
            or len(usage_head) != 1
            or usage_head[0].get("usage_generation_id") != new_usage_id
            or usage_head[0].get("state") != "visible"
            or len(usage_state) != 1
            or usage_state[0].get("state") != "visible"
        ):
            _invalid(D1ErrorCode.generation_state)
        return ExposureReceipt(publication_id, task_id, usage_generation_id=new_usage_id)

    # Names used by later lifecycle callers; all route through the same CAS path.
    replace_usage_projection = replace_usage
    swap_usage = replace_usage
    expose_usage = replace_usage
    usage_only_swap = replace_usage

    def _verify_existing_generation(self, payload: Mapping[str, Any]) -> None:
        rows = self._query(_statement(_GENERATION_SELECT, payload["publicationId"], payload["taskId"]))
        if rows:
            row = rows[0]
            expected = self._generation_expected(payload)
            actual = tuple(row.get(key) for key in ("task_id", "run_id", "metadata_digest", "idempotency_key", "state", "expected_task_count", "expected_pipeline_count", "expected_run_count", "expected_event_count", "expected_artifact_count", "created_at"))
            if actual != expected and not (actual[:4] == expected[:4] and actual[5:] == expected[5:] and actual[4] == "visible"):
                _invalid(D1ErrorCode.generation_conflict)
            if row.get("state") not in {"staged", "visible"}:
                _invalid(D1ErrorCode.generation_state)

    def _verify_existing_usage_generation(self, payload: Mapping[str, Any]) -> str | None:
        usage_generation = payload["usage"]["generation"]
        rows = self._query(
            _statement(
                _USAGE_GENERATION_SELECT,
                usage_generation["usageGenerationId"],
                payload["publicationId"],
                payload["taskId"],
            )
        )
        if rows:
            row = rows[0]
            expected = self._usage_generation_expected(payload)
            actual = tuple(
                row.get(key)
                for key in (
                    "usage_generation_id",
                    "publication_id",
                    "task_id",
                    "ownership_class",
                    "schema_version",
                    "metadata_digest",
                    "state",
                    "expected_summary_count",
                    "expected_invocation_count",
                    "expected_turn_count",
                    "expected_price_count",
                    "expected_global_count",
                    "created_at",
                )
            )
            if actual != expected and not (actual[:6] == expected[:6] and actual[7:] == expected[7:] and actual[6] in {"visible", "superseded"}):
                _invalid(D1ErrorCode.generation_conflict)
            if row.get("state") not in {"staged", "visible", "superseded"}:
                _invalid(D1ErrorCode.generation_state)
            return str(row.get("state"))
        return None

    def _verify_unique_generation_keys(self, payload: Mapping[str, Any]) -> None:
        generation = payload["generation"]
        for statement, params in (
            (_GENERATION_RUN_SELECT, (payload["taskId"], generation["runId"])),
            (_GENERATION_KEY_SELECT, (payload["taskId"], generation["idempotencyKey"])),
        ):
            rows = self._query(_statement(statement, *params))
            if any(row.get("publication_id") != payload["publicationId"] for row in rows):
                _invalid(D1ErrorCode.generation_conflict)

    def _verify_unique_usage_keys(self, payload: Mapping[str, Any]) -> None:
        usage = payload["usage"]
        usage_generation = usage["generation"]
        rows = self._query(_statement(_USAGE_GENERATION_ID_SELECT, usage_generation["usageGenerationId"]))
        if any(row.get("publication_id") != payload["publicationId"] or row.get("task_id") != payload["taskId"] for row in rows):
            _invalid(D1ErrorCode.generation_conflict)

    def _visible_usage_payload(self, task_id: str, usage_generation_id: str) -> dict[str, Any]:
        """Rebuild a complete replacement envelope from public D1 rows only."""

        head_rows = self._query(_statement(_HEAD_SELECT, task_id))
        if len(head_rows) != 1 or head_rows[0].get("state") != "visible":
            _invalid(D1ErrorCode.generation_state)
        head = head_rows[0]
        publication_id = _id(head.get("publication_id"))
        if head.get("usage_generation_id") != usage_generation_id:
            _invalid(D1ErrorCode.generation_conflict)
        generation_rows = self._query(_statement(_GENERATION_SELECT, publication_id, task_id))
        usage_generation_rows = self._query(_statement(_USAGE_GENERATION_SELECT, usage_generation_id, publication_id, task_id))
        if len(generation_rows) != 1 or len(usage_generation_rows) != 1:
            _invalid(D1ErrorCode.generation_state)
        generation = generation_rows[0]
        usage_generation = usage_generation_rows[0]
        task_rows = self._query(_statement(_TASK_SELECT, publication_id))
        pipeline_rows = self._query(_statement(_PIPELINE_SELECT, publication_id))
        run_rows = self._query(_statement(_RUN_SELECT, publication_id))
        event_rows = self._query(_statement(_EVENT_SELECT, publication_id))
        artifact_rows = self._query(_statement(_ARTIFACT_SELECT, publication_id))
        if len(task_rows) != 1:
            _invalid(D1ErrorCode.generation_state)
        task = task_rows[0]
        usage_summaries = self._query(_statement(_USAGE_SUMMARY_SELECT, usage_generation_id))
        usage_invocations = self._query(_statement(_USAGE_INVOCATION_SELECT, usage_generation_id))
        usage_turns = self._query(_statement(_USAGE_TURN_SELECT, usage_generation_id))
        usage_globals = self._query(_statement(_USAGE_GLOBAL_SELECT, usage_generation_id))
        usage_prices = self._query(_statement(_USAGE_PRICE_SELECT, usage_generation_id, usage_generation_id, usage_generation_id, usage_generation_id))

        def row_map(raw: Mapping[str, Any], fields: Sequence[tuple[str, str]]) -> dict[str, Any]:
            return {public: raw.get(database) for public, database in fields}

        payload: dict[str, Any] = {
            "schemaVersion": "2.0",
            "publicationId": publication_id,
            "taskId": task_id,
            "generation": {
                "publicationId": publication_id,
                "taskId": task_id,
                "runId": generation.get("run_id"),
                "metadataDigest": generation.get("metadata_digest"),
                "idempotencyKey": generation.get("idempotency_key"),
                "state": "staged",
                "expectedCounts": {
                    "tasks": generation.get("expected_task_count"),
                    "pipelines": generation.get("expected_pipeline_count"),
                    "runs": generation.get("expected_run_count"),
                    "events": generation.get("expected_event_count"),
                    "artifacts": generation.get("expected_artifact_count"),
                },
                "createdAt": generation.get("created_at"),
            },
            "headIntent": {
                "publicationId": publication_id,
                "taskId": task_id,
                "state": "visible",
                "updatedAt": head.get("updated_at"),
            },
            "task": row_map(task, (("taskId", "task_id"), ("title", "title"), ("lifecycleState", "lifecycle_state"), ("createdAt", "created_at"), ("completedAt", "completed_at"))),
            "pipelines": [row_map(item, (("pipelineId", "pipeline_id"), ("taskId", "task_id"), ("name", "name"), ("createdAt", "created_at"))) for item in pipeline_rows],
            "runs": [row_map(item, (("runId", "run_id"), ("taskId", "task_id"), ("pipelineId", "pipeline_id"), ("role", "role"), ("runState", "run_state"), ("startedAt", "started_at"), ("completedAt", "completed_at"), ("durationMs", "duration_ms"), ("atifDigest", "atif_digest"), ("atifArtifactId", "atif_artifact_id"))) for item in run_rows],
            "events": [row_map(item, (("taskId", "task_id"), ("sequence", "sequence"), ("eventType", "event_type"), ("occurredAt", "occurred_at"), ("summary", "summary"))) for item in event_rows],
            "artifacts": [
                {
                    **row_map(item, (("artifactId", "artifact_id"), ("taskId", "task_id"), ("runId", "run_id"), ("logicalPath", "logical_path"), ("publicKey", "public_key"), ("mediaType", "media_type"), ("byteSize", "byte_size"), ("sha256", "sha256"), ("availability", "availability"))),
                    "disclosure": {"redactionApplied": bool(item.get("redaction_applied")), "originalRetained": bool(item.get("original_retained"))},
                }
                for item in artifact_rows
            ],
        }
        usage: dict[str, Any] = {
            "schemaVersion": "1.0",
            "generation": {
                "usageGenerationId": usage_generation_id,
                "publicationId": publication_id,
                "taskId": task_id,
                "schemaVersion": usage_generation.get("schema_version"),
                "metadataDigest": usage_generation.get("metadata_digest"),
                "state": "staged",
                "expectedCounts": {
                    "summaries": usage_generation.get("expected_summary_count"),
                    "invocations": usage_generation.get("expected_invocation_count"),
                    "turns": usage_generation.get("expected_turn_count"),
                    "prices": usage_generation.get("expected_price_count"),
                    "globals": usage_generation.get("expected_global_count"),
                },
                "createdAt": usage_generation.get("created_at"),
            },
            "summaries": [],
            "invocations": [],
            "turns": [],
            "prices": [],
            "globals": [],
        }
        def usage_fields(item: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
            normalized = self._normalize_usage_row(item)
            return {name: normalized.get(name) for name in names}

        summary_names = tuple(_SUMMARY)
        invocation_names = tuple(_INVOCATION)
        turn_names = tuple(_TURN)
        global_names = tuple(_GLOBAL)
        for item in usage_summaries:
            value = usage_fields(item, summary_names)
            value.update({"summaryId": item.get("summary_id"), "scope": item.get("scope"), "coverage": item.get("coverage"), "coveredInvocations": item.get("covered_invocations"), "expectedInvocations": item.get("expected_invocations"), "knownTokenSubtotal": item.get("known_token_subtotal"), "knownCostSubtotalMicroUsd": item.get("known_cost_subtotal_micro_usd"), "runId": item.get("run_id")})
            usage["summaries"].append(value)
        for item in usage_invocations:
            value = usage_fields(item, invocation_names)
            value.update({"invocationId": item.get("invocation_id"), "pipelineId": item.get("pipeline_id"), "ownershipClass": item.get("ownership_class"), "billingMode": item.get("billing_mode"), "processOutcome": item.get("process_outcome"), "coverage": item.get("coverage"), "issueCount": item.get("issue_count"), "coveredTurns": item.get("covered_turns"), "expectedTurns": item.get("expected_turns")})
            usage["invocations"].append(value)
        for item in usage_turns:
            value = usage_fields(item, turn_names)
            value.update({"turnId": item.get("turn_id"), "ordinal": item.get("ordinal")})
            usage["turns"].append(value)
        for item in usage_globals:
            value = usage_fields(item, global_names)
            value.update({"globalId": item.get("global_id"), "periodKind": item.get("period_kind"), "periodKey": item.get("period_key"), "ownershipClass": item.get("ownership_class"), "coverage": item.get("coverage"), "coveredInvocations": item.get("covered_invocations"), "expectedInvocations": item.get("expected_invocations"), "knownTokenSubtotal": item.get("known_token_subtotal"), "knownCostSubtotalMicroUsd": item.get("known_cost_subtotal_micro_usd"), "aggregateOnly": bool(item.get("aggregate_only"))})
            usage["globals"].append(value)
        # A visible global head stores the aggregate after other task
        # publications have been merged.  A usage-only replacement must be
        # validated against this task's own invocation evidence first; the
        # transition below will merge that contribution back into the shared
        # aggregate atomically.
        task_contributions = self._usage_global_contributions(usage_generation_id)
        for item in usage["globals"]:
            if item.get("ownershipClass") != "task-owned":
                continue
            contribution = task_contributions.get(self._global_key(item))
            if contribution is None:
                continue
            for field in _GLOBAL_VALUE_FIELDS:
                item[field] = contribution[field]
        referenced_price_digests = {
            row.get("priceEntryDigest")
            for collection in ("invocations", "turns")
            for row in usage[collection]
            if row.get("priceEntryDigest") is not None
        }
        referenced_price_digests.update(
            row.get("priceProvenanceDigest")
            for collection in ("summaries", "globals")
            for row in usage[collection]
            if row.get("priceProvenanceDigest") is not None
        )
        for item in usage_prices:
            if item.get("price_entry_digest") not in referenced_price_digests:
                continue
            usage["prices"].append({"priceEntryDigest": item.get("price_entry_digest"), "usageGenerationId": item.get("usage_generation_id"), "catalogDigest": item.get("catalog_digest"), "model": item.get("model"), "effectiveAt": item.get("effective_at"), "effectiveUntil": item.get("effective_until")})
        payload["usage"] = usage
        artifact_by_digest = {item.get("sha256"): item.get("artifact_id") for item in artifact_rows}
        for run in payload["runs"]:
            run["atifArtifactId"] = artifact_by_digest.get(run.get("atifDigest"))
        return payload

    @staticmethod
    def _price_digest(entry: PriceEntry, catalog_digest: str) -> str:
        if not isinstance(entry, PriceEntry):
            _invalid(D1ErrorCode.generation_conflict)
        value = entry.to_public_dict(catalog_digest=catalog_digest)
        canonical = (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _catalog_timestamp(value: object) -> str | None:
        """Serialize catalog interval endpoints to the D1 timestamp shape."""

        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                _invalid(D1ErrorCode.generation_conflict)
            return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if isinstance(value, str):
            return _timestamp(value)
        _invalid(D1ErrorCode.generation_conflict)

    def _build_price_backfill(
        self,
        payload: dict[str, Any],
        *,
        catalog: PriceCatalog,
        selected_turn_ids: set[str],
    ) -> tuple[dict[str, Any], int]:
        if not isinstance(catalog, PriceCatalog):
            _invalid(D1ErrorCode.generation_conflict)
        catalog_digest = catalog.digest
        if _DIGEST.fullmatch(catalog_digest) is None:
            _invalid(D1ErrorCode.generation_conflict)
        usage = payload["usage"]
        old_usage_id = usage["generation"]["usageGenerationId"]
        new_usage_id = "usage-" + hashlib.sha256(f"{old_usage_id}:{catalog_digest}".encode()).hexdigest()
        invocations = usage["invocations"]
        inv_by_id = {item.get("invocationId"): item for item in invocations if item.get("invocationId") is not None}
        price_rows = {item["priceEntryDigest"]: item for item in usage["prices"]}
        filled = 0
        turn_price: dict[str, str] = {}
        for turn in usage["turns"]:
            turn_id = turn.get("turnId")
            if turn_id not in selected_turn_ids or all(turn.get(field) is not None for field in _COST_FIELDS):
                continue
            invocation = inv_by_id.get(turn.get("invocationId"))
            if invocation is None or invocation.get("model") is None or invocation.get("startedAt") is None or invocation.get("billingMode") is None:
                continue
            if any(turn.get(field) is None for field in _TOKEN_FIELDS):
                continue
            try:
                started = datetime.fromisoformat(str(invocation["startedAt"]).replace("Z", "+00:00"))
                entry = catalog.find(invocation["model"], started)
                if entry is None:
                    continue
                telemetry_turn = TelemetryTurn.from_usage({"input_tokens": turn["promptTokens"], "cached_input_tokens": turn["cachedTokens"], "output_tokens": turn["completionTokens"], "reasoning_output_tokens": turn["reasoningTokens"]}, ordinal=turn["ordinal"])
                estimate = estimate_cost([telemetry_turn], billing_mode=invocation["billingMode"], configured_model=invocation["model"], started_at=started, catalog=catalog)
            except Exception:
                continue
            if estimate.status is not CostStatus.estimated:
                continue
            turn.update({"uncachedInputCostMicroUsd": estimate.uncached_input_micro_usd, "cachedInputCostMicroUsd": estimate.cached_input_micro_usd, "outputCostMicroUsd": estimate.output_micro_usd, "totalCostMicroUsd": estimate.micro_usd})
            price_digest = self._price_digest(entry, catalog_digest)
            turn["priceEntryDigest"] = price_digest
            price_rows.setdefault(
                price_digest,
                {
                    "priceEntryDigest": price_digest,
                    "usageGenerationId": new_usage_id,
                    "catalogDigest": catalog_digest,
                    "model": entry.model,
                    "effectiveAt": self._catalog_timestamp(entry.effective_from),
                    "effectiveUntil": self._catalog_timestamp(entry.effective_until),
                },
            )
            turn_price[str(turn_id)] = price_digest
            filled += 1
        if not filled:
            return payload, 0
        old_to_new_invocation: dict[str, str] = {}
        for invocation in invocations:
            old_id = invocation.get("invocationId")
            new_id = "invocation-" + hashlib.sha256(f"{new_usage_id}:{old_id or invocation.get('runId')}:{invocation.get('retryOrdinal')}".encode()).hexdigest()
            old_to_new_invocation[str(old_id)] = new_id
            invocation["invocationId"] = new_id
        for turn in usage["turns"]:
            old_id = turn.get("invocationId")
            turn["invocationId"] = old_to_new_invocation.get(str(old_id), old_id)
            turn["turnId"] = "turn-" + hashlib.sha256(f"{new_usage_id}:{turn.get('invocationId')}:{turn.get('ordinal')}".encode()).hexdigest()
        for invocation in invocations:
            matching = [item for item in usage["turns"] if item.get("invocationId") == invocation.get("invocationId")]
            if matching and all(item.get(field) is not None for item in matching for field in _COST_FIELDS) and not self._numeric_cost(invocation):
                for field in _COST_FIELDS:
                    invocation[field] = sum(item[field] for item in matching)
                digests = {item.get("priceEntryDigest") for item in matching}
                invocation["priceEntryDigest"] = next(iter(digests)) if len(digests) == 1 else None
        for summary in usage["summaries"]:
            matching = [item for item in invocations if summary.get("scope") == "task" or item.get("runId") == summary.get("runId")]
            if matching and not self._numeric_cost(summary) and all(self._numeric_cost(item) for item in matching):
                for field in _COST_FIELDS:
                    summary[field] = sum(item[field] for item in matching)
                summary["knownCostSubtotalMicroUsd"] = summary["totalCostMicroUsd"]
                digests = {item.get("priceEntryDigest") for item in matching}
                summary["priceProvenanceDigest"] = next(iter(digests)) if len(digests) == 1 else None
        for global_row in usage["globals"]:
            if global_row.get("ownershipClass") != "task-owned" or self._numeric_cost(global_row):
                continue
            matching = [item for item in invocations if item.get("ownershipClass") == "task-owned" and item.get("model") == global_row.get("model") and (global_row.get("periodKind") == "lifetime" or (isinstance(item.get("startedAt"), str) and item["startedAt"][:10] == global_row.get("periodKey")))]
            if matching and all(self._numeric_cost(item) for item in matching):
                for field in _COST_FIELDS:
                    global_row[field] = sum(item[field] for item in matching)
                global_row["knownCostSubtotalMicroUsd"] = global_row["totalCostMicroUsd"]
                digests = {item.get("priceEntryDigest") for item in matching}
                global_row["priceProvenanceDigest"] = next(iter(digests)) if len(digests) == 1 else None
        for collection in ("summaries", "invocations", "turns", "globals", "prices"):
            for row in usage[collection]:
                row["usageGenerationId"] = new_usage_id
        for summary in usage["summaries"]:
            summary["summaryId"] = "summary-" + hashlib.sha256(f"{new_usage_id}:{summary.get('scope')}:{summary.get('runId')}".encode()).hexdigest()
        for global_row in usage["globals"]:
            global_row["globalId"] = "global-" + hashlib.sha256(f"{new_usage_id}:{global_row.get('periodKind')}:{global_row.get('periodKey')}:{global_row.get('model')}:{global_row.get('ownershipClass')}".encode()).hexdigest()
        usage["prices"] = list(price_rows.values())
        usage["generation"]["usageGenerationId"] = new_usage_id
        usage["generation"]["expectedCounts"] = {name: len(usage[name]) for name in ("summaries", "invocations", "turns", "prices", "globals")}
        usage["generation"]["metadataDigest"] = _usage_metadata_digest(payload)
        return payload, filled

    def backfill_na_costs(
        self,
        catalog: PriceCatalog,
        *,
        cursor: str | None = None,
        limit: int = 64,
    ) -> UsageBackfillReceipt:
        """Fill only newly priceable N.A. turns from cached public evidence."""

        if not isinstance(catalog, PriceCatalog):
            _invalid(D1ErrorCode.generation_conflict)
        rows, next_cursor = self.list_visible_na_turns(cursor=cursor, limit=limit)
        if not rows:
            return UsageBackfillReceipt(next_cursor=None)
        marker = getattr(self, "_backfill_completed", None)
        if marker is None:
            marker = set()
            self._backfill_completed = marker
        catalog_digest = catalog.digest
        if _DIGEST.fullmatch(catalog_digest) is None:
            _invalid(D1ErrorCode.generation_conflict)
        processed = 0
        changed = False
        first_task_id: str | None = None
        first_usage_id: str | None = None
        result_usage_id: str | None = None
        grouped: dict[tuple[str, str], set[str]] = {}
        for row in rows:
            task_value = row.get("task_id")
            usage_value = row.get("head_usage_generation_id")
            if not isinstance(task_value, str) or not isinstance(usage_value, str):
                continue
            grouped.setdefault((task_value, usage_value), set()).add(str(row.get("turn_id")))
        for (task_id, usage_id), selected_ids in sorted(grouped.items()):
            if first_task_id is None:
                first_task_id, first_usage_id = task_id, usage_id
            marker_key = (task_id, usage_id, catalog_digest)
            if marker_key in marker:
                result_usage_id = usage_id
                continue
            payload = self._visible_usage_payload(task_id, usage_id)
            payload, filled = self._build_price_backfill(payload, catalog=catalog, selected_turn_ids=selected_ids)
            if not filled:
                marker.add(marker_key)
                result_usage_id = usage_id
                continue
            new_usage_id = payload["usage"]["generation"]["usageGenerationId"]
            try:
                receipt = self.replace_usage(payload, base_usage_generation_id=usage_id)
            except D1Error as error:
                if error.code == D1ErrorCode.generation_conflict:
                    return UsageBackfillReceipt(
                        first_task_id,
                        first_usage_id,
                        new_usage_id,
                        processed + filled,
                        changed,
                        next_cursor,
                        "numeric_conflict",
                    )
                raise
            marker.add((task_id, receipt.usage_generation_id, catalog_digest))
            processed += filled
            changed = True
            result_usage_id = receipt.usage_generation_id
        return UsageBackfillReceipt(
            first_task_id,
            first_usage_id,
            result_usage_id,
            processed,
            changed,
            # Replacements derive fresh turn identities.  A cursor from the
            # superseded generation is therefore not a valid continuation;
            # restart from the first visible N.A. row on the next bounded
            # worker unit.
            None if changed else next_cursor,
        )

    reconcile_price_catalog = backfill_na_costs
    backfill_na_turns = backfill_na_costs
    fill_na_costs = backfill_na_costs

    def expose(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        if payload["headIntent"]["state"] != "visible":
            _invalid(D1ErrorCode.generation_state)
        generation_state = self._verify_generation(payload)
        usage_state = self._verify_usage_generation(payload, allow_superseded=True)
        self._verify_rows(payload)
        self._verify_price_ledger(payload, check_overlap=True)
        current = self._query(_statement(_VISIBLE_HEAD_SELECT, payload["taskId"]))
        if current and current[0].get("publication_id") == payload["publicationId"]:
            usage_id = payload["usage"]["generation"]["usageGenerationId"]
            usage_head = self._query(_statement(_USAGE_HEAD_SELECT, payload["taskId"]))
            if current[0].get("usage_generation_id") != usage_id or len(usage_head) != 1 or usage_head[0].get("usage_generation_id") != usage_id:
                _invalid(D1ErrorCode.generation_conflict)
            if current[0].get("state") == "visible":
                if usage_state == "superseded":
                    _invalid(D1ErrorCode.generation_state)
                self._verify_usage_rows(payload)
                if usage_head[0].get("state") != "visible":
                    _invalid(D1ErrorCode.generation_state)
                return ExposureReceipt(payload["publicationId"], payload["taskId"], usage_generation_id=usage_id)
            if current[0].get("state") == "hidden":
                if usage_head[0].get("state") != "hidden":
                    _invalid(D1ErrorCode.generation_state)
                if usage_state == "staged":
                    self._verify_usage_rows(payload)
                return ExposureReceipt(payload["publicationId"], payload["taskId"], state="hidden", usage_generation_id=usage_id)
            _invalid(D1ErrorCode.generation_state)
        if generation_state != "staged" or usage_state != "staged":
            _invalid(D1ErrorCode.generation_state)
        self._verify_usage_rows(payload)
        updated_at = payload["headIntent"]["updatedAt"]
        usage_id = payload["usage"]["generation"]["usageGenerationId"]
        old_usage_id = (
            current[0].get("usage_generation_id")
            if current and current[0].get("state") == "visible"
            else None
        )
        statements: list[Statement] = [
            _statement(
                _EXPOSE_OLD,
                payload["taskId"],
                payload["publicationId"],
                payload["publicationId"],
                payload["taskId"],
            ),
            _statement(
                _EXPOSE_OLD_USAGE,
                payload["taskId"],
                usage_id,
                usage_id,
                payload["taskId"],
            ),
        ]
        statements.extend(
            self._global_transition_statements(
                task_id=payload["taskId"],
                publication_id=payload["publicationId"],
                old_usage_id=old_usage_id,
                new_usage_id=usage_id,
                new_rows=payload["usage"]["globals"],
                updated_at=updated_at,
                guarded=old_usage_id is not None,
            )
        )
        statements.extend(
            (
                _statement(_EXPOSE_NEW, updated_at, payload["publicationId"], payload["taskId"]),
                _statement(_EXPOSE_NEW_USAGE, updated_at, usage_id, payload["taskId"]),
                _statement(_USAGE_HEAD_UPSERT, payload["taskId"], usage_id, updated_at),
                _statement(_HEAD_UPSERT, usage_id, updated_at, payload["publicationId"], payload["taskId"]),
            )
        )
        self._batch(tuple(statements))
        visible = self._query(_statement(_VERIFY_COUNTS, payload["publicationId"], payload["taskId"]))
        usage_visible = self._query(_statement(_VERIFY_USAGE_COUNTS, usage_id, payload["publicationId"], payload["taskId"]))
        head = self._query(_statement(_VISIBLE_HEAD_SELECT, payload["taskId"]))
        usage_head = self._query(_statement(_USAGE_HEAD_SELECT, payload["taskId"]))
        if (
            len(visible) != 1
            or visible[0].get("state") != "visible"
            or len(usage_visible) != 1
            or usage_visible[0].get("state") != "visible"
            or len(head) != 1
            or head[0].get("publication_id") != payload["publicationId"]
            or head[0].get("usage_generation_id") != usage_id
            or head[0].get("state") != "visible"
            or len(usage_head) != 1
            or usage_head[0].get("usage_generation_id") != usage_id
            or usage_head[0].get("state") != "visible"
        ):
            _invalid(D1ErrorCode.generation_state)
        return ExposureReceipt(payload["publicationId"], payload["taskId"], usage_generation_id=usage_id)

    def publish(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        self.stage(payload)
        return self.expose(payload)

    @staticmethod
    def _overhead_value_digest(row: Mapping[str, Any]) -> str:
        value = {key: row[key] for key in (*_GLOBAL_KEY_FIELDS, *_GLOBAL_VALUE_FIELDS)}
        canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _overhead_generation_id(period_kind: str, period_key: str, model: str, value_digest: str) -> str:
        identity = json.dumps(
            {"periodKind": period_kind, "periodKey": period_key, "model": model, "valueDigest": value_digest},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "usage-overhead-" + hashlib.sha256(identity).hexdigest()

    @staticmethod
    def _overhead_global_id(period_kind: str, period_key: str, model: str, value_digest: str) -> str:
        identity = json.dumps(
            {"periodKind": period_kind, "periodKey": period_key, "model": model, "valueDigest": value_digest},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "global-overhead-" + hashlib.sha256(identity).hexdigest()

    @staticmethod
    def _overhead_guard(
        daily: Mapping[str, Any] | None,
        lifetime: Mapping[str, Any] | None,
        *,
        model: str | None = None,
        daily_period_key: str | None = None,
    ) -> tuple[str, tuple[Scalar, ...]]:
        """Build a visible-head CAS predicate for both aggregate keys."""

        terms: list[str] = []
        params: list[Scalar] = []
        for index, expected in enumerate((daily, lifetime)):
            kind = expected.get("periodKind") if expected is not None else ("daily" if index == 0 else "lifetime")
            period_key = expected.get("periodKey") if expected is not None else (daily_period_key if index == 0 else "lifetime")
            expected_model = expected.get("model") if expected is not None else model
            owner = "steward-overhead"
            if expected is None:
                terms.append(
                    "NOT EXISTS (SELECT 1 FROM usage_global_heads "
                    "WHERE period_kind = ? AND period_key = ? AND model = ? AND ownership_class = ? "
                    "AND state = 'visible')"
                )
                params.extend((kind, period_key, expected_model, owner))
            else:
                terms.append(
                    "EXISTS (SELECT 1 FROM usage_global_heads "
                    "WHERE period_kind = ? AND period_key = ? AND model = ? AND ownership_class = ? "
                    "AND usage_generation_id = ? AND global_id = ? AND state = 'visible')"
                )
                params.extend((kind, period_key, expected_model, owner, expected["usageGenerationId"], expected["globalId"]))
        return " AND ".join(terms), tuple(params)

    def _verify_overhead_stored(self, head: Mapping[str, Any]) -> dict[str, Any]:
        """Reject malformed or task-owned rows reached through an overhead head."""

        usage_id = _id(head.get("usageGenerationId"))
        generations = self._query(_statement(_OVERHEAD_GENERATION_SELECT, usage_id))
        if len(generations) != 1:
            _invalid(D1ErrorCode.generation_state)
        generation = generations[0]
        if (
            generation.get("publication_id") is not None
            or generation.get("task_id") is not None
            or generation.get("ownership_class") != "steward-overhead"
            or generation.get("expected_summary_count") != 0
            or generation.get("expected_invocation_count") != 0
            or generation.get("expected_turn_count") != 0
            or generation.get("expected_price_count") != 0
            or generation.get("expected_global_count") != 1
            or generation.get("summary_count") != 0
            or generation.get("invocation_count") != 0
            or generation.get("turn_count") != 0
            or generation.get("price_count") != 0
            or generation.get("global_count") != 1
            or generation.get("state") != "visible"
        ):
            _invalid(D1ErrorCode.generation_conflict)
        globals_ = self._query(_statement(_OVERHEAD_GLOBAL_SELECT, usage_id))
        if len(globals_) != 1:
            _invalid(D1ErrorCode.generation_state)
        stored = self._global_db_row(globals_[0])
        _overhead_public_mapping(
            {key: stored[key] for key in (
                "periodKind", "periodKey", "model", "ownershipClass", "coverage",
                "coveredInvocations", "expectedInvocations", "knownTokenSubtotal",
                "knownCostSubtotalMicroUsd", *_USAGE_FIELDS, "priceProvenanceDigest", "aggregateOnly",
            )}
        )
        for field in (*_GLOBAL_KEY_FIELDS, "usageGenerationId", "globalId"):
            if stored.get(field) != head.get(field):
                _invalid(D1ErrorCode.generation_conflict)
        if stored.get("ownershipClass") != "steward-overhead" or stored.get("aggregateOnly") is not True:
            _invalid(D1ErrorCode.generation_conflict)
        return stored

    def _verify_overhead_generation(
        self,
        usage_generation_id: str,
        global_id: str,
        expected: Mapping[str, Any],
    ) -> None:
        generations = self._query(_statement(_OVERHEAD_GENERATION_SELECT, usage_generation_id))
        if len(generations) != 1:
            _invalid(D1ErrorCode.generation_state)
        generation = generations[0]
        if (
            generation.get("publication_id") is not None
            or generation.get("task_id") is not None
            or generation.get("ownership_class") != "steward-overhead"
            or generation.get("schema_version") != "1.0"
            or generation.get("metadata_digest") != expected["metadataDigest"]
            or generation.get("state") not in {"staged", "visible"}
            or generation.get("expected_summary_count") != 0
            or generation.get("expected_invocation_count") != 0
            or generation.get("expected_turn_count") != 0
            or generation.get("expected_price_count") != 0
            or generation.get("expected_global_count") != 1
            or generation.get("summary_count") != 0
            or generation.get("invocation_count") != 0
            or generation.get("turn_count") != 0
            or generation.get("price_count") != 0
            or generation.get("global_count") != 1
        ):
            _invalid(D1ErrorCode.generation_conflict)
        globals_ = self._query(_statement(_OVERHEAD_GLOBAL_SELECT, usage_generation_id))
        if len(globals_) != 1:
            _invalid(D1ErrorCode.count_mismatch)
        actual = self._global_db_row(globals_[0])
        if actual.get("globalId") != global_id or actual.get("usageGenerationId") != usage_generation_id:
            _invalid(D1ErrorCode.generation_conflict)
        for field in (*_GLOBAL_KEY_FIELDS, *_GLOBAL_VALUE_FIELDS):
            if actual.get(field) != expected.get(field):
                _invalid(D1ErrorCode.generation_conflict)

    @staticmethod
    def _overhead_lifetime_row(
        old_daily: Mapping[str, Any] | None,
        old_lifetime: Mapping[str, Any] | None,
        new_daily: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Replace one daily contribution while preserving unknown evidence."""

        if old_lifetime is None:
            if old_daily is not None:
                _invalid(D1ErrorCode.generation_conflict)
            result = dict(new_daily)
            result.update({"periodKind": "lifetime", "periodKey": "lifetime"})
            return result
        result = dict(old_lifetime)
        result.update({"periodKind": "lifetime", "periodKey": "lifetime", "ownershipClass": "steward-overhead", "aggregateOnly": True})
        old_daily = old_daily or {}
        for field in ("coveredInvocations", "expectedInvocations"):
            value = (old_lifetime.get(field) or 0) - (old_daily.get(field) or 0) + (new_daily.get(field) or 0)
            if value < 0 or value > _SAFE_INTEGER_MAX:
                _invalid(D1ErrorCode.generation_conflict)
            result[field] = value
        for field in _USAGE_FIELDS:
            aggregate = old_lifetime.get(field)
            previous = old_daily.get(field)
            current = new_daily.get(field)
            if aggregate is None or current is None or (old_daily and previous is None):
                result[field] = None
                continue
            value = aggregate - (previous or 0) + current
            if value < 0 or value > _SAFE_INTEGER_MAX:
                _invalid(D1ErrorCode.generation_conflict)
            result[field] = value
        result["knownTokenSubtotal"] = result["totalTokens"]
        result["knownCostSubtotalMicroUsd"] = result["totalCostMicroUsd"]
        result["coverage"] = (
            "unavailable"
            if all(result[field] is None for field in _USAGE_FIELDS)
            else "complete"
            if result["coveredInvocations"] == result["expectedInvocations"]
            and all(result[field] is not None for field in _USAGE_FIELDS)
            else "partial"
        )
        result["priceProvenanceDigest"] = None
        return result

    def _upsert_overhead_one(
        self,
        row: Mapping[str, Any],
        row_digest: str,
        updated_at: str,
    ) -> OverheadReceipt:
        date = row["periodKey"]
        model = row["model"]
        daily_key = ("daily", date, model, "steward-overhead")
        lifetime_key = ("lifetime", "lifetime", model, "steward-overhead")
        daily_rows = self._query(_statement(_GLOBAL_HEAD_KEY_SELECT, *daily_key))
        lifetime_rows = self._query(_statement(_GLOBAL_HEAD_KEY_SELECT, *lifetime_key))
        if len(daily_rows) > 1 or len(lifetime_rows) > 1:
            _invalid(D1ErrorCode.generation_state)
        old_daily = self._verify_overhead_stored(self._global_db_row(daily_rows[0])) if daily_rows else None
        old_lifetime = self._verify_overhead_stored(self._global_db_row(lifetime_rows[0])) if lifetime_rows else None
        if old_daily is not None and old_lifetime is None:
            _invalid(D1ErrorCode.generation_state)
        new_daily = dict(row)
        new_daily.update({"periodKind": "daily", "periodKey": date, "ownershipClass": "steward-overhead", "aggregateOnly": True})
        new_lifetime = self._overhead_lifetime_row(old_daily, old_lifetime, new_daily)
        daily_value_digest = row_digest
        lifetime_value_digest = self._overhead_value_digest(new_lifetime)
        daily_id = self._overhead_generation_id("daily", date, model, daily_value_digest)
        daily_global_id = self._overhead_global_id("daily", date, model, daily_value_digest)
        lifetime_id = self._overhead_generation_id("lifetime", "lifetime", model, lifetime_value_digest)
        lifetime_global_id = self._overhead_global_id("lifetime", "lifetime", model, lifetime_value_digest)
        daily_expected = {**new_daily, "metadataDigest": daily_value_digest}
        lifetime_expected = {**new_lifetime, "metadataDigest": lifetime_value_digest}
        if (
            old_daily is not None
            and old_lifetime is not None
            and old_daily.get("usageGenerationId") == daily_id
            and old_daily.get("globalId") == daily_global_id
            and old_lifetime.get("usageGenerationId") == lifetime_id
            and old_lifetime.get("globalId") == lifetime_global_id
        ):
            self._verify_overhead_generation(daily_id, daily_global_id, daily_expected)
            self._verify_overhead_generation(lifetime_id, lifetime_global_id, lifetime_expected)
            return OverheadReceipt(date, model, row_digest, changed=False)

        self._batch(
            (
                _statement(_OVERHEAD_GENERATION_INSERT, daily_id, daily_value_digest, updated_at),
                _statement(
                    _OVERHEAD_GLOBAL_INSERT,
                    daily_global_id,
                    daily_id,
                    new_daily["periodKind"],
                    new_daily["periodKey"],
                    new_daily["model"],
                    new_daily["coverage"],
                    new_daily["coveredInvocations"],
                    new_daily["expectedInvocations"],
                    new_daily["knownTokenSubtotal"],
                    new_daily["knownCostSubtotalMicroUsd"],
                    *(new_daily[field] for field in _TOKEN_FIELDS),
                    *(new_daily[field] for field in _COST_FIELDS),
                ),
                _statement(_OVERHEAD_GENERATION_INSERT, lifetime_id, lifetime_value_digest, updated_at),
                _statement(
                    _OVERHEAD_GLOBAL_INSERT,
                    lifetime_global_id,
                    lifetime_id,
                    new_lifetime["periodKind"],
                    new_lifetime["periodKey"],
                    new_lifetime["model"],
                    new_lifetime["coverage"],
                    new_lifetime["coveredInvocations"],
                    new_lifetime["expectedInvocations"],
                    new_lifetime["knownTokenSubtotal"],
                    new_lifetime["knownCostSubtotalMicroUsd"],
                    *(new_lifetime[field] for field in _TOKEN_FIELDS),
                    *(new_lifetime[field] for field in _COST_FIELDS),
                ),
            )
        )
        self._verify_overhead_generation(daily_id, daily_global_id, daily_expected)
        self._verify_overhead_generation(lifetime_id, lifetime_global_id, lifetime_expected)

        old_ids = tuple(
            item["usageGenerationId"]
            for item, replacement_id in ((old_daily, daily_id), (old_lifetime, lifetime_id))
            if item is not None and item["usageGenerationId"] != replacement_id
        )
        old_daily_head = (
            {"periodKind": old_daily["periodKind"], "periodKey": old_daily["periodKey"], "model": old_daily["model"], "usageGenerationId": old_daily["usageGenerationId"], "globalId": old_daily["globalId"]}
            if old_daily
            else None
        )
        old_lifetime_head = (
            {"periodKind": old_lifetime["periodKind"], "periodKey": old_lifetime["periodKey"], "model": old_lifetime["model"], "usageGenerationId": old_lifetime["usageGenerationId"], "globalId": old_lifetime["globalId"]}
            if old_lifetime
            else None
        )
        guard, guard_params = self._overhead_guard(
            old_daily_head,
            old_lifetime_head,
            model=model,
            daily_period_key=date,
        )
        if old_ids:
            supersede_sql = (
                "UPDATE usage_generations SET state = 'superseded' WHERE ownership_class = 'steward-overhead' "
                f"AND state = 'visible' AND usage_generation_id IN ({','.join('?' for _ in old_ids)}) AND {guard}"
            )
            supersede_params: tuple[Scalar, ...] = (*old_ids, *guard_params)
        else:
            supersede_sql = "UPDATE usage_generations SET state = 'superseded' WHERE 0"
            supersede_params = ()
        expose_sql = (
            "UPDATE usage_generations SET state = 'visible', exposed_at = ? "
            f"WHERE ownership_class = 'steward-overhead' AND state = 'staged' AND usage_generation_id IN (?, ?) AND {guard}"
        )
        expose_params: tuple[Scalar, ...] = (updated_at, daily_id, lifetime_id, *guard_params)
        daily_new = {"periodKind": "daily", "periodKey": date, "model": model, "usageGenerationId": daily_id, "globalId": daily_global_id}
        daily_head_sql = (
            "INSERT INTO usage_global_heads "
            "(period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) "
            "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, g.usage_generation_id, g.global_id, 'visible', ? "
            f"FROM usage_globals AS g WHERE g.global_id = ? AND g.usage_generation_id = ? AND {guard} "
            "ON CONFLICT(period_kind, period_key, model, ownership_class) DO UPDATE SET "
            "usage_generation_id = excluded.usage_generation_id, global_id = excluded.global_id, state = 'visible', updated_at = excluded.updated_at"
        )
        daily_head_params: tuple[Scalar, ...] = (updated_at, daily_global_id, daily_id, *guard_params)
        lifetime_guard, lifetime_guard_params = self._overhead_guard(
            daily_new,
            old_lifetime_head,
            model=model,
            daily_period_key=date,
        )
        lifetime_head_sql = (
            "INSERT INTO usage_global_heads "
            "(period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) "
            "SELECT g.period_kind, g.period_key, g.model, g.ownership_class, g.usage_generation_id, g.global_id, 'visible', ? "
            f"FROM usage_globals AS g WHERE g.global_id = ? AND g.usage_generation_id = ? AND {lifetime_guard} "
            "ON CONFLICT(period_kind, period_key, model, ownership_class) DO UPDATE SET "
            "usage_generation_id = excluded.usage_generation_id, global_id = excluded.global_id, state = 'visible', updated_at = excluded.updated_at"
        )
        lifetime_head_params: tuple[Scalar, ...] = (updated_at, lifetime_global_id, lifetime_id, *lifetime_guard_params)
        self._batch(
            (
                _statement(supersede_sql, *supersede_params),
                _statement(expose_sql, *expose_params),
                _statement(daily_head_sql, *daily_head_params),
                _statement(lifetime_head_sql, *lifetime_head_params),
            )
        )
        current_daily = self._query(_statement(_GLOBAL_HEAD_KEY_SELECT, *daily_key))
        current_lifetime = self._query(_statement(_GLOBAL_HEAD_KEY_SELECT, *lifetime_key))
        if (
            len(current_daily) != 1
            or len(current_lifetime) != 1
            or current_daily[0].get("usage_generation_id") != daily_id
            or current_daily[0].get("global_id") != daily_global_id
            or current_lifetime[0].get("usage_generation_id") != lifetime_id
            or current_lifetime[0].get("global_id") != lifetime_global_id
        ):
            _invalid(D1ErrorCode.generation_conflict)
        self._verify_overhead_generation(daily_id, daily_global_id, daily_expected)
        self._verify_overhead_generation(lifetime_id, lifetime_global_id, lifetime_expected)
        return OverheadReceipt(date, model, row_digest, changed=True)

    def upsert_overhead(
        self,
        source: object,
        *,
        digest: str | None = None,
        archive_digest: str | None = None,
        updated_at: str | None = None,
    ) -> OverheadReceipt | tuple[OverheadReceipt, ...]:
        """Atomically replace bounded daily/model overhead aggregates."""

        if isinstance(source, Mapping) or _object_mapping(source) is not None:
            values = (source,)
        elif isinstance(source, Sequence) and not isinstance(source, (str, bytes, bytearray)):
            values = tuple(source)
        else:
            _invalid(D1ErrorCode.generation_conflict)
        if not values or len(values) > 32:
            _invalid(D1ErrorCode.count_mismatch)
        supplied_digest = archive_digest if archive_digest is not None else digest
        batch_digest = _overhead_digest(values, supplied_digest)
        normalized = tuple(_overhead_row(value) for value in values)
        if updated_at is None:
            updated_at = _timestamp_now()
        else:
            _timestamp(updated_at)
        seen: set[tuple[str, str]] = set()
        receipts: list[OverheadReceipt] = []
        for row in sorted(normalized, key=lambda item: (item["periodKey"], item["model"])):
            key = (row["periodKey"], row["model"])
            if key in seen:
                _invalid(D1ErrorCode.generation_conflict)
            seen.add(key)
            row_digest = _overhead_digest((row,))
            receipts.append(self._upsert_overhead_one(row, row_digest, updated_at))
        if len(receipts) > 1:
            receipts = [OverheadReceipt(item.date, item.model, batch_digest, item.state, item.changed) for item in receipts]
        return receipts[0] if len(receipts) == 1 else tuple(receipts)

    def list_visible_na_turns(
        self,
        *,
        cursor: str | None = None,
        limit: int = 64,
    ) -> tuple[list[Mapping[str, Any]], str | None]:
        """Return one bounded cursor page of visible turns missing costs."""

        if cursor is not None:
            cursor = _id(cursor)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 128:
            _invalid(D1ErrorCode.count_mismatch)
        rows = self._query((_VISIBLE_NA_TURNS_SELECT, (cursor, cursor, limit)))
        next_cursor = str(rows[-1].get("turn_id")) if len(rows) == limit and rows else None
        return rows, next_cursor

    # Stable aliases used by daemon/reconciliation callers.
    upsert_overhead_usage = upsert_overhead
    reconcile_overhead = upsert_overhead
    replace_overhead = upsert_overhead
    publish_overhead = upsert_overhead
    page_na_turns = list_visible_na_turns
    list_na_turns = list_visible_na_turns

    def hide_task(self, task_id: str, reason_code: str) -> HideReceipt:
        task_id = _id(task_id)
        if not isinstance(reason_code, str) or _REASON.fullmatch(reason_code) is None or _PRIVATE_LOCATOR.search(reason_code):
            _invalid()
        current = self._query(_statement(_HEAD_SELECT, task_id))
        head_present = bool(current)
        publication_id: str | None = None
        usage_generation_id: str | None = None
        state: str | None = None
        if current:
            publication_id = _id(current[0].get("publication_id"))
            usage_generation_id = _id(current[0].get("usage_generation_id"))
            state = current[0].get("state") if current[0].get("state") in {"visible", "hidden"} else None
        if publication_id is None:
            rows = self._query(_statement(_VISIBLE_GENERATION_SELECT, task_id))
            if rows:
                publication_id = _id(rows[0].get("publication_id"))
        if usage_generation_id is None:
            rows = self._query(_statement(_VISIBLE_USAGE_GENERATION_SELECT, task_id))
            if rows:
                usage_generation_id = _id(rows[0].get("usage_generation_id"))
        staged = self._query(_statement(_STAGED_GENERATION_SELECT, task_id))
        staged_ids = tuple(_id(row.get("publication_id")) for row in staged)
        staged_usage = self._query(_statement(_STAGED_USAGE_GENERATION_SELECT, task_id))
        staged_usage_ids = tuple(_id(row.get("usage_generation_id")) for row in staged_usage)
        # A concurrent expose can commit between the initial head read and
        # these staged-generation reads. Refresh identifiers before composing
        # the single hide batch so its correction rows include that winner.
        if publication_id is None:
            rows = self._query(_statement(_VISIBLE_GENERATION_SELECT, task_id))
            if rows:
                publication_id = _id(rows[0].get("publication_id"))
        if usage_generation_id is None:
            rows = self._query(_statement(_VISIBLE_USAGE_GENERATION_SELECT, task_id))
            if rows:
                usage_generation_id = _id(rows[0].get("usage_generation_id"))
        if publication_id is None and usage_generation_id is None and not staged and not staged_usage:
            return HideReceipt(task_id, None, changed=False)
        if state == "hidden" and not staged and not staged_usage:
            return HideReceipt(task_id, publication_id, changed=False)
        statements: list[Statement] = []
        # Keep every visibility decision in one D1 transaction. The race
        # statements re-check the head inside that transaction so a generation
        # exposed after the pre-batch reads is retired with its head.
        if staged:
            statements.append(_statement(_HIDE_STAGED, task_id))
        if staged_usage:
            statements.append(_statement(_HIDE_USAGE_STAGED, task_id))
        if head_present:
            statements.append(
                _statement(
                    _HIDE_RACED_VISIBLE_WITH_HEAD,
                    task_id,
                    task_id,
                    publication_id,
                )
            )
            statements.append(
                _statement(
                    _HIDE_USAGE_RACED_VISIBLE_WITH_HEAD,
                    task_id,
                    task_id,
                    usage_generation_id,
                )
            )
        else:
            statements.append(_statement(_HIDE_RACED_VISIBLE_WITHOUT_HEAD, task_id, task_id))
            statements.append(_statement(_HIDE_USAGE_RACED_VISIBLE_WITHOUT_HEAD, task_id, task_id))

        # Materialize a hidden head before retiring its usage generation. This
        # also covers a visible generation that had not yet acquired a head.
        statements.extend(
            (
                _statement(_HIDE_UPSERT, _timestamp_now(), task_id),
                _statement(_USAGE_HIDE_UPSERT, _timestamp_now(), task_id),
            )
        )

        removed_globals: dict[tuple[Any, ...], dict[str, Any]] = {}
        correction_rows: list[tuple[Mapping[str, Any], Mapping[str, Any], dict[str, Any]]] = []
        if usage_generation_id is not None:
            removed_globals.update(self._usage_global_contributions(usage_generation_id))
            unavailable_count = self._usage_unavailable_invocation_count(usage_generation_id)
            stored_globals = {
                self._global_key(row): self._global_db_row(row)
                for row in self._query(_statement(_USAGE_GLOBAL_SELECT, usage_generation_id))
                if row.get("ownership_class") == "task-owned"
            }
            for key, row in stored_globals.items():
                if key in removed_globals:
                    continue
                if unavailable_count:
                    # A visible aggregate may have replaced an unavailable
                    # task row. Reconstruct only its denominator; unknown
                    # token/cost evidence must never be treated as zero.
                    unavailable = dict(row)
                    unavailable["coverage"] = "unavailable"
                    unavailable["coveredInvocations"] = 0
                    unavailable["expectedInvocations"] = unavailable_count
                    unavailable["knownTokenSubtotal"] = None
                    unavailable["knownCostSubtotalMicroUsd"] = None
                    for field in _USAGE_FIELDS:
                        unavailable[field] = None
                    unavailable["priceProvenanceDigest"] = None
                    removed_globals[key] = unavailable
                else:
                    removed_globals[key] = row

            remaining_globals: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
            for raw in self._query(_statement(_VISIBLE_TASK_GLOBAL_SELECT, task_id)):
                row = self._global_db_row(raw)
                remaining_globals.setdefault(self._global_key(row), []).append(row)

            for key in sorted(removed_globals):
                current_rows = self._query(_statement(_GLOBAL_HEAD_KEY_SELECT, *key))
                if not current_rows:
                    continue
                # Rebuild from the surviving immutable task contributions. The
                # current head can be NULL because an unavailable contribution
                # was present, so subtraction alone would turn known survivors
                # into zero instead of restoring their evidence.
                current_row = current_rows[0]
                aggregate = self._global_db_row(current_row)
                corrected = (
                    self._aggregate_global_rows(remaining_globals[key])
                    if remaining_globals.get(key)
                    else self._empty_global_contribution(aggregate)
                )
                corrected["usageGenerationId"] = aggregate["usageGenerationId"]
                corrected["globalId"] = aggregate["globalId"]
                correction_rows.append((current_row, aggregate, corrected))

            statements.append(_statement(_HIDE_USAGE_GENERATION, usage_generation_id, task_id))
            for current_row, target, corrected in correction_rows:
                statements.append(
                    _statement(
                        _GLOBAL_UPDATE,
                        corrected["coverage"],
                        corrected["coveredInvocations"],
                        corrected["expectedInvocations"],
                        corrected["knownTokenSubtotal"],
                        corrected["knownCostSubtotalMicroUsd"],
                        *(corrected[field] for field in _TOKEN_FIELDS),
                        *(corrected[field] for field in _COST_FIELDS),
                        corrected["priceProvenanceDigest"],
                        int(corrected["aggregateOnly"]),
                        target["globalId"],
                    )
                )
                if corrected["expectedInvocations"] > 0:
                    statements.append(
                        _statement(
                            _GLOBAL_HEAD_UPSERT,
                            target["usageGenerationId"],
                            _timestamp_now(),
                            target["globalId"],
                            target["usageGenerationId"],
                        )
                    )
                else:
                    statements.append(
                        _statement(
                            _GLOBAL_HEAD_HIDE,
                            _timestamp_now(),
                            current_row.get("period_kind"),
                            current_row.get("period_key"),
                            current_row.get("model"),
                            current_row.get("ownership_class"),
                            current_row.get("usage_generation_id"),
                            current_row.get("global_id"),
                        )
                    )
        statements.extend(
            (
                _statement(_HIDE_HEAD, _timestamp_now(), task_id),
                _statement(_HIDE_USAGE_HEAD, _timestamp_now(), task_id),
            )
        )
        self._batch(tuple(statements))
        head = self._query(_statement(_HEAD_SELECT, task_id))
        usage_head = self._query(_statement(_USAGE_HEAD_SELECT, task_id))
        if (head_present or publication_id is not None or usage_generation_id is not None) and (len(head) != 1 or head[0].get("state") != "hidden"):
            _invalid(D1ErrorCode.generation_state)
        if (head_present or publication_id is not None or usage_generation_id is not None) and (len(usage_head) != 1 or usage_head[0].get("state") != "hidden"):
            _invalid(D1ErrorCode.generation_state)
        remaining = self._query(_statement(_STAGED_GENERATION_SELECT, task_id))
        remaining_usage = self._query(_statement(_STAGED_USAGE_GENERATION_SELECT, task_id))
        if remaining or remaining_usage:
            _invalid(D1ErrorCode.generation_state)
        visible = self._query(_statement(_VISIBLE_GENERATION_SELECT, task_id))
        if staged_ids and any(row.get("publication_id") in staged_ids for row in visible):
            _invalid(D1ErrorCode.generation_state)
        visible_usage = self._query(_statement(_VISIBLE_USAGE_GENERATION_SELECT, task_id))
        if staged_usage_ids and any(row.get("usage_generation_id") in staged_usage_ids for row in visible_usage):
            _invalid(D1ErrorCode.generation_state)
        effective_publication_id: str | None = publication_id
        if head:
            effective_publication_id = _id(head[0].get("publication_id"))
            if usage_generation_id is not None and _id(head[0].get("usage_generation_id")) != usage_generation_id:
                _invalid(D1ErrorCode.generation_conflict)
            if len(usage_head) != 1 or _id(usage_head[0].get("usage_generation_id")) != _id(head[0].get("usage_generation_id")):
                _invalid(D1ErrorCode.generation_conflict)
            if head[0].get("state") != "hidden":
                _invalid(D1ErrorCode.generation_state)
        changed = bool(staged or staged_usage) or (publication_id is not None and state != "hidden")
        return HideReceipt(task_id, effective_publication_id, changed=changed)


D1Client = D1PublicationClient
PublicationD1Client = D1PublicationClient


__all__ = [
    "D1Client",
    "D1Error",
    "D1ErrorCode",
    "D1PublicationClient",
    "ExposureReceipt",
    "HideReceipt",
    "OverheadReceipt",
    "MAX_BATCH_BYTES",
    "MAX_BATCH_PARAMETERS",
    "MAX_BATCH_STATEMENTS",
    "MAX_RESPONSE_BYTES",
    "PublicationD1Client",
    "StageReceipt",
    "UsageBackfillReceipt",
]
