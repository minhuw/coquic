"""Bounded, public-safe staging for the Steward Cloudflare D1 schema.

The publisher hands this module one already-sanitized publication envelope.  This
module owns the transport boundary and the visibility protocol only: SQL is fixed
in this file, all values are bound parameters, staging is replayable, and the
single final batch is the only operation that can change a public head.
"""

from __future__ import annotations

import hashlib
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
    def post(self, url: str, **kwargs: Any) -> D1Response: ...


@dataclass(frozen=True, slots=True)
class StageReceipt:
    publication_id: str
    task_id: str
    run_id: str
    staged: bool = True


@dataclass(frozen=True, slots=True)
class ExposureReceipt:
    publication_id: str
    task_id: str
    state: str = "visible"


@dataclass(frozen=True, slots=True)
class HideReceipt:
    task_id: str
    publication_id: str | None
    state: str = "hidden"
    changed: bool = True


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

    for row in summary_rows:
        selected = [
            invocation
            for invocation in invocation_rows
            if invocation["ownershipClass"] == "task-owned" and (row["scope"] == "task" or invocation["runId"] == row["runId"])
        ]
        if row["coveredInvocations"] != len(selected):
            _invalid(D1ErrorCode.generation_conflict)
        totals = {field: sum(invocation[field] for invocation in selected if invocation[field] is not None) if any(invocation[field] is not None for invocation in selected) else None for field in _USAGE_FIELDS}
        if row["coverage"] == "complete" or any(row[field] is not None for field in _TOKEN_FIELDS):
            for field in _USAGE_FIELDS:
                if row[field] is not None and row[field] != totals[field]:
                    _invalid(D1ErrorCode.generation_conflict)

    global_keys: set[tuple[object, ...]] = set()
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
        _bool(row["aggregateOnly"])
        if row["priceProvenanceDigest"] is not None:
            _digest(row["priceProvenanceDigest"])


def _validate_payload(source: Mapping[str, Any]) -> dict[str, Any]:
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
    if generation["metadataDigest"] != _metadata_digest(payload):
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
    "(usage_generation_id, publication_id, task_id, schema_version, metadata_digest, state, "
    "expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, "
    "expected_global_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?, ?) "
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
    "SELECT usage_generation_id, publication_id, task_id, schema_version, metadata_digest, state, "
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
    "SELECT u.state, u.metadata_digest, u.expected_summary_count, u.expected_invocation_count, "
    "u.expected_turn_count, u.expected_price_count, u.expected_global_count, "
    "(SELECT count(*) FROM usage_summaries WHERE usage_generation_id = u.usage_generation_id) AS summary_count, "
    "(SELECT count(*) FROM usage_invocations WHERE usage_generation_id = u.usage_generation_id) AS invocation_count, "
    "(SELECT count(*) FROM usage_turns WHERE usage_generation_id = u.usage_generation_id) AS turn_count, "
    "(SELECT count(*) FROM usage_prices WHERE usage_generation_id = u.usage_generation_id) AS price_count, "
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
_USAGE_PRICE_SELECT = "SELECT price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until FROM usage_prices WHERE usage_generation_id = ? ORDER BY price_entry_digest"
_USAGE_GLOBAL_SELECT = "SELECT global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only FROM usage_globals WHERE usage_generation_id = ? ORDER BY global_id"
_HEAD_SELECT = "SELECT publication_id, usage_generation_id, state FROM task_heads WHERE task_id = ?"
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
_STAGED_GENERATION_SELECT = "SELECT publication_id FROM publication_generations WHERE task_id = ? AND state = 'staged'"
_STAGED_USAGE_GENERATION_SELECT = "SELECT usage_generation_id FROM usage_generations WHERE task_id = ? AND state = 'staged'"


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
        self._client: D1HttpClient = http_client or httpx.Client(transport=transport, timeout=self.timeout_seconds)

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
        if self._owned_client and hasattr(self._client, "close"):
            self._client.close()  # type: ignore[attr-defined]

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
        status = int(getattr(response, "status_code", 0))
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

    def _verify_usage_generation(self, payload: Mapping[str, Any]) -> str:
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
        if actual[5] == "superseded":
            _invalid(D1ErrorCode.generation_state)
        if actual != expected and not (actual[:5] == expected[:5] and actual[6:] == expected[6:] and actual[5] == "visible"):
            _invalid(D1ErrorCode.generation_conflict)
        if actual[5] not in {"staged", "visible"}:
            _invalid(D1ErrorCode.generation_state)
        return actual[5]

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
                _statement(_USAGE_PRICE_SELECT, usage_id),
                tuple(
                    (
                        item["priceEntryDigest"],
                        item["usageGenerationId"],
                        item["catalogDigest"],
                        item["model"],
                        item["effectiveAt"],
                        item["effectiveUntil"],
                    )
                    for item in usage["prices"]
                ),
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
            if name == "invocations":
                sort_key = lambda value: (value[0] is not None, value[0] or "")
            else:
                sort_key = lambda value: value[0]
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

    def stage(self, source: Mapping[str, Any]) -> StageReceipt:
        payload = _validate_payload(source)
        self._verify_existing_generation(payload)
        self._verify_existing_usage_generation(payload)
        self._verify_unique_generation_keys(payload)
        self._verify_unique_usage_keys(payload)
        for chunk in self._chunks(self._stage_statements(payload)):
            self._batch(chunk)
        self._verify_generation(payload)
        self._verify_rows(payload)
        self._verify_usage_generation(payload)
        self._verify_usage_rows(payload)
        return StageReceipt(payload["publicationId"], payload["taskId"], payload["generation"]["runId"])

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

    def _verify_existing_usage_generation(self, payload: Mapping[str, Any]) -> None:
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
            if actual != expected and not (actual[:5] == expected[:5] and actual[6:] == expected[6:] and actual[5] == "visible"):
                _invalid(D1ErrorCode.generation_conflict)
            if row.get("state") not in {"staged", "visible"}:
                _invalid(D1ErrorCode.generation_state)

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

    def expose(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        if payload["headIntent"]["state"] != "visible":
            _invalid(D1ErrorCode.generation_state)
        generation_state = self._verify_generation(payload)
        usage_state = self._verify_usage_generation(payload)
        self._verify_rows(payload)
        self._verify_usage_rows(payload)
        current = self._query(_statement(_VISIBLE_HEAD_SELECT, payload["taskId"]))
        if current and current[0].get("publication_id") == payload["publicationId"]:
            usage_id = payload["usage"]["generation"]["usageGenerationId"]
            usage_head = self._query(_statement(_USAGE_HEAD_SELECT, payload["taskId"]))
            if current[0].get("usage_generation_id") != usage_id or len(usage_head) != 1 or usage_head[0].get("usage_generation_id") != usage_id:
                _invalid(D1ErrorCode.generation_conflict)
            if current[0].get("state") == "visible":
                if usage_head[0].get("state") != "visible":
                    _invalid(D1ErrorCode.generation_state)
                return ExposureReceipt(payload["publicationId"], payload["taskId"])
            if current[0].get("state") == "hidden":
                if usage_head[0].get("state") != "hidden":
                    _invalid(D1ErrorCode.generation_state)
                return ExposureReceipt(payload["publicationId"], payload["taskId"], state="hidden")
            _invalid(D1ErrorCode.generation_state)
        if generation_state != "staged" or usage_state != "staged":
            _invalid(D1ErrorCode.generation_state)
        updated_at = payload["headIntent"]["updatedAt"]
        usage_id = payload["usage"]["generation"]["usageGenerationId"]
        self._batch(
            (
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
                _statement(_EXPOSE_NEW, updated_at, payload["publicationId"], payload["taskId"]),
                _statement(_EXPOSE_NEW_USAGE, updated_at, usage_id, payload["taskId"]),
                _statement(_USAGE_HEAD_UPSERT, payload["taskId"], usage_id, updated_at),
                _statement(_HEAD_UPSERT, usage_id, updated_at, payload["publicationId"], payload["taskId"]),
            )
        )
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
        return ExposureReceipt(payload["publicationId"], payload["taskId"])

    def publish(self, source: Mapping[str, Any]) -> ExposureReceipt:
        payload = _validate_payload(source)
        self.stage(payload)
        return self.expose(payload)

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
        if publication_id is None and usage_generation_id is None and not staged and not staged_usage:
            return HideReceipt(task_id, None, changed=False)
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
        statements.extend(
            (
                _statement(_HIDE_UPSERT, _timestamp_now(), task_id),
                _statement(_USAGE_HIDE_UPSERT, _timestamp_now(), task_id),
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
    "MAX_BATCH_BYTES",
    "MAX_BATCH_PARAMETERS",
    "MAX_BATCH_STATEMENTS",
    "MAX_RESPONSE_BYTES",
    "PublicationD1Client",
    "StageReceipt",
]
