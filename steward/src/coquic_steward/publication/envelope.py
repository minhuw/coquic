"""Transport-neutral validation and digesting for publication envelopes.

This module owns the closed publication contract independently of any
provider transport.  Callers receive detached data and bounded categories
without source values or diagnostic text leaking across the boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any


class EnvelopeErrorCode(StrEnum):
    """Stable categories for invalid publication envelopes."""

    invalid_request = "invalid_request"
    private_value = "private_value"
    generation_conflict = "generation_conflict"
    generation_state = "generation_state"
    count_mismatch = "count_mismatch"
    digest_mismatch = "digest_mismatch"


class EnvelopeError(ValueError):
    """An envelope failure whose text contains only its category."""

    def __init__(self, code: EnvelopeErrorCode | str):
        try:
            normalized = EnvelopeErrorCode(code)
        except (TypeError, ValueError):
            normalized = EnvelopeErrorCode.invalid_request
        self.code = normalized
        self.category = normalized
        self.reason_code = normalized
        super().__init__(normalized.value)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_DIGEST = re.compile(r"^[0-9a-f]{64}$")

_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")

_PATH = re.compile(r"^(?!/)(?!.*://)(?!.*\.\.)[^\x00-\x1f]{1,1024}$")

_MEDIA = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")

_PUBLIC_KEY = re.compile(r"^v1/tasks/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$")

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

_SAFE_INTEGER_MAX = 9_007_199_254_740_991

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

def _invalid(code: EnvelopeErrorCode = EnvelopeErrorCode.invalid_request) -> None:
    raise EnvelopeError(code)


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
        _invalid(EnvelopeErrorCode.private_value)
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
            _invalid(EnvelopeErrorCode.private_value)
        if _PRIVATE_LOCATOR.search(value):
            _invalid(EnvelopeErrorCode.private_value)
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
        _invalid(EnvelopeErrorCode.generation_conflict)
    return value


def _usage_math(row: Mapping[str, Any], *, nullable: bool = True) -> None:
    values: dict[str, int | None] = {}
    for field in _USAGE_FIELDS:
        values[field] = _usage_integer(row[field], allow_none=nullable)
    tokens = tuple(values[field] for field in _TOKEN_FIELDS)
    if all(value is not None for value in tokens):
        prompt, cached, uncached, completion, reasoning, total = tokens
        if cached > prompt or uncached != prompt - cached or reasoning > completion or total != prompt + completion:
            _invalid(EnvelopeErrorCode.generation_conflict)
    costs = tuple(values[field] for field in _COST_FIELDS)
    if any(value is None for value in costs) and any(value is not None for value in costs):
        _invalid(EnvelopeErrorCode.generation_conflict)


def _usage_price_in_range(price: Mapping[str, Any], started_at: str | None) -> None:
    if started_at is None:
        return
    effective_at = datetime.fromisoformat(price["effectiveAt"].replace("Z", "+00:00"))
    effective_until = price["effectiveUntil"]
    started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    if started < effective_at or (effective_until is not None and started >= datetime.fromisoformat(effective_until.replace("Z", "+00:00"))):
        _invalid(EnvelopeErrorCode.generation_conflict)


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


def _validate_usage(
    payload: Mapping[str, Any],
    pipeline_ids: set[str],
    run_ids: set[str],
) -> None:
    usage = _mapping(payload["usage"])
    _keys(usage, _USAGE)
    if usage["schemaVersion"] != "1.0":
        _invalid(EnvelopeErrorCode.generation_conflict)
    usage_generation = _mapping(usage["generation"])
    _keys(usage_generation, _USAGE_GENERATION)
    publication_id = payload["publicationId"]
    task_id = payload["taskId"]
    usage_generation_id = _id(usage_generation["usageGenerationId"])
    if _id(usage_generation["publicationId"]) != publication_id or _id(usage_generation["taskId"]) != task_id:
        _invalid(EnvelopeErrorCode.generation_conflict)
    if usage_generation["schemaVersion"] != "1.0" or usage_generation["state"] != "staged":
        _invalid(EnvelopeErrorCode.generation_state)
    _digest(usage_generation["metadataDigest"])
    _timestamp(usage_generation["createdAt"])
    counts = _mapping(usage_generation["expectedCounts"])
    _keys(counts, _USAGE_COUNTS)
    limits = {"summaries": 4096, "invocations": 128, "turns": 4096, "prices": 4096, "globals": 4096}
    for name, maximum in limits.items():
        _usage_integer(counts[name], allow_none=False, maximum=maximum)
    if counts["summaries"] < 1:
        _invalid(EnvelopeErrorCode.count_mismatch)
    if usage_generation["metadataDigest"] != _usage_metadata_digest(payload):
        _invalid(EnvelopeErrorCode.digest_mismatch)

    collections = {name: usage[name] for name in ("summaries", "invocations", "turns", "prices", "globals")}
    for name, values in collections.items():
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            _invalid(EnvelopeErrorCode.invalid_request)
        if len(values) != counts[name]:
            _invalid(EnvelopeErrorCode.count_mismatch)
        if name == "summaries" and not values:
            _invalid(EnvelopeErrorCode.count_mismatch)

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
            _invalid(EnvelopeErrorCode.generation_conflict)
        summary_ids.add(summary_id)
        if _id(row["usageGenerationId"]) != usage_generation_id or _id(row["publicationId"]) != publication_id or _id(row["taskId"]) != task_id:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["scope"] not in {"task", "run"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["scope"] == "task":
            if row["runId"] is not None:
                _invalid(EnvelopeErrorCode.generation_conflict)
        elif row["runId"] is None or _id(row["runId"]) not in run_ids:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        covered = _usage_integer(row["coveredInvocations"], allow_none=False)
        expected = _usage_integer(row["expectedInvocations"], allow_none=False)
        if covered > expected:
            _invalid(EnvelopeErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "complete" and covered != expected:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["coverage"] == "unavailable" and (row["knownTokenSubtotal"] is not None or row["knownCostSubtotalMicroUsd"] is not None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["knownTokenSubtotal"] is not None:
            _usage_integer(row["knownTokenSubtotal"])
        if row["knownCostSubtotalMicroUsd"] is not None:
            _usage_integer(row["knownCostSubtotalMicroUsd"])
        if row["priceProvenanceDigest"] is not None:
            _digest(row["priceProvenanceDigest"])
        if row["totalTokens"] is not None and row["knownTokenSubtotal"] is not None and row["totalTokens"] != row["knownTokenSubtotal"]:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["totalCostMicroUsd"] is not None and row["knownCostSubtotalMicroUsd"] is not None and row["totalCostMicroUsd"] != row["knownCostSubtotalMicroUsd"]:
            _invalid(EnvelopeErrorCode.generation_conflict)
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
                _invalid(EnvelopeErrorCode.generation_conflict)
            invocation_ids.add(invocation_id)
            invocation_by_id[invocation_id] = row
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(EnvelopeErrorCode.generation_conflict)
        ownership = row["ownershipClass"]
        if ownership == "task-owned":
            if _id(row["publicationId"]) != publication_id or _id(row["taskId"]) != task_id or _id(row["pipelineId"]) not in pipeline_ids or _id(row["runId"]) not in run_ids:
                _invalid(EnvelopeErrorCode.generation_conflict)
            group = (row["runId"], ownership)
        elif ownership == "steward-overhead":
            if any(row[field] is not None for field in ("publicationId", "taskId", "pipelineId", "runId")) or row["coveredTurns"] != 0 or row["expectedTurns"] != 0:
                _invalid(EnvelopeErrorCode.generation_conflict)
            group = ("overhead", ownership)
        else:
            _invalid(EnvelopeErrorCode.generation_conflict)
        ordinal = _usage_integer(row["retryOrdinal"], allow_none=False)
        ordinal_groups.setdefault(group, []).append(ordinal)
        started_at = row["startedAt"]
        completed_at = row["completedAt"]
        if (started_at is None) != (completed_at is None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if started_at is not None:
            _timestamp(started_at)
            _timestamp(completed_at)
            if datetime.fromisoformat(completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(started_at.replace("Z", "+00:00")):
                _invalid(EnvelopeErrorCode.generation_conflict)
        if row["model"] is not None:
            _text(row["model"], maximum=256)
        if row["billingMode"] not in {None, "unknown", "chatgpt", "api"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["processOutcome"] is not None:
            _text(row["processOutcome"], maximum=48)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        _usage_integer(row["issueCount"], allow_none=False)
        covered_turns = _usage_integer(row["coveredTurns"], allow_none=False, maximum=4096)
        expected_turns = _usage_integer(row["expectedTurns"], allow_none=False, maximum=4096)
        if covered_turns > expected_turns or (row["coverage"] == "complete" and covered_turns != expected_turns):
            _invalid(EnvelopeErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "unavailable" and any(row[field] is not None for field in _USAGE_FIELDS):
            _invalid(EnvelopeErrorCode.generation_conflict)
        costs_known = all(row[field] is not None for field in _COST_FIELDS)
        if costs_known != (row["priceEntryDigest"] is not None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["priceEntryDigest"] is not None:
            _digest(row["priceEntryDigest"])
        if invocation_id is None and row["coverage"] != "unavailable":
            _invalid(EnvelopeErrorCode.generation_conflict)
        invocation_rows.append(row)
    for ordinals in ordinal_groups.values():
        if sorted(ordinals) != list(range(len(ordinals))):
            _invalid(EnvelopeErrorCode.generation_conflict)

    price_map: dict[str, Mapping[str, Any]] = {}
    intervals: dict[str, list[tuple[datetime, datetime | None]]] = {}
    for item in prices:
        row = _mapping(item)
        _keys(row, _PRICE)
        digest = _digest(row["priceEntryDigest"])
        if digest in price_map:
            _invalid(EnvelopeErrorCode.generation_conflict)
        price_map[digest] = row
        _digest(row["catalogDigest"])
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(EnvelopeErrorCode.generation_conflict)
        _text(row["model"], maximum=256)
        _timestamp(row["effectiveAt"])
        if row["effectiveUntil"] is not None:
            _timestamp(row["effectiveUntil"])
            if datetime.fromisoformat(row["effectiveUntil"].replace("Z", "+00:00")) <= datetime.fromisoformat(row["effectiveAt"].replace("Z", "+00:00")):
                _invalid(EnvelopeErrorCode.generation_conflict)
        start = datetime.fromisoformat(row["effectiveAt"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(row["effectiveUntil"].replace("Z", "+00:00")) if row["effectiveUntil"] is not None else None
        intervals.setdefault(row["model"], []).append((start, end))
    for entries in intervals.values():
        entries.sort(key=lambda item: item[0])
        for previous, current in zip(entries, entries[1:]):
            if previous[1] is None or current[0] < previous[1]:
                _invalid(EnvelopeErrorCode.generation_conflict)

    for row in invocation_rows:
        if row["priceEntryDigest"] is not None:
            price = price_map.get(row["priceEntryDigest"])
            if price is None or row["model"] != price["model"]:
                _invalid(EnvelopeErrorCode.generation_conflict)
            _usage_price_in_range(price, row["startedAt"])

    turn_ids: set[str] = set()
    turns_by_invocation: dict[str, list[Mapping[str, Any]]] = {}
    for item in turns:
        row = _mapping(item)
        _keys(row, _TURN)
        turn_id = _id(row["turnId"])
        if turn_id in turn_ids:
            _invalid(EnvelopeErrorCode.generation_conflict)
        turn_ids.add(turn_id)
        invocation_id = _id(row["invocationId"])
        invocation = invocation_by_id.get(invocation_id)
        if invocation is None or invocation["ownershipClass"] != "task-owned":
            _invalid(EnvelopeErrorCode.generation_conflict)
        if any(_id(row[field]) != invocation[field] for field in ("usageGenerationId", "publicationId", "taskId", "runId")):
            _invalid(EnvelopeErrorCode.generation_conflict)
        ordinal = _usage_integer(row["ordinal"], allow_none=False, maximum=4096)
        for field in _TOKEN_FIELDS:
            _usage_integer(row[field], allow_none=False)
        _usage_math(row)
        costs_known = all(row[field] is not None for field in _COST_FIELDS)
        if costs_known != (row["priceEntryDigest"] is not None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["priceEntryDigest"] is not None:
            _digest(row["priceEntryDigest"])
            price = price_map.get(row["priceEntryDigest"])
            if price is None or invocation["model"] != price["model"]:
                _invalid(EnvelopeErrorCode.generation_conflict)
            _usage_price_in_range(price, invocation["startedAt"])
        turns_by_invocation.setdefault(invocation_id, []).append(row)
    for invocation_id, invocation_turns in turns_by_invocation.items():
        if sorted(turn["ordinal"] for turn in invocation_turns) != list(range(1, len(invocation_turns) + 1)):
            _invalid(EnvelopeErrorCode.generation_conflict)
        invocation = invocation_by_id[invocation_id]
        if invocation["coveredTurns"] != len(invocation_turns):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if invocation["coverage"] == "complete":
            totals = {field: sum(turn[field] for turn in invocation_turns) for field in _USAGE_FIELDS}
            if any(invocation[field] != totals[field] for field in _USAGE_FIELDS):
                _invalid(EnvelopeErrorCode.generation_conflict)
    for invocation in invocation_rows:
        if invocation["invocationId"] is not None and invocation["invocationId"] not in turns_by_invocation and invocation["coveredTurns"] != 0:
            _invalid(EnvelopeErrorCode.generation_conflict)

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
            _invalid(EnvelopeErrorCode.generation_conflict)
        totals = {field: sum(invocation[field] for invocation in selected if invocation[field] is not None) if any(invocation[field] is not None for invocation in selected) else None for field in _USAGE_FIELDS}
        if row["coverage"] == "complete" or any(row[field] is not None for field in _TOKEN_FIELDS):
            for field in _USAGE_FIELDS:
                if row[field] is not None and row[field] != totals[field]:
                    _invalid(EnvelopeErrorCode.generation_conflict)

    global_keys: set[tuple[object, ...]] = set()
    task_owned_global_keys: set[tuple[object, ...]] = set()
    for item in globals_:
        row = _mapping(item)
        _keys(row, _GLOBAL)
        key = (row["periodKind"], row["periodKey"], row["model"], row["ownershipClass"])
        if key in global_keys:
            _invalid(EnvelopeErrorCode.generation_conflict)
        global_keys.add(key)
        if _id(row["usageGenerationId"]) != usage_generation_id:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["periodKind"] == "lifetime" and row["periodKey"] != "lifetime":
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["periodKind"] == "daily" and (not isinstance(row["periodKey"], str) or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", row["periodKey"]) is None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["periodKind"] not in {"lifetime", "daily"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        _text(row["model"], maximum=256)
        if row["ownershipClass"] not in {"task-owned", "steward-overhead"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["coverage"] not in {"complete", "partial", "unavailable"}:
            _invalid(EnvelopeErrorCode.generation_conflict)
        covered = _usage_integer(row["coveredInvocations"], allow_none=False)
        expected = _usage_integer(row["expectedInvocations"], allow_none=False)
        if covered > expected or (row["coverage"] == "complete" and covered != expected):
            _invalid(EnvelopeErrorCode.generation_conflict)
        _usage_math(row)
        if row["coverage"] == "unavailable" and (row["knownTokenSubtotal"] is not None or row["knownCostSubtotalMicroUsd"] is not None):
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["knownTokenSubtotal"] is not None:
            _usage_integer(row["knownTokenSubtotal"])
        if row["knownCostSubtotalMicroUsd"] is not None:
            _usage_integer(row["knownCostSubtotalMicroUsd"])
        if row["totalTokens"] is not None and row["knownTokenSubtotal"] is not None and row["totalTokens"] != row["knownTokenSubtotal"]:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["totalCostMicroUsd"] is not None and row["knownCostSubtotalMicroUsd"] is not None and row["totalCostMicroUsd"] != row["knownCostSubtotalMicroUsd"]:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["ownershipClass"] == "steward-overhead" and row["aggregateOnly"] is not True:
            _invalid(EnvelopeErrorCode.generation_conflict)
        if row["ownershipClass"] == "task-owned" and row["aggregateOnly"] is not True:
            _invalid(EnvelopeErrorCode.generation_conflict)
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
                    _invalid(EnvelopeErrorCode.generation_conflict)
            elif row["coverage"] != "unavailable" or any(row[field] is not None for field in _USAGE_FIELDS):
                # A numeric task-owned aggregate without a matching, verified
                # invocation would otherwise bypass the rollup boundary.
                _invalid(EnvelopeErrorCode.generation_conflict)

    # Every derived task-owned lifetime/daily key must be represented.  The
    # unavailable-only case has no model/date evidence from which to derive a
    # key, so its explicitly unavailable rows remain valid without inventing
    # zero-valued evidence.
    if verified_globals and task_owned_global_keys != set(verified_globals):
        _invalid(EnvelopeErrorCode.generation_conflict)


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
        _invalid(EnvelopeErrorCode.generation_conflict)
    generation_run_id = _id(generation["runId"])
    if generation["state"] != "staged":
        _invalid(EnvelopeErrorCode.generation_state)
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
        _invalid(EnvelopeErrorCode.generation_conflict)
    if head["state"] not in {"visible", "hidden"}:
        _invalid()
    _timestamp(head["updatedAt"])

    task = _mapping(payload["task"])
    _keys(task, _TASK)
    if _id(task["taskId"]) != task_id:
        _invalid(EnvelopeErrorCode.generation_conflict)
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
        _invalid(EnvelopeErrorCode.count_mismatch)

    pipeline_ids: set[str] = set()
    for item in pipelines:
        row = _mapping(item)
        _keys(row, _PIPELINE)
        pipeline_id = _id(row["pipelineId"])
        if pipeline_id in pipeline_ids or _id(row["taskId"]) != task_id:
            _invalid(EnvelopeErrorCode.generation_conflict)
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
            _invalid(EnvelopeErrorCode.generation_conflict)
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
            _invalid(EnvelopeErrorCode.generation_conflict)
        sequence = _integer(row["sequence"], minimum=1)
        if sequence in sequences:
            _invalid(EnvelopeErrorCode.generation_conflict)
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
            _invalid(EnvelopeErrorCode.generation_conflict)
        artifact_ids.add(artifact_id)
        logical_paths.add(logical_path)
        if _id(row["taskId"]) != task_id or _id(row["runId"]) not in run_ids:
            _invalid(EnvelopeErrorCode.generation_conflict)
        public_key = _text(row["publicKey"], maximum=256)
        key_match = _PUBLIC_KEY.fullmatch(public_key)
        if key_match is None or key_match.group(1) != task_id or key_match.group(2) != key_match.group(3)[:2]:
            _invalid(EnvelopeErrorCode.private_value if _PRIVATE_LOCATOR.search(public_key) else EnvelopeErrorCode.invalid_request)
        _text(row["mediaType"], maximum=128)
        if _MEDIA.fullmatch(row["mediaType"]) is None:
            _invalid()
        _integer(row["byteSize"])
        _digest(row["sha256"])
        if key_match.group(3) != row["sha256"]:
            _invalid(EnvelopeErrorCode.digest_mismatch)
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
            _invalid(EnvelopeErrorCode.digest_mismatch)
    if not atif_artifact_ids.issubset(artifact_ids):
        _invalid(EnvelopeErrorCode.generation_conflict)
    if generation_run_id not in run_ids:
        _invalid(EnvelopeErrorCode.generation_conflict)
    _validate_usage(payload, pipeline_ids, run_ids)
    if not allow_usage_replacement and generation["metadataDigest"] != _metadata_digest(payload):
        _invalid(EnvelopeErrorCode.digest_mismatch)
    # Keep the returned object detached from mutable caller containers.
    return json.loads(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def validate_publication_envelope(
    source: Mapping[str, Any],
    *,
    allow_usage_replacement: bool = False,
) -> dict[str, Any]:
    """Validate and detach one publication envelope."""

    try:
        return _validate_payload(source, allow_usage_replacement=allow_usage_replacement)
    except EnvelopeError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise EnvelopeError(EnvelopeErrorCode.invalid_request) from None


def publication_metadata_digest(payload: Mapping[str, Any]) -> str:
    """Return the canonical digest of publication metadata."""

    return _metadata_digest(payload)


def usage_metadata_digest(payload: Mapping[str, Any]) -> str:
    """Return the canonical digest of usage metadata."""

    return _usage_metadata_digest(payload)


def detached_publication_envelope(source: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached publication envelope copy."""

    return validate_publication_envelope(source)


__all__ = [
    "EnvelopeError",
    "EnvelopeErrorCode",
    "detached_publication_envelope",
    "publication_metadata_digest",
    "usage_metadata_digest",
    "validate_publication_envelope",
]
