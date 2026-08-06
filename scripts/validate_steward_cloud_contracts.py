#!/usr/bin/env python3
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import math
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from jsonschema import Draft202012Validator
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "steward-cloud" / "atif-v1.7.schema.json"
PUBLICATION_SCHEMA_PATH = ROOT / "contracts" / "steward-cloud" / "publication.schema.json"
D1_SCHEMA_PATH = ROOT / "contracts" / "steward-cloud" / "d1.sql"
FIXTURE_DIR = ROOT / "contracts" / "steward-cloud" / "fixtures"
SUPPORTED_IMAGES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_PUBLIC_INVOCATIONS = 128
MAX_PUBLIC_INVOCATION_TURNS = 4_096
MAX_PUBLIC_INVOCATION_ISSUES = 32
MAX_PUBLIC_INVOCATION_TOKENS = 10**15
PUBLIC_USAGE_KEYS = {"prompt", "cached", "uncached", "completion", "reasoning", "total"}
SAFE_INTEGER_MAX = 9007199254740991
USAGE_TOKEN_FIELDS = (
    "promptTokens",
    "cachedTokens",
    "uncachedTokens",
    "completionTokens",
    "reasoningTokens",
    "totalTokens",
)
USAGE_COST_FIELDS = (
    "uncachedInputCostMicroUsd",
    "cachedInputCostMicroUsd",
    "outputCostMicroUsd",
    "totalCostMicroUsd",
)
USAGE_ALL_FIELDS = USAGE_TOKEN_FIELDS + USAGE_COST_FIELDS
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_KEY_PATTERN = re.compile(
    r"^v1/tasks/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"^v1/originals/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/sha256/([0-9a-f]{64})\.jsonl$"
)
PRIVATE_NAME = re.compile(
    r"(?:bucket|objectkey|credential|secret|password|token|authorization|apikey|private)",
    re.IGNORECASE,
)
SAFE_USAGE_FIELDS = {
    "prompttokens", "cachedtokens", "uncachedtokens", "completiontokens",
    "reasoningtokens", "totaltokens", "knowntokensubtotal", "knowncostsubtotalmicrousd",
    "uncachedinputcostmicrousd", "cachedinputcostmicrousd", "outputcostmicrousd",
    "totalcostmicrousd", "priceentrydigest", "priceprovenancedigest", "usagenerationid",
    "usagegeneration", "usagesummaries", "usageinvocations", "usageturns", "usageprices",
    "usageglobals", "ownershipclass", "coveredinvocations", "expectedinvocations",
    "coveredturns", "expectedturns", "retryordinal", "issuecount", "billingmode",
}
EXPECTED_D1_TABLES = {
    "publication_generations", "task_heads", "tasks", "pipelines", "runs", "task_events", "artifacts",
    "usage_generations", "usage_heads", "usage_summaries", "usage_invocations", "usage_turns",
    "usage_prices", "usage_globals", "usage_global_heads",
}
PRIVATE_VALUE = re.compile(
    r"(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?)://|"
    r"^(?:~[/\\]|[A-Za-z]:[/\\]|\\\\)|"
    r"(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]key)?|url|path)(?:$|[-_])",
    re.IGNORECASE,
)
@dataclass(frozen=True)
class Issue:
    rule: str
    path: tuple[Any, ...] = ()
    def rendered(self) -> str:
        value = "$"
        for part in self.path:
            value += f"[{part}]" if isinstance(part, int) else f".{part}"
        return f"{self.rule} at {value}"
class DuplicateKey(ValueError):
    pass
def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey
        result[key] = value
    return result
def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
def _add(issues: set[Issue], rule: str, path: Iterable[Any] = ()) -> None:
    issues.add(Issue(rule, tuple(path)))


def _issue_sort_key(issue: Issue) -> tuple[tuple[str, ...], str]:
    return tuple(str(part) for part in issue.path), issue.rule
def _nonempty_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_PATTERN.fullmatch(value))
def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
def _private_scan(value: Any, path: tuple[Any, ...], issues: set[Issue], key: str | None = None) -> None:
    if key is not None:
        compact = re.sub(r"[^a-z0-9]", "", key.lower())
        if compact not in SAFE_USAGE_FIELDS and (PRIVATE_NAME.search(compact) or compact in {"url", "uri", "endpoint", "baseurl", "baseuri"}):
            _add(issues, "private-field", path)
        if compact in {"trajectorypath", "filepath", "credentialpath", "privatepath"}:
            _add(issues, "private-locator", path)
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _private_scan(child_value, path + (child_key,), issues, str(child_key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _private_scan(child, path + (index,), issues, key)
        return
    if isinstance(value, str):
        if value.startswith("/") or (key is not None and compact == "mediatype" and value.lower().startswith("image/") and value not in SUPPORTED_IMAGES): _add(issues, "private-locator" if value.startswith("/") else "media-type", path)
        if PRIVATE_VALUE.search(value):
            _add(issues, "private-locator", path)
        if key is not None and key.lower().endswith("path") and compact != "logicalpath" and not value.startswith("artifact:"):
            _add(issues, "private-locator", path)
def _schema_issues(document: Any, validator: Draft202012Validator) -> set[Issue]:
    issues: set[Issue] = set()
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.validator),
    )
    for error in errors:
        _add(issues, f"schema-{error.validator}", error.absolute_path)
    return issues
def _check_content(
    content: Any, path: tuple[Any, ...], step_id: int,
    artifacts: dict[str, tuple[dict[str, Any], tuple[Any, ...]]], referenced: set[str], issues: set[Issue],
) -> None:
    if not isinstance(content, list):
        return
    for index, part in enumerate(content):
        part_path = path + (index,)
        if not isinstance(part, dict):
            continue
        part_type = part.get("type")
        if part_type == "text":
            if not isinstance(part.get("text"), str) or part.get("source") is not None:
                _add(issues, "content-shape", part_path)
            continue
        if part_type != "image":
            continue
        source = part.get("source")
        if not isinstance(source, dict):
            _add(issues, "media-type", part_path + ("source",))
            continue
        media_type = source.get("media_type")
        if media_type not in SUPPORTED_IMAGES:
            _add(issues, "media-type", part_path + ("source", "media_type"))
        logical = source.get("path")
        if not isinstance(logical, str) or not logical.startswith("artifact:"):
            _add(issues, "artifact-reference", part_path + ("source", "path"))
            continue
        artifact_id = logical.removeprefix("artifact:")
        descriptor = artifacts.get(artifact_id)
        if descriptor is None:
            _add(issues, "artifact-reference", part_path + ("source", "path"))
            continue
        referenced.add(artifact_id)
        item, item_path = descriptor
        if item.get("ownerStepId") != step_id:
            _add(issues, "artifact-owner", item_path + ("ownerStepId",))
        if item.get("mediaType") != media_type:
            _add(issues, "artifact-media-type", item_path + ("mediaType",))
def _check_artifacts(
    coqui: dict[str, Any], steps: list[Any], issues: set[Issue],
) -> None:
    raw_artifacts = coqui.get("artifacts")
    if not isinstance(raw_artifacts, list):
        _add(issues, "artifact-shape", ("extra", "coquic", "artifacts"))
        return
    artifacts: dict[str, tuple[dict[str, Any], tuple[Any, ...]]] = {}
    step_ids = {step.get("step_id") for step in steps if isinstance(step, dict)}
    for index, item in enumerate(raw_artifacts):
        item_path = ("extra", "coquic", "artifacts", index)
        if not isinstance(item, dict):
            _add(issues, "artifact-shape", item_path)
            continue
        required = {"artifactId", "mediaType", "sha256", "byteSize", "ownerStepId"}
        if set(item) != required:
            _add(issues, "artifact-shape", item_path)
        artifact_id = item.get("artifactId")
        if not _nonempty_id(artifact_id):
            _add(issues, "artifact-id", item_path + ("artifactId",))
        elif artifact_id in artifacts:
            _add(issues, "artifact-unique", item_path + ("artifactId",))
        else:
            artifacts[artifact_id] = (item, item_path)
        media_type = item.get("mediaType")
        if not isinstance(media_type, str) or not media_type or any(char.isspace() for char in media_type):
            _add(issues, "artifact-media-type", item_path + ("mediaType",))
        elif media_type.startswith("image/") and media_type not in SUPPORTED_IMAGES:
            _add(issues, "media-type", item_path + ("mediaType",))
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            _add(issues, "artifact-digest", item_path + ("sha256",))
        size = item.get("byteSize")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            _add(issues, "artifact-size", item_path + ("byteSize",))
        owner = item.get("ownerStepId")
        if not isinstance(owner, int) or isinstance(owner, bool) or owner not in step_ids:
            _add(issues, "artifact-owner", item_path + ("ownerStepId",))

    referenced: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        step_id = step.get("step_id")
        step_extra = step.get("extra")
        step_extra = step_extra if isinstance(step_extra, dict) and isinstance(step_extra.get("coquic"), dict) else {"coquic": {}}
        if not isinstance(step_extra, dict):
            continue
        step_coqui = step_extra.get("coquic")
        if not isinstance(step_coqui, dict):
            continue
        refs = step_coqui.get("artifactIds", [])
        if not isinstance(refs, list):
            _add(issues, "artifact-reference", ("steps", index, "extra", "coquic", "artifactIds"))
        else:
            for ref_index, artifact_id in enumerate(refs):
                ref_path = ("steps", index, "extra", "coquic", "artifactIds", ref_index)
                if not isinstance(artifact_id, str) or artifact_id not in artifacts:
                    _add(issues, "artifact-reference", ref_path)
                    continue
                referenced.add(artifact_id)
                item, item_path = artifacts[artifact_id]
                if item.get("ownerStepId") != step_id:
                    _add(issues, "artifact-owner", item_path + ("ownerStepId",))
        _check_content(step.get("message"), ("steps", index, "message"), step_id, artifacts, referenced, issues)
        observation = step.get("observation")
        if isinstance(observation, dict):
            for result_index, result in enumerate(observation.get("results", [])):
                if isinstance(result, dict):
                    _check_content(
                        result.get("content"),
                        ("steps", index, "observation", "results", result_index, "content"), step_id, artifacts, referenced, issues,
                    )
    for artifact_id, (_, item_path) in artifacts.items():
        if artifact_id not in referenced:
            _add(issues, "artifact-unreferenced", item_path)


def _check_invocations(
    source: dict[str, Any], coqui: dict[str, Any], issues: set[Issue]
) -> None:
    raw_invocations = source.get("invocations")
    base_path = ("extra", "coquic", "source", "invocations")
    if not isinstance(raw_invocations, list):
        _add(issues, "invocation-shape", base_path)
        return
    if not raw_invocations or len(raw_invocations) > MAX_PUBLIC_INVOCATIONS:
        _add(issues, "invocation-bound", base_path)
        return
    required = {
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
    seen_ids: set[str] = set()
    for index, invocation in enumerate(raw_invocations):
        path = base_path + (index,)
        if not isinstance(invocation, dict) or set(invocation) != required:
            _add(issues, "invocation-shape", path)
            continue
        for key in ("taskId", "pipelineId", "runId"):
            if invocation.get(key) != coqui.get(key):
                _add(issues, "invocation-ownership", path + (key,))
        invocation_id = invocation.get("invocationId")
        if invocation_id is not None:
            if not _nonempty_id(invocation_id):
                _add(issues, "invocation-id", path + ("invocationId",))
            elif invocation_id in seen_ids:
                _add(issues, "invocation-unique", path + ("invocationId",))
            else:
                seen_ids.add(invocation_id)
        ordinal = invocation.get("retryOrdinal")
        if type(ordinal) is not int or ordinal != index or ordinal < 0:
            _add(issues, "invocation-ordinal", path + ("retryOrdinal",))
        started = invocation.get("startedAt")
        completed = invocation.get("completedAt")
        if (started is None) != (completed is None):
            _add(issues, "invocation-timing", path)
        started_value = _timestamp(started) if started is not None else None
        completed_value = _timestamp(completed) if completed is not None else None
        if started is not None and started_value is None:
            _add(issues, "invocation-timing", path + ("startedAt",))
        if completed is not None and completed_value is None:
            _add(issues, "invocation-timing", path + ("completedAt",))
        if started_value is not None and completed_value is not None and completed_value < started_value:
            _add(issues, "invocation-timing-order", path + ("completedAt",))
        model = invocation.get("model")
        if model is not None and (not isinstance(model, str) or not model or len(model) > 256):
            _add(issues, "invocation-model", path + ("model",))
        billing_mode = invocation.get("billingMode")
        if billing_mode not in {None, "unknown", "chatgpt", "api"}:
            _add(issues, "invocation-billing", path + ("billingMode",))
        outcome = invocation.get("processOutcome")
        if outcome is not None and (not isinstance(outcome, str) or not outcome or len(outcome) > 48):
            _add(issues, "invocation-outcome", path + ("processOutcome",))
        coverage = invocation.get("coverage")
        if coverage not in {"complete", "partial", "unavailable"}:
            _add(issues, "invocation-coverage", path + ("coverage",))
        if invocation_id is None and coverage != "unavailable":
            _add(issues, "invocation-id", path + ("invocationId",))

        raw_issues = invocation.get("issues")
        if not isinstance(raw_issues, list) or len(raw_issues) > MAX_PUBLIC_INVOCATION_ISSUES:
            _add(issues, "invocation-issues", path + ("issues",))
        else:
            categories: set[str] = set()
            for issue_index, issue in enumerate(raw_issues):
                issue_path = path + ("issues", issue_index)
                if (
                    not isinstance(issue, dict)
                    or set(issue) != {"category", "count"}
                    or not isinstance(issue.get("category"), str)
                    or not issue.get("category")
                    or len(issue["category"]) > 96
                    or issue["category"] in categories
                    or type(issue.get("count")) is not int
                    or issue["count"] < 1
                    or issue["count"] > MAX_PUBLIC_INVOCATION_TOKENS
                ):
                    _add(issues, "invocation-issues", issue_path)
                elif isinstance(issue.get("category"), str):
                    categories.add(issue["category"])

        turns = invocation.get("turns")
        if not isinstance(turns, list) or len(turns) > MAX_PUBLIC_INVOCATION_TURNS:
            _add(issues, "invocation-turns", path + ("turns",))
            turns = []
        sums = {key: 0 for key in PUBLIC_USAGE_KEYS}
        turn_keys = {"ordinal", *PUBLIC_USAGE_KEYS}
        for turn_index, turn in enumerate(turns, start=1):
            turn_path = path + ("turns", turn_index - 1)
            if not isinstance(turn, dict) or set(turn) != turn_keys or turn.get("ordinal") != turn_index:
                _add(issues, "invocation-turn", turn_path)
                continue
            if any(type(turn.get(key)) is not int or turn[key] < 0 or turn[key] > MAX_PUBLIC_INVOCATION_TOKENS for key in PUBLIC_USAGE_KEYS):
                _add(issues, "invocation-turn", turn_path)
                continue
            if turn["cached"] > turn["prompt"] or turn["uncached"] != turn["prompt"] - turn["cached"] or turn["reasoning"] > turn["completion"] or turn["total"] != turn["prompt"] + turn["completion"]:
                _add(issues, "invocation-math", turn_path)
            for key in sums:
                sums[key] += turn[key]

        aggregate = invocation.get("aggregate")
        usage = aggregate.get("usage") if isinstance(aggregate, dict) else None
        if aggregate is not None and (not isinstance(aggregate, dict) or set(aggregate) != {"usage"} or not isinstance(usage, dict)):
            _add(issues, "invocation-aggregate", path + ("aggregate",))
            usage = None
        if isinstance(usage, dict):
            if set(usage) - PUBLIC_USAGE_KEYS or any(type(number) is not int or number < 0 or number > MAX_PUBLIC_INVOCATION_TOKENS for number in usage.values()):
                _add(issues, "invocation-aggregate", path + ("aggregate", "usage"))
            prompt = usage.get("prompt")
            cached = usage.get("cached")
            uncached = usage.get("uncached")
            completion = usage.get("completion")
            reasoning = usage.get("reasoning")
            total = usage.get("total")
            if prompt is not None and cached is not None and cached > prompt:
                _add(issues, "invocation-math", path + ("aggregate", "usage"))
            if prompt is not None and cached is not None and uncached is not None and uncached != prompt - cached:
                _add(issues, "invocation-math", path + ("aggregate", "usage"))
            if completion is not None and reasoning is not None and reasoning > completion:
                _add(issues, "invocation-math", path + ("aggregate", "usage"))
            if prompt is not None and completion is not None and total is not None and total != prompt + completion:
                _add(issues, "invocation-math", path + ("aggregate", "usage"))
            if turns and set(usage) == PUBLIC_USAGE_KEYS and any(usage[key] != sums[key] for key in PUBLIC_USAGE_KEYS):
                _add(issues, "invocation-aggregate", path + ("aggregate", "usage"))
        if coverage == "complete" and (not turns or not isinstance(usage, dict) or set(usage) != PUBLIC_USAGE_KEYS):
            _add(issues, "invocation-coverage", path + ("coverage",))
        if coverage == "unavailable" and (turns or aggregate is not None):
            _add(issues, "invocation-coverage", path + ("coverage",))


def _check_trajectory(document: Any, issues: set[Issue], *, embedded: bool = False) -> None:
    if not isinstance(document, dict):
        return
    if document.get("schema_version") != "ATIF-v1.7":
        _add(issues, "root-schema-version", ("schema_version",))
    if document.get("continued_trajectory_ref") not in (None,):
        _add(issues, "partial-run", ("continued_trajectory_ref",))
    if embedded and not _nonempty_id(document.get("trajectory_id")):
        _add(issues, "trajectory-id", ("trajectory_id",))

    steps = document.get("steps")
    if not isinstance(steps, list):
        return
    expected = list(range(1, len(steps) + 1))
    actual = [step.get("step_id") for step in steps if isinstance(step, dict)]
    if actual != expected:
        _add(issues, "step-sequence", ("steps",))
    call_ids: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        calls = step.get("tool_calls")
        if isinstance(calls, list):
            for call_index, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                call_id = call.get("tool_call_id")
                call_path = ("steps", index, "tool_calls", call_index, "tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    _add(issues, "tool-call-id", call_path)
                elif call_id in call_ids:
                    _add(issues, "tool-call-unique", call_path)
                else:
                    call_ids.add(call_id)
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        observation = step.get("observation")
        if isinstance(observation, dict) and isinstance(observation.get("results"), list):
            for result_index, result in enumerate(observation["results"]):
                if not isinstance(result, dict):
                    continue
                source = result.get("source_call_id")
                if source is not None and source not in call_ids:
                    _add(
                        issues,
                        "observation-reference",
                        ("steps", index, "observation", "results", result_index, "source_call_id"),
                    )
    extra = document.get("extra")
    coqui = extra.get("coquic") if isinstance(extra, dict) else None
    if not isinstance(coqui, dict):
        _add(issues, "provenance-shape", ("extra", "coquic"))
    else:
        required = {"taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure", "artifacts"}
        for field in sorted(required - set(coqui)):
            _add(issues, "provenance-field", ("extra", "coquic", field))
        for field in ("taskId", "pipelineId", "runId"):
            if field in coqui and not _nonempty_id(coqui[field]):
                _add(issues, "provenance-id", ("extra", "coquic", field))
        if "role" in coqui and (not isinstance(coqui["role"], str) or not coqui["role"]):
            _add(issues, "provenance-role", ("extra", "coquic", "role"))
        started = _timestamp(coqui.get("startedAt"))
        completed = _timestamp(coqui.get("completedAt"))
        if started is None or completed is None:
            _add(issues, "timing", ("extra", "coquic"))
        elif completed < started:
            _add(issues, "timing-order", ("extra", "coquic", "completedAt"))
        if not _is_number(coqui.get("durationMs")) or coqui["durationMs"] < 0:
            _add(issues, "duration", ("extra", "coquic", "durationMs"))
        disclosure = coqui.get("disclosure")
        if not isinstance(disclosure, dict) or set(disclosure) != {"redactionApplied", "originalRetained"} or any(
            type(disclosure.get(key)) is not bool for key in ("redactionApplied", "originalRetained")
        ):
            _add(issues, "disclosure", ("extra", "coquic", "disclosure"))
        _check_artifacts(coqui, steps, issues)
        source = coqui.get("source")
        if isinstance(source, dict) and "invocations" in source:
            _check_invocations(source, coqui, issues)
        elif not embedded:
            _add(issues, "invocation-shape", ("extra", "coquic", "source", "invocations"))
    children = document.get("subagent_trajectories")
    child_ids: set[str] = set()
    if isinstance(children, list):
        for index, child in enumerate(children):
            child_path = ("subagent_trajectories", index)
            if not isinstance(child, dict):
                continue
            child_id = child.get("trajectory_id")
            if not _nonempty_id(child_id):
                _add(issues, "trajectory-id", child_path + ("trajectory_id",))
            elif child_id in child_ids:
                _add(issues, "trajectory-unique", child_path + ("trajectory_id",))
            else:
                child_ids.add(child_id)
            _check_trajectory(child, issues, embedded=True)
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get("observation"), dict):
            continue
        for result_index, result in enumerate(step["observation"].get("results", [])):
            if not isinstance(result, dict):
                continue
            refs = result.get("subagent_trajectory_ref")
            if not isinstance(refs, list):
                continue
            for ref_index, ref in enumerate(refs):
                ref_path = ("steps", index, "observation", "results", result_index, "subagent_trajectory_ref", ref_index)
                if not isinstance(ref, dict):
                    continue
                trajectory_id = ref.get("trajectory_id")
                trajectory_path = ref.get("trajectory_path")
                if trajectory_id is None and trajectory_path is None:
                    _add(issues, "subagent-reference", ref_path)
                if trajectory_id is not None and trajectory_id not in child_ids:
                    _add(issues, "subagent-reference", ref_path + ("trajectory_id",))
                if trajectory_path is not None:
                    _add(issues, "private-locator", ref_path + ("trajectory_path",))
def validate_atif_document(
    document: Any,
    validator: Draft202012Validator,
    raw: bytes | None = None,
) -> list[Issue]:
    issues = _schema_issues(document, validator)
    _private_scan(document, (), issues)
    _check_trajectory(document, issues)
    if raw is not None:
        try:
            if raw != canonical_bytes(document):
                _add(issues, "canonicalization")
        except (TypeError, ValueError, UnicodeEncodeError):
            _add(issues, "canonicalization")
    return sorted(issues, key=_issue_sort_key)
def validate_atif_bytes(raw: bytes, validator: Draft202012Validator) -> tuple[Any | None, list[Issue]]:
    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_object_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey, ValueError):
        return None, [Issue("canonicalization")]
    issues = validate_atif_document(document, validator, raw)
    return document, issues


def _publication_metadata(document: dict[str, Any]) -> dict[str, Any]:
    return {key: document[key] for key in ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts", "usage")}


def _publication_metadata_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(_publication_metadata(document))).hexdigest()


def _usage_metadata(document: dict[str, Any]) -> dict[str, Any]:
    usage = document.get("usage")
    if not isinstance(usage, dict):
        return {}
    generation = usage.get("generation")
    if isinstance(generation, dict):
        generation = copy.deepcopy(generation)
        generation["metadataDigest"] = ""
    return {
        "publicationId": document.get("publicationId"),
        "taskId": document.get("taskId"),
        "generation": generation,
        "summaries": usage.get("summaries"),
        "invocations": usage.get("invocations"),
        "turns": usage.get("turns"),
        "prices": usage.get("prices"),
        "globals": usage.get("globals"),
    }


def _usage_metadata_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(_usage_metadata(document))).hexdigest()


def _usage_math(
    item: dict[str, Any], path: tuple[Any, ...], issues: set[Issue], *, nullable: bool
) -> bool:
    values: dict[str, int | None] = {}
    valid = True
    for field in USAGE_ALL_FIELDS:
        value = item.get(field)
        values[field] = value
        if value is None and nullable:
            continue
        if type(value) is not int or value < 0 or value > SAFE_INTEGER_MAX:
            _add(issues, "usage-safe-integer", path + (field,))
            valid = False
    tokens = [values[field] for field in USAGE_TOKEN_FIELDS]
    if all(value is not None for value in tokens):
        prompt, cached, uncached, completion, reasoning, total = tokens
        if cached > prompt or uncached != prompt - cached or reasoning > completion or total != prompt + completion:
            _add(issues, "usage-math", path)
            valid = False
    costs = [values[field] for field in USAGE_COST_FIELDS]
    if any(value is None for value in costs) and any(value is not None for value in costs):
        _add(issues, "usage-cost-availability", path)
        valid = False
    return valid


def _usage_sum(rows: list[dict[str, Any]]) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for field in USAGE_ALL_FIELDS:
        values = [row.get(field) for row in rows]
        result[field] = sum(value for value in values if type(value) is int) if any(value is not None for value in values) else None
    return result


def _check_usage(
    document: dict[str, Any],
    usage: Any,
    run_map: dict[str, dict[str, Any]],
    pipeline_ids: set[str],
    issues: set[Issue],
) -> None:
    base = ("usage",)
    if not isinstance(usage, dict):
        _add(issues, "usage-shape", base)
        return
    publication_id = document.get("publicationId")
    task_id = document.get("taskId")
    generation = usage.get("generation")
    if not isinstance(generation, dict):
        _add(issues, "usage-generation-shape", base + ("generation",))
        return
    usage_generation_id = generation.get("usageGenerationId")
    for field, expected in (("publicationId", publication_id), ("taskId", task_id)):
        if generation.get(field) != expected:
            _add(issues, "usage-generation-identity", base + ("generation", field))
    if generation.get("schemaVersion") != "1.0":
        _add(issues, "usage-schema-version", base + ("generation", "schemaVersion"))
    if _valid_digest(generation.get("metadataDigest")):
        candidate = copy.deepcopy(document)
        candidate_usage = candidate.get("usage")
        if isinstance(candidate_usage, dict) and isinstance(candidate_usage.get("generation"), dict):
            candidate_usage["generation"]["metadataDigest"] = generation["metadataDigest"]
        if generation["metadataDigest"] != _usage_metadata_digest(candidate):
            _add(issues, "usage-metadata-digest", base + ("generation", "metadataDigest"))
    expected_counts = generation.get("expectedCounts")
    collections = {
        "summaries": usage.get("summaries"),
        "invocations": usage.get("invocations"),
        "turns": usage.get("turns"),
        "prices": usage.get("prices"),
        "globals": usage.get("globals"),
    }
    if isinstance(expected_counts, dict):
        for name, values in collections.items():
            expected = expected_counts.get(name)
            if type(expected) is int and isinstance(values, list) and expected != len(values):
                _add(issues, "usage-row-count", base + ("generation", "expectedCounts", name))

    summaries = usage.get("summaries")
    invocations = usage.get("invocations")
    turns = usage.get("turns")
    prices = usage.get("prices")
    globals_ = usage.get("globals")
    if not isinstance(summaries, list) or not summaries:
        _add(issues, "usage-summary-shape", base + ("summaries",))
        summaries = []
    if not isinstance(invocations, list):
        _add(issues, "usage-invocation-shape", base + ("invocations",))
        invocations = []
    if not isinstance(turns, list):
        _add(issues, "usage-turn-shape", base + ("turns",))
        turns = []
    if not isinstance(prices, list):
        _add(issues, "usage-price-shape", base + ("prices",))
        prices = []
    if not isinstance(globals_, list):
        _add(issues, "usage-global-shape", base + ("globals",))
        globals_ = []

    summary_map: dict[str, dict[str, Any]] = {}
    for index, summary in enumerate(summaries):
        path = base + ("summaries", index)
        if not isinstance(summary, dict):
            continue
        summary_id = summary.get("summaryId")
        if not isinstance(summary_id, str) or summary_id in summary_map:
            _add(issues, "usage-summary-unique", path + ("summaryId",))
        else:
            summary_map[summary_id] = summary
        for field, expected in (("publicationId", publication_id), ("taskId", task_id), ("usageGenerationId", usage_generation_id)):
            if summary.get(field) != expected:
                _add(issues, "usage-ownership", path + (field,))
        scope = summary.get("scope")
        run_id = summary.get("runId")
        if scope == "task" and run_id is not None:
            _add(issues, "usage-summary-scope", path + ("runId",))
        if scope == "run" and (not isinstance(run_id, str) or run_id not in run_map):
            _add(issues, "usage-summary-scope", path + ("runId",))
        covered = summary.get("coveredInvocations")
        expected = summary.get("expectedInvocations")
        if type(covered) is int and type(expected) is int and covered > expected:
            _add(issues, "usage-summary-coverage", path)
        _usage_math(summary, path, issues, nullable=True)
        if summary.get("coverage") == "unavailable" and any(summary.get(field) is not None for field in ("knownTokenSubtotal", "knownCostSubtotalMicroUsd")):
            _add(issues, "usage-summary-coverage", path)
        total = summary.get("totalTokens")
        known = summary.get("knownTokenSubtotal")
        if total is not None and known is not None and total != known:
            _add(issues, "usage-summary-rollup", path + ("knownTokenSubtotal",))

    invocation_map: dict[str, dict[str, Any]] = {}
    ordinal_groups: dict[tuple[Any, ...], list[int]] = {}
    for index, invocation in enumerate(invocations):
        path = base + ("invocations", index)
        if not isinstance(invocation, dict):
            continue
        invocation_id = invocation.get("invocationId")
        if not isinstance(invocation_id, str) or invocation_id in invocation_map:
            _add(issues, "usage-invocation-unique", path + ("invocationId",))
        else:
            invocation_map[invocation_id] = invocation
        if invocation.get("usageGenerationId") != usage_generation_id:
            _add(issues, "usage-ownership", path + ("usageGenerationId",))
        ownership = invocation.get("ownershipClass")
        task_owned = ownership == "task-owned"
        if task_owned:
            for field, expected in (("publicationId", publication_id), ("taskId", task_id)):
                if invocation.get(field) != expected:
                    _add(issues, "usage-ownership", path + (field,))
            if invocation.get("pipelineId") not in pipeline_ids or invocation.get("runId") not in run_map:
                _add(issues, "usage-ownership", path)
            group = (invocation.get("runId"), ownership)
        elif ownership == "steward-overhead":
            if any(invocation.get(field) is not None for field in ("publicationId", "taskId", "pipelineId", "runId")):
                _add(issues, "usage-overhead", path)
            if invocation.get("coveredTurns") != 0 or invocation.get("expectedTurns") != 0:
                _add(issues, "usage-overhead", path)
            group = ("overhead", ownership)
        else:
            _add(issues, "usage-ownership", path + ("ownershipClass",))
            group = ("invalid", ownership)
        ordinal = invocation.get("retryOrdinal")
        if type(ordinal) is not int or ordinal < 0 or ordinal > SAFE_INTEGER_MAX:
            _add(issues, "usage-invocation-ordinal", path + ("retryOrdinal",))
        else:
            ordinal_groups.setdefault(group, []).append(ordinal)
        started = _timestamp(invocation.get("startedAt")) if invocation.get("startedAt") is not None else None
        completed = _timestamp(invocation.get("completedAt")) if invocation.get("completedAt") is not None else None
        if (invocation.get("startedAt") is None) != (invocation.get("completedAt") is None):
            _add(issues, "usage-invocation-timing", path)
        if invocation.get("startedAt") is not None and started is None:
            _add(issues, "usage-invocation-timing", path + ("startedAt",))
        if invocation.get("completedAt") is not None and completed is None:
            _add(issues, "usage-invocation-timing", path + ("completedAt",))
        if started is not None and completed is not None and completed < started:
            _add(issues, "usage-invocation-timing", path + ("completedAt",))
        coverage = invocation.get("coverage")
        if coverage == "complete" and invocation.get("coveredTurns") != invocation.get("expectedTurns"):
            _add(issues, "usage-invocation-coverage", path)
        if coverage == "unavailable" and any(invocation.get(field) is not None for field in USAGE_ALL_FIELDS):
            _add(issues, "usage-invocation-coverage", path)
        _usage_math(invocation, path, issues, nullable=True)
        costs_known = all(invocation.get(field) is not None for field in USAGE_COST_FIELDS)
        if costs_known and invocation.get("priceEntryDigest") is None:
            _add(issues, "usage-price-provenance", path + ("priceEntryDigest",))
        if not costs_known and invocation.get("priceEntryDigest") is not None:
            _add(issues, "usage-price-provenance", path + ("priceEntryDigest",))
    for group, ordinals in ordinal_groups.items():
        if sorted(ordinals) != list(range(len(ordinals))):
            _add(issues, "usage-invocation-order", base + ("invocations",))

    price_map: dict[str, dict[str, Any]] = {}
    for index, price in enumerate(prices):
        path = base + ("prices", index)
        if not isinstance(price, dict):
            continue
        digest = price.get("priceEntryDigest")
        if not isinstance(digest, str) or not _valid_digest(digest) or digest in price_map:
            _add(issues, "usage-price-unique", path + ("priceEntryDigest",))
        else:
            price_map[digest] = price
        if price.get("usageGenerationId") != usage_generation_id:
            _add(issues, "usage-price-provenance", path + ("usageGenerationId",))
        effective_at = _timestamp(price.get("effectiveAt"))
        effective_until = _timestamp(price.get("effectiveUntil")) if price.get("effectiveUntil") is not None else None
        if effective_at is None or (price.get("effectiveUntil") is not None and effective_until is None):
            _add(issues, "usage-price-timing", path)
        if effective_at is not None and effective_until is not None and effective_until <= effective_at:
            _add(issues, "usage-price-timing", path)
    intervals: dict[str, list[tuple[datetime, datetime | None, int]]] = {}
    for index, price in enumerate(prices):
        if not isinstance(price, dict):
            continue
        effective_at = _timestamp(price.get("effectiveAt"))
        if effective_at is None:
            continue
        effective_until = _timestamp(price.get("effectiveUntil")) if price.get("effectiveUntil") is not None else None
        intervals.setdefault(str(price.get("model")), []).append((effective_at, effective_until, index))
    for model, entries in intervals.items():
        entries.sort(key=lambda item: item[0])
        for previous, current in zip(entries, entries[1:]):
            if previous[1] is None or current[0] < previous[1]:
                _add(issues, "usage-price-overlap", base + ("prices", current[2]))
    for index, invocation in enumerate(invocations):
        if not isinstance(invocation, dict) or invocation.get("priceEntryDigest") is None:
            continue
        price = price_map.get(invocation.get("priceEntryDigest"))
        path = base + ("invocations", index, "priceEntryDigest")
        if price is None:
            _add(issues, "usage-price-provenance", path)
        elif invocation.get("model") != price.get("model"):
            _add(issues, "usage-price-model", path)
        started = _timestamp(invocation.get("startedAt")) if invocation.get("startedAt") else None
        effective_at = _timestamp(price.get("effectiveAt")) if price else None
        effective_until = _timestamp(price.get("effectiveUntil")) if price and price.get("effectiveUntil") else None
        if started is not None and effective_at is not None and (started < effective_at or (effective_until is not None and started >= effective_until)):
            _add(issues, "usage-price-time", path)

    turns_by_invocation: dict[str, list[dict[str, Any]]] = {}
    for index, turn in enumerate(turns):
        path = base + ("turns", index)
        if not isinstance(turn, dict):
            continue
        invocation_id = turn.get("invocationId")
        invocation = invocation_map.get(invocation_id)
        if invocation is None:
            _add(issues, "usage-turn-ownership", path + ("invocationId",))
        else:
            if invocation.get("ownershipClass") != "task-owned":
                _add(issues, "usage-overhead", path)
            for field in ("usageGenerationId", "publicationId", "taskId", "runId"):
                expected = invocation.get(field)
                if turn.get(field) != expected:
                    _add(issues, "usage-turn-ownership", path + (field,))
            turns_by_invocation.setdefault(invocation_id, []).append(turn)
        if turn.get("usageGenerationId") != usage_generation_id:
            _add(issues, "usage-turn-ownership", path + ("usageGenerationId",))
        _usage_math(turn, path, issues, nullable=True)
        costs_known = all(turn.get(field) is not None for field in USAGE_COST_FIELDS)
        if costs_known != (turn.get("priceEntryDigest") is not None):
            _add(issues, "usage-price-provenance", path + ("priceEntryDigest",))
        if turn.get("priceEntryDigest") is not None and turn.get("priceEntryDigest") not in price_map:
            _add(issues, "usage-price-provenance", path + ("priceEntryDigest",))
    for invocation_id, invocation_turns in turns_by_invocation.items():
        ordinals = [turn.get("ordinal") for turn in invocation_turns]
        if sorted(ordinals) != list(range(1, len(ordinals) + 1)):
            _add(issues, "usage-cursor-order", base + ("turns", invocation_id))
        invocation = invocation_map.get(invocation_id)
        if invocation is None:
            continue
        if invocation.get("coverage") == "complete":
            totals = _usage_sum(invocation_turns)
            for field in USAGE_ALL_FIELDS:
                if invocation.get(field) != totals[field]:
                    _add(issues, "usage-rollup", base + ("invocations", invocation_id, field))

    for index, summary in enumerate(summaries):
        if not isinstance(summary, dict):
            continue
        scope = summary.get("scope")
        run_id = summary.get("runId")
        selected = [
            invocation for invocation in invocations
            if isinstance(invocation, dict)
            and invocation.get("ownershipClass") == "task-owned"
            and (scope == "task" or invocation.get("runId") == run_id)
        ]
        covered = len(selected)
        expected = summary.get("expectedInvocations")
        if type(expected) is int and summary.get("coveredInvocations") != covered:
            _add(issues, "usage-summary-rollup", base + ("summaries", index, "coveredInvocations"))
        totals = _usage_sum(selected)
        if summary.get("coverage") == "complete" or any(summary.get(field) is not None for field in USAGE_TOKEN_FIELDS):
            for field in USAGE_ALL_FIELDS:
                value = summary.get(field)
                if value is not None and value != totals[field]:
                    _add(issues, "usage-summary-rollup", base + ("summaries", index, field))

    global_keys: set[tuple[Any, ...]] = set()
    for index, row in enumerate(globals_):
        path = base + ("globals", index)
        if not isinstance(row, dict):
            continue
        key = (row.get("periodKind"), row.get("periodKey"), row.get("model"), row.get("ownershipClass"))
        if key in global_keys:
            _add(issues, "usage-global-key", path)
        global_keys.add(key)
        if row.get("usageGenerationId") != usage_generation_id:
            _add(issues, "usage-global-ownership", path + ("usageGenerationId",))
        if row.get("periodKind") == "lifetime" and row.get("periodKey") != "lifetime":
            _add(issues, "usage-global-key", path + ("periodKey",))
        if row.get("periodKind") == "daily" and (not isinstance(row.get("periodKey"), str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", row.get("periodKey"))):
            _add(issues, "usage-global-key", path + ("periodKey",))
        if row.get("ownershipClass") == "steward-overhead" and row.get("aggregateOnly") is not True:
            _add(issues, "usage-overhead", path + ("aggregateOnly",))
        _usage_math(row, path, issues, nullable=True)

def validate_publication_document(document: Any, validator: Draft202012Validator) -> list[Issue]:
    issues = _schema_issues(document, validator)
    _private_scan(document, (), issues)
    if not isinstance(document, dict):
        return sorted(issues, key=_issue_sort_key)

    publication_id = document.get("publicationId")
    task_id = document.get("taskId")
    generation = document.get("generation")
    head = document.get("headIntent")
    task = document.get("task")
    pipelines = document.get("pipelines")
    runs = document.get("runs")
    events = document.get("events")
    artifacts = document.get("artifacts")

    def same(item: Any, field: str, expected: Any, rule: str, path: tuple[Any, ...]) -> None:
        if isinstance(item, dict) and field in item and item[field] != expected:
            _add(issues, rule, path + (field,))

    same(generation, "publicationId", publication_id, "identity", ("generation",))
    same(generation, "taskId", task_id, "identity", ("generation",))
    same(head, "publicationId", publication_id, "identity", ("headIntent",))
    same(head, "taskId", task_id, "identity", ("headIntent",))
    same(task, "taskId", task_id, "ownership", ("task",))

    counts = generation.get("expectedCounts") if isinstance(generation, dict) else None
    collections = {"tasks": 1, "pipelines": pipelines, "runs": runs, "events": events, "artifacts": artifacts}
    if isinstance(counts, dict):
        for name, value in collections.items():
            if isinstance(counts.get(name), int) and not isinstance(counts.get(name), bool):
                actual = value if isinstance(value, int) else len(value) if isinstance(value, list) else None
                if actual is not None and counts[name] != actual:
                    _add(issues, "row-count", ("generation", "expectedCounts", name))

    def check_timestamp(value: Any, path: tuple[Any, ...], *, nullable: bool = False) -> datetime | None:
        if value is None and nullable:
            return None
        parsed = _timestamp(value)
        if parsed is None:
            _add(issues, "timestamp", path)
        return parsed

    if isinstance(generation, dict):
        check_timestamp(generation.get("createdAt"), ("generation", "createdAt"))
    if isinstance(head, dict):
        check_timestamp(head.get("updatedAt"), ("headIntent", "updatedAt"))
    task_created = task_completed = None
    if isinstance(task, dict):
        task_created = check_timestamp(task.get("createdAt"), ("task", "createdAt"))
        task_completed = check_timestamp(task.get("completedAt"), ("task", "completedAt"), nullable=True)
        lifecycle = task.get("lifecycleState")
        if lifecycle == "active" and task_completed is not None:
            _add(issues, "task-completion", ("task", "completedAt"))
        if lifecycle in {"completed", "failed", "cancelled"} and task_completed is None:
            _add(issues, "task-completion", ("task", "completedAt"))
        if task_created is not None and task_completed is not None and task_completed < task_created:
            _add(issues, "timing-order", ("task", "completedAt"))

    pipeline_ids: set[str] = set()
    if isinstance(pipelines, list):
        for index, pipeline in enumerate(pipelines):
            if not isinstance(pipeline, dict):
                continue
            pipeline_id = pipeline.get("pipelineId")
            if isinstance(pipeline_id, str) and pipeline_id in pipeline_ids:
                _add(issues, "pipeline-unique", ("pipelines", index, "pipelineId"))
            elif isinstance(pipeline_id, str):
                pipeline_ids.add(pipeline_id)
            same(pipeline, "taskId", task_id, "ownership", ("pipelines", index))
            check_timestamp(pipeline.get("createdAt"), ("pipelines", index, "createdAt"))

    run_map: dict[str, dict[str, Any]] = {}
    if isinstance(runs, list):
        for index, run in enumerate(runs):
            if not isinstance(run, dict):
                continue
            run_id = run.get("runId")
            if isinstance(run_id, str) and run_id in run_map:
                _add(issues, "run-unique", ("runs", index, "runId"))
            elif isinstance(run_id, str):
                run_map[run_id] = run
            same(run, "taskId", task_id, "ownership", ("runs", index))
            if run.get("pipelineId") not in pipeline_ids:
                _add(issues, "ownership", ("runs", index, "pipelineId"))
            started = check_timestamp(run.get("startedAt"), ("runs", index, "startedAt"))
            completed = check_timestamp(run.get("completedAt"), ("runs", index, "completedAt"))
            if started is not None and completed is not None:
                if completed < started:
                    _add(issues, "timing-order", ("runs", index, "completedAt"))
                duration = run.get("durationMs")
                if isinstance(duration, int) and not isinstance(duration, bool) and duration != int((completed - started).total_seconds() * 1000):
                    _add(issues, "run-duration", ("runs", index, "durationMs"))

    generation_run = generation.get("runId") if isinstance(generation, dict) else None
    if generation_run is not None and generation_run not in run_map:
        _add(issues, "ownership", ("generation", "runId"))

    if isinstance(events, list):
        sequences = [event.get("sequence") for event in events if isinstance(event, dict)]
        if sequences != list(range(1, len(events) + 1)):
            _add(issues, "event-order", ("events",))
        for index, event in enumerate(events):
            if isinstance(event, dict):
                same(event, "taskId", task_id, "ownership", ("events", index))
                check_timestamp(event.get("occurredAt"), ("events", index, "occurredAt"))

    artifact_map: dict[str, dict[str, Any]] = {}
    logical_paths: set[str] = set()
    object_sizes: dict[tuple[str, str], int] = {}
    if isinstance(artifacts, list):
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                continue
            artifact_id = artifact.get("artifactId")
            if isinstance(artifact_id, str) and artifact_id in artifact_map:
                _add(issues, "artifact-unique", ("artifacts", index, "artifactId"))
            elif isinstance(artifact_id, str):
                artifact_map[artifact_id] = artifact
            same(artifact, "taskId", task_id, "ownership", ("artifacts", index))
            if artifact.get("runId") not in run_map:
                _add(issues, "ownership", ("artifacts", index, "runId"))
            logical_path = artifact.get("logicalPath")
            if isinstance(logical_path, str):
                if logical_path in logical_paths:
                    _add(issues, "artifact-logical-path-unique", ("artifacts", index, "logicalPath"))
                else:
                    logical_paths.add(logical_path)
            public_key = artifact.get("publicKey")
            digest = artifact.get("sha256")
            if not _valid_public_key(public_key, task_id, digest):
                _add(issues, "artifact-key", ("artifacts", index, "publicKey"))
            elif isinstance(digest, str) and isinstance(artifact.get("byteSize"), int) and not isinstance(artifact.get("byteSize"), bool):
                object_identity = (digest, public_key)
                previous_size = object_sizes.get(object_identity)
                if previous_size is not None and previous_size != artifact["byteSize"]:
                    _add(issues, "artifact-object-size", ("artifacts", index, "byteSize"))
                else:
                    object_sizes[object_identity] = artifact["byteSize"]

    for index, run in enumerate(runs if isinstance(runs, list) else []):
        if not isinstance(run, dict):
            continue
        artifact = artifact_map.get(run.get("atifArtifactId"))
        if artifact is None:
            _add(issues, "atif-artifact", ("runs", index, "atifArtifactId"))
            continue
        if artifact.get("taskId") != task_id or artifact.get("runId") != run.get("runId"):
            _add(issues, "atif-artifact", ("runs", index, "atifArtifactId"))
        if artifact.get("sha256") != run.get("atifDigest"):
            _add(issues, "atif-digest", ("runs", index, "atifDigest"))
        if artifact.get("availability") != "available":
            _add(issues, "atif-availability", ("runs", index, "atifArtifactId"))

    _check_usage(document, document.get("usage"), run_map, pipeline_ids, issues)

    metadata_fields = ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts", "usage")
    if isinstance(generation, dict) and _valid_digest(generation.get("metadataDigest")) and all(field in document for field in metadata_fields):
        if generation["metadataDigest"] != _publication_metadata_digest(document):
            _add(issues, "metadata-digest", ("generation", "metadataDigest"))
    return sorted(issues, key=_issue_sort_key)


def _fixture_content_bytes(value: Any) -> bytes | None:
    if isinstance(value, dict):
        try:
            return canonical_bytes(value)
        except (TypeError, ValueError, UnicodeEncodeError):
            return None
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _load_publication_fixture(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    fixture = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(fixture, dict) or raw != canonical_bytes(fixture):
        raise ValueError("fixture-not-canonical")
    return fixture


def validate_publication_fixture(
    fixture: Any,
    publication_validator: Draft202012Validator,
    atif_validator: Draft202012Validator,
    *,
    expected_redaction: bool,
    expected_lifecycle: str,
) -> list[Issue]:
    issues: set[Issue] = set()
    if not isinstance(fixture, dict) or set(fixture) != {"atif", "objects", "publication"}:
        _add(issues, "fixture-shape")
        return sorted(issues, key=_issue_sort_key)
    publication = fixture["publication"]
    atif = fixture["atif"]
    objects = fixture["objects"]
    issues.update(validate_publication_document(publication, publication_validator))
    atif_raw = _fixture_content_bytes(atif)
    if atif_raw is None:
        _add(issues, "atif-shape", ("atif",))
    else:
        _, atif_issues = validate_atif_bytes(atif_raw, atif_validator)
        issues.update(Issue(issue.rule, ("atif",) + issue.path) for issue in atif_issues)
    if not isinstance(publication, dict) or not isinstance(atif, dict) or not isinstance(objects, list):
        return sorted(issues, key=_issue_sort_key)

    expected_disclosure = {"redactionApplied": expected_redaction, "originalRetained": True}
    coqui = atif.get("extra", {}).get("coquic") if isinstance(atif.get("extra"), dict) else None
    if not isinstance(coqui, dict) or coqui.get("disclosure") != expected_disclosure:
        _add(issues, "disclosure", ("atif", "extra", "coquic", "disclosure"))
    pipelines = publication.get("pipelines")
    pipeline_id = pipelines[0].get("pipelineId") if isinstance(pipelines, list) and pipelines and isinstance(pipelines[0], dict) else None
    generation = publication.get("generation")
    run_id = generation.get("runId") if isinstance(generation, dict) else None
    publication_runs = publication.get("runs")
    referenced_run = None
    referenced_run_index = None
    if isinstance(coqui, dict) and isinstance(coqui.get("runId"), str) and isinstance(publication_runs, list):
        for index, run in enumerate(publication_runs):
            if isinstance(run, dict) and run.get("runId") == coqui["runId"]:
                referenced_run = run
                referenced_run_index = index
                break
        if referenced_run is None:
            _add(issues, "atif-run-reference", ("atif", "extra", "coquic", "runId"))
    expected_pipeline_id = referenced_run.get("pipelineId") if isinstance(referenced_run, dict) else pipeline_id
    for field, expected in (("taskId", publication.get("taskId")), ("pipelineId", expected_pipeline_id), ("runId", run_id)):
        if isinstance(coqui, dict) and coqui.get(field) != expected:
            _add(issues, "atif-identity", ("atif", "extra", "coquic", field))
    if isinstance(coqui, dict) and isinstance(referenced_run, dict):
        for field in ("role", "startedAt", "completedAt", "durationMs"):
            coqui_value = coqui.get(field)
            run_value = referenced_run.get(field)
            if field in {"startedAt", "completedAt"}:
                coqui_time = _timestamp(coqui_value)
                run_time = _timestamp(run_value)
                mismatch = coqui_time is not None and run_time is not None and coqui_time != run_time
            else:
                mismatch = coqui_value != run_value
            if mismatch:
                _add(issues, "atif-provenance", ("atif", "extra", "coquic", field))
    if isinstance(coqui, dict) and coqui.get("disclosure") == expected_disclosure:
        if expected_lifecycle == "active":
            runs = publication.get("runs")
            task = publication.get("task")
            if not isinstance(task, dict) or task.get("lifecycleState") != "active" or task.get("completedAt") is not None:
                _add(issues, "active-task", ("publication", "task"))
            if not isinstance(runs, list) or len(runs) != 1 or runs[0].get("role") != "planning" or runs[0].get("runState") != "completed":
                _add(issues, "planning-run", ("publication", "runs"))
        elif not isinstance(publication.get("task"), dict) or publication["task"].get("lifecycleState") != expected_lifecycle:
            _add(issues, "task-lifecycle", ("publication", "task", "lifecycleState"))

    artifacts = publication.get("artifacts")
    artifact_map = {item.get("artifactId"): item for item in artifacts if isinstance(item, dict)} if isinstance(artifacts, list) else {}
    if isinstance(coqui, dict) and isinstance(referenced_run, dict) and isinstance(coqui.get("disclosure"), dict):
        for index, artifact in enumerate(artifacts if isinstance(artifacts, list) else []):
            if not isinstance(artifact, dict) or artifact.get("runId") != referenced_run.get("runId"):
                continue
            disclosure = artifact.get("disclosure")
            if isinstance(disclosure, dict) and any(
                disclosure.get(field) != coqui["disclosure"].get(field)
                for field in ("redactionApplied", "originalRetained")
            ):
                _add(issues, "atif-disclosure", ("publication", "artifacts", index, "disclosure"))
    object_map: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(objects):
        path = ("objects", index)
        if not isinstance(item, dict) or set(item) != {"artifactId", "publicKey", "mediaType", "sha256", "byteSize", "content"}:
            _add(issues, "object-shape", path)
            continue
        artifact_id = item["artifactId"]
        if artifact_id in object_map:
            _add(issues, "object-unique", path + ("artifactId",))
        object_map[artifact_id] = item
        artifact = artifact_map.get(artifact_id)
        if not isinstance(artifact, dict):
            _add(issues, "object-reference", path + ("artifactId",))
            continue
        body = _fixture_content_bytes(item["content"])
        if body is None:
            _add(issues, "object-content", path + ("content",))
            continue
        digest = hashlib.sha256(body).hexdigest()
        if item["sha256"] != digest:
            _add(issues, "object-digest", path + ("sha256",))
        if item["byteSize"] != len(body):
            _add(issues, "object-size", path + ("byteSize",))
        if item["sha256"] != artifact.get("sha256") or item["byteSize"] != artifact.get("byteSize"):
            _add(issues, "object-agreement", path)
        if item["mediaType"] != artifact.get("mediaType"):
            _add(issues, "object-media-type", path + ("mediaType",))
        if item["publicKey"] != artifact.get("publicKey") or not _valid_public_key(item["publicKey"], publication.get("taskId"), item["sha256"]):
            _add(issues, "object-key", path + ("publicKey",))
        _private_scan(item, path, issues)
    for artifact_id, artifact in artifact_map.items():
        if artifact.get("availability") == "available" and artifact_id not in object_map:
            _add(issues, "object-reference", ("publication", "artifacts", artifact_id))

    if atif_raw is not None and isinstance(referenced_run, dict):
        run = referenced_run
        atif_digest = hashlib.sha256(atif_raw).hexdigest()
        atif_artifact = artifact_map.get(run.get("atifArtifactId"))
        atif_object = object_map.get(run.get("atifArtifactId"))
        run_path = ("publication", "runs", referenced_run_index if referenced_run_index is not None else 0)
        if not isinstance(atif_artifact, dict) or atif_artifact.get("sha256") != atif_digest:
            _add(issues, "atif-object-digest", run_path + ("atifDigest",))
        if not isinstance(atif_artifact, dict) or atif_artifact.get("byteSize") != len(atif_raw):
            _add(issues, "atif-object-size", run_path + ("atifArtifactId",))
        if not isinstance(atif_object, dict) or _fixture_content_bytes(atif_object.get("content")) != atif_raw:
            _add(issues, "atif-object-content", ("objects",))
    atif_artifacts = coqui.get("artifacts") if isinstance(coqui, dict) else None
    if isinstance(atif_artifacts, list):
        for index, descriptor in enumerate(atif_artifacts):
            if not isinstance(descriptor, dict):
                continue
            artifact = artifact_map.get(descriptor.get("artifactId"))
            if not isinstance(artifact, dict) or any(descriptor.get(field) != artifact.get(source) for field, source in (("mediaType", "mediaType"), ("sha256", "sha256"), ("byteSize", "byteSize"))):
                _add(issues, "atif-artifact", ("atif", "extra", "coquic", "artifacts", index))
    if isinstance(coqui, dict) and isinstance(coqui.get("source"), dict):
        atif_invocations = coqui["source"].get("invocations")
        usage = publication.get("usage") if isinstance(publication, dict) else None
        usage_invocations = usage.get("invocations") if isinstance(usage, dict) else None
        if isinstance(atif_invocations, list) and isinstance(usage_invocations, list):
            usage_by_id = {
                row.get("invocationId"): row
                for row in usage_invocations
                if isinstance(row, dict) and isinstance(row.get("invocationId"), str)
            }
            for index, atif_invocation in enumerate(atif_invocations):
                if not isinstance(atif_invocation, dict):
                    continue
                usage_row = usage_by_id.get(atif_invocation.get("invocationId"))
                if usage_row is None:
                    _add(issues, "usage-atif-reference", ("publication", "usage", "invocations", index))
                    continue
                aggregate = atif_invocation.get("aggregate")
                source_usage = aggregate.get("usage") if isinstance(aggregate, dict) else None
                if isinstance(source_usage, dict) and usage_row.get("totalTokens") != source_usage.get("total"):
                    _add(issues, "usage-atif-rollup", ("publication", "usage", "invocations", index))
    return sorted(issues, key=_issue_sort_key)


def _publication_example() -> dict[str, Any]:
    task_id = "task-example"
    run_id = "run-example"
    atif_digest = "a" * 64
    output_digest = "b" * 64
    def artifact(artifact_id: str, digest: str, path: str, media_type: str, size: int) -> dict[str, Any]:
        return {
            "artifactId": artifact_id,
            "taskId": task_id,
            "runId": run_id,
            "logicalPath": path,
            "publicKey": f"v1/tasks/{task_id}/objects/sha256/{digest[:2]}/{digest}",
            "mediaType": media_type,
            "byteSize": size,
            "sha256": digest,
            "availability": "available",
            "disclosure": {"redactionApplied": False, "originalRetained": True},
        }
    usage_generation_id = "usage-generation-example"
    price_digest = "c" * 64
    token_values = {
        "promptTokens": 11,
        "cachedTokens": 2,
        "uncachedTokens": 9,
        "completionTokens": 7,
        "reasoningTokens": 3,
        "totalTokens": 18,
    }
    cost_values = {
        "uncachedInputCostMicroUsd": 10,
        "cachedInputCostMicroUsd": 20,
        "outputCostMicroUsd": 30,
        "totalCostMicroUsd": 60,
    }
    invocation = {
        "invocationId": "invocation-example",
        "usageGenerationId": usage_generation_id,
        "publicationId": "publication-example",
        "taskId": task_id,
        "pipelineId": "pipeline-example",
        "runId": run_id,
        "ownershipClass": "task-owned",
        "retryOrdinal": 0,
        "startedAt": "2026-07-28T00:00:00Z",
        "completedAt": "2026-07-28T00:00:01Z",
        "model": "gpt-fixture",
        "billingMode": "api",
        "processOutcome": "success",
        "coverage": "complete",
        "issueCount": 0,
        "coveredTurns": 1,
        "expectedTurns": 1,
        **token_values,
        **cost_values,
        "priceEntryDigest": price_digest,
    }
    usage = {
        "schemaVersion": "1.0",
        "generation": {
            "usageGenerationId": usage_generation_id,
            "publicationId": "publication-example",
            "taskId": task_id,
            "schemaVersion": "1.0",
            "metadataDigest": "0" * 64,
            "state": "staged",
            "expectedCounts": {"summaries": 2, "invocations": 1, "turns": 1, "prices": 1, "globals": 2},
            "createdAt": "2026-07-28T00:00:00Z",
        },
        "summaries": [
            {
                "summaryId": "summary-task-example",
                "usageGenerationId": usage_generation_id,
                "publicationId": "publication-example",
                "taskId": task_id,
                "runId": None,
                "scope": "task",
                "coverage": "complete",
                "coveredInvocations": 1,
                "expectedInvocations": 1,
                "knownTokenSubtotal": 18,
                "knownCostSubtotalMicroUsd": 60,
                **token_values,
                **cost_values,
                "priceProvenanceDigest": price_digest,
            },
            {
                "summaryId": "summary-run-example",
                "usageGenerationId": usage_generation_id,
                "publicationId": "publication-example",
                "taskId": task_id,
                "runId": run_id,
                "scope": "run",
                "coverage": "complete",
                "coveredInvocations": 1,
                "expectedInvocations": 1,
                "knownTokenSubtotal": 18,
                "knownCostSubtotalMicroUsd": 60,
                **token_values,
                **cost_values,
                "priceProvenanceDigest": price_digest,
            },
        ],
        "invocations": [invocation],
        "turns": [
            {
                "turnId": "turn-example",
                "usageGenerationId": usage_generation_id,
                "invocationId": "invocation-example",
                "publicationId": "publication-example",
                "taskId": task_id,
                "runId": run_id,
                "ordinal": 1,
                **token_values,
                **cost_values,
                "priceEntryDigest": price_digest,
            }
        ],
        "prices": [
            {
                "priceEntryDigest": price_digest,
                "usageGenerationId": usage_generation_id,
                "catalogDigest": "d" * 64,
                "model": "gpt-fixture",
                "effectiveAt": "2026-01-01T00:00:00Z",
                "effectiveUntil": None,
            }
        ],
        "globals": [
            {
                "globalId": "global-lifetime-example",
                "usageGenerationId": usage_generation_id,
                "periodKind": "lifetime",
                "periodKey": "lifetime",
                "model": "gpt-fixture",
                "ownershipClass": "task-owned",
                "coverage": "complete",
                "coveredInvocations": 1,
                "expectedInvocations": 1,
                "knownTokenSubtotal": 18,
                "knownCostSubtotalMicroUsd": 60,
                **token_values,
                **cost_values,
                "priceProvenanceDigest": price_digest,
                "aggregateOnly": True,
            },
            {
                "globalId": "global-overhead-example",
                "usageGenerationId": usage_generation_id,
                "periodKind": "daily",
                "periodKey": "2026-07-28",
                "model": "gpt-overhead",
                "ownershipClass": "steward-overhead",
                "coverage": "unavailable",
                "coveredInvocations": 0,
                "expectedInvocations": 0,
                "knownTokenSubtotal": None,
                "knownCostSubtotalMicroUsd": None,
                "promptTokens": None,
                "cachedTokens": None,
                "uncachedTokens": None,
                "completionTokens": None,
                "reasoningTokens": None,
                "totalTokens": None,
                "uncachedInputCostMicroUsd": None,
                "cachedInputCostMicroUsd": None,
                "outputCostMicroUsd": None,
                "totalCostMicroUsd": None,
                "priceProvenanceDigest": None,
                "aggregateOnly": True,
            },
        ],
    }
    document: dict[str, Any] = {
        "schemaVersion": "2.0",
        "publicationId": "publication-example",
        "taskId": task_id,
        "generation": {
            "publicationId": "publication-example",
            "taskId": task_id,
            "runId": run_id,
            "metadataDigest": "0" * 64,
            "idempotencyKey": "retry-publication-example",
            "state": "staged",
            "expectedCounts": {"tasks": 1, "pipelines": 1, "runs": 1, "events": 2, "artifacts": 2},
            "createdAt": "2026-07-28T00:00:00Z",
        },
        "headIntent": {"publicationId": "publication-example", "taskId": task_id, "state": "visible", "updatedAt": "2026-07-28T00:00:02Z"},
        "task": {"taskId": task_id, "title": "Example task", "lifecycleState": "completed", "createdAt": "2026-07-28T00:00:00Z", "completedAt": "2026-07-28T00:00:01Z"},
        "pipelines": [{"pipelineId": "pipeline-example", "taskId": task_id, "name": "Example pipeline", "createdAt": "2026-07-28T00:00:00Z"}],
        "runs": [{"runId": run_id, "taskId": task_id, "pipelineId": "pipeline-example", "role": "planning", "runState": "completed", "startedAt": "2026-07-28T00:00:00Z", "completedAt": "2026-07-28T00:00:01Z", "durationMs": 1000, "atifDigest": atif_digest, "atifArtifactId": "artifact-atif"}],
        "events": [
            {"taskId": task_id, "sequence": 1, "eventType": "started", "occurredAt": "2026-07-28T00:00:00Z", "summary": "Planning started"},
            {"taskId": task_id, "sequence": 2, "eventType": "completed", "occurredAt": "2026-07-28T00:00:01Z", "summary": "Planning completed"},
        ],
        "artifacts": [
            artifact("artifact-atif", atif_digest, "runs/run-example/trajectory.json", "application/json", 1024),
            artifact("artifact-output", output_digest, "steps/1/output.txt", "text/plain", 42),
        ],
        "usage": usage,
    }
    document["usage"]["generation"]["metadataDigest"] = _usage_metadata_digest(document)
    document["generation"]["metadataDigest"] = _publication_metadata_digest(document)
    return document


def _run_publication_cases(validator: Draft202012Validator, atif_validator: Draft202012Validator) -> tuple[int, int]:
    fixture_specs = (
        ("clean", "clean-publication.json", False, "completed"),
        ("redacted", "redacted-publication.json", True, "completed"),
        ("active-after-planning", "active-after-planning.json", False, "active"),
    )
    passed = failed = 0
    accepted_names: list[str] = []
    rejected_names: list[str] = []
    fixtures: dict[str, dict[str, Any]] = {}
    for name, filename, redaction, lifecycle in fixture_specs:
        try:
            fixture = _load_publication_fixture(FIXTURE_DIR / filename)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, DuplicateKey, ValueError):
            print(f"FAIL fixture {name}: could not load canonical envelope", file=sys.stderr)
            failed += 1
            continue
        issues = validate_publication_fixture(fixture, validator, atif_validator, expected_redaction=redaction, expected_lifecycle=lifecycle)
        if issues or not _fixture_d1_probe(fixture["publication"]):
            detail = ", ".join(issue.rendered() for issue in issues) if issues else "d1-visibility"
            print(f"FAIL accepted publication {name}: {detail}", file=sys.stderr)
            failed += 1
            continue
        fixtures[name] = fixture
        passed += 1
        accepted_names.append(name)
    if "clean" not in fixtures:
        print("FAIL publication cases: clean fixture unavailable", file=sys.stderr)
        return passed, failed + 1
    clean = fixtures["clean"]["publication"]
    reused = copy.deepcopy(clean)
    reused["artifacts"][1]["sha256"] = reused["artifacts"][0]["sha256"]
    reused["artifacts"][1]["publicKey"] = reused["artifacts"][0]["publicKey"]
    reused["artifacts"][1]["byteSize"] = reused["artifacts"][0]["byteSize"]
    reused["generation"]["metadataDigest"] = _publication_metadata_digest(reused)
    if not validate_publication_document(reused, validator):
        passed += 1
        accepted_names.append("reused-object")
    else:
        failed += 1

    def refresh_usage(document: dict[str, Any]) -> None:
        document["usage"]["generation"]["metadataDigest"] = _usage_metadata_digest(document)
        document["generation"]["metadataDigest"] = _publication_metadata_digest(document)

    variants: dict[str, dict[str, Any]] = {}
    variant = copy.deepcopy(clean)
    for row in variant["usage"]["invocations"] + variant["usage"]["summaries"] + variant["usage"]["globals"]:
        for field in USAGE_COST_FIELDS:
            row[field] = None
        for field in ("knownCostSubtotalMicroUsd",):
            if field in row:
                row[field] = None
        for field in ("priceEntryDigest", "priceProvenanceDigest"):
            if field in row:
                row[field] = None
    for row in variant["usage"]["turns"]:
        for field in USAGE_COST_FIELDS:
            row[field] = None
        row["priceEntryDigest"] = None
    variant["usage"]["prices"] = []
    variant["usage"]["generation"]["expectedCounts"]["prices"] = 0
    refresh_usage(variant)
    variants["all-na-costs"] = variant
    variant = copy.deepcopy(clean)
    for row in variant["usage"]["invocations"] + variant["usage"]["summaries"] + variant["usage"]["globals"] + variant["usage"]["turns"]:
        for field in USAGE_TOKEN_FIELDS:
            row[field] = 0
        if "knownTokenSubtotal" in row:
            row["knownTokenSubtotal"] = None if row.get("coverage") == "unavailable" else 0
    refresh_usage(variant)
    variants["zero-token"] = variant
    variant = copy.deepcopy(clean)
    invocation = variant["usage"]["invocations"][0]
    invocation["coverage"] = "partial"
    invocation["coveredTurns"] = 0
    for field in USAGE_ALL_FIELDS:
        invocation[field] = None
    invocation["priceEntryDigest"] = None
    for row in variant["usage"]["summaries"] + variant["usage"]["globals"]:
        row["coverage"] = "partial"
        row["knownTokenSubtotal"] = None
        row["knownCostSubtotalMicroUsd"] = None
        for field in USAGE_ALL_FIELDS:
            row[field] = None
        row["priceProvenanceDigest"] = None
    refresh_usage(variant)
    variants["partial"] = variant
    for name, document in variants.items():
        variant_issues = validate_publication_document(document, validator)
        if variant_issues:
            print(f"FAIL accepted usage variant {name}: {', '.join(issue.rendered() for issue in variant_issues)}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
            accepted_names.append(name)

    negatives: dict[str, tuple[dict[str, Any], str]] = {}
    mutated = copy.deepcopy(clean); mutated["unknown"] = True; negatives["unknown-field"] = (mutated, "schema-additionalProperties")
    mutated = copy.deepcopy(clean); mutated["publicationId"] = "bad id"; negatives["malformed-id"] = (mutated, "schema-pattern")
    mutated = copy.deepcopy(clean); mutated["task"]["createdAt"] = "0000-01-01T00:00:00Z"; negatives["zero-timestamp"] = (mutated, "timestamp")
    mutated = copy.deepcopy(clean); mutated["runs"][0]["runState"] = "running"; negatives["partial-run"] = (mutated, "schema-enum")
    mutated = copy.deepcopy(clean); mutated["generation"]["expectedCounts"]["artifacts"] = 4; negatives["bad-count"] = (mutated, "row-count")
    mutated = copy.deepcopy(clean); mutated["pipelines"][0]["taskId"] = "other-task"; negatives["ownership"] = (mutated, "ownership")
    mutated = copy.deepcopy(clean); mutated["events"][1]["sequence"] = 3; negatives["event-order"] = (mutated, "event-order")
    mutated = copy.deepcopy(clean); mutated["runs"][0]["atifArtifactId"] = "missing"; negatives["atif-link"] = (mutated, "atif-artifact")
    mutated = copy.deepcopy(clean); mutated["artifacts"][0]["publicKey"] = f"v1/tasks/{clean['taskId']}/objects/sha256/bb/" + "b" * 64; negatives["digest-key"] = (mutated, "artifact-key")
    mutated = copy.deepcopy(clean); mutated["generation"]["metadataDigest"] = "c" * 64; negatives["metadata-digest"] = (mutated, "metadata-digest")
    mutated = copy.deepcopy(clean); mutated["runs"][0]["atifDigest"] = "c" * 64; negatives["atif-digest"] = (mutated, "atif-digest")
    mutated = copy.deepcopy(clean); mutated["artifacts"][0]["publicKey"] = "https://private.example/object"; negatives["noncanonical-key"] = (mutated, "artifact-key")
    mutated = copy.deepcopy(clean); mutated["artifacts"][0]["logicalPath"] = "/private/trajectory.json"; negatives["private-locator"] = (mutated, "private-locator")
    mutated = copy.deepcopy(clean); mutated["privateBucket"] = "not included"; negatives["private-field"] = (mutated, "private-field")
    mutated = copy.deepcopy(clean); mutated["artifacts"][1]["byteSize"] = -1; negatives["negative-size"] = (mutated, "schema-minimum")
    mutated = copy.deepcopy(clean); mutated["pipelines"][0]["name"] = "p" * 257; mutated["generation"]["metadataDigest"] = _publication_metadata_digest(mutated); negatives["pipeline-name-d1-limit"] = (mutated, "schema-maxLength")
    mutated = copy.deepcopy(clean); mutated["runs"][0]["role"] = "r" * 129; mutated["generation"]["metadataDigest"] = _publication_metadata_digest(mutated); negatives["run-role-d1-limit"] = (mutated, "schema-maxLength")
    mutated = copy.deepcopy(clean); mutated["events"][0]["eventType"] = "e" * 129; mutated["generation"]["metadataDigest"] = _publication_metadata_digest(mutated); negatives["event-type-d1-limit"] = (mutated, "schema-maxLength")
    mutated = copy.deepcopy(clean); mutated["artifacts"][1]["logicalPath"] = mutated["artifacts"][0]["logicalPath"]; mutated["generation"]["metadataDigest"] = _publication_metadata_digest(mutated); negatives["duplicate-logical-path"] = (mutated, "artifact-logical-path-unique")
    mutated = copy.deepcopy(clean); mutated["artifacts"][1]["sha256"] = mutated["artifacts"][0]["sha256"]; mutated["artifacts"][1]["publicKey"] = mutated["artifacts"][0]["publicKey"]; mutated["artifacts"][1]["byteSize"] = mutated["artifacts"][0]["byteSize"] + 1; mutated["generation"]["metadataDigest"] = _publication_metadata_digest(mutated); negatives["conflicting-object-size"] = (mutated, "artifact-object-size")
    mutated = copy.deepcopy(clean); mutated["usage"]["turns"][0]["invocationId"] = "missing"; refresh_usage(mutated); negatives["dangling-turn"] = (mutated, "usage-turn-ownership")
    mutated = copy.deepcopy(clean); mutated["usage"]["summaries"][0]["knownTokenSubtotal"] = 19; refresh_usage(mutated); negatives["wrong-usage-rollup"] = (mutated, "usage-summary-rollup")
    mutated = copy.deepcopy(clean); duplicate_price = copy.deepcopy(mutated["usage"]["prices"][0]); duplicate_price["priceEntryDigest"] = "f" * 64; duplicate_price["effectiveAt"] = "2026-02-01T00:00:00Z"; mutated["usage"]["prices"].append(duplicate_price); mutated["usage"]["generation"]["expectedCounts"]["prices"] = 2; refresh_usage(mutated); negatives["overlapping-price"] = (mutated, "usage-price-overlap")
    mutated = copy.deepcopy(clean); mutated["usage"]["invocations"][0]["promptTokens"] = SAFE_INTEGER_MAX + 1; refresh_usage(mutated); negatives["unsafe-usage-integer"] = (mutated, "usage-safe-integer")
    mutated = copy.deepcopy(clean); mutated["usage"]["invocations"][0]["ownershipClass"] = "steward-overhead"; refresh_usage(mutated); negatives["overhead-detail"] = (mutated, "usage-overhead")
    mutated = copy.deepcopy(clean); mutated["usage"]["turns"][0]["ordinal"] = 2; refresh_usage(mutated); negatives["cursor-order"] = (mutated, "usage-cursor-order")
    fixture_mutations: dict[str, tuple[dict[str, Any], str, bool, str]] = {}
    fixture = copy.deepcopy(fixtures["clean"])
    fixture["atif"]["extra"]["coquic"]["credentialPath"] = "redacted"
    fixture_mutations["recursive-private-field"] = (fixture, "private-field", False, "completed")
    fixture = copy.deepcopy(fixtures["clean"])
    fixture["objects"][1]["sha256"] = "0" * 64
    fixture_mutations["object-digest"] = (fixture, "object-digest", False, "completed")
    fixture = copy.deepcopy(fixtures["clean"])
    fixture["objects"][1]["byteSize"] += 1
    fixture_mutations["object-size"] = (fixture, "object-size", False, "completed")
    fixture = copy.deepcopy(fixtures["clean"])
    fixture["atif"]["extra"]["coquic"]["artifacts"][0]["artifactId"] = "missing"
    fixture_mutations["dangling-atif-artifact"] = (fixture, "atif-artifact", False, "completed")
    fixture = copy.deepcopy(fixtures["clean"])
    fixture["publication"]["generation"]["expectedCounts"]["artifacts"] = 4
    fixture_mutations["fixture-count"] = (fixture, "row-count", False, "completed")
    fixture = copy.deepcopy(fixtures["redacted"])
    for artifact in fixture["publication"]["artifacts"]:
        artifact["disclosure"]["redactionApplied"] = False
    fixture["publication"]["generation"]["metadataDigest"] = _publication_metadata_digest(fixture["publication"])
    fixture_mutations["publication-artifact-disclosure"] = (fixture, "atif-disclosure", True, "completed")
    fixture = copy.deepcopy(fixtures["active-after-planning"])
    fixture["atif"]["extra"]["coquic"]["role"] = "implementation"
    atif_raw = canonical_bytes(fixture["atif"])
    atif_digest = hashlib.sha256(atif_raw).hexdigest()
    atif_artifact_id = fixture["publication"]["runs"][0]["atifArtifactId"]
    atif_key = f"v1/tasks/{fixture['publication']['taskId']}/objects/sha256/{atif_digest[:2]}/{atif_digest}"
    atif_artifact = next(item for item in fixture["publication"]["artifacts"] if item["artifactId"] == atif_artifact_id)
    atif_object = next(item for item in fixture["objects"] if item["artifactId"] == atif_artifact_id)
    fixture["publication"]["runs"][0]["atifDigest"] = atif_digest
    atif_artifact.update({"sha256": atif_digest, "byteSize": len(atif_raw), "publicKey": atif_key})
    atif_object.update({"sha256": atif_digest, "byteSize": len(atif_raw), "publicKey": atif_key, "content": fixture["atif"]})
    fixture["publication"]["generation"]["metadataDigest"] = _publication_metadata_digest(fixture["publication"])
    fixture_mutations["atif-run-provenance"] = (fixture, "atif-provenance", False, "active")
    for name, (fixture, expected_rule, redaction, lifecycle) in fixture_mutations.items():
        issues = validate_publication_fixture(fixture, validator, atif_validator, expected_redaction=redaction, expected_lifecycle=lifecycle)
        if not any(issue.rule == expected_rule for issue in issues):
            print(f"FAIL rejected publication {name}: missing {expected_rule}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
            rejected_names.append(name)
    for name, (document, expected_rule) in negatives.items():
        issues = validate_publication_document(document, validator)
        if not any(issue.rule == expected_rule for issue in issues):
            print(f"FAIL rejected publication {name}: missing {expected_rule}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
            rejected_names.append(name)
    print(f"Publication checks: accepted={','.join(accepted_names)} rejected={','.join(rejected_names)} failed={failed}")
    return passed, failed


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST_PATTERN.fullmatch(value))


def _valid_public_key(value: Any, task_id: str | None = None, digest: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    match = PUBLIC_KEY_PATTERN.fullmatch(value)
    return bool(match and match.group(2) == match.group(3)[:2]
        and (task_id is None or match.group(1) == task_id)
        and (digest is None or match.group(3) == digest))


def _valid_private_key(value: Any) -> bool:
    return isinstance(value, str) and bool(PRIVATE_KEY_PATTERN.fullmatch(value))


def _private_d1_column(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return compact not in {"publickey", "logicalpath", *SAFE_USAGE_FIELDS} and (
        bool(PRIVATE_NAME.search(compact))
        or compact in {"url", "uri", "endpoint", "baseurl", "baseuri", "filepath", "credentialpath", "privatepath"}
    )


def _d1_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(D1_SCHEMA_PATH.read_text(encoding="utf-8"))
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise RuntimeError("foreign keys are disabled")
    return connection


def _d1_public_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        """
        SELECT h.task_id, p.publication_id, t.title, r.run_id
          FROM task_heads AS h
          JOIN publication_generations AS p
            ON p.publication_id = h.publication_id AND p.state = 'visible'
          JOIN tasks AS t
            ON t.publication_id = p.publication_id AND t.task_id = h.task_id
          JOIN runs AS r
            ON r.publication_id = p.publication_id AND r.task_id = h.task_id
          JOIN usage_heads AS uh
            ON uh.task_id = h.task_id
           AND uh.usage_generation_id = h.usage_generation_id
           AND uh.state = 'visible'
          JOIN usage_generations AS ug
            ON ug.usage_generation_id = uh.usage_generation_id
           AND ug.state = 'visible'
         WHERE h.state = 'visible'
         ORDER BY h.task_id
        """
    ).fetchall()


def _d1_stage(
    connection: sqlite3.Connection,
    publication_id: str,
    task_id: str,
    run_id: str,
    metadata_digest: str,
    *,
    artifact_rows: int = 2,
    expected_artifact_count: int = 2,
) -> None:
    key_digest = "0" * 64
    public_key = f"v1/tasks/{task_id}/objects/sha256/{key_digest[:2]}/{key_digest}"
    usage_generation_id = f"usage-{publication_id}"
    price_digest = hashlib.sha256(usage_generation_id.encode("utf-8")).hexdigest()
    usage_metadata_digest = "e" * 64
    expected_generation = (task_id, run_id, metadata_digest, f"retry-{publication_id}", "staged", 1, 1, 1, 1, expected_artifact_count, "2026-07-28T00:00:00Z")
    generation_sql = "SELECT task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at FROM publication_generations WHERE publication_id = ?"
    existing_generation = connection.execute(generation_sql, (publication_id,)).fetchone()
    if existing_generation is not None and existing_generation != expected_generation:
        raise ValueError("generation-conflict")
    if existing_generation is not None:
        connection.execute("BEGIN")
        try:
            for index in range(artifact_rows):
                connection.execute(
                    "INSERT OR IGNORE INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) VALUES (?, ?, ?, ?, ?, ?, 'text/plain', ?, ?, 'available', 0, 1)",
                    (publication_id, f"artifact-{publication_id}-{index}", task_id, run_id, f"steps/1/output-{index}.txt", public_key, 12 + index, key_digest),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return
    connection.execute("BEGIN")
    try:
        connection.execute(
            "INSERT INTO publication_generations (publication_id, task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', 1, 1, 1, 1, ?, ?)",
            (publication_id, task_id, run_id, metadata_digest, f"retry-{publication_id}", expected_artifact_count, "2026-07-28T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO usage_generations (usage_generation_id, publication_id, task_id, schema_version, metadata_digest, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at) VALUES (?, ?, ?, '1.0', ?, 'staged', 2, 1, 1, 1, 1, ?)",
            (usage_generation_id, publication_id, task_id, usage_metadata_digest, "2026-07-28T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO tasks (publication_id, task_id, title, lifecycle_state, created_at, completed_at) VALUES (?, ?, ?, 'completed', ?, ?)",
            (publication_id, task_id, "Example task", "2026-07-28T00:00:00Z", "2026-07-28T00:00:01Z"),
        )
        pipeline_id = f"pipeline-{publication_id}"
        connection.execute(
            "INSERT INTO pipelines (publication_id, pipeline_id, task_id, name, created_at) VALUES (?, ?, ?, ?, ?)",
            (publication_id, pipeline_id, task_id, "Example pipeline", "2026-07-28T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO runs (publication_id, run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest) VALUES (?, ?, ?, ?, 'implementation', 'completed', ?, ?, 1000, ?)",
            (publication_id, run_id, task_id, pipeline_id, "2026-07-28T00:00:00Z", "2026-07-28T00:00:01Z", "f" * 64),
        )
        connection.execute(
            "INSERT INTO task_events (publication_id, task_id, sequence, event_type, occurred_at, summary) VALUES (?, ?, 1, 'completed', ?, ?)",
            (publication_id, task_id, "2026-07-28T00:00:01Z", "Run completed"),
        )
        for index in range(artifact_rows):
            connection.execute(
                "INSERT INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) VALUES (?, ?, ?, ?, ?, ?, 'text/plain', ?, ?, 'available', 0, 1)",
                (publication_id, f"artifact-{publication_id}-{index}", task_id, run_id, f"steps/1/output-{index}.txt", public_key, 12 + index, key_digest),
            )
        connection.execute(
            "INSERT INTO usage_prices (price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until) VALUES (?, ?, ?, 'gpt-fixture', ?, NULL)",
            (price_digest, usage_generation_id, "2" * 64, "2026-01-01T00:00:00Z"),
        )
        token_values = (11, 2, 9, 7, 3, 18)
        cost_values = (1, 2, 3, 6)
        for summary_id, scope, summary_run in ((f"summary-{publication_id}-task", "task", None), (f"summary-{publication_id}-run", "run", run_id)):
            connection.execute(
                "INSERT INTO usage_summaries (summary_id, usage_generation_id, publication_id, task_id, run_id, scope, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest) VALUES (?, ?, ?, ?, ?, ?, 'complete', 1, 1, 18, 6, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (summary_id, usage_generation_id, publication_id, task_id, summary_run, scope, *token_values, *cost_values, price_digest),
            )
        connection.execute(
            "INSERT INTO usage_invocations (invocation_id, usage_generation_id, publication_id, task_id, pipeline_id, run_id, ownership_class, retry_ordinal, started_at, completed_at, model, billing_mode, process_outcome, coverage, issue_count, covered_turns, expected_turns, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, 'task-owned', 0, ?, ?, 'gpt-fixture', 'api', 'success', 'complete', 0, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"invocation-{publication_id}", usage_generation_id, publication_id, task_id, pipeline_id, run_id, "2026-07-28T00:00:00Z", "2026-07-28T00:00:01Z", *token_values, *cost_values, price_digest),
        )
        connection.execute(
            "INSERT INTO usage_turns (turn_id, usage_generation_id, invocation_id, publication_id, task_id, run_id, ordinal, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"turn-{publication_id}", usage_generation_id, f"invocation-{publication_id}", publication_id, task_id, run_id, *token_values, *cost_values, price_digest),
        )
        connection.execute(
            "INSERT INTO usage_globals (global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only) VALUES (?, ?, 'lifetime', 'lifetime', 'gpt-fixture', 'task-owned', 'complete', 1, 1, 18, 6, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (f"global-{publication_id}", usage_generation_id, *token_values, *cost_values, price_digest),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_stage_overhead(
    connection: sqlite3.Connection,
    usage_generation_id: str = "usage-overhead-1",
    global_id: str = "global-overhead-1",
    *,
    period_kind: str = "daily",
    period_key: str = "2026-07-28",
    model: str = "gpt-overhead",
    publication_id: str | None = None,
    task_id: str | None = None,
) -> None:
    """Insert one detached overhead generation and its visible global head."""

    created_at = "2026-07-28T00:00:00Z"
    connection.execute(
        "INSERT INTO usage_generations (usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at, exposed_at) VALUES (?, ?, ?, 'steward-overhead', '1.0', ?, 'visible', 0, 0, 0, 0, 1, ?, ?)",
        (usage_generation_id, publication_id, task_id, "a" * 64, created_at, created_at),
    )
    connection.execute(
        "INSERT INTO usage_globals (global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only) VALUES (?, ?, ?, ?, ?, 'steward-overhead', 'complete', 1, 1, 8, 9, 5, 1, 4, 3, 1, 8, 4, 2, 3, 9, NULL, 1)",
        (global_id, usage_generation_id, period_kind, period_key, model),
    )
    connection.execute(
        "INSERT INTO usage_global_heads (period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) VALUES (?, ?, ?, 'steward-overhead', ?, ?, 'visible', ?)",
        (period_kind, period_key, model, usage_generation_id, global_id, created_at),
    )


def _d1_stage_usage_clone(connection: sqlite3.Connection, task_id: str, source_usage_id: str, new_usage_id: str) -> None:
    """Stage a second usage generation for the same visible publication."""

    source = connection.execute(
        "SELECT publication_id, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count FROM usage_generations WHERE usage_generation_id = ? AND task_id = ?",
        (source_usage_id, task_id),
    ).fetchone()
    if source is None:
        raise ValueError("usage-source")
    publication_id, summaries, invocations, turns, prices, globals_ = source
    run_id, pipeline_id = connection.execute(
        "SELECT r.run_id, r.pipeline_id FROM runs AS r WHERE r.publication_id = ? AND r.task_id = ? ORDER BY r.run_id LIMIT 1",
        (publication_id, task_id),
    ).fetchone()
    price_digest = "9" * 64
    invocation_id = f"invocation-{new_usage_id}"
    connection.execute("BEGIN")
    try:
        connection.execute(
            "INSERT INTO usage_generations (usage_generation_id, publication_id, task_id, schema_version, metadata_digest, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at) VALUES (?, ?, ?, '1.0', ?, 'staged', ?, ?, ?, ?, ?, ?)",
            (new_usage_id, publication_id, task_id, "f" * 64, summaries, invocations, turns, prices, globals_, "2026-07-28T00:00:03Z"),
        )
        connection.execute(
            "INSERT INTO usage_prices (price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until) VALUES (?, ?, ?, 'gpt-fixture', '2026-01-01T00:00:00Z', NULL)",
            (price_digest, new_usage_id, "8" * 64),
        )
        token_values = (11, 2, 9, 7, 3, 18)
        cost_values = (1, 2, 3, 6)
        for summary_id, scope, summary_run in ((f"summary-{new_usage_id}-task", "task", None), (f"summary-{new_usage_id}-run", "run", run_id)):
            connection.execute(
                "INSERT INTO usage_summaries (summary_id, usage_generation_id, publication_id, task_id, run_id, scope, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest) VALUES (?, ?, ?, ?, ?, ?, 'complete', 1, 1, 18, 6, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (summary_id, new_usage_id, publication_id, task_id, summary_run, scope, *token_values, *cost_values, price_digest),
            )
        connection.execute(
            "INSERT INTO usage_invocations (invocation_id, usage_generation_id, publication_id, task_id, pipeline_id, run_id, ownership_class, retry_ordinal, started_at, completed_at, model, billing_mode, process_outcome, coverage, issue_count, covered_turns, expected_turns, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, 'task-owned', 0, '2026-07-28T00:00:00Z', '2026-07-28T00:00:01Z', 'gpt-fixture', 'api', 'success', 'complete', 0, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (invocation_id, new_usage_id, publication_id, task_id, pipeline_id, run_id, *token_values, *cost_values, price_digest),
        )
        connection.execute(
            "INSERT INTO usage_turns (turn_id, usage_generation_id, invocation_id, publication_id, task_id, run_id, ordinal, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"turn-{new_usage_id}", new_usage_id, invocation_id, publication_id, task_id, run_id, *token_values, *cost_values, price_digest),
        )
        connection.execute(
            "INSERT INTO usage_globals (global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only) VALUES (?, ?, 'lifetime', 'lifetime', 'gpt-fixture', 'task-owned', 'complete', 1, 1, 18, 6, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (f"global-{new_usage_id}", new_usage_id, *token_values, *cost_values, price_digest),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_stage_payload(connection: sqlite3.Connection, payload: dict[str, Any]) -> None:
    generation = payload["generation"]
    counts = generation["expectedCounts"]
    task = payload["task"]
    usage = payload["usage"]
    usage_generation = usage["generation"]
    publication_id = payload["publicationId"]
    connection.execute("BEGIN")
    try:
        connection.execute(
            "INSERT INTO publication_generations (publication_id, task_id, run_id, metadata_digest, idempotency_key, state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?, ?)",
            (publication_id, payload["taskId"], generation["runId"], generation["metadataDigest"], generation["idempotencyKey"], counts["tasks"], counts["pipelines"], counts["runs"], counts["events"], counts["artifacts"], generation["createdAt"]),
        )
        usage_counts = usage_generation["expectedCounts"]
        connection.execute(
            "INSERT INTO usage_generations (usage_generation_id, publication_id, task_id, schema_version, metadata_digest, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?, ?)",
            (usage_generation["usageGenerationId"], publication_id, payload["taskId"], usage_generation["schemaVersion"], usage_generation["metadataDigest"], usage_counts["summaries"], usage_counts["invocations"], usage_counts["turns"], usage_counts["prices"], usage_counts["globals"], usage_generation["createdAt"]),
        )
        connection.execute(
            "INSERT INTO tasks (publication_id, task_id, title, lifecycle_state, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (publication_id, task["taskId"], task["title"], task["lifecycleState"], task["createdAt"], task["completedAt"]),
        )
        for pipeline in payload["pipelines"]:
            connection.execute(
                "INSERT INTO pipelines (publication_id, pipeline_id, task_id, name, created_at) VALUES (?, ?, ?, ?, ?)",
                (publication_id, pipeline["pipelineId"], pipeline["taskId"], pipeline["name"], pipeline["createdAt"]),
            )
        for run in payload["runs"]:
            connection.execute(
                "INSERT INTO runs (publication_id, run_id, task_id, pipeline_id, role, run_state, started_at, completed_at, duration_ms, atif_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (publication_id, run["runId"], run["taskId"], run["pipelineId"], run["role"], run["runState"], run["startedAt"], run["completedAt"], run["durationMs"], run["atifDigest"]),
            )
        for event in payload["events"]:
            connection.execute(
                "INSERT INTO task_events (publication_id, task_id, sequence, event_type, occurred_at, summary) VALUES (?, ?, ?, ?, ?, ?)",
                (publication_id, event["taskId"], event["sequence"], event["eventType"], event["occurredAt"], event["summary"]),
            )
        for artifact in payload["artifacts"]:
            disclosure = artifact["disclosure"]
            connection.execute(
                "INSERT INTO artifacts (publication_id, artifact_id, task_id, run_id, logical_path, public_key, media_type, byte_size, sha256, availability, redaction_applied, original_retained) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (publication_id, artifact["artifactId"], artifact["taskId"], artifact["runId"], artifact["logicalPath"], artifact["publicKey"], artifact["mediaType"], artifact["byteSize"], artifact["sha256"], artifact["availability"], int(disclosure["redactionApplied"]), int(disclosure["originalRetained"])),
            )
        for price in usage["prices"]:
            connection.execute(
                "INSERT INTO usage_prices (price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until) VALUES (?, ?, ?, ?, ?, ?)",
                (price["priceEntryDigest"], price["usageGenerationId"], price["catalogDigest"], price["model"], price["effectiveAt"], price["effectiveUntil"]),
            )
        for summary in usage["summaries"]:
            connection.execute(
                "INSERT INTO usage_summaries (summary_id, usage_generation_id, publication_id, task_id, run_id, scope, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (summary["summaryId"], summary["usageGenerationId"], summary["publicationId"], summary["taskId"], summary["runId"], summary["scope"], summary["coverage"], summary["coveredInvocations"], summary["expectedInvocations"], summary["knownTokenSubtotal"], summary["knownCostSubtotalMicroUsd"], summary["promptTokens"], summary["cachedTokens"], summary["uncachedTokens"], summary["completionTokens"], summary["reasoningTokens"], summary["totalTokens"], summary["uncachedInputCostMicroUsd"], summary["cachedInputCostMicroUsd"], summary["outputCostMicroUsd"], summary["totalCostMicroUsd"], summary["priceProvenanceDigest"]),
            )
        for invocation in usage["invocations"]:
            connection.execute(
                "INSERT INTO usage_invocations (invocation_id, usage_generation_id, publication_id, task_id, pipeline_id, run_id, ownership_class, retry_ordinal, started_at, completed_at, model, billing_mode, process_outcome, coverage, issue_count, covered_turns, expected_turns, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (invocation["invocationId"], invocation["usageGenerationId"], invocation["publicationId"], invocation["taskId"], invocation["pipelineId"], invocation["runId"], invocation["ownershipClass"], invocation["retryOrdinal"], invocation["startedAt"], invocation["completedAt"], invocation["model"], invocation["billingMode"], invocation["processOutcome"], invocation["coverage"], invocation["issueCount"], invocation["coveredTurns"], invocation["expectedTurns"], invocation["promptTokens"], invocation["cachedTokens"], invocation["uncachedTokens"], invocation["completionTokens"], invocation["reasoningTokens"], invocation["totalTokens"], invocation["uncachedInputCostMicroUsd"], invocation["cachedInputCostMicroUsd"], invocation["outputCostMicroUsd"], invocation["totalCostMicroUsd"], invocation["priceEntryDigest"]),
            )
        for turn in usage["turns"]:
            connection.execute(
                "INSERT INTO usage_turns (turn_id, usage_generation_id, invocation_id, publication_id, task_id, run_id, ordinal, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_entry_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (turn["turnId"], turn["usageGenerationId"], turn["invocationId"], turn["publicationId"], turn["taskId"], turn["runId"], turn["ordinal"], turn["promptTokens"], turn["cachedTokens"], turn["uncachedTokens"], turn["completionTokens"], turn["reasoningTokens"], turn["totalTokens"], turn["uncachedInputCostMicroUsd"], turn["cachedInputCostMicroUsd"], turn["outputCostMicroUsd"], turn["totalCostMicroUsd"], turn["priceEntryDigest"]),
            )
        for row in usage["globals"]:
            connection.execute(
                "INSERT INTO usage_globals (global_id, usage_generation_id, period_kind, period_key, model, ownership_class, coverage, covered_invocations, expected_invocations, known_token_subtotal, known_cost_subtotal_micro_usd, prompt_tokens, cached_tokens, uncached_tokens, completion_tokens, reasoning_tokens, total_tokens, uncached_input_cost_micro_usd, cached_input_cost_micro_usd, output_cost_micro_usd, total_cost_micro_usd, price_provenance_digest, aggregate_only) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row["globalId"], row["usageGenerationId"], row["periodKind"], row["periodKey"], row["model"], row["ownershipClass"], row["coverage"], row["coveredInvocations"], row["expectedInvocations"], row["knownTokenSubtotal"], row["knownCostSubtotalMicroUsd"], row["promptTokens"], row["cachedTokens"], row["uncachedTokens"], row["completionTokens"], row["reasoningTokens"], row["totalTokens"], row["uncachedInputCostMicroUsd"], row["cachedInputCostMicroUsd"], row["outputCostMicroUsd"], row["totalCostMicroUsd"], row["priceProvenanceDigest"], int(row["aggregateOnly"])),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _fixture_d1_probe(payload: dict[str, Any]) -> bool:
    connection = _d1_connection()
    try:
        _d1_stage_payload(connection, payload)
        if _d1_public_rows(connection):
            return False
        _d1_expose(connection, payload["taskId"], payload["publicationId"])
        visible = _d1_public_rows(connection)
        expected = [(payload["taskId"], payload["publicationId"], payload["task"]["title"], payload["runs"][0]["runId"])]
        if visible != expected:
            return False
        _d1_hide(connection, payload["taskId"])
        return _d1_public_rows(connection) == []
    finally:
        connection.close()


def _d1_expose(
    connection: sqlite3.Connection,
    task_id: str,
    publication_id: str,
    *,
    inject_failure: bool = False,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        row = connection.execute(
            "SELECT state, expected_task_count, expected_pipeline_count, expected_run_count, expected_event_count, expected_artifact_count "
            "FROM publication_generations WHERE publication_id = ? AND task_id = ?",
            (publication_id, task_id),
        ).fetchone()
        if row is None or row[0] != "staged":
            raise ValueError("generation-state")
        expected_tables = ("tasks", "pipelines", "runs", "task_events", "artifacts")
        for table, expected in zip(expected_tables, row[1:]):
            actual = connection.execute(f"SELECT count(*) FROM {table} WHERE publication_id = ?", (publication_id,)).fetchone()[0]
            if actual != expected:
                raise ValueError("row-count")
        usage_row = connection.execute(
            "SELECT usage_generation_id, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count FROM usage_generations WHERE publication_id = ? AND task_id = ?",
            (publication_id, task_id),
        ).fetchone()
        if usage_row is None or usage_row[1] != "staged":
            raise ValueError("usage-generation-state")
        usage_id = usage_row[0]
        for table, expected in zip(("usage_summaries", "usage_invocations", "usage_turns", "usage_prices", "usage_globals"), usage_row[2:]):
            actual = connection.execute(f"SELECT count(*) FROM {table} WHERE usage_generation_id = ?", (usage_id,)).fetchone()[0]
            if actual != expected:
                raise ValueError("usage-row-count")
        connection.execute(
            "UPDATE publication_generations SET state = 'superseded' WHERE task_id = ? AND state = 'visible' AND publication_id <> ?",
            (task_id, publication_id),
        )
        connection.execute(
            "UPDATE usage_generations SET state = 'superseded' WHERE task_id = ? AND state = 'visible' AND usage_generation_id <> ?",
            (task_id, usage_id),
        )
        changed = connection.execute(
            "UPDATE publication_generations SET state = 'visible', exposed_at = ? WHERE publication_id = ? AND state = 'staged'",
            ("2026-07-28T00:00:02Z", publication_id),
        ).rowcount
        if changed != 1:
            raise ValueError("generation-state")
        usage_changed = connection.execute(
            "UPDATE usage_generations SET state = 'visible', exposed_at = ? WHERE usage_generation_id = ? AND state = 'staged'",
            ("2026-07-28T00:00:02Z", usage_id),
        ).rowcount
        if usage_changed != 1:
            raise ValueError("usage-generation-state")
        if inject_failure:
            raise RuntimeError("injected-swap-failure")
        connection.execute(
            "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) VALUES (?, ?, 'visible', ?) ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, state = 'visible', updated_at = excluded.updated_at",
            (task_id, usage_id, "2026-07-28T00:00:02Z"),
        )
        connection.execute(
            "INSERT INTO task_heads (task_id, publication_id, usage_generation_id, state, updated_at) VALUES (?, ?, ?, 'visible', ?) ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, usage_generation_id = excluded.usage_generation_id, state = 'visible', updated_at = excluded.updated_at",
            (task_id, publication_id, usage_id, "2026-07-28T00:00:02Z"),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_swap_usage(
    connection: sqlite3.Connection,
    task_id: str,
    usage_generation_id: str,
    *,
    inject_failure: bool = False,
) -> None:
    """Atomically replace only usage while retaining the visible task publication."""

    connection.execute("BEGIN IMMEDIATE")
    try:
        task_head = connection.execute(
            "SELECT publication_id, state FROM task_heads WHERE task_id = ?", (task_id,)
        ).fetchone()
        usage = connection.execute(
            "SELECT state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count FROM usage_generations WHERE usage_generation_id = ? AND task_id = ?",
            (usage_generation_id, task_id),
        ).fetchone()
        if task_head is None or task_head[1] != "visible" or usage is None or usage[0] != "staged":
            raise ValueError("usage-swap-state")
        for table, expected in zip(("usage_summaries", "usage_invocations", "usage_turns", "usage_prices", "usage_globals"), usage[1:]):
            actual = connection.execute(f"SELECT count(*) FROM {table} WHERE usage_generation_id = ?", (usage_generation_id,)).fetchone()[0]
            if actual != expected:
                raise ValueError("usage-row-count")
        connection.execute(
            "UPDATE usage_generations SET state = 'superseded' WHERE task_id = ? AND state = 'visible' AND usage_generation_id <> ?",
            (task_id, usage_generation_id),
        )
        if connection.execute(
            "UPDATE usage_generations SET state = 'visible', exposed_at = ? WHERE usage_generation_id = ? AND state = 'staged'",
            ("2026-07-28T00:00:04Z", usage_generation_id),
        ).rowcount != 1:
            raise ValueError("usage-swap-state")
        if inject_failure:
            raise RuntimeError("injected-usage-swap-failure")
        connection.execute(
            "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) VALUES (?, ?, 'visible', ?) ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, state = 'visible', updated_at = excluded.updated_at",
            (task_id, usage_generation_id, "2026-07-28T00:00:04Z"),
        )
        connection.execute(
            "UPDATE task_heads SET usage_generation_id = ?, updated_at = ? WHERE task_id = ? AND state = 'visible'",
            (usage_generation_id, "2026-07-28T00:00:04Z", task_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_hide(connection: sqlite3.Connection, task_id: str) -> None:
    """Apply the atomic remote hide/supersession batch used by D1 client."""

    connection.execute("BEGIN IMMEDIATE")
    try:
        head = connection.execute(
            "SELECT publication_id, usage_generation_id, state FROM task_heads WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if head is None:
            visible = connection.execute(
                "SELECT publication_id FROM publication_generations "
                "WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, publication_id DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            usage_visible = connection.execute(
                "SELECT usage_generation_id FROM usage_generations WHERE task_id = ? AND state = 'visible' ORDER BY exposed_at DESC, usage_generation_id DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            head = None if visible is None else (visible[0], usage_visible[0] if usage_visible else None, None)
        staged = connection.execute(
            "SELECT count(*) FROM publication_generations WHERE task_id = ? AND state = 'staged'",
            (task_id,),
        ).fetchone()[0]
        if staged:
            connection.execute(
                "UPDATE publication_generations SET state = 'superseded' "
                "WHERE task_id = ? AND state = 'staged'",
                (task_id,),
            )
        connection.execute(
            "UPDATE usage_generations SET state = 'superseded' WHERE task_id = ? AND state = 'staged'",
            (task_id,),
        )
        if head is not None and head[0] is not None and head[2] != "hidden":
            connection.execute(
                "INSERT INTO usage_heads (task_id, usage_generation_id, state, updated_at) VALUES (?, ?, 'hidden', ?) ON CONFLICT(task_id) DO UPDATE SET usage_generation_id = excluded.usage_generation_id, state = 'hidden', updated_at = excluded.updated_at",
                (task_id, head[1], "2026-07-28T00:00:03Z"),
            )
            connection.execute(
                "INSERT INTO task_heads (task_id, publication_id, usage_generation_id, state, updated_at) VALUES (?, ?, ?, 'hidden', ?) ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, usage_generation_id = excluded.usage_generation_id, state = 'hidden', updated_at = excluded.updated_at",
                (task_id, head[0], head[1], "2026-07-28T00:00:03Z"),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _d1_rejected(connection: sqlite3.Connection, statement: str, parameters: tuple[Any, ...]) -> bool:
    connection.execute("BEGIN")
    try:
        connection.execute(statement, parameters)
    except sqlite3.IntegrityError:
        connection.rollback()
        return True
    connection.rollback()
    return False

def _d1_stage_rejected(connection: sqlite3.Connection, *arguments: Any) -> bool:
    try: _d1_stage(connection, *arguments)
    except ValueError: return True
    return False


def _run_d1_cases() -> tuple[int, int]:
    checks: list[tuple[str, bool]] = []
    connection: sqlite3.Connection | None = None

    def record(name: str, result: bool) -> None:
        checks.append((name, result))

    try:
        connection = _d1_connection()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        record("schema-load", EXPECTED_D1_TABLES <= tables)
        record("foreign-keys", connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
        columns = [column[1] for table in sorted(EXPECTED_D1_TABLES) for column in connection.execute(f"PRAGMA table_info({table})")]
        record("private-locator-denial", not any(_private_d1_column(column) for column in columns))
        record("key-grammar", _valid_public_key("v1/tasks/task-1/objects/sha256/00/" + "0" * 64, "task-1", "0" * 64) and _valid_private_key("v1/originals/task-1/run-1/sha256/" + "a" * 64 + ".jsonl") and not _valid_public_key("v1/originals/task-1/run-1/sha256/" + "a" * 64 + ".jsonl") and not _valid_public_key("v1/tasks/task-1/objects/sha256/AA/" + "A" * 64) and not _valid_public_key("v1/tasks/task-1/objects/sha256/01/" + "0" * 64) and _valid_digest("0" * 64) and not _valid_digest("A" * 64))
        _d1_stage(connection, "pub-1", "task-1", "run-1", "a" * 64)
        record("staged-hidden", _d1_public_rows(connection) == [])
        _d1_expose(connection, "task-1", "pub-1")
        record("task-plus-usage-atomic-expose", _d1_public_rows(connection) == [("task-1", "pub-1", "Example task", "run-1")])
        record("head-generation-agreement", connection.execute("SELECT h.publication_id = p.publication_id AND h.usage_generation_id = uh.usage_generation_id FROM task_heads h JOIN publication_generations p ON p.publication_id = h.publication_id JOIN usage_heads uh ON uh.task_id = h.task_id WHERE h.task_id = 'task-1'").fetchone()[0] == 1)
        _d1_stage(connection, "pub-2", "task-1", "run-2", "b" * 64, artifact_rows=1)
        _d1_stage(connection, "pub-2", "task-1", "run-2", "b" * 64)
        record("staging-isolation", _d1_public_rows(connection)[0][1] == "pub-1")
        record("object-key-reuse", connection.execute("SELECT count(DISTINCT public_key) FROM artifacts WHERE publication_id = 'pub-2'").fetchone()[0] == 1)
        try:
            _d1_expose(connection, "task-1", "pub-2", inject_failure=True)
        except RuntimeError:
            pass
        record("publication-usage-swap-rollback", _d1_public_rows(connection)[0][1] == "pub-1" and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-1'").fetchone()[0] == "visible" and connection.execute("SELECT state FROM usage_generations WHERE usage_generation_id = 'usage-pub-2'").fetchone()[0] == "staged")
        _d1_expose(connection, "task-1", "pub-2")
        record("supersede-and-repoint", _d1_public_rows(connection)[0][1] == "pub-2" and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-1'").fetchone()[0] == "superseded" and connection.execute("SELECT state FROM usage_generations WHERE usage_generation_id = 'usage-pub-1'").fetchone()[0] == "superseded")
        _d1_stage_usage_clone(connection, "task-1", "usage-pub-2", "usage-pub-2-refresh")
        try:
            _d1_swap_usage(connection, "task-1", "usage-pub-2-refresh", inject_failure=True)
        except RuntimeError:
            pass
        record("usage-only-swap-rollback", _d1_public_rows(connection)[0][1] == "pub-2" and connection.execute("SELECT usage_generation_id FROM task_heads WHERE task_id = 'task-1'").fetchone()[0] == "usage-pub-2" and connection.execute("SELECT state FROM usage_generations WHERE usage_generation_id = 'usage-pub-2-refresh'").fetchone()[0] == "staged")
        _d1_swap_usage(connection, "task-1", "usage-pub-2-refresh")
        record("usage-only-swap", _d1_public_rows(connection)[0][1] == "pub-2" and connection.execute("SELECT usage_generation_id FROM task_heads WHERE task_id = 'task-1'").fetchone()[0] == "usage-pub-2-refresh" and connection.execute("SELECT state FROM publication_generations WHERE publication_id = 'pub-2'").fetchone()[0] == "visible")
        _d1_stage(connection, "pub-bad", "task-1", "run-bad", "c" * 64, artifact_rows=1)
        try:
            _d1_expose(connection, "task-1", "pub-bad")
        except ValueError as error:
            record("row-count-denial", str(error) == "row-count")
        else:
            record("row-count-denial", False)
        record("invalid-state-denial", _d1_rejected(connection, "UPDATE publication_generations SET state = 'invalid' WHERE publication_id = ?", ("pub-2",)))
        record("invalid-digest-denial", _d1_rejected(connection, "UPDATE artifacts SET sha256 = ? WHERE publication_id = ?", ("A" * 64, "pub-2")))
        record("invalid-key-denial", _d1_rejected(connection, "UPDATE artifacts SET public_key = ? WHERE publication_id = ?", ("private://object", "pub-2")))
        record("private-name-denial", _private_d1_column("private_locator") and _private_d1_column("credential_url") and _d1_rejected(connection, "INSERT INTO task_heads (task_id, publication_id, usage_generation_id, state, updated_at) VALUES (?, ?, ?, 'visible', ?)", ("other-task", "pub-2", "usage-pub-2", "2026-07-28T00:00:00Z")))
        _d1_hide(connection, "task-1")
        record("hide-atomic-supersession", connection.execute("SELECT state FROM task_heads WHERE task_id = ?", ("task-1",)).fetchone()[0] == "hidden" and connection.execute("SELECT state FROM usage_heads WHERE task_id = ?", ("task-1",)).fetchone()[0] == "hidden" and connection.execute("SELECT count(*) FROM publication_generations WHERE task_id = ? AND state = 'staged'", ("task-1",)).fetchone()[0] == 0 and connection.execute("SELECT count(*) FROM usage_generations WHERE task_id = ? AND state = 'staged'", ("task-1",)).fetchone()[0] == 0)
        record("hidden-task-excluded", _d1_public_rows(connection) == [])
        overhead = _d1_connection()
        try:
            _d1_stage_overhead(overhead)
            overhead.commit()
            record(
                "overhead-detached-owner",
                overhead.execute(
                    "SELECT ug.publication_id IS NULL AND ug.task_id IS NULL AND ug.ownership_class = 'steward-overhead' AND NOT EXISTS (SELECT 1 FROM usage_heads WHERE usage_generation_id = ug.usage_generation_id) FROM usage_generations AS ug WHERE ug.usage_generation_id = 'usage-overhead-1'"
                ).fetchone()[0] == 1,
            )
            record(
                "overhead-private-shape-denial",
                _d1_rejected(
                    overhead,
                    "INSERT INTO usage_global_heads (period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) VALUES (?, ?, ?, 'steward-overhead', ?, ?, 'visible', ?)",
                    ("daily", "2026-07-28", "private://model", "usage-overhead-1", "global-overhead-1", "2026-07-28T00:00:00Z"),
                ),
            )
            record(
                "overhead-mixed-owner-denial",
                _d1_rejected(
                    overhead,
                    "INSERT INTO usage_generations (usage_generation_id, publication_id, task_id, ownership_class, schema_version, metadata_digest, state, expected_summary_count, expected_invocation_count, expected_turn_count, expected_price_count, expected_global_count, created_at) VALUES (?, ?, ?, 'steward-overhead', '1.0', ?, 'staged', 0, 0, 0, 0, 1, ?)",
                    ("usage-overhead-mixed", "pub-1", "task-1", "b" * 64, "2026-07-28T00:00:00Z"),
                ),
            )
            record(
                "overhead-dangling-head-denial",
                _d1_rejected(
                    overhead,
                    "INSERT INTO usage_global_heads (period_kind, period_key, model, ownership_class, usage_generation_id, global_id, state, updated_at) VALUES ('daily', '2026-07-29', 'gpt-overhead', 'steward-overhead', 'missing-generation', 'missing-global', 'visible', '2026-07-28T00:00:00Z')",
                    (),
                ),
            )
        finally:
            overhead.close()
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
        record("d1-execution", False)
        print(f"FAIL d1 execution: {type(error).__name__}", file=sys.stderr)
    finally:
        if connection is not None:
            connection.close()
    passed = sum(result for _, result in checks)
    failed = len(checks) - passed
    summary = ", ".join(f"{name}={'ok' if result else 'FAIL'}" for name, result in checks)
    print(f"D1 checks: {summary}")
    return passed, failed
def _example() -> dict[str, Any]:
    invocation = {
        "invocationId": "invocation-example",
        "taskId": "task-example",
        "pipelineId": "pipeline-example",
        "runId": "run-example",
        "retryOrdinal": 0,
        "startedAt": "2026-07-28T00:00:00Z",
        "completedAt": "2026-07-28T00:00:01Z",
        "model": "gpt-example",
        "billingMode": "unknown",
        "processOutcome": "success",
        "coverage": "complete",
        "issues": [],
        "aggregate": {
            "usage": {
                "prompt": 11,
                "cached": 2,
                "uncached": 9,
                "completion": 7,
                "reasoning": 3,
                "total": 18,
            }
        },
        "turns": [
            {
                "ordinal": 1,
                "prompt": 11,
                "cached": 2,
                "uncached": 9,
                "completion": 7,
                "reasoning": 3,
                "total": 18,
            }
        ],
    }
    return {
        "schema_version": "ATIF-v1.7",
        "agent": {"name": "codex", "version": "1"},
        "steps": [
            {"step_id": 1, "source": "user", "message": "Inspect the task."},
            {
                "step_id": 2,
                "source": "agent",
                "message": [
                    {"type": "text", "text": "The result is ready."},
                    {"type": "image", "source": {"media_type": "image/png", "path": "artifact:plot-1"}},
                ],
                "tool_calls": [{"tool_call_id": "call-1", "function_name": "inspect", "arguments": {}}],
                "observation": {
                    "results": [
                        {"source_call_id": "call-1", "content": "Inspection complete."}
                    ]
                },
                "extra": {"coquic": {"artifactIds": ["plot-1", "log-1"]}},
            },
        ],
        "extra": {
            "coquic": {
                "taskId": "task-example",
                "pipelineId": "pipeline-example",
                "runId": "run-example",
                "role": "implementation",
                "startedAt": "2026-07-28T00:00:00Z",
                "completedAt": "2026-07-28T00:00:01Z",
                "durationMs": 1000,
                "disclosure": {"redactionApplied": False, "originalRetained": True},
                "artifacts": [
                    {
                        "artifactId": "plot-1",
                        "mediaType": "image/png",
                        "sha256": "0" * 64,
                        "byteSize": 12,
                        "ownerStepId": 2,
                    },
                    {
                        "artifactId": "log-1",
                        "mediaType": "text/plain",
                        "sha256": "1" * 64,
                        "byteSize": 8,
                        "ownerStepId": 2,
                    },
                ],
                "source": {"invocations": [invocation]},
            }
        },
    }
def _run_cases(validator: Draft202012Validator) -> tuple[int, int]:
    clean = _example()
    redacted = copy.deepcopy(clean)
    redacted["extra"]["coquic"]["disclosure"] = {"redactionApplied": True, "originalRetained": True}
    partial = copy.deepcopy(clean)
    partial_invocation = copy.deepcopy(clean["extra"]["coquic"]["source"]["invocations"][0])
    partial_invocation.update(
        {
            "invocationId": "invocation-partial",
            "retryOrdinal": 1,
            "startedAt": None,
            "completedAt": None,
            "model": None,
            "billingMode": None,
            "processOutcome": "interrupted",
            "coverage": "partial",
            "issues": [{"category": "telemetry_incomplete", "count": 1}],
            "aggregate": None,
            "turns": [],
        }
    )
    partial["extra"]["coquic"]["source"]["invocations"].append(partial_invocation)
    unavailable = copy.deepcopy(clean)
    unavailable_invocation = copy.deepcopy(partial_invocation)
    unavailable_invocation.update(
        {"retryOrdinal": 0, "coverage": "unavailable", "processOutcome": None, "issues": [{"category": "telemetry_missing", "count": 1}]}
    )
    unavailable["extra"]["coquic"]["source"]["invocations"] = [unavailable_invocation]
    positives = {"clean": clean, "redacted": redacted, "partial": partial, "unavailable": unavailable}
    negatives: dict[str, tuple[dict[str, Any], str]] = {}
    mutated = copy.deepcopy(clean); mutated["schema_version"] = "ATIF-v1.6"; negatives["schema-version"] = (mutated, "root-schema-version")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["completedAt"] = None; negatives["partial-run"] = (mutated, "timing")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["step_id"] = 3; negatives["step-sequence"] = (mutated, "step-sequence")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["tool_calls"].append(copy.deepcopy(mutated["steps"][1]["tool_calls"][0])); negatives["duplicate-call"] = (mutated, "tool-call-unique")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["observation"]["results"][0]["source_call_id"] = "missing"; negatives["dangling-observation"] = (mutated, "observation-reference")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["message"][1]["source"]["media_type"] = "image/tiff"; negatives["unsupported-image"] = (mutated, "media-type")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["artifacts"] = []; negatives["missing-artifact"] = (mutated, "artifact-reference")
    mutated = copy.deepcopy(clean); mutated["steps"][1]["message"][1]["source"]["path"] = "https://private.example/object"; negatives["private-locator"] = (mutated, "private-locator")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["accessToken"] = "not printed"; negatives["token-metadata"] = (mutated, "private-field")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["disclosure"]["redactionApplied"] = "false"; negatives["disclosure-type"] = (mutated, "disclosure")
    mutated = copy.deepcopy(clean); duplicate = copy.deepcopy(mutated["extra"]["coquic"]["source"]["invocations"][0]); duplicate["retryOrdinal"] = 1; mutated["extra"]["coquic"]["source"]["invocations"].append(duplicate); negatives["invocation-duplicate"] = (mutated, "invocation-unique")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["taskId"] = "other-task"; negatives["invocation-ownership"] = (mutated, "invocation-ownership")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["model"] = "https://provider.example/model"; negatives["invocation-private-model"] = (mutated, "private-locator")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["turns"][0]["total"] = 19; negatives["invocation-turn-math"] = (mutated, "invocation-math")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["path"] = "private://telemetry"; negatives["invocation-private-shape"] = (mutated, "invocation-shape")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["aggregate"]["usage"]["total"] = 19; negatives["invocation-aggregate-math"] = (mutated, "invocation-math")
    mutated = copy.deepcopy(clean); del mutated["extra"]["coquic"]["source"]["invocations"]; negatives["invocation-missing"] = (mutated, "invocation-shape")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"] = []; negatives["invocation-empty"] = (mutated, "invocation-bound")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["invocationId"] = None; negatives["invocation-null-identity"] = (mutated, "invocation-id")
    mutated = copy.deepcopy(clean); mutated["extra"]["coquic"]["source"]["invocations"][0]["issues"] = [{"category": "too_many", "count": MAX_PUBLIC_INVOCATION_TOKENS + 1}]; negatives["invocation-issue-bound"] = (mutated, "invocation-issues")
    oversized = copy.deepcopy(clean)
    oversized_rows = []
    for index in range(MAX_PUBLIC_INVOCATIONS + 1):
        row = copy.deepcopy(clean["extra"]["coquic"]["source"]["invocations"][0])
        row["invocationId"] = f"invocation-{index}"
        row["retryOrdinal"] = index
        oversized_rows.append(row)
    oversized["extra"]["coquic"]["source"]["invocations"] = oversized_rows
    negatives["invocation-bound"] = (oversized, "invocation-bound")
    passed = 0
    failed = 0
    for name, document in positives.items():
        _, issues = validate_atif_bytes(canonical_bytes(document), validator)
        if issues:
            print(f"FAIL accepted {name}: {', '.join(issue.rendered() for issue in issues)}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
    for name, (document, expected_rule) in negatives.items():
        _, issues = validate_atif_bytes(canonical_bytes(document), validator)
        if not any(issue.rule == expected_rule for issue in issues):
            print(f"FAIL rejected {name}: missing {expected_rule}", file=sys.stderr)
            failed += 1
        else:
            passed += 1
    noncanonical = json.dumps(clean, ensure_ascii=False).encode("utf-8")
    _, issues = validate_atif_bytes(noncanonical, validator)
    if not any(issue.rule == "canonicalization" for issue in issues):
        print("FAIL rejected noncanonical: missing canonicalization", file=sys.stderr)
        failed += 1
    else:
        passed += 1
    print(f"ATIF checks: {passed} accepted cases, {failed} failed cases")
    return passed, failed
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Steward cloud contracts")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--atif-only", action="store_true", help="run the ATIF contract checks")
    modes.add_argument("--d1-only", action="store_true", help="run the clean D1 contract checks")
    modes.add_argument("--publication-only", action="store_true", help="run the staged publication contract checks")
    args = parser.parse_args(argv)
    if not any((args.atif_only, args.d1_only, args.publication_only)):
        return max(
            main(["--atif-only"]),
            main(["--d1-only"]),
            main(["--publication-only"]),
        )
    if args.d1_only:
        try:
            _, failed = _run_d1_cases()
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            print("D1 validator could not load its clean schema", file=sys.stderr)
            return 1
        return 1 if failed else 0
    if args.publication_only:
        try:
            publication_schema = json.loads(PUBLICATION_SCHEMA_PATH.read_text(encoding="utf-8"))
            atif_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(publication_schema)
            Draft202012Validator.check_schema(atif_schema)
            _, failed = _run_publication_cases(Draft202012Validator(publication_schema), Draft202012Validator(atif_schema))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            print("Publication validator could not load its staged schema", file=sys.stderr)
            return 1
        return 1 if failed else 0
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        _, failed = _run_cases(validator)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        print("ATIF validator could not load its pinned schema", file=sys.stderr)
        return 1
    return 1 if failed else 0
if __name__ == "__main__":
    raise SystemExit(main())
