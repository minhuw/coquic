from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import pytest

from coquic_steward.publication.d1 import (
    D1Error,
    D1ErrorCode,
    D1PublicationClient,
    MAX_BATCH_PARAMETERS,
)


ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "contracts" / "steward-cloud" / "d1.sql"
ACCOUNT = "a" * 32
DATABASE = "12345678-1234-4abc-8def-1234567890ab"
TOKEN = "test-token"
TS = "2026-07-28T00:00:00Z"
METADATA_FIELDS = ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts", "usage")


def refresh_metadata_digest(payload: dict[str, Any]) -> None:
    usage = payload["usage"]
    usage_generation = dict(usage["generation"])
    usage_generation["metadataDigest"] = ""
    usage_metadata = {
        "publicationId": payload["publicationId"],
        "taskId": payload["taskId"],
        "generation": usage_generation,
        "summaries": usage["summaries"],
        "invocations": usage["invocations"],
        "turns": usage["turns"],
        "prices": usage["prices"],
        "globals": usage["globals"],
    }
    usage_canonical = (
        json.dumps(usage_metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    payload["usage"]["generation"]["metadataDigest"] = hashlib.sha256(usage_canonical).hexdigest()
    metadata = {key: payload[key] for key in METADATA_FIELDS}
    canonical = (
        json.dumps(metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    payload["generation"]["metadataDigest"] = hashlib.sha256(canonical).hexdigest()


class ScriptedD1:
    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        self.requests: list[dict[str, Any]] = []
        self.fail_visibility_once = False
        self.fail_usage_swap_once = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        statements = body.get("batch")
        if statements is None:
            statements = [{"sql": body["sql"], "params": body.get("params", [])}]
        self.requests.append(body)
        if self.fail_visibility_once and any("UPDATE publication_generations SET state = 'superseded'" in item["sql"] for item in statements):
            self.fail_visibility_once = False
            return httpx.Response(503, json={"success": False, "errors": [{"code": "temporarily-unavailable"}]}, request=request)
        if self.fail_usage_swap_once and any("UPDATE usage_generations SET state = 'superseded'" in item["sql"] for item in statements):
            self.fail_usage_swap_once = False
            return httpx.Response(503, json={"success": False, "errors": [{"code": "temporarily-unavailable"}]}, request=request)

        results: list[dict[str, Any]] = []
        try:
            self.connection.execute("BEGIN")
            for item in statements:
                cursor = self.connection.execute(item["sql"], item.get("params", []))
                rows = [dict(row) for row in cursor.fetchall()] if cursor.description else []
                results.append({"success": True, "results": rows, "meta": {"changes": cursor.rowcount}})
            self.connection.commit()
        except sqlite3.Error:
            self.connection.rollback()
            return httpx.Response(400, json={"success": False, "errors": [{"code": "query-failed"}]}, request=request)
        return httpx.Response(200, json={"success": True, "errors": [], "result": results}, request=request)


class HideExposureInterposer(ScriptedD1):
    """Commit an exposure after hide's staged-generation read returns."""

    def __init__(self) -> None:
        super().__init__()
        self.after_staged_query: Any = None
        self.interposed = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        statements = body.get("batch")
        if statements is None:
            statements = [{"sql": body["sql"], "params": body.get("params", [])}]
        is_staged_query = any(
            item["sql"] == "SELECT publication_id FROM publication_generations WHERE task_id = ? AND state = 'staged'"
            for item in statements
        )
        response = super().__call__(request)
        if is_staged_query and not self.interposed:
            self.interposed = True
            callback = self.after_staged_query
            assert callable(callback)
            callback()
        return response


def client(server: ScriptedD1) -> D1PublicationClient:
    return D1PublicationClient(
        account_id=ACCOUNT,
        database_id=DATABASE,
        token=TOKEN,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )


def publication(
    publication_id: str = "publication-clean",
    *,
    run_id: str = "run-clean",
    artifact_count: int = 2,
    task_id: str = "task-clean",
) -> dict[str, Any]:
    pipeline_id = f"pipeline-{publication_id}"
    artifacts: list[dict[str, Any]] = []
    for index in range(artifact_count):
        content = f"artifact-{publication_id}-{index}".encode()
        digest = hashlib.sha256(content).hexdigest()
        artifacts.append(
            {
                "artifactId": f"artifact-{publication_id}-{index}",
                "taskId": task_id,
                "runId": run_id,
                "logicalPath": f"steps/1/output-{index}.txt",
                "publicKey": f"v1/tasks/{task_id}/objects/sha256/{digest[:2]}/{digest}",
                "mediaType": "text/plain",
                "byteSize": len(content),
                "sha256": digest,
                "availability": "available",
                "disclosure": {"redactionApplied": False, "originalRetained": True},
            }
        )
    usage_generation_id = f"usage-{publication_id}"
    # The catalog entry is shared across task publications; distinct facts
    # use distinct digests in the dedicated provenance tests below.
    price_digest = hashlib.sha256(b"price-gpt-fixture").hexdigest()
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
    invocation_id = f"invocation-{publication_id}"
    payload = {
        "schemaVersion": "2.0",
        "publicationId": publication_id,
        "taskId": task_id,
        "generation": {
            "publicationId": publication_id,
            "taskId": task_id,
            "runId": run_id,
            "metadataDigest": "0" * 64,
            "idempotencyKey": f"retry-{publication_id}",
            "state": "staged",
            "expectedCounts": {"tasks": 1, "pipelines": 1, "runs": 1, "events": 1, "artifacts": artifact_count},
            "createdAt": TS,
        },
        "headIntent": {"publicationId": publication_id, "taskId": task_id, "state": "visible", "updatedAt": "2026-07-28T00:00:02Z"},
        "task": {"taskId": task_id, "title": "Clean publication", "lifecycleState": "completed", "createdAt": TS, "completedAt": "2026-07-28T00:00:01Z"},
        "pipelines": [{"pipelineId": pipeline_id, "taskId": task_id, "name": "Planning", "createdAt": TS}],
        "runs": [{"runId": run_id, "taskId": task_id, "pipelineId": pipeline_id, "role": "planning", "runState": "completed", "startedAt": TS, "completedAt": "2026-07-28T00:00:01Z", "durationMs": 1000, "atifDigest": artifacts[0]["sha256"], "atifArtifactId": artifacts[0]["artifactId"]}],
        "events": [{"taskId": task_id, "sequence": 1, "eventType": "completed", "occurredAt": "2026-07-28T00:00:01Z", "summary": "Run completed"}],
        "artifacts": artifacts,
        "usage": {
            "schemaVersion": "1.0",
            "generation": {
                "usageGenerationId": usage_generation_id,
                "publicationId": publication_id,
                "taskId": task_id,
                "schemaVersion": "1.0",
                "metadataDigest": "0" * 64,
                "state": "staged",
                "expectedCounts": {"summaries": 2, "invocations": 1, "turns": 1, "prices": 1, "globals": 2},
                "createdAt": TS,
            },
            "summaries": [
                {
                    "summaryId": f"summary-task-{publication_id}",
                    "usageGenerationId": usage_generation_id,
                    "publicationId": publication_id,
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
                    "summaryId": f"summary-run-{publication_id}",
                    "usageGenerationId": usage_generation_id,
                    "publicationId": publication_id,
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
            "invocations": [
                {
                    "invocationId": invocation_id,
                    "usageGenerationId": usage_generation_id,
                    "publicationId": publication_id,
                    "taskId": task_id,
                    "pipelineId": pipeline_id,
                    "runId": run_id,
                    "ownershipClass": "task-owned",
                    "retryOrdinal": 0,
                    "startedAt": TS,
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
            ],
            "turns": [
                {
                    "turnId": f"turn-{publication_id}",
                    "usageGenerationId": usage_generation_id,
                    "invocationId": invocation_id,
                    "publicationId": publication_id,
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
                    "globalId": f"global-{publication_id}",
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
                    "globalId": f"global-overhead-{publication_id}",
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
        },
    }
    lifetime_global = payload["usage"]["globals"][0]
    daily_global = dict(lifetime_global)
    daily_global.update(
        {
            "globalId": f"global-daily-{publication_id}",
            "periodKind": "daily",
            "periodKey": "2026-07-28",
        }
    )
    payload["usage"]["globals"].insert(1, daily_global)
    payload["usage"]["generation"]["expectedCounts"]["globals"] = len(payload["usage"]["globals"])
    refresh_metadata_digest(payload)
    return payload


def usage_replacement(source: dict[str, Any], suffix: str) -> dict[str, Any]:
    replacement = copy.deepcopy(source)
    usage = replacement["usage"]
    previous_metadata_digest = replacement["generation"]["metadataDigest"]
    previous_usage_id = usage["generation"]["usageGenerationId"]
    usage_id = f"{previous_usage_id}-{suffix}"
    usage["generation"]["usageGenerationId"] = usage_id
    for row in usage["summaries"]:
        row["usageGenerationId"] = usage_id
        row["summaryId"] = f"{row['summaryId']}-{suffix}"
    for row in usage["invocations"]:
        row["usageGenerationId"] = usage_id
        row["invocationId"] = f"{row['invocationId']}-{suffix}"
    for row in usage["turns"]:
        row["usageGenerationId"] = usage_id
        row["turnId"] = f"{row['turnId']}-{suffix}"
        row["invocationId"] = f"{row['invocationId']}-{suffix}"
    for row in usage["prices"]:
        row["usageGenerationId"] = usage_id
    for row in usage["globals"]:
        row["usageGenerationId"] = usage_id
        row["globalId"] = f"{row['globalId']}-{suffix}"
    refresh_metadata_digest(replacement)
    replacement["generation"]["metadataDigest"] = previous_metadata_digest
    return replacement


def add_daily_task_global(payload: dict[str, Any]) -> None:
    usage = payload["usage"]
    if any(row["ownershipClass"] == "task-owned" and row["periodKind"] == "daily" for row in usage["globals"]):
        return
    source = next(row for row in usage["globals"] if row["ownershipClass"] == "task-owned")
    daily = copy.deepcopy(source)
    daily["globalId"] = f"{source['globalId']}-daily"
    daily["periodKind"] = "daily"
    daily["periodKey"] = "2026-07-28"
    usage["globals"].append(daily)
    usage["generation"]["expectedCounts"]["globals"] = len(usage["globals"])
    refresh_metadata_digest(payload)


def add_second_lifetime_model(payload: dict[str, Any]) -> None:
    usage = payload["usage"]
    base_invocation = copy.deepcopy(usage["invocations"][0])
    second_invocation_id = f"{base_invocation['invocationId']}-second"
    second_price_digest = "b" * 64
    base_invocation.update(
        {
            "invocationId": second_invocation_id,
            "retryOrdinal": 1,
            "startedAt": None,
            "completedAt": None,
            "model": "gpt-second",
            "priceEntryDigest": second_price_digest,
        }
    )
    usage["invocations"].append(base_invocation)
    second_turn = copy.deepcopy(usage["turns"][0])
    second_turn.update(
        {
            "turnId": f"{second_turn['turnId']}-second",
            "invocationId": second_invocation_id,
            "priceEntryDigest": second_price_digest,
        }
    )
    usage["turns"].append(second_turn)
    usage["prices"].append(
        {
            "priceEntryDigest": second_price_digest,
            "usageGenerationId": usage["generation"]["usageGenerationId"],
            "catalogDigest": "c" * 64,
            "model": "gpt-second",
            "effectiveAt": "2026-01-01T00:00:00Z",
            "effectiveUntil": None,
        }
    )
    for summary in usage["summaries"]:
        summary.update(
            {
                "coveredInvocations": 2,
                "expectedInvocations": 2,
                "knownTokenSubtotal": 36,
                "knownCostSubtotalMicroUsd": 120,
                "priceProvenanceDigest": None,
            }
        )
        for field in ("promptTokens", "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens"):
            summary[field] *= 2
        for field in ("uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd"):
            summary[field] *= 2
    second_global = copy.deepcopy(
        next(row for row in usage["globals"] if row["ownershipClass"] == "task-owned" and row["periodKind"] == "lifetime")
    )
    second_global.update(
        {
            "globalId": f"global-second-{payload['publicationId']}",
            "model": "gpt-second",
            "priceProvenanceDigest": second_price_digest,
        }
    )
    usage["globals"].append(second_global)
    usage["generation"]["expectedCounts"].update(
        {"invocations": 2, "turns": 2, "prices": 2, "globals": len(usage["globals"])}
    )
    refresh_metadata_digest(payload)


def mark_usage_unavailable(payload: dict[str, Any]) -> None:
    usage = payload["usage"]
    nullable_fields = (
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
    )
    invocation = usage["invocations"][0]
    invocation.update(
        {
            "invocationId": None,
            "startedAt": None,
            "completedAt": None,
            "model": None,
            "billingMode": None,
            "processOutcome": None,
            "coverage": "unavailable",
            "coveredTurns": 0,
            "expectedTurns": 0,
            "priceEntryDigest": None,
        }
    )
    for field in nullable_fields:
        invocation[field] = None
    usage["turns"] = []
    usage["prices"] = []
    usage["generation"]["expectedCounts"]["turns"] = 0
    usage["generation"]["expectedCounts"]["prices"] = 0
    for summary in usage["summaries"]:
        summary.update(
            {
                "coverage": "unavailable",
                "coveredInvocations": 0,
                "expectedInvocations": 1,
                "knownTokenSubtotal": None,
                "knownCostSubtotalMicroUsd": None,
                "priceProvenanceDigest": None,
            }
        )
        for field in nullable_fields:
            summary[field] = None
    for global_row in usage["globals"]:
        if global_row["ownershipClass"] != "task-owned":
            continue
        global_row.update(
            {
                "coverage": "unavailable",
                "coveredInvocations": 0,
                "expectedInvocations": 1,
                "knownTokenSubtotal": None,
                "knownCostSubtotalMicroUsd": None,
                "priceProvenanceDigest": None,
            }
        )
        for field in nullable_fields:
            global_row[field] = None
    refresh_metadata_digest(payload)


def test_task_owned_globals_match_verified_invocation_rollups() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-global-mismatch")
    global_row = next(row for row in payload["usage"]["globals"] if row["ownershipClass"] == "task-owned")
    global_row.update(
        {
            "promptTokens": 100,
            "cachedTokens": 0,
            "uncachedTokens": 100,
            "completionTokens": 18,
            "reasoningTokens": 0,
            "totalTokens": 118,
            "knownTokenSubtotal": 118,
        }
    )
    refresh_metadata_digest(payload)

    with pytest.raises(D1Error) as error:
        d1.stage(payload)

    assert error.value.code == D1ErrorCode.generation_conflict
    assert server.requests == []


def test_task_owned_global_keys_must_cover_every_derived_period() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-global-missing")
    payload["usage"]["globals"] = [
        row
        for row in payload["usage"]["globals"]
        if not (row["ownershipClass"] == "task-owned" and row["periodKind"] == "daily")
    ]
    payload["usage"]["generation"]["expectedCounts"]["globals"] = len(payload["usage"]["globals"])
    refresh_metadata_digest(payload)

    with pytest.raises(D1Error) as error:
        d1.stage(payload)

    assert error.value.code == D1ErrorCode.generation_conflict
    assert server.requests == []


def test_hide_subtracts_only_the_hidden_task_global_contribution() -> None:
    server = ScriptedD1()
    d1 = client(server)
    d1.publish(publication("publication-global-one", run_id="run-global-one", task_id="task-one"))
    d1.publish(publication("publication-global-two", run_id="run-global-two", task_id="task-two"))

    before = server.connection.execute(
        "SELECT g.total_tokens, g.expected_invocations FROM usage_global_heads AS h "
        "JOIN usage_globals AS g ON g.global_id = h.global_id "
        "WHERE h.period_kind = 'lifetime' AND h.model = 'gpt-fixture' AND h.ownership_class = 'task-owned'"
    ).fetchone()
    assert tuple(before) == (36, 2)

    d1.hide_task("task-two", "unsafe_content")

    after = server.connection.execute(
        "SELECT g.total_tokens, g.expected_invocations, h.state FROM usage_global_heads AS h "
        "JOIN usage_globals AS g ON g.global_id = h.global_id "
        "WHERE h.period_kind = 'lifetime' AND h.model = 'gpt-fixture' AND h.ownership_class = 'task-owned'"
    ).fetchone()
    assert tuple(after) == (18, 1, "visible")


def test_hide_unavailable_task_preserves_known_shared_totals() -> None:
    server = ScriptedD1()
    d1 = client(server)
    d1.publish(publication("publication-global-complete", run_id="run-global-complete", task_id="task-complete"))
    unavailable = publication("publication-global-unavailable", run_id="run-global-unavailable", task_id="task-unavailable")
    mark_usage_unavailable(unavailable)
    d1.publish(unavailable)

    d1.hide_task("task-unavailable", "unsafe_content")

    row = server.connection.execute(
        "SELECT g.total_tokens, g.total_cost_micro_usd, g.coverage, g.expected_invocations, "
        "g.price_provenance_digest, h.state FROM usage_global_heads AS h "
        "JOIN usage_globals AS g ON g.global_id = h.global_id "
        "WHERE h.period_kind = 'lifetime' AND h.model = 'gpt-fixture' AND h.ownership_class = 'task-owned'"
    ).fetchone()
    assert tuple(row) == (18, 60, "complete", 1, hashlib.sha256(b"price-gpt-fixture").hexdigest(), "visible")


def test_usage_replacement_with_daily_and_lifetime_keys_stays_below_batch_limit() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-global-replace", run_id="run-global-replace", task_id="task-replace")
    add_daily_task_global(first)
    d1.publish(first)
    replacement = usage_replacement(first, "refresh")
    old_usage_id = first["usage"]["generation"]["usageGenerationId"]
    before = len(server.requests)

    d1.replace_usage(replacement, base_usage_generation_id=old_usage_id)

    replacement_batches = [
        request
        for request in server.requests[before:]
        if "batch" in request
        and any("UPDATE usage_generations SET state = 'superseded'" in item["sql"] for item in request["batch"])
    ]
    assert len(replacement_batches) == 1
    assert sum(len(item["params"]) for item in replacement_batches[0]["batch"]) <= MAX_BATCH_PARAMETERS


def test_three_shared_global_keys_fit_one_bounded_replacement_batch() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-global-three-one", run_id="run-global-three-one", task_id="task-global-three-one")
    second = publication("publication-global-three-two", run_id="run-global-three-two", task_id="task-global-three-two")
    add_second_lifetime_model(first)
    add_second_lifetime_model(second)
    d1.publish(first)
    d1.publish(second)
    replacement = usage_replacement(first, "refresh")
    before = len(server.requests)

    d1.replace_usage(replacement, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])

    replacement_batches = [
        request
        for request in server.requests[before:]
        if "batch" in request
        and any("UPDATE usage_generations SET state = 'superseded'" in item["sql"] for item in request["batch"])
    ]
    assert len(replacement_batches) == 1
    assert len(replacement_batches[0]["batch"]) <= 64
    assert sum(len(item["params"]) for item in replacement_batches[0]["batch"]) <= MAX_BATCH_PARAMETERS


def test_price_overlap_with_distinct_digest_is_rejected_before_staging() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-price-one", run_id="run-price-one")
    d1.publish(first)
    second = publication("publication-price-two", run_id="run-price-two")
    price_digest = "e" * 64
    second["usage"]["prices"][0]["priceEntryDigest"] = price_digest
    for collection in ("invocations", "turns"):
        second["usage"][collection][0]["priceEntryDigest"] = price_digest
    for collection in ("summaries", "globals"):
        for row in second["usage"][collection]:
            if row["priceProvenanceDigest"] is not None:
                row["priceProvenanceDigest"] = price_digest
    refresh_metadata_digest(second)

    with pytest.raises(D1Error) as error:
        d1.stage(second)

    assert error.value.code == D1ErrorCode.generation_conflict
    assert server.connection.execute("SELECT count(*) FROM usage_generations").fetchone()[0] == 1


def test_price_verification_is_bounded_by_indexed_lookups() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-price-large", run_id="run-price-large")
    d1.publish(first)
    for index in range(4097):
        digest = hashlib.sha256(f"unrelated-price-{index}".encode()).hexdigest()
        server.connection.execute(
            "INSERT INTO usage_prices "
            "(price_entry_digest, usage_generation_id, catalog_digest, model, effective_at, effective_until) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                digest,
                first["usage"]["generation"]["usageGenerationId"],
                "a" * 64,
                f"unrelated-model-{index}",
                "2020-01-01T00:00:00Z",
                None,
            ),
        )
    server.connection.commit()

    second = publication("publication-price-large-two", run_id="run-price-large-two")
    d1.stage(second)

    assert server.connection.execute("SELECT count(*) FROM usage_generations").fetchone()[0] == 2


def test_stage_is_hidden_until_verified_exposure_and_replays() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication()

    d1.stage(payload)
    assert server.connection.execute("SELECT state FROM publication_generations").fetchone()[0] == "staged"
    assert server.connection.execute("SELECT count(*) FROM task_heads").fetchone()[0] == 0
    d1.stage(copy.deepcopy(payload))
    assert d1.expose(payload).state == "visible"
    assert server.connection.execute("SELECT state FROM publication_generations").fetchone()[0] == "visible"
    assert server.connection.execute("SELECT state FROM task_heads").fetchone()[0] == "visible"
    d1.stage(payload)
    assert d1.expose(payload).publication_id == payload["publicationId"]


def test_usage_replacement_preserves_task_identity_and_replays() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-usage-replace", run_id="run-usage-replace")
    d1.publish(first)
    replacement = usage_replacement(first, "refresh")
    old_usage_id = first["usage"]["generation"]["usageGenerationId"]
    new_usage_id = replacement["usage"]["generation"]["usageGenerationId"]

    result = d1.replace_usage(replacement, base_usage_generation_id=old_usage_id)

    assert result.publication_id == first["publicationId"]
    assert result.usage_generation_id == new_usage_id
    assert tuple(server.connection.execute("SELECT publication_id, usage_generation_id, state FROM task_heads").fetchone()) == (
        first["publicationId"],
        new_usage_id,
        "visible",
    )
    assert server.connection.execute(
        "SELECT state FROM usage_generations WHERE usage_generation_id = ?", (old_usage_id,)
    ).fetchone()[0] == "superseded"
    assert tuple(server.connection.execute(
        "SELECT usage_generation_id, state FROM usage_global_heads WHERE ownership_class = 'task-owned'"
    ).fetchone()) == (new_usage_id, "visible")
    assert d1.replace_usage(copy.deepcopy(replacement), base_usage_generation_id=new_usage_id).usage_generation_id == new_usage_id


def test_usage_replacement_rejects_numeric_cost_mutation_and_stale_base() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-usage-cost", run_id="run-usage-cost")
    d1.publish(first)
    invalid = usage_replacement(first, "repriced")
    for collection in ("summaries", "invocations", "turns", "globals"):
        for row in invalid["usage"][collection]:
            row["uncachedInputCostMicroUsd"] = 11
            row["totalCostMicroUsd"] = 61
            if collection in {"summaries", "globals"}:
                row["knownCostSubtotalMicroUsd"] = 61
            if collection in {"summaries", "globals"}:
                row["priceProvenanceDigest"] = first["usage"]["prices"][0]["priceEntryDigest"]
            else:
                row["priceEntryDigest"] = first["usage"]["prices"][0]["priceEntryDigest"]
    refresh_metadata_digest(invalid)
    invalid["generation"]["metadataDigest"] = first["generation"]["metadataDigest"]

    with pytest.raises(D1Error) as error:
        d1.replace_usage(invalid, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])
    assert error.value.code == D1ErrorCode.generation_conflict
    assert server.connection.execute("SELECT count(*) FROM usage_generations WHERE state = 'staged'").fetchone()[0] == 0

    replacement = usage_replacement(first, "valid")
    d1.replace_usage(replacement, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])
    stale = usage_replacement(first, "stale")
    with pytest.raises(D1Error) as error:
        d1.replace_usage(stale, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])
    assert error.value.code == D1ErrorCode.generation_conflict
    assert server.connection.execute("SELECT count(*) FROM usage_generations WHERE state = 'staged'").fetchone()[0] == 0


def test_usage_replacement_fills_na_cost_and_failure_rolls_back() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-usage-na", run_id="run-usage-na")
    usage = first["usage"]
    usage["prices"] = []
    usage["generation"]["expectedCounts"]["prices"] = 0
    for collection in ("summaries", "invocations", "turns", "globals"):
        for row in usage[collection]:
            for field in ("uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd"):
                row[field] = None
            if collection == "summaries":
                row.update({"coverage": "partial", "knownCostSubtotalMicroUsd": None, "priceProvenanceDigest": None})
            elif collection == "invocations":
                row.update({"coverage": "partial", "priceEntryDigest": None})
            elif collection == "turns":
                row["priceEntryDigest"] = None
            else:
                row.update({"coverage": "partial", "knownCostSubtotalMicroUsd": None, "priceProvenanceDigest": None})
    refresh_metadata_digest(first)
    d1.publish(first)
    replacement = usage_replacement(first, "fill")
    usage = replacement["usage"]
    price_digest = "e" * 64
    usage["prices"] = [{
        "priceEntryDigest": price_digest,
        "usageGenerationId": usage["generation"]["usageGenerationId"],
        "catalogDigest": "f" * 64,
        "model": "gpt-fixture",
        "effectiveAt": "2026-01-01T00:00:00Z",
        "effectiveUntil": None,
    }]
    usage["generation"]["expectedCounts"]["prices"] = 1
    for collection in ("summaries", "invocations", "turns", "globals"):
        for row in usage[collection]:
            row.update({"uncachedInputCostMicroUsd": 10, "cachedInputCostMicroUsd": 20, "outputCostMicroUsd": 30, "totalCostMicroUsd": 60})
            if collection in {"summaries", "globals"}:
                row.update({"coverage": "complete", "knownCostSubtotalMicroUsd": 60, "priceProvenanceDigest": price_digest})
            else:
                row["priceEntryDigest"] = price_digest
    refresh_metadata_digest(replacement)
    replacement["generation"]["metadataDigest"] = first["generation"]["metadataDigest"]
    server.fail_usage_swap_once = True
    with pytest.raises(D1Error) as error:
        d1.replace_usage(replacement, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])
    assert error.value.code == D1ErrorCode.transient
    assert server.connection.execute("SELECT usage_generation_id FROM task_heads").fetchone()[0] == first["usage"]["generation"]["usageGenerationId"]
    assert server.connection.execute(
        "SELECT state FROM usage_generations WHERE usage_generation_id = ?", (replacement["usage"]["generation"]["usageGenerationId"],)
    ).fetchone()[0] == "staged"
    result = d1.replace_usage(replacement, base_usage_generation_id=first["usage"]["generation"]["usageGenerationId"])
    assert result.usage_generation_id == replacement["usage"]["generation"]["usageGenerationId"]
    assert server.connection.execute(
        "SELECT total_cost_micro_usd FROM usage_globals WHERE usage_generation_id = ?", (replacement["usage"]["generation"]["usageGenerationId"],)
    ).fetchone()[0] == 60


def test_supersession_and_hide_are_atomic_and_idempotent() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication()
    d1.publish(first)
    second = publication("publication-next", run_id="run-next")
    d1.stage(second)
    assert server.connection.execute("SELECT state FROM publication_generations WHERE publication_id = ?", (first["publicationId"],)).fetchone()[0] == "visible"
    d1.expose(second)
    states = dict(server.connection.execute("SELECT publication_id, state FROM publication_generations"))
    assert states == {first["publicationId"]: "superseded", second["publicationId"]: "visible"}
    hidden = d1.hide_task("task-clean", "unsafe_content")
    assert hidden.changed is True
    assert d1.hide_task("task-clean", "unsafe_content").changed is False
    assert server.connection.execute("SELECT state FROM task_heads").fetchone()[0] == "hidden"


def test_hide_supersedes_staged_generations_and_wins_expose_race() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-hide-head", run_id="run-hide-head")
    d1.publish(first)
    staged = publication("publication-hide-staged", run_id="run-hide-staged")
    d1.stage(staged)

    hidden = d1.hide_task(first["taskId"], "unsafe_content")

    assert hidden.changed is True
    hide_batches = [
        item
        for item in server.requests
        if "batch" in item
        and any(
            "UPDATE publication_generations SET state = 'superseded' WHERE task_id = ? AND state = 'staged'"
            in statement["sql"]
            for statement in item["batch"]
        )
    ]
    assert len(hide_batches) == 1
    assert any(
        "ON CONFLICT(task_id) DO UPDATE SET publication_id = excluded.publication_id, state = 'hidden'"
        in statement["sql"]
        for statement in hide_batches[0]["batch"]
    )
    states = dict(
        server.connection.execute(
            "SELECT publication_id, state FROM publication_generations WHERE task_id = ?",
            (first["taskId"],),
        )
    )
    assert states == {
        first["publicationId"]: "visible",
        staged["publicationId"]: "superseded",
    }
    assert server.connection.execute(
        "SELECT state FROM task_heads WHERE task_id = ?", (first["taskId"],)
    ).fetchone()[0] == "hidden"

    with pytest.raises(D1Error) as error:
        d1.expose(staged)
    assert error.value.code == D1ErrorCode.generation_state
    assert d1.hide_task(first["taskId"], "unsafe_content").changed is False


def test_hide_supersedes_exposure_committed_after_staged_read() -> None:
    server = HideExposureInterposer()
    d1 = client(server)
    staged = publication("publication-hide-interposed", run_id="run-hide-interposed")
    d1.stage(staged)
    server.after_staged_query = lambda: d1.expose(staged)

    hidden = d1.hide_task(staged["taskId"], "unsafe_content")

    assert server.interposed is True
    assert hidden.state == "hidden"
    assert hidden.changed is True
    assert hidden.publication_id == staged["publicationId"]
    assert server.connection.execute(
        "SELECT state FROM publication_generations WHERE publication_id = ?",
        (staged["publicationId"],),
    ).fetchone()[0] == "superseded"
    assert server.connection.execute(
        "SELECT state FROM task_heads WHERE task_id = ?", (staged["taskId"],)
    ).fetchone()[0] == "hidden"
    assert server.connection.execute(
        "SELECT count(*) FROM publication_generations WHERE task_id = ? AND state = 'visible'",
        (staged["taskId"],),
    ).fetchone()[0] == 0


def test_interrupted_visibility_batch_rolls_back_without_changing_head() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication()
    d1.publish(first)
    second = publication("publication-next", run_id="run-next")
    d1.stage(second)
    server.fail_visibility_once = True
    with pytest.raises(D1Error) as error:
        d1.expose(second)
    assert error.value.code == D1ErrorCode.transient
    assert server.connection.execute("SELECT publication_id FROM task_heads").fetchone()[0] == first["publicationId"]
    assert server.connection.execute("SELECT usage_generation_id FROM task_heads").fetchone()[0] == first["usage"]["generation"]["usageGenerationId"]
    assert server.connection.execute("SELECT state FROM publication_generations WHERE publication_id = ?", (second["publicationId"],)).fetchone()[0] == "staged"
    assert server.connection.execute("SELECT state FROM usage_generations WHERE usage_generation_id = ?", (second["usage"]["generation"]["usageGenerationId"],)).fetchone()[0] == "staged"


def test_conflict_private_locator_and_bounds_fail_closed() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication()
    conflicting = copy.deepcopy(payload)
    conflicting["task"]["title"] = "changed"
    refresh_metadata_digest(conflicting)
    d1.stage(payload)
    with pytest.raises(D1Error) as error:
        d1.stage(conflicting)
    assert error.value.code == D1ErrorCode.generation_conflict

    private = publication()
    private["task"]["title"] = "private://bucket/object"
    refresh_metadata_digest(private)
    with pytest.raises(D1Error) as error:
        d1.stage(private)
    assert error.value.code == D1ErrorCode.private_value

    too_many = publication("publication-large", run_id="run-large", artifact_count=8)
    d1.stage(too_many)
    staged_batches = [item for item in server.requests if "batch" in item and any("INSERT INTO artifacts" in statement["sql"] for statement in item["batch"])]
    assert len(staged_batches) >= 2
    assert all(sum(len(statement["params"]) for statement in item["batch"]) <= MAX_BATCH_PARAMETERS for item in staged_batches)


def test_row_verification_normalizes_fixed_query_order() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-order", artifact_count=2)
    payload["artifacts"].reverse()
    refresh_metadata_digest(payload)

    d1.stage(payload)


def test_unavailable_invocation_coverage_preserves_represented_denominator() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-unavailable", run_id="run-unavailable")
    mark_usage_unavailable(payload)

    d1.stage(payload)

    summaries = server.connection.execute(
        "SELECT scope, covered_invocations, expected_invocations, coverage "
        "FROM usage_summaries ORDER BY scope"
    ).fetchall()
    assert [tuple(row) for row in summaries] == [
        ("run", 0, 1, "unavailable"),
        ("task", 0, 1, "unavailable"),
    ]
    stored_invocation = server.connection.execute(
        "SELECT invocation_id, total_tokens, total_cost_micro_usd, coverage "
        "FROM usage_invocations"
    ).fetchone()
    assert tuple(stored_invocation) == (None, None, None, "unavailable")


def test_false_metadata_digest_is_rejected_before_staging() -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-digest")
    payload["generation"]["metadataDigest"] = "0" * 64

    with pytest.raises(D1Error) as error:
        d1.stage(payload)

    assert error.value.code == D1ErrorCode.digest_mismatch
    assert server.requests == []
    assert server.connection.execute("SELECT count(*) FROM publication_generations").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["identity", "count", "digest", "owner", "rollup", "private"])
def test_usage_contract_failures_are_rejected_before_transport(mutation: str) -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication(f"publication-usage-{mutation}")
    if mutation == "identity":
        payload["usage"]["summaries"][0]["usageGenerationId"] = "usage-other"
    elif mutation == "count":
        payload["usage"]["generation"]["expectedCounts"]["turns"] = 2
        refresh_metadata_digest(payload)
    elif mutation == "digest":
        payload["usage"]["generation"]["metadataDigest"] = "0" * 64
    elif mutation == "owner":
        payload["usage"]["summaries"][0]["taskId"] = "task-other"
        refresh_metadata_digest(payload)
    elif mutation == "rollup":
        payload["usage"]["summaries"][0]["totalTokens"] = 19
        refresh_metadata_digest(payload)
    else:
        payload["usage"]["invocations"][0]["model"] = "private://model"
        refresh_metadata_digest(payload)

    with pytest.raises(D1Error):
        d1.stage(payload)
    assert server.requests == []


@pytest.mark.parametrize("locator", ["~/work/coquic", r"~\work\coquic", r"\\server\share", "internal_object_key"])
def test_shared_private_locators_are_rejected_before_transport(locator: str) -> None:
    server = ScriptedD1()
    d1 = client(server)
    payload = publication("publication-locator")
    payload["task"]["title"] = locator
    refresh_metadata_digest(payload)

    with pytest.raises(D1Error) as error:
        d1.stage(payload)

    assert error.value.code == D1ErrorCode.private_value
    assert server.requests == []


def test_hidden_head_replay_does_not_reopen_generation() -> None:
    server = ScriptedD1()
    d1 = client(server)
    first = publication("publication-hidden", run_id="run-hidden")
    d1.publish(first)
    d1.hide_task(first["taskId"], "unsafe_content")

    replay = d1.publish(copy.deepcopy(first))
    assert replay.state == "hidden"
    assert server.connection.execute("SELECT state FROM task_heads WHERE task_id = ?", (first["taskId"],)).fetchone()[0] == "hidden"

    second = publication("publication-after-hidden", run_id="run-after-hidden")
    d1.publish(second)
    assert server.connection.execute("SELECT state FROM task_heads WHERE task_id = ?", (first["taskId"],)).fetchone()[0] == "visible"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, D1ErrorCode.provider),
        (401, D1ErrorCode.authentication),
        (429, D1ErrorCode.quota),
        (504, D1ErrorCode.transient),
    ],
)
def test_provider_failures_are_bounded(status: int, expected: D1ErrorCode) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"success": False, "errors": [{"message": "private provider detail"}]}, request=request)

    d1 = D1PublicationClient(account_id=ACCOUNT, database_id=DATABASE, token=TOKEN, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(D1Error) as error:
        d1.stage(publication())
    assert error.value.code == expected
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    "document",
    [
        {"success": False, "errors": [{"message": "private provider detail"}], "result": []},
        {
            "success": True,
            "errors": [],
            "result": [
                {
                    "success": False,
                    "errors": [{"message": "private query detail"}],
                    "results": [],
                    "meta": {},
                }
            ],
        },
    ],
)
def test_successful_http_error_envelopes_are_permanent(document: dict[str, object]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=document, request=request)

    d1 = D1PublicationClient(
        account_id=ACCOUNT,
        database_id=DATABASE,
        token=TOKEN,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(D1Error) as error:
        d1.stage(publication("publication-envelope"))
    assert error.value.code == D1ErrorCode.provider
    assert "detail" not in str(error.value)


def test_malformed_nested_error_envelope_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": True,
                "errors": [],
                "result": [
                    {
                        "success": True,
                        "errors": "malformed",
                        "results": [],
                        "meta": {},
                    }
                ],
            },
            request=request,
        )

    d1 = D1PublicationClient(
        account_id=ACCOUNT,
        database_id=DATABASE,
        token=TOKEN,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(D1Error) as error:
        d1.stage(publication("publication-malformed-envelope"))
    assert error.value.code == D1ErrorCode.malformed_response
