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
METADATA_FIELDS = ("publicationId", "taskId", "task", "pipelines", "runs", "events", "artifacts")


def refresh_metadata_digest(payload: dict[str, Any]) -> None:
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

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        statements = body.get("batch")
        if statements is None:
            statements = [{"sql": body["sql"], "params": body.get("params", [])}]
        self.requests.append(body)
        if self.fail_visibility_once and any("UPDATE publication_generations SET state = 'superseded'" in item["sql"] for item in statements):
            self.fail_visibility_once = False
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


def client(server: ScriptedD1) -> D1PublicationClient:
    return D1PublicationClient(
        account_id=ACCOUNT,
        database_id=DATABASE,
        token=TOKEN,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )


def publication(publication_id: str = "publication-clean", *, run_id: str = "run-clean", artifact_count: int = 2) -> dict[str, Any]:
    task_id = "task-clean"
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
    payload = {
        "schemaVersion": "1.0",
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
    }
    refresh_metadata_digest(payload)
    return payload


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
    assert server.connection.execute("SELECT state FROM publication_generations WHERE publication_id = ?", (second["publicationId"],)).fetchone()[0] == "staged"


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
