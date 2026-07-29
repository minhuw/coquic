from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from coquic_steward.publication import (
    AtifConversionError,
    LogicalArtifact,
    PublicationError,
    ReasonCode,
    RunIdentity,
    RunLineage,
    RunMetadata,
    UsageSummary,
    convert_completed_run,
    validate_atif_document,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "contracts" / "steward-cloud" / "atif-v1.7.schema.json"


def _run(*, run_id: str = "run-convert", role: str = "implementation") -> RunMetadata:
    started = datetime(2026, 7, 28, 12, 0, 0, 123000, tzinfo=timezone.utc)
    return RunMetadata(
        identity=RunIdentity("task-convert", "pipeline-convert", run_id),
        role=role,
        state="succeeded",
        started_at=started,
        completed_at=started.replace(second=1),
        duration_ms=877,
        model="gpt-test",
        reasoning="medium",
        lineage=RunLineage(retry_of_run_id="run-previous", resume_of_run_id="run-interrupted"),
        usage=UsageSummary(
            prompt_tokens=11,
            completion_tokens=7,
            total_tokens=18,
            cached_input_tokens=2,
            reasoning_output_tokens=3,
        ),
    )


def _documents(codex: list[dict[str, object]], *, telemetry: dict[str, object] | None = None) -> dict[str, bytes]:
    run = _run()
    run_document = {
        "taskId": run.identity.task_id,
        "pipelineId": run.identity.pipeline_id,
        "runId": run.identity.run_id,
        "role": run.role,
        "state": "succeeded",
        "startedAt": "2026-07-28T12:00:00.123Z",
        "completedAt": "2026-07-28T12:00:01.123Z",
    }
    values: dict[str, bytes] = {
        "codex.jsonl": b"".join(
            json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
            for item in codex
        ),
        "run.json": json.dumps(run_document, separators=(",", ":")).encode() + b"\n",
    }
    values["activities.jsonl"] = (
        b'{"record_type":"header","schema_version":1}\n'
        b'{"record_type":"event","schema_version":1,"sequence":1,"source_event_id":"activity-1",'
        b'"activity":"investigate","summary":"Trace safe records",'
        b'"recorded_at":"2026-07-28T12:00:00.200Z"}\n'
        b'{"record_type":"summary","schema_version":1,"capture_state":"complete",'
        b'"recorded":1,"invalid":0,"duplicate":0,"omitted":0,"truncated":false}\n'
    )
    values["telemetry.json"] = json.dumps(
        telemetry
        or {
            "schema_version": 1,
            "provenance": "codex_exec",
            "completeness": "complete",
            "aggregate": {
                "input_tokens": 11,
                "cached_input_tokens": 2,
                "output_tokens": 7,
                "reasoning_output_tokens": 3,
            },
            "cost": {"status": "unavailable", "reason": "price unavailable"},
        },
        separators=(",", ":"),
    ).encode()
    return values


def test_messages_tools_reasoning_and_order_are_structured() -> None:
    codex = [
        {"type": "thread.started", "thread_id": "private-provider-session"},
        {"type": "item.started", "item": {"id": "message-1", "type": "user_message", "text": "Inspect the result."}},
        {"type": "item.completed", "item": {"id": "message-1", "type": "user_message", "text": "Inspect the result."}},
        {"type": "item.completed", "item": {"id": "reason-1", "type": "reasoning", "text": "I will inspect the result first."}},
        {"type": "item.completed", "item": {"id": "call-1", "type": "function_call", "name": "inspect", "arguments": '{"path":"src/result.txt"}'}},
        {"type": "item.completed", "item": {"id": "output-1", "type": "function_call_output", "call_id": "call-1", "output": "ok"}},
        {"type": "custom.safe", "safe_fact": "preserved", "number": 4},
    ]
    result = convert_completed_run(run=_run(), documents=_documents(codex))
    document = result.as_dict()
    steps = document["steps"]
    assert [step["step_id"] for step in steps] == [1, 2, 3, 4, 5]
    assert [step["source"] for step in steps] == ["user", "agent", "agent", "agent", "agent"]
    assert steps[0]["message"] == "Inspect the result."
    assert steps[1]["reasoning_content"] == "I will inspect the result first."
    assert steps[2]["tool_calls"][0]["tool_call_id"] == "call-1"
    assert steps[2]["tool_calls"][0]["arguments"] == {"logicalPath": "src/result.txt"}
    assert steps[3]["observation"]["results"][0]["source_call_id"] == "call-1"
    assert steps[4]["extra"]["coquic"]["source"]["facts"] == {"safe_fact": "preserved", "number": 4}
    assert "private-provider-session" not in result.content.decode()


def test_missing_call_ids_are_deterministic_and_unpaired_results_remain_unlinked() -> None:
    codex = [
        {"type": "function_call", "name": "first", "arguments": {}},
        {"type": "function_call", "name": "second", "arguments": {}},
        {"type": "function_call_output", "output": "first result"},
        {"type": "function_call_output", "call_id": "never-seen", "output": "unpaired"},
    ]
    first = convert_completed_run(run=_run(), documents=_documents(codex))
    second = convert_completed_run(run=_run(), documents=_documents(codex))
    assert first.content == second.content
    calls = [call["tool_call_id"] for step in first.as_dict()["steps"] for call in step.get("tool_calls", [])]
    assert len(calls) == len(set(calls)) == 2
    observations = [step["observation"]["results"][0] for step in first.as_dict()["steps"] if "observation" in step]
    assert observations[0]["source_call_id"] == calls[0]
    assert "source_call_id" not in observations[1]
    assert observations[1]["content"] == "unpaired"


def test_multimodal_images_and_artifacts_use_logical_references() -> None:
    image = b"synthetic-image-bytes"
    import hashlib

    artifact = LogicalArtifact(
        "plot-1",
        "evidence/plot.png",
        "image/png",
        len(image),
        hashlib.sha256(image).hexdigest(),
        owner_step_id=2,
    )
    codex = [
        {"type": "user_message", "content": "Show the plot."},
        {"type": "agent_message", "content": [{"type": "text", "text": "Here it is."}, {"type": "image", "source": {"media_type": "image/png", "path": "artifact:plot-1"}}]},
    ]
    result = convert_completed_run(run=_run(), documents=_documents(codex), artifacts=(artifact,))
    document = result.as_dict()
    assert document["steps"][1]["message"][1]["source"]["path"] == "artifact:plot-1"
    assert document["extra"]["coquic"]["artifacts"] == [
        {
            "artifactId": "plot-1",
            "mediaType": "image/png",
            "sha256": hashlib.sha256(image).hexdigest(),
            "byteSize": len(image),
            "ownerStepId": 2,
        }
    ]
    assert document["steps"][1]["extra"]["coquic"]["artifactIds"] == ["plot-1"]


def test_lineage_metrics_timing_and_canonical_schema() -> None:
    result = convert_completed_run(
        run=_run(),
        documents=_documents(
            [
                {"type": "user_message", "timestamp": "2026-07-28T12:00:00.200Z", "text": "hello"},
                {"type": "agent_message", "timestamp": "2026-07-28T12:00:00.900Z", "text": "done", "duration_ms": 700},
            ]
        ),
    )
    document = result.as_dict()
    assert result.content == json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    assert document["extra"]["coquic"]["lineage"] == {"parentRunId": None, "retryOfRunId": "run-previous", "resumeOfRunId": "run-interrupted"}
    assert document["final_metrics"]["extra"]["usage"] == {"cached": 2, "completion": 7, "prompt": 11, "reasoning": 3, "total": 18}
    assert document["steps"][1]["extra"]["coquic"]["timing"] == {"durationMs": 700}
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert list(validator.iter_errors(document)) == []


@pytest.mark.parametrize(
    "documents, code",
    [
        ({"codex.jsonl": b'{"type":"item.completed","item":{"type":"agent_message","text":"partial"}}'}, ReasonCode.partial),
        ({"codex.jsonl": b'{"type":"item.completed","item":{"type":"agent_message","text":"bad"}}\n', "run.json": b'{"taskId":"task-convert","pipelineId":"pipeline-convert","runId":"run-convert","state":"running","completedAt":null}'}, ReasonCode.partial),
        ({"codex.jsonl": b'{"type":"item.completed","item":{"type":"agent_message","text":"bad"}}\n', "telemetry.json": b'{"cost":NaN}'}, ReasonCode.invalid_jsonl),
    ],
)
def test_incomplete_or_invalid_inputs_fail_closed(documents: dict[str, bytes], code: ReasonCode) -> None:
    with pytest.raises(PublicationError) as error:
        convert_completed_run(run=_run(), documents=documents)
    assert error.value.code == code


def test_private_source_facts_are_not_exposed() -> None:
    documents = _documents([{"type": "custom.safe", "safe_fact": "https://private.example"}])
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(run=_run(), documents=documents)
    assert error.value.code == ReasonCode.unsafe_content


def test_completed_run_requires_all_evidence_and_rejects_partial_or_contradictory_sources() -> None:
    documents = _documents([{"type": "agent_message", "text": "complete"}])
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(run=_run(), documents={key: value for key, value in documents.items() if key != "activities.jsonl"})
    assert error.value.code == ReasonCode.partial

    partial_activity = documents | {
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"summary","schema_version":1,"capture_state":"partial",'
            b'"recorded":0,"invalid":1,"duplicate":0,"omitted":0,"truncated":false}\n'
        )
    }
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(run=_run(), documents=partial_activity)
    assert error.value.code == ReasonCode.partial

    contradictory = documents | {
        "telemetry.json": json.dumps(
            {
                "schema_version": 1,
                "provenance": "codex_exec_jsonl",
                "completeness": "complete",
                "aggregate": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 999},
                "cost": {"status": "unavailable"},
            },
            separators=(",", ":"),
        ).encode()
    }
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(run=_run(), documents=contradictory)
    assert error.value.code == ReasonCode.invalid_metadata


def test_raw_activity_envelope_preserves_order_without_synthetic_records() -> None:
    activities = (
        b'{"type":"item.completed","item":{"id":"activity-one","type":"agent_message",'
        b'"text":"STEWARD_ACTIVITY {\\"activity\\":\\"investigate\\",\\"summary\\":\\"one\\"}"}}\n'
        b'{"type":"item.completed","item":{"id":"activity-two","type":"agent_message",'
        b'"text":"STEWARD_ACTIVITY {\\"activity\\":\\"edit\\",\\"summary\\":\\"two\\"}"}}\n'
    )
    document = convert_completed_run(
        run=_run(),
        documents=_documents([{"type": "agent_message", "text": "complete"}]) | {"activities.jsonl": activities},
    ).as_dict()
    events = document["extra"]["coquic"]["source"]["activities"]["events"]
    assert [item["sourceId"] for item in events] == ["activity-one", "activity-two"]
    assert all(item["recordType"] == "item.completed" for item in events)


def test_raw_session_activity_envelope_keeps_lifecycle_order() -> None:
    activities = (
        b'{"type":"thread.started"}\n'
        b'{"type":"item.completed","item":{"id":"activity-one","type":"agent_message",'
        b'"text":"STEWARD_ACTIVITY {\\"activity\\":\\"investigate\\",\\"summary\\":\\"one\\"}"}}\n'
    )
    document = convert_completed_run(
        run=_run(),
        documents=_documents([{"type": "agent_message", "text": "complete"}])
        | {"activities.jsonl": activities},
    ).as_dict()
    events = document["extra"]["coquic"]["source"]["activities"]["events"]
    assert [event["recordType"] for event in events] == ["thread.started", "item.completed"]
    assert events[1]["sourceId"] == "activity-one"
    assert events[1]["activity"] == "investigate"
    assert "header" not in {event["recordType"] for event in events}
    assert "summary" not in {event["recordType"] for event in events}


def test_telemetry_availability_and_full_sidecar_evidence_are_preserved() -> None:
    documents = _documents([{"type": "agent_message", "text": "complete"}])
    unavailable = convert_completed_run(
        run=_run(), documents=documents | {"telemetry.json": b'{"availability":"unavailable"}'}
    ).as_dict()
    assert unavailable["extra"]["coquic"]["source"]["telemetry"] == {"availability": "unavailable"}

    turn = {
        "ordinal": 1,
        "input_tokens": 11,
        "cached_input_tokens": 2,
        "uncached_input_tokens": 9,
        "output_tokens": 7,
        "reasoning_output_tokens": 3,
        "total_tokens": 18,
    }
    sidecar = {
        "schema_version": 1,
        "provenance": "codex_exec_jsonl",
        "invocation_id": "private-invocation",
        "task_id": "private-task",
        "run_name": "private-run",
        "stage": "code",
        "retry_ordinal": 0,
        "configured_model": "gpt-test",
        "reasoning_effort": "medium",
        "billing_mode": "unknown",
        "started_at": "2026-07-28T12:00:00.123Z",
        "completed_at": "2026-07-28T12:00:01.123Z",
        "duration_ms": 1000,
        "first_agent_message_completed_ms": 400,
        "process_outcome": "success",
        "turns": [turn],
        "aggregate": {
            "completed_turns": 1,
            "input_tokens": 11,
            "cached_input_tokens": 2,
            "uncached_input_tokens": 9,
            "output_tokens": 7,
            "reasoning_output_tokens": 3,
            "total_tokens": 18,
        },
        "cost": {"status": "unavailable", "reason": "no price"},
        "completeness": "complete",
        "issues": [],
    }
    result = convert_completed_run(
        run=_run(), documents=documents | {"telemetry.json": json.dumps(sidecar).encode()}
    )
    telemetry = result.as_dict()["extra"]["coquic"]["source"]["telemetry"]
    assert telemetry["provenance"] == "codex_exec_jsonl"
    assert telemetry["turns"] == [{"ordinal": 1, "input": 11, "cached": 2, "uncached": 9, "output": 7, "reasoning": 3, "total": 18}]
    assert telemetry["duration_ms"] == 1000
    assert telemetry["cost"] == {"status": "unavailable", "reason": "no price"}
    assert "private-invocation" not in result.content.decode()


def test_runtime_semantics_reject_artifact_reference_in_wrong_step() -> None:
    image = b"image"
    artifact = LogicalArtifact("plot", "evidence/plot.png", "image/png", len(image), hashlib.sha256(image).hexdigest(), owner_step_id=2)
    result = convert_completed_run(
        run=_run(),
        documents=_documents([{"type": "user_message", "text": "one"}, {"type": "agent_message", "text": "two"}]),
        artifacts=(artifact,),
    )
    mutated = result.as_dict()
    mutated["steps"][0]["extra"]["coquic"]["artifactIds"].append("plot")
    with pytest.raises(AtifConversionError) as error:
        validate_atif_document(mutated)
    assert error.value.code == ReasonCode.invalid_metadata


def test_file_change_paths_are_logical_and_private_paths_fail_closed() -> None:
    safe = convert_completed_run(
        run=_run(),
        documents=_documents([{"type": "item.completed", "item": {"id": "change", "type": "file_change", "changes": [{"path": "src/main.zig", "kind": "edit"}]}}]),
    ).as_dict()
    source = safe["steps"][0]["extra"]["coquic"]["source"]
    assert source["recordType"] == "file_change"
    assert source["facts"]["changes"][0]["logicalPath"] == "src/main.zig"
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(
            run=_run(),
            documents=_documents([{"type": "item.completed", "item": {"id": "change", "type": "file_change", "changes": [{"path": "/private/main.zig"}]}}]),
        )
    assert error.value.code == ReasonCode.unsafe_content


def test_inline_input_image_is_retained_as_a_deterministic_artifact() -> None:
    result = convert_completed_run(
        run=_run(),
        documents=_documents([{"type": "user_message", "content": [{"type": "input_image", "image_url": "data:image/png;base64,aGVsbG8="}]}]),
    )
    document = result.as_dict()
    image = document["steps"][0]["message"][0]
    artifact = document["extra"]["coquic"]["artifacts"][0]
    assert image["source"]["media_type"] == "image/png"
    assert image["source"]["path"] == f"artifact:{artifact['artifactId']}"
    assert artifact["byteSize"] == 5
    assert artifact["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert len(result.artifacts) == 1
    assert result.artifacts[0].artifact.artifact_id == artifact["artifactId"]
    assert result.artifacts[0].content == b"hello"
    assert result.artifact_contents[artifact["artifactId"]] == b"hello"
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(
            run=_run(),
            documents=_documents([{"type": "user_message", "content": [{"type": "input_image", "image_url": "data:image/svg+xml;base64,aGVsbG8="}]}]),
        )
    assert error.value.code == ReasonCode.invalid_media_type


def test_string_artifact_owner_resolves_unique_source_identity() -> None:
    artifact = LogicalArtifact("output", "evidence/output.log", "text/plain", 1, "0" * 64, owner_step_id="message-two")
    document = convert_completed_run(
        run=_run(),
        documents=_documents([
            {"type": "item.completed", "item": {"id": "message-one", "type": "user_message", "text": "one"}},
            {"type": "item.completed", "item": {"id": "message-two", "type": "agent_message", "text": "two"}},
        ]),
        artifacts=(artifact,),
    ).as_dict()
    assert document["extra"]["coquic"]["artifacts"][0]["ownerStepId"] == 2
    assert document["steps"][1]["extra"]["coquic"]["artifactIds"] == ["output"]

    missing = LogicalArtifact("missing", "evidence/missing.log", "text/plain", 1, "0" * 64, owner_step_id="not-a-step")
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(run=_run(), documents=_documents([{"type": "agent_message", "text": "one"}]), artifacts=(missing,))
    assert error.value.code == ReasonCode.invalid_metadata


def test_duplicate_completed_source_identity_fails_artifact_owner_closed() -> None:
    artifact = LogicalArtifact("output", "evidence/output.log", "text/plain", 1, "0" * 64, owner_step_id="same-id")
    with pytest.raises(AtifConversionError) as error:
        convert_completed_run(
            run=_run(),
            documents=_documents(
                [
                    {"type": "item.completed", "item": {"id": "same-id", "type": "agent_message", "text": "one"}},
                    {"type": "item.completed", "item": {"id": "same-id", "type": "agent_message", "text": "two"}},
                ]
            ),
            artifacts=(artifact,),
        )
    assert error.value.code == ReasonCode.invalid_metadata
