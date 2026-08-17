from __future__ import annotations

from collections.abc import Mapping
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.publication import (
    AtifSource,
    FailClosed,
    ReasonCode,
    RepairRequired,
    RunIdentity,
    RunMetadata,
)
from coquic_steward.publication.generation import (
    GenerationIdentity,
    PublicationGeneration,
    compose_publication_generation,
)
import coquic_steward.publication.generation as generation_module
from coquic_steward.publication.pipeline import build_publication_bundle


def _scanner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def _source(
    *,
    task_id: str = "task-generation",
    pipeline_id: str = "pipeline-generation",
    run_id: str = "run-generation",
    state: str = "succeeded",
    message: str = "safe",
) -> AtifSource:
    started = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)
    completed = started.replace(second=1)
    run = RunMetadata(
        RunIdentity(task_id, pipeline_id, run_id),
        "planning",
        state,
        started,
        completed,
        1_000,
    )
    codex = json.dumps(
        {"type": "item.completed", "item": {"id": "message-1", "type": "agent_message", "text": message}},
        separators=(",", ":"),
    ).encode() + b"\n"
    documents = {
        "codex.jsonl": codex,
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,"source_event_id":"activity-1",'
            b'"activity":"investigate","summary":"Complete the task","recorded_at":"2026-07-28T12:00:00.100Z"}\n'
            b'{"record_type":"summary","schema_version":1,"capture_state":"complete",'
            b'"recorded":1,"invalid":0,"duplicate":0,"omitted":0,"truncated":false}\n'
        ),
        "telemetry.json": b'{"schema_version":1,"provenance":"codex_exec","completeness":"complete","aggregate":{},"cost":{"status":"unavailable"}}',
        "run.json": json.dumps(
            {
                "taskId": task_id,
                "pipelineId": pipeline_id,
                "runId": run_id,
                "role": "planning",
                "state": state,
                "startedAt": "2026-07-28T12:00:00.000Z",
                "completedAt": "2026-07-28T12:00:01.000Z",
            },
            separators=(",", ":"),
        ).encode()
        + b"\n",
    }
    return AtifSource(run=run, documents=documents)


def _graph(source: AtifSource, *, lifecycle: str = "active") -> dict:
    task_id = source.run.identity.task_id
    pipeline_id = source.run.identity.pipeline_id
    return {
        "task": {
            "taskId": task_id,
            "title": "Generation fixture",
            "lifecycleState": lifecycle,
            "createdAt": "2026-07-28T12:00:00Z",
            "completedAt": None if lifecycle == "active" else "2026-07-28T12:00:01Z",
        },
        "pipelines": [
            {
                "pipelineId": pipeline_id,
                "taskId": task_id,
                "name": "Planning pipeline",
                "createdAt": "2026-07-28T12:00:00Z",
            }
        ],
        "runs": [source],
        "events": [
            {
                "taskId": task_id,
                "sequence": 1,
                "eventType": "started",
                "occurredAt": "2026-07-28T12:00:00Z",
                "summary": "Planning started",
            },
            {
                "taskId": task_id,
                "sequence": 2,
                "eventType": "completed",
                "occurredAt": "2026-07-28T12:00:01Z",
                "summary": "Planning completed",
            },
        ],
    }


def _compose(graph: dict):
    return compose_publication_generation(graph, scanner_runner=_scanner)


class _ThirdTraversalMapping(Mapping[str, object]):
    def __init__(self, values: dict[str, object], *, field: str, transient: object, stable: object) -> None:
        self._values = dict(values)
        self._field = field
        self._transient = transient
        self._stable = stable
        self._items_calls = 0

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def items(self):
        self._items_calls += 1
        if self._items_calls == 3:
            self._values[self._field] = self._transient
            try:
                return list(self._values.items())
            finally:
                self._values[self._field] = self._stable
        return self._values.items()


class _CaptureWindowMapping(Mapping[str, object]):
    def __init__(self, values: dict[str, object], *, field: str, transient: object, stable: object) -> None:
        self._values = dict(values)
        self._field = field
        self._transient = transient
        self._stable = stable
        self._items_calls = 0

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def items(self):
        self._items_calls += 1
        if 2 <= self._items_calls <= 4:
            self._values[self._field] = self._transient
            try:
                return list(self._values.items())
            finally:
                self._values[self._field] = self._stable
        return self._values.items()


class _GenerationAsDictLookalike:
    def __init__(self) -> None:
        self.called = False

    def as_dict(self) -> dict[str, object]:
        self.called = True
        raise AssertionError("unsupported serializer executed")


class _GenerationModelDumpLookalike:
    def __init__(self) -> None:
        self.called = False

    def model_dump(self, **_kwargs: object) -> dict[str, object]:
        self.called = True
        raise AssertionError("unsupported serializer executed")


def test_generation_is_deterministic_and_detached() -> None:
    graph = _graph(_source())
    first = _compose(graph)
    second = _compose(graph)

    assert isinstance(first, PublicationGeneration)
    assert isinstance(second, PublicationGeneration)
    assert first.as_dict() == second.as_dict()
    assert first.objects == second.objects
    assert first.payload["generation"]["metadataDigest"] == first.payload["generation"]["metadataDigest"]
    assert first.payload["generation"]["state"] == "staged"
    with pytest.raises(TypeError):
        first.payload["taskId"] = "other"  # type: ignore[index]


def test_generation_boundary_and_outbox_mapping_are_canonical() -> None:
    result = _compose(_graph(_source()))

    assert isinstance(result, PublicationGeneration)
    identity = GenerationIdentity(result.task_id, result.generation_boundary)
    record = result.to_outbox()
    assert result.publication_id == identity.publication_id
    assert result.idempotency_key == identity.idempotency_key
    assert record.publication_id == result.publication_id
    assert record.generation_boundary == result.generation_boundary
    assert record.run_id == result.run_id
    assert record.metadata_digest == result.metadata_digest
    assert record.rows == sum(result.generation["expectedCounts"].values())
    assert record.objects == len(result.objects) + len(result.private_originals)
    assert "generationBoundary" not in json.dumps(result.as_dict(), sort_keys=True)


def test_usage_summary_preserves_projection_coverage_and_unavailable_evidence(monkeypatch) -> None:
    captured = {}
    build_projection = generation_module.build_task_usage_projection

    def capture_projection(*args: object, **kwargs: object):
        projection = build_projection(*args, **kwargs)
        captured["projection"] = projection
        return projection

    monkeypatch.setattr(generation_module, "build_task_usage_projection", capture_projection)
    result = _compose(_graph(_source()))

    assert isinstance(result, PublicationGeneration)
    projection = captured["projection"]
    assert projection.summary.coverage.as_dict() == {
        "coveredInvocations": 0,
        "expectedInvocations": 1,
        "status": "N.A.",
    }
    summaries = result.payload["usage"]["summaries"]
    assert [(row["scope"], row["coveredInvocations"], row["expectedInvocations"], row["coverage"]) for row in summaries] == [
        ("task", 0, 1, "unavailable"),
        ("run", 0, 1, "unavailable"),
    ]
    invocation = result.payload["usage"]["invocations"][0]
    assert invocation["invocationId"] is None
    assert invocation["coverage"] == "unavailable"
    assert all(invocation[field] is None for field in (
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
    ))


def test_generation_rejects_caller_supplied_identity() -> None:
    graph = _graph(_source())

    result = compose_publication_generation(
        graph,
        publication_id="caller-publication",
        scanner_runner=_scanner,
    )

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.invalid_metadata,)


@pytest.mark.parametrize("lookalike_type", [_GenerationAsDictLookalike, _GenerationModelDumpLookalike])
def test_generation_rejects_serializer_lookalikes_without_execution(lookalike_type) -> None:
    lookalike = lookalike_type()
    graph = _graph(_source())
    graph["task"] = lookalike

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.invalid_metadata,)
    assert lookalike.called is False


def test_generation_rejects_nested_serializer_subtypes_without_execution() -> None:
    executed = False

    class ArmedIdentity(RunIdentity):
        def as_dict(self) -> dict[str, object]:
            nonlocal executed
            executed = True
            raise AssertionError("unsupported nested serializer executed")

    source = _source()
    run = RunMetadata(
        identity=ArmedIdentity("task-generation", "pipeline-generation", "run-generation"),
        role=source.run.role,
        state=source.run.state,
        started_at=source.run.started_at,
        completed_at=source.run.completed_at,
        duration_ms=source.run.duration_ms,
        model=source.run.model,
        reasoning=source.run.reasoning,
        lineage=source.run.lineage,
        usage=source.run.usage,
    )
    result = _compose(_graph(AtifSource(run=run, documents=source.documents)))

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.invalid_metadata,)
    assert executed is False


def test_active_task_after_completed_planning_run_is_visible() -> None:
    result = _compose(_graph(_source(), lifecycle="active"))

    assert isinstance(result, PublicationGeneration)
    assert result.payload["task"]["lifecycleState"] == "active"
    assert result.payload["task"]["completedAt"] is None
    assert result.payload["runs"][0]["runState"] == "completed"
    assert result.payload["runs"][0]["atifArtifactId"] == "artifact-atif"
    assert result.payload["artifacts"][0]["logicalPath"].endswith("trajectory.json")
    assert len(result.objects) == len(result.payload["artifacts"])


def test_later_completed_run_supersedes_by_deterministic_generation_identity() -> None:
    first = _source(run_id="run-a")
    second = _source(run_id="run-b")
    graph = _graph(first, lifecycle="completed")
    graph["runs"] = [first, second]
    graph["pipelines"].append(
        {
            "pipelineId": "pipeline-generation-2",
            "taskId": "task-generation",
            "name": "Follow-up",
            "createdAt": "2026-07-28T12:00:00Z",
        }
    )
    # Make the second source belong to the second pipeline while retaining a
    # complete stable graph.
    second = _source(pipeline_id="pipeline-generation-2", run_id="run-b")
    graph["runs"] = [first, second]
    result = _compose(graph)

    assert isinstance(result, PublicationGeneration)
    assert result.payload["generation"]["runId"] == "run-b"
    assert len(result.payload["runs"]) == 2
    assert len({row["artifactId"] for row in result.payload["artifacts"]}) == len(result.payload["artifacts"])
    assert len({row["logicalPath"] for row in result.payload["artifacts"]}) == len(result.payload["artifacts"])


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ({"stable": False}, ReasonCode.changing),
        ({"materialized": False}, ReasonCode.partial),
        ({"unknownFiles": ["private.bin"]}, ReasonCode.partial),
    ],
)
def test_unstable_or_uncovered_run_is_not_publishable(marker: dict, expected: ReasonCode) -> None:
    source = _source()
    entry = {"source": source, **marker}
    graph = _graph(source)
    graph["runs"] = [entry]

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (expected,)


def test_running_run_is_rejected_before_builder() -> None:
    source = _source(state="succeeded")
    graph = _graph(source)
    graph["runs"] = [{"source": source, "state": "running"}]

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.running,)


@pytest.mark.parametrize(
    ("section", "index", "field"),
    [
        ("task", None, "title"),
        ("pipeline", 0, "name"),
        ("event", 0, "eventType"),
        ("event", 1, "summary"),
    ],
)
def test_public_graph_strings_are_credential_inspected(section: str, index: int | None, field: str) -> None:
    secret = "generation-graph-secret"
    graph = _graph(_source())
    graph_key = {"pipeline": "pipelines", "event": "events"}.get(section, section)
    target = graph[graph_key] if index is None else graph[graph_key][index]
    target[field] = secret

    result = compose_publication_generation(
        graph,
        known_secrets=(secret,),
        scanner_runner=_scanner,
    )

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.unsafe_content,)
    assert not hasattr(result, "payload")


def test_generation_string_scan_uses_configured_staging_root(tmp_path: Path) -> None:
    live_paths: list[Path] = []

    def scanner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        descriptor = kwargs["pass_fds"][0]
        live_paths.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    result = compose_publication_generation(
        _graph(_source()),
        staging_root=tmp_path,
        scanner_runner=scanner,
    )

    assert isinstance(result, PublicationGeneration)
    assert len(live_paths) >= 2
    assert all(path.parent == tmp_path for path in live_paths)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("section", ["task", "pipeline", "run", "event"])
def test_graph_mutation_after_builder_is_fail_closed(section: str) -> None:
    graph = _graph(_source())

    def mutate() -> None:
        if section == "task":
            graph["task"]["title"] = "changed after build"
        elif section == "pipeline":
            graph["pipelines"][0]["name"] = "changed after build"
        elif section == "run":
            graph["runs"][0].documents["codex.jsonl"] = graph["runs"][0].documents["codex.jsonl"].replace(b"safe", b"changed")
        else:
            graph["events"][1]["summary"] = "changed after build"

    def builder(
        source: object,
        *,
        credential_sources: object,
        known_secrets: object,
        staging_root: object,
        scanner_runner: object,
        scanner_timeout: float,
        max_repair_passes: int,
        ocr_runner: object,
        ocr_timeout: float,
    ):
        outcome = build_publication_bundle(
            source,
            credential_sources=credential_sources,
            known_secrets=known_secrets,
            staging_root=staging_root,
            scanner_runner=scanner_runner,
            scanner_timeout=scanner_timeout,
            max_repair_passes=max_repair_passes,
            ocr_runner=ocr_runner,
            ocr_timeout=ocr_timeout,
        )
        mutate()
        return outcome

    result = compose_publication_generation(graph, run_builder=builder, scanner_runner=_scanner)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.changing,)
    assert not hasattr(result, "payload")


def test_aba_mutation_during_detached_capture_is_fail_closed() -> None:
    source = _source()
    graph = _graph(source)
    graph["task"] = _ThirdTraversalMapping(
        graph["task"],
        field="title",
        transient="transient ABA title",
        stable="Generation fixture",
    )

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.changing,)
    assert not hasattr(result, "payload")


@pytest.mark.parametrize("section", ["task", "pipeline", "run", "event"])
def test_nested_aba_mutation_during_capture_is_fail_closed(section: str) -> None:
    source = _source()
    graph = _graph(source)
    if section == "task":
        graph["task"] = _ThirdTraversalMapping(
            graph["task"],
            field="title",
            transient="nested transient task title",
            stable="Generation fixture",
        )
    elif section == "pipeline":
        graph["pipelines"][0] = _ThirdTraversalMapping(
            graph["pipelines"][0],
            field="name",
            transient="nested transient pipeline name",
            stable="Planning pipeline",
        )
    elif section == "run":
        graph["runs"][0] = _ThirdTraversalMapping(
            {"source": graph["runs"][0], "state": "succeeded"},
            field="state",
            transient="running",
            stable="succeeded",
        )
    else:
        graph["events"][0] = _ThirdTraversalMapping(
            graph["events"][0],
            field="summary",
            transient="nested transient event summary",
            stable="Planning started",
        )

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.changing,)
    assert not hasattr(result, "payload")


@pytest.mark.parametrize("section", ["task", "pipeline", "run", "event"])
def test_detached_capture_must_match_source_bookends(section: str) -> None:
    source = _source()
    graph = _graph(source)
    if section == "task":
        graph["task"] = _CaptureWindowMapping(
            graph["task"],
            field="title",
            transient="transient task title",
            stable="Generation fixture",
        )
    elif section == "pipeline":
        graph["pipelines"][0] = _CaptureWindowMapping(
            graph["pipelines"][0],
            field="name",
            transient="transient pipeline name",
            stable="Planning pipeline",
        )
    elif section == "run":
        graph["runs"][0] = _CaptureWindowMapping(
            {"source": graph["runs"][0], "state": "succeeded"},
            field="state",
            transient="running",
            stable="succeeded",
        )
    else:
        graph["events"][0] = _CaptureWindowMapping(
            graph["events"][0],
            field="summary",
            transient="transient event summary",
            stable="Planning started",
        )

    result = _compose(graph)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.changing,)
    assert not hasattr(result, "payload")


def test_builder_type_error_is_reduced_after_one_invocation() -> None:
    calls = 0

    def builder(
        _source: object,
        *,
        credential_sources: object,
        known_secrets: object,
        staging_root: object,
        scanner_runner: object,
        scanner_timeout: float,
        max_repair_passes: int,
        ocr_runner: object,
        ocr_timeout: float,
    ):
        nonlocal calls
        calls += 1
        raise TypeError("builder body failed")

    result = compose_publication_generation(
        _graph(_source()),
        run_builder=builder,
        scanner_runner=_scanner,
    )

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.invalid_metadata,)
    assert calls == 1


def test_repair_and_fail_closed_outcomes_never_emit_generation(monkeypatch) -> None:
    source = _source()

    def repair_builder(
        _source: object,
        *,
        credential_sources: object,
        known_secrets: object,
        staging_root: object,
        scanner_runner: object,
        scanner_timeout: float,
        max_repair_passes: int,
        ocr_runner: object,
        ocr_timeout: float,
    ):
        return RepairRequired((ReasonCode.source_finding,), ())

    result = compose_publication_generation(_graph(source), run_builder=repair_builder, scanner_runner=_scanner)
    assert isinstance(result, RepairRequired)
    assert result.reason_codes == (ReasonCode.source_finding,)

    def fail_builder(
        _source: object,
        *,
        credential_sources: object,
        known_secrets: object,
        staging_root: object,
        scanner_runner: object,
        scanner_timeout: float,
        max_repair_passes: int,
        ocr_runner: object,
        ocr_timeout: float,
    ):
        return FailClosed((ReasonCode.unsafe_content,), ())

    result = compose_publication_generation(_graph(source), run_builder=fail_builder, scanner_runner=_scanner)
    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.unsafe_content,)


def test_redacted_run_keeps_private_original_outside_public_payload() -> None:
    secret = "generation-private-secret"
    result = compose_publication_generation(
        _graph(_source(message=f"remove {secret}")),
        known_secrets=(secret,),
        scanner_runner=_scanner,
    )

    assert isinstance(result, PublicationGeneration)
    assert len(result.private_originals) == 1
    assert secret.encode() in result.private_originals[0].content
    rendered = json.dumps(result.as_dict(), sort_keys=True).encode()
    assert secret.encode() not in rendered
