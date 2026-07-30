from __future__ import annotations

from collections.abc import Mapping
import json
import subprocess
from datetime import datetime, timezone

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
    PublicationGeneration,
    compose_publication_generation,
)
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

    def builder(source: object, **kwargs: object):
        outcome = build_publication_bundle(source, **kwargs)
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


def test_repair_and_fail_closed_outcomes_never_emit_generation(monkeypatch) -> None:
    source = _source()

    def repair_builder(*args, **kwargs):
        return RepairRequired((ReasonCode.source_finding,), ())

    result = compose_publication_generation(_graph(source), run_builder=repair_builder, scanner_runner=_scanner)
    assert isinstance(result, RepairRequired)
    assert result.reason_codes == (ReasonCode.source_finding,)

    def fail_builder(*args, **kwargs):
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
