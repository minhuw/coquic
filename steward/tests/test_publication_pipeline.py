from __future__ import annotations

import json
import hashlib
import subprocess
from datetime import datetime, timezone

from coquic_steward.publication import (
    AtifSource,
    AtifDocument,
    FailClosed,
    LogicalArtifact,
    MediaInspection,
    Publishable,
    PublicBundleComponent,
    ReasonCode,
    RepairRequired,
    RunIdentity,
    RunMetadata,
    build_publication_bundle,
    canonical_atif_bytes,
)


def _source(message: str = "safe") -> AtifSource:
    started = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)
    run = RunMetadata(
        RunIdentity("task-pipeline", "pipeline-pipeline", "run-pipeline"),
        "planning",
        "succeeded",
        started,
        started.replace(second=1),
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
                "taskId": run.identity.task_id,
                "pipelineId": run.identity.pipeline_id,
                "runId": run.identity.run_id,
                "role": run.role,
                "state": "succeeded",
                "startedAt": "2026-07-28T12:00:00.000Z",
                "completedAt": "2026-07-28T12:00:01.000Z",
            },
            separators=(",", ":"),
        ).encode()
        + b"\n",
    }
    return AtifSource(run=run, documents=documents)


def _clean_scanner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, 0, b"", b"")


def test_clean_build_is_deterministic_and_every_component_is_inspected(tmp_path) -> None:
    first = build_publication_bundle(_source(), staging_root=tmp_path, run_scanner=False, scanner_runner=_clean_scanner)
    second = build_publication_bundle(_source(), staging_root=tmp_path, run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(first, Publishable)
    assert isinstance(second, Publishable)
    assert first.snapshot.public_bundle.inspected
    assert first.snapshot.public_bundle.components[0].artifact.logical_path == "runs/run-pipeline/trajectory.json"
    assert first.snapshot.public_bundle.components[0].inspection is not None
    assert first.snapshot.private_original is None
    disclosure = first.snapshot.public_bundle.components[0].content
    assert b'"originalRetained":false' in disclosure
    assert b'"redactionApplied":false' in disclosure
    assert first.snapshot.public_bundle.components[0].content == second.snapshot.public_bundle.components[0].content


def test_atif_redaction_retains_only_the_original_codex_jsonl() -> None:
    secret = "pipeline-secret-value"
    result = build_publication_bundle(
        _source(f"remove {secret}"),
        known_secrets=(secret,),
        run_scanner=False,
        scanner_runner=_clean_scanner,
    )

    assert isinstance(result, Publishable)
    assert result.snapshot.private_original is not None
    assert secret.encode() in result.snapshot.private_original.content
    trajectory = result.snapshot.public_bundle.components[0].content
    assert secret.encode() not in trajectory
    assert b'"originalRetained":true' in trajectory
    assert b'"redactionApplied":true' in trajectory
    assert all("activity" not in component.artifact.logical_path for component in result.snapshot.public_bundle.components)


def test_artifact_redaction_does_not_create_a_transcript_original(monkeypatch) -> None:
    import importlib

    source = _source()
    artifact_secret = "artifact-pipeline-secret"
    payload = json.dumps({"token": artifact_secret}, separators=(",", ":")).encode() + b"\n"
    artifact = LogicalArtifact(
        "artifact-json",
        "steps/1/output.json",
        "application/json",
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        owner_step_id=1,
    )
    module = importlib.import_module("coquic_steward.publication.pipeline")
    original = module.convert_completed_run(source)
    mapping = original.as_dict()
    mapping["extra"]["coquic"]["artifacts"] = [
        {key: value for key, value in artifact.as_dict().items() if key != "logicalPath"}
    ]
    mapping["steps"][0].setdefault("extra", {}).setdefault("coquic", {})["artifactIds"] = [artifact.artifact_id]
    monkeypatch.setattr(
        module,
        "convert_completed_run",
        lambda *args, **kwargs: AtifDocument(
            mapping,
            canonical_atif_bytes(mapping),
            artifacts=(PublicBundleComponent(artifact, payload),),
        ),
    )
    result = module.build_publication_bundle(
        known_secrets=(artifact_secret,),
        run_scanner=False,
        scanner_runner=_clean_scanner,
    )

    assert isinstance(result, Publishable)
    assert result.snapshot.private_original is None
    assert result.snapshot.public_bundle.disclosures[0] == {"redactionApplied": False, "originalRetained": False}
    assert result.snapshot.public_bundle.disclosures[1] == {"redactionApplied": True, "originalRetained": False}


def test_partial_input_returns_bounded_failure_without_public_bytes() -> None:
    source = _source()
    partial = AtifSource(run=source.run, documents={"codex.jsonl": source.documents["codex.jsonl"]})
    result = build_publication_bundle(partial, run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.partial,)
    assert result.as_dict() == {"status": "fail_closed", "reasonCodes": ["partial"], "findings": []}


def test_source_repair_is_not_publishable(monkeypatch) -> None:
    import importlib

    module = importlib.import_module("coquic_steward.publication.pipeline")
    monkeypatch.setattr(
        module,
        "sanitize_publication",
        lambda *args, **kwargs: module.SanitizationResult.repair(ReasonCode.source_finding, count=2),
    )
    result = build_publication_bundle(_source(), run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(result, RepairRequired)
    assert result.reason_codes == (ReasonCode.source_finding,)
    assert result.findings[0].count == 2


def test_media_failure_fails_closed_without_receipts(monkeypatch) -> None:
    import importlib

    module = importlib.import_module("coquic_steward.publication.pipeline")
    monkeypatch.setattr(
        module,
        "inspect_media",
        lambda content, media_type, **kwargs: MediaInspection.failed_result(
            category="text",
            media_type=media_type,
            content=content,
            reason=ReasonCode.scanner_failure,
        ),
    )
    result = build_publication_bundle(_source(), run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.scanner_failure,)


def test_untrusted_staging_root_fails_closed(tmp_path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    result = build_publication_bundle(_source(), staging_root=unsafe, run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.staging_unsafe,)


def test_scanner_cannot_be_disabled_by_public_builder() -> None:
    raw = "heuristic-pipeline-secret"
    calls = 0

    def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        if calls == 1:
            output = json.dumps(
                {
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "entry-0000.txt"}}},
                    "Raw": raw,
                }
            ).encode() + b"\n"
            return subprocess.CompletedProcess(argv, 0, output, b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    result = build_publication_bundle(_source(f"found {raw}"), run_scanner=False, scanner_runner=runner)

    assert isinstance(result, Publishable)
    assert calls == 2
    assert raw.encode() not in result.snapshot.public_bundle.components[0].content


def test_descriptor_without_public_bytes_fails_closed() -> None:
    source = _source()
    payload = b"plot bytes"
    descriptor = LogicalArtifact(
        "plot-1",
        "plots/plot-1.png",
        "image/png",
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        owner_step_id=1,
    )
    incomplete = AtifSource(run=source.run, documents=source.documents, artifacts=(descriptor,))

    result = build_publication_bundle(incomplete, run_scanner=False, scanner_runner=_clean_scanner)

    assert isinstance(result, FailClosed)
    assert result.reason_codes == (ReasonCode.partial,)
    assert result.as_dict() == {"status": "fail_closed", "reasonCodes": ["partial"], "findings": []}
