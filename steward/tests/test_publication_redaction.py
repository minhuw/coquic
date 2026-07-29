from __future__ import annotations

import json
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.publication import (
    AtifDocument,
    CorpusEntry,
    LogicalArtifact,
    PublicBundleComponent,
    REDACTION_MARKER,
    ReasonCode,
    RunIdentity,
    RunMetadata,
    ScannerProtocolError,
    convert_completed_run,
    discover_secrets,
    parse_trufflehog_json,
    redact_atif_document,
    run_trufflehog,
    sanitize_publication,
)


def _run() -> RunMetadata:
    started = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)
    return RunMetadata(
        RunIdentity("task-redaction", "pipeline-redaction", "run-redaction"),
        "implementation",
        "succeeded",
        started,
        started.replace(second=1),
        1_000,
    )


def _document(message: str = "safe") -> AtifDocument:
    run = _run()
    documents = {
        "codex.jsonl": json.dumps(
            {"type": "item.completed", "item": {"id": "message-1", "type": "agent_message", "text": message}},
            separators=(",", ":"),
        ).encode()
        + b"\n",
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,"source_event_id":"activity-1",'
            b'"activity":"investigate","summary":"Trace safe records","recorded_at":"2026-07-28T12:00:00.200Z"}\n'
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
                "startedAt": "2026-07-28T12:00:00Z",
                "completedAt": "2026-07-28T12:00:01Z",
            },
            separators=(",", ":"),
        ).encode()
        + b"\n",
    }
    return convert_completed_run(run=run, documents=documents)


def test_discover_secrets_uses_sensitive_leaves_and_longest_order(tmp_path: Path) -> None:
    source = tmp_path / "credentials.json"
    source.write_text(
        json.dumps({"api_key": "short", "nested": {"access_token": "overlap-token"}, "token": "overlap"}),
        encoding="utf-8",
    )
    assert discover_secrets((source,)) == ("overlap-token",)


def test_literal_redaction_preserves_structural_metadata(tmp_path: Path) -> None:
    secret = "literal-secret-value"
    source = tmp_path / "credential"
    source.write_text(secret + "\n", encoding="utf-8")
    result = redact_atif_document(_document(f"before {secret} after {secret}"), (source,))
    assert result.status == "clean"
    assert result.document is not None
    assert result.document.as_dict()["steps"][0]["message"] == f"before {REDACTION_MARKER} after {REDACTION_MARKER}"
    assert result.document.as_dict()["steps"][0]["step_id"] == 1
    assert result.document.as_dict()["extra"]["coquic"]["disclosure"]["redactionApplied"] is True
    assert secret not in result.document.content.decode()
    assert result.replacement_count == 2


def test_json_artifact_replaces_values_but_not_keys(tmp_path: Path) -> None:
    secret = "artifact-secret-value"
    source = tmp_path / "credential"
    source.write_text(secret, encoding="utf-8")
    payload = json.dumps({"api_key": secret, "message": "safe"}, separators=(",", ":")).encode() + b"\n"
    artifact = LogicalArtifact(
        "artifact-json",
        "steps/1/output.json",
        "application/json",
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        owner_step_id=1,
    )
    document = _document("safe")
    document = AtifDocument(document.document, document.content, artifacts=(PublicBundleComponent(artifact, payload),))
    result = redact_atif_document(document, (source,))
    assert result.status == "clean"
    assert result.document is not None
    artifact_content = result.document.artifact_contents["artifact-json"].decode()
    assert '"api_key"' in artifact_content
    assert REDACTION_MARKER in artifact_content


def test_unsafe_credential_source_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("unsafe-secret-value", encoding="utf-8")
    link = tmp_path / "credential"
    link.symlink_to(target)
    result = redact_atif_document(_document(), (link,))
    assert result.status == "fail_closed"
    assert result.reason_codes == (ReasonCode.unsafe_content,)
    assert "unsafe-secret-value" not in repr(result)


def test_scanner_parser_requires_mapped_json_lines() -> None:
    output = json.dumps(
        {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "entry-0000.txt"}}},
            "Raw": "heuristic-secret",
            "DetectorName": "Test",
        }
    ) + "\n"
    finding = parse_trufflehog_json(output)[0]
    assert finding.corpus_path == "entry-0000.txt"
    assert repr(finding) == "ScannerFinding(corpus_path='entry-0000.txt', category='text', detector='Test')"
    with pytest.raises(ScannerProtocolError) as error:
        parse_trufflehog_json("not-json\n")
    assert error.value.code == ReasonCode.scanner_failure
    assert parse_trufflehog_json(
        json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": "entry-0000.txt"}}},
                "Raw": REDACTION_MARKER,
            }
        )
        + "\n"
    ) == ()


def test_scanner_uses_local_json_no_update_or_verification(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    report = run_trufflehog((CorpusEntry("trajectory.json", b"safe text"),), staging_root=tmp_path, runner=runner)
    assert report.clean
    assert calls
    assert "filesystem" in calls[0]
    assert "--json" in calls[0]
    assert "--no-update" in calls[0]
    assert "--no-verification" in calls[0]


def test_scanner_repairs_and_rescans_without_exposing_raw_value() -> None:
    raw = "heuristic-secret"
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

    result = sanitize_publication(_document(f"found {raw}"), run_scanner=True, scanner_runner=runner)
    assert result.status == "clean"
    assert result.document is not None
    assert raw not in result.document.content.decode()
    assert calls == 2


def test_scanner_nonzero_exit_fails_closed() -> None:
    def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 2, b"", b"private detector error")

    result = sanitize_publication(_document(), run_scanner=True, scanner_runner=runner)
    assert result.status == "fail_closed"
    assert result.reason_codes == (ReasonCode.scanner_failure,)
    assert "private detector error" not in repr(result)
