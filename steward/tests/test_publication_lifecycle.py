from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.core.config import StewardPublicationConfig
from coquic_steward.execution.executor import (
    IntegrationTranscript,
    StewardExecutor,
)
from coquic_steward.publication.atif import AtifSource
from coquic_steward.publication.generation import PublicationGeneration
from coquic_steward.publication.models import FailClosed, ReasonCode, RepairRequired
from coquic_steward.publication.scanner import ScannerFinding, ScannerReport


class _EventStore:
    def __init__(self) -> None:
        self.items: list[SimpleNamespace] = []

    def add_event(self, task_id: str, kind: str, message: str, data: dict) -> None:
        self.items.append(SimpleNamespace(task_id=task_id, kind=kind, message=message, data=data))

    def events(self, task_id: str) -> list[SimpleNamespace]:
        return [item for item in self.items if item.task_id == task_id]


class _Worktrees:
    def __init__(self) -> None:
        self.removed = False

    def tree(self, _path: Path) -> str:
        return "validated-tree"

    def diff(self, _path: Path) -> str:
        if self.removed:
            raise RuntimeError("integration worktree removed")
        return "patch"


def _publication_config(tmp_path: Path, credential: str) -> StewardPublicationConfig:
    paths = []
    for name, value in (
        ("d1-token", credential),
        ("r2-access-key", "configured-access-key-value"),
        ("r2-secret-key", "configured-secret-key-value"),
    ):
        path = tmp_path / name
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(0o600)
        paths.append(path)
    staging = tmp_path / "publication-staging"
    staging.mkdir(mode=0o700)
    return StewardPublicationConfig(
        enabled=True,
        account_id="a" * 32,
        d1_database_id="00000000-0000-4000-8000-000000000000",
        d1_token_path=paths[0],
        r2_endpoint="https://example.r2.cloudflarestorage.com",
        r2_access_key_id_path=paths[1],
        r2_secret_access_key_path=paths[2],
        public_bucket="publication-public",
        private_bucket="publication-private",
        public_base_url="https://publication.example.test",
        staging_root=staging,
    )


def _publication_graph(title: str) -> dict[str, object]:
    task_id = "task-publication-preflight"
    pipeline_id = "pipeline-publication-preflight"
    run_id = "run-publication-preflight"
    documents = {
        "codex.jsonl": (
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "message-1",
                        "type": "agent_message",
                        "text": "safe",
                    },
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        ),
        "activities.jsonl": (
            b'{"record_type":"header","schema_version":1}\n'
            b'{"record_type":"event","schema_version":1,"sequence":1,'
            b'"source_event_id":"activity-1","activity":"investigate",'
            b'"summary":"Complete the task",'
            b'"recorded_at":"2026-07-28T12:00:00.100Z"}\n'
            b'{"record_type":"summary","schema_version":1,'
            b'"capture_state":"complete","recorded":1,"invalid":0,'
            b'"duplicate":0,"omitted":0,"truncated":false}\n'
        ),
        "telemetry.json": (
            b'{"schema_version":1,"provenance":"codex_exec",'
            b'"completeness":"complete","aggregate":{},'
            b'"cost":{"status":"unavailable"}}'
        ),
        "run.json": (
            b'{"taskId":"task-publication-preflight",'
            b'"pipelineId":"pipeline-publication-preflight",'
            b'"runId":"run-publication-preflight","role":"planning",'
            b'"state":"succeeded","startedAt":"2026-07-28T12:00:00.000Z",'
            b'"completedAt":"2026-07-28T12:00:01.000Z"}\n'
        ),
    }
    source = AtifSource(
        run={
            "taskId": task_id,
            "pipelineId": pipeline_id,
            "runId": run_id,
            "role": "planning",
            "state": "succeeded",
            "startedAt": "2026-07-28T12:00:00.000Z",
            "completedAt": "2026-07-28T12:00:01.000Z",
            "durationMs": 1_000,
        },
        documents=documents,
    )
    return {
        "task": {
            "taskId": task_id,
            "title": title,
            "lifecycleState": "active",
            "createdAt": "2026-07-28T12:00:00Z",
            "completedAt": None,
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
                "eventType": "completed",
                "occurredAt": "2026-07-28T12:00:01Z",
                "summary": "Planning completed",
            }
        ],
    }


def test_source_scanner_keeps_patch_and_tree_categories(
    repo: Path, monkeypatch
) -> None:
    (repo / "README.md").write_text("source change\n", encoding="utf-8")
    captured: list[object] = []

    def scan(entries, **_kwargs):
        captured.extend(entries)
        return ScannerReport()

    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_trufflehog", scan
    )
    executor = object.__new__(StewardExecutor)

    result = StewardExecutor._scan_integration_source(executor, repo, "patch text")

    assert result.clean
    assert captured[0].category == "patch"
    assert captured[0].logical_path == "integration.patch"
    source_entries = captured[1:]
    assert source_entries
    assert all(entry.category == "source" for entry in source_entries)
    assert any(entry.logical_path == "README.md" for entry in source_entries)


def test_source_scanner_rejects_symlinked_tree_file(repo: Path) -> None:
    (repo / "target.txt").write_text("source\n", encoding="utf-8")
    (repo / "linked.txt").symlink_to("target.txt")
    executor = object.__new__(StewardExecutor)

    with pytest.raises(ValueError, match="symlink"):
        StewardExecutor._scan_integration_source(executor, repo, "patch text")


def test_publication_preflight_inspects_configured_credentials(
    repo: Path, tmp_path: Path
) -> None:
    credential = "plain-credential-value"
    config = _publication_config(tmp_path, credential)
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(publication=config)
    executor._publication_scanner_runner = lambda argv, **_kwargs: SimpleNamespace(
        returncode=0,
        stdout=b"",
    )
    executor._integration_publication_graph = lambda _source: _publication_graph(
        credential
    )

    outcome, counts, fingerprint = executor._build_integration_publication_outcome(
        SimpleNamespace(id="task-publication-preflight"),
        repo,
        "safe patch",
    )

    assert isinstance(outcome, FailClosed)
    assert outcome.reason_codes == (ReasonCode.unsafe_content,)
    assert counts == {"source": 0, "patch": 0}
    assert credential not in repr(outcome)
    assert credential not in fingerprint


def test_source_scanner_detects_literal_configured_credentials(
    repo: Path, tmp_path: Path
) -> None:
    credential = "plain-credential-value"
    config = _publication_config(tmp_path, credential)
    (repo / "README.md").write_text(
        f"source contains {credential}\n",
        encoding="utf-8",
    )
    executor = object.__new__(StewardExecutor)
    executor._publication_scanner_runner = lambda argv, **_kwargs: SimpleNamespace(
        returncode=0,
        stdout=b"",
    )

    report = executor._scan_integration_source(
        repo,
        f"patch contains {credential}",
        credential_sources=(
            config.d1_token_path,
            config.r2_access_key_id_path,
            config.r2_secret_access_key_path,
        ),
    )

    assert report.clean is False
    assert {finding.category for finding in report.findings} == {"source", "patch"}
    assert credential not in repr(report)


def test_repair_required_blocks_current_integration_before_commit(
    tmp_path: Path,
) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=SimpleNamespace(enabled=True), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    worktrees = _Worktrees()
    executor.worktrees = worktrees
    executor._finish_task = lambda *_args: setattr(worktrees, "removed", True)
    executor._build_integration_publication_outcome = lambda *_args: (
        RepairRequired((ReasonCode.source_finding,)),
        {"source": 1, "patch": 0},
        "f" * 64,
    )
    repaired_patches: list[str] = []

    def repair(*args) -> bool:
        repaired_patches.append(args[2])
        return True

    executor._repair_integration_validation_failure = repair
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")
    task = SimpleNamespace(id="integration-task")
    source = SimpleNamespace(id="source-task")

    result = executor._integration_publication_preflight(
        task,
        source,
        tmp_path,
        "patch",
        "validated-tree",
        transcript,
    )

    assert result is True
    assert repaired_patches == ["patch"]
    assert any(
        event.kind == "integration.publication_preflight"
        and event.data["status"] == "repair_required"
        for event in store.items
    )
    assert "publication_repair" in transcript.path.read_text(encoding="utf-8")


def test_clean_publication_preflight_allows_commit_path(tmp_path: Path) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=SimpleNamespace(enabled=True), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    executor.worktrees = _Worktrees()
    executor._build_integration_publication_outcome = lambda *_args: (
        PublicationGeneration({}),
        {"source": 0, "patch": 0},
        "c" * 64,
    )
    executor._finish_task = lambda *_args: pytest.fail("clean preflight must not finish a task")
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")

    result = executor._integration_publication_preflight(
        SimpleNamespace(id="integration-task"),
        SimpleNamespace(id="source-task"),
        tmp_path,
        "patch",
        "validated-tree",
        transcript,
    )

    assert result is None
    assert store.items[0].data["status"] == "clean"
    assert "preflight clean" in transcript.path.read_text(encoding="utf-8")


def test_fail_closed_publication_preflight_blocks_without_finding_text(
    tmp_path: Path,
) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=SimpleNamespace(enabled=True), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    executor.worktrees = _Worktrees()
    executor._build_integration_publication_outcome = lambda *_args: (
        FailClosed((ReasonCode.scanner_failure,)),
        {"source": 0, "patch": 0},
        "d" * 64,
    )
    finished: list[tuple[object, ...]] = []
    executor._finish_task = lambda *args: finished.append(args)
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")

    result = executor._integration_publication_preflight(
        SimpleNamespace(id="integration-task"),
        SimpleNamespace(id="source-task"),
        tmp_path,
        "patch contains private-secret-value",
        "validated-tree",
        transcript,
    )

    assert result is False
    assert len(finished) == 2
    assert all("private-secret-value" not in str(item) for item in store.items)
    assert "private-secret-value" not in transcript.path.read_text(encoding="utf-8")
    assert store.items[0].data["reason_codes"] == [ReasonCode.scanner_failure.value]


def test_disabled_publication_preflight_scans_clean_source(tmp_path: Path) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=StewardPublicationConfig(), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    executor.worktrees = _Worktrees()
    scanned: list[tuple[Path, str, object]] = []

    def scan(worktree: Path, patch_text: str, *, credential_sources: object) -> ScannerReport:
        scanned.append((worktree, patch_text, credential_sources))
        return ScannerReport()

    executor._scan_integration_source = scan
    executor._integration_publication_graph = lambda _source: pytest.fail(
        "disabled transport must not require an archive graph"
    )
    executor._finish_task = lambda *_args: pytest.fail(
        "clean source must reach the commit path"
    )
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")

    result = executor._integration_publication_preflight(
        SimpleNamespace(id="integration-task"),
        SimpleNamespace(id="source-task"),
        tmp_path,
        "patch",
        "validated-tree",
        transcript,
    )

    assert result is None
    assert scanned == [(tmp_path, "patch", ())]
    assert store.items[0].data["status"] == "clean"


def test_disabled_publication_preflight_repairs_source_findings(
    tmp_path: Path,
) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=StewardPublicationConfig(), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    worktrees = _Worktrees()
    executor.worktrees = worktrees
    executor._scan_integration_source = lambda *_args, **_kwargs: ScannerReport(
        findings=(ScannerFinding("README.md", b"source-secret", category="source"),)
    )
    executor._integration_publication_graph = lambda _source: pytest.fail(
        "disabled transport must not require an archive graph"
    )
    executor._finish_task = lambda *_args: setattr(worktrees, "removed", True)
    repaired_patches: list[str] = []

    def repair(*args) -> bool:
        repaired_patches.append(args[2])
        return True

    executor._repair_integration_validation_failure = repair
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")

    result = executor._integration_publication_preflight(
        SimpleNamespace(id="integration-task"),
        SimpleNamespace(id="source-task"),
        tmp_path,
        "patch",
        "validated-tree",
        transcript,
    )

    assert result is True
    assert repaired_patches == ["patch"]
    assert store.items[0].data["status"] == "repair_required"


def test_disabled_publication_preflight_fails_closed_on_scan_error(
    tmp_path: Path,
) -> None:
    store = _EventStore()
    executor = object.__new__(StewardExecutor)
    executor.config = SimpleNamespace(
        publication=StewardPublicationConfig(), logs_dir=tmp_path / "logs"
    )
    executor.store = store
    executor.worktrees = _Worktrees()
    executor._scan_integration_source = lambda *_args, **_kwargs: ScannerReport(
        failure=ReasonCode.scanner_failure
    )
    executor._integration_publication_graph = lambda _source: pytest.fail(
        "disabled transport must not require an archive graph"
    )
    finished: list[tuple[object, ...]] = []
    executor._finish_task = lambda *args: finished.append(args)
    transcript = IntegrationTranscript(tmp_path / "transcript.txt")

    result = executor._integration_publication_preflight(
        SimpleNamespace(id="integration-task"),
        SimpleNamespace(id="source-task"),
        tmp_path,
        "patch contains private-secret-value",
        "validated-tree",
        transcript,
    )

    assert result is False
    assert len(finished) == 2
    assert store.items[0].data["reason_codes"] == [ReasonCode.scanner_failure.value]
    assert "private-secret-value" not in transcript.path.read_text(encoding="utf-8")
