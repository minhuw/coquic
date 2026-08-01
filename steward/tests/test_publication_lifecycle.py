from __future__ import annotations

import json
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.core.config import StewardPublicationConfig
import coquic_steward.execution.session as session_module
from coquic_steward.execution.executor import (
    IntegrationTranscript,
    PublicationPreflightClean,
    StewardExecutor,
)
from coquic_steward.execution.session import load_publication_snapshot
from coquic_steward.execution.task_archive import TaskArchiveWriter
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.publication.atif import AtifSource
from coquic_steward.publication.generation import PublicationGeneration
from coquic_steward.publication.models import FailClosed, ReasonCode, RepairRequired
from coquic_steward.publication.outbox import (
    CleanupIntent,
    CleanupState,
    PublicationReceipt,
    ReceiptClass,
)
from coquic_steward.publication.r2 import private_original_key
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
        PublicationPreflightClean(),
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


def test_terminal_publication_receipts_match_immutable_generation(
    monkeypatch,
) -> None:
    graph = _publication_graph("terminal-receipts")
    from coquic_steward.publication.generation import compose_publication_generation

    composed = compose_publication_generation(
        graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(composed, PublicationGeneration)
    now = datetime.now(timezone.utc)
    durable = replace(
        composed.outbox_record,
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    receipts = [
        PublicationReceipt.public_receipt(
            item.sha256,
            item.byte_size,
            item.public_key,
            now,
            item.logical_path,
        )
        for item in composed.objects
    ]
    receipts.extend(
        PublicationReceipt.private_receipt(
            item.sha256,
            item.byte_size,
            private_original_key(item.task_id, item.run_id, item.sha256),
            now,
        )
        for item in composed.private_originals
    )

    class Store:
        def list_publication_receipts(self, _publication_id):
            return list(receipts)

    task = SimpleNamespace(id=durable.task_id)
    daemon = object.__new__(StewardDaemon)
    daemon.store = Store()
    daemon._publication_source = lambda _generation: graph
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.compose_publication_generation",
        lambda *_args, **_kwargs: composed,
    )

    assert daemon._terminal_publication_receipts_verified(task, durable) == (
        True,
        "verified",
    )
    receipts.pop()
    assert daemon._terminal_publication_receipts_verified(task, durable) == (
        False,
        "receipt_mismatch",
    )


def test_terminal_gate_rejects_exposed_active_snapshot_until_terminal_generation(
    tmp_path: Path, monkeypatch
) -> None:
    from coquic_steward.publication.generation import compose_publication_generation

    active_graph = _publication_graph("active-snapshot")
    active_composed = compose_publication_generation(
        active_graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(active_composed, PublicationGeneration)
    task = SimpleNamespace(
        id=active_composed.task_id,
        status="failed",
        updated_at=datetime(2026, 7, 28, 12, 1, tzinfo=timezone.utc),
    )
    run = SimpleNamespace(
        id=active_composed.run_id,
        state="succeeded",
        completed_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=timezone.utc),
    )
    daemon = object.__new__(StewardDaemon)
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    archive = session_module.TaskArchiveWriter(SimpleNamespace(tasks_dir=tasks_dir))
    archive.ensure_epoch()
    archive.task_dir(task.id).mkdir()
    assert session_module._write_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir),
        task.id,
        run.id,
        active_graph,
    )
    daemon.config = SimpleNamespace(
        tasks_dir=tasks_dir,
        publication=SimpleNamespace(enabled=True),
    )
    daemon.executor = SimpleNamespace(
        _integration_publication_graph=lambda _task: active_graph,
    )
    terminal_run_id = daemon._terminal_publication_run_alias(task, run)
    assert terminal_run_id is not None and terminal_run_id != run.id
    assert daemon._prepare_terminal_publication_snapshot(task, run)
    terminal_graph = session_module.load_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir),
        task.id,
        terminal_run_id,
    )
    assert terminal_graph is not None
    assert session_module.load_publication_snapshot(
        SimpleNamespace(tasks_dir=tasks_dir), task.id, run.id
    )["task"]["lifecycleState"] == "active"
    terminal_composed = compose_publication_generation(
        terminal_graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(terminal_composed, PublicationGeneration)
    assert terminal_composed.publication_id != active_composed.publication_id

    now = datetime.now(timezone.utc)

    def receipts_for(composed: PublicationGeneration) -> list[PublicationReceipt]:
        values = [
            PublicationReceipt.public_receipt(
                item.sha256,
                item.byte_size,
                item.public_key,
                now,
                item.logical_path,
            )
            for item in composed.objects
        ]
        values.extend(
            PublicationReceipt.private_receipt(
                item.sha256,
                item.byte_size,
                private_original_key(item.task_id, item.run_id, item.sha256),
                now,
            )
            for item in composed.private_originals
        )
        return values

    active = replace(
        active_composed.outbox_record,
        state="exposed",
        updated_at=now,
        exposed_at=now,
    )
    terminal = replace(
        terminal_composed.outbox_record,
        state="queued",
        updated_at=now,
    )
    current = {"generation": terminal}
    receipts = {
        active.publication_id: receipts_for(active_composed),
        terminal.publication_id: receipts_for(terminal_composed),
    }

    class Store:
        def __init__(self) -> None:
            self.events_value: list[SimpleNamespace] = []

        def list_runs(self, _task_id):
            return [run]

        def get_publication_generation(self, _publication_id):
            return current["generation"]

        def list_publication_receipts(self, publication_id):
            return list(receipts[publication_id])

        def events(self, _task_id):
            return list(self.events_value)

        def add_event(self, task_id, kind, message, data=None):
            self.events_value.append(
                SimpleNamespace(
                    task_id=task_id,
                    kind=kind,
                    message=message,
                    data=data or {},
                )
            )

    store = Store()
    daemon.store = store
    daemon.logger = None
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.enqueue_materialized_publication",
        lambda _config, _store, _task, enqueue_run: _enqueue_terminal(
            enqueue_run, terminal.run_id, current["generation"]
        ),
    )
    daemon._publication_source = lambda generation: (
        active_graph
        if generation.publication_id == active.publication_id
        else terminal_graph
    )
    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.compose_publication_generation",
        lambda source, **_kwargs: (
            active_composed if source is active_graph else terminal_composed
        ),
    )

    assert daemon._terminal_publication_receipts_verified(task, active) == (
        False,
        "terminal_lifecycle_mismatch",
    )
    assert daemon._terminal_publication_gate(task) is False
    assert any(
        event.data.get("reason") == "final_generation_queued"
        for event in store.events_value
    )

    current["generation"] = replace(terminal, state="exposed", exposed_at=now)
    assert daemon._terminal_publication_gate(task) is True


def _enqueue_terminal(run: object, expected: str, generation: object) -> object:
    assert getattr(run, "id", None) == expected
    return generation


def test_materialized_success_enqueues_deterministically_without_transport(
    monkeypatch,
) -> None:
    graph = _publication_graph("completion-boundary")
    # Build the valid immutable generation through the existing pure contract;
    # the session hook itself must only hand its outbox record to the store.
    from coquic_steward.publication.generation import compose_publication_generation

    scanner = lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b"")
    generation = compose_publication_generation(graph, scanner_runner=scanner)
    assert isinstance(generation, PublicationGeneration)
    monkeypatch.setattr(session_module, "publication_graph_for_task", lambda *_args: graph)
    monkeypatch.setattr(
        session_module,
        "compose_publication_generation",
        lambda *_args, **_kwargs: generation,
    )

    queued: list[object] = []
    store = SimpleNamespace(enqueue_publication=lambda value: queued.append(value) or value)
    config = SimpleNamespace(publication=SimpleNamespace(enabled=True))
    task = SimpleNamespace(id="task-publication-preflight")
    run = SimpleNamespace(
        state="succeeded", completed_at=datetime.now(timezone.utc)
    )

    first = session_module.enqueue_materialized_publication(config, store, task, run)
    second = session_module.enqueue_materialized_publication(config, store, task, run)

    assert first.publication_id == generation.publication_id
    assert second.publication_id == generation.publication_id
    assert [item.publication_id for item in queued] == [
        generation.publication_id,
        generation.publication_id,
    ]

    run.state = "running"
    assert session_module.enqueue_materialized_publication(config, store, task, run) is None


def test_materialized_publication_uses_immutable_snapshot_after_graph_changes(
    tmp_path: Path, monkeypatch
) -> None:
    graph = _publication_graph("original-title")
    from coquic_steward.publication.generation import compose_publication_generation

    generation = compose_publication_generation(
        graph,
        scanner_runner=lambda _argv, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert isinstance(generation, PublicationGeneration)
    observed_titles: list[str] = []

    def compose(source: object, **_kwargs: object) -> object:
        assert isinstance(source, dict)
        if source["task"]["title"] != "original-title":
            raise AssertionError("mutable graph was used for publication")
        observed_titles.append(source["task"]["title"])
        return generation

    monkeypatch.setattr(session_module, "publication_graph_for_task", lambda *_args: graph)
    monkeypatch.setattr(session_module, "compose_publication_generation", compose)
    queued: list[object] = []
    config = SimpleNamespace(
        tasks_dir=tmp_path / "tasks",
        publication=SimpleNamespace(enabled=True),
    )
    store = SimpleNamespace(enqueue_publication=lambda value: queued.append(value) or value)
    task = SimpleNamespace(id="task-publication-preflight")
    run = SimpleNamespace(
        id="run-publication-preflight",
        state="succeeded",
        completed_at=datetime.now(timezone.utc),
    )

    first = session_module.enqueue_materialized_publication(config, store, task, run)
    graph["task"]["title"] = "mutated-title"
    second = session_module.enqueue_materialized_publication(config, store, task, run)

    assert first.publication_id == generation.publication_id
    assert second.publication_id == generation.publication_id
    assert observed_titles == ["original-title", "original-title"]
    snapshot = load_publication_snapshot(
        config, task.id, run.id
    )
    assert snapshot is not None
    assert snapshot["task"]["title"] == "original-title"

    daemon = object.__new__(StewardDaemon)
    daemon.config = config
    daemon.store = SimpleNamespace(get=lambda _task_id: task)
    daemon.executor = SimpleNamespace(_integration_publication_graph=lambda _task: graph)
    daemon.logger = None
    source = daemon._publication_source(queued[0])
    assert source["task"]["title"] == "original-title"


def test_verified_cleanup_intent_rejects_replaced_archive_before_delete(tmp_path: Path) -> None:
    task_id = "task-cleanup-replacement"
    tasks_dir = tmp_path / "tasks"
    archive = TaskArchiveWriter(SimpleNamespace(tasks_dir=tasks_dir))

    def seal_archive(completion_identity: str) -> str:
        archive.create_task(task_id, "prompt", pipeline_id="pipeline-cleanup")
        archive.materialize_pipeline(
            task_id,
            {
                "pipelineId": "pipeline-cleanup",
                "taskId": task_id,
                "runs": [
                    {
                        "runId": "run-cleanup",
                        "role": "implementation",
                        "roleOrdinal": 1,
                        "state": "succeeded",
                        "path": "pipelines/pipeline-cleanup/runs/run-cleanup/run.json",
                    }
                ],
            },
        )
        archive.materialize_run(
            task_id,
            "pipeline-cleanup",
            {
                "runId": "run-cleanup",
                "taskId": task_id,
                "pipelineId": "pipeline-cleanup",
                "role": "implementation",
                "roleOrdinal": 1,
                "state": "succeeded",
                "completedAt": "2026-07-22T00:00:02Z",
            },
        )
        pipeline_path = archive.task_path(
            task_id, "pipelines/pipeline-cleanup/pipeline.json"
        )
        pipeline = json.loads(pipeline_path.read_text())
        pipeline.update(state="succeeded", completedAt="2026-07-22T00:00:03Z")
        archive.write_json(task_id, "pipelines/pipeline-cleanup/pipeline.json", pipeline)
        task_path = archive.task_path(task_id, "task.json")
        task = json.loads(task_path.read_text())
        task["status"] = "succeeded"
        archive.write_json(task_id, "task.json", task)
        archive.seal(
            task_id,
            "succeeded",
            completion_identity=completion_identity,
            completed_at="2026-07-22T00:00:04Z",
            external_actions_complete=True,
            writer_final=True,
        )
        return archive.manifest_digest(task_id)

    expected_digest = seal_archive("completion-cleanup-a")
    archive.task_dir(task_id).rename(tmp_path / "archive-a")
    replacement_digest = seal_archive("completion-cleanup-b")
    assert replacement_digest != expected_digest

    class CleanupStore:
        def __init__(self) -> None:
            self.blocked: list[tuple[str, str]] = []
            self.completed: list[str] = []

        def verify_cleanup_intent(self, *_args: object, **_kwargs: object):
            raise AssertionError("verified cleanup intent must not be re-verified")

        def block_cleanup_intent(self, intent_id: str, *, reason: str):
            self.blocked.append((intent_id, reason))
            return SimpleNamespace(status="blocked")

        def complete_cleanup_intent(self, intent_id: str, **_kwargs: object):
            self.completed.append(intent_id)
            return SimpleNamespace(status="completed")

    store = CleanupStore()
    daemon = object.__new__(StewardDaemon)
    daemon.store = store
    daemon._log = lambda _message: None
    now = datetime.now(timezone.utc)
    intent = CleanupIntent(
        task_id=task_id,
        publication_id="publication-cleanup-replacement",
        manifest_digest=expected_digest,
        exact_path=str(archive.task_dir(task_id)),
        requested_at=now,
        state=CleanupState.pending,
        verified_at=now,
    )

    assert daemon._delete_terminal_archive(
        SimpleNamespace(id=task_id),
        archive,
        intent,
    ) is False
    assert archive.task_dir(task_id).is_dir()
    assert store.blocked == [(intent.intent_id, "cleanup_failed")]
    assert store.completed == []


def test_session_completion_enqueues_every_materialized_revision(tmp_path: Path) -> None:
    completed_ids: list[str] = []

    class Archive:
        def task_path(self, _task_id: str, relative: str) -> Path:
            return tmp_path / relative

        def append_run_jsonl(self, *_args: object, **_kwargs: object) -> None:
            return None

        def write_run_file(
            self,
            _task_id: str,
            _pipeline_id: str,
            run_id: str,
            name: str,
            value: object,
        ) -> Path:
            path = tmp_path / "archive" / run_id / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, dict):
                path.write_text(json.dumps(value), encoding="utf-8")
            elif isinstance(value, str):
                path.write_text(value, encoding="utf-8")
            else:
                path.write_bytes(value)
            return path

        def materialize_run(self, *_args: object, **_kwargs: object) -> None:
            return None

    class Store:
        def __init__(self, run: SimpleNamespace) -> None:
            self.run = run

        def transition_run(self, _run_id: str, state: str, **_kwargs: object) -> None:
            self.run.state = state
            self.run.completed_at = datetime.now(timezone.utc)

        def get_run(self, _run_id: str) -> SimpleNamespace:
            return self.run

    class Invoker:
        def invoke(self, _request: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                provider_session_id=None,
                interrupted=False,
                forced=False,
                completed=True,
                exit_code=0,
                events=(),
                incomplete_suffix=b"",
                malformed_lines=0,
            )

    for role in ("implementation", "review", "validation", "integration"):
        run_id = f"run-{role}"
        run = SimpleNamespace(
            id=run_id,
            pipeline_id="pipeline-revisions",
            state="running",
            completed_at=None,
            exit_reason=None,
        )
        store = Store(run)
        supervisor = object.__new__(session_module.SessionSupervisor)
        supervisor.archive = Archive()
        supervisor.store = store
        supervisor.config = SimpleNamespace()
        supervisor._active = {}
        supervisor._active_lock = threading.RLock()
        supervisor._enqueue_completed_run = lambda _task, saved: completed_ids.append(
            saved.id
        )
        task = SimpleNamespace(id=f"task-{role}")
        session = SimpleNamespace(id=f"session-{role}", checkpoint_id=None, private_home_path=None)
        request = SimpleNamespace(output_last_message=tmp_path / f"private-{role}.md")

        supervisor._execute(
            task,
            session,
            run,
            request,
            runtime=None,
            invoker=Invoker(),
            api_key=None,
            timeout_seconds=1.0,
        )

    assert completed_ids == ["run-implementation", "run-review", "run-validation", "run-integration"]
