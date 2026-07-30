from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from coquic_steward.execution.executor import (
    IntegrationTranscript,
    StewardExecutor,
)
from coquic_steward.publication.generation import PublicationGeneration
from coquic_steward.publication.models import FailClosed, ReasonCode, RepairRequired
from coquic_steward.publication.scanner import ScannerReport


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
