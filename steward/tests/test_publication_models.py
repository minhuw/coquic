from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from coquic_steward.publication import (
    FailClosed,
    FindingSummary,
    LogicalArtifact,
    PrivateOriginal,
    PublicationError,
    PublicationSnapshot,
    PublicBundle,
    PublicBundleComponent,
    Publishable,
    ReasonCode,
    RepairRequired,
    RunIdentity,
    RunMetadata,
    SourceDocument,
    UsageSummary,
    private_staging,
    read_stable_file,
    read_stable_jsonl,
)


def _run(state: str = "completed") -> RunMetadata:
    started = datetime(2026, 7, 28, tzinfo=timezone.utc)
    return RunMetadata(
        identity=RunIdentity("task-clean", "pipeline-clean", "run-clean"),
        role="planning",
        state=state,
        started_at=started,
        completed_at=started,
        duration_ms=0,
        model="gpt-test",
        reasoning="medium",
        usage=UsageSummary(prompt_tokens=1, completion_tokens=2, total_tokens=3),
    )


def test_models_round_trip_as_bounded_dicts() -> None:
    document = SourceDocument("runs/run-clean/trajectory.json", b'{"ok":true}\n', "application/json")
    artifact = LogicalArtifact.from_document("artifact-trajectory", document, owner_step_id=1)
    component = PublicBundleComponent(artifact, document.content)
    snapshot = PublicationSnapshot(
        _run(),
        documents=(document,),
        artifacts=(artifact,),
        public_bundle=PublicBundle((component,)),
        private_original=PrivateOriginal(b"private original\n"),
        findings=(FindingSummary(ReasonCode.unsafe_content, 1),),
    )

    assert Publishable(snapshot).as_dict()["status"] == "publishable"
    rendered = snapshot.as_dict()
    assert rendered["run"]["taskId"] == "task-clean"
    assert rendered["documents"][0]["sha256"] == hashlib.sha256(document.content).hexdigest()
    assert b"private original" not in repr(rendered).encode()
    with pytest.raises((AttributeError, TypeError)):
        snapshot.documents += (document,)  # type: ignore[misc]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: RunIdentity("../private", "pipeline", "run"),
        lambda: SourceDocument("../private.txt", b"secret"),
        lambda: LogicalArtifact("artifact", "https://private", "text/plain", 1, "0" * 64),
        lambda: RunMetadata(RunIdentity("task", "pipeline", "run"), "planning", "running", datetime.now(timezone.utc), datetime.now(timezone.utc), 1),
    ],
)
def test_unsafe_values_fail_without_echoing_input(factory) -> None:
    with pytest.raises(PublicationError) as error:
        factory()
    assert error.value.code in {
        ReasonCode.invalid_identifier,
        ReasonCode.invalid_path,
        ReasonCode.running,
    }
    assert "private" not in str(error.value)
    assert "https" not in str(error.value)


def test_outcomes_have_only_enumerated_reasons_and_counts() -> None:
    repair = RepairRequired((ReasonCode.scanner_failure,), (FindingSummary(ReasonCode.unsafe_content, 2),))
    failed = FailClosed((ReasonCode.partial,), (FindingSummary(ReasonCode.partial, 1),))
    assert repair.as_dict() == {
        "status": "repair_required",
        "reasonCodes": ["scanner_failure"],
        "findings": [{"code": "unsafe_content", "count": 2}],
    }
    assert failed.as_dict()["reasonCodes"] == ["partial"]
    with pytest.raises(PublicationError):
        RepairRequired(("scanner leaked a credential",))  # type: ignore[arg-type]


def test_stable_file_and_jsonl_reads(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'{"event":1}\n{"event":2}\n')
    value = read_stable_jsonl(path)
    assert value.records[0]["event"] == 1
    assert value.byte_size == path.stat().st_size
    assert value.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert read_stable_file(path).content == path.read_bytes()


@pytest.mark.parametrize("payload", [b"{\"event\": 1}", b"{\"event\": 1}\n\n", b"[]\n", b"{\"event\": 1, \"event\": 2}\n"])
def test_jsonl_rejects_partial_blank_non_object_and_duplicate_records(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(payload)
    with pytest.raises(PublicationError) as error:
        read_stable_jsonl(path)
    assert error.value.code in {ReasonCode.partial, ReasonCode.invalid_jsonl}


def test_stable_read_rejects_unsafe_files_and_evidence(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(PublicationError) as error:
        read_stable_file(directory)
    assert error.value.code == ReasonCode.non_regular

    target = tmp_path / "target"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(PublicationError) as error:
        read_stable_file(link)
    assert error.value.code == ReasonCode.symlink

    with pytest.raises(PublicationError) as error:
        read_stable_file(target, expected_size=3)
    assert error.value.code == ReasonCode.size_mismatch
    with pytest.raises(PublicationError) as error:
        read_stable_file(target, expected_sha256="0" * 64)
    assert error.value.code == ReasonCode.digest_mismatch
    with pytest.raises(PublicationError) as error:
        read_stable_file(target, max_bytes=3)
    assert error.value.code == ReasonCode.oversized

    hardlink = tmp_path / "hardlink"
    os.link(target, hardlink)
    with pytest.raises(PublicationError) as error:
        read_stable_file(target)
    assert error.value.code == ReasonCode.hardlink


def test_private_staging_is_contained_and_mode_0700(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    with private_staging(tmp_path) as staging:
        assert staging.parent == tmp_path
        assert stat.S_IMODE(staging.lstat().st_mode) == 0o700
        (staging / "work.txt").write_text("temporary", encoding="utf-8")
    assert not staging.exists()

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    os.chmod(unsafe, 0o755)
    with pytest.raises(PublicationError) as error:
        with private_staging(unsafe):
            pass
    assert error.value.code == ReasonCode.staging_unsafe


def test_snapshot_rejects_duplicate_paths_and_oversized_artifact() -> None:
    first = SourceDocument("a.txt", b"a", "text/plain")
    second = SourceDocument("a.txt", b"b", "text/plain")
    artifact = LogicalArtifact.from_document("artifact-a", first)
    with pytest.raises(PublicationError) as error:
        PublicationSnapshot(
            _run(),
            documents=(first, second),
            artifacts=(artifact,),
            public_bundle=PublicBundle((PublicBundleComponent(artifact, first.content),)),
        )
    assert error.value.code == ReasonCode.invalid_metadata
    with pytest.raises(PublicationError) as error:
        LogicalArtifact("artifact", "a.txt", "text/plain", 65 * 1024 * 1024, "0" * 64)
    assert error.value.code == ReasonCode.oversized
