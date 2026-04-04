from __future__ import annotations

from pathlib import Path

from coquic_rag.cli.main import main
from coquic_rag.embed.provider import DEFAULT_EMBEDDING_MODEL
from coquic_rag.store.artifacts import (
    read_graph_edges,
    read_graph_nodes,
    read_section_records,
)
from coquic_rag.store.qdrant_store import QdrantSectionStore


_RFC_FIXTURE_TEXT = """Network Working Group
Request for Comments: 9000

QUIC: A UDP-Based Multiplexed and Secure Transport

Abstract

This is a minimal RFC fixture for build-index tests.

18.2.  Transport Parameter Definitions

max_udp_payload_size (0x03):
The max_udp_payload_size transport parameter is defined.
"""

_DRAFT_FIXTURE_TEXT = """Network Working Group
Internet-Draft
Intended status: Informational
Expires: 4 April 2027

draft-ietf-quic-qlog-main-schema-13

qlog: Structured Logging for Network Protocols

Abstract

This is a minimal draft fixture for build-index tests.

1.  Introduction

This section describes structured logging for network protocol analysis.
"""


def _write_fixture_rfc(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "rfc9000.txt").write_text(_RFC_FIXTURE_TEXT, encoding="utf-8")


def _write_fixture_draft(
    source_dir: Path,
    *,
    filename: str = "draft-ietf-quic-qlog-main-schema-13.txt",
    draft_name: str = "draft-ietf-quic-qlog-main-schema-13",
) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    source_text = _DRAFT_FIXTURE_TEXT.replace(
        "draft-ietf-quic-qlog-main-schema-13",
        draft_name,
    )
    (source_dir / filename).write_text(source_text, encoding="utf-8")


def test_build_index_writes_artifacts_and_qdrant_state(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    _write_fixture_draft(source_dir)

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    artifacts_dir = state_dir / "artifacts"
    assert read_section_records(artifacts_dir / "sections.jsonl")
    assert read_graph_nodes(artifacts_dir / "graph_nodes.jsonl")
    assert read_graph_edges(artifacts_dir / "graph_edges.jsonl")
    assert QdrantSectionStore(state_dir / "qdrant").collection_exists()

    output = capsys.readouterr().out
    assert "indexed 2 documents" in output


def test_build_index_reports_progress_stages(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    _write_fixture_draft(source_dir)

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "parse docs" in output
    assert "embed sections" in output
    assert "100%" in output


def test_build_index_rejects_duplicate_doc_ids(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_draft(source_dir, filename="draft-a.txt")
    _write_fixture_draft(source_dir, filename="draft-b.txt")

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 1
    output = capsys.readouterr()
    assert "duplicate doc_id draft-ietf-quic-qlog-main-schema-13" in output.err
    assert "Traceback" not in output.err


def test_build_index_uses_remote_qdrant_url_from_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    captured: dict[str, object] = {}

    class FakeStore:
        def __init__(
            self,
            state_dir: Path,
            qdrant_url: str | None = None,
            collection_name: str = "quic_sections",
        ) -> None:
            captured["state_dir"] = state_dir
            captured["qdrant_url"] = qdrant_url
            captured["collection_name"] = collection_name

        def reset_collection(self) -> None:
            return None

        def upsert_sections(self, *_args, progress=None, **_kwargs) -> None:
            if progress is not None:
                progress(1, 1)

    monkeypatch.setenv("COQUIC_QDRANT_URL", "http://127.0.0.1:6333")
    monkeypatch.setattr("coquic_rag.cli.main.QdrantSectionStore", FakeStore)

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    assert captured == {
        "state_dir": state_dir / "qdrant",
        "qdrant_url": "http://127.0.0.1:6333",
        "collection_name": "quic_sections",
    }


def test_doctor_reports_ready_after_build_index(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)

    build_exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )
    assert build_exit_code == 0
    capsys.readouterr()

    doctor_exit_code = main(
        [
            "doctor",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
        ]
    )

    assert doctor_exit_code == 0
    output = capsys.readouterr().out
    assert "source_docs: ok" in output
    assert "artifacts: ok" in output
    assert "qdrant: ok" in output
    assert "ready: yes" in output


def test_doctor_reports_remote_backend_when_qdrant_url_is_configured(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    monkeypatch.setenv("COQUIC_QDRANT_URL", "http://127.0.0.1:6333")
    monkeypatch.setattr(QdrantSectionStore, "section_count", lambda self: None)

    doctor_exit_code = main(
        [
            "doctor",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
        ]
    )

    assert doctor_exit_code == 1
    output = capsys.readouterr().out
    assert "qdrant_backend: remote" in output


def test_doctor_reports_unreachable_remote_backend_without_crashing(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    monkeypatch.setenv("COQUIC_QDRANT_URL", "http://127.0.0.1:6333")

    def _raise_connection_error(_self: QdrantSectionStore) -> int | None:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(QdrantSectionStore, "section_count", _raise_connection_error)

    doctor_exit_code = main(
        [
            "doctor",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
        ]
    )

    assert doctor_exit_code == 1
    output = capsys.readouterr().out
    assert "qdrant_backend: remote" in output
    assert "qdrant: unreachable" in output
    assert "ready: no" in output


def test_default_embedding_model_uses_small_cpu_friendly_model() -> None:
    assert DEFAULT_EMBEDDING_MODEL == "sentence-transformers/all-MiniLM-L6-v2"
