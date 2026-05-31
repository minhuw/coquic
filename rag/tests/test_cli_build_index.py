from __future__ import annotations

import json
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


def _write_fixture_rfc_9001(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "rfc9001.txt").write_text(
        """Network Working Group
Request for Comments: 9001

Using TLS to Secure QUIC

Abstract

This is a minimal RFC fixture for upsert tests.

4.  TLS Integration

QUIC uses TLS for authenticated key exchange and packet protection.
""",
        encoding="utf-8",
    )


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


def test_index_corpus_upserts_new_corpus_without_resetting_existing_artifacts(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)

    first_exit_code = main(
        [
            "index-corpus",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )
    assert first_exit_code == 0
    capsys.readouterr()

    (source_dir / "rfc9000.txt").unlink()
    _write_fixture_rfc_9001(source_dir)

    second_exit_code = main(
        [
            "index-corpus",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert second_exit_code == 0
    sections = read_section_records(state_dir / "artifacts" / "sections.jsonl")
    assert {record["doc_id"] for record in sections} == {"rfc9000", "rfc9001"}
    output = capsys.readouterr().out
    assert "upserted 1 documents" in output


def test_index_corpus_replace_resets_artifacts_to_current_corpus(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)

    first_exit_code = main(
        [
            "index-corpus",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )
    assert first_exit_code == 0
    capsys.readouterr()

    (source_dir / "rfc9000.txt").unlink()
    _write_fixture_rfc_9001(source_dir)

    second_exit_code = main(
        [
            "index-corpus",
            "--replace",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert second_exit_code == 0
    sections = read_section_records(state_dir / "artifacts" / "sections.jsonl")
    assert {record["doc_id"] for record in sections} == {"rfc9001"}
    assert QdrantSectionStore(state_dir / "qdrant").section_count() == len(sections)
    output = capsys.readouterr().out
    assert "replaced 1 documents" in output


def test_index_corpus_accepts_generic_document_loader_args(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    source_dir.mkdir()
    (source_dir / "guide.md").write_text("# Guide\n\nQUIC text", encoding="utf-8")

    monkeypatch.setattr(
        "coquic_rag.cli.main.load_corpus",
        lambda source, config: type(
            "LoadedCorpus",
            (),
            {
                "section_records": [
                    {
                        "node_id": "guide#1",
                        "doc_id": "guide",
                        "doc_kind": "document",
                        "rfc_number": None,
                        "draft_name": None,
                        "section_id": "1",
                        "title": "guide.md",
                        "text": "QUIC text",
                        "source_path": "guide.md",
                        "source_type": "document",
                        "loader": config.loader,
                    }
                ],
                "graph_nodes": [],
                "graph_edges": [],
                "doc_ids": {"guide"},
            },
        )(),
    )

    exit_code = main(
        [
            "index-corpus",
            "--loader",
            "llamaindex",
            "--include",
            "**/*.md",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    sections = read_section_records(state_dir / "artifacts" / "sections.jsonl")
    assert sections[0]["loader"] == "llamaindex"
    output = capsys.readouterr().out
    assert "upserted 1 documents" in output


def test_index_corpus_accepts_source_code_loader_args(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    source_dir.mkdir()
    (source_dir / "main.cpp").write_text("void f() {}\n", encoding="utf-8")

    monkeypatch.setattr(
        "coquic_rag.cli.main.load_corpus",
        lambda source, config: type(
            "LoadedCorpus",
            (),
            {
                "section_records": [
                    {
                        "node_id": "main#1",
                        "doc_id": "main",
                        "doc_kind": "source_code",
                        "rfc_number": None,
                        "draft_name": None,
                        "section_id": "1",
                        "title": "main.cpp",
                        "text": "void f() {}",
                        "source_path": "main.cpp",
                        "source_type": "source_code",
                        "loader": config.loader,
                    }
                ],
                "graph_nodes": [],
                "graph_edges": [],
                "doc_ids": {"main"},
            },
        )(),
    )

    exit_code = main(
        [
            "index-corpus",
            "--loader",
            "cocoindex",
            "--include",
            "**/*.cpp",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    sections = read_section_records(state_dir / "artifacts" / "sections.jsonl")
    assert sections[0]["loader"] == "cocoindex"
    output = capsys.readouterr().out
    assert "upserted 1 documents" in output


def test_build_index_defaults_to_openrouter_free_embedding_model(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    captured: dict[str, object] = {}

    class FakeStore:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        def reset_collection(self) -> None:
            return None

        def upsert_sections(self, _records, embedder, *, progress=None, **_kwargs) -> None:
            captured["embedder_type"] = type(embedder).__name__
            captured["model_name"] = embedder.model_name
            if progress is not None:
                progress(1, 1)

    monkeypatch.setattr("coquic_rag.cli.main.QdrantSectionStore", FakeStore)

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
        ]
    )

    assert exit_code == 0
    assert captured == {
        "embedder_type": "OpenRouterEmbedder",
        "model_name": "nvidia/llama-nemotron-embed-vl-1b-v2:free",
    }


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
            qdrant_api_key: str | None = None,
            collection_name: str = "quic_sections",
        ) -> None:
            captured["state_dir"] = state_dir
            captured["qdrant_url"] = qdrant_url
            captured["qdrant_api_key"] = qdrant_api_key
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
        "qdrant_api_key": None,
        "collection_name": "quic_sections",
    }


def test_build_index_uses_remote_qdrant_api_key_from_env(
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
            qdrant_api_key: str | None = None,
            collection_name: str = "quic_sections",
        ) -> None:
            captured["state_dir"] = state_dir
            captured["qdrant_url"] = qdrant_url
            captured["qdrant_api_key"] = qdrant_api_key
            captured["collection_name"] = collection_name

        def reset_collection(self) -> None:
            return None

        def upsert_sections(self, *_args, progress=None, **_kwargs) -> None:
            if progress is not None:
                progress(1, 1)

    monkeypatch.setenv("COQUIC_QDRANT_URL", "https://example.qdrant.cloud")
    monkeypatch.setenv("COQUIC_QDRANT_API_KEY", "secret")
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
        "qdrant_url": "https://example.qdrant.cloud",
        "qdrant_api_key": "secret",
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


def test_list_corpus_reports_artifact_and_qdrant_counts(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _write_fixture_rfc(source_dir)
    _write_fixture_draft(source_dir)

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

    list_exit_code = main(
        [
            "list-corpus",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--format",
            "json",
        ]
    )

    assert list_exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["artifact_doc_count"] == 2
    assert payload["qdrant_doc_count"] == 2
    assert payload["qdrant_missing_doc_ids"] == []
    docs_by_id = {doc["doc_id"]: doc for doc in payload["docs"]}
    assert docs_by_id["rfc9000"]["qdrant_sections"] == docs_by_id["rfc9000"]["sections"]
    assert docs_by_id["rfc9000"]["sha256"]


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


def test_default_embedding_model_uses_openrouter_free_embedding_model() -> None:
    assert DEFAULT_EMBEDDING_MODEL == "nvidia/llama-nemotron-embed-vl-1b-v2:free"
