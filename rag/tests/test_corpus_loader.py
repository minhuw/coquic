from __future__ import annotations

import sys
import types
from pathlib import Path

from coquic_rag.ingest.corpus_loader import CorpusLoadConfig, load_corpus


def test_auto_loader_uses_rfc_parser_for_rfc_text(tmp_path: Path) -> None:
    source = tmp_path / "docs"
    source.mkdir()
    (source / "rfc9000.txt").write_text(
        """Network Working Group
Request for Comments: 9000

QUIC

Abstract

Fixture.

1.  Introduction

QUIC transport text.
""",
        encoding="utf-8",
    )

    corpus = load_corpus(source, CorpusLoadConfig(loader="auto"))

    assert corpus.doc_ids == {"rfc9000"}
    assert corpus.section_records[0]["doc_kind"] == "rfc"
    assert corpus.section_records[0]["section_id"] == "1"


def test_llamaindex_loader_normalizes_documents(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "docs"
    source.mkdir()
    doc_path = source / "guide.md"
    doc_path.write_text("# Guide\n\nQUIC docs", encoding="utf-8")

    class FakeDocument:
        id_ = str(doc_path)
        text = "QUIC docs loaded by LlamaIndex."
        metadata = {"file_path": str(doc_path), "file_name": "guide.md"}

    class FakeSimpleDirectoryReader:
        def __init__(self, *, input_files, filename_as_id):
            assert input_files == [str(doc_path)]
            assert filename_as_id is True

        def load_data(self):
            return [FakeDocument()]

    core_module = types.ModuleType("llama_index.core")
    core_module.SimpleDirectoryReader = FakeSimpleDirectoryReader
    package_module = types.ModuleType("llama_index")
    monkeypatch.setitem(sys.modules, "llama_index", package_module)
    monkeypatch.setitem(sys.modules, "llama_index.core", core_module)

    corpus = load_corpus(source, CorpusLoadConfig(loader="llamaindex"))

    assert len(corpus.section_records) == 1
    record = corpus.section_records[0]
    assert record["doc_kind"] == "document"
    assert record["loader"] == "llamaindex"
    assert record["source_path"] == str(doc_path)
    assert record["title"] == "guide.md"


def test_cocoindex_loader_normalizes_code_chunks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    code_path = source / "main.cpp"
    code_path.write_text("void f() {}\nvoid g() {}\n", encoding="utf-8")

    class FakeRecursiveSplitter:
        def split(self, text, *, language, chunk_size, chunk_overlap):
            assert language == "cpp"
            assert chunk_size == 1200
            assert chunk_overlap == 160
            return ["void f() {}", "void g() {}"]

    text_module = types.ModuleType("cocoindex.ops.text")
    text_module.detect_code_language = lambda filename: "cpp"
    text_module.RecursiveSplitter = FakeRecursiveSplitter
    ops_module = types.ModuleType("cocoindex.ops")
    package_module = types.ModuleType("cocoindex")
    monkeypatch.setitem(sys.modules, "cocoindex", package_module)
    monkeypatch.setitem(sys.modules, "cocoindex.ops", ops_module)
    monkeypatch.setitem(sys.modules, "cocoindex.ops.text", text_module)

    corpus = load_corpus(source, CorpusLoadConfig(loader="cocoindex"))

    assert len(corpus.section_records) == 2
    record = corpus.section_records[0]
    assert record["doc_kind"] == "source_code"
    assert record["loader"] == "cocoindex"
    assert record["source_path"] == "main.cpp"
    assert record["metadata_language"] == "cpp"


def test_cocoindex_loader_runs_with_default_dependency(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.cpp").write_text("void f() {}\n", encoding="utf-8")

    corpus = load_corpus(source, CorpusLoadConfig(loader="cocoindex"))

    assert corpus.section_records
    assert corpus.section_records[0]["loader"] == "cocoindex"
