from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coquic_rag.cli.main import main as cli_main
from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.query.service import IndexNotBuiltError, QueryService


_DRAFT_FIXTURE_TEXT = """Network Working Group
Internet-Draft
Intended status: Informational
Expires: 4 April 2027

draft-ietf-quic-qlog-main-schema-13

qlog: Structured Logging for Network Protocols

Abstract

This is a minimal draft fixture for query tests.

1.  Introduction

This section describes structured logging for network protocol analysis.
"""


def _copy_query_fixtures(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("rfc9000.txt", "rfc9369.txt"):
        shutil.copyfile(Path("docs/rfc") / filename, source_dir / filename)
    (source_dir / "draft-ietf-quic-qlog-main-schema-13.txt").write_text(
        _DRAFT_FIXTURE_TEXT,
        encoding="utf-8",
    )


def _build_service(tmp_path: Path) -> QueryService:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)

    exit_code = cli_main(
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

    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )
    return QueryService(paths=paths, embedder=FakeEmbedder())


def test_query_service_get_section_returns_exact_match(tmp_path: Path) -> None:
    service = _build_service(tmp_path)

    section = service.get_section("rfc9000", "18.2")

    assert section["found"] is True
    assert section["doc_id"] == "rfc9000"
    assert section["doc_kind"] == "rfc"
    assert section["rfc_number"] == 9000
    assert section["draft_name"] is None
    assert section["citation"] == "RFC 9000 Section 18.2"
    assert section["title"] == "Transport Parameter Definitions"


def test_query_service_get_section_accepts_legacy_rfc_number(tmp_path: Path) -> None:
    service = _build_service(tmp_path)

    section = service.get_section(9000, "18.2")

    assert section["found"] is True
    assert section["doc_id"] == "rfc9000"
    assert section["citation"] == "RFC 9000 Section 18.2"


def test_query_service_get_section_returns_draft_section(tmp_path: Path) -> None:
    service = _build_service(tmp_path)

    section = service.get_section("draft-ietf-quic-qlog-main-schema-13", "1")

    assert section["found"] is True
    assert section["doc_id"] == "draft-ietf-quic-qlog-main-schema-13"
    assert section["doc_kind"] == "internet-draft"
    assert section["rfc_number"] is None
    assert section["draft_name"] == "draft-ietf-quic-qlog-main-schema-13"
    assert section["citation"] == "draft-ietf-quic-qlog-main-schema-13 Section 1"
    assert section["title"] == "Introduction"


def test_query_service_render_section_resource_accepts_legacy_rfc_number(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    rendered = service.render_section_resource(9000, "18.2")

    assert rendered.startswith("RFC 9000 Section 18.2: ")


def test_query_service_trace_term_returns_definitions_and_mentions(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    trace = service.trace_term("max_udp_payload_size")

    assert trace["term"] == "max_udp_payload_size"
    assert trace["definitions"][0]["citation"] == "RFC 9000 Section 18.2"
    assert any(
        item["citation"] == "RFC 9000 Section 7.4.1"
        for item in trace["mentions"]
    )


def test_query_service_trace_term_accepts_legacy_rfc_filter(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    trace = service.trace_term("max_udp_payload_size", rfc=9000)

    assert trace["definitions"]
    assert all(item["doc_id"] == "rfc9000" for item in trace["definitions"])


def test_query_service_related_sections_finds_semantic_neighbors(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    related_sections = service.related_sections("rfc9369", "5")

    assert related_sections
    assert any(
        section["section_id"] in {"4", "4.1"} for section in related_sections
    )


def test_query_service_related_sections_accepts_legacy_rfc_number(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    related_sections = service.related_sections(9369, "5")

    assert related_sections


def test_query_service_search_sections_returns_cited_ack_hits(tmp_path: Path) -> None:
    service = _build_service(tmp_path)

    results = service.search_sections("ACK frame behavior", top_k=3)

    assert results
    assert results[0]["doc_id"] == "rfc9000"
    assert results[0]["citations"]


def test_query_service_search_sections_accepts_legacy_rfc_filter(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    results = service.search_sections(
        "ACK frame behavior",
        rfc=9000,
        top_k=3,
    )

    assert results
    assert all(result["doc_id"] == "rfc9000" for result in results)


def test_query_service_search_sections_returns_mixed_corpus_hits(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    results = service.search_sections("structured logging network protocol", top_k=5)

    assert any(
        result["doc_id"] == "draft-ietf-quic-qlog-main-schema-13"
        for result in results
    )


def test_query_service_reports_missing_index(tmp_path: Path) -> None:
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=tmp_path / "source",
        state_dir=tmp_path / ".rag",
        model_cache_dir=tmp_path / ".rag" / "cache" / "models",
    )
    service = QueryService(paths=paths, embedder=FakeEmbedder())

    with pytest.raises(IndexNotBuiltError):
        service.search_sections("ACK frame behavior")
