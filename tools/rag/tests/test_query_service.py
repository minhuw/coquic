from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from coquic_rag.cli.main import main as cli_main
from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.query.service import IndexNotBuiltError, QueryService


def _copy_query_fixtures(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("rfc9000.txt", "rfc9369.txt"):
        shutil.copyfile(Path("docs/rfc") / filename, source_dir / filename)


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

    section = service.get_section(9000, "18.2")

    assert section["found"] is True
    assert section["citation"] == "RFC 9000 Section 18.2"
    assert section["title"] == "Transport Parameter Definitions"


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


def test_query_service_related_sections_finds_semantic_neighbors(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    related_sections = service.related_sections(9369, "5")

    assert related_sections
    assert any(
        section["section_id"] in {"4", "4.1"} for section in related_sections
    )


def test_query_service_search_sections_returns_cited_ack_hits(tmp_path: Path) -> None:
    service = _build_service(tmp_path)

    results = service.search_sections("ACK frame behavior", top_k=3)

    assert results
    assert results[0]["rfc"] == 9000
    assert results[0]["citations"]


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
