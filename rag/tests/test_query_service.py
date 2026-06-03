from __future__ import annotations

from pathlib import Path

import pytest

from coquic_rag.cli.main import main as cli_main
from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.query.service import QueryService
from coquic_rag.store.qdrant_store import QdrantSectionStore, SectionSearchHit
from fixtures import write_query_fixtures


def _build_service(tmp_path: Path) -> QueryService:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    write_query_fixtures(source_dir)

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


def test_query_service_get_section_legacy_rfc_miss_keeps_rfc_field(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    section = service.get_section(9000, "999")

    assert section["found"] is False
    assert section["rfc"] == 9000
    assert section["section_id"] == "999"


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


def test_query_service_render_section_resource_legacy_rfc_miss_message(
    tmp_path: Path,
) -> None:
    service = _build_service(tmp_path)

    with pytest.raises(LookupError, match="RFC 9000 Section 999 not found"):
        service.render_section_resource(9000, "999")


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


def test_query_service_semantic_search_can_use_qdrant_payloads_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=None,
        state_dir=tmp_path / ".rag",
        qdrant_url="https://example.qdrant.cloud",
    )

    def _search_sections(
        self: QdrantSectionStore,
        query_text: str,
        embedder: FakeEmbedder,
        *,
        limit: int = 5,
        payload_filters: dict[str, object] | None = None,
    ) -> list[SectionSearchHit]:
        assert query_text == "ACK frame behavior"
        assert limit == 3
        assert payload_filters is None
        return [
            SectionSearchHit(
                node_id="rfc9000#19.3",
                score=0.91,
                payload={
                    "node_id": "rfc9000#19.3",
                    "doc_id": "rfc9000",
                    "doc_kind": "rfc",
                    "rfc_number": 9000,
                    "section_id": "19.3",
                    "title": "ACK Frames",
                    "text": "ACK frames contain acknowledgment ranges.",
                },
                text="ACK frames contain acknowledgment ranges.",
            )
        ]

    monkeypatch.setattr(QdrantSectionStore, "search_sections", _search_sections)

    service = QueryService(
        paths=paths,
        embedder=FakeEmbedder(),
        require_artifacts_for_search=False,
    )

    results = service.search_sections("ACK frame behavior", top_k=3)

    assert results == [
        {
            "found": True,
            "node_id": "rfc9000#19.3",
            "doc_id": "rfc9000",
            "doc_kind": "rfc",
            "rfc_number": 9000,
            "draft_name": None,
            "section_id": "19.3",
            "title": "ACK Frames",
            "text": "ACK frames contain acknowledgment ranges.",
            "citation": "RFC 9000 Section 19.3",
            "citations": ["RFC 9000 Section 19.3"],
            "score": 0.91,
            "relation": "semantic",
            "rfc": 9000,
        }
    ]


def test_query_service_get_section_can_use_qdrant_payloads_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=None,
        state_dir=tmp_path / ".rag",
        qdrant_url="https://example.qdrant.cloud",
    )

    def _get_section(
        self: QdrantSectionStore,
        doc_id: str,
        section_id: str,
    ) -> SectionSearchHit | None:
        assert doc_id == "rfc9000"
        assert section_id == "19.3"
        return SectionSearchHit(
            node_id="rfc9000#19.3",
            score=1.0,
            payload={
                "node_id": "rfc9000#19.3",
                "doc_id": "rfc9000",
                "doc_kind": "rfc",
                "rfc_number": 9000,
                "section_id": "19.3",
                "title": "ACK Frames",
                "text": "ACK frames contain acknowledgment ranges.",
            },
            text="ACK frames contain acknowledgment ranges.",
        )

    monkeypatch.setattr(QdrantSectionStore, "get_section", _get_section)

    service = QueryService(paths=paths, embedder=FakeEmbedder())

    section = service.get_section("rfc9000", "19.3")

    assert section["found"] is True
    assert section["citation"] == "RFC 9000 Section 19.3"


def test_query_service_search_returns_empty_when_collection_is_missing(
    tmp_path: Path,
) -> None:
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=None,
        state_dir=tmp_path / ".rag",
    )
    service = QueryService(paths=paths, embedder=FakeEmbedder())

    assert service.search_sections("ACK frame behavior") == []
