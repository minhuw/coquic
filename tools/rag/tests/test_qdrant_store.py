from __future__ import annotations

from pathlib import Path

from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.store.qdrant_store import QdrantSectionStore


def test_qdrant_store_upserts_sections_and_filters_search_results(
    tmp_path: Path,
) -> None:
    store = QdrantSectionStore(
        state_dir=tmp_path / "qdrant",
        collection_name="quic_sections",
    )
    embedder = FakeEmbedder()
    section_records = [
        {
            "node_id": "rfc9000#1",
            "rfc": 9000,
            "section_id": "1",
            "title": "Overview",
            "text": "QUIC transport overview and connection setup.",
        },
        {
            "node_id": "rfc9000#18.2",
            "rfc": 9000,
            "section_id": "18.2",
            "title": "Transport Parameter Definitions",
            "text": "Transport parameters define payload limits and endpoint behavior.",
        },
        {
            "node_id": "rfc9000#A.1",
            "rfc": 9000,
            "section_id": "A.1",
            "title": "Sample Appendix",
            "text": "This appendix walks through a worked example.",
        },
        {
            "node_id": "rfc9369#5",
            "rfc": 9369,
            "section_id": "5",
            "title": "Compatible Version Negotiation",
            "text": "Version negotiation keeps the transport extensible.",
        },
    ]

    assert not store.collection_exists()

    store.upsert_sections(section_records, embedder)

    assert store.collection_exists()

    hits = store.search_sections(
        "transport parameter payload limits",
        embedder,
        limit=3,
        payload_filters={"rfc": 9000, "section_kind": "numbered"},
    )

    assert len(hits) == 2
    assert hits[0].payload["node_id"] == "rfc9000#18.2"
    assert hits[0].payload["title"] == "Transport Parameter Definitions"
    assert hits[0].payload["rfc"] == 9000
    assert hits[0].payload["section_kind"] == "numbered"
    assert hits[0].text == section_records[1]["text"]
