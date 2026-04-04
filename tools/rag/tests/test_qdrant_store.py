from __future__ import annotations

from pathlib import Path
from typing import Any

from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.store.qdrant_store import QdrantSectionStore
from coquic_rag.store.qdrant_store import _point_id


def test_qdrant_store_prefers_configured_url_over_local_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeQdrantClient:
        def __init__(self, **kwargs: Any) -> None:
            calls.append(kwargs)

        def collection_exists(self, _collection_name: str) -> bool:
            return False

    monkeypatch.setattr(
        "coquic_rag.store.qdrant_store.QdrantClient",
        _FakeQdrantClient,
    )

    store = QdrantSectionStore(
        state_dir=tmp_path / "qdrant",
        qdrant_url="http://127.0.0.1:6333",
        collection_name="quic_sections",
    )

    assert not store.collection_exists()
    assert calls[0]["url"] == "http://127.0.0.1:6333"
    assert "path" not in calls[0]


def test_qdrant_store_sets_longer_timeout_for_remote_backend(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeQdrantClient:
        def __init__(self, **kwargs: Any) -> None:
            calls.append(kwargs)

        def collection_exists(self, _collection_name: str) -> bool:
            return False

    monkeypatch.setattr(
        "coquic_rag.store.qdrant_store.QdrantClient",
        _FakeQdrantClient,
    )

    store = QdrantSectionStore(
        state_dir=tmp_path / "qdrant",
        qdrant_url="http://127.0.0.1:6333",
        collection_name="quic_sections",
    )

    assert not store.collection_exists()
    assert calls == [{"url": "http://127.0.0.1:6333", "timeout": 30}]


def test_point_id_is_stringified_for_qdrant_client_compatibility() -> None:
    assert isinstance(_point_id("rfc9000#1"), str)


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
            "doc_id": "rfc9000",
            "doc_kind": "rfc",
            "rfc_number": 9000,
            "draft_name": None,
            "section_id": "1",
            "title": "Overview",
            "text": "QUIC transport overview and connection setup.",
        },
        {
            "node_id": "draft-ietf-quic-qlog-main-schema-13#1",
            "doc_id": "draft-ietf-quic-qlog-main-schema-13",
            "doc_kind": "internet-draft",
            "rfc_number": None,
            "draft_name": "draft-ietf-quic-qlog-main-schema-13",
            "section_id": "1",
            "title": "Introduction",
            "text": "Qlog defines structured logging for network protocol events.",
        },
    ]

    assert not store.collection_exists()

    store.upsert_sections(section_records, embedder)

    assert store.collection_exists()

    hits = store.search_sections(
        "structured logging network protocol",
        embedder,
        limit=3,
        payload_filters={"doc_id": "draft-ietf-quic-qlog-main-schema-13"},
    )

    assert len(hits) == 1
    assert hits[0].payload["node_id"] == "draft-ietf-quic-qlog-main-schema-13#1"
    assert hits[0].payload["title"] == "Introduction"
    assert hits[0].payload["doc_id"] == "draft-ietf-quic-qlog-main-schema-13"
    assert hits[0].payload["doc_kind"] == "internet-draft"
    assert hits[0].payload["draft_name"] == "draft-ietf-quic-qlog-main-schema-13"
    assert hits[0].payload["section_kind"] == "numbered"
    assert "rfc" not in hits[0].payload
    assert hits[0].text == section_records[1]["text"]

    rfc_hits = store.search_sections(
        "transport overview connection",
        embedder,
        limit=3,
        payload_filters={"doc_id": "rfc9000"},
    )
    assert len(rfc_hits) == 1
    assert rfc_hits[0].payload["node_id"] == "rfc9000#1"
    assert rfc_hits[0].payload["doc_id"] == "rfc9000"
    assert rfc_hits[0].payload["doc_kind"] == "rfc"
    assert rfc_hits[0].payload["rfc_number"] == 9000
    assert rfc_hits[0].payload["rfc"] == 9000
