from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

from coquic_rag.embed.provider import EmbeddingProvider


def _section_kind(section_id: str) -> str:
    return "appendix" if section_id[:1].isalpha() else "numbered"


def _point_id(node_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, node_id)


def _embed_input(section_record: dict[str, object]) -> str:
    title = str(section_record.get("title", "")).strip()
    text = str(section_record.get("text", "")).strip()
    return f"{title}\n\n{text}".strip()


def _payload_filter(payload_filters: dict[str, object] | None) -> Filter | None:
    if not payload_filters:
        return None
    must = [
        FieldCondition(key=key, match=MatchValue(value=value))
        for key, value in payload_filters.items()
    ]
    return Filter(must=must)


@dataclass(frozen=True)
class SectionSearchHit:
    node_id: str
    score: float
    payload: dict[str, Any]
    text: str


class QdrantSectionStore:
    def __init__(
        self,
        state_dir: Path,
        collection_name: str = "quic_sections",
    ) -> None:
        self._state_dir = Path(state_dir)
        self._collection_name = collection_name
        self._client: QdrantClient | None = None

    @property
    def collection_name(self) -> str:
        return self._collection_name

    def collection_exists(self) -> bool:
        return self._client_or_create().collection_exists(self._collection_name)

    def reset_collection(self) -> None:
        client = self._client_or_create()
        if client.collection_exists(self._collection_name):
            client.delete_collection(self._collection_name)

    def section_count(self) -> int | None:
        client = self._client_or_create()
        if not client.collection_exists(self._collection_name):
            return None
        return int(client.count(self._collection_name, exact=True).count)

    def upsert_sections(
        self,
        section_records: list[dict[str, object]],
        embedder: EmbeddingProvider,
        *,
        batch_size: int = 32,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        if not section_records:
            return
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")

        client = self._client_or_create()
        total = len(section_records)
        if progress is not None:
            progress(0, total)

        processed = 0
        for start in range(0, total, batch_size):
            batch_records = section_records[start : start + batch_size]
            embeddings = embedder.embed(
                [_embed_input(record) for record in batch_records]
            )
            if not embeddings:
                continue

            if not client.collection_exists(self._collection_name):
                client.create_collection(
                    self._collection_name,
                    vectors_config=VectorParams(
                        size=len(embeddings[0]),
                        distance=Distance.COSINE,
                    ),
                    on_disk_payload=True,
                )

            points = [
                PointStruct(
                    id=_point_id(str(record["node_id"])),
                    vector=embedding,
                    payload={
                        "node_id": str(record["node_id"]),
                        "rfc": int(record["rfc"]),
                        "section_id": str(record["section_id"]),
                        "section_kind": _section_kind(str(record["section_id"])),
                        "title": str(record["title"]),
                        "text": str(record["text"]),
                    },
                )
                for record, embedding in zip(batch_records, embeddings, strict=True)
            ]
            client.upsert(self._collection_name, points=points, wait=True)
            processed += len(batch_records)
            if progress is not None:
                progress(processed, total)

    def search_sections(
        self,
        query_text: str,
        embedder: EmbeddingProvider,
        *,
        limit: int = 5,
        payload_filters: dict[str, object] | None = None,
    ) -> list[SectionSearchHit]:
        client = self._client_or_create()
        if not client.collection_exists(self._collection_name):
            return []

        query_vector = embedder.embed([query_text])[0]
        response = client.query_points(
            self._collection_name,
            query=query_vector,
            query_filter=_payload_filter(payload_filters),
            limit=limit,
            with_payload=True,
        )
        hits = []
        for point in response.points:
            payload = dict(point.payload or {})
            hits.append(
                SectionSearchHit(
                    node_id=str(payload.get("node_id", point.id)),
                    score=float(point.score),
                    payload=payload,
                    text=str(payload.get("text", "")),
                )
            )
        return hits

    def _client_or_create(self) -> QdrantClient:
        if self._client is None:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            self._client = QdrantClient(path=str(self._state_dir))
        return self._client
