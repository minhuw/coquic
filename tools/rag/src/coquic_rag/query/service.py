from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import EmbeddingProvider, SentenceTransformerEmbedder
from coquic_rag.store.artifacts import (
    read_graph_edges,
    read_graph_nodes,
    read_section_records,
)
from coquic_rag.store.qdrant_store import QdrantSectionStore, SectionSearchHit

_SECTION_ARTIFACT = "sections.jsonl"
_GRAPH_NODES_ARTIFACT = "graph_nodes.jsonl"
_GRAPH_EDGES_ARTIFACT = "graph_edges.jsonl"


class IndexNotBuiltError(RuntimeError):
    pass


@dataclass(frozen=True)
class IndexStatus:
    source_ok: bool
    artifacts_ok: bool
    qdrant_ok: bool
    qdrant_status: str
    qdrant_backend: str
    section_count: int | None
    indexed_count: int | None

    @property
    def ready(self) -> bool:
        return self.source_ok and self.artifacts_ok and self.qdrant_ok

    def lines(self) -> list[str]:
        lines = [
            f"source_docs: {'ok' if self.source_ok else 'missing'}",
            f"artifacts: {'ok' if self.artifacts_ok else 'missing'}",
            f"qdrant_backend: {self.qdrant_backend}",
            f"qdrant: {self.qdrant_status}",
        ]
        if self.section_count is not None and self.indexed_count is not None:
            lines.append(f"indexed_sections: {self.indexed_count}/{self.section_count}")
        lines.append(f"ready: {'yes' if self.ready else 'no'}")
        return lines

    def failure_message(self, paths: ProjectPaths) -> str:
        command = (
            "uv run --project tools/rag python -m coquic_rag.cli.main "
            f"build-index --source {paths.rfc_source} --state-dir {paths.state_dir}"
        )
        return "\n".join(
            [
                f"QUIC index is not ready under {paths.state_dir}",
                *self.lines(),
                f"rebuild with: {command}",
            ]
        )


def _normalize_term_name(term: str) -> str:
    return term.strip().lower().replace(" ", "_")


def _section_citation(record: dict[str, object]) -> str:
    return f"RFC {record['rfc']} Section {record['section_id']}"


def _required_artifact_paths(paths: ProjectPaths) -> tuple[Path, Path, Path]:
    return (
        paths.artifacts_dir / _SECTION_ARTIFACT,
        paths.artifacts_dir / _GRAPH_NODES_ARTIFACT,
        paths.artifacts_dir / _GRAPH_EDGES_ARTIFACT,
    )


def _configured_qdrant_url(paths: ProjectPaths) -> str | None:
    return paths.qdrant_url or os.getenv("COQUIC_QDRANT_URL")


def get_index_status(
    paths: ProjectPaths | None = None,
    *,
    collection_name: str = "quic_sections",
) -> IndexStatus:
    resolved_paths = paths or ProjectPaths.default()
    qdrant_url = _configured_qdrant_url(resolved_paths)
    qdrant_backend = "remote" if qdrant_url else "local"
    source_ok = resolved_paths.rfc_source.is_dir() and bool(
        sorted(path for path in resolved_paths.rfc_source.glob("*.txt") if path.is_file())
    )

    required_paths = _required_artifact_paths(resolved_paths)
    artifacts_ok = all(path.is_file() for path in required_paths)
    section_count: int | None = None
    if artifacts_ok:
        section_count = len(read_section_records(required_paths[0]))

    store = QdrantSectionStore(
        state_dir=resolved_paths.qdrant_dir,
        qdrant_url=qdrant_url,
        collection_name=collection_name,
    )
    try:
        indexed_count = store.section_count()
    except Exception:
        if qdrant_backend != "remote":
            raise
        return IndexStatus(
            source_ok=source_ok,
            artifacts_ok=artifacts_ok,
            qdrant_ok=False,
            qdrant_status="unreachable",
            qdrant_backend=qdrant_backend,
            section_count=section_count,
            indexed_count=None,
        )

    if indexed_count is None:
        qdrant_status = "missing"
        qdrant_ok = False
    elif section_count is not None and indexed_count != section_count:
        qdrant_status = "stale"
        qdrant_ok = False
    else:
        qdrant_status = "ok"
        qdrant_ok = True

    return IndexStatus(
        source_ok=source_ok,
        artifacts_ok=artifacts_ok,
        qdrant_ok=qdrant_ok,
        qdrant_status=qdrant_status,
        qdrant_backend=qdrant_backend,
        section_count=section_count,
        indexed_count=indexed_count,
    )


def require_index_ready(
    paths: ProjectPaths | None = None,
    *,
    collection_name: str = "quic_sections",
) -> IndexStatus:
    resolved_paths = paths or ProjectPaths.default()
    status = get_index_status(resolved_paths, collection_name=collection_name)
    if not status.ready:
        raise IndexNotBuiltError(status.failure_message(resolved_paths))
    return status


class QueryService:
    def __init__(
        self,
        paths: ProjectPaths | None = None,
        *,
        embedder: EmbeddingProvider | None = None,
        collection_name: str = "quic_sections",
    ) -> None:
        self._paths = paths or ProjectPaths.default()
        qdrant_url = _configured_qdrant_url(self._paths)
        self._embedder = embedder or SentenceTransformerEmbedder(paths=self._paths)
        self._store = QdrantSectionStore(
            state_dir=self._paths.qdrant_dir,
            qdrant_url=qdrant_url,
            collection_name=collection_name,
        )
        self._loaded = False
        self._sections_by_key: dict[tuple[int, str], dict[str, object]] = {}
        self._sections_by_node_id: dict[str, dict[str, object]] = {}
        self._nodes_by_id: dict[str, dict[str, object]] = {}
        self._edges_from: dict[str, list[dict[str, object]]] = defaultdict(list)
        self._edges_to: dict[str, list[dict[str, object]]] = defaultdict(list)

    def get_section(self, rfc: int, section_id: str) -> dict[str, object]:
        self._ensure_loaded()
        key = (rfc, str(section_id))
        record = self._sections_by_key.get(key)
        if record is None:
            return {"found": False, "rfc": rfc, "section_id": str(section_id)}
        return self._section_result(record)

    def lookup_term(self, term_type: str, name: str) -> dict[str, object]:
        self._ensure_loaded()
        term_id = f"term:{term_type}:{_normalize_term_name(name)}"
        node = self._nodes_by_id.get(term_id)
        if node is None:
            return {
                "found": False,
                "term_type": term_type,
                "term": _normalize_term_name(name),
            }
        return self._trace_term_node(node)

    def trace_term(self, term: str, rfc: int | None = None) -> dict[str, object]:
        self._ensure_loaded()
        normalized_term = _normalize_term_name(term)
        matches = [
            node
            for node in self._nodes_by_id.values()
            if node.get("node_type") == "term" and node.get("name") == normalized_term
        ]
        if not matches:
            return {
                "found": False,
                "term": normalized_term,
                "definitions": [],
                "mentions": [],
                "fallback_results": self.search_sections(
                    normalized_term,
                    rfc=rfc,
                    top_k=5,
                ),
            }
        return self._trace_term_node(matches[0], rfc=rfc)

    def related_sections(
        self,
        rfc: int,
        section_id: str,
        edge_types: tuple[str, ...] = ("cites", "mentions", "defines"),
        top_k: int = 5,
    ) -> list[dict[str, object]]:
        self._ensure_loaded()
        source = self._sections_by_key.get((rfc, str(section_id)))
        if source is None:
            return []

        source_node_id = str(source["node_id"])
        related: dict[str, dict[str, object]] = {}
        source_edges = self._edges_from.get(source_node_id, [])

        for edge in source_edges:
            edge_type = str(edge["edge_type"])
            if edge_type not in edge_types:
                continue
            target = str(edge["target"])
            if edge_type == "cites" and target in self._sections_by_node_id:
                related[target] = self._section_result(
                    self._sections_by_node_id[target],
                    relation=edge_type,
                )
            elif edge_type in {"mentions", "defines"}:
                for reverse_edge in self._edges_to.get(target, []):
                    if reverse_edge["source"] == source_node_id:
                        continue
                    other_section = self._sections_by_node_id.get(str(reverse_edge["source"]))
                    if other_section is None:
                        continue
                    related[str(other_section["node_id"])] = self._section_result(
                        other_section,
                        relation=f"shared_{edge_type}",
                    )

        if related:
            return list(related.values())

        query_text = f"{source['title']}\n\n{source['text']}"
        hits = self._store.search_sections(
            query_text,
            self._embedder,
            limit=top_k + 1,
            payload_filters={"rfc": rfc},
        )
        results = []
        for hit in hits:
            if hit.node_id == source_node_id:
                continue
            results.append(self._search_hit_result(hit, relation="semantic"))
            if len(results) >= top_k:
                break
        return results

    def search_sections(
        self,
        query: str,
        *,
        rfc: int | None = None,
        category: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, object]]:
        self._ensure_loaded()
        payload_filters: dict[str, object] = {}
        if rfc is not None:
            payload_filters["rfc"] = rfc
        if category is not None:
            payload_filters["section_kind"] = category

        hits = self._store.search_sections(
            query,
            self._embedder,
            limit=top_k,
            payload_filters=payload_filters or None,
        )
        return [self._search_hit_result(hit, relation="semantic") for hit in hits]

    def render_section_resource(self, rfc: int, section_id: str) -> str:
        section = self.get_section(rfc, section_id)
        if not section.get("found"):
            raise LookupError(f"RFC {rfc} Section {section_id} not found")
        return (
            f"{section['citation']}: {section['title']}\n\n"
            f"{section['text']}"
        )

    def _trace_term_node(
        self,
        node: dict[str, object],
        rfc: int | None = None,
    ) -> dict[str, object]:
        term_id = str(node["id"])
        definitions = []
        mentions = []
        for edge in self._edges_to.get(term_id, []):
            edge_type = str(edge["edge_type"])
            source = self._sections_by_node_id.get(str(edge["source"]))
            if source is None:
                continue
            if rfc is not None and int(source["rfc"]) != rfc:
                continue
            rendered = self._section_result(source, relation=edge_type)
            if edge_type == "defines":
                definitions.append(rendered)
            elif edge_type == "mentions":
                mentions.append(rendered)

        return {
            "found": True,
            "term": str(node["name"]),
            "term_id": term_id,
            "term_class": str(node["term_class"]),
            "definitions": definitions,
            "mentions": mentions,
        }

    def _search_hit_result(
        self,
        hit: SectionSearchHit,
        *,
        relation: str,
    ) -> dict[str, object]:
        record = self._sections_by_node_id.get(hit.node_id)
        if record is None:
            payload = hit.payload
            record = {
                "node_id": hit.node_id,
                "rfc": payload["rfc"],
                "section_id": payload["section_id"],
                "title": payload["title"],
                "text": payload["text"],
            }
        return self._section_result(record, score=hit.score, relation=relation)

    def _section_result(
        self,
        record: dict[str, object],
        *,
        score: float | None = None,
        relation: str | None = None,
    ) -> dict[str, object]:
        citation = _section_citation(record)
        citations = [citation]
        for edge in self._edges_from.get(str(record["node_id"]), []):
            if edge["edge_type"] != "cites":
                continue
            target = self._sections_by_node_id.get(str(edge["target"]))
            if target is None:
                continue
            target_citation = _section_citation(target)
            if target_citation not in citations:
                citations.append(target_citation)

        result = {
            "found": True,
            "node_id": str(record["node_id"]),
            "rfc": int(record["rfc"]),
            "section_id": str(record["section_id"]),
            "title": str(record["title"]),
            "text": str(record["text"]),
            "citation": citation,
            "citations": citations,
        }
        if score is not None:
            result["score"] = score
        if relation is not None:
            result["relation"] = relation
        return result

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        require_index_ready(self._paths, collection_name=self._store.collection_name)

        sections_path, nodes_path, edges_path = _required_artifact_paths(self._paths)

        sections = read_section_records(sections_path)
        nodes = read_graph_nodes(nodes_path)
        edges = read_graph_edges(edges_path)

        self._sections_by_key = {
            (int(record["rfc"]), str(record["section_id"])): record for record in sections
        }
        self._sections_by_node_id = {
            str(record["node_id"]): record for record in sections
        }
        self._nodes_by_id = {str(node["id"]): node for node in nodes}
        self._edges_from = defaultdict(list)
        self._edges_to = defaultdict(list)
        for edge in edges:
            self._edges_from[str(edge["source"])].append(edge)
            self._edges_to[str(edge["target"])].append(edge)
        self._loaded = True
