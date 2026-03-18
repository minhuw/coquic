from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import (
    DEFAULT_EMBEDDING_MODEL,
    FakeEmbedder,
    SentenceTransformerEmbedder,
)
from coquic_rag.graph.extractor import build_graph_artifacts
from coquic_rag.ingest.rfc_parser import parse_rfc_document
from coquic_rag.query.service import IndexNotBuiltError, QueryService, get_index_status
from coquic_rag.store.artifacts import (
    write_graph_edges,
    write_graph_nodes,
    write_section_records,
)
from coquic_rag.store.qdrant_store import QdrantSectionStore

_SECTION_ARTIFACT = "sections.jsonl"
_GRAPH_NODES_ARTIFACT = "graph_nodes.jsonl"
_GRAPH_EDGES_ARTIFACT = "graph_edges.jsonl"


class _ProgressBar:
    def __init__(self, label: str, total: int) -> None:
        self._label = label
        self._total = max(total, 1)
        self._stream = sys.stdout
        self._is_tty = self._stream.isatty()

    def update(self, current: int, detail: str | None = None) -> None:
        clamped = min(max(current, 0), self._total)
        filled = int((clamped / self._total) * 20)
        bar = "#" * filled + "-" * (20 - filled)
        percent = int((clamped / self._total) * 100)
        line = f"{self._label:<14} [{bar}] {clamped}/{self._total} {percent:>3}%"
        if detail:
            line = f"{line} {detail}"
        if self._is_tty:
            print(f"\r{line}", end="", file=self._stream, flush=True)
            if clamped == self._total:
                print(file=self._stream, flush=True)
            return
        print(line, file=self._stream, flush=True)


def _runtime_paths(source: Path, state_dir: Path) -> ProjectPaths:
    return ProjectPaths(
        repo_root=Path.cwd(),
        rfc_source=source,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
        qdrant_url=os.getenv("COQUIC_QDRANT_URL"),
    )


def _iter_rfc_paths(source: Path) -> list[Path]:
    return sorted(path for path in source.glob("*.txt") if path.is_file())


def _build_embedder(name: str, paths: ProjectPaths, model_name: str):
    if name == "fake":
        return FakeEmbedder()
    return SentenceTransformerEmbedder(paths=paths, model_name=model_name)


def _build_index(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    rfc_paths = _iter_rfc_paths(paths.rfc_source)
    if not paths.rfc_source.is_dir() or not rfc_paths:
        print(f"no RFC sources found under {paths.rfc_source}")
        return 1

    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []

    parse_progress = _ProgressBar("parse RFCs", len(rfc_paths))
    parse_progress.update(0)
    for index, path in enumerate(rfc_paths, start=1):
        document = parse_rfc_document(path)
        doc_section_records, doc_graph_nodes, doc_graph_edges = build_graph_artifacts(
            document
        )
        section_records.extend(doc_section_records)
        graph_nodes.extend(doc_graph_nodes)
        graph_edges.extend(doc_graph_edges)
        parse_progress.update(index, path.name)

    write_section_records(paths.artifacts_dir / _SECTION_ARTIFACT, section_records)
    write_graph_nodes(paths.artifacts_dir / _GRAPH_NODES_ARTIFACT, graph_nodes)
    write_graph_edges(paths.artifacts_dir / _GRAPH_EDGES_ARTIFACT, graph_edges)

    store = QdrantSectionStore(
        state_dir=paths.qdrant_dir,
        qdrant_url=paths.qdrant_url,
        collection_name=args.collection_name,
    )
    store.reset_collection()
    embed_progress = _ProgressBar("embed sections", len(section_records))
    store.upsert_sections(
        section_records,
        _build_embedder(args.embedder, paths, args.model_name),
        progress=lambda current, total: embed_progress.update(current),
    )

    print(
        f"indexed {len(rfc_paths)} RFC{'s' if len(rfc_paths) != 1 else ''} "
        f"with {len(section_records)} sections"
    )
    return 0


def _doctor(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    status = get_index_status(paths, collection_name=args.collection_name)
    for line in status.lines():
        print(line)
    return 0 if status.ready else 1


def _query_service(args: argparse.Namespace) -> QueryService:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    return QueryService(
        paths=paths,
        embedder=_build_embedder(args.embedder, paths, args.model_name),
        collection_name=args.collection_name,
    )


def _write_json(payload: object) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    print()


def _search_sections(args: argparse.Namespace) -> int:
    _write_json(
        {
            "results": _query_service(args).search_sections(
                args.query,
                rfc=args.rfc,
                category=args.category,
                top_k=args.top_k,
            )
        }
    )
    return 0


def _get_section(args: argparse.Namespace) -> int:
    _write_json(_query_service(args).get_section(args.rfc, args.section_id))
    return 0


def _trace_term(args: argparse.Namespace) -> int:
    _write_json(_query_service(args).trace_term(args.term, rfc=args.rfc))
    return 0


def _related_sections(args: argparse.Namespace) -> int:
    _write_json(
        {
            "sections": _query_service(args).related_sections(
                args.rfc,
                args.section_id,
                edge_types=tuple(args.edge_type) if args.edge_type else ("cites", "mentions", "defines"),
                top_k=args.top_k,
            )
        }
    )
    return 0


def _lookup_term(args: argparse.Namespace) -> int:
    _write_json(_query_service(args).lookup_term(args.term_type, args.name))
    return 0


def _add_runtime_args(
    parser: argparse.ArgumentParser,
    *,
    include_embedder: bool = False,
) -> None:
    parser.add_argument("--source", default="docs/rfc")
    parser.add_argument("--state-dir", default=".rag")
    parser.add_argument("--collection-name", default="quic_sections")
    if include_embedder:
        parser.add_argument(
            "--embedder",
            choices=("sentence-transformer", "fake"),
            default="sentence-transformer",
        )
        parser.add_argument("--model-name", default=DEFAULT_EMBEDDING_MODEL)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coquic-rag")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build-index")
    _add_runtime_args(build_parser, include_embedder=True)
    build_parser.set_defaults(handler=_build_index)

    doctor_parser = subparsers.add_parser("doctor")
    _add_runtime_args(doctor_parser)
    doctor_parser.set_defaults(handler=_doctor)

    search_sections_parser = subparsers.add_parser("search-sections")
    _add_runtime_args(search_sections_parser, include_embedder=True)
    search_sections_parser.add_argument("query")
    search_sections_parser.add_argument("--rfc", type=int)
    search_sections_parser.add_argument("--category")
    search_sections_parser.add_argument("--top-k", type=int, default=5)
    search_sections_parser.set_defaults(handler=_search_sections)

    get_section_parser = subparsers.add_parser("get-section")
    _add_runtime_args(get_section_parser, include_embedder=True)
    get_section_parser.add_argument("--rfc", type=int, required=True)
    get_section_parser.add_argument("--section-id", required=True)
    get_section_parser.set_defaults(handler=_get_section)

    trace_term_parser = subparsers.add_parser("trace-term")
    _add_runtime_args(trace_term_parser, include_embedder=True)
    trace_term_parser.add_argument("term")
    trace_term_parser.add_argument("--rfc", type=int)
    trace_term_parser.set_defaults(handler=_trace_term)

    related_sections_parser = subparsers.add_parser("related-sections")
    _add_runtime_args(related_sections_parser, include_embedder=True)
    related_sections_parser.add_argument("--rfc", type=int, required=True)
    related_sections_parser.add_argument("--section-id", required=True)
    related_sections_parser.add_argument("--edge-type", action="append")
    related_sections_parser.add_argument("--top-k", type=int, default=5)
    related_sections_parser.set_defaults(handler=_related_sections)

    lookup_term_parser = subparsers.add_parser("lookup-term")
    _add_runtime_args(lookup_term_parser, include_embedder=True)
    lookup_term_parser.add_argument("--term-type", required=True)
    lookup_term_parser.add_argument("--name", required=True)
    lookup_term_parser.set_defaults(handler=_lookup_term)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except IndexNotBuiltError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
