from __future__ import annotations

import argparse
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
from coquic_rag.query.service import get_index_status
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coquic-rag")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build-index")
    build_parser.add_argument("--source", default="docs/rfc")
    build_parser.add_argument("--state-dir", default=".rag")
    build_parser.add_argument("--embedder", choices=("sentence-transformer", "fake"), default="sentence-transformer")
    build_parser.add_argument("--model-name", default=DEFAULT_EMBEDDING_MODEL)
    build_parser.add_argument("--collection-name", default="quic_sections")
    build_parser.set_defaults(handler=_build_index)

    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--source", default="docs/rfc")
    doctor_parser.add_argument("--state-dir", default=".rag")
    doctor_parser.add_argument("--collection-name", default="quic_sections")
    doctor_parser.set_defaults(handler=_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
