from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import (
    DEFAULT_EMBEDDING_MODEL,
    FakeEmbedder,
    OpenRouterEmbedder,
)
from coquic_rag.graph.extractor import build_graph_artifacts
from coquic_rag.ingest.corpus_loader import CorpusLoadConfig, load_corpus
from coquic_rag.ingest.rfc_parser import parse_source_document
from coquic_rag.query.service import IndexNotBuiltError, QueryService, get_index_status
from coquic_rag.store.artifacts import (
    read_graph_edges,
    read_graph_nodes,
    read_section_records,
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
        qdrant_url=os.getenv("COQUIC_QDRANT_URL"),
        qdrant_api_key=os.getenv("COQUIC_QDRANT_API_KEY"),
    )


def _iter_source_paths(source: Path) -> list[Path]:
    return sorted(path for path in source.glob("*.txt") if path.is_file())


def _required_artifact_paths(paths: ProjectPaths) -> tuple[Path, Path, Path]:
    return (
        paths.artifacts_dir / _SECTION_ARTIFACT,
        paths.artifacts_dir / _GRAPH_NODES_ARTIFACT,
        paths.artifacts_dir / _GRAPH_EDGES_ARTIFACT,
    )


def _embedding_model_name(args: argparse.Namespace) -> str:
    explicit_model = getattr(args, "model_name", None)
    if explicit_model:
        return str(explicit_model)
    return DEFAULT_EMBEDDING_MODEL


def _build_embedder(name: str, model_name: str):
    if name == "fake":
        return FakeEmbedder()
    return OpenRouterEmbedder(model_name=model_name)


def _parse_source_artifacts(
    source_paths: list[Path],
    *,
    allow_duplicate_doc_ids: bool,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], set[str]]:
    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []
    parsed_doc_ids: set[str] = set()

    parse_progress = _ProgressBar("parse docs", len(source_paths))
    parse_progress.update(0)
    for index, path in enumerate(source_paths, start=1):
        document = parse_source_document(path)
        if not allow_duplicate_doc_ids and document.doc_id in parsed_doc_ids:
            raise ValueError(f"duplicate doc_id {document.doc_id}")
        parsed_doc_ids.add(document.doc_id)
        doc_section_records, doc_graph_nodes, doc_graph_edges = build_graph_artifacts(
            document
        )
        section_records.extend(doc_section_records)
        graph_nodes.extend(doc_graph_nodes)
        graph_edges.extend(doc_graph_edges)
        parse_progress.update(index, path.name)
    return section_records, graph_nodes, graph_edges, parsed_doc_ids


def _store_for_paths(paths: ProjectPaths, collection_name: str) -> QdrantSectionStore:
    return QdrantSectionStore(
        state_dir=paths.qdrant_dir,
        qdrant_url=paths.qdrant_url,
        qdrant_api_key=paths.qdrant_api_key,
        collection_name=collection_name,
    )


def _write_artifacts(
    paths: ProjectPaths,
    section_records: list[dict[str, object]],
    graph_nodes: list[dict[str, object]],
    graph_edges: list[dict[str, object]],
) -> None:
    sections_path, nodes_path, edges_path = _required_artifact_paths(paths)
    write_section_records(sections_path, section_records)
    write_graph_nodes(nodes_path, graph_nodes)
    write_graph_edges(edges_path, graph_edges)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_existing_artifacts(
    paths: ProjectPaths,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    sections_path, nodes_path, edges_path = _required_artifact_paths(paths)
    if not sections_path.is_file() or not nodes_path.is_file() or not edges_path.is_file():
        return [], [], []
    return (
        read_section_records(sections_path),
        read_graph_nodes(nodes_path),
        read_graph_edges(edges_path),
    )


def _merge_records_by_key(
    existing: list[dict[str, object]],
    incoming: list[dict[str, object]],
    key: str,
) -> list[dict[str, object]]:
    records: dict[str, dict[str, object]] = {
        str(record[key]): record for record in existing
    }
    for record in incoming:
        records[str(record[key])] = record
    return sorted(records.values(), key=lambda record: str(record[key]))


def _merge_artifacts(
    paths: ProjectPaths,
    section_records: list[dict[str, object]],
    graph_nodes: list[dict[str, object]],
    graph_edges: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    existing_sections, existing_nodes, existing_edges = _load_existing_artifacts(paths)
    return (
        _merge_records_by_key(existing_sections, section_records, "node_id"),
        _merge_records_by_key(existing_nodes, graph_nodes, "id"),
        _dedupe_graph_edges([*existing_edges, *graph_edges]),
    )


def _dedupe_graph_edges(edges: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    deduped = []
    for edge in edges:
        key = (str(edge["edge_type"]), str(edge["source"]), str(edge["target"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return sorted(
        deduped,
        key=lambda edge: (str(edge["edge_type"]), str(edge["source"]), str(edge["target"])),
    )


def _build_index(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    source_paths = _iter_source_paths(paths.rfc_source)
    if not paths.rfc_source.is_dir() or not source_paths:
        raise ValueError(f"no source documents found under {paths.rfc_source}")

    section_records, graph_nodes, graph_edges, _parsed_doc_ids = _parse_source_artifacts(
        source_paths,
        allow_duplicate_doc_ids=False,
    )
    _write_artifacts(paths, section_records, graph_nodes, graph_edges)

    store = _store_for_paths(paths, args.collection_name)
    store.reset_collection()
    embed_progress = _ProgressBar("embed sections", len(section_records))
    store.upsert_sections(
        section_records,
        _build_embedder(args.embedder, _embedding_model_name(args)),
        progress=lambda current, total: embed_progress.update(current),
    )

    print(
        f"indexed {len(source_paths)} documents "
        f"with {len(section_records)} sections"
    )
    return 0


def _index_corpus(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    corpus = load_corpus(
        paths.rfc_source,
        CorpusLoadConfig(
            loader=args.loader,
            include=tuple(args.include or ()),
            exclude=tuple(args.exclude or ()),
            chunk_size=args.chunk_size,
            chunk_overlap=args.chunk_overlap,
        ),
    )
    if args.replace:
        merged_sections = corpus.section_records
        merged_nodes = corpus.graph_nodes
        merged_edges = corpus.graph_edges
    else:
        merged_sections, merged_nodes, merged_edges = _merge_artifacts(
            paths,
            corpus.section_records,
            corpus.graph_nodes,
            corpus.graph_edges,
        )
    _write_artifacts(paths, merged_sections, merged_nodes, merged_edges)

    store = _store_for_paths(paths, args.collection_name)
    if args.replace:
        store.reset_collection()

    embed_progress = _ProgressBar("embed sections", len(corpus.section_records))
    store.upsert_sections(
        corpus.section_records,
        _build_embedder(args.embedder, _embedding_model_name(args)),
        batch_size=args.batch_size,
        progress=lambda current, total: embed_progress.update(current),
    )

    mode = "replaced" if args.replace else "upserted"
    print(
        f"{mode} {len(corpus.doc_ids)} documents "
        f"with {len(corpus.section_records)} sections into {args.collection_name}"
    )
    return 0


def _doctor(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    status = get_index_status(paths, collection_name=args.collection_name)
    for line in status.lines():
        print(line)
    return 0 if status.ready else 1


def _source_path_for_doc(
    source: Path,
    record: dict[str, object],
) -> Path | None:
    source_path = record.get("source_path")
    if source_path is not None:
        path = Path(str(source_path))
        if path.is_absolute():
            return path
        return source / path
    doc_kind = str(record.get("doc_kind", ""))
    doc_id = str(record.get("doc_id", ""))
    if doc_kind in {"rfc", "internet-draft"}:
        return source / f"{doc_id}.txt"
    return None


def _artifact_doc_summaries(
    paths: ProjectPaths,
) -> list[dict[str, object]]:
    sections_path = paths.artifacts_dir / _SECTION_ARTIFACT
    if not sections_path.is_file():
        return []
    records = read_section_records(sections_path)
    summaries: dict[str, dict[str, object]] = {}
    for record in records:
        doc_id = str(record["doc_id"])
        summary = summaries.setdefault(
            doc_id,
            {
                "doc_id": doc_id,
                "doc_kind": str(record["doc_kind"]),
                "sections": 0,
                "title": str(record.get("title") or ""),
                "source_path": None,
                "loader": record.get("loader"),
                "sha256": None,
            },
        )
        summary["sections"] = int(summary["sections"]) + 1
        source_path = _source_path_for_doc(paths.rfc_source, record)
        if source_path is not None:
            summary["source_path"] = str(source_path)
            if source_path.is_file():
                summary["sha256"] = _file_sha256(source_path)
        if record.get("loader") is not None:
            summary["loader"] = str(record["loader"])
    return sorted(summaries.values(), key=lambda item: str(item["doc_id"]))


def _print_corpus_table(summaries: list[dict[str, object]]) -> None:
    if not summaries:
        print("no corpus artifacts found")
        return
    print("doc_id\tdoc_kind\tsections\tqdrant_sections\tsha256\tsource")
    for summary in summaries:
        print(
            "\t".join(
                [
                    str(summary["doc_id"]),
                    str(summary["doc_kind"]),
                    str(summary["sections"]),
                    str(summary.get("qdrant_sections", "")),
                    str(summary.get("sha256") or ""),
                    str(summary.get("source_path") or ""),
                ]
            )
        )


def _list_corpus(args: argparse.Namespace) -> int:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    summaries = _artifact_doc_summaries(paths)
    status = get_index_status(paths, collection_name=args.collection_name)
    qdrant_summaries = []
    if status.qdrant_ok or args.include_qdrant:
        try:
            qdrant_summaries = _store_for_paths(
                paths,
                args.collection_name,
            ).document_summaries()
        except Exception as error:
            if args.include_qdrant:
                raise ValueError(f"unable to read Qdrant corpus: {error}") from error
    qdrant_by_doc = {
        summary.doc_id: summary for summary in qdrant_summaries
    }
    for summary in summaries:
        qdrant_summary = qdrant_by_doc.get(str(summary["doc_id"]))
        if qdrant_summary is not None:
            summary["qdrant_sections"] = qdrant_summary.sections

    if args.format == "json":
        qdrant_doc_ids = set(qdrant_by_doc)
        artifact_doc_ids = {str(summary["doc_id"]) for summary in summaries}
        payload = {
            "source": str(paths.rfc_source),
            "state_dir": str(paths.state_dir),
            "collection_name": args.collection_name,
            "artifact_doc_count": len(summaries),
            "artifact_section_count": sum(int(summary["sections"]) for summary in summaries),
            "qdrant_doc_count": len(qdrant_by_doc),
            "qdrant_section_count": sum(summary.sections for summary in qdrant_summaries),
            "qdrant_missing_doc_ids": sorted(artifact_doc_ids - qdrant_doc_ids),
            "qdrant_extra_doc_ids": sorted(qdrant_doc_ids - artifact_doc_ids),
            "docs": summaries,
        }
        _write_json(payload)
        return 0

    _print_corpus_table(summaries)
    kind_counts = Counter(str(summary["doc_kind"]) for summary in summaries)
    print(
        f"artifact_docs={len(summaries)} "
        f"artifact_sections={sum(int(summary['sections']) for summary in summaries)} "
        f"qdrant_docs={len(qdrant_by_doc)} "
        f"qdrant_sections={sum(summary.sections for summary in qdrant_summaries)}"
    )
    if kind_counts:
        print(
            "doc_kinds="
            + ",".join(f"{kind}:{count}" for kind, count in sorted(kind_counts.items()))
        )
    return 0


def _query_service(args: argparse.Namespace) -> QueryService:
    paths = _runtime_paths(Path(args.source), Path(args.state_dir))
    return QueryService(
        paths=paths,
        embedder=_build_embedder(args.embedder, _embedding_model_name(args)),
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
                doc_id=args.doc,
                category=args.category,
                top_k=args.top_k,
            )
        }
    )
    return 0


def _get_section(args: argparse.Namespace) -> int:
    _write_json(_query_service(args).get_section(args.doc, args.section_id))
    return 0


def _trace_term(args: argparse.Namespace) -> int:
    _write_json(_query_service(args).trace_term(args.term, doc_id=args.doc))
    return 0


def _related_sections(args: argparse.Namespace) -> int:
    _write_json(
        {
            "sections": _query_service(args).related_sections(
                args.doc,
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
            choices=("openrouter", "fake"),
            default="openrouter",
        )
        parser.add_argument("--model-name")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coquic-rag")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build-index")
    _add_runtime_args(build_parser, include_embedder=True)
    build_parser.set_defaults(handler=_build_index)

    index_corpus_parser = subparsers.add_parser(
        "index-corpus",
        help="Parse, embed, and upsert RFC or Internet-Draft text files into Qdrant.",
    )
    _add_runtime_args(index_corpus_parser, include_embedder=True)
    index_corpus_parser.add_argument(
        "--loader",
        choices=("auto", "rfc", "llamaindex", "cocoindex"),
        default="auto",
        help="Corpus parser to use. auto picks RFC text, source code, or generic documents.",
    )
    index_corpus_parser.add_argument(
        "--include",
        action="append",
        help="Glob pattern relative to --source to include. Can be repeated.",
    )
    index_corpus_parser.add_argument(
        "--exclude",
        action="append",
        help="Glob pattern relative to --source to exclude. Can be repeated.",
    )
    index_corpus_parser.add_argument(
        "--replace",
        action="store_true",
        help="Reset the target Qdrant collection before inserting this corpus.",
    )
    index_corpus_parser.add_argument("--batch-size", type=int, default=32)
    index_corpus_parser.add_argument("--chunk-size", type=int, default=1200)
    index_corpus_parser.add_argument("--chunk-overlap", type=int, default=160)
    index_corpus_parser.set_defaults(handler=_index_corpus)

    doctor_parser = subparsers.add_parser("doctor")
    _add_runtime_args(doctor_parser)
    doctor_parser.set_defaults(handler=_doctor)

    list_corpus_parser = subparsers.add_parser("list-corpus")
    _add_runtime_args(list_corpus_parser)
    list_corpus_parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
    )
    list_corpus_parser.add_argument(
        "--include-qdrant",
        action="store_true",
        help="Read Qdrant payloads even when doctor status is not ready.",
    )
    list_corpus_parser.set_defaults(handler=_list_corpus)

    search_sections_parser = subparsers.add_parser("search-sections")
    _add_runtime_args(search_sections_parser, include_embedder=True)
    search_sections_parser.add_argument("query")
    search_sections_parser.add_argument("--doc")
    search_sections_parser.add_argument("--category")
    search_sections_parser.add_argument("--top-k", type=int, default=5)
    search_sections_parser.set_defaults(handler=_search_sections)

    get_section_parser = subparsers.add_parser("get-section")
    _add_runtime_args(get_section_parser, include_embedder=True)
    get_section_parser.add_argument("--doc", required=True)
    get_section_parser.add_argument("--section-id", required=True)
    get_section_parser.set_defaults(handler=_get_section)

    trace_term_parser = subparsers.add_parser("trace-term")
    _add_runtime_args(trace_term_parser, include_embedder=True)
    trace_term_parser.add_argument("term")
    trace_term_parser.add_argument("--doc")
    trace_term_parser.set_defaults(handler=_trace_term)

    related_sections_parser = subparsers.add_parser("related-sections")
    _add_runtime_args(related_sections_parser, include_embedder=True)
    related_sections_parser.add_argument("--doc", required=True)
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
    except (IndexNotBuiltError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
