from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from coquic_rag.graph.extractor import build_graph_artifacts
from coquic_rag.ingest.rfc_parser import parse_source_document


DEFAULT_GENERIC_EXTENSIONS = frozenset(
    {
        ".adoc",
        ".html",
        ".md",
        ".mdx",
        ".pdf",
        ".rst",
        ".txt",
    }
)
DEFAULT_CODE_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".mjs",
        ".py",
        ".rs",
        ".ts",
        ".tsx",
        ".zig",
    }
)
RFC_NAME_PREFIXES = ("rfc", "draft-")


@dataclass(frozen=True)
class CorpusLoadConfig:
    loader: str = "auto"
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    chunk_size: int = 1200
    chunk_overlap: int = 160


@dataclass(frozen=True)
class LoadedCorpus:
    section_records: list[dict[str, object]]
    graph_nodes: list[dict[str, object]]
    graph_edges: list[dict[str, object]]
    doc_ids: set[str]


def load_corpus(source: Path, config: CorpusLoadConfig) -> LoadedCorpus:
    source = Path(source)
    loader = config.loader
    if loader == "auto":
        loader = _detect_loader(source)
    if loader == "rfc":
        return load_rfc_corpus(source, config)
    if loader == "llamaindex":
        return load_llamaindex_corpus(source, config)
    if loader == "cocoindex":
        return load_cocoindex_corpus(source, config)
    raise ValueError(f"unsupported corpus loader: {config.loader}")


def load_rfc_corpus(source: Path, config: CorpusLoadConfig) -> LoadedCorpus:
    paths = _iter_files(source, config, default_extensions={".txt"})
    if not paths:
        raise ValueError(f"no RFC or Internet-Draft text files found under {source}")

    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []
    doc_ids: set[str] = set()

    for path in paths:
        document = parse_source_document(path)
        if document.doc_id in doc_ids:
            raise ValueError(f"duplicate doc_id {document.doc_id}")
        doc_ids.add(document.doc_id)
        doc_section_records, doc_graph_nodes, doc_graph_edges = build_graph_artifacts(
            document
        )
        section_records.extend(doc_section_records)
        graph_nodes.extend(doc_graph_nodes)
        graph_edges.extend(doc_graph_edges)

    return LoadedCorpus(section_records, graph_nodes, graph_edges, doc_ids)


def load_llamaindex_corpus(source: Path, config: CorpusLoadConfig) -> LoadedCorpus:
    try:
        from llama_index.core import SimpleDirectoryReader
    except ImportError as error:
        raise RuntimeError(
            "LlamaIndex generic document loading dependencies are not installed"
        ) from error

    paths = _iter_files(source, config, default_extensions=DEFAULT_GENERIC_EXTENSIONS)
    if not paths:
        raise ValueError(f"no generic document files found under {source}")

    reader = SimpleDirectoryReader(
        input_files=[str(path) for path in paths],
        filename_as_id=True,
    )
    documents = reader.load_data()
    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []
    doc_ids: set[str] = set()

    for document in documents:
        metadata = dict(getattr(document, "metadata", {}) or {})
        source_path = str(metadata.get("file_path") or getattr(document, "id_", "document"))
        doc_id = _path_doc_id(source_path)
        doc_ids.add(doc_id)
        text = str(getattr(document, "text", "")).strip()
        title = str(metadata.get("file_name") or Path(source_path).name or doc_id)
        chunks = _chunk_text(text, config.chunk_size, config.chunk_overlap)
        section_records.extend(
            _generic_section_records(
                doc_id=doc_id,
                title=title,
                chunks=chunks,
                source_path=source_path,
                source_type="document",
                loader="llamaindex",
                extra_metadata=metadata,
            )
        )
        graph_nodes.append(_document_node(doc_id, "document", title, source_path, "llamaindex"))

    return LoadedCorpus(section_records, graph_nodes, graph_edges, doc_ids)


def load_cocoindex_corpus(source: Path, config: CorpusLoadConfig) -> LoadedCorpus:
    paths = _iter_files(source, config, default_extensions=DEFAULT_CODE_EXTENSIONS)
    if not paths:
        raise ValueError(f"no source code files found under {source}")

    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []
    doc_ids: set[str] = set()

    for path in paths:
        relative_path = _relative_path(path, source)
        doc_id = _path_doc_id(relative_path)
        doc_ids.add(doc_id)
        title = str(relative_path)
        text = path.read_text(encoding="utf-8", errors="replace")
        language = _detect_code_language(path, text)
        chunks = _split_code_chunks(
            text,
            language=language,
            chunk_size=config.chunk_size,
            chunk_overlap=config.chunk_overlap,
        )
        section_records.extend(
            _generic_section_records(
                doc_id=doc_id,
                title=title,
                chunks=chunks,
                source_path=str(relative_path),
                source_type="source_code",
                loader="cocoindex",
                extra_metadata={"language": language},
            )
        )
        graph_nodes.append(_document_node(doc_id, "source_code", title, str(relative_path), "cocoindex"))

    return LoadedCorpus(section_records, graph_nodes, graph_edges, doc_ids)


def _iter_files(
    source: Path,
    config: CorpusLoadConfig,
    *,
    default_extensions: set[str] | frozenset[str],
) -> list[Path]:
    if source.is_file():
        candidates = [source]
        root = source.parent
    else:
        root = source
        candidates = [path for path in source.rglob("*") if path.is_file()]
    filtered = []
    for path in sorted(candidates):
        relative = _relative_path(path, root)
        if config.include and not _matches_any(relative, config.include):
            continue
        if config.exclude and _matches_any(relative, config.exclude):
            continue
        if not config.include and path.suffix.lower() not in default_extensions:
            continue
        filtered.append(path)
    return filtered


def _detect_loader(source: Path) -> str:
    paths = [source] if source.is_file() else [path for path in source.rglob("*") if path.is_file()]
    suffixes = {path.suffix.lower() for path in paths}
    names = {path.name.lower() for path in paths}
    if suffixes and suffixes <= {".txt"} and all(
        name.startswith(RFC_NAME_PREFIXES) for name in names
    ):
        return "rfc"
    if suffixes and suffixes <= DEFAULT_CODE_EXTENSIONS:
        return "cocoindex"
    return "llamaindex"


def _split_code_chunks(
    text: str,
    *,
    language: str,
    chunk_size: int,
    chunk_overlap: int,
) -> list[str]:
    try:
        from cocoindex.ops.text import RecursiveSplitter
    except ImportError:
        try:
            import cocoindex
        except ImportError:
            return _chunk_text(text, chunk_size, chunk_overlap)

        legacy_splitter = getattr(cocoindex.functions, "SplitRecursively", None)
        if legacy_splitter is None:
            return _chunk_text(text, chunk_size, chunk_overlap)
        try:
            splitter = legacy_splitter()
            chunks = splitter.split(
                text,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                language=language,
            )
            return [_chunk_text_value(chunk) for chunk in chunks if _chunk_text_value(chunk)]
        except Exception:
            return _chunk_text(text, chunk_size, chunk_overlap)

    try:
        splitter = RecursiveSplitter()
        chunks = splitter.split(
            text,
            language=language,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        return [_chunk_text_value(chunk) for chunk in chunks if _chunk_text_value(chunk)]
    except Exception:
        return _chunk_text(text, chunk_size, chunk_overlap)


def _detect_code_language(path: Path, text: str) -> str:
    try:
        from cocoindex.ops.text import detect_code_language
    except ImportError as error:
        try:
            import cocoindex
        except ImportError:
            raise RuntimeError(
                "CocoIndex source-code loading dependencies are not installed"
            ) from error

        detector = getattr(cocoindex.functions, "DetectProgrammingLanguage", None)
        if detector is not None:
            try:
                detected = detector()(filename=str(path))
                if detected:
                    return str(detected)
            except Exception:
                pass
        return _language_from_suffix(path.suffix.lower())

    detected = detect_code_language(filename=str(path))
    if detected:
        return str(detected)
    return _language_from_suffix(path.suffix.lower())


def _language_from_suffix(suffix: str) -> str:
    return {
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".go": "go",
        ".h": "cpp",
        ".hpp": "cpp",
        ".java": "java",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".py": "python",
        ".rs": "rust",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".zig": "zig",
    }.get(suffix, "text")


def _chunk_text_value(chunk: object) -> str:
    return str(getattr(chunk, "text", chunk)).strip()


def _chunk_text(text: str, chunk_size: int, chunk_overlap: int) -> list[str]:
    clean = text.strip()
    if not clean:
        return []
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")
    overlap = min(max(chunk_overlap, 0), max(chunk_size - 1, 0))
    chunks = []
    start = 0
    while start < len(clean):
        end = min(len(clean), start + chunk_size)
        chunk = clean[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(clean):
            break
        start = end - overlap
    return chunks


def _generic_section_records(
    *,
    doc_id: str,
    title: str,
    chunks: Sequence[str],
    source_path: str,
    source_type: str,
    loader: str,
    extra_metadata: dict[str, object],
) -> list[dict[str, object]]:
    records = []
    for index, chunk in enumerate(chunks, start=1):
        section_id = str(index)
        record: dict[str, object] = {
            "node_id": f"{doc_id}#{section_id}",
            "doc_id": doc_id,
            "doc_kind": source_type,
            "rfc_number": None,
            "draft_name": None,
            "section_id": section_id,
            "title": title if len(chunks) == 1 else f"{title} chunk {index}",
            "text": chunk,
            "source_path": source_path,
            "source_type": source_type,
            "loader": loader,
        }
        record.update({f"metadata_{key}": value for key, value in extra_metadata.items()})
        records.append(record)
    return records


def _document_node(
    doc_id: str,
    source_type: str,
    title: str,
    source_path: str,
    loader: str,
) -> dict[str, object]:
    return {
        "id": f"doc:{doc_id}",
        "node_type": "document",
        "doc_id": doc_id,
        "doc_kind": source_type,
        "rfc_number": None,
        "draft_name": None,
        "title": title,
        "source_path": source_path,
        "source_type": source_type,
        "loader": loader,
    }


def _path_doc_id(path: str | Path) -> str:
    normalized = str(path).replace("\\", "/").strip("/")
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]
    stem = Path(normalized).stem or "document"
    slug = "".join(char.lower() if char.isalnum() else "-" for char in stem).strip("-")
    return f"{slug}-{digest}"


def _relative_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _matches_any(path: Path, patterns: Iterable[str]) -> bool:
    normalized = path.as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)
