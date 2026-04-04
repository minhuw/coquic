from __future__ import annotations

import re
from collections.abc import Iterable

from coquic_rag.ingest.models import SourceDocument, SourceSection

_TRANSPORT_PARAMETER_RE = re.compile(
    r"^\s*([a-z][a-z0-9_]+)\s+\(0x[0-9a-fA-F]+\):",
    re.MULTILINE,
)
_FRAME_NAME_RE = re.compile(r"\b([A-Z][A-Z0-9_ ]+)\s+FRAME\b")
_FRAME_SECTION_TITLE_RE = re.compile(r"^\s*([A-Z][A-Z0-9_ ]+)\s+Frames?\s*$")
_TRANSPORT_ERROR_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]+)\s+\(0x[0-9a-fA-F]+(?:-0x[0-9a-fA-F]+)?\):"
)


def _normalize_term(raw_name: str) -> str:
    return raw_name.strip().lower().replace(" ", "_")


def _document_node_id(doc_id: str) -> str:
    return f"doc:{doc_id}"


def _section_node_id(doc_id: str, section_id: str) -> str:
    return f"{doc_id}#{section_id}"


def _build_section_record(section: SourceSection) -> dict[str, object]:
    return {
        "node_id": _section_node_id(section.doc_id, section.section_id),
        "doc_id": section.doc_id,
        "doc_kind": section.doc_kind,
        "rfc_number": section.rfc_number,
        "draft_name": section.draft_name,
        "section_id": section.section_id,
        "title": section.title,
        "text": section.text,
    }


def _extract_terms(section: SourceSection) -> Iterable[tuple[str, str]]:
    seen_terms: set[tuple[str, str]] = set()

    frame_title_match = _FRAME_SECTION_TITLE_RE.match(section.title)
    if section.section_id.startswith("19.") and frame_title_match:
        frame_term = ("frame_name", _normalize_term(frame_title_match.group(1)))
        seen_terms.add(frame_term)
        yield frame_term

    for match in _TRANSPORT_PARAMETER_RE.finditer(section.text):
        term = ("transport_parameter", _normalize_term(match.group(1)))
        if term not in seen_terms:
            seen_terms.add(term)
            yield term

    for match in _FRAME_NAME_RE.finditer(section.text):
        term = ("frame_name", _normalize_term(match.group(1)))
        if term not in seen_terms:
            seen_terms.add(term)
            yield term

    for match in _TRANSPORT_ERROR_RE.finditer(section.text):
        term_name = _normalize_term(match.group(1))
        term = ("transport_error_code", term_name)
        if term not in seen_terms:
            seen_terms.add(term)
            yield term


def _term_mention_pattern(term_name: str) -> re.Pattern[str]:
    raw_tokens = term_name.split("_")
    tokens = [re.escape(token) for token in raw_tokens]
    if len(raw_tokens) == 1 and len(raw_tokens[0]) <= 3:
        pattern = rf"(?<![\w-]){tokens[0]}(?![\w-])"
    else:
        pattern = r"\b" + r"[_\s]+".join(tokens) + r"\b"
    return re.compile(pattern, re.IGNORECASE)


def _section_mentions_term(section: SourceSection, term_name: str) -> bool:
    haystack = f"{section.title}\n{section.text}"
    return bool(_term_mention_pattern(term_name).search(haystack))


def build_graph_artifacts(
    document: SourceDocument,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []

    document_id = _document_node_id(document.doc_id)
    graph_nodes.append(
        {
            "id": document_id,
            "node_type": "document",
            "doc_id": document.doc_id,
            "doc_kind": document.doc_kind,
            "rfc_number": document.rfc_number,
            "draft_name": document.draft_name,
            "title": document.title,
        }
    )

    term_node_ids: set[str] = set()
    known_terms: dict[tuple[str, str], set[str]] = {}

    # First pass: collect deterministic term definitions per section.
    for section in document.sections:
        section_id = _section_node_id(document.doc_id, section.section_id)
        for term_class, term_name in _extract_terms(section):
            term_key = (term_class, term_name)
            if term_key not in known_terms:
                known_terms[term_key] = set()
            is_definition = (
                (term_class == "transport_parameter" and section.section_id == "18.2")
                or (term_class == "frame_name" and section.section_id.startswith("19."))
                or (
                    term_class == "transport_error_code"
                    and section.section_id.startswith("20.")
                )
            )
            if is_definition:
                known_terms[term_key].add(section_id)

    for section in document.sections:
        section_id = _section_node_id(document.doc_id, section.section_id)
        section_records.append(_build_section_record(section))

        graph_nodes.append(
            {
                "id": section_id,
                "node_type": "section",
                "doc_id": section.doc_id,
                "doc_kind": section.doc_kind,
                "rfc_number": section.rfc_number,
                "draft_name": section.draft_name,
                "section_id": section.section_id,
                "title": section.title,
            }
        )

        graph_edges.append(
            {
                "edge_type": "contains",
                "source": document_id,
                "target": section_id,
            }
        )

        for citation in section.citations:
            graph_edges.append(
                {
                    "edge_type": "cites",
                    "source": section_id,
                    "target": _section_node_id(document.doc_id, citation.target_start),
                }
            )
            if citation.target_end:
                graph_edges.append(
                    {
                        "edge_type": "cites",
                        "source": section_id,
                        "target": _section_node_id(document.doc_id, citation.target_end),
                    }
                )

        for term_class, term_name in known_terms:
            if not _section_mentions_term(section, term_name):
                continue
            term_id = f"term:{term_class}:{term_name}"
            if term_id not in term_node_ids:
                term_node_ids.add(term_id)
                graph_nodes.append(
                    {
                        "id": term_id,
                        "node_type": "term",
                        "term_class": term_class,
                        "name": term_name,
                    }
                )

            graph_edges.append(
                {
                    "edge_type": "mentions",
                    "source": section_id,
                    "target": term_id,
                }
            )

            if section_id in known_terms[(term_class, term_name)]:
                graph_edges.append(
                    {
                        "edge_type": "defines",
                        "source": section_id,
                        "target": term_id,
                    }
                )

    return section_records, graph_nodes, graph_edges
