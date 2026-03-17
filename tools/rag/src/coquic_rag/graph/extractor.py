from __future__ import annotations

import re
from collections.abc import Iterable

from coquic_rag.ingest.models import RfcDocument, RfcSection

_TRANSPORT_PARAMETER_RE = re.compile(
    r"^\s*([a-z][a-z0-9_]+)\s+\(0x[0-9a-fA-F]+\):",
    re.MULTILINE,
)
_FRAME_NAME_RE = re.compile(r"\b([A-Z][A-Z0-9_ ]+)\s+FRAME\b")
_TRANSPORT_ERROR_RE = re.compile(r"\b([A-Z][A-Z0-9_]+)\s+\(0x[0-9a-fA-F]+\):")


def _normalize_term(raw_name: str) -> str:
    return raw_name.strip().lower().replace(" ", "_")


def _section_node_id(rfc_number: int, section_id: str) -> str:
    return f"rfc{rfc_number}#{section_id}"


def _build_section_record(section: RfcSection) -> dict[str, object]:
    return {
        "node_id": _section_node_id(section.rfc, section.section_id),
        "rfc": section.rfc,
        "section_id": section.section_id,
        "title": section.title,
        "text": section.text,
    }


def _extract_terms(section: RfcSection) -> Iterable[tuple[str, str]]:
    for match in _TRANSPORT_PARAMETER_RE.finditer(section.text):
        yield ("transport_parameter", _normalize_term(match.group(1)))

    for match in _FRAME_NAME_RE.finditer(section.text):
        yield ("frame_name", _normalize_term(match.group(1)))

    for match in _TRANSPORT_ERROR_RE.finditer(section.text):
        term_name = _normalize_term(match.group(1))
        if "frame" not in term_name:
            yield ("transport_error_code", term_name)


def build_graph_artifacts(
    document: RfcDocument,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    section_records: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = []
    graph_edges: list[dict[str, object]] = []

    rfc_node_id = f"rfc{document.rfc}"
    graph_nodes.append(
        {
            "id": rfc_node_id,
            "node_type": "rfc",
            "rfc": document.rfc,
            "title": document.title,
        }
    )

    term_node_ids: set[str] = set()

    for section in document.sections:
        section_id = _section_node_id(document.rfc, section.section_id)
        section_records.append(_build_section_record(section))

        graph_nodes.append(
            {
                "id": section_id,
                "node_type": "section",
                "rfc": document.rfc,
                "section_id": section.section_id,
                "title": section.title,
            }
        )

        graph_edges.append(
            {
                "edge_type": "contains",
                "source": rfc_node_id,
                "target": section_id,
            }
        )

        for citation in section.citations:
            graph_edges.append(
                {
                    "edge_type": "cites",
                    "source": section_id,
                    "target": _section_node_id(document.rfc, citation.target_start),
                }
            )
            if citation.target_end:
                graph_edges.append(
                    {
                        "edge_type": "cites",
                        "source": section_id,
                        "target": _section_node_id(document.rfc, citation.target_end),
                    }
                )

        for term_class, term_name in _extract_terms(section):
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

            is_definition = (
                (term_class == "transport_parameter" and section.section_id == "18.2")
                or (term_class == "frame_name" and section.section_id.startswith("19."))
                or (
                    term_class == "transport_error_code"
                    and section.section_id.startswith("20.")
                )
            )
            if is_definition:
                graph_edges.append(
                    {
                        "edge_type": "defines",
                        "source": section_id,
                        "target": term_id,
                    }
                )

    return section_records, graph_nodes, graph_edges
