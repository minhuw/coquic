from __future__ import annotations

from pathlib import Path

from coquic_rag.graph.extractor import build_graph_artifacts
from coquic_rag.ingest.rfc_parser import parse_rfc_document
from coquic_rag.store.artifacts import (
    read_graph_edges,
    read_graph_nodes,
    read_section_records,
    write_graph_edges,
    write_graph_nodes,
    write_section_records,
)


def test_build_graph_artifacts_from_rfc9000() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))

    section_records, graph_nodes, graph_edges = build_graph_artifacts(doc)

    section_node_ids = {
        node["id"] for node in graph_nodes if node["node_type"] == "section"
    }
    assert "rfc9000#18.2" in section_node_ids

    cites_to_132 = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "cites" and edge["target"] == "rfc9000#13.2"
    ]
    assert cites_to_132

    term_id = "term:transport_parameter:max_udp_payload_size"
    term_nodes = [node for node in graph_nodes if node["id"] == term_id]
    assert term_nodes
    assert term_nodes[0]["term_class"] == "transport_parameter"

    defines_edges = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "defines"
        and edge["source"] == "rfc9000#18.2"
        and edge["target"] == term_id
    ]
    assert defines_edges

    frame_term_id = "term:frame_name:ack"
    frame_nodes = [node for node in graph_nodes if node["id"] == frame_term_id]
    assert frame_nodes

    frame_defines_edges = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "defines"
        and edge["source"] == "rfc9000#19.3"
        and edge["target"] == frame_term_id
    ]
    assert frame_defines_edges

    frame_mentions_edges = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "mentions"
        and edge["source"] == "rfc9000#13.4.2.1"
        and edge["target"] == frame_term_id
    ]
    assert frame_mentions_edges

    ack_false_positive_mentions = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "mentions"
        and edge["source"] == "rfc9000#4.1"
        and edge["target"] == frame_term_id
    ]
    assert ack_false_positive_mentions == []

    frame_encoding_error_id = "term:transport_error_code:frame_encoding_error"
    crypto_error_id = "term:transport_error_code:crypto_error"
    error_node_ids = {
        node["id"]
        for node in graph_nodes
        if node.get("term_class") == "transport_error_code"
    }
    assert frame_encoding_error_id in error_node_ids
    assert crypto_error_id in error_node_ids

    error_defines_edges = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "defines"
        and edge["source"] == "rfc9000#20.1"
        and edge["target"] in {frame_encoding_error_id, crypto_error_id}
    ]
    assert len(error_defines_edges) == 2

    transport_param_mentions = [
        edge
        for edge in graph_edges
        if edge["edge_type"] == "mentions"
        and edge["source"] == "rfc9000#7.4.1"
        and edge["target"] == term_id
    ]
    assert transport_param_mentions

    section_record_ids = {record["node_id"] for record in section_records}
    assert "rfc9000#18.2" in section_record_ids


def test_artifact_jsonl_roundtrip(tmp_path: Path) -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))
    section_records, graph_nodes, graph_edges = build_graph_artifacts(doc)

    sections_path = tmp_path / "sections.jsonl"
    nodes_path = tmp_path / "nodes.jsonl"
    edges_path = tmp_path / "edges.jsonl"

    write_section_records(sections_path, section_records)
    write_graph_nodes(nodes_path, graph_nodes)
    write_graph_edges(edges_path, graph_edges)

    assert read_section_records(sections_path) == section_records
    assert read_graph_nodes(nodes_path) == graph_nodes
    assert read_graph_edges(edges_path) == graph_edges
