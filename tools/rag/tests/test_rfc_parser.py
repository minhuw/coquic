from __future__ import annotations

from pathlib import Path

from coquic_rag.ingest.rfc_parser import parse_rfc_document


def test_parse_rfc9000_core_metadata_and_sections() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))

    assert doc.rfc == 9000
    assert doc.title == "QUIC: A UDP-Based Multiplexed and Secure Transport"

    section_1 = doc.section_by_id("1")
    assert section_1 is not None
    assert section_1.title in {"Overview", "Introduction"}
    assert section_1.rfc == 9000
    assert section_1.section_id == "1"

    section_182 = doc.section_by_id("18.2")
    assert section_182 is not None
    assert "Transport Parameter" in section_182.title
    assert section_182.rfc == 9000
    assert section_182.section_id == "18.2"


def test_extract_section_citations_from_body_text() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))

    section_523 = doc.section_by_id("5.2.3")
    assert section_523 is not None

    targets = {citation.target_start for citation in section_523.citations}
    assert "21.11" in targets
