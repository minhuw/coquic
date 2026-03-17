from __future__ import annotations

from pathlib import Path

from coquic_rag.ingest.models import SectionCitation
from coquic_rag.ingest.rfc_parser import parse_rfc_document


def test_parse_rfc9000_core_metadata_and_sections() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))

    assert doc.rfc == 9000
    assert doc.title == "QUIC: A UDP-Based Multiplexed and Secure Transport"

    section_1 = doc.section_by_id("1")
    assert section_1 is not None
    assert section_1.title == "Overview"
    assert section_1.rfc == 9000
    assert section_1.section_id == "1"

    section_182 = doc.section_by_id("18.2")
    assert section_182 is not None
    assert section_182.title == "Transport Parameter Definitions"
    assert section_182.rfc == 9000
    assert section_182.section_id == "18.2"

    appendix_a = doc.section_by_id("A")
    assert appendix_a is not None
    assert appendix_a.title == "Pseudocode"

    appendix_a1 = doc.section_by_id("A.1")
    assert appendix_a1 is not None
    assert appendix_a1.title == "Sample Variable-Length Integer Decoding"


def test_extract_section_citations_from_body_text() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))

    section_523 = doc.section_by_id("5.2.3")
    assert section_523 is not None

    targets = {citation.target_start for citation in section_523.citations}
    assert "21.11" in targets


def test_extracts_range_section_citations(tmp_path: Path) -> None:
    tmp_doc = tmp_path / "rfc9999-test.txt"
    tmp_doc.write_text(
        (
            "Request for Comments: 9999\n\n"
            "           Test RFC Title\n\n"
            "Abstract\n\n"
            "1.  Intro\n"
            "See Section 3.1-3.3 and Section 4.2 to 4.4.\n"
        ),
        encoding="utf-8",
    )

    doc = parse_rfc_document(tmp_doc)
    section_1 = doc.section_by_id("1")
    assert section_1 is not None

    assert section_1.citations == (
        SectionCitation(target_start="3.1", target_end="3.3"),
        SectionCitation(target_start="4.2", target_end="4.4"),
    )
