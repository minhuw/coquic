from __future__ import annotations

from pathlib import Path

import pytest

from coquic_rag.ingest.models import SectionCitation
from coquic_rag.ingest.rfc_parser import parse_rfc_document, parse_source_document


def test_parse_rfc9000_core_metadata_and_sections() -> None:
    doc = parse_source_document(Path("docs/rfc/rfc9000.txt"))

    assert doc.doc_id == "rfc9000"
    assert doc.doc_kind == "rfc"
    assert doc.rfc_number == 9000
    assert doc.draft_name is None
    assert doc.title == "QUIC: A UDP-Based Multiplexed and Secure Transport"

    section_182 = doc.section_by_id("18.2")
    assert section_182 is not None
    assert section_182.doc_id == "rfc9000"
    assert section_182.title == "Transport Parameter Definitions"
    assert section_182.section_id == "18.2"


def test_parse_draft_qlog_main_schema_core_metadata_and_sections() -> None:
    doc = parse_source_document(Path("docs/rfc/draft-ietf-quic-qlog-main-schema-13.txt"))

    assert doc.doc_id == "draft-ietf-quic-qlog-main-schema-13"
    assert doc.doc_kind == "internet-draft"
    assert doc.rfc_number is None
    assert doc.draft_name == "draft-ietf-quic-qlog-main-schema-13"
    assert doc.title == "qlog: Structured Logging for Network Protocols"

    section_1 = doc.section_by_id("1")
    assert section_1 is not None
    assert section_1.title == "Introduction"


def test_parse_source_document_rejects_unknown_text(tmp_path: Path) -> None:
    bad_doc = tmp_path / "unknown-source.txt"
    bad_doc.write_text(
        "This is not an RFC and not an Internet-Draft.\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError, match="Unable to identify source document as RFC or Internet-Draft"
    ):
        parse_source_document(bad_doc)


def test_parse_source_document_preserves_wrapped_title(tmp_path: Path) -> None:
    wrapped = tmp_path / "rfc9998-wrapped-title.txt"
    wrapped.write_text(
        (
            "Request for Comments: 9998\n\n"
            "           Wrapped RFC Title First Line\n"
            "           Wrapped RFC Title Second Line\n\n"
            "Abstract\n\n"
            "1.  Intro\n"
            "Body text.\n"
        ),
        encoding="utf-8",
    )

    doc = parse_source_document(wrapped)
    assert doc.title == "Wrapped RFC Title First Line Wrapped RFC Title Second Line"


def test_parse_rfc_document_rejects_draft_fixture() -> None:
    with pytest.raises(ValueError, match="parse_rfc_document only accepts RFC input"):
        parse_rfc_document(Path("docs/rfc/draft-ietf-quic-qlog-main-schema-13.txt"))


def test_parse_rfc_document_accepts_rfc_fixture() -> None:
    doc = parse_rfc_document(Path("docs/rfc/rfc9000.txt"))
    assert doc.rfc == 9000


def test_extract_section_citations_from_body_text() -> None:
    doc = parse_source_document(Path("docs/rfc/rfc9000.txt"))

    section_523 = doc.section_by_id("5.2.3")
    assert section_523 is not None

    targets = {citation.target_start for citation in section_523.citations}
    assert "21.11" in targets


def test_extract_appendix_citation_from_rfc9000_fixture() -> None:
    doc = parse_source_document(Path("docs/rfc/rfc9000.txt"))

    section_1342 = doc.section_by_id("13.4.2")
    assert section_1342 is not None

    assert SectionCitation(target_start="A.4", target_end=None) in section_1342.citations


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

    doc = parse_source_document(tmp_doc)
    section_1 = doc.section_by_id("1")
    assert section_1 is not None

    assert section_1.citations == (
        SectionCitation(target_start="3.1", target_end="3.3"),
        SectionCitation(target_start="4.2", target_end="4.4"),
    )
