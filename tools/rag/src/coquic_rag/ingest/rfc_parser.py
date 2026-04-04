from __future__ import annotations

import re
from pathlib import Path

from coquic_rag.ingest.models import SourceDocument, SourceSection, SectionCitation

_RFC_NUMBER_RE = re.compile(r"Request for Comments:\s*(\d+)\b")
_DRAFT_NAME_RE = re.compile(r"^\s*(draft-[a-z0-9-]+-\d+)\s*$", re.MULTILINE)
_SECTION_HEADING_RE = re.compile(
    r"^(?:(?:Appendix\s+(?P<appendix>[A-Z]))|(?P<section>\d+(?:\.\d+)*|[A-Z](?:\.\d+)*))\.\s{2,}(?P<title>.+?)\s*$",
    re.MULTILINE,
)
_CITATION_RE = re.compile(
    r"\b(?:Section\s+(?P<section>\d+(?:\.\d+)*)|Appendix\s+(?P<appendix>[A-Z](?:\.\d+)*))"
    r"(?:\s*(?:-|to)\s*(?P<range_end>\d+(?:\.\d+)*|[A-Z](?:\.\d+)*))?"
)


def _extract_rfc_number(text: str) -> int:
    match = _RFC_NUMBER_RE.search(text)
    if not match:
        raise ValueError("Unable to identify source document as RFC or Internet-Draft")
    return int(match.group(1))


def _extract_draft_name(front_matter: str) -> str:
    match = _DRAFT_NAME_RE.search(front_matter)
    if not match:
        raise ValueError("Unable to identify source document as RFC or Internet-Draft")
    return match.group(1)


def _extract_title(front_matter: str) -> str:
    paragraphs = [p for p in re.split(r"\n\s*\n", front_matter.strip()) if p.strip()]
    for paragraph in reversed(paragraphs):
        lines = [line.strip() for line in paragraph.splitlines() if line.strip()]
        filtered_lines = [line for line in lines if not _DRAFT_NAME_RE.fullmatch(line)]
        if not filtered_lines:
            continue
        return " ".join(filtered_lines)
    raise ValueError("Unable to parse source document title")


def _extract_citations(section_text: str) -> tuple[SectionCitation, ...]:
    citations = []
    for match in _CITATION_RE.finditer(section_text):
        target_start = match.group("section") or match.group("appendix")
        citations.append(
            SectionCitation(
                target_start=target_start,
                target_end=match.group("range_end"),
            )
        )
    return tuple(citations)


def parse_source_document(path: Path) -> SourceDocument:
    text = path.read_text(encoding="utf-8").lstrip("\ufeff")
    front_matter, _, _ = text.partition("\n\nAbstract")
    if not front_matter:
        raise ValueError("Unable to identify source document as RFC or Internet-Draft")

    rfc_match = _RFC_NUMBER_RE.search(front_matter)
    draft_match = _DRAFT_NAME_RE.search(front_matter)

    if rfc_match is not None:
        doc_kind = "rfc"
        rfc_number = _extract_rfc_number(front_matter)
        draft_name = None
        doc_id = f"rfc{rfc_number}"
    elif draft_match is not None:
        doc_kind = "internet-draft"
        draft_name = _extract_draft_name(front_matter)
        rfc_number = None
        doc_id = draft_name
    else:
        raise ValueError("Unable to identify source document as RFC or Internet-Draft")

    title = _extract_title(front_matter)

    headings = list(_SECTION_HEADING_RE.finditer(text))
    sections = []
    for index, heading in enumerate(headings):
        section_id = heading.group("appendix") or heading.group("section")
        section_title = heading.group("title").strip()
        start = heading.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        section_text = text[start:end].strip()
        sections.append(
            SourceSection(
                doc_id=doc_id,
                section_id=section_id,
                title=section_title,
                text=section_text,
                citations=_extract_citations(section_text),
                doc_kind=doc_kind,
                rfc_number=rfc_number,
                draft_name=draft_name,
            )
        )

    return SourceDocument(
        doc_id=doc_id,
        doc_kind=doc_kind,
        title=title,
        sections=tuple(sections),
        rfc_number=rfc_number,
        draft_name=draft_name,
    )


def parse_rfc_document(path: Path) -> SourceDocument:
    document = parse_source_document(path)
    if document.doc_kind != "rfc":
        raise ValueError("parse_rfc_document only accepts RFC input")
    return document
