from __future__ import annotations

import re
from pathlib import Path

from coquic_rag.ingest.models import RfcDocument, RfcSection, SectionCitation

_RFC_NUMBER_RE = re.compile(r"Request for Comments:\s*(\d+)\b")
_TITLE_RE = re.compile(r"\n\s{2,}([^\n]+)\n\nAbstract\b")
_SECTION_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)\.\s{2,}(.+?)\s*$", re.MULTILINE)
_CITATION_RE = re.compile(
    r"\bSection\s+(\d+(?:\.\d+)*)(?:\s*(?:-|to)\s*(\d+(?:\.\d+)*))?"
)


def _extract_rfc_number(text: str) -> int:
    match = _RFC_NUMBER_RE.search(text)
    if not match:
        raise ValueError("Unable to parse RFC number")
    return int(match.group(1))


def _extract_title(text: str) -> str:
    match = _TITLE_RE.search(text)
    if not match:
        raise ValueError("Unable to parse RFC title")
    return match.group(1).strip()


def _extract_citations(section_text: str) -> tuple[SectionCitation, ...]:
    citations = []
    for match in _CITATION_RE.finditer(section_text):
        citations.append(
            SectionCitation(
                target_start=match.group(1),
                target_end=match.group(2),
            )
        )
    return tuple(citations)


def parse_rfc_document(path: Path) -> RfcDocument:
    text = path.read_text(encoding="utf-8").lstrip("\ufeff")
    rfc = _extract_rfc_number(text)
    title = _extract_title(text)

    headings = list(_SECTION_HEADING_RE.finditer(text))
    sections = []
    for index, heading in enumerate(headings):
        section_id = heading.group(1)
        section_title = heading.group(2).strip()
        start = heading.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        section_text = text[start:end].strip()
        sections.append(
            RfcSection(
                rfc=rfc,
                section_id=section_id,
                title=section_title,
                text=section_text,
                citations=_extract_citations(section_text),
            )
        )

    return RfcDocument(rfc=rfc, title=title, sections=tuple(sections))
