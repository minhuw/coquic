from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SectionCitation:
    target_start: str
    target_end: str | None = None


@dataclass(frozen=True)
class RfcSection:
    rfc: int
    section_id: str
    title: str
    text: str
    citations: tuple[SectionCitation, ...]


@dataclass(frozen=True)
class RfcDocument:
    rfc: int
    title: str
    sections: tuple[RfcSection, ...]

    def section_by_id(self, section_id: str) -> RfcSection | None:
        for section in self.sections:
            if section.section_id == section_id:
                return section
        return None
