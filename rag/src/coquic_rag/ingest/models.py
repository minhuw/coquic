from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DocKind = Literal["rfc", "internet-draft"]


@dataclass(frozen=True)
class SectionCitation:
    target_start: str
    target_end: str | None = None


@dataclass(frozen=True)
class SourceSection:
    doc_id: str
    section_id: str
    title: str
    text: str
    citations: tuple[SectionCitation, ...]
    doc_kind: DocKind
    rfc_number: int | None = None
    draft_name: str | None = None

    @property
    def rfc(self) -> int:
        if self.rfc_number is None:
            raise AttributeError("Source section is not an RFC")
        return self.rfc_number


@dataclass(frozen=True)
class SourceDocument:
    doc_id: str
    doc_kind: DocKind
    title: str
    sections: tuple[SourceSection, ...]
    rfc_number: int | None = None
    draft_name: str | None = None

    @property
    def rfc(self) -> int:
        if self.rfc_number is None:
            raise AttributeError("Source document is not an RFC")
        return self.rfc_number

    def section_by_id(self, section_id: str) -> SourceSection | None:
        for section in self.sections:
            if section.section_id == section_id:
                return section
        return None


# Compatibility aliases for existing call sites.
RfcSection = SourceSection
RfcDocument = SourceDocument
