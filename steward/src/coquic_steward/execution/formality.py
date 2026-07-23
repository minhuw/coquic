"""Strict, read-only review-formality examination.

Reviewers report technical findings.  Formality decides only whether each
finding is relevant to the accepted task boundary.  It never edits raw review
bytes and it never schedules external work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.config import StewardConfig
from ..core.models import FormalityDisposition, TaskRecord

MAX_FORMALITY_BYTES = 64 * 1024
MAX_FINDINGS = 128
MAX_TEXT = 4_000
_DISPOSITION_KEYS = {"sourceIndex", "disposition", "rationale", "followUp"}
_FOLLOW_UP_KEYS = {"title", "kind", "worker", "rationale", "scope", "nonGoals", "validation"}
_KIND_VALUES = {"feature", "ci", "code-quality", "rfc-audit", "custom", "interop", "health"}


class FormalityError(ValueError):
    """The examination output is malformed or cannot be mapped one-to-one."""


@dataclass(frozen=True)
class FormalityDispositionRecord:
    source_index: int
    disposition: FormalityDisposition
    rationale: str
    follow_up: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "sourceIndex": self.source_index,
            "disposition": self.disposition.value,
            "rationale": self.rationale,
            "followUp": self.follow_up,
        }


@dataclass(frozen=True)
class FormalityResult:
    raw_review: Mapping[str, Any]
    dispositions: tuple[FormalityDispositionRecord, ...]
    effective_review: dict[str, Any]
    proposals: tuple[dict[str, Any], ...]
    blocking: bool
    escalated: bool

    @property
    def follow_ups(self) -> tuple[dict[str, Any], ...]:
        return self.proposals

    def as_dict(self) -> dict[str, Any]:
        return {
            "dispositions": [item.as_dict() for item in self.dispositions],
            "effectiveReview": self.effective_review,
            "proposals": list(self.proposals),
            "blocking": self.blocking,
            "escalated": self.escalated,
        }


def formality_schema_path(config: StewardConfig) -> Path:
    path = config.state_dir / "schemas" / "formality.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(FORMALITY_OUTPUT_SCHEMA, indent=2) + "\n", encoding="utf-8")
    return path


def render_formality_prompt(
    task: TaskRecord,
    review: Mapping[str, Any],
    *,
    implementation_plan: Mapping[str, Any] | None = None,
    declared_scope: Sequence[str] = (),
) -> str:
    """Render a bounded read-only examination prompt."""

    context = {
        "intent": task.spec.prompt,
        "nonGoals": task.spec.metadata.get("non_goals", []),
        "acceptedPlan": implementation_plan,
        "declaredScope": list(declared_scope),
        "rawReview": review,
    }
    return "\n".join(
        [
            "Examine the following Steward review for task-boundary formality.",
            "Do not edit files, rewrite findings, or invent findings.",
            "Return JSON with exactly one disposition for every finding index.",
            "A followUp disposition must include title, kind, worker, rationale, scope, nonGoals, and validation.",
            "Use escalate when relevance cannot be decided without a human.",
            "",
            json.dumps(context, indent=2, sort_keys=True),
        ]
    )


def parse_formality(
    message: str | bytes,
    raw_review: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> FormalityResult:
    """Parse strict JSON and build an effective review without mutating input."""

    encoded = message.encode("utf-8") if isinstance(message, str) else message
    if len(encoded) > MAX_FORMALITY_BYTES:
        raise FormalityError("formality output exceeds bounded size")
    try:
        parsed = json.loads(encoded)
    except (TypeError, json.JSONDecodeError) as exc:
        raise FormalityError("formality output is not valid JSON") from exc
    findings = _findings(raw_review)
    if not isinstance(parsed, dict) or set(parsed) != {"dispositions"}:
        raise FormalityError("formality output must contain only dispositions")
    values = parsed["dispositions"]
    if not isinstance(values, list) or len(values) != len(findings):
        raise FormalityError("formality must map every raw finding exactly once")
    records: list[FormalityDispositionRecord] = []
    seen: set[int] = set()
    for value in values:
        value = _normalise_disposition(value)
        if value is None:
            raise FormalityError("malformed finding disposition")
        index = value.get("sourceIndex")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= len(findings):
            raise FormalityError("disposition sourceIndex is out of range")
        if index in seen:
            raise FormalityError("duplicate disposition sourceIndex")
        seen.add(index)
        try:
            disposition = FormalityDisposition(value.get("disposition"))
        except ValueError as exc:
            raise FormalityError("unknown formality disposition") from exc
        rationale = value.get("rationale")
        if not _text(rationale):
            raise FormalityError("disposition rationale is required")
        follow_up = value.get("followUp")
        if disposition == FormalityDisposition.follow_up:
            follow_up = _parse_follow_up(follow_up)
        elif follow_up is not None:
            raise FormalityError("non-follow-up dispositions cannot carry proposals")
        records.append(FormalityDispositionRecord(index, disposition, rationale, follow_up))
    if seen != set(range(len(findings))):
        raise FormalityError("formality omitted one or more source findings")
    records.sort(key=lambda item: item.source_index)
    result = build_effective_review(raw_review, records)
    return result


parse_formality_output = parse_formality
parse_formality_json = parse_formality
validate_formality = parse_formality


def build_effective_review(
    raw_review: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    dispositions: Sequence[FormalityDispositionRecord | Mapping[str, Any]],
) -> FormalityResult:
    findings = _findings(raw_review)
    records = tuple(_record(item) for item in dispositions)
    if len(records) != len(findings) or {item.source_index for item in records} != set(range(len(findings))):
        raise FormalityError("effective review requires one disposition per finding")
    selected: list[Any] = []
    proposals: list[dict[str, Any]] = []
    blocking = False
    escalated = False
    for item in records:
        finding = findings[item.source_index]
        if item.disposition in {FormalityDisposition.required, FormalityDisposition.revert}:
            selected.append(finding)
            blocking = True
        elif item.disposition == FormalityDisposition.escalate:
            selected.append(finding)
            blocking = True
            escalated = True
        elif item.disposition == FormalityDisposition.follow_up:
            if item.follow_up is None:
                raise FormalityError("follow-up disposition is missing proposal")
            proposals.append(dict(item.follow_up))
        elif item.disposition != FormalityDisposition.reject:
            raise FormalityError("unsupported disposition")
    source = dict(raw_review) if isinstance(raw_review, Mapping) else {"findings": list(raw_review)}
    effective = {
        "verdict": "block" if blocking else "approve",
        "summary": str(source.get("summary", "")),
        "findings": selected,
        "validation_gaps": list(source.get("validation_gaps", [])),
        "remaining_risk": str(source.get("remaining_risk", "")),
    }
    return FormalityResult(
        raw_review=source,
        dispositions=records,
        effective_review=effective,
        proposals=tuple(proposals),
        blocking=blocking,
        escalated=escalated,
    )


effective_review = build_effective_review
effective_review_from_formality = build_effective_review


def _findings(raw_review: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(raw_review, Mapping):
        findings = raw_review.get("findings")
    else:
        findings = raw_review
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise FormalityError("raw review findings are malformed")
    if not all(isinstance(item, Mapping) for item in findings):
        raise FormalityError("raw review findings must be objects")
    return list(findings)


def _record(value: FormalityDispositionRecord | Mapping[str, Any]) -> FormalityDispositionRecord:
    if isinstance(value, FormalityDispositionRecord):
        return value
    value = _normalise_disposition(value)
    if value is None:
        raise FormalityError("malformed disposition record")
    try:
        disposition = FormalityDisposition(value["disposition"])
    except (KeyError, ValueError) as exc:
        raise FormalityError("invalid disposition record") from exc
    follow_up = value.get("followUp")
    if disposition == FormalityDisposition.follow_up:
        follow_up = _parse_follow_up(follow_up)
    elif follow_up is not None:
        raise FormalityError("unexpected follow-up proposal")
    return FormalityDispositionRecord(
        int(value["sourceIndex"]), disposition, str(value["rationale"]), follow_up
    )


def _normalise_disposition(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if set(value) == _DISPOSITION_KEYS:
        return dict(value)
    aliases = {"source_index", "disposition", "rationale", "follow_up"}
    if set(value) == aliases:
        return {
            "sourceIndex": value["source_index"],
            "disposition": value["disposition"],
            "rationale": value["rationale"],
            "followUp": value["follow_up"],
        }
    return None


def _parse_follow_up(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _FOLLOW_UP_KEYS:
        raise FormalityError("followUp must use the complete structured shape")
    for key in ("title", "kind", "worker", "rationale"):
        if not _text(value.get(key)):
            raise FormalityError(f"followUp.{key} is required")
    if value["kind"] not in _KIND_VALUES:
        raise FormalityError("followUp.kind is invalid")
    for key in ("scope", "nonGoals", "validation"):
        values = value.get(key)
        if not isinstance(values, list) or not values or len(values) > 32 or not all(_text(item) for item in values):
            raise FormalityError(f"followUp.{key} must be a non-empty bounded list")
    return dict(value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= MAX_TEXT


FORMALITY_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "dispositions": {
            "type": "array",
            "maxItems": MAX_FINDINGS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "sourceIndex": {"type": "integer", "minimum": 0},
                    "disposition": {"type": "string", "enum": [item.value for item in FormalityDisposition]},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT},
                    "followUp": {"type": ["object", "null"]},
                },
                "required": sorted(_DISPOSITION_KEYS),
            },
        }
    },
    "required": ["dispositions"],
}
