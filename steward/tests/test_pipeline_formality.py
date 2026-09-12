from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator, ValidationError

from coquic_steward.execution.formality import (
    FORMALITY_OUTPUT_SCHEMA,
    MAX_TEXT,
    FormalityError,
    parse_formality,
)


def _review(count: int = 5) -> dict[str, object]:
    return {
        "verdict": "block",
        "summary": "findings",
        "findings": [
            {
                "severity": "medium",
                "title": f"finding {index}",
                "file": "README.md",
                "line": index + 1,
                "detail": "detail",
                "recommendation": "recommendation",
            }
            for index in range(count)
        ],
        "validation_gaps": [],
        "remaining_risk": "",
    }


def _disposition(index: int, value: str, follow_up: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "sourceIndex": index,
        "disposition": value,
        "rationale": "bounded rationale",
        "followUp": follow_up,
    }


def test_formality_maps_every_disposition_and_keeps_raw_review() -> None:
    raw = _review()
    proposal = {
        "title": "Track prerequisite",
        "kind": "custom",
        "worker": "custom",
        "rationale": "outside the task",
        "scope": ["the prerequisite"],
        "nonGoals": ["this patch"],
        "validation": ["run focused tests"],
    }
    message = json.dumps(
        {
            "dispositions": [
                _disposition(0, "required"),
                _disposition(1, "revert"),
                _disposition(2, "followUp", proposal),
                _disposition(3, "reject"),
                _disposition(4, "escalate"),
            ]
        }
    )

    Draft202012Validator.check_schema(FORMALITY_OUTPUT_SCHEMA)
    Draft202012Validator(FORMALITY_OUTPUT_SCHEMA).validate(json.loads(message))
    result = parse_formality(message, raw)

    assert raw["findings"]
    assert result.blocking is True
    assert result.escalated is True
    assert result.effective_review["verdict"] == "block"
    assert len(result.effective_review["findings"]) == 3
    assert result.proposals == (proposal,)


def test_follow_up_only_is_non_blocking() -> None:
    raw = _review(1)
    proposal = {
        "title": "Track prerequisite",
        "kind": "ci",
        "worker": "ci-doctor",
        "rationale": "outside",
        "scope": ["CI"],
        "nonGoals": ["source patch"],
        "validation": ["CI test"],
    }
    result = parse_formality(
        json.dumps({"dispositions": [_disposition(0, "followUp", proposal)]}), raw
    )
    assert result.blocking is False
    assert result.effective_review["verdict"] == "approve"


@pytest.mark.parametrize("verdict", ["block", "revise"])
def test_evidence_level_block_without_findings_remains_blocking(verdict: str) -> None:
    raw = _review(0)
    raw["verdict"] = verdict
    raw["validation_gaps"] = ["required validation evidence is unavailable"]
    raw["remaining_risk"] = "the patch has not passed its required gates"

    result = parse_formality('{"dispositions": []}', raw)

    assert result.blocking is True
    assert result.effective_review["verdict"] == "block"
    assert result.effective_review["validation_gaps"] == raw["validation_gaps"]
    assert result.effective_review["remaining_risk"] == raw["remaining_risk"]


@pytest.mark.parametrize(
    "message",
    [
        json.dumps({"dispositions": []}),
        json.dumps({"dispositions": [_disposition(0, "required"), _disposition(0, "reject")]}),
        json.dumps({"dispositions": [{"sourceIndex": 0, "disposition": "required", "rationale": "x", "followUp": None, "extra": 1}]}),
    ],
)
def test_formality_rejects_omitted_duplicate_and_extra_mappings(message: str) -> None:
    with pytest.raises(FormalityError):
        parse_formality(message, _review(1))


@pytest.fixture
def follow_up() -> dict[str, object]:
    return {
        "title": "Track prerequisite",
        "kind": "ci",
        "worker": "ci-doctor",
        "rationale": "outside",
        "scope": ["CI"],
        "nonGoals": ["source patch"],
        "validation": ["CI test"],
    }


@pytest.mark.parametrize("kind", ["feature", "ci", "code-quality", "rfc-audit", "custom", "interop", "health"])
def test_formality_schema_accepts_complete_follow_up(follow_up: dict[str, object], kind: str) -> None:
    follow_up["kind"] = kind
    message = {"dispositions": [_disposition(0, "followUp", follow_up)]}
    Draft202012Validator(FORMALITY_OUTPUT_SCHEMA).validate(message)
    assert parse_formality(json.dumps(message), _review(1)).proposals == (follow_up,)


@pytest.mark.parametrize("key", ["title", "kind", "worker", "rationale", "scope", "nonGoals", "validation"])
def test_formality_schema_requires_every_follow_up_field(follow_up: dict[str, object], key: str) -> None:
    del follow_up[key]
    message = {"dispositions": [_disposition(0, "followUp", follow_up)]}
    with pytest.raises(ValidationError):
        Draft202012Validator(FORMALITY_OUTPUT_SCHEMA).validate(message)
    with pytest.raises(FormalityError):
        parse_formality(json.dumps(message), _review(1))


@pytest.mark.parametrize(
    ("key", "value"),
    [(key, value) for key in ("title", "worker", "rationale") for value in ("", "x" * (MAX_TEXT + 1), 1)]
    + [(key, value) for key in ("scope", "nonGoals", "validation") for value in ([], ["x"] * 33, [""], ["x" * (MAX_TEXT + 1)], [1], "x")]
    + [("kind", "unknown"), ("extra", "unexpected")],
)
def test_formality_schema_rejects_invalid_follow_up_fields(
    follow_up: dict[str, object], key: str, value: object
) -> None:
    follow_up[key] = value
    message = {"dispositions": [_disposition(0, "followUp", follow_up)]}
    with pytest.raises(ValidationError):
        Draft202012Validator(FORMALITY_OUTPUT_SCHEMA).validate(message)
    with pytest.raises(FormalityError):
        parse_formality(json.dumps(message), _review(1))


@pytest.mark.parametrize("disposition", ["required", "revert", "reject", "escalate"])
def test_non_follow_up_dispositions_still_reject_proposals(
    follow_up: dict[str, object], disposition: str
) -> None:
    with pytest.raises(FormalityError, match="non-follow-up dispositions cannot carry proposals"):
        parse_formality(json.dumps({"dispositions": [_disposition(0, disposition, follow_up)]}), _review(1))


def test_follow_up_disposition_still_requires_proposal() -> None:
    with pytest.raises(FormalityError, match="complete structured shape"):
        parse_formality(json.dumps({"dispositions": [_disposition(0, "followUp")]}), _review(1))
