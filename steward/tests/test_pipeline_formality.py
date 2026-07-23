from __future__ import annotations

import json

import pytest

from coquic_steward.execution.formality import FormalityError, parse_formality


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
