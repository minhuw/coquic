from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.config import StewardConfig
from ..core.models import TaskRecord


def render_review_prompt(task: TaskRecord, config: StewardConfig) -> str:
    return "\n".join(
        [
            "Review the current uncommitted changes in this Steward task worktree.",
            "",
            f"Task: {task.id} - {task.spec.title}",
            f"Kind: {task.spec.kind}",
            f"Worker: {task.spec.worker}",
            "",
            "Original task prompt:",
            task.spec.prompt,
            "",
            "Review policy:",
            "- Review only the uncommitted changes in this worktree.",
            "- Treat generated state, build outputs, vendored cache updates, unrelated rewrites, missing validation, and unsafe protocol behavior as blocking when relevant.",
            "- Approve only when the patch is correct, scoped, validated, and ready for Steward integration.",
            "- Return only JSON matching the provided schema.",
            "",
            _render_skills(config),
        ]
    ).strip()


def review_schema_path(config: StewardConfig) -> Path:
    path = config.state_dir / "schemas" / "review.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(REVIEW_OUTPUT_SCHEMA, indent=2), encoding="utf-8")
    return path


def parse_review(message: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    verdict = parsed.get("verdict")
    if verdict not in {"approve", "block"}:
        return None
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        return None
    if _is_meta_review_failure(parsed):
        return None
    return parsed


def review_approved(review: dict[str, Any]) -> bool:
    return review.get("verdict") == "approve" and not review.get("findings")


def summarize_review(review: dict[str, Any]) -> str:
    summary = str(review.get("summary", "")).strip()
    if summary:
        return summary
    verdict = str(review.get("verdict", "block"))
    count = len(review.get("findings", []))
    return f"review {verdict} with {count} finding(s)"


def _is_meta_review_failure(review: dict[str, Any]) -> bool:
    if review.get("verdict") != "block":
        return False
    findings = review.get("findings")
    if not isinstance(findings, list) or not findings:
        return False
    has_empty_file_finding = any(
        isinstance(finding, dict) and not str(finding.get("file", "")).strip()
        for finding in findings
    )
    if not has_empty_file_finding:
        return False
    status_text = " ".join(
        [
            str(review.get("summary", "")),
            str(review.get("remaining_risk", "")),
            *[
                str(gap)
                for gap in review.get("validation_gaps", [])
                if isinstance(gap, str)
            ],
        ]
    ).lower()
    findings_text = " ".join(
        " ".join(
            str(finding.get(key, ""))
            for key in ("title", "detail", "recommendation")
        )
        for finding in findings
        if isinstance(finding, dict)
    ).lower()
    return "review not completed" in status_text and any(
        marker in findings_text
        for marker in (
            "invalid premature response",
            "accidentally attempted final response",
            "continuing review would be required",
            "ignore this response",
        )
    )


def render_review_revision_prompt(task: TaskRecord, review: dict[str, Any]) -> str:
    return "\n".join(
        [
            "A Steward review blocked your current patch.",
            "",
            f"Task: {task.id} - {task.spec.title}",
            "",
            "Address the review findings in the existing worktree.",
            "Keep the original task scope. Do not commit, push, or change generated state.",
            "After editing, run the relevant local validation commands and leave the revised patch in the worktree.",
            "",
            "Review JSON:",
            json.dumps(review, indent=2, sort_keys=True),
        ]
    ).strip()


def _render_skills(config: StewardConfig) -> str:
    path = config.repo_root / ".agents" / "skills" / "quic-rag" / "SKILL.md"
    if not path.exists():
        return f"Repo review skill missing at {path}."
    return "Repo review skill:\n" + path.read_text(encoding="utf-8").strip()


REVIEW_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "block"]},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "title": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                    "detail": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
                "required": [
                    "severity",
                    "title",
                    "file",
                    "line",
                    "detail",
                    "recommendation",
                ],
            },
        },
        "validation_gaps": {
            "type": "array",
            "items": {"type": "string"},
        },
        "remaining_risk": {"type": "string"},
    },
    "required": [
        "verdict",
        "summary",
        "findings",
        "validation_gaps",
        "remaining_risk",
    ],
}
