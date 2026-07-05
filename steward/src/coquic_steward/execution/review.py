from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.config import StewardConfig
from ..core.models import TaskRecord

REVISION_SCOPE_CONTROL = """\
Revision scope control:
- Fix only findings that can be addressed within the original task boundary.
- Do not add unrelated tooling changes, generated-state updates, new backend
  infrastructure, broad public API/binding rewrites, or speculative hardening to
  satisfy a review finding.
- If a finding is valid but requires broader prerequisite work, reduce or keep
  the current patch to a safe scoped slice and report a follow-up task proposal
  instead of implementing that prerequisite here.
- Follow-up task proposals must use this format in the final report:
  Follow-up task proposals:
  - Title: <imperative title>
    Kind: <feature|ci|code-quality|rfc-audit|custom>
    Worker: <recommended steward worker>
    Rationale: <why this is outside the current task>
    Scope: <files/subsystems and explicit non-goals>
    Validation: <commands/tests>
"""


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


def render_review_revision_prompt(
    task: TaskRecord, review: dict[str, Any], config: StewardConfig | None = None
) -> str:
    lines = [
        "A Steward review blocked your current patch.",
        "",
        f"Task: {task.id} - {task.spec.title}",
        "",
        "Address the review findings in the existing worktree.",
        "Keep the original task scope. Do not commit, push, or change generated state.",
        REVISION_SCOPE_CONTROL,
        "After editing, run the relevant local validation commands and leave the revised patch in the worktree.",
    ]
    frozen = _render_frozen_paths(task, config)
    if frozen:
        lines.extend(["", "Frozen path policy:", frozen])
    lines.extend(
        [
            "",
            "Review JSON:",
            json.dumps(review, indent=2, sort_keys=True),
        ]
    )
    return "\n".join(lines).strip()


def _render_frozen_paths(
    task: TaskRecord, config: StewardConfig | None
) -> str:
    if config is None:
        return ""
    patterns = config.path_policy.frozen_for_kind(task.spec.kind)
    if not patterns:
        return ""
    lines = [
        "Do not modify these repository paths for this task. Steward will block "
        "patches that change them.",
    ]
    lines.extend(f"- {pattern}" for pattern in patterns)
    return "\n".join(lines)


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
