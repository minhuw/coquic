from __future__ import annotations

import fnmatch
import json
from pathlib import Path, PurePosixPath
from typing import Any

from ..core.config import StewardConfig
from ..core.models import TaskRecord
from .worktree import FORBIDDEN_PATH_PARTS

MAX_PLAN_RUN_ATTEMPTS = 2
MAX_PLAN_BYTES = 32_768
MAX_LIST_ITEMS = 32
MAX_TEXT_LENGTH = 4_000
_PLAN_KEYS = {
    "summary",
    "assumptions",
    "steps",
    "validation",
    "risks",
    "non_goals",
}
_STEP_KEYS = {"title", "detail", "files"}
_ADDITIONAL_FORBIDDEN_PARTS = {"build", "out", "plans", "zig-out"}
_STRING_LIST_SCHEMA = {
    "type": "array",
    "maxItems": MAX_LIST_ITEMS,
    "items": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
}


def implementation_plan_required(task: TaskRecord) -> bool:
    """Feature pipelines require a structured plan; fixes may use task intent."""

    return str(task.spec.workflow) == "feature" or str(task.spec.kind) == "feature"


def deterministic_plan_skip_reason(task: TaskRecord) -> str:
    """Stable evidence for an eligible fix that intentionally skips planning."""

    if implementation_plan_required(task):
        raise ValueError("feature tasks cannot skip implementation planning")
    return "task intent is already executable and workflow is narrowly scoped"


# Compatibility aliases used by callers that describe the decision as a gate.
plan_required = implementation_plan_required
plan_skip_reason = deterministic_plan_skip_reason


def implementation_plan_schema_path(config: StewardConfig) -> Path:
    path = config.state_dir / "schemas" / "implementation-plan.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(IMPLEMENTATION_PLAN_SCHEMA, indent=2), encoding="utf-8")
    return path


def parse_implementation_plan(
    message: str, task: TaskRecord, config: StewardConfig
) -> dict[str, Any] | None:
    if len(message.encode("utf-8")) > MAX_PLAN_BYTES:
        return None
    try:
        plan = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(plan, dict) or set(plan) != _PLAN_KEYS:
        return None
    if not _bounded_text(plan.get("summary")):
        return None
    for key in ("assumptions", "validation", "risks", "non_goals"):
        values = plan.get(key)
        if not _bounded_text_list(values, required=key == "validation"):
            return None
    steps = plan.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_LIST_ITEMS:
        return None
    for step in steps:
        if not isinstance(step, dict) or set(step) != _STEP_KEYS:
            return None
        if not _bounded_text(step.get("title")) or not _bounded_text(step.get("detail")):
            return None
        files = step.get("files")
        if not isinstance(files, list) or len(files) > MAX_LIST_ITEMS:
            return None
        if any(
            not isinstance(path, str) or not _allowed_plan_path(path, task, config)
            for path in files
        ):
            return None
    return plan


def save_implementation_plan(
    config: StewardConfig, task_id: str, run: int, plan: dict[str, Any]
) -> Path:
    path = config.implementation_plans_dir / task_id / f"plan-{run}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _bounded_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= MAX_TEXT_LENGTH


def _bounded_text_list(value: object, *, required: bool) -> bool:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        return False
    if required and not value:
        return False
    return all(_bounded_text(item) for item in value)


def _allowed_plan_path(path_text: str, task: TaskRecord, config: StewardConfig) -> bool:
    normalized = path_text.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        return False
    forbidden = FORBIDDEN_PATH_PARTS | _ADDITIONAL_FORBIDDEN_PARTS
    if any(part in forbidden for part in path.parts):
        return False
    return not any(
        _matches(normalized, pattern)
        for pattern in config.path_policy.frozen_for_kind(task.spec.kind)
    )


def _matches(path: str, pattern: str) -> bool:
    normalized = pattern.strip().replace("\\", "/").rstrip("/")
    if any(char in normalized for char in "*?["):
        return fnmatch.fnmatchcase(path, normalized)
    return path == normalized or path.startswith(normalized + "/")


IMPLEMENTATION_PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
        "assumptions": _STRING_LIST_SCHEMA,
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_LIST_ITEMS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
                    "detail": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
                    "files": {
                        "type": "array",
                        "maxItems": MAX_LIST_ITEMS,
                        "items": {"type": "string", "minLength": 1, "maxLength": 500},
                    },
                },
                "required": ["title", "detail", "files"],
            },
        },
        "validation": {**_STRING_LIST_SCHEMA, "minItems": 1},
        "risks": _STRING_LIST_SCHEMA,
        "non_goals": _STRING_LIST_SCHEMA,
    },
    "required": sorted(_PLAN_KEYS),
}
