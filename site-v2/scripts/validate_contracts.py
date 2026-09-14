#!/usr/bin/env python3
"""Validate V2 schemas, examples, SSE data records, and Markdown links."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
EXAMPLE_DIR = ROOT / "examples"
CLOUD_EXAMPLE_DIR = EXAMPLE_DIR / "steward-cloud"

EXAMPLE_TARGETS = {
    "coverage-snapshot.json": ("evidence.schema.json", "coverageSnapshot"),
    "interop-snapshot.json": ("evidence.schema.json", "interopSnapshot"),
    "performance-snapshot.json": ("evidence.schema.json", "performanceSnapshot"),
    "scenario-catalog.json": ("catalog.schema.json", "scenarioCatalog"),
    "steward-daily-summary.json": ("steward.schema.json", "dailySummary"),
    "steward-growth-summary.json": ("steward.schema.json", "growthSummary"),
    "steward-live-snapshot.json": ("steward-live.schema.json", "snapshot"),
    "transcript-search.json": ("transcript.schema.json", "searchResponse"),
    "workbench-command.json": ("workbench.schema.json", "command"),
    "steward-cloud/redacted-publication.json": ("steward-cloud.schema.json", "taskDetailResponse"),
    "steward-cloud/active-after-planning.json": ("steward-cloud.schema.json", "taskDetailResponse"),
    "steward-cloud/complete-trajectory-clean.json": ("steward-cloud.schema.json", "completeTrajectoryResponse"),
    "steward-cloud/complete-trajectory-redacted-multimodal.json": ("steward-cloud.schema.json", "completeTrajectoryResponse"),
}


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_json_contracts() -> int:
    schemas = {path.name: read_json(path) for path in sorted(SCHEMA_DIR.glob("*.json"))}
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    failures = 0

    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as error:  # jsonschema provides detailed context.
            failures += 1
            print(f"schema {name}: {error}")

    for example_name, (schema_name, definition) in EXAMPLE_TARGETS.items():
        schema = schemas[schema_name]
        target = {"$ref": f"{schema['$id']}#/$defs/{definition}"}
        validator = Draft202012Validator(
            target, registry=registry, format_checker=FormatChecker()
        )
        errors = sorted(
            validator.iter_errors(read_json(EXAMPLE_DIR / example_name)),
            key=lambda error: list(error.path),
        )
        for error in errors:
            failures += 1
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            print(f"example {example_name} at {location}: {error.message}")

    qa_schema = schemas["qa.schema.json"]
    qa_target = {"$ref": f"{qa_schema['$id']}#/$defs/streamEvent"}
    qa_validator = Draft202012Validator(
        qa_target,
        registry=registry,
        format_checker=FormatChecker(),
    )
    for line_number, line in enumerate(
        (EXAMPLE_DIR / "qa-stream.sse").read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.startswith("data: "):
            continue
        for error in qa_validator.iter_errors(json.loads(line[6:])):
            failures += 1
            print(f"example qa-stream.sse line {line_number}: {error.message}")

    return failures


_CLOUD_PRIVATE_KEY = re.compile(
    r"(?:private|secret|credential|password|authorization|apikey|presign|signed|scanner|"
    r"filesystem|file[_-]?path|endpoint|uri|url|bucket|object[_-]?key|token|raw|direct)",
    re.IGNORECASE,
)
_CLOUD_PRIVATE_VALUE = re.compile(
    r"(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?)://|"
    r"(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]?key)?|url|path)(?:$|[-_])",
    re.IGNORECASE,
)
_CLOUD_OBJECT_KEY = re.compile(
    r"v1/(?:tasks/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/objects/sha256|"
    r"originals/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/sha256)/"
)
_CLOUD_LOCATOR = re.compile(r"(?:^|[\s\"'([{<>=,:;])/(?:[^\s/]|$)")
_CLOUD_SAME_ORIGIN_HREF = re.compile(
    r"^/api/steward/tasks/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/artifact\?path="
    r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$'()*+,;=@-])+$"
)
_CLOUD_PUBLIC_FIELDS = {
    "cachedTokens",
    "promptTokens",
    "completionTokens",
    "promptTokenIds",
    "completionTokenIds",
    "totalPromptTokens",
    "totalCompletionTokens",
    "totalCachedTokens",
}


def _cloud_public_scan(value: object, path: str = "", reject_object_keys: bool = False) -> int:
    failures = 0
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else key
            if (
                _CLOUD_PRIVATE_KEY.search(key)
                and key not in {"logicalPath", "publicKey"}
                and key not in _CLOUD_PUBLIC_FIELDS
            ):
                print(f"cloud {child_path}: private field is not public")
                failures += 1
            failures += _cloud_public_scan(item, child_path, reject_object_keys)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures += _cloud_public_scan(item, f"{path}[{index}]", reject_object_keys)
    elif isinstance(value, str):
        if (
            not (path.endswith(".href") and _CLOUD_SAME_ORIGIN_HREF.fullmatch(value))
            and (
                _CLOUD_LOCATOR.search(value)
                or _CLOUD_PRIVATE_VALUE.search(value)
                or (reject_object_keys and not path.endswith(".publicKey") and _CLOUD_OBJECT_KEY.search(value))
            )
        ):
            print(f"cloud {path}: private locator value is not public")
            failures += 1
    return failures


def validate_complete_trajectory_examples() -> int:
    failures = 0
    for name in (
        "complete-trajectory-clean.json",
        "complete-trajectory-redacted-multimodal.json",
    ):
        response = read_json(CLOUD_EXAMPLE_DIR / name)
        data = response.get("data", {})
        if response.get("schemaVersion") != "4.0" or not isinstance(data, dict):
            failures += 1
            print(f"cloud {name}: complete trajectory must use schema version 4.0")
            continue
        task_id = data.get("taskId")
        steps = data.get("steps", [])
        artifacts = data.get("artifacts", [])
        if not isinstance(task_id, str) or not isinstance(steps, list) or not isinstance(artifacts, list):
            failures += 1
            print(f"cloud {name}: display model metadata is malformed")
            continue
        if data.get("metadata", {}).get("artifacts") != artifacts:
            failures += 1
            print(f"cloud {name}: metadata artifacts must match display artifacts")
        expected_steps = list(range(1, len(steps) + 1))
        actual_steps = [item.get("stepId") for item in steps if isinstance(item, dict)]
        if actual_steps != expected_steps:
            failures += 1
            print(f"cloud {name}: steps must be source ordered")
        anchors = [item.get("anchor") for item in steps if isinstance(item, dict)]
        if len(anchors) != len(set(anchors)):
            failures += 1
            print(f"cloud {name}: step anchors must be unique")
        disclosure = data.get("disclosure")
        if disclosure not in (
            {"redactionApplied": False, "originalRetained": True},
            {"redactionApplied": True, "originalRetained": True},
        ):
            failures += 1
            print(f"cloud {name}: disclosure must contain only public booleans")
        if name.endswith("redacted-multimodal.json") and disclosure != {"redactionApplied": True, "originalRetained": True}:
            failures += 1
            print(f"cloud {name}: multimodal fixture must disclose redaction")
        failures += _cloud_public_scan(response, name, True)
    return failures


def validate_steward_cloud_examples() -> int:
    failures = 0
    for name in ("redacted-publication.json", "active-after-planning.json"):
        response = read_json(CLOUD_EXAMPLE_DIR / name)
        data = response.get("data", {})
        task = data.get("task", {}) if isinstance(data, dict) else {}
        runs = data.get("runs", []) if isinstance(data, dict) else []
        artifacts = data.get("artifacts", []) if isinstance(data, dict) else []
        if not isinstance(task, dict) or not isinstance(runs, list) or not isinstance(artifacts, list):
            failures += 1
            print(f"cloud {name}: task, runs, and artifacts must be objects/arrays")
            continue
        if task.get("completeness") != "complete":
            failures += 1
            print(f"cloud {name}: publication must be complete")
        if task.get("eventCount") != len(data.get("events", [])) or task.get("artifactCount") != len(artifacts):
            failures += 1
            print(f"cloud {name}: task counts do not match response collections")
        disclosure = task.get("disclosure")
        if name == "redacted-publication.json":
            if task.get("lifecycleState") != "completed" or disclosure != {"redactionApplied": True, "originalRetained": True}:
                failures += 1
                print(f"cloud {name}: completed redaction disclosure is inconsistent")
        else:
            completed = [run for run in runs if isinstance(run, dict) and run.get("runState") == "completed"]
            if task.get("lifecycleState") != "active" or task.get("completedAt") is not None:
                failures += 1
                print(f"cloud {name}: task must remain active after planning")
            if len(completed) != 1 or completed[0].get("role") != "planning" or task.get("completedRunId") != completed[0].get("runId"):
                failures += 1
                print(f"cloud {name}: active task must expose one completed planning run")
            if disclosure != {"redactionApplied": False, "originalRetained": True}:
                failures += 1
                print(f"cloud {name}: active disclosure is inconsistent")
        for artifact in artifacts:
            if isinstance(artifact, dict) and artifact.get("disclosure") != disclosure:
                failures += 1
                print(f"cloud {name}: artifact disclosure does not match task disclosure")
        trajectory = data.get("trajectory") if isinstance(data, dict) else None
        if not isinstance(trajectory, dict) or trajectory.get("disclosure") != disclosure:
            failures += 1
            print(f"cloud {name}: trajectory disclosure does not match task disclosure")
        task_id = task.get("taskId"); pipelines = {p.get("pipelineId"): p for p in data["pipelines"] if isinstance(p, dict)}
        run_by_id = {r.get("runId"): r for r in runs if isinstance(r, dict)}; artifact_by_id = {a.get("artifactId"): a for a in artifacts if isinstance(a, dict)}
        relations = [task.get("pipelineId") in pipelines and pipelines.get(task.get("pipelineId"), {}).get("taskId") == task_id and task.get("completedRunId") in run_by_id and run_by_id.get(task.get("completedRunId"), {}).get("taskId") == task_id]; trajectory_run = run_by_id.get(trajectory.get("runId")) if isinstance(trajectory, dict) else None
        relations += [p.get("taskId") == task_id for p in pipelines.values()]
        relations += [r.get("taskId") == task_id and r.get("pipelineId") in pipelines for r in run_by_id.values()]
        relations += [e.get("taskId") == task_id for e in data["events"]]
        relations += [a.get("taskId") == task_id and a.get("runId") in run_by_id for a in artifacts]
        relations += [isinstance(a.get("sha256"), str) and a.get("publicKey") == f"v1/tasks/{task_id}/objects/sha256/{a['sha256'][:2]}/{a['sha256']}" for a in artifacts]
        relations += [(a := artifact_by_id.get(r.get("atifArtifactId"))) is not None and a.get("sha256") == r.get("atifDigest") for r in run_by_id.values()]
        relations += [isinstance(trajectory, dict) and trajectory.get("taskId") == task_id and trajectory.get("runId") == task.get("completedRunId") and trajectory_run is not None and trajectory.get("pipelineId") == trajectory_run.get("pipelineId")]
        relations += [isinstance(trajectory, dict) and trajectory_run is not None and (a := artifact_by_id.get(trajectory.get("artifactId"))) is not None and a.get("artifactId") == trajectory_run.get("atifArtifactId") and all(trajectory.get(k) == a.get(k) for k in ("sha256", "publicKey", "byteSize"))]
        failures += sum(not relation for relation in relations)
        if not all(relations): print(f"cloud {name}: ownership or integrity relation is inconsistent")
        failures += _cloud_public_scan(response, name)
    return failures


def validate_markdown_links() -> int:
    failures = 0
    link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")
    for path in sorted(ROOT.glob("*.md")):
        for target in link_pattern.findall(path.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            relative = target.split("#", 1)[0]
            if relative and not (path.parent / relative).exists():
                failures += 1
                print(f"link {path.name}: missing {target}")
    return failures


def validate_steward_growth() -> int:
    growth = read_json(EXAMPLE_DIR / "steward-growth-summary.json")["data"]
    daily = read_json(EXAMPLE_DIR / "steward-daily-summary.json")["data"]
    ranges = growth["ranges"]
    failures = 0

    ids = [item["id"] for item in ranges]
    if ids != ["day", "7d", "30d", "all"]:
        failures += 1
        print(
            "example steward-growth-summary.json: ranges must be ordered day, 7d, 30d, all"
        )

    for item in ranges:
        if item["endDate"] != growth["throughDate"]:
            failures += 1
            print(
                f"example steward-growth-summary.json range {item['id']}: endDate must equal throughDate"
            )
        if (
            item["outcomes"]["validationsPassed"]
            > item["outcomes"]["validationsCompleted"]
        ):
            failures += 1
            print(
                f"example steward-growth-summary.json range {item['id']}: passed validations exceed completed"
            )
        usage = item["modelUsage"]
        if usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]:
            failures += 1
            print(
                f"example steward-growth-summary.json range {item['id']}: token total is inconsistent"
            )
        if item["completeness"] == "partial" and not item["warnings"]:
            failures += 1
            print(
                f"example steward-growth-summary.json range {item['id']}: partial range needs a warning"
            )

    day = ranges[0]
    if day["endDate"] != daily["date"]:
        failures += 1
        print(
            "example steward-growth-summary.json: day range does not match daily date"
        )
    for field in ("modelUsage", "repository", "outcomes"):
        if day[field] != daily[field]:
            failures += 1
            print(
                f"example steward-growth-summary.json: day {field} does not match daily summary"
            )

    return failures


def main() -> int:
    failures = (
        validate_json_contracts()
        + validate_steward_cloud_examples()
        + validate_complete_trajectory_examples()
        + validate_markdown_links()
        + validate_steward_growth()
    )
    if failures:
        print(f"contract validation failed with {failures} finding(s)")
        return 1
    print("contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
