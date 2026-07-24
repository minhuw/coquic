#!/usr/bin/env python3
"""Validate V2 schemas, examples, SSE data records, and Markdown links."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
EXAMPLE_DIR = ROOT / "examples"
DATASET_DIR = EXAMPLE_DIR / "steward-dataset"
CONTROL_LOOP_DIR = EXAMPLE_DIR / "steward-control-loop"

EXAMPLE_TARGETS = {
    "coverage-snapshot.json": ("evidence.schema.json", "coverageSnapshot"),
    "interop-snapshot.json": ("evidence.schema.json", "interopSnapshot"),
    "performance-snapshot.json": ("evidence.schema.json", "performanceSnapshot"),
    "scenario-catalog.json": ("catalog.schema.json", "scenarioCatalog"),
    "steward-daily-summary.json": ("steward.schema.json", "dailySummary"),
    "steward-dashboard.json": ("steward-dashboard.schema.json", "snapshot"),
    "steward-control-loop.json": ("steward-observability.schema.json", "controlLoop"),
    "steward-active-task-detail.json": ("steward-observability.schema.json", "taskDetail"),
    "steward-real-task-detail.json": ("steward-observability.schema.json", "taskDetail"),
    "steward-task-detail.json": ("steward-observability.schema.json", "taskDetail"),
    "steward-growth-summary.json": ("steward.schema.json", "growthSummary"),
    "steward-status.json": ("steward.schema.json", "monitor"),
    "transcript-search.json": ("transcript.schema.json", "searchResponse"),
    "workbench-command.json": ("workbench.schema.json", "command"),
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


def validate_steward_dashboard() -> int:
    dashboard = read_json(EXAMPLE_DIR / "steward-dashboard.json")["data"]
    failures = 0

    outcome_total = sum(item["count"] for item in dashboard["outcomes"])
    if outcome_total != dashboard["archive"]["tasks"]:
        failures += 1
        print(
            "example steward-dashboard.json: outcome counts must sum to archive tasks"
        )

    validations = dashboard["archive"]["validations"]
    if validations["passed"] + validations["failed"] != validations["total"]:
        failures += 1
        print(
            "example steward-dashboard.json: passed and failed validations must sum to total"
        )

    tasks = dashboard["tasks"]
    if tasks["total"] != dashboard["archive"]["tasks"]:
        failures += 1
        print(
            "example steward-dashboard.json: task aggregate must match archive tasks"
        )
    if tasks["publishedCount"] != len(tasks["items"]):
        failures += 1
        print(
            "example steward-dashboard.json: published task count must match task items"
        )

    signals = dashboard["signals"]
    if signals["providerCount"] != len(signals["providers"]):
        failures += 1
        print(
            "example steward-dashboard.json: provider count must match provider items"
        )
    if signals["publishedCount"] != len(signals["items"]):
        failures += 1
        print(
            "example steward-dashboard.json: published signal count must match signal items"
        )
    if signals["publishedWakeupCount"] != len(signals["wakeups"]):
        failures += 1
        print(
            "example steward-dashboard.json: published wakeup count must match wakeup items"
        )

    return failures


def validate_steward_observability() -> int:
    loop = read_json(EXAMPLE_DIR / "steward-control-loop.json")["data"]
    details = [
        read_json(EXAMPLE_DIR / "steward-active-task-detail.json")["data"],
        read_json(EXAMPLE_DIR / "steward-task-detail.json")["data"],
        read_json(EXAMPLE_DIR / "steward-real-task-detail.json")["data"],
    ]
    failures = 0

    if loop["counts"]["signals"] < len(loop["signals"]):
        failures += 1
        print("example steward-control-loop.json: signal total is smaller than published items")
    if loop["counts"]["plannerRuns"] < len(loop["plannerRuns"]):
        failures += 1
        print("example steward-control-loop.json: planner-run total is smaller than published items")
    if loop["counts"]["tasks"] < len(loop["tasks"]):
        failures += 1
        print("example steward-control-loop.json: task total is smaller than published items")

    published_task_ids = {item["id"] for item in loop["tasks"]}
    for signal in loop["signals"]:
        task_id = signal["plannedTaskId"]
        if task_id is not None and task_id not in published_task_ids:
            failures += 1
            print(
                f"example steward-control-loop.json signal {signal['id']}: planned task is not published"
            )

    for detail in details:
        task_id = detail["task"]["id"]
        attempts = {item["number"] for item in detail["attempts"]}
        if task_id not in published_task_ids:
            failures += 1
            print(f"example task detail {task_id}: task is not in control-loop index")
        transition_pairs: set[tuple[str, str]] = set()
        for transition in detail["pipeline"]["transitions"]:
            pair = (transition["from"], transition["to"])
            if pair in transition_pairs:
                failures += 1
                print(f"example task detail {task_id}: pipeline transition {pair} is duplicated")
            transition_pairs.add(pair)
            transition_attempts = set(transition["attempts"])
            if transition["count"] != len(transition["attempts"]):
                failures += 1
                print(f"example task detail {task_id}: pipeline transition {pair} count is inconsistent")
            if not transition_attempts <= attempts:
                failures += 1
                print(f"example task detail {task_id}: pipeline transition {pair} references unknown attempt")
            cause_attempts = {cause["attempt"] for cause in transition["causes"] if cause["attempt"] is not None}
            if not cause_attempts <= transition_attempts:
                failures += 1
                print(f"example task detail {task_id}: pipeline transition {pair} cause references an unrelated attempt")
        for item in detail["transcript"]:
            if item["attempt"] not in attempts:
                failures += 1
                print(f"example task detail {task_id}: transcript references unknown attempt")
        for record in detail["validations"]:
            if record["attempt"] not in attempts:
                failures += 1
                print(f"example task detail {task_id}: validation references unknown attempt")
        for record in detail["reviews"]:
            if record["attempt"] not in attempts:
                failures += 1
                print(f"example task detail {task_id}: review references unknown attempt")
        patch_attempts: set[int] = set()
        for patch in detail["patches"]:
            if patch["attempt"] not in attempts:
                failures += 1
                print(f"example task detail {task_id}: patch references unknown attempt")
            if patch["attempt"] in patch_attempts:
                failures += 1
                print(f"example task detail {task_id}: attempt has duplicate patches")
            patch_attempts.add(patch["attempt"])
            files = patch["files"]
            if patch["filesChanged"] != len(files):
                failures += 1
                print(f"example task detail {task_id}: patch file count is inconsistent")
            for field in ("additions", "deletions"):
                if patch[field] != sum(item[field] for item in files):
                    failures += 1
                    print(f"example task detail {task_id}: patch {field} total is inconsistent")
            paths = [item["path"] for item in files]
            if len(paths) != len(set(paths)):
                failures += 1
                print(f"example task detail {task_id}: patch paths must be unique")
            for file in files:
                for hunk in file["hunks"]:
                    for line in hunk["lines"]:
                        if line["type"] == "addition" and line["oldLine"] is not None:
                            failures += 1
                            print(f"example task detail {task_id}: added line has an old line number")
                        if line["type"] == "deletion" and line["newLine"] is not None:
                            failures += 1
                            print(f"example task detail {task_id}: deleted line has a new line number")
        if detail["task"]["status"] == "running" and detail["completeness"]["state"] != "partial":
            failures += 1
            print(f"example task detail {task_id}: running task must declare partial completeness")

    return failures


def _dataset_validator(definition: str) -> Draft202012Validator:
    schema = read_json(SCHEMA_DIR / "steward-dataset.schema.json")
    common = read_json(SCHEMA_DIR / "common.schema.json")
    registry = Registry().with_resources(
        (item["$id"], Resource.from_contents(item)) for item in (schema, common)
    )
    return Draft202012Validator(
        {"$ref": f"{schema['$id']}#/$defs/{definition}"},
        registry=registry,
        format_checker=FormatChecker(),
    )


def _dataset_validate_json(path: Path, definition: str, root: Path) -> int:
    try:
        value = read_json(path)
    except (OSError, json.JSONDecodeError) as error:
        print(f"dataset {path.relative_to(root)} [json-invalid]: {error}")
        return 1
    failures = 0
    validator = _dataset_validator(definition)
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        failures += 1
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        print(f"dataset {path.relative_to(root)} at {location} [schema-invalid]: {error.message}")
    return failures


def _dataset_jsonl(path: Path, root: Path) -> tuple[list[object], int, bytes, int]:
    """Return parsed complete records, accepted bytes, prefix digest, tail size."""
    data = path.read_bytes()
    last_newline = data.rfind(b"\n")
    accepted_size = last_newline + 1
    accepted = data[:accepted_size]
    tail = data[accepted_size:]
    records: list[object] = []
    failures = 0
    for line_number, line in enumerate(accepted.splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            failures += 1
            print(
                f"dataset {path.relative_to(root)} line {line_number} "
                f"[jsonl-invalid]: {error}"
            )
    if failures:
        raise ValueError("invalid complete JSONL prefix")
    prefix_identity = hashlib.sha256(accepted).digest()
    return records, accepted_size, prefix_identity, len(tail)


def _dataset_artifact_descriptors(value: object) -> list[dict[str, object]]:
    descriptors: list[dict[str, object]] = []
    if isinstance(value, dict):
        required = {"path", "lifecycle", "availability", "byteSize", "sha256"}
        if required <= value.keys():
            descriptors.append(value)
        for child in value.values():
            descriptors.extend(_dataset_artifact_descriptors(child))
    elif isinstance(value, list):
        for child in value:
            descriptors.extend(_dataset_artifact_descriptors(child))
    return descriptors


def _dataset_path_is_safe(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    parts = path.split("/")
    return all(part and part not in {".", ".."} and not part.startswith(".") for part in parts)


def _dataset_path_has_symlink(task_root: Path, relative: str) -> bool:
    candidate = task_root
    for part in relative.split("/"):
        candidate /= part
        if candidate.is_symlink():
            return True
    return False


def _dataset_session_lineage_error(session_runs: list[dict[str, object]]) -> str | None:
    if any(run["resumeOfRunId"] == run["runId"] for run in session_runs):
        return "session-recovery-cycle"
    if len(session_runs) == 1:
        return None
    roots = [run for run in session_runs if run["resumeOfRunId"] is None]
    if len(roots) != 1:
        return "session-reuse-without-recovery"
    resume_targets = [run["resumeOfRunId"] for run in session_runs if run["resumeOfRunId"]]
    if len(resume_targets) != len(set(resume_targets)):
        return "session-recovery-branch"
    reachable = {roots[0]["runId"]}
    while True:
        added = {
            run["runId"]
            for run in session_runs
            if run["resumeOfRunId"] in reachable and run["runId"] not in reachable
        }
        if not added:
            break
        reachable.update(added)
    if len(reachable) != len(session_runs):
        return "session-recovery-chain"
    return None


def _dataset_pipeline_parent_error(
    pipeline_id: str,
    ordinal: int,
    parent_id: str | None,
    pipeline_ordinals: dict[str, int],
) -> str | None:
    if parent_id is None:
        return None
    if parent_id not in pipeline_ordinals:
        return "parent-pipeline-missing"
    if parent_id == pipeline_id or pipeline_ordinals[parent_id] >= ordinal:
        return "parent-pipeline-cycle"
    return None


def _dataset_run_has_live_artifact(run: dict[str, object]) -> bool:
    return run["state"] != "running" and any(
        artifact["lifecycle"] == "live" for artifact in run["artifacts"].values()
    )


def _dataset_artifact_checks(
    task_root: Path, metadata_path: Path, value: object, running: bool
) -> int:
    failures = 0
    for artifact in _dataset_artifact_descriptors(value):
        relative = artifact["path"]
        if not isinstance(relative, str) or not _dataset_path_is_safe(relative):
            print(f"dataset {metadata_path.relative_to(DATASET_DIR)} [unsafe-artifact-path]")
            failures += 1
            continue
        target = task_root / relative
        if _dataset_path_has_symlink(task_root, relative) or (
            target.exists() and not target.is_file()
        ):
            print(f"dataset {metadata_path.relative_to(DATASET_DIR)} [artifact-not-regular]")
            failures += 1
            continue
        frozen = artifact["lifecycle"] == "terminal"
        if not target.exists():
            if not running:
                print(f"dataset {metadata_path.relative_to(DATASET_DIR)} [artifact-missing]")
                failures += 1
            continue
        available = artifact["availability"] in {"available", "partial"}
        if frozen and available and artifact["byteSize"] != target.stat().st_size:
            print(f"dataset {metadata_path.relative_to(DATASET_DIR)} [artifact-byte-size]")
            failures += 1
    return failures


def _dataset_relation_checks(task_root: Path, task: dict[str, object], running: bool) -> int:
    failures = 0
    task_id = task["taskId"]
    task_rel = task_root
    pipelines = task["pipelines"]
    pipeline_ids = [item["pipelineId"] for item in pipelines]
    ordinals = [item["ordinal"] for item in pipelines]
    pipeline_ordinals = {
        item["pipelineId"]: item["ordinal"] for item in pipelines
    }
    if len(pipeline_ids) != len(set(pipeline_ids)):
        print(f"dataset {task_id} [duplicate-pipeline-id]")
        failures += 1
    if ordinals != sorted(ordinals):
        print(f"dataset {task_id} [pipeline-order]")
        failures += 1
    if task["currentPipelineId"] is not None and task["currentPipelineId"] not in pipeline_ids:
        print(f"dataset {task_id} [current-pipeline-missing]")
        failures += 1

    all_runs: dict[str, tuple[dict[str, object], str]] = {}
    for pipeline_ref in pipelines:
        pipeline_path = task_rel / pipeline_ref["path"]
        if not pipeline_path.exists():
            if running:
                continue
            print(f"dataset {task_id}/{pipeline_ref['pipelineId']} [pipeline-missing]")
            failures += 1
            continue
        pipeline = read_json(pipeline_path)
        if pipeline["taskId"] != task_id or pipeline["pipelineId"] != pipeline_ref["pipelineId"]:
            print(f"dataset {pipeline_path.relative_to(task_root)} [pipeline-relation]")
            failures += 1
        if pipeline["ordinal"] != pipeline_ref["ordinal"]:
            print(f"dataset {pipeline_path.relative_to(task_root)} [pipeline-ordinal]")
            failures += 1
        parent = pipeline["parentPipelineId"]
        if pipeline["ordinal"] == 1 and parent is not None:
            print(f"dataset {pipeline_path.relative_to(task_root)} [root-parent]")
            failures += 1
        parent_error = _dataset_pipeline_parent_error(
            pipeline["pipelineId"], pipeline["ordinal"], parent, pipeline_ordinals
        )
        if parent_error is not None:
            print(f"dataset {pipeline_path.relative_to(task_root)} [{parent_error}]")
            failures += 1

        def check_artifact_reference(reference: str, category: str) -> None:
            nonlocal failures
            if not (task_root / reference).exists() and not running:
                print(f"dataset {pipeline_path.relative_to(task_root)} [{category}-missing]")
                failures += 1

        for group_name in ("inputs", "patches"):
            for artifact in pipeline[group_name]:
                if not _dataset_path_is_safe(artifact["path"]):
                    print(f"dataset {pipeline_path.relative_to(task_root)} [unsafe-artifact-path]")
                    failures += 1
                check_artifact_reference(artifact["path"], "pipeline-artifact")
        validations = pipeline["validations"]
        if [item["ordinal"] for item in validations] != sorted(item["ordinal"] for item in validations):
            print(f"dataset {pipeline_path.relative_to(task_root)} [validation-order]")
            failures += 1
        reviews = pipeline["reviews"]
        if [item["ordinal"] for item in reviews] != sorted(item["ordinal"] for item in reviews):
            print(f"dataset {pipeline_path.relative_to(task_root)} [review-order]")
            failures += 1
        runs = pipeline["runs"]
        if [item["roleOrdinal"] for item in runs] != sorted(item["roleOrdinal"] for item in runs):
            print(f"dataset {pipeline_path.relative_to(task_root)} [run-order]")
            failures += 1
        for run_ref in runs:
            run_path = task_root / run_ref["path"]
            if not run_path.exists():
                if running:
                    continue
                print(f"dataset {run_ref['path']} [run-missing]")
                failures += 1
                continue
            run = read_json(run_path)
            run_id = run["runId"]
            if run_id in all_runs:
                print(f"dataset {run_ref['path']} [duplicate-run-id]")
                failures += 1
            all_runs[run_id] = (run, pipeline["pipelineId"])
            if run["taskId"] != task_id or run["pipelineId"] != pipeline["pipelineId"]:
                print(f"dataset {run_ref['path']} [run-relation]")
                failures += 1
            if run["runId"] != run_ref["runId"] or run["role"] != run_ref["role"] or run["roleOrdinal"] != run_ref["roleOrdinal"]:
                print(f"dataset {run_ref['path']} [run-descriptor]")
                failures += 1
            if run["state"] != run_ref["state"]:
                print(f"dataset {run_ref['path']} [run-state]")
                failures += 1

    for run_id, (run, pipeline_id) in all_runs.items():
        for relation_name in ("parentRunId", "retryOfRunId"):
            relation_id = run[relation_name]
            if relation_id is not None:
                relation_entry = all_runs.get(relation_id)
                if relation_entry is None:
                    print(f"dataset {task_id}/{run_id} [{relation_name}-missing]")
                    failures += 1
                elif relation_entry[1] != pipeline_id:
                    print(f"dataset {task_id}/{run_id} [{relation_name}-cross-pipeline]")
                    failures += 1
        resume_id = run["resumeOfRunId"]
        if resume_id is None:
            continue
        prior_entry = all_runs.get(resume_id)
        legal_roles = {"planning", "implementation", "reviewer", "review"}
        if prior_entry is None:
            print(f"dataset {task_id}/{run_id} [resume-target-missing]")
            failures += 1
            continue
        prior, prior_pipeline_id = prior_entry
        if prior_pipeline_id != pipeline_id or prior["taskId"] != run["taskId"]:
            print(f"dataset {task_id}/{run_id} [resume-cross-pipeline]")
            failures += 1
        if prior["state"] != "interrupted" or run["role"] not in legal_roles or prior["role"] != run["role"]:
            print(f"dataset {task_id}/{run_id} [illegal-resume-lineage]")
            failures += 1
        if prior["sessionId"] != run["sessionId"]:
            print(f"dataset {task_id}/{run_id} [resume-session-mismatch]")
            failures += 1

    sessions: dict[str, list[dict[str, object]]] = {}
    for run, _pipeline_id in all_runs.values():
        sessions.setdefault(run["sessionId"], []).append(run)
    for session_id, session_runs in sessions.items():
        category = _dataset_session_lineage_error(session_runs)
        if category is not None:
            print(f"dataset {task_id}/{session_id} [{category}]")
            failures += 1
    return failures


def _dataset_manifest_state(
    task_root: Path,
    *,
    expected_epoch_id: str | None = None,
    expected_task_id: str | None = None,
    expected_terminal_status: str | None = None,
    previously_verified: bool = False,
) -> str:
    manifest_path = task_root / "manifest.json"
    if manifest_path.is_symlink():
        return "corrupt"
    if not manifest_path.exists():
        return "corrupt" if previously_verified else "live"
    if not manifest_path.is_file():
        return "corrupt"
    try:
        manifest = read_json(manifest_path)
    except (OSError, json.JSONDecodeError):
        return "corrupt"
    expected_identity = {
        "epochId": expected_epoch_id,
        "taskId": expected_task_id,
        "terminalStatus": expected_terminal_status,
    }
    if any(
        expected is not None and manifest.get(field) != expected
        for field, expected in expected_identity.items()
    ):
        return "corrupt"
    descriptors = manifest.get("files")
    if not isinstance(descriptors, list):
        return "corrupt"
    descriptor_map: dict[str, dict[str, object]] = {}
    for item in descriptors:
        path = item.get("path") if isinstance(item, dict) else None
        if not isinstance(path, str) or not _dataset_path_is_safe(path) or path in descriptor_map:
            return "corrupt"
        descriptor_map[path] = item
    if list(descriptor_map) != sorted(descriptor_map):
        return "corrupt"
    actual: dict[str, Path] = {}
    for path in task_root.rglob("*"):
        if path == manifest_path:
            continue
        if path.is_symlink():
            return "corrupt"
        if path.is_file():
            relative = path.relative_to(task_root).as_posix()
            if not _dataset_path_is_safe(relative):
                return "corrupt"
            actual[relative] = path
        elif not path.is_dir():
            return "corrupt"
    if set(actual) != set(descriptor_map):
        if set(actual) < set(descriptor_map) and not previously_verified:
            return "incomplete"
        return "corrupt"
    for relative, path in actual.items():
        descriptor = descriptor_map[relative]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if descriptor.get("byteSize") != path.stat().st_size or descriptor.get("sha256") != digest:
            return "corrupt"
    return "verified"


def _dataset_mutation_checks(running_root: Path, complete_root: Path) -> int:
    failures = 0

    def expect(label: str, actual: object, expected: object) -> None:
        nonlocal failures
        if actual != expected:
            failures += 1
            print(f"dataset mutation [{label}]: expected {expected!r}, got {actual!r}")

    invalid_usage = {
        "availability": "unavailable",
        "promptTokens": 0,
        "completionTokens": 0,
        "totalTokens": 0,
        "sourcePath": None,
        "reason": None,
    }
    expect(
        "unavailable-usage-is-not-zero",
        bool(list(_dataset_validator("usage").iter_errors(invalid_usage))),
        True,
    )
    invalid_cost = {
        "availability": "available",
        "estimatedMicroUsd": 100,
        "currency": "USD",
        "model": "synthetic-codex-2.0",
        "pricingSource": None,
        "reason": None,
    }
    expect(
        "available-cost-needs-provenance",
        bool(list(_dataset_validator("cost").iter_errors(invalid_cost))),
        True,
    )
    task_list_response = {
        "schemaVersion": "2.0",
        "generatedAt": "2026-07-22T08:05:00Z",
        "data": {
            "epochId": "epoch-synthetic-20260722",
            "tasks": [
                {
                    "taskId": "task-running-synthetic",
                    "status": "running",
                    "archiveState": "live",
                    "currentPipelineId": "pipeline-initial",
                    "updatedAt": "2026-07-22T08:05:00Z",
                    "lastSuccessfulImportAt": "2026-07-22T08:05:00Z",
                    "importLag": None,
                }
            ],
            "freshness": {
                "lastSyncAt": "2026-07-22T08:05:00Z",
                "lastSuccessfulImportAt": "2026-07-22T08:05:00Z",
            },
        },
    }
    expect(
        "task-list-response-schema",
        list(_dataset_validator("taskListResponse").iter_errors(task_list_response)),
        [],
    )

    complete_task = read_json(complete_root / "task.json")
    pipeline_groups = []
    for pipeline_ref in complete_task["pipelines"]:
        pipeline = read_json(complete_root / pipeline_ref["path"])
        pipeline_groups.append(
            {
                "pipeline": pipeline,
                "validations": [
                    read_json(complete_root / item["path"])
                    for item in pipeline["validations"]
                ],
                "reviews": [
                    read_json(complete_root / item["path"])
                    for item in pipeline["reviews"]
                ],
                "runs": [
                    read_json(complete_root / item["path"])
                    for item in pipeline["runs"]
                ],
            }
        )
    complete_manifest = read_json(complete_root / "manifest.json")
    task_detail_response = {
        "schemaVersion": "2.0",
        "generatedAt": complete_manifest["completedAt"],
        "data": {
            "task": complete_task,
            "pipelines": pipeline_groups,
            "archiveState": "verified",
            "archiveVerification": {
                "state": "verified",
                "manifestObservedAt": complete_manifest["completedAt"],
                "verifiedAt": complete_manifest["completedAt"],
                "reason": None,
            },
            "freshness": {
                "lastSyncAt": complete_manifest["completedAt"],
                "lastSuccessfulImportAt": complete_manifest["completedAt"],
            },
            "importLag": None,
        },
    }
    expect(
        "task-detail-response-schema",
        list(_dataset_validator("taskDetailResponse").iter_errors(task_detail_response)),
        [],
    )

    interrupted = read_json(
        running_root
        / "pipelines/pipeline-initial/runs/run-implementation-interrupted/run.json"
    )
    recovery = read_json(
        running_root
        / "pipelines/pipeline-initial/runs/run-implementation-recovery/run.json"
    )
    self_resume = dict(interrupted)
    self_resume["resumeOfRunId"] = self_resume["runId"]
    expect(
        "self-resume-cycle",
        _dataset_session_lineage_error([self_resume]),
        "session-recovery-cycle",
    )
    null_evidence = dict(recovery)
    null_evidence.update({"usage": None, "cost": None})
    expect(
        "run-needs-explicit-usage-and-cost",
        bool(list(_dataset_validator("run").iter_errors(null_evidence))),
        True,
    )
    mutable_terminal = dict(interrupted)
    mutable_terminal["completedAt"] = None
    mutable_terminal["artifacts"] = {
        name: {**artifact, "lifecycle": "live"}
        for name, artifact in interrupted["artifacts"].items()
    }
    expect(
        "terminal-run-needs-completion-time",
        bool(list(_dataset_validator("run").iter_errors(mutable_terminal))),
        True,
    )
    expect(
        "terminal-run-artifacts-freeze",
        _dataset_run_has_live_artifact(mutable_terminal),
        True,
    )
    expect(
        "pipeline-self-parent",
        _dataset_pipeline_parent_error(
            "pipeline-repair",
            2,
            "pipeline-repair",
            {"pipeline-initial": 1, "pipeline-repair": 2},
        ),
        "parent-pipeline-cycle",
    )
    unrelated = dict(interrupted)
    unrelated.update({"runId": "run-unrelated", "roleOrdinal": 3})
    expect(
        "unrelated-run-session-reuse",
        _dataset_session_lineage_error([interrupted, recovery, unrelated]),
        "session-reuse-without-recovery",
    )

    with tempfile.TemporaryDirectory(prefix="steward-dataset-") as temporary:
        temporary_root = Path(temporary)
        live = temporary_root / "running"
        complete = temporary_root / "complete"
        shutil.copytree(running_root, live)
        shutil.copytree(complete_root, complete)

        live_codex = live / "pipelines/pipeline-initial/runs/run-implementation-interrupted/codex.jsonl"
        records, _codex_accepted_size, _codex_prefix_identity, tail_size = _dataset_jsonl(live_codex, running_root)
        expect("incomplete-final-record", tail_size > 0, True)
        expect("complete-line-count", len(records), 3)

        # Metadata-before-artifact and artifact-before-metadata are recoverable.
        (live / "pipelines/pipeline-initial/inputs/original-prompt.md").unlink()
        expect("metadata-before-artifact", _dataset_manifest_state(live), "live")
        (live / "orphan-artifact.bin").write_bytes(b"synthetic out of order")
        expect("artifact-before-metadata", _dataset_manifest_state(live), "live")

        malformed = live / "task.json"
        malformed.write_text("{\"status\":", encoding="utf-8")
        try:
            json.loads(malformed.read_text(encoding="utf-8"))
            expect("incomplete-json", "parsed", "retained-last-valid")
        except json.JSONDecodeError:
            expect("incomplete-json", "retained-last-valid", "retained-last-valid")

        # Restore the live tree for cursor cases.
        shutil.rmtree(live)
        shutil.copytree(running_root, live)
        append = live / "events.jsonl"
        original_events = running_root / "events.jsonl"
        original_bytes = original_events.read_bytes()
        _event_records, accepted_size, prefix_identity, _event_tail = _dataset_jsonl(original_events, running_root)
        append.write_bytes(original_bytes + b'{"eventId":"event-running-4","kind":"rescan"}\n')
        appended_records, appended_size, _identity, _tail = _dataset_jsonl(append, running_root)
        expect("appended-jsonl", len(appended_records), 4)
        expect("append-offset", appended_size > accepted_size, True)
        duplicate = live / "events.jsonl"
        duplicate.write_bytes(append.read_bytes() + b'{"eventId":"event-running-4","kind":"rescan"}\n')
        duplicate_records, _size, _identity, _tail = _dataset_jsonl(duplicate, running_root)
        unique_records = {json.dumps(item, sort_keys=True) for item in duplicate_records}
        expect("duplicate-replay", len(unique_records), 4)
        replacement = live / "events.jsonl"
        replacement.write_bytes(b'{"eventId":"replacement","kind":"rescan"}\n')
        _records, _size, replacement_identity, _tail = _dataset_jsonl(replacement, running_root)
        expect("replacement-prefix", replacement_identity == prefix_identity, False)
        truncated = live / "events.jsonl"
        truncated.write_bytes(original_bytes[: accepted_size // 2])
        _records, truncated_size, _identity, _tail = _dataset_jsonl(truncated, running_root)
        expect("truncation-offset", truncated_size < accepted_size, True)
        expect("missed-event-rescan", (live / "task.json").exists(), True)

        manifest_expectations = {
            "expected_epoch_id": complete_task["epochId"],
            "expected_task_id": complete_task["taskId"],
            "expected_terminal_status": complete_task["status"],
        }
        identity = temporary_root / "manifest-identity"
        shutil.copytree(complete_root, identity)
        original_manifest = read_json(identity / "manifest.json")
        invalid_identities = {
            "epochId": "epoch-other-synthetic",
            "taskId": "task-other-synthetic",
            "terminalStatus": "failed",
        }
        for field, invalid_value in invalid_identities.items():
            changed_manifest = dict(original_manifest)
            changed_manifest[field] = invalid_value
            (identity / "manifest.json").write_text(
                json.dumps(changed_manifest), encoding="utf-8"
            )
            expect(
                f"manifest-{field}-relation",
                _dataset_manifest_state(identity, **manifest_expectations),
                "corrupt",
            )

        # A manifest can arrive before content, but a changed or extra terminal
        # file is corruption once the terminal tree is otherwise present.
        missing = temporary_root / "manifest-before-content"
        shutil.copytree(complete_root, missing)
        expect(
            "verified-before-deletion",
            _dataset_manifest_state(missing, **manifest_expectations),
            "verified",
        )
        missing_file = missing / "events.jsonl"
        missing_file.unlink()
        expect(
            "manifest-before-content",
            _dataset_manifest_state(missing, **manifest_expectations),
            "incomplete",
        )
        expect(
            "post-verification-deletion",
            _dataset_manifest_state(
                missing, previously_verified=True, **manifest_expectations
            ),
            "corrupt",
        )
        missing_manifest = temporary_root / "manifest-missing-after-verification"
        shutil.copytree(complete_root, missing_manifest)
        expect(
            "verified-before-manifest-deletion",
            _dataset_manifest_state(missing_manifest, **manifest_expectations),
            "verified",
        )
        (missing_manifest / "manifest.json").unlink()
        expect(
            "post-verification-manifest-deletion",
            _dataset_manifest_state(
                missing_manifest,
                previously_verified=True,
                **manifest_expectations,
            ),
            "corrupt",
        )
        delayed_artifact = temporary_root / "active-metadata-before-artifact"
        shutil.copytree(running_root, delayed_artifact)
        delayed_run_path = (
            delayed_artifact
            / "pipelines/pipeline-initial/runs/run-implementation-interrupted/run.json"
        )
        delayed_run = read_json(delayed_run_path)
        (delayed_artifact / delayed_run["artifacts"]["activities"]["path"]).unlink(
            missing_ok=True
        )
        expect(
            "active-metadata-before-terminal-artifact",
            _dataset_artifact_checks(
                delayed_artifact, delayed_run_path, delayed_run, running=True
            ),
            0,
        )
        symlink_parent = temporary_root / "symlink-parent-artifact"
        shutil.copytree(running_root, symlink_parent)
        changes_relative = (
            "pipelines/pipeline-initial/runs/run-implementation-interrupted/"
            "tool-changes"
        )
        changes = symlink_parent / changes_relative
        external_changes = temporary_root / "external-tool-changes"
        shutil.move(changes, external_changes)
        changes.symlink_to(external_changes, target_is_directory=True)
        expect(
            "symlink-parent-artifact",
            _dataset_path_has_symlink(
                symlink_parent, f"{changes_relative}/manifest.jsonl"
            ),
            True,
        )
        changed = temporary_root / "changed-after-verification"
        shutil.copytree(complete_root, changed)
        changed_file = next(path for path in changed.rglob("*") if path.is_file() and path.name != "manifest.json")
        changed_file.write_bytes(changed_file.read_bytes() + b"changed")
        expect("post-verification-mutation", _dataset_manifest_state(changed), "corrupt")
        extra = temporary_root / "extra-terminal-file"
        shutil.copytree(complete_root, extra)
        (extra / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        expect("unexpected-terminal-file", _dataset_manifest_state(extra), "corrupt")
        linked = temporary_root / "symlink-terminal-file"
        shutil.copytree(complete_root, linked)
        link_target = next(path for path in linked.rglob("*") if path.is_file() and path.name != "manifest.json")
        (linked / "unsafe-link").symlink_to(link_target)
        expect("symlink-terminal-file", _dataset_manifest_state(linked), "corrupt")
        linked_manifest = temporary_root / "symlink-terminal-manifest"
        shutil.copytree(complete_root, linked_manifest)
        external_manifest = temporary_root / "external-manifest.json"
        external_manifest.write_bytes((linked_manifest / "manifest.json").read_bytes())
        (linked_manifest / "manifest.json").unlink()
        (linked_manifest / "manifest.json").symlink_to(external_manifest)
        expect(
            "symlink-terminal-manifest",
            _dataset_manifest_state(linked_manifest, **manifest_expectations),
            "corrupt",
        )
        nonregular = temporary_root / "nonregular-terminal-file"
        shutil.copytree(complete_root, nonregular)
        fifo = nonregular / "unsafe-fifo"
        try:
            os.mkfifo(fifo)
            expect("nonregular-terminal-file", _dataset_manifest_state(nonregular), "corrupt")
        except (OSError, ValueError):
            # The platform may not permit creating a FIFO in the test sandbox.
            pass

    return failures


def validate_steward_dataset() -> int:
    failures = 0
    epoch_path = DATASET_DIR / "epoch.json"
    failures += _dataset_validate_json(epoch_path, "epoch", DATASET_DIR)
    epoch = read_json(epoch_path)
    task_roots = [DATASET_DIR / "task-running", DATASET_DIR / "task-complete"]
    tasks: dict[str, dict[str, object]] = {}
    for task_root in task_roots:
        running = task_root.name == "task-running"
        task_path = task_root / "task.json"
        failures += _dataset_validate_json(task_path, "task", DATASET_DIR)
        task = read_json(task_path)
        tasks[task["taskId"]] = task
        failures += _dataset_relation_checks(task_root, task, running)

        def check_artifact_reference(reference: str, category: str) -> None:
            nonlocal failures
            if not (task_root / reference).exists() and task_root.name != "task-running":
                print(f"dataset {task_path.relative_to(DATASET_DIR)} [{category}-missing]")
                failures += 1

        metadata_targets = [(task_root / "pipelines" / item["pipelineId"] / "pipeline.json", "pipeline") for item in task["pipelines"]]
        for pipeline_path, _definition in metadata_targets:
            if pipeline_path.exists():
                failures += _dataset_validate_json(pipeline_path, "pipeline", DATASET_DIR)
                pipeline = read_json(pipeline_path)
                failures += _dataset_artifact_checks(
                    task_root, pipeline_path, pipeline, running
                )
                for validation_ref in pipeline["validations"]:
                    validation_path = task_root / validation_ref["path"]
                    if validation_path.exists():
                        failures += _dataset_validate_json(validation_path, "validation", DATASET_DIR)
                        validation = read_json(validation_path)
                        failures += _dataset_artifact_checks(
                            task_root, validation_path, validation, running
                        )
                        check_artifact_reference(validation["outputPath"], "validation-output")
                        check_artifact_reference(validation["output"]["path"], "validation-artifact")
                for review_ref in pipeline["reviews"]:
                    review_path = task_root / review_ref["path"]
                    if review_path.exists():
                        failures += _dataset_validate_json(review_path, "review", DATASET_DIR)
                        review = read_json(review_path)
                        failures += _dataset_artifact_checks(
                            task_root, review_path, review, running
                        )
                        check_artifact_reference(review["artifact"]["path"], "review-artifact")
                for run_ref in pipeline["runs"]:
                    run_path = task_root / run_ref["path"]
                    if run_path.exists():
                        failures += _dataset_validate_json(run_path, "run", DATASET_DIR)
                        run = read_json(run_path)
                        failures += _dataset_artifact_checks(
                            task_root, run_path, run, running
                        )
                        if _dataset_run_has_live_artifact(run):
                            failures += 1
                            print(
                                f"dataset {run_path.relative_to(DATASET_DIR)} "
                                "[completed-run-live-artifact]"
                            )
                        for artifact in run["artifacts"].values():
                            check_artifact_reference(artifact["path"], "run-artifact")
                        if run["result"]["path"] is not None:
                            check_artifact_reference(run["result"]["path"], "run-result")
                        if run["usage"] is not None and run["usage"]["sourcePath"] is not None:
                            check_artifact_reference(run["usage"]["sourcePath"], "usage-source")
        for jsonl_path in sorted(task_root.rglob("*.jsonl")):
            try:
                _dataset_jsonl(jsonl_path, DATASET_DIR)
            except ValueError:
                failures += 1
        manifest_path = task_root / "manifest.json"
        if task_root.name == "task-running":
            if manifest_path.exists():
                failures += 1
                print(f"dataset {manifest_path.relative_to(DATASET_DIR)} [running-manifest-present]")
        else:
            failures += _dataset_validate_json(manifest_path, "manifest", DATASET_DIR)
            state = _dataset_manifest_state(
                task_root,
                expected_epoch_id=epoch["epochId"],
                expected_task_id=task["taskId"],
                expected_terminal_status=task["status"],
            )
            if state != "verified":
                failures += 1
                print(f"dataset {manifest_path.relative_to(DATASET_DIR)} [manifest-{state}]")

    if tasks["task-running-synthetic"]["epochId"] != epoch["epochId"]:
        failures += 1
        print("dataset task-running/task.json [epoch-relation]")
    if tasks["task-complete-synthetic"]["epochId"] != epoch["epochId"]:
        failures += 1
        print("dataset task-complete/task.json [epoch-relation]")
    failures += _dataset_mutation_checks(DATASET_DIR / "task-running", DATASET_DIR / "task-complete")
    return failures


def _control_loop_validator(definition: str) -> Draft202012Validator:
    schema = read_json(SCHEMA_DIR / "steward-control-loop.schema.json")
    registry = Registry().with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        {"$ref": f"{schema['$id']}#/$defs/{definition}"},
        registry=registry,
        format_checker=FormatChecker(),
    )


def _control_loop_validate(path: Path, definition: str) -> int:
    failures = 0
    try:
        value = read_json(path)
    except (OSError, json.JSONDecodeError) as error:
        print(f"control-loop {path.relative_to(CONTROL_LOOP_DIR)} [json-invalid]: {error}")
        return 1
    validator = _control_loop_validator(definition)
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        print(f"control-loop {path.relative_to(CONTROL_LOOP_DIR)} at {location} [schema-invalid]: {error.message}")
        failures += 1
    return failures


def validate_control_loop_fixture() -> int:
    """Validate the raw peer fixture and its graph/manifest invariants."""

    failures = 0
    if not CONTROL_LOOP_DIR.is_dir():
        print("control-loop fixture is missing")
        return 1
    failures += _control_loop_validate(CONTROL_LOOP_DIR / "epoch.json", "epoch")
    failures += _control_loop_validate(CONTROL_LOOP_DIR / "current.json", "current")
    epoch = read_json(CONTROL_LOOP_DIR / "epoch.json")
    current = read_json(CONTROL_LOOP_DIR / "current.json")
    task_epoch = read_json(DATASET_DIR / "epoch.json")
    epoch_id = epoch.get("epochId")
    for key in ("epochId", "policy", "startedAt"):
        if epoch.get(key) != task_epoch.get(key):
            print(f"control-loop epoch.json [{key}-not-shared-with-task-archive]")
            failures += 1
    if epoch.get("taskFormatVersion") != task_epoch.get("formatVersion"):
        print("control-loop epoch.json [task-format-version-mismatch]")
        failures += 1
    if current.get("epochId") != epoch_id:
        print("control-loop current.json [epoch-mismatch]")
        failures += 1

    event_validator = _control_loop_validator("event")
    invalid_event = {
        "eventId": "event-schema-guard",
        "epochId": epoch_id,
        "sequence": 0,
        "occurredAt": "2026-07-24T00:00:00Z",
        "kind": "totally.unknown",
        "payload": {},
    }
    if not list(event_validator.iter_errors(invalid_event)):
        print("control-loop schema [unknown-event-kind-accepted]")
        failures += 1
    invalid_event["kind"] = "planner.started"
    if not list(event_validator.iter_errors(invalid_event)):
        print("control-loop schema [invalid-event-payload-accepted]")
        failures += 1

    records: list[dict[str, object]] = []
    event_ids: set[str] = set()
    sequences: list[int] = []
    for path in sorted((CONTROL_LOOP_DIR / "events").rglob("*.jsonl")):
        relative = path.relative_to(CONTROL_LOOP_DIR / "events").as_posix()
        if not re.fullmatch(r"\d{4}/\d{2}/\d{2}\.jsonl", relative):
            print(f"control-loop events/{relative} [unsafe-daily-path]")
            failures += 1
        data = path.read_bytes()
        if data and not data.endswith(b"\n"):
            print(f"control-loop events/{relative} [incomplete-final-line]")
            failures += 1
        for line_number, line in enumerate(data.splitlines(), 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"control-loop events/{relative}:{line_number} [jsonl-invalid]: {error}")
                failures += 1
                continue
            validator = _control_loop_validator("event")
            errors = list(validator.iter_errors(value))
            if errors:
                failures += len(errors)
                for error in errors:
                    print(f"control-loop events/{relative}:{line_number} [schema-invalid]: {error.message}")
                continue
            event_id = value["eventId"]
            sequence = value["sequence"]
            if event_id in event_ids:
                print(f"control-loop events/{relative}:{line_number} [duplicate-event-id]")
                failures += 1
            if sequence in sequences:
                print(f"control-loop events/{relative}:{line_number} [duplicate-sequence]")
                failures += 1
            if value["epochId"] != epoch_id:
                print(f"control-loop events/{relative}:{line_number} [epoch-mismatch]")
                failures += 1
            event_ids.add(event_id)
            sequences.append(sequence)
            records.append(value)
    if sequences and sequences != list(range(min(sequences), max(sequences) + 1)):
        print("control-loop events [non-monotonic-sequence]")
        failures += 1

    run_ids: set[str] = set()
    for run_root in sorted((CONTROL_LOOP_DIR / "planner-runs").iterdir()):
        if not run_root.is_dir() or run_root.name.startswith("."):
            print(f"control-loop planner-runs/{run_root.name} [visible-unsealed-or-special]")
            failures += 1
            continue
        run_ids.add(run_root.name)
        manifest_path = run_root / "manifest.json"
        if not manifest_path.exists():
            print(f"control-loop planner-runs/{run_root.name} [manifest-missing]")
            failures += 1
            continue
        failures += _control_loop_validate(manifest_path, "manifest")
        try:
            manifest = read_json(manifest_path)
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("epochId") != epoch_id or manifest.get("plannerRunId") != run_root.name:
            print(f"control-loop planner-runs/{run_root.name} [manifest-identity]")
            failures += 1
        descriptors = {item.get("path"): item for item in manifest.get("files", []) if isinstance(item, dict)}
        actual: dict[str, Path] = {}
        for path in run_root.rglob("*"):
            if path == manifest_path:
                continue
            if path.is_symlink() or not path.is_file():
                print(f"control-loop planner-runs/{run_root.name} [special-file]")
                failures += 1
                continue
            relative = path.relative_to(run_root).as_posix()
            if not _dataset_path_is_safe(relative):
                print(f"control-loop planner-runs/{run_root.name}/{relative} [unsafe-path]")
                failures += 1
            actual[relative] = path
        if set(actual) != set(descriptors):
            print(f"control-loop planner-runs/{run_root.name} [manifest-file-set]")
            failures += 1
        for relative, path in actual.items():
            descriptor = descriptors.get(relative)
            if not isinstance(descriptor, dict):
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if descriptor.get("byteSize") != path.stat().st_size or descriptor.get("sha256") != digest:
                print(f"control-loop planner-runs/{run_root.name}/{relative} [manifest-hash]")
                failures += 1

    fetch_ids: set[str] = set()
    signal_ids: set[str] = set()
    observation_ids: set[str] = set()
    planner_event_ids: set[str] = set()
    proposal_ids: set[str] = set()
    task_ids: set[str] = set()
    observations: list[dict[str, object]] = []
    transitions: list[dict[str, object]] = []
    planner_inputs: list[dict[str, object]] = []
    proposals: list[dict[str, object]] = []
    edges: set[tuple[str, str, str]] = set()
    edge_ids: set[str] = set()
    for event in records:
        kind = event.get("kind")
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        nested_key = {
            "signal_fetch.finished": "fetch",
            "signal.created": "signal",
            "signal.observation": "observation",
            "signal.transition": "transition",
            "scheduler.wakeup": "wakeup",
            "daemon.cycle": "cycle",
            "planner.started": "plannerRun",
            "planner.proposal": "proposal",
            "graph.edge": "edge",
        }.get(kind)
        if nested_key is not None and not isinstance(payload.get(nested_key), dict):
            print(f"control-loop {event.get('eventId')} [producer-payload-shape]")
            failures += 1
            continue
        if kind == "signal_fetch.finished":
            fetch = payload["fetch"]
            required = {
                "fetchId",
                "provider",
                "status",
                "startedAt",
                "completedAt",
                "itemCount",
                "newItemCount",
                "hasMore",
            }
            if not required <= fetch.keys():
                print(f"control-loop {event.get('eventId')} [fetch-shape]")
                failures += 1
            if isinstance(fetch.get("fetchId"), str):
                fetch_ids.add(fetch["fetchId"])
        elif kind == "signal.created":
            signal = payload["signal"]
            if isinstance(signal.get("signalId"), str):
                signal_ids.add(signal["signalId"])
        elif kind == "signal.observation":
            observation = payload["observation"]
            observations.append(observation)
            if isinstance(observation.get("observationId"), str):
                observation_ids.add(observation["observationId"])
        elif kind == "signal.transition":
            transitions.append(payload["transition"])
        elif kind == "planner.started":
            planner = payload["plannerRun"]
            planner_inputs.append(planner)
            if isinstance(planner.get("plannerRunId"), str):
                planner_event_ids.add(planner["plannerRunId"])
            if planner.get("epochId") != epoch_id:
                print(f"control-loop {event.get('eventId')} [planner-epoch]")
                failures += 1
        elif kind == "planner.finished":
            if not isinstance(payload.get("plannerRunId"), str):
                print(f"control-loop {event.get('eventId')} [planner-finished-shape]")
                failures += 1
            else:
                planner_event_ids.add(payload["plannerRunId"])
        elif kind == "planner.proposal":
            proposal = payload["proposal"]
            proposals.append(proposal)
            if isinstance(proposal.get("proposalId"), str):
                proposal_ids.add(proposal["proposalId"])
            if isinstance(proposal.get("taskId"), str):
                task_ids.add(proposal["taskId"])
        elif kind == "graph.edge":
            edge = payload["edge"]
            values = (edge.get("edgeType"), edge.get("sourceId"), edge.get("targetId"))
            if all(isinstance(value, str) for value in values):
                edges.add(values)
            else:
                print(f"control-loop {event.get('eventId')} [edge-shape]")
                failures += 1
            edge_id = edge.get("edgeId")
            if isinstance(edge_id, str):
                if edge_id in edge_ids:
                    print(f"control-loop {event.get('eventId')} [duplicate-edge-id]")
                    failures += 1
                edge_ids.add(edge_id)

    for observation in observations:
        if observation.get("fetchId") not in fetch_ids:
            print(f"control-loop observation {observation.get('observationId')} [fetch-reference]")
            failures += 1
        signal_id = observation.get("canonicalSignalId")
        observation_id = observation.get("observationId")
        if signal_id not in signal_ids:
            print(f"control-loop observation {observation_id} [signal-reference]")
            failures += 1
        if ("observation_signal", observation_id, signal_id) not in edges:
            print(f"control-loop observation {observation_id} [edge-missing]")
            failures += 1
    for planner in planner_inputs:
        run_id = planner.get("plannerRunId")
        for signal_id in planner.get("inputSignalIds", []):
            if signal_id not in signal_ids or ("signal_planner_run", signal_id, run_id) not in edges:
                print(f"control-loop planner {run_id} [input-edge]")
                failures += 1
    for transition in transitions:
        if transition.get("signalId") not in signal_ids:
            print(f"control-loop transition {transition.get('signalId')} [signal-reference]")
            failures += 1
        if transition.get("fromStatus") == transition.get("toStatus"):
            print(f"control-loop transition {transition.get('signalId')} [no-op]")
            failures += 1
    if {transition.get("toStatus") for transition in transitions} < {"planned", "superseded"}:
        print("control-loop [signal-transition-coverage]")
        failures += 1
    if not set(current.get("pendingSignalIds", [])) <= signal_ids:
        print("control-loop current.json [pending-signal-reference]")
        failures += 1

    proposal_ordinals: dict[str, list[int]] = {}
    outcomes: set[str] = set()
    for proposal in proposals:
        failures += _control_loop_validate_value(
            proposal, "proposal", proposal.get("proposalId", "proposal")
        )
        run_id = proposal.get("plannerRunId")
        if isinstance(run_id, str):
            proposal_ordinals.setdefault(run_id, []).append(proposal.get("ordinal", 0))
        outcome = proposal.get("outcome")
        if isinstance(outcome, str):
            outcomes.add(outcome)
        if outcome in {"accepted", "duplicate"} and not isinstance(proposal.get("taskId"), str):
            print(f"control-loop {proposal.get('proposalId')} [proposal-task-missing]")
            failures += 1
        proposal_id = proposal.get("proposalId")
        if run_id not in planner_event_ids or ("planner_proposal", run_id, proposal_id) not in edges:
            print(f"control-loop proposal {proposal_id} [planner-edge]")
            failures += 1
        for signal_id in proposal.get("signalIds", []):
            if signal_id not in signal_ids or ("signal_proposal", signal_id, proposal_id) not in edges:
                print(f"control-loop proposal {proposal_id} [signal-edge]")
                failures += 1
        task_id = proposal.get("taskId")
        if isinstance(task_id, str) and ("proposal_task", proposal_id, task_id) not in edges:
            print(f"control-loop proposal {proposal_id} [task-edge]")
            failures += 1
    for run_id, ordinals in proposal_ordinals.items():
        if ordinals != list(range(1, len(ordinals) + 1)):
            print(f"control-loop planner {run_id} [proposal-ordinal]")
            failures += 1
    if not {"accepted", "invalid", "policy_rejected", "duplicate", "capacity_skipped"} <= outcomes:
        print("control-loop [proposal-outcome-coverage]")
        failures += 1
    if not {"planner-synthetic-failed", "planner-synthetic-success"} <= run_ids:
        print("control-loop [fresh-run-fixtures-missing]")
        failures += 1
    if run_ids != planner_event_ids:
        print("control-loop [planner-run-event-relation]")
        failures += 1
    if not {
        "observation_signal",
        "signal_planner_run",
        "planner_proposal",
        "signal_proposal",
        "proposal_task",
    } <= {edge_type for edge_type, _source, _target in edges}:
        print("control-loop [full-graph-edge-coverage]")
        failures += 1
    return failures


def _control_loop_validate_value(value: object, definition: str, label: object) -> int:
    failures = 0
    for error in _control_loop_validator(definition).iter_errors(value):
        print(f"control-loop {label} [schema-invalid]: {error.message}")
        failures += 1
    return failures


def main() -> int:
    failures = (
        validate_json_contracts()
        + validate_markdown_links()
        + validate_steward_dashboard()
        + validate_steward_observability()
        + validate_steward_growth()
        + validate_steward_dataset()
        + validate_control_loop_fixture()
    )
    if failures:
        print(f"contract validation failed with {failures} finding(s)")
        return 1
    print("contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
