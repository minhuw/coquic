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

EXAMPLE_TARGETS = {
    "coverage-snapshot.json": ("evidence.schema.json", "coverageSnapshot"),
    "interop-snapshot.json": ("evidence.schema.json", "interopSnapshot"),
    "performance-snapshot.json": ("evidence.schema.json", "performanceSnapshot"),
    "scenario-catalog.json": ("catalog.schema.json", "scenarioCatalog"),
    "steward-daily-summary.json": ("steward.schema.json", "dailySummary"),
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


def main() -> int:
    failures = (
        validate_json_contracts()
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
