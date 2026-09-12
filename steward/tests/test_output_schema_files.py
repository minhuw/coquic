from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from coquic_steward.core.config import StewardConfig
from coquic_steward.core.output_schema import write_output_schema_file
from coquic_steward.execution.executor import (
    COMMIT_MESSAGE_OUTPUT_SCHEMA,
    commit_message_schema_path,
)
from coquic_steward.execution.formality import FORMALITY_OUTPUT_SCHEMA, formality_schema_path
from coquic_steward.execution.implementation_plan import (
    IMPLEMENTATION_PLAN_SCHEMA,
    implementation_plan_schema_path,
)
from coquic_steward.execution.review import REVIEW_OUTPUT_SCHEMA, review_schema_path
from coquic_steward.planning.planner import PLANNER_OUTPUT_SCHEMA, planner_schema_path


@pytest.mark.parametrize(
    ("writer", "schema", "filename", "trailing_newline"),
    [
        (planner_schema_path, PLANNER_OUTPUT_SCHEMA, "planner.schema.json", False),
        (
            implementation_plan_schema_path,
            IMPLEMENTATION_PLAN_SCHEMA,
            "implementation-plan.schema.json",
            False,
        ),
        (review_schema_path, REVIEW_OUTPUT_SCHEMA, "review.schema.json", False),
        (formality_schema_path, FORMALITY_OUTPUT_SCHEMA, "formality.schema.json", True),
        (
            commit_message_schema_path,
            COMMIT_MESSAGE_OUTPUT_SCHEMA,
            "commit-message.schema.json",
            False,
        ),
    ],
)
def test_schema_wrappers_preserve_path_and_bytes(
    config: StewardConfig,
    writer: Callable[[StewardConfig], Path],
    schema: dict[str, object],
    filename: str,
    trailing_newline: bool,
) -> None:
    path = writer(config)

    assert path == config.state_dir / "schemas" / filename
    expected = json.dumps(schema, indent=2).encode("utf-8")
    if trailing_newline:
        expected += b"\n"
    assert path.read_bytes() == expected


def test_writer_creates_parent_and_overwrites_existing_file(config: StewardConfig) -> None:
    schema_path = config.state_dir / "schemas" / "custom.json"

    returned = write_output_schema_file(config, "custom.json", {"version": 1})
    assert returned == schema_path
    assert schema_path.read_bytes() == json.dumps({"version": 1}, indent=2).encode("utf-8")

    write_output_schema_file(config, "custom.json", {"version": 2})

    assert schema_path.read_bytes() == json.dumps({"version": 2}, indent=2).encode("utf-8")

def test_planner_schema_file_matches_expected_shape(config: StewardConfig) -> None:
    path = planner_schema_path(config)
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == ["consumed_item_ids", "tasks"]
    assert schema["properties"]["consumed_item_ids"]["type"] == "array"
    item = schema["properties"]["tasks"]["items"]
    assert "code-quality" in item["properties"]["kind"]["enum"]
    assert "feature" in item["properties"]["kind"]["enum"]
    assert schema["additionalProperties"] is False
    assert item["additionalProperties"] is False
    assert item["properties"]["metadata"]["additionalProperties"] is False
    assert item["properties"]["metadata"]["required"] == ["selected_signal_item_ids"]
    assert set(item["properties"]["metadata"]["properties"]) == {
        "selected_signal_item_ids",
    }
    selected_ids = item["properties"]["metadata"]["properties"]["selected_signal_item_ids"]
    assert selected_ids["items"]["type"] == "string"

def test_planner_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(planner_schema_path(config).read_text(encoding="utf-8"))

    assert_openai_structured_output_schema(schema)

def test_review_schema_file_matches_expected_shape(config: StewardConfig) -> None:
    path = review_schema_path(config)
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == [
        "verdict",
        "summary",
        "findings",
        "validation_gaps",
        "remaining_risk",
    ]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["verdict"]["enum"] == ["approve", "block"]
    finding = schema["properties"]["findings"]["items"]
    assert finding["additionalProperties"] is False
    assert finding["properties"]["line"]["type"] == ["integer", "null"]

def test_review_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(review_schema_path(config).read_text(encoding="utf-8"))

    assert_openai_structured_output_schema(schema)

def test_commit_message_schema_matches_openai_structured_output_subset(
    config: StewardConfig,
) -> None:
    schema = json.loads(commit_message_schema_path(config).read_text(encoding="utf-8"))

    assert schema["type"] == "object"
    assert schema["required"] == ["subject", "body"]
    assert schema["additionalProperties"] is False
    assert_openai_structured_output_schema(schema)

def test_formality_schema_recursively_requires_closed_objects(config: StewardConfig) -> None:
    schema = json.loads(formality_schema_path(config).read_text(encoding="utf-8"))

    def visit(node: object) -> None:
        if isinstance(node, dict):
            node_type = node.get("type")
            types = node_type if isinstance(node_type, list) else [node_type]
            if "object" in types:
                assert node.get("additionalProperties") is False
                assert isinstance(node.get("properties"), dict)
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(schema)


def assert_openai_structured_output_schema(schema: dict[str, object]) -> None:
    unsupported_keywords = {
        "allOf",
        "not",
        "dependentRequired",
        "dependentSchemas",
        "if",
        "then",
        "else",
        "patternProperties",
        # Keep schemas compatible with fine-tuned model Structured Outputs too.
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "multipleOf",
        "unevaluatedProperties",
        "propertyNames",
        "minProperties",
        "maxProperties",
        "minItems",
        "maxItems",
        "uniqueItems",
        "contains",
    }
    supported_types = {"string", "number", "boolean", "integer", "object", "array", "null"}
    stats = {
        "properties": 0,
        "enum_values": 0,
        "max_depth": 0,
        "schema_string_length": 0,
        "largest_enum_string_length": 0,
    }

    def visit(node: object, path: str, depth: int) -> None:
        if not isinstance(node, dict):
            return
        stats["max_depth"] = max(stats["max_depth"], depth)
        unsupported = unsupported_keywords & set(node)
        assert not unsupported, f"{path}: unsupported keywords {sorted(unsupported)}"
        if "enum" in node:
            enum = node["enum"]
            assert isinstance(enum, list), f"{path}.enum must be an array"
            stats["enum_values"] += len(enum)
            enum_string_length = 0
            for value in enum:
                if isinstance(value, str):
                    enum_string_length += len(value)
                    stats["schema_string_length"] += len(value)
            stats["largest_enum_string_length"] = max(
                stats["largest_enum_string_length"], enum_string_length
            )
        node_type = node.get("type")
        types = node_type if isinstance(node_type, list) else [node_type]
        assert all(item in supported_types for item in types), (
            f"{path}: unsupported type {node_type!r}"
        )
        if "object" in types:
            properties = node.get("properties")
            assert isinstance(properties, dict), f"{path}: object missing properties"
            assert (
                node.get("additionalProperties") is False
            ), f"{path}: additionalProperties must be false"
            required = node.get("required")
            assert isinstance(required, list), f"{path}: required must be an array"
            assert set(required) == set(properties), (
                f"{path}: required must include exactly every property"
            )
            stats["properties"] += len(properties)
            for key, value in properties.items():
                stats["schema_string_length"] += len(key)
                visit(value, f"{path}.properties.{key}", depth + 1)
        items = node.get("items")
        if isinstance(items, dict):
            visit(items, f"{path}.items", depth + 1)
        for keyword in ("anyOf", "$defs"):
            value = node.get(keyword)
            if isinstance(value, list):
                for index, item in enumerate(value):
                    visit(item, f"{path}.{keyword}[{index}]", depth + 1)
            elif isinstance(value, dict):
                for key, item in value.items():
                    visit(item, f"{path}.{keyword}.{key}", depth + 1)

    visit(schema, "$", 1)
    assert schema.get("type") == "object"
    assert "anyOf" not in schema
    assert stats["properties"] <= 5000
    assert stats["enum_values"] <= 1000
    assert stats["max_depth"] <= 10
    assert stats["schema_string_length"] <= 120_000
    if stats["enum_values"] > 250:
        assert stats["largest_enum_string_length"] <= 15_000
