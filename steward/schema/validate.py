from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("public-monitor-v3.json")
FIXTURE_DIR = Path(__file__).with_name("fixtures") / "public-monitor-v3"


class SchemaValidationError(ValueError):
    """Raised when a public monitor document violates the checked-in schema."""


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def load_public_monitor_schema_version() -> int:
    properties = load_schema().get("properties", {})
    version = properties.get("schema_version", {}).get("const")
    if type(version) is not int or version < 1:
        raise SchemaValidationError("schema_version must have a positive integer const")
    return version


def validate_public_monitor(value: object) -> None:
    schema = load_schema()
    _validate(value, schema, schema, "$", set())


def _validate(value: object, schema: dict[str, Any], root: dict[str, Any], path: str, stack: set[str]) -> None:
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in stack:
            raise SchemaValidationError(f"recursive schema reference at {path}")
        target = _resolve_ref(root, ref)
        _validate(value, target, root, path, stack | {ref})
        return

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        errors: list[str] = []
        for candidate in any_of:
            try:
                _validate(value, candidate, root, path, stack)
                break
            except SchemaValidationError as exc:
                errors.append(str(exc))
        else:
            raise SchemaValidationError(f"{path}: no anyOf branch matched ({'; '.join(errors)})")
        return

    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected {schema['const']!r}")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise SchemaValidationError(f"{path}: expected one of {enum!r}")

    expected = schema.get("type")
    if expected is not None and not _matches_type(value, expected):
        raise SchemaValidationError(f"{path}: expected {expected!r}")

    if isinstance(value, str):
        _check_number(schema.get("minLength"), len(value), path, "minimum length")
        _check_number(schema.get("maxLength"), len(value), path, "maximum length")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _check_number(schema.get("minimum"), value, path, "minimum")
        _check_number(schema.get("maximum"), value, path, "maximum")
    if isinstance(value, list):
        _check_number(schema.get("minItems"), len(value), path, "minimum items")
        _check_number(schema.get("maxItems"), len(value), path, "maximum items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate(item, item_schema, root, f"{path}[{index}]", stack)
    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            missing = [key for key in required if key not in value]
            if missing:
                raise SchemaValidationError(f"{path}: missing required fields {missing!r}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value and isinstance(child_schema, dict):
                    _validate(value[key], child_schema, root, f"{path}.{key}", stack)


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema reference {ref!r}")
    value: Any = root
    for part in ref[2:].split("/"):
        value = value[part]
    if not isinstance(value, dict):
        raise SchemaValidationError(f"schema reference {ref!r} is not an object")
    return value


def _matches_type(value: object, expected: object) -> bool:
    choices = expected if isinstance(expected, list) else [expected]
    return any(
        choice == "null" and value is None
        or choice == "object" and isinstance(value, dict)
        or choice == "array" and isinstance(value, list)
        or choice == "string" and isinstance(value, str)
        or choice == "integer" and isinstance(value, int) and not isinstance(value, bool)
        or choice == "number" and isinstance(value, (int, float)) and not isinstance(value, bool)
        or choice == "boolean" and isinstance(value, bool)
        for choice in choices
    )


def _check_number(limit: object, actual: int | float, path: str, label: str) -> None:
    if not isinstance(limit, (int, float)):
        return
    maximum = label.startswith("maximum")
    if (maximum and actual > limit) or (not maximum and actual < limit):
        raise SchemaValidationError(f"{path}: exceeds {label} {limit}")
