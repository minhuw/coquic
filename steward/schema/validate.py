from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

SCHEMA_PATH = Path(__file__).with_name("public-monitor-v3.json")
FIXTURE_DIR = Path(__file__).with_name("fixtures") / "public-monitor-v3"
_MAX_VALIDATION_ERRORS = 4
_MAX_ERROR_LENGTH = 240
_MAX_DIAGNOSTIC_LENGTH = 1024


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
    try:
        schema = load_schema()
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        errors = []
        for error in validator.iter_errors(value):
            errors.append(error)
            if len(errors) == _MAX_VALIDATION_ERRORS:
                break
        errors = sorted(
            errors,
            key=lambda error: (_error_path(error), error.validator or "", _clip(error.message)),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaError, TypeError, ValueError) as exc:
        raise SchemaValidationError("public monitor schema validation could not run") from exc

    if errors:
        details = "; ".join(_format_error(error) for error in errors)
        raise SchemaValidationError(
            _clip(f"public monitor document is invalid: {details}", _MAX_DIAGNOSTIC_LENGTH)
        )


def _format_error(error: ValidationError) -> str:
    return f"{_error_path(error)}: {error.validator} ({_clip(error.message)})"


def _error_path(error: ValidationError) -> str:
    path = "$"
    for part in error.absolute_path:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{_clip(str(part), 80)}"
    return path


def _clip(value: str, limit: int = _MAX_ERROR_LENGTH) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."
