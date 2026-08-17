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
    expected = json.dumps(schema, indent=2)
    if trailing_newline:
        expected += "\n"
    assert path.read_text(encoding="utf-8") == expected


def test_writer_creates_parent_and_overwrites_existing_file(config: StewardConfig) -> None:
    schema_path = config.state_dir / "schemas" / "custom.json"

    returned = write_output_schema_file(config, "custom.json", {"version": 1})
    assert returned == schema_path
    assert schema_path.read_text(encoding="utf-8") == json.dumps({"version": 1}, indent=2)

    write_output_schema_file(config, "custom.json", {"version": 2})

    assert schema_path.read_text(encoding="utf-8") == json.dumps({"version": 2}, indent=2)
