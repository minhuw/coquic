from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from steward.schema.validate import (
    FIXTURE_DIR,
    SCHEMA_PATH,
    SchemaValidationError,
    validate_public_monitor,
)

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "steward" / "schema" / "generate_types.py"


@pytest.mark.parametrize("fixture", sorted(FIXTURE_DIR.glob("*.json")))
def test_v3_fixtures_validate(fixture: Path) -> None:
    document = json.loads(fixture.read_text(encoding="utf-8"))
    validate_public_monitor(document)


def test_schema_requires_runtime_and_rejects_bounded_overflow() -> None:
    document = json.loads((FIXTURE_DIR / "idle.json").read_text(encoding="utf-8"))
    missing_runtime = copy.deepcopy(document)
    del missing_runtime["runtime"]
    with pytest.raises(SchemaValidationError):
        validate_public_monitor(missing_runtime)

    too_many_tasks = copy.deepcopy(document)
    too_many_tasks["tasks"] = [{}] * 81
    with pytest.raises(SchemaValidationError):
        validate_public_monitor(too_many_tasks)


def test_schema_and_fixtures_contain_no_private_seed_data() -> None:
    serialized = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(FIXTURE_DIR.glob("*.json"))
    )
    for fragment in ("/home/", "/media/", "BEGIN PRIVATE KEY", "thread_id", "prompt", "ssh-key"):
        assert fragment not in serialized
    assert json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["$defs"]["Artifact"]["properties"]["truncated"]


def test_generated_types_are_deterministic_and_current() -> None:
    subprocess.run([sys.executable, str(GENERATOR), "--check"], cwd=ROOT, check=True)
