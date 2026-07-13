from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from steward.schema.validate import (
    FIXTURE_DIR,
    SCHEMA_PATH,
    SchemaValidationError,
    load_public_monitor_schema_version,
    validate_public_monitor,
)
from coquic_steward.public_schema import PUBLIC_STEWARD_SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "steward" / "schema" / "generate_types.py"
COMPATIBILITY_FIXTURE = ROOT / "steward" / "schema" / "fixtures" / "public-monitor-compatibility.json"


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


def test_schema_version_is_shared_by_producer_and_generated_consumers() -> None:
    version = load_public_monitor_schema_version()
    assert version == PUBLIC_STEWARD_SCHEMA_VERSION
    generated_types = (ROOT / "site" / "next" / "src" / "generated" / "steward-public.ts").read_text(encoding="utf-8")
    assert f"export const PUBLIC_STEWARD_SCHEMA_VERSION = {version};" in generated_types


def test_compatibility_cases_match_producer_expectations() -> None:
    manifest = json.loads(COMPATIBILITY_FIXTURE.read_text(encoding="utf-8"))
    assert manifest["cases"]["current"]["schema_version"] == load_public_monitor_schema_version()
    base = json.loads((ROOT / "steward" / "schema" / "fixtures" / manifest["base_fixture"]).read_text(encoding="utf-8"))
    for case in manifest["cases"].values():
        if "text" in case:
            with pytest.raises(json.JSONDecodeError):
                json.loads(case["text"])
            continue
        document = copy.deepcopy(base)
        if "schema_version" in case:
            document["schema_version"] = case["schema_version"]
        document.update(case.get("fields", {}))
        if case["expected"] == "compatible":
            validate_public_monitor(document)
        else:
            with pytest.raises(SchemaValidationError):
                validate_public_monitor(document)


def test_version_bump_fails_until_generated_contract_outputs_are_refreshed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temporary_root = Path(directory)
        schema_path = temporary_root / "public-monitor.json"
        types_path = temporary_root / "steward-public.ts"
        python_path = temporary_root / "public_schema.py"
        shutil.copy2(SCHEMA_PATH, schema_path)
        subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--schema",
                str(schema_path),
                "--typescript-output",
                str(types_path),
                "--python-output",
                str(python_path),
            ],
            cwd=ROOT,
            check=True,
        )
        bumped = json.loads(schema_path.read_text(encoding="utf-8"))
        bumped["properties"]["schema_version"]["const"] += 1
        schema_path.write_text(json.dumps(bumped), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--check",
                "--schema",
                str(schema_path),
                "--typescript-output",
                str(types_path),
                "--python-output",
                str(python_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
