from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "contracts/steward-live/live-state.schema.json"
WORKER_TEST = ROOT / "infra/cloudflare/tests/live_state_worker.test.mjs"


def test_live_state_schema_is_closed_and_requires_availability() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["availability"] == {"enum": ["live", "stale"]}
    assert schema["properties"]["observedAt"]["pattern"].startswith("^[0-9]{4}")
    assert schema["properties"]["observedAt"]["pattern"].endswith("Z$")
    assert schema["properties"]["staleAfterSeconds"] == {
        "type": "integer",
        "minimum": 30,
        "maximum": 3600,
    }
    for field in ("daemon", "signals", "planning", "tasks", "integration"):
        assert schema["properties"][field]["additionalProperties"] is False


def test_live_state_worker_with_node_builtin_runner() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the dependency-free Worker tests")
    result = subprocess.run(
        [node, "--test", str(WORKER_TEST)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
