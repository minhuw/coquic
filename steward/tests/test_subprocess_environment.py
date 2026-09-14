from __future__ import annotations

import json
import os
import sys

import pytest

from coquic_steward.core.subprocesses import run_command


@pytest.mark.parametrize("replace_env", (False, True))
def test_none_environment_overrides_delete_keys_without_mutating_parent(tmp_path, monkeypatch, replace_env):
    monkeypatch.setenv("STEWARD_TEST_REMOVE", "inherited")
    monkeypatch.setenv("STEWARD_TEST_REPLACE", "old")
    monkeypatch.setenv("STEWARD_TEST_KEEP", "kept")
    before = dict(os.environ)
    result = run_command(
        [sys.executable, "-c", "import os,json; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('STEWARD_TEST_')}))"],
        cwd=tmp_path,
        env={"STEWARD_TEST_REMOVE": None, "STEWARD_TEST_ABSENT": None,
             "STEWARD_TEST_REPLACE": "new", "STEWARD_TEST_EMPTY": ""},
        replace_env=replace_env,
        check=True,
    )
    expected = {"STEWARD_TEST_REPLACE": "new", "STEWARD_TEST_EMPTY": ""}
    if not replace_env:
        expected["STEWARD_TEST_KEEP"] = "kept"
    assert json.loads(result.stdout) == expected
    assert dict(os.environ) == before


def test_omitted_environment_still_inherits(tmp_path, monkeypatch):
    monkeypatch.setenv("STEWARD_TEST_KEEP", "kept")
    result = run_command(
        [sys.executable, "-c", "import os; print(os.environ['STEWARD_TEST_KEEP'])"],
        cwd=tmp_path, check=True,
    )
    assert result.stdout == "kept\n"
