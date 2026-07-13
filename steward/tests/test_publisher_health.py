from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.core.config import PublicMirrorConfig
from coquic_steward.core.subprocesses import CommandResult
from coquic_steward.orchestration.daemon import StewardDaemon
from coquic_steward.public_mirror import classify_publish_failure
from coquic_steward.core.models import PublicMirrorFailureCategory
from coquic_steward.storage import TaskStore


def _public_config(config, tmp_path: Path):
    return replace(
        config,
        public_mirror=PublicMirrorConfig(
            enabled=True,
            publish=True,
            output_path=tmp_path / "status.json",
            retry_initial_seconds=1,
            retry_max_seconds=2,
        ),
    )


@pytest.mark.parametrize(
    ("args", "stderr", "returncode", "expected"),
    [
        (["ssh"], "host key rejected", 255, PublicMirrorFailureCategory.ssh_preparation),
        (["rsync"], "remote transfer failed", 23, PublicMirrorFailureCategory.rsync_transfer),
        (["rsync"], "command timed out", 124, PublicMirrorFailureCategory.timeout),
        (["rsync"], "permission denied", 1, PublicMirrorFailureCategory.permissions),
    ],
)
def test_publish_failures_are_classified_without_raw_output(
    args: list[str], stderr: str, returncode: int, expected: PublicMirrorFailureCategory
) -> None:
    result = CommandResult(args=args, cwd=Path("."), returncode=returncode, stdout="", stderr=stderr)
    assert classify_publish_failure(result) == expected


def test_failed_publish_is_sanitized_and_recovery_resets_retry_state(
    config, tmp_path, monkeypatch
) -> None:
    config = _public_config(config, tmp_path)
    store = TaskStore(config.db_path)
    daemon = StewardDaemon(config, store)
    results = [
        CommandResult(
            args=["rsync"],
            cwd=config.repo_root,
            returncode=23,
            stdout="remote user=secret",
            stderr="permission denied /home/private/key",
        ),
        CommandResult(
            args=["rsync"],
            cwd=config.repo_root,
            returncode=0,
            stdout="",
            stderr="",
        ),
    ]

    def fake_publish(*_args, **_kwargs):
        return config.state_dir / "status.json", results.pop(0)

    monkeypatch.setattr(
        "coquic_steward.orchestration.daemon.publish_public_mirror", fake_publish
    )

    assert daemon._update_public_mirror_if_changed(publish=True) is False
    failed = json.loads((tmp_path / "status.json").read_text())["publication"]
    assert failed["state"] == "failed"
    assert failed["last_failure_category"] == "permissions"
    assert failed["retry_count"] == 1
    assert "/home/private" not in json.dumps(failed)
    assert "secret" not in json.dumps(failed)

    assert daemon._update_public_mirror_if_changed(publish=True) is True
    recovered = json.loads((tmp_path / "status.json").read_text())["publication"]
    assert recovered["state"] == "published"
    assert recovered["retry_count"] == 0
    assert recovered["last_failure_category"] is None
