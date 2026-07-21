from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.core.config import PublicMirrorConfig
from coquic_steward.core.models import Event, SignalItem
from coquic_steward.public_mirror import (
    _public_change_trajectory,
    public_mirror_payload,
    write_public_mirror,
)
from coquic_steward.storage import TaskStore


def test_public_target_rejects_raw_transcripts() -> None:
    with pytest.raises(ValueError, match="raw.*publish=true"):
        PublicMirrorConfig(publish=True, transcript_mode="raw")


def test_recursive_public_redaction_and_link_allowlist(config) -> None:
    store = TaskStore(config.db_path)
    store.add_signal_items(
        [
            SignalItem(
                provider="test",
                kind="finding",
                fingerprint="fingerprint-is-not-public",
                title="API_KEY=should-not-leak",
                summary=(
                    "thread_private and /home/private/key.pem "
                    "/worktrees/task /transcripts/task /patches/task "
                    "secret = client_secret ="
                ),
                links=[
                    {"label": "safe", "url": "https://github.com/minhuw/coquic/issues/1"},
                    {"label": "unsafe", "url": "https://evil.example.test/steal"},
                ],
                payload={"prompt": "private prompt", "nested": {"token": "secret"}},
            )
        ]
    )
    store.add_event(
        "daemon",
        "diagnostic",
        "Authorization: Bearer private-token",
        {
            "prompt": "private prompt",
            "nested": {
                "api_key": "secret",
                "url": "file:///etc/passwd",
                "safe_url": "https://github.com/minhuw/coquic/commit/abcdef1",
            },
        },
    )

    payload = public_mirror_payload(config, store)
    serialized = json.dumps(payload, sort_keys=True)
    assert "private prompt" not in serialized
    assert "private-token" not in serialized
    assert "/home/private" not in serialized
    assert "/worktrees/" not in serialized
    assert "/transcripts/" not in serialized
    assert "/patches/" not in serialized
    assert "file://" not in serialized
    assert "secret =" not in serialized
    assert "client_secret" not in serialized
    assert "https://evil.example.test" not in serialized
    assert payload["signals"]["items"][0]["links"] == [
        {"label": "safe", "url": "https://github.com/minhuw/coquic/issues/1"}
    ]


def test_public_artifacts_have_explicit_size_and_restrictive_permissions(
    config, tmp_path: Path
) -> None:
    config = replace(
        config,
        public_mirror=replace(
            config.public_mirror,
            output_path=tmp_path / "status.json",
            transcript_mode="redacted",
        ),
    )
    path = write_public_mirror(config, TaskStore(config.db_path))
    assert path.stat().st_mode & 0o077 == 0


def test_public_planner_history_is_bounded_and_sanitized(config) -> None:
    store = TaskStore(config.db_path)
    run_id = "planner-task-20260713120000-a1b2c3d4"
    transcript = config.transcripts_dir / run_id / "planner" / "codex.jsonl"
    last_message = config.transcripts_dir / run_id / "planner" / "last-message.md"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(
        '{"type":"item.completed","item":{"type":"agent_message","text":"safe result"}}\n',
        encoding="utf-8",
    )
    last_message.write_text("safe last message\n", encoding="utf-8")
    store.add_event(
        "daemon",
        "planner.finished",
        "planner finished",
        {
            "run_id": run_id,
            "completed": True,
            "exit_code": 0,
            "accepted_count": 1,
            "proposed_count": 2,
            "consumed_item_ids": ["signal-1"],
            "thread_id": "private-thread",
            "transcript_path": str(transcript),
        },
    )

    planner = public_mirror_payload(config, store)["planner_runs"]
    assert len(planner) == 1
    assert planner[0]["id"] == run_id
    assert planner[0]["status"] == "succeeded"
    assert planner[0]["accepted_count"] == 1
    assert planner[0]["artifacts"]["transcript"]["availability"] == "available"
    assert "private-thread" not in json.dumps(planner)
    assert str(config.state_dir) not in json.dumps(planner)


def test_malformed_private_trajectory_fails_closed_without_private_text(config) -> None:
    transcript = config.transcripts_dir / "task-private" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text("worker\n", encoding="utf-8")
    run_dir = transcript.parent / "tool-changes"
    run_dir.mkdir()
    (run_dir / "summary.json").write_text(
        '{"schema_version":1,"state":"complete","completeness":"complete",'
        '"reasons":["private prompt /home/private/key.pem"],'
        '"reason_categories":[],"discovered":1}',
        encoding="utf-8",
    )

    trajectory = _public_change_trajectory(config, transcript)
    assert trajectory["availability"] == "unavailable"
    assert trajectory["completeness"] == "unavailable"
    serialized = json.dumps(trajectory)
    assert "private prompt" not in serialized
    assert "/home/private" not in serialized
