from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from coquic_steward.core.config import PublicMirrorConfig
from coquic_steward.core.models import Event, SignalItem
from coquic_steward.public_mirror import public_mirror_payload, write_public_mirror
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
                summary="thread_private and /home/private/key.pem",
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
    assert "file:///etc/passwd" not in serialized
    assert "https://evil.example.test" not in serialized
    assert "https://github.com/minhuw/coquic/commit/abcdef1" in serialized
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

