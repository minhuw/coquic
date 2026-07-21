from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from coquic_steward.agents.activity import (
    ACTIVITY_REPORTING_RULES,
    ActivityRecorder,
    parse_activity_marker,
)
from coquic_steward.agents.runner import (
    CodexRunner,
    _archive_retry_artifacts,
    _communicate_streaming,
    _prompt_with_activity_rules,
)
from coquic_steward.core.models import (
    CodexStage,
    TaskKind,
    TaskSpec,
    WorkerKind,
    WorkerResult,
)
from coquic_steward.public_mirror import _public_activities, _render_agent_message_item
from coquic_steward.storage import TaskStore


def _event(source_id: str, text: str) -> dict[str, object]:
    return {
        "type": "item.completed",
        "item": {"id": source_id, "type": "agent_message", "text": text},
    }


def test_marker_parser_requires_exact_closed_shape() -> None:
    valid = 'STEWARD_ACTIVITY {"activity":"investigate","summary":"Trace packets"}'
    assert parse_activity_marker(valid) is not None
    assert parse_activity_marker("human\n" + valid) is None
    assert parse_activity_marker(
        'STEWARD_ACTIVITY {"activity":"investigate","summary":"Trace","outcome":"ok"}'
    ) is None
    assert parse_activity_marker(
        'STEWARD_ACTIVITY {"activity":"unknown","summary":"Trace"}'
    ) is None
    assert parse_activity_marker(
        'STEWARD_ACTIVITY {"activity":"edit","summary":"line\\nnext"}'
    ) is None


def test_recorder_writes_ordered_private_records_and_bounded_counters(tmp_path: Path) -> None:
    path = tmp_path / "worker" / "activities.jsonl"
    recorder = ActivityRecorder(path, max_events=1)
    assert recorder.observe(
        _event(
            "item_1",
            'STEWARD_ACTIVITY {"activity":"orient","summary":"Read task"}',
        )
    )
    assert not recorder.observe(
        _event(
            "item_1",
            'STEWARD_ACTIVITY {"activity":"edit","summary":"Change code"}',
        )
    )
    assert not recorder.observe(
        _event(
            "item_2",
            'STEWARD_ACTIVITY {"activity":"report","summary":"Later"}',
        )
    )
    diagnostics = recorder.finalize()
    assert diagnostics == {
        "schema_version": 1,
        "capture_state": "complete",
        "recorded": 1,
        "invalid": 0,
        "duplicate": 1,
        "omitted": 1,
        "truncated": True,
    }
    assert path.stat().st_mode & 0o777 == 0o600
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["record_type"] == "header"
    assert records[1]["record_type"] == "event"
    assert records[-1]["record_type"] == "summary"
    assert records[1]["source_event_id"] == "item_1"
    assert "outcome" not in records[1]


def test_recorder_creates_private_file_without_chmod(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "worker" / "activities.jsonl"
    previous_umask = os.umask(0o022)
    monkeypatch.setattr(
        os,
        "chmod",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")),
    )
    try:
        recorder = ActivityRecorder(path)
        recorder.finalize()
    finally:
        os.umask(previous_umask)

    assert path.stat().st_mode & 0o777 == 0o600


def test_recorder_rejects_non_agent_and_malformed_markers(tmp_path: Path) -> None:
    recorder = ActivityRecorder(tmp_path / "activities.jsonl")
    cases = [
        {"type": "thread.started", "thread_id": "thread-private"},
        _event("bad id", 'STEWARD_ACTIVITY {"activity":"orient","summary":"ok"}'),
        _event("item_2", "STEWARD_ACTIVITY not-json"),
        _event("item_3", 'STEWARD_ACTIVITY {"activity":"orient","summary":"\x01"}'),
        _event(
            "item_4",
            'STEWARD_ACTIVITY {"activity":"orient","summary":"'
            + "x" * 241
            + '"}',
        ),
    ]
    for case in cases:
        assert recorder.observe(case) is False
    assert recorder.finalize()["invalid"] == len(cases)


def test_code_runner_injects_rules_and_records_marker(config, tmp_path: Path) -> None:
    fake = tmp_path / "codex"
    prompt_capture = tmp_path / "prompt.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f"cat > '{prompt_capture}'\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        'mkdir -p "$(dirname "$last")"\n'
        "printf 'done\\n' > \"$last\"\n"
        "printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"id\":\"item_1\",\"type\":\"agent_message\",\"text\":\"STEWARD_ACTIVITY {\\\"activity\\\":\\\"edit\\\",\\\"summary\\\":\\\"Update source\\\"}\"}}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    result = CodexRunner(config).run(task, "hello", config.repo_root)
    assert result.completed
    assert prompt_capture.read_text(encoding="utf-8").count(ACTIVITY_REPORTING_RULES) == 1
    sidecar = result.transcript_path.with_name("activities.jsonl")
    records = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    assert records[1]["activity"] == "edit"
    assert result.diagnostics["activities"]["recorded"] == 1
    assert result.transcript_path.read_text(encoding="utf-8").endswith("\n")


def test_retry_archive_failure_cannot_publish_previous_activity(config) -> None:
    transcript = config.transcripts_dir / "task" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n", encoding="utf-8")
    sidecar = transcript.with_name("activities.jsonl")
    recorder = ActivityRecorder(sidecar)
    assert recorder.observe(
        _event(
            "old_1",
            'STEWARD_ACTIVITY {"activity":"report","summary":"Old attempt"}',
        )
    )
    recorder.finalize()
    transcript.with_name("activities.retry-1.jsonl").mkdir()
    result = WorkerResult(
        completed=False,
        command=[],
        cwd=config.repo_root,
        exit_code=1,
        transcript_path=transcript,
        last_message_path=transcript.with_name("last-message.md"),
    )

    archived = _archive_retry_artifacts(result, 1, archive_tool_changes=False)

    assert archived["activities_archive_failed"] is True
    assert archived["activities_preserved"] is True
    assert transcript.with_name("activities.retry-1.unavailable-1.jsonl").exists()
    assert not sidecar.exists()
    assert _public_activities(config, transcript)["availability"] == "not_produced"

    current = ActivityRecorder(sidecar)
    assert current.observe(
        _event(
            "new_1",
            'STEWARD_ACTIVITY {"activity":"edit","summary":"New attempt"}',
        )
    )
    current.finalize()
    public = _public_activities(config, transcript)
    assert public["availability"] == "available"
    assert [event["summary"] for event in public["events"]] == ["New attempt"]


def test_retry_invalidation_fails_closed_without_private_diagnostics(config) -> None:
    transcript = config.transcripts_dir / "task" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n", encoding="utf-8")
    sidecar = transcript.with_name("activities.jsonl")
    recorder = ActivityRecorder(sidecar)
    assert recorder.observe(
        _event(
            "old_1",
            'STEWARD_ACTIVITY {"activity":"report","summary":"Old attempt"}',
        )
    )
    recorder.finalize()
    transcript.with_name("activities.retry-1.jsonl").mkdir()
    result = WorkerResult(
        completed=False,
        command=[],
        cwd=config.repo_root,
        exit_code=1,
        transcript_path=transcript,
        last_message_path=transcript.with_name("last-message.md"),
    )
    sidecar.chmod(0o400)
    transcript.parent.chmod(0o500)
    try:
        archived = _archive_retry_artifacts(result, 1, archive_tool_changes=False)
    finally:
        transcript.parent.chmod(0o700)

    assert archived == {
        "transcript_archive_failed": True,
        "activities_archive_failed": True,
        "activities_preserve_failed": True,
        "activities_invalidated": True,
    }
    assert sidecar.exists()
    assert sidecar.stat().st_mode & 0o777 == 0
    assert _public_activities(config, transcript)["availability"] == "unavailable"


def test_retry_activity_diagnostics_do_not_expose_archive_path(config) -> None:
    transcript = config.transcripts_dir / "task" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n", encoding="utf-8")
    recorder = ActivityRecorder(transcript.with_name("activities.jsonl"))
    recorder.finalize()
    result = WorkerResult(
        completed=False,
        command=[],
        cwd=config.repo_root,
        exit_code=1,
        transcript_path=transcript,
        last_message_path=transcript.with_name("last-message.md"),
    )

    archived = _archive_retry_artifacts(result, 1, archive_tool_changes=False)

    assert not any(key.startswith("activities_") for key in archived)


def test_slow_metadata_observer_does_not_extend_process_timeout(tmp_path: Path) -> None:
    raw_line = '{"type":"item.completed","item":{"type":"agent_message"}}\n'
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time; "
            f"sys.stdout.write({raw_line!r}); sys.stdout.flush(); time.sleep(5)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    observer_started = threading.Event()
    release_observer = threading.Event()

    def slow_observer(_event: dict[str, object]) -> None:
        observer_started.set()
        release_observer.wait(timeout=2)

    started = time.monotonic()
    try:
        stdout = _communicate_streaming(
            proc,
            "",
            tmp_path / "codex.jsonl",
            timeout_seconds=0.1,
            event_observer=slow_observer,
        )
        elapsed = time.monotonic() - started
    finally:
        release_observer.set()

    assert observer_started.is_set()
    assert elapsed < 1.0
    assert proc.returncode == 124
    assert stdout == raw_line
    assert (tmp_path / "codex.jsonl").read_text(encoding="utf-8").startswith(raw_line)


def test_non_code_prompts_do_not_receive_activity_rules() -> None:
    assert ACTIVITY_REPORTING_RULES not in _prompt_with_activity_rules(
        "plan", CodexStage.implementation_plan
    )
    assert ACTIVITY_REPORTING_RULES not in _prompt_with_activity_rules(
        "review", CodexStage.review
    )
    assert ACTIVITY_REPORTING_RULES in _prompt_with_activity_rules("code", CodexStage.code)


def test_public_activity_projection_is_bounded_and_marker_is_removed(config, tmp_path: Path) -> None:
    transcript = config.transcripts_dir / "task" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n", encoding="utf-8")
    recorder = ActivityRecorder(transcript.with_name("activities.jsonl"))
    for index in range(70):
        recorder.observe(
            _event(
                f"item_{index}",
                'STEWARD_ACTIVITY {"activity":"report","summary":"secret /home/private"}',
            )
        )
    recorder.finalize()
    projected = _public_activities(config, transcript)
    assert projected["availability"] == "available"
    assert projected["published_count"] == 64
    assert projected["omitted_event_count"] == 6
    assert projected["events"][0]["sequence"] == 7
    assert "/home/private" not in json.dumps(projected)
    rendered = _render_agent_message_item(
        {"text": 'STEWARD_ACTIVITY {"activity":"report","summary":"ok"}\nHuman text'}
    )
    assert rendered == "Human text"
    malformed = _render_agent_message_item({"text": "STEWARD_ACTIVITY not-json\nHuman"})
    assert malformed.startswith("STEWARD_ACTIVITY")
