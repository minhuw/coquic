from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from coquic_steward.agents.activity import (
    ACTIVITY_REPORTING_RULES,
    ActivityRecorder,
    activity_retry_pending_path,
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
    path.parent.mkdir(parents=True)
    path.with_name("codex.jsonl").write_text("{}\n", encoding="utf-8")
    recorder = ActivityRecorder(path, max_events=1)
    assert recorder.observe(
        _event("item_1", 'STEWARD_ACTIVITY {"activity":"orient","summary":"Read task"}')
    )
    assert not recorder.observe(
        _event("item_1", 'STEWARD_ACTIVITY {"activity":"edit","summary":"Change code"}')
    )
    assert not recorder.observe(
        _event("item_2", 'STEWARD_ACTIVITY {"activity":"report","summary":"Later"}')
    )
    assert recorder.finalize() == {
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


def test_recorder_creates_private_file_without_chmod(tmp_path: Path, monkeypatch) -> None:
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
        _event("item_4", 'STEWARD_ACTIVITY {"activity":"orient","summary":"' + "x" * 241 + '"}'),
    ]
    for case in cases:
        assert recorder.observe(case) is False
    assert recorder.finalize()["invalid"] == len(cases)


def test_successful_retry_replaces_activity_sidecar_and_clears_pending_marker(
    config, tmp_path: Path, monkeypatch
) -> None:
    fake = tmp_path / "codex"
    count = tmp_path / "count.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'count=$(cat "{count}" 2>/dev/null || printf 0)\n'
        "count=$((count + 1))\n"
        f'printf "%s" "$count" > "{count}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$count" -eq 1 ]; then\n'
        "  printf 'stream disconnected before completion\\n' > \"$last\"\n"
        "  printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"thread-transient\"}'\n"
        "  printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"id\":\"old_1\",\"type\":\"agent_message\",\"text\":\"STEWARD_ACTIVITY {\\\"activity\\\":\\\"report\\\",\\\"summary\\\":\\\"Old attempt\\\"}\"}}'\n"
        "  exit 1\n"
        "fi\n"
        "printf 'done\\n' > \"$last\"\n"
        "printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"id\":\"new_1\",\"type\":\"agent_message\",\"text\":\"STEWARD_ACTIVITY {\\\"activity\\\":\\\"edit\\\",\\\"summary\\\":\\\"New attempt\\\"}\"}}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    monkeypatch.setattr("coquic_steward.agents.runner.time.sleep", lambda _delay: None)

    result = CodexRunner(config).run(task, "hello", config.repo_root)

    assert result.completed
    assert not activity_retry_pending_path(result.transcript_path).exists()
    assert result.transcript_path.with_name("activities.retry-1.jsonl").is_file()
    final_records = [
        json.loads(line)
        for line in result.transcript_path.with_name("activities.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [
        record["summary"]
        for record in final_records
        if record.get("record_type") == "event"
    ] == ["New attempt"]


def test_retry_archives_activity_sidecar_as_private_evidence(config) -> None:
    transcript = config.transcripts_dir / "task" / "worker" / "codex.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n", encoding="utf-8")
    sidecar = transcript.with_name("activities.jsonl")
    recorder = ActivityRecorder(sidecar)
    recorder.observe(
        _event("old_1", 'STEWARD_ACTIVITY {"activity":"report","summary":"Old"}')
    )
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

    archived_path = transcript.with_name("activities.retry-1.jsonl")
    assert "activities_archive_failed" not in archived
    assert archived_path.is_file()
    assert not sidecar.exists()


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

    import time

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
