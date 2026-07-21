from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from coquic_steward.agents.tool_changes import (
    LOCK_TIMEOUT_SECONDS,
    MAX_TOOL_INPUT_BYTES,
    MAX_TOOL_RESPONSE_BYTES,
    ToolChangeCapture,
    handle_hook,
)
from coquic_steward.agents.runner import CodexRunner
from coquic_steward.core.models import CodexStage, TaskKind, TaskSpec, WorkerKind
from coquic_steward.core.subprocesses import run_command
from coquic_steward.execution.worktree import Worktrees
from coquic_steward.storage import TaskStore


def _envelope(
    repo: Path,
    event: str,
    tool_id: str,
    *,
    command: str = "apply_patch <<'PATCH'\nPATCH",
    response: object | None = None,
    session: str = "session_1",
    turn: str = "turn_1",
    tool_name: str = "apply_patch",
) -> bytes:
    value: dict[str, object] = {
        "hook_event_name": event,
        "session_id": session,
        "turn_id": turn,
        "cwd": str(repo),
        "tool_name": tool_name,
        "tool_use_id": tool_id,
        "tool_input": {"command": command},
    }
    if event == "PostToolUse":
        value["tool_response"] = response if response is not None else {"success": True}
    return json.dumps(value).encode("utf-8")


def _manifest(run_dir: Path) -> list[dict[str, object]]:
    path = run_dir / "manifest.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_hook_pair_captures_binary_and_untracked_tree(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    (repo / "blob.bin").write_bytes(b"\x00\x01\xff")
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    summary = capture.finalize()

    assert summary.state == "complete"
    assert summary.captured == 1
    record = _manifest(capture.run_dir)[0]
    patch = capture.run_dir / str(record["patch"]["path"])
    assert stat.S_IMODE(patch.stat().st_mode) == 0o600
    assert record["paths"] == ["README.md", "blob.bin"]
    clone = tmp_path / "clone"
    run_command(["git", "clone", "--no-hardlinks", str(repo), str(clone)], cwd=tmp_path, check=True)
    # The clone starts from the changed worktree, so apply the patch to a fresh
    # base repository instead to prove Git's binary patch is canonical.
    base = tmp_path / "base"
    run_command(["git", "clone", "--no-hardlinks", str(repo), str(base)], cwd=tmp_path, check=True)
    run_command(["git", "reset", "--hard", "HEAD~0"], cwd=base, check=True)
    run_command(["git", "apply", "--binary", str(patch)], cwd=base, check=True)
    assert (base / "README.md").read_text(encoding="utf-8") == "changed\n"
    assert (base / "blob.bin").read_bytes() == b"\x00\x01\xff"


def test_missing_or_untrusted_context_is_inert(repo: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("COQUIC_STEWARD_HOOK_CONTEXT", raising=False)
    handle_hook(b"not json")
    assert not (tmp_path / "tool-changes").exists()

    run_dir = tmp_path / "tool-changes"
    capture = ToolChangeCapture.start(repo, run_dir)
    handle_hook(_envelope(repo, "PreToolUse", "tool_1", session="session-a"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PostToolUse", "tool_1", session="session-b"), context_path=capture.context_path)
    assert capture.finalize().state == "partial"


def test_gap_and_unmatched_post_are_explicit(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PostToolUse", "missing"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    (repo / "README.md").write_text("external\n", encoding="utf-8")
    handle_hook(_envelope(repo, "PreToolUse", "tool_2"), context_path=capture.context_path)
    summary = capture.finalize()
    assert summary.state == "partial"
    assert summary.gaps >= 1
    assert "missing_pre" in summary.reasons
    assert "missing_post" in summary.reasons


def test_duplicate_tool_use_id_is_partial(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    summary = capture.finalize()
    assert summary.state == "partial"
    assert "duplicate_tool_use" in summary.reasons


def test_failed_tool_is_behavior_only(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(
        _envelope(repo, "PostToolUse", "tool_1", response={"status": "error", "error": "failed"}),
        context_path=capture.context_path,
    )
    summary = capture.finalize()
    assert summary.failed == 1
    assert summary.state == "partial"
    assert "tool_failed" in summary.reasons
    assert _manifest(capture.run_dir)[0]["status"] == "failed"


def test_successful_no_change_is_empty(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    summary = capture.finalize()

    assert summary.state == "complete"
    assert summary.empty == 1
    record = _manifest(capture.run_dir)[0]
    assert record["status"] == "empty"
    assert record["patch"] is None


def test_hook_manifest_omits_tool_input_and_response(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    value = {
        "hook_event_name": "PreToolUse",
        "session_id": "session_1",
        "turn_id": "turn_1",
        "cwd": str(repo),
        "tool_name": "apply_patch",
        "tool_use_id": "tool_1",
        "tool_input": "authorization=private-input",
    }
    handle_hook(json.dumps(value), context_path=capture.context_path)
    value["hook_event_name"] = "PostToolUse"
    value["tool_response"] = {"success": True, "output": "private-response"}
    handle_hook(json.dumps(value), context_path=capture.context_path)
    capture.finalize()
    record = _manifest(capture.run_dir)[0]
    serialized = json.dumps(record, sort_keys=True)
    assert "private-input" not in serialized
    assert "private-response" not in serialized
    assert not (capture.run_dir / "inputs").exists()
    assert not (capture.run_dir / "responses").exists()


def test_hook_response_remains_bounded_without_persistence(
    repo: Path, tmp_path: Path
) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(
        _envelope(
            repo,
            "PostToolUse",
            "tool_1",
            response={"output": "x" * (MAX_TOOL_RESPONSE_BYTES + 1)},
        ),
        context_path=capture.context_path,
    )

    summary = capture.finalize()
    assert summary.state == "partial"
    assert "oversized_response" in summary.reasons
    assert "missing_post" in summary.reasons
    assert not (capture.run_dir / "responses").exists()


def test_lock_contention_is_bounded(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    with capture.lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        started = time.monotonic()
        handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
        elapsed = time.monotonic() - started
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    assert elapsed < LOCK_TIMEOUT_SECONDS * 10
    summary = capture.finalize()
    assert summary.state == "unavailable"
    assert "lock_failed" in summary.reasons


def test_context_requires_private_file(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    capture.context_path.chmod(0o644)
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    assert capture.finalize().state == "unavailable"


def test_reconcile_refreshes_after_late_write(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    assert capture.finalize().state == "complete"

    (repo / "late.txt").write_text("unhooked\n", encoding="utf-8")
    final_patch = tmp_path / "final.patch"
    Worktrees.__new__(Worktrees).save_patch(repo, final_patch)
    summary = capture.reconcile(final_patch_path=final_patch)
    assert summary.state == "partial"
    assert "external_mutation" in summary.reasons
    assert capture.reconcile(final_patch_path=final_patch).state == "partial"


def test_authoritative_final_patch_is_reconciled(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    (repo / "new.bin").write_bytes(b"\x00\xff")
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    final_patch = tmp_path / "final.patch"
    Worktrees.__new__(Worktrees).save_patch(repo, final_patch)
    summary = capture.finalize(final_patch_path=final_patch)
    assert summary.state == "complete"


def test_authoritative_final_patch_uses_head_base_for_dirty_revision(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "README.md").write_text("prior revision\n", encoding="utf-8")
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    (repo / "later.txt").write_text("later revision\n", encoding="utf-8")
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    assert capture.finalize().state == "complete"

    final_patch = tmp_path / "final.patch"
    Worktrees.__new__(Worktrees).save_patch(repo, final_patch)
    summary = capture.reconcile(final_patch_path=final_patch)

    assert summary.state == "complete"
    assert "final_patch_mismatch" not in summary.reasons


def test_hook_cli_reads_large_bounded_pipe_input(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    command = "x" * (128 * 1024)
    env = {
        **os.environ,
        "COQUIC_STEWARD_HOOK_CONTEXT": str(capture.context_path),
    }
    for event in ("PreToolUse", "PostToolUse"):
        subprocess.run(
            [sys.executable, "-m", "coquic_steward.agents.tool_changes"],
            cwd=repo,
            env=env,
            input=_envelope(
                repo,
                event,
                "tool_1",
                command=command,
                tool_name="Bash",
            ),
            check=True,
        )

    summary = capture.finalize()
    assert summary.state == "complete"
    assert summary.discovered == 1
    record = _manifest(capture.run_dir)[0]
    assert "input" not in record
    assert "input_artifact" not in record
    assert not (capture.run_dir / "inputs").exists()

    oversized = ToolChangeCapture.start(repo, tmp_path / "oversized-tool-changes")
    oversized_env = {
        **os.environ,
        "COQUIC_STEWARD_HOOK_CONTEXT": str(oversized.context_path),
    }
    subprocess.run(
        [sys.executable, "-m", "coquic_steward.agents.tool_changes"],
        cwd=repo,
        env=oversized_env,
        input=_envelope(
            repo,
            "PreToolUse",
            "tool_2",
            command="x" * (MAX_TOOL_INPUT_BYTES + 1),
            tool_name="Bash",
        ),
        check=True,
    )
    oversized_summary = oversized.finalize()
    assert oversized_summary.state == "unavailable"
    assert "oversized_input" in oversized_summary.reasons


def test_context_artifacts_are_private(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(_envelope(repo, "PostToolUse", "tool_1"), context_path=capture.context_path)
    capture.finalize()
    for path in capture.run_dir.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_runner_only_exports_context_for_code_stage(config, tmp_path: Path) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        "printf '%s\\n' '{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"session_1\",\"turn_id\":\"turn_1\",\"cwd\":\"'\"$PWD\"'\",\"tool_name\":\"Bash\",\"tool_use_id\":\"tool_1\",\"tool_input\":{\"command\":\"printf changed > README.md\"}}' | python -m coquic_steward.agents.tool_changes\n"
        "printf changed > README.md\n"
        "printf '%s\\n' '{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"session_1\",\"turn_id\":\"turn_1\",\"cwd\":\"'\"$PWD\"'\",\"tool_name\":\"Bash\",\"tool_use_id\":\"tool_1\",\"tool_input\":{\"command\":\"printf changed > README.md\"},\"tool_response\":{\"success\":true}}' | python -m coquic_steward.agents.tool_changes\n"
        'mkdir -p "$(dirname "$last")"\n'
        'printf "done\\n" > "$last"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    result = CodexRunner(config).run(task, "hello", config.repo_root)
    assert result.completed
    assert result.diagnostics["tool_change_capture"]["captured"] == 1
    assert result.diagnostics["tool_change_capture"]["state"] == "complete"
    assert (result.transcript_path.parent / "tool-changes" / "manifest.jsonl").exists()


@pytest.mark.parametrize("archive_failure", ["collision", "rename"])
def test_retry_archive_failure_isolated_from_next_capture(
    config, tmp_path: Path, monkeypatch, archive_failure: str
) -> None:
    fake = tmp_path / "codex"
    calls = tmp_path / "calls.txt"
    fake.write_text(
        "#!/bin/sh\n"
        f'count=$(wc -l < "{calls}" 2>/dev/null || printf 0)\n'
        "count=$((count + 1))\n"
        f'printf "%s\\n" "$count" >> "{calls}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'tool_id="tool_$count"\n'
        'printf \'%s\\n\' \'{"hook_event_name":"PreToolUse","session_id":"session_1","turn_id":"turn_1","cwd":"\'"$PWD"\'","tool_name":"Bash","tool_use_id":"\'"$tool_id"\'","tool_input":{"command":"change README"}}\' | python -m coquic_steward.agents.tool_changes\n'
        'printf "%s\\n" "$tool_id" > README.md\n'
        'printf \'%s\\n\' \'{"hook_event_name":"PostToolUse","session_id":"session_1","turn_id":"turn_1","cwd":"\'"$PWD"\'","tool_name":"Bash","tool_use_id":"\'"$tool_id"\'","tool_input":{"command":"change README"},"tool_response":{"success":true}}\' | python -m coquic_steward.agents.tool_changes\n'
        'mkdir -p "$(dirname "$last")"\n'
        'if [ "$count" -eq 1 ]; then\n'
        "  printf 'stream disconnected before completion\\n' > \"$last\"\n"
        '  printf \'%s\\n\' \'{"type":"thread.started","thread_id":"thread-transient"}\'\n'
        "  exit 1\n"
        "fi\n"
        "printf 'done\\n' > \"$last\"\n"
        "printf '%s\\n' '{\"message\":\"done\"}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    runner = CodexRunner(config)
    transcript_path, _ = runner.paths(task)
    run_dir = transcript_path.parent
    run_dir.mkdir(parents=True, exist_ok=True)
    collision = run_dir / "tool-changes.retry-1"
    if archive_failure == "collision":
        collision.mkdir()
        (collision / "existing").write_text("keep\n", encoding="utf-8")
    else:
        original_replace = Path.replace

        def fail_tool_change_replace(self: Path, target: Path) -> Path:
            if self.name == "tool-changes":
                raise OSError("forced tool change archive failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", fail_tool_change_replace)
    monkeypatch.setattr("coquic_steward.agents.runner.time.sleep", lambda _delay: None)

    result = runner.run(task, "hello", config.repo_root)

    assert result.completed
    assert calls.read_text(encoding="utf-8").splitlines() == ["1", "2"]
    retry = result.diagnostics["retries"][0]
    assert retry["tool_changes_archive_failed"] is True
    current = run_dir / "tool-changes"
    if archive_failure == "collision":
        assert (collision / "existing").read_text(encoding="utf-8") == "keep\n"
        preserved = Path(retry["tool_changes_preserved_path"])
        assert [item["tool_use_id"] for item in _manifest(preserved)] == ["tool_1"]
        assert (
            ToolChangeCapture.from_context(preserved / "context.json").summary.state
            == "partial"
        )
        current_records = _manifest(current)
        assert [item["tool_use_id"] for item in current_records] == ["tool_2"]
        assert [item["start_sequence"] for item in current_records] == [1]
        assert result.diagnostics["tool_change_capture"]["state"] == "partial"
    else:
        assert retry["tool_changes_preserve_failed"] is True
        assert [item["tool_use_id"] for item in _manifest(current)] == ["tool_1"]
        assert (
            ToolChangeCapture.from_context(current / "context.json").summary.state
            == "partial"
        )
        assert result.diagnostics["tool_change_capture"]["state"] == "unavailable"
    assert "context_unavailable" in result.diagnostics["tool_change_capture"]["reasons"]


def test_non_code_stage_has_no_context_artifacts(config, tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "codex"
    fake.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi\n'
        "  shift || true\n"
        "done\n"
        "cat >/dev/null\n"
        'mkdir -p "$(dirname "$last")"\n'
        'printf "done\\n" > "$last"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    config = config.__class__(**{**config.__dict__, "codex_bin": str(fake)})
    config.ensure_dirs()
    task = TaskStore(config.db_path).add_task(
        TaskSpec(kind=TaskKind.custom, worker=WorkerKind.custom, title="T", prompt="P")
    )[0]
    monkeypatch.setenv("COQUIC_STEWARD_HOOK_CONTEXT", str(tmp_path / "ambient"))
    result = CodexRunner(config).run(
        task, "hello", config.repo_root, stage=CodexStage.implementation_plan
    )
    assert result.completed
    assert "tool_change_capture" not in result.diagnostics
    assert not (result.transcript_path.parent / "tool-changes").exists()
