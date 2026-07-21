from __future__ import annotations

import json
import stat
from pathlib import Path

from coquic_steward.agents.tool_changes import (
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
) -> bytes:
    value: dict[str, object] = {
        "hook_event_name": event,
        "session_id": session,
        "turn_id": turn,
        "cwd": str(repo),
        "tool_name": "apply_patch",
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


def test_failed_tool_is_behavior_only(repo: Path, tmp_path: Path) -> None:
    capture = ToolChangeCapture.start(repo, tmp_path / "tool-changes")
    handle_hook(_envelope(repo, "PreToolUse", "tool_1"), context_path=capture.context_path)
    handle_hook(
        _envelope(repo, "PostToolUse", "tool_1", response={"status": "error", "error": "failed"}),
        context_path=capture.context_path,
    )
    summary = capture.finalize()
    assert summary.failed == 1
    assert _manifest(capture.run_dir)[0]["status"] == "failed"


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
