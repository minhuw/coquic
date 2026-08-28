from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from coquic_steward.core.config import PathPolicyConfig, StewardConfig, StewardLimits
from coquic_steward.core.models import TaskKind, TaskSpec, ValidationResult, WorkerKind
from coquic_steward.execution import StewardExecutor
from coquic_steward.orchestration import StewardDaemon
from coquic_steward.storage import TaskStore


def drive_durable(
    executor: StewardExecutor,
    task_id: str,
    *,
    max_steps: int = 128,
    finalize: bool = False,
) -> bool:
    """Advance one task through persisted phases with a bounded driver."""

    for _ in range(max_steps):
        outcome = executor.advance_once(task_id)
        if outcome.status in {"ready_to_seal", "terminal", "blocked"}:
            if finalize:
                StewardDaemon(executor.config, executor.store).finalize_terminal_task(task_id)
            return outcome.status in {"ready_to_seal", "terminal"}
        if outcome.status == "in_progress":
            continue
        if not outcome.progressed and outcome.next_phase is None:
            return False
    raise AssertionError(f"durable task did not reach a stopping point: {task_id}")


def write_durable_codex(
    tmp_path: Path,
    *,
    change: str = "changed by durable pipeline",
    review: str = (
        '{"verdict":"approve","summary":"ok","findings":[],'
        '"validation_gaps":[],"remaining_risk":""}'
    ),
    commit: str = (
        '{"subject":"fix: durable pipeline",'
        '"body":"persist the accepted durable tree"}'
    ),
    plan: str | None = None,
    thread_events: bool = False,
) -> Path:
    fake = tmp_path / "durable-codex"
    events = (
        {
            "plan": '{"type":"thread.started","thread_id":"plan-thread"}',
            "review": '{"type":"thread.started","thread_id":"review-thread"}',
            "commit": '{"type":"thread.started","thread_id":"commit-message-thread"}',
            "change": '{"type":"thread.started","thread_id":"worker-thread"}',
        }
        if thread_events
        else {}
    )

    def event(stage: str) -> str:
        if stage not in events:
            return ""
        return f"; printf '%s\\n' {shlex.quote(events[stage])}"

    script = [
        "#!/bin/sh",
        "last=",
        'while [ "$#" -gt 0 ]; do',
        '  if [ "$1" = "--output-last-message" ]; then shift; last=$1; fi',
        "  shift || true",
        "done",
        "cat >/dev/null",
        'mkdir -p "$(dirname "$last")"',
        'case "$last" in',
    ]
    if plan is not None:
        script.append(
            f"  */implementation-plan-*) printf '%s\\n' {shlex.quote(plan)} > \"$last\""
            f"{event('plan')} ;;"
        )
    script.extend(
        [
            f"  */reviewer-*) printf '%s\\n' {shlex.quote(review)} > \"$last\""
            f"{event('review')} ;;",
            f"  */commit-message-*) printf '%s\\n' {shlex.quote(commit)} > \"$last\""
            f"{event('commit')} ;;",
            f"  *) printf '%s\\n' {shlex.quote(change)} > README.md; "
            f"printf 'done\\n' > \"$last\"{event('change')} ;;",
            "esac",
        ]
    )
    fake.write_text("\n".join(script) + "\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


def passing_durable_gates(
    config,
    task_id,
    cwd,
    *,
    label=None,
    on_gate_start=None,
    on_gate_result=None,
    command_runner=None,
):
    command = ["fake-gate"]
    if on_gate_start is not None:
        on_gate_start(0, "gate.txt", command)
    output = config.logs_dir / task_id / (label or "durable") / "gate.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\n", encoding="utf-8")
    validation = ValidationResult(
        command=command, cwd=cwd, passed=True, exit_code=0, output_path=output
    )
    if on_gate_result is not None:
        on_gate_result(0, validation)
    return [validation]

def _advance_durable(
    executor: StewardExecutor, task_id: str, steps: int
) -> list[object]:
    return [executor.advance_once(task_id) for _ in range(steps)]

def _callback_gate_results(
    results: list[ValidationResult], *, on_gate_start=None, on_gate_result=None
) -> list[ValidationResult]:
    for position, validation in enumerate(results):
        if on_gate_start is not None:
            on_gate_start(position, validation.output_path.name, validation.command)
        if on_gate_result is not None:
            on_gate_result(position, validation)
    return results

def _durable_push_setup(
    config: StewardConfig,
    tmp_path: Path,
    monkeypatch,
    *,
    issue_numbers: tuple[int, ...] = (),
    dry_run: bool = False,
    frozen_paths: tuple[str, ...] = (),
    max_main_pushes_per_day: int | None = None,
):
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)],
        cwd=config.repo_root,
        check=True,
    )
    subprocess.run(
        ["git", "push", "-u", "origin", "main"],
        cwd=config.repo_root,
        check=True,
    )
    fake = write_durable_codex(tmp_path, change="durable push change")
    config = config.__class__(
        **{
            **config.__dict__,
            "codex_bin": str(fake),
            "git_remote": "origin",
            "dry_run": dry_run,
            "limits": (
                StewardLimits(
                    **{
                        **config.limits.__dict__,
                        "max_main_pushes_per_day": max_main_pushes_per_day,
                    }
                )
                if max_main_pushes_per_day is not None
                else config.limits
            ),
            "path_policy": (
                PathPolicyConfig(
                    frozen_by_kind={TaskKind.integration.value: frozen_paths}
                )
                if frozen_paths
                else config.path_policy
            ),
        }
    )
    config.ensure_dirs()
    store = TaskStore.create(config.db_path, dry_run=dry_run)
    selected = [
        {
            "kind": "github-issues.feature-request",
            "payload": {"issue_number": number},
        }
        for number in issue_numbers
    ]
    source, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.feature,
            worker=WorkerKind.feature_implementer,
            title="Feature source",
            prompt="Implement the selected feature",
            metadata={"source_context": {"selected_signal_items": selected}},
        )
    )
    integration, _ = store.add_task(
        TaskSpec(
            kind=TaskKind.integration,
            worker=WorkerKind.integration_manager,
            title="Integrate feature",
            prompt="Integrate the feature",
            metadata={"source_task_id": source.id},
        )
    )
    monkeypatch.setattr(
        "coquic_steward.execution.executor.run_gates", passing_durable_gates
    )
    return config, store, source, integration, StewardExecutor(config, store)
