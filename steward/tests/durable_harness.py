from __future__ import annotations

import shlex
from pathlib import Path

from coquic_steward.core.models import ValidationResult
from coquic_steward.execution import StewardExecutor
from coquic_steward.orchestration import StewardDaemon


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
    output = config.logs_dir / task_id / (label or "durable") / "gate.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("ok\n", encoding="utf-8")
    return [
        ValidationResult(
            command=["fake-gate"], cwd=cwd, passed=True, exit_code=0, output_path=output
        )
    ]
