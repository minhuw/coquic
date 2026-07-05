from __future__ import annotations

import json
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import TaskRecord, ValidationResult, utc_now
from ..core.subprocesses import run_command

VALIDATION_SCOPE_CONTROL = """\
Validation repair scope control:
- Fix validation failures caused by the current patch with the smallest source
  change that preserves the original task scope.
- Do not change repo-wide tooling, Nix/flake setup, generated snapshots, vendored
  files, or scanner/CI policy just to make a gate pass unless the original task
  is explicitly about that tooling.
- If a validation failure exposes unrelated broken tooling or prerequisite work,
  keep the feature patch scoped and report a follow-up task proposal instead of
  implementing that work here.
- Follow-up task proposals must use this format in the final report:
  Follow-up task proposals:
  - Title: <imperative title>
    Kind: <feature|ci|code-quality|rfc-audit|custom>
    Worker: <recommended steward worker>
    Rationale: <why this is outside the current task>
    Scope: <files/subsystems and explicit non-goals>
    Validation: <commands/tests>
"""


DEFAULT_GATES = (
    ("git-diff-check.txt", ["git", "diff", "--check"]),
    ("zig-build-test.txt", ["nix", "develop", "-c", "zig", "build", "test"]),
    ("pre-commit.txt", ["nix", "develop", "-c", "pre-commit", "run", "--all-files"]),
)


def run_gates(
    config: StewardConfig, task_id: str, cwd: Path, *, label: str | None = None
) -> list[ValidationResult]:
    results: list[ValidationResult] = []
    for filename, command in DEFAULT_GATES:
        results.append(
            run_validation(config, task_id, cwd, filename, command, label=label)
        )
    return results


def run_validation(
    config: StewardConfig,
    task_id: str,
    cwd: Path,
    filename: str,
    command: list[str],
    *,
    label: str | None = None,
) -> ValidationResult:
    output_path = config.logs_dir / task_id / label / filename if label else config.logs_dir / task_id / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    result = run_command(
        command,
        cwd=cwd,
        timeout=config.limits.validation_timeout_minutes * 60,
    )
    output_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n",
        encoding="utf-8",
    )
    return ValidationResult(
        command=command,
        cwd=cwd,
        passed=result.ok,
        exit_code=result.returncode,
        output_path=output_path,
        summary=(result.stdout or result.stderr).strip()[-1000:],
        started_at=started,
        completed_at=utc_now(),
    )


def render_validation_revision_prompt(
    task: TaskRecord,
    validations: list[ValidationResult],
    config: StewardConfig | None = None,
) -> str:
    failed = [validation for validation in validations if not validation.passed]
    lines = [
        "A Steward validation gate failed for your current patch.",
        "",
        f"Task: {task.id} - {task.spec.title}",
        "",
        "Fix the validation failures in the existing worktree.",
        "Keep the original task scope. Do not commit, push, or change generated state.",
        VALIDATION_SCOPE_CONTROL,
        "After editing, run the relevant local validation commands and leave the revised patch in the worktree.",
    ]
    frozen = _render_frozen_paths(task, config)
    if frozen:
        lines.extend(["", "Frozen path policy:", frozen])
    lines.extend(
        [
            "",
            "Original task prompt:",
            task.spec.prompt,
            "",
            "Failed validation JSON:",
            json.dumps(
                [
                    {
                        "command": validation.command,
                        "command_text": " ".join(validation.command),
                        "exit_code": validation.exit_code,
                        "summary": validation.summary,
                        "log": str(validation.output_path),
                    }
                    for validation in failed
                ],
                indent=2,
            ),
        ]
    )
    return "\n".join(lines).strip()


def _render_frozen_paths(
    task: TaskRecord, config: StewardConfig | None
) -> str:
    if config is None:
        return ""
    patterns = config.path_policy.frozen_for_kind(task.spec.kind)
    if not patterns:
        return ""
    lines = [
        "Do not modify these repository paths for this task. Steward will block "
        "patches that change them.",
    ]
    lines.extend(f"- {pattern}" for pattern in patterns)
    return "\n".join(lines)
