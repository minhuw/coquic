from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - fixed validation Docker argv
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import TaskRecord, ValidationResult, utc_now
from ..core.subprocesses import CommandResult, run_command

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


_CLEAN_VALIDATION_SHELL_PREFIX = (
    "nix",
    "develop",
    "--ignore-env",
    "--keep-env-var",
    "HOME",
)
MAX_VALIDATION_OUTPUT_BYTES = 2 * 1024 * 1024


def default_gates(worktree: Path) -> tuple[tuple[str, list[str]], ...]:
    lint_flake = f"git+{worktree.resolve().as_uri()}#lint"
    clean_shell = (*_CLEAN_VALIDATION_SHELL_PREFIX, lint_flake, "-c")
    indexed = (
        *clean_shell,
        "bash",
        str(worktree.resolve() / "scripts" / "run-validation-with-index.sh"),
    )
    return (
        (
            "git-diff-check.txt",
            [*indexed, "git", "diff", "--cached", "--check", "HEAD", "--"],
        ),
        (
            "nix-flake-check.txt",
            [
                *indexed,
                "nix",
                "flake",
                "check",
                "--no-build",
                "--no-update-lock-file",
                ".",
            ],
        ),
        ("zig-build-test.txt", [*indexed, "zig", "build", "test"]),
        (
            "pre-commit.txt",
            [
                *indexed,
                "env",
                "COQUIC_CLANG_TIDY_IN_NIX=1",
                "pre-commit",
                "run",
                "--all-files",
            ],
        ),
    )


def run_gates(
    config: StewardConfig,
    task_id: str,
    cwd: Path,
    *,
    label: str | None = None,
    on_gate_start: Callable[[int, str, list[str]], None] | None = None,
    on_gate_result: Callable[[int, ValidationResult], None] | None = None,
    command_runner: Callable[[list[str], Path, float], CommandResult] | None = None,
) -> list[ValidationResult]:
    if (
        command_runner is None
        and getattr(config, "validation_image_digest", None)
        and not getattr(config, "local_codex_test_harness", False)
    ):
        command_runner = _docker_validation_runner(config, task_id, cwd)
    results: list[ValidationResult] = []
    for index, (filename, command) in enumerate(default_gates(cwd)):
        if on_gate_start is not None:
            on_gate_start(index, filename, command)
        result = run_validation(
            config,
            task_id,
            cwd,
            filename,
            command,
            label=label,
            command_runner=command_runner,
        )
        results.append(result)
        if on_gate_result is not None:
            on_gate_result(index, result)
    return results


def _docker_validation_runner(
    config: StewardConfig, task_id: str, cwd: Path
) -> Callable[[list[str], Path, float], CommandResult]:
    """Return a no-network, read-only-source runner for one validation run.

    The daemon-side executor normally supplies the persistent sibling runtime;
    this fallback keeps direct integration callers on the same validation image
    and rejects task-image or host-Docker fallbacks.
    """
    digest = str(config.validation_image_digest)
    if not digest.startswith("sha256:"):
        raise ValueError("validation requires an exact image digest")
    docker_bin = getattr(config.container, "docker_bin", "docker")
    output_root = config.logs_dir / task_id / "validation-container"
    output_root.mkdir(parents=True, exist_ok=True)
    store_root = config.private_dir / "validation-store" / task_id
    store_root.mkdir(parents=True, exist_ok=True)
    git_common_dir = _validation_git_common_dir(cwd)
    deployment = config.deployment
    validation_uid = 10000 if deployment.host_uid is None else int(deployment.host_uid)
    validation_gid = 10000 if deployment.host_gid is None else int(deployment.host_gid)
    scratch_bytes = deployment.max_scratch_bytes

    def execute(command: list[str], workdir: Path, timeout: float) -> CommandResult:
        mapped = [
            item.replace(str(workdir.resolve()), "/validation/worktree")
            .replace(workdir.resolve().as_uri(), "file:///validation/worktree")
            for item in command
        ]
        argv = [
            docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(deployment.max_pids),
            "--memory",
            str(deployment.max_memory_bytes),
            "--user",
            f"{validation_uid}:{validation_gid}",
            "--mount",
            f"type=bind,src={workdir.resolve()},dst=/validation/worktree,readonly",
            "--mount",
            f"type=bind,src={workdir.resolve()},dst={workdir.resolve()},readonly",
            "--mount",
            f"type=bind,src={output_root},dst=/validation/output",
            "--mount",
            f"type=bind,src={store_root},dst=/nix/var/nix",
            "--mount",
            f"type=bind,src={git_common_dir},dst={git_common_dir},readonly",
            "--mount",
            f"type=bind,src={git_common_dir},dst=/validation/git-common-ro,readonly",
            "--env",
            f"VALIDATION_SOURCE_WORKTREE={workdir.resolve()}",
            "--env",
            f"VALIDATION_GIT_OBJECTS_DIR={git_common_dir / 'objects'}",
            "--env",
            "VALIDATION_GIT_ALTERNATE_OBJECTS=/validation/git-common-ro/objects",
            "--tmpfs",
            f"{git_common_dir / 'objects'}:rw,nosuid,nodev,size=256m,mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={scratch_bytes},mode=1777",
            "--tmpfs",
            f"/validation/worktree/.zig-cache:rw,exec,nosuid,nodev,size={scratch_bytes},mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            f"/validation/worktree/site/next:rw,noexec,nosuid,nodev,size=1g,mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            f"/validation/worktree/.duvet:rw,noexec,nosuid,nodev,size=1g,mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            f"/nix/store:rw,nosuid,nodev,size={scratch_bytes},mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            f"/nix/var/log/nix:rw,noexec,nosuid,nodev,size=64m,mode=0755,uid={validation_uid},gid={validation_gid}",
            "--tmpfs",
            "/run:rw,noexec,nosuid,nodev,size=16m",
            digest,
            "--exec",
            *mapped,
        ]
        try:
            result = subprocess.run(
                argv,
                cwd=workdir,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(command, workdir, 124, "", "validation container timed out")
        return CommandResult(command, workdir, result.returncode, result.stdout, result.stderr)

    return execute


def _validation_git_common_dir(worktree: Path) -> Path:
    common = run_command(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=worktree,
    )
    git_dir = run_command(["git", "rev-parse", "--absolute-git-dir"], cwd=worktree)
    if not common.ok or not git_dir.ok:
        raise ValueError("validation worktree Git metadata is unavailable")
    common_path = Path(common.stdout.strip()).resolve()
    git_dir_path = Path(git_dir.stdout.strip()).resolve()
    if (
        not common_path.is_dir()
        or common_path.is_symlink()
        or not git_dir_path.is_relative_to(common_path)
    ):
        raise ValueError("validation worktree Git metadata is ambiguous")
    return common_path


def run_validation(
    config: StewardConfig,
    task_id: str,
    cwd: Path,
    filename: str,
    command: list[str],
    *,
    label: str | None = None,
    command_runner: Callable[[list[str], Path, float], CommandResult] | None = None,
) -> ValidationResult:
    output_path = config.logs_dir / task_id / label / filename if label else config.logs_dir / task_id / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    timeout = config.limits.validation_timeout_minutes * 60
    if command_runner is not None:
        result = command_runner(command, cwd, timeout)
    else:
        git_dir = run_command(
            ["git", "rev-parse", "--absolute-git-dir"], cwd=cwd
        ).stdout.strip()
        object_store = str(Path(git_dir) / "objects") if git_dir else ""
        environment = os.environ.copy()
        if object_store:
            with tempfile.TemporaryDirectory(prefix="coquic-steward-validation-") as temporary:
                environment["GIT_OBJECT_DIRECTORY"] = temporary
                environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(Path(object_store).resolve())
                result = run_command(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    env=environment,
                )
        else:
            result = run_command(command, cwd=cwd, timeout=timeout)
    stdout = _bounded_output(result.stdout)
    stderr = _bounded_output(result.stderr)
    output_path.write_text(
        f"$ {' '.join(command)}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n",
        encoding="utf-8",
    )
    return ValidationResult(
        command=command,
        cwd=cwd,
        passed=result.ok,
        exit_code=result.returncode,
        output_path=output_path,
        summary=(stdout or stderr).strip()[-1000:],
        started_at=started,
        completed_at=utc_now(),
    )


def _bounded_output(value: str) -> str:
    if len(value.encode("utf-8", errors="replace")) <= MAX_VALIDATION_OUTPUT_BYTES:
        return value
    encoded = value.encode("utf-8", errors="replace")
    suffix = b"\n[output truncated by Steward validation boundary]\n"
    return (encoded[: MAX_VALIDATION_OUTPUT_BYTES - len(suffix)] + suffix).decode(
        "utf-8", errors="replace"
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
