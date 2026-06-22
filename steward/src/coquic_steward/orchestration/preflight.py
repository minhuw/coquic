from __future__ import annotations

from ..core.config import StewardConfig
from ..core.models import IntegrationMode
from ..core.subprocesses import CommandResult, run_command

PREFLIGHT_TIMEOUT_SECONDS = 30.0
_NONINTERACTIVE_GIT_ENV = {
    "GCM_INTERACTIVE": "never",
    "GIT_TERMINAL_PROMPT": "0",
}
_COMMIT_ENV = {
    **_NONINTERACTIVE_GIT_ENV,
    "GIT_AUTHOR_EMAIL": "steward@example.invalid",
    "GIT_AUTHOR_NAME": "CoQUIC Steward",
    "GIT_COMMITTER_EMAIL": "steward@example.invalid",
    "GIT_COMMITTER_NAME": "CoQUIC Steward",
}


class StewardPreflightError(RuntimeError):
    pass


def preflight_remote_push(config: StewardConfig) -> bool:
    if (
        config.integration_mode != IntegrationMode.push_main.value
        or config.local_only
    ):
        return False
    fetch = run_command(
        ["git", "fetch", "--quiet", config.git_remote, config.main_branch],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_NONINTERACTIVE_GIT_ENV,
    )
    if not fetch.ok:
        raise _preflight_error(config, "fetch remote main", fetch)
    commit = run_command(
        [
            "git",
            "commit-tree",
            "FETCH_HEAD^{tree}",
            "-p",
            "FETCH_HEAD",
            "-m",
            "steward push preflight",
        ],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_COMMIT_ENV,
    )
    if not commit.ok:
        raise _preflight_error(config, "prepare dry-run commit", commit)
    dry_run = run_command(
        [
            "git",
            "push",
            "--dry-run",
            "--porcelain",
            config.git_remote,
            f"{commit.stdout.strip()}:{_remote_branch_ref(config.main_branch)}",
        ],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_NONINTERACTIVE_GIT_ENV,
    )
    if not dry_run.ok:
        raise _preflight_error(config, "dry-run push to main", dry_run)
    return True


def _remote_branch_ref(branch: str) -> str:
    if branch.startswith("refs/heads/"):
        return branch
    return f"refs/heads/{branch}"


def _preflight_error(
    config: StewardConfig, step: str, result: CommandResult
) -> StewardPreflightError:
    return StewardPreflightError(
        "\n".join(
            part
            for part in (
                (
                    "remote push preflight failed: Steward is configured for "
                    f"{IntegrationMode.push_main.value!r} but cannot verify write "
                    f"access to {config.git_remote}/{config.main_branch}."
                ),
                f"step: {step}",
                f"command: {' '.join(result.args)}",
                f"exit code: {result.returncode}",
                _output_block("stdout", result.stdout),
                _output_block("stderr", result.stderr),
            )
            if part
        )
    )


def _output_block(label: str, text: str) -> str:
    value = text.strip()
    if not value:
        return ""
    if len(value) > 2000:
        value = value[-2000:]
    return f"{label}:\n{value}"
