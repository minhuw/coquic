from __future__ import annotations

import json
import os
import shutil
import stat
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import StewardConfig
from ..core.github_auth import git_remote_environment, validate_ssh_remote
from ..core.subprocesses import CommandResult, run_command
from ..control_loop import ArchiveError, ControlLoopArchive

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
_REMOTE_REWRITE_PATTERN = r"^url\..*\.(insteadOf|pushInsteadOf)$"


class StewardPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightReport:
    """Bounded launch checks; values never include subprocess output."""

    checks: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        values = [*self.checks, *(f"warning:{item}" for item in self.warnings)]
        return ", ".join(values) if values else "ok"


def run_preflight(
    config: StewardConfig,
    store: object | None = None,
    *,
    check_remote_push: bool = True,
) -> PreflightReport:
    """Validate all daemon-owned launch boundaries before dispatch.

    Checks are intentionally local and bounded. Docker is required only when
    the task container section is explicitly enabled.
    """

    if (config.container.enabled or config.deployment.enabled) and (
        config.authentication.proxy_url is None or config.authentication.api_key is None
    ):
        raise StewardPreflightError(
            "preflight failed: configure [steward.authentication] with proxy_url and api_key"
        )
    config.ensure_dirs()
    checks: list[str] = ["directories"]
    warnings: list[str] = []
    if config.deployment.enabled:
        _validate_deployment_boundary(config)
        checks.append("deployment")
    ledger = getattr(store, "control_loop_ledger", None)
    try:
        task_epoch = config.ensure_epoch()
    except Exception as exc:
        raise StewardPreflightError("preflight failed: task archive epoch is invalid") from exc
    checks.append("epoch")
    try:
        ControlLoopArchive(config, task_root=config).ensure_task_epoch(task_epoch)
        checks.append("control-loop")
    except ArchiveError as exc:
        if ledger is None:
            raise StewardPreflightError(
                "preflight failed: control-loop archive is invalid"
            ) from exc
        ledger.set_planning_blocked(
            True,
            reason=f"control-loop preflight: {exc.__class__.__name__}",
        )
        warnings.append("planning-blocked")
    if ledger is not None and getattr(ledger, "planning_blocked", False):
        if "planning-blocked" not in warnings:
            warnings.append("planning-blocked")
    if config.db_path.exists():
        try:
            with sqlite3.connect(f"file:{config.db_path}?mode=ro", uri=True) as connection:
                result = connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.Error as exc:
            raise StewardPreflightError("preflight failed: SQLite is unavailable") from exc
        if not result or result[0] != "ok":
            raise StewardPreflightError("preflight failed: SQLite integrity check failed")
        checks.append("sqlite")

    if config.container.enabled:
        container = config.container
        if container.image_digest is None:
            raise StewardPreflightError("preflight failed: task image digest is required")
        if container.repository_host_path is None or not container.repository_host_path.exists():
            raise StewardPreflightError("preflight failed: repository host path is unavailable")
        if container.state_host_path is None or not container.state_host_path.exists():
            raise StewardPreflightError("preflight failed: state host path is unavailable")
        _validate_container_host_mapping(config)
        _check_executable(container.docker_bin, "Docker", expected_name="docker")
        docker = run_command([container.docker_bin, "info"], cwd=config.repo_root, timeout=PREFLIGHT_TIMEOUT_SECONDS)
        if not docker.ok:
            raise StewardPreflightError("preflight failed: Docker runtime is unavailable")
        inspect = run_command(
            [container.docker_bin, "image", "inspect", container.image_digest],
            cwd=config.repo_root,
            timeout=PREFLIGHT_TIMEOUT_SECONDS,
        )
        if not inspect.ok:
            raise StewardPreflightError("preflight failed: locked task image is unavailable")
        _validate_task_image_identity(inspect.stdout, container.runtime_protocol)
        checks.extend(("docker", "task-image"))

    if check_remote_push and not config.dry_run:
        preflight_remote_push(config)
        checks.append("remote-push")
    return PreflightReport(tuple(checks), tuple(warnings))


def _validate_deployment_boundary(config: StewardConfig) -> None:
    """Validate the Compose host contract without mutating host state."""

    deployment = config.deployment
    home = config.coquic_home
    repository = config.repository_path
    if not home.is_absolute() or home.is_symlink():
        raise StewardPreflightError("preflight failed: COQUIC_HOME is not an absolute non-symlink path")
    if repository != home / "repository" or repository.is_symlink():
        raise StewardPreflightError("preflight failed: repository must be COQUIC_HOME/repository")
    if not repository.is_dir():
        raise StewardPreflightError("preflight failed: dedicated repository clone is unavailable")
    if config.repo_root.resolve() != repository.resolve():
        raise StewardPreflightError("preflight failed: daemon repo_root is not the dedicated clone")
    socket = deployment.docker_socket
    try:
        socket_stat = socket.lstat()
    except OSError as exc:
        raise StewardPreflightError("preflight failed: Docker socket is unavailable") from exc
    if not stat.S_ISSOCK(socket_stat.st_mode):
        raise StewardPreflightError("preflight failed: Docker endpoint must be a local Unix socket")
    if deployment.docker_gid is not None and socket_stat.st_gid != deployment.docker_gid:
        raise StewardPreflightError("preflight failed: Docker socket group ownership is mismatched")
    if deployment.host_uid is not None and os.getuid() != deployment.host_uid:
        raise StewardPreflightError("preflight failed: daemon UID does not match configured host UID")
    if deployment.host_gid is not None and os.getgid() != deployment.host_gid:
        raise StewardPreflightError("preflight failed: daemon GID does not match configured host GID")
    if deployment.docker_gid is not None and deployment.docker_gid not in os.getgroups() and os.getgid() != deployment.docker_gid:
        raise StewardPreflightError("preflight failed: daemon lacks configured Docker socket group")
    credentials = (
        (deployment.github_token_path, "GitHub API token"),
        (deployment.git_ssh_key_path, "Git SSH key"),
        (deployment.git_known_hosts_path, "Git known-hosts"),
    )
    for path, label in credentials:
        _check_secret_file(path, label)
        assert path is not None
        if deployment.host_uid is not None and path.lstat().st_uid != deployment.host_uid:
            raise StewardPreflightError(f"preflight failed: {label} owner is mismatched")
    _validate_remote_policy(config, repository)
    branch = run_command(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], cwd=repository)
    if not branch.ok or branch.stdout.strip() != deployment.expected_branch:
        raise StewardPreflightError("preflight failed: repository is detached or on the wrong branch")
    dirty = run_command(["git", "status", "--porcelain"], cwd=repository)
    if not dirty.ok or dirty.stdout.strip():
        raise StewardPreflightError("preflight failed: daemon repository is dirty")
    worktree = run_command(["git", "worktree", "list", "--porcelain"], cwd=repository)
    if not worktree.ok or not worktree.stdout.startswith(f"worktree {repository}\n"):
        raise StewardPreflightError("preflight failed: repository worktree identity is ambiguous")


def validate_remote_operation(config: StewardConfig, repository: Path) -> None:
    """Validate the Git context immediately before a production remote call."""

    if config.deployment.enabled:
        _validate_remote_policy(config, repository)


def _validate_remote_policy(config: StewardConfig, repository: Path) -> None:
    contexts = (repository,)
    try:
        is_canonical = repository.resolve() == config.repo_root.resolve()
    except OSError as exc:
        raise StewardPreflightError(
            "preflight failed: Git remote configuration is unavailable"
        ) from exc
    if is_canonical:
        contexts += _linked_worktree_paths(repository)
    for context in contexts:
        _validate_remote_policy_context(config, context)


def _linked_worktree_paths(repository: Path) -> tuple[Path, ...]:
    result = run_command(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repository,
    )
    if not result.ok:
        raise StewardPreflightError(
            "preflight failed: Git remote configuration is unavailable"
        )
    canonical = repository.resolve()
    paths: list[Path] = []
    for entry in result.stdout.split("\n\n"):
        lines = entry.splitlines()
        if not lines:
            continue
        worktree_lines = [line for line in lines if line.startswith("worktree ")]
        if len(worktree_lines) != 1:
            raise StewardPreflightError(
                "preflight failed: Git remote configuration is unavailable"
            )
        raw_path = worktree_lines[0].removeprefix("worktree ")
        if not raw_path:
            raise StewardPreflightError(
                "preflight failed: Git remote configuration is unavailable"
            )
        path = Path(raw_path)
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError as exc:
            if any(
                line == "prunable" or line.startswith("prunable ")
                for line in lines
            ):
                continue
            raise StewardPreflightError(
                "preflight failed: Git remote configuration is unavailable"
            ) from exc
        except OSError as exc:
            raise StewardPreflightError(
                "preflight failed: Git remote configuration is unavailable"
            ) from exc
        if resolved != canonical:
            paths.append(path)
    return tuple(paths)


def _validate_remote_policy_context(
    config: StewardConfig, repository: Path
) -> None:
    deployment = config.deployment
    remote_names = tuple(
        dict.fromkeys((deployment.expected_remote, config.git_remote))
    )
    for remote_name in remote_names:
        label = (
            "expected Git remote"
            if remote_name == deployment.expected_remote
            else "configured Git remote"
        )
        fetch_urls = _git_remote_config_values(
            repository, f"remote.{remote_name}.url"
        )
        if not fetch_urls:
            raise StewardPreflightError(
                f"preflight failed: {label} is unavailable"
            )
        push_urls = _git_remote_config_values(
            repository, f"remote.{remote_name}.pushurl"
        )
        for remote_url in (*fetch_urls, *(push_urls or fetch_urls)):
            try:
                validate_ssh_remote(remote_url)
            except ValueError as exc:
                raise StewardPreflightError(
                    f"preflight failed: {label} must be credential-free SSH"
                ) from exc

    environment = git_remote_environment(config)
    _reject_repository_url_rewrites(repository, environment)
    for remote_name in remote_names:
        label = (
            "expected Git remote"
            if remote_name == deployment.expected_remote
            else "configured Git remote"
        )
        fetch_urls = _effective_remote_urls(
            repository, remote_name, environment=environment
        )
        push_urls = _effective_remote_urls(
            repository, remote_name, environment=environment, push=True
        )
        for direction, remote_urls in (
            ("fetch", fetch_urls),
            ("push", push_urls),
        ):
            if len(remote_urls) != 1:
                raise StewardPreflightError(
                    f"preflight failed: {label} must have exactly one effective "
                    f"{direction} URL"
                )
            try:
                validate_ssh_remote(remote_urls[0])
            except ValueError as exc:
                raise StewardPreflightError(
                    f"preflight failed: {label} must be credential-free SSH"
                ) from exc


def _git_remote_config_values(repository: Path, key: str) -> tuple[str, ...]:
    result = run_command(
        [
            "git",
            "config",
            "--local",
            "--includes",
            "--null",
            "--get-all",
            key,
        ],
        cwd=repository,
    )
    if result.ok:
        values = result.stdout.split("\0")
        if values and values[-1] == "":
            values.pop()
        return tuple(values)
    if result.returncode == 1 and not result.stdout:
        return ()
    raise StewardPreflightError(
        "preflight failed: Git remote configuration is unavailable"
    )


def _reject_repository_url_rewrites(
    repository: Path, environment: dict[str, str]
) -> None:
    result = run_command(
        [
            "git",
            "config",
            "--includes",
            "--null",
            "--name-only",
            "--get-regexp",
            _REMOTE_REWRITE_PATTERN,
        ],
        cwd=repository,
        env=environment,
    )
    if result.ok and not result.stdout:
        return
    if result.ok and result.stdout:
        raise StewardPreflightError(
            "preflight failed: repository-local Git URL rewriting "
            "(insteadOf/pushInsteadOf) is not allowed"
        )
    if result.returncode == 1 and not result.stdout:
        return
    raise StewardPreflightError(
        "preflight failed: Git remote configuration is unavailable"
    )


def _effective_remote_urls(
    repository: Path,
    remote: str,
    *,
    environment: dict[str, str],
    push: bool = False,
) -> tuple[str, ...]:
    command = ["git", "remote", "get-url"]
    if push:
        command.append("--push")
    command.extend(("--all", remote))
    result = run_command(command, cwd=repository, env=environment)
    if not result.ok:
        raise StewardPreflightError(
            "preflight failed: Git remote configuration is unavailable"
        )
    return tuple(result.stdout.splitlines())


def _check_executable(
    value: str,
    label: str,
    *,
    expected_name: str | None = None,
    path_command: str | None = None,
) -> Path:
    if Path(value).is_absolute():
        candidate = Path(value)
    else:
        resolved = shutil.which(value)
        candidate = Path(resolved) if resolved else Path(value)
    if not candidate.exists() or not os.access(candidate, os.X_OK):
        raise StewardPreflightError(f"preflight failed: {label} executable is unavailable")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise StewardPreflightError(
            f"preflight failed: {label} executable identity is unavailable"
        ) from exc
    if expected_name is not None and resolved.name != expected_name:
        raise StewardPreflightError(
            f"preflight failed: {label} executable identity is invalid"
        )
    if path_command is not None:
        selected = shutil.which(path_command)
        if selected is None:
            raise StewardPreflightError(
                f"preflight failed: {label} executable is unavailable"
            )
        try:
            path_identity = Path(selected).resolve(strict=True)
        except OSError as exc:
            raise StewardPreflightError(
                f"preflight failed: {label} PATH identity is unavailable"
            ) from exc
        if path_identity != resolved:
            raise StewardPreflightError(
                f"preflight failed: {label} executable does not match its locked PATH identity"
            )
    return resolved


def _validate_task_image_identity(stdout: str, runtime_protocol: str) -> None:
    try:
        payload = json.loads(stdout)
        image = payload[0]
        labels = image["Config"]["Labels"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise StewardPreflightError(
            "preflight failed: locked task image metadata is invalid"
        ) from exc
    required = {
        "org.opencontainers.image.source-revision": None,
        "coquic.steward.runtime-protocol": runtime_protocol,
        "coquic.steward.codex-version": None,
        "coquic.steward.closure": None,
    }
    for key, expected in required.items():
        value = labels.get(key) if isinstance(labels, dict) else None
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 128
            or any(character in value for character in "\x00\r\n")
            or (expected is not None and value != expected)
        ):
            raise StewardPreflightError(
                "preflight failed: locked task image identity is invalid"
            )
    optional_architecture = labels.get("org.opencontainers.image.architecture") if isinstance(labels, dict) else None
    if optional_architecture is not None and optional_architecture != "x86_64-linux":
        raise StewardPreflightError("preflight failed: locked task image architecture is invalid")


def _check_secret_file(path: Path | None, label: str) -> None:
    if path is None:
        raise StewardPreflightError(f"preflight failed: {label} path is missing")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise StewardPreflightError(f"preflight failed: {label} file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise StewardPreflightError(f"preflight failed: {label} file is not regular")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise StewardPreflightError(f"preflight failed: {label} file permissions are unsafe")


def _validate_container_host_mapping(config: StewardConfig) -> None:
    """Ensure Docker sees the exact repository and state roots Steward owns."""

    container = config.container
    assert container.repository_host_path is not None
    assert container.state_host_path is not None
    expected_repository = config.repo_root.resolve()
    expected_state = config.coquic_home.resolve()
    try:
        repository = container.repository_host_path.resolve(strict=True)
        state = container.state_host_path.resolve(strict=True)
    except OSError as exc:
        raise StewardPreflightError(
            "preflight failed: Docker host path mapping cannot be resolved"
        ) from exc
    if repository != expected_repository:
        raise StewardPreflightError(
            "preflight failed: repository Docker host mapping does not match repository root"
        )
    if state != expected_state:
        raise StewardPreflightError(
            "preflight failed: state Docker host mapping does not match Steward state root"
        )


def preflight_remote_push(config: StewardConfig) -> bool:
    if config.dry_run:
        return False
    validate_remote_operation(config, config.repo_root)
    fetch = run_command(
        ["git", "fetch", "--quiet", config.git_remote, config.main_branch],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=git_remote_environment(config),
    )
    if not fetch.ok:
        raise _preflight_error(config, "fetch remote main", fetch)
    _require_synced_main(config)
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
    validate_remote_operation(config, config.repo_root)
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
        env=git_remote_environment(config),
    )
    if not dry_run.ok:
        raise _preflight_error(config, "dry-run push to main", dry_run)
    return True


def _require_synced_main(config: StewardConfig) -> None:
    local_ref = _remote_branch_ref(config.main_branch)
    local = run_command(
        ["git", "rev-parse", "--verify", local_ref],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_NONINTERACTIVE_GIT_ENV,
    )
    if not local.ok:
        raise _preflight_error(config, "resolve local main", local)
    remote = run_command(
        ["git", "rev-parse", "--verify", "FETCH_HEAD"],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_NONINTERACTIVE_GIT_ENV,
    )
    if not remote.ok:
        raise _preflight_error(config, "resolve remote main", remote)
    local_sha = local.stdout.strip()
    remote_sha = remote.stdout.strip()
    if local_sha == remote_sha:
        return
    counts = run_command(
        ["git", "rev-list", "--left-right", "--count", f"{local_ref}...FETCH_HEAD"],
        cwd=config.repo_root,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
        env=_NONINTERACTIVE_GIT_ENV,
    )
    divergence = counts.stdout.strip() if counts.ok else "unknown"
    raise StewardPreflightError(
        "\n".join(
            (
                "remote push preflight failed: local main does not match remote main.",
                f"local {local_ref}: {local_sha}",
                f"remote {config.git_remote}/{config.main_branch}: {remote_sha}",
                f"ahead/behind: {divergence}",
                "reconcile and push local main before starting Steward",
            )
        )
    )


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
                    "remote push preflight failed: live Steward cannot verify write "
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
