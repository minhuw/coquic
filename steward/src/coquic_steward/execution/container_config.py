"""Validated, daemon-owned configuration for one task container.

This module deliberately contains no TOML parsing and no Docker calls.  It is
the small value-object boundary shared by the trusted daemon and tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:/-]{0,255}$")
_CONTAINER_ROOTS = {
    "/task/worktree-ro",
    "/task/worktree",
    "/task/archive",
    "/task/session",
    "/task/scratch",
    "/task/git",
    "/validation/worktree",
    "/validation/output",
    "/validation/store",
    "/validation/scratch",
    "/validation/git-common-ro",
    "/nix/var/nix",
    "/nix/store/.links",
}
_PLANNER_ROOTS = {"/planner/history", "/planner/session", "/planner/output"}


class TaskRole(StrEnum):
    planner = "planner"
    implementation = "implementation"
    validation = "validation"
    reviewer = "reviewer"
    formality = "formality"
    commit_message = "commit-message"

    @property
    def can_write_worktree(self) -> bool:
        return self is TaskRole.implementation

    @property
    def needs_scratch(self) -> bool:
        return self in {TaskRole.validation, TaskRole.implementation}


Role = TaskRole


@dataclass(frozen=True)
class ContainerLimits:
    """Kernel-enforced bounds applied at container creation."""

    memory_bytes: int = 4 * 1024 * 1024 * 1024
    pids: int = 512
    timeout_seconds: int = 7200
    scratch_bytes: int = 8 * 1024 * 1024 * 1024
    log_max_bytes: int = 64 * 1024 * 1024
    log_max_files: int = 3
    stop_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.memory_bytes <= 0:
            raise ValueError("memory_bytes must be positive")
        if self.pids < 32:
            raise ValueError("pids must be at least 32")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.scratch_bytes <= 0:
            raise ValueError("scratch_bytes must be positive")
        if self.log_max_bytes <= 0:
            raise ValueError("log_max_bytes must be positive")
        if self.log_max_files <= 0 or self.log_max_files > 32:
            raise ValueError("log_max_files must be between 1 and 32")
        if self.stop_timeout_seconds <= 0:
            raise ValueError("stop_timeout_seconds must be positive")


@dataclass(frozen=True)
class ContainerMount:
    source: Path
    target: str
    read_only: bool = True
    exact_host_target: bool = False

    def __post_init__(self) -> None:
        source = Path(self.source)
        if not source.is_absolute():
            raise ValueError(f"mount source must be absolute: {source}")
        if source.is_symlink():
            raise ValueError(f"mount source must not be a symlink: {source}")
        target = _validate_container_path(self.target)
        mount_roots = _CONTAINER_ROOTS | _PLANNER_ROOTS
        inside_boundary = target in mount_roots or any(
            target.startswith(root + "/") for root in mount_roots
        )
        exact_read_only = (
            self.exact_host_target
            and self.read_only
            and source != Path("/")
            and target == source.as_posix()
        )
        if not inside_boundary and not exact_read_only:
            raise ValueError(f"mount target is outside task boundary: {target}")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "target", target)


@dataclass(frozen=True)
class TaskContainerConfig:
    """Complete task-scoped container identity and mount policy."""

    task_id: str
    image: str
    image_digest: str
    worktree: Path
    archive: Path
    private_sessions: Path
    git_dir: Path
    git_common_dir: Path
    repo_root: Path | None = None
    scratch: Path | None = None
    container_worktree_ro: str = "/task/worktree-ro"
    container_worktree_rw: str = "/task/worktree"
    container_archive: str = "/task/archive"
    container_session: str = "/task/session"
    container_scratch: str = "/task/scratch"
    container_git_dir: str = "/task/git/linked"
    container_git_common_dir: str = "/task/git/common"
    limits: ContainerLimits = field(default_factory=ContainerLimits)
    network: str = "bridge"
    labels: dict[str, str] = field(default_factory=dict)
    daemon_uid: int = 0
    task_write_gid: int = 2000
    validation_gid: int = 2001
    epoch_id: str | None = None
    release_id: str | None = None

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.task_id):
            raise ValueError(f"invalid task id: {self.task_id!r}")
        if not _IMAGE_REF.fullmatch(self.image):
            raise ValueError(f"invalid task image: {self.image!r}")
        if not _DIGEST.fullmatch(self.image_digest):
            raise ValueError("image_digest must be a locked sha256 digest")
        for name in ("worktree", "archive", "private_sessions", "git_dir", "git_common_dir"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise ValueError(f"{name} must be absolute: {value}")
            object.__setattr__(self, name, value)
        if self.repo_root is not None:
            root = Path(self.repo_root)
            if not root.is_absolute():
                raise ValueError("repo_root must be absolute")
            object.__setattr__(self, "repo_root", root)
        if self.scratch is not None:
            scratch = Path(self.scratch)
            if not scratch.is_absolute():
                raise ValueError("scratch must be absolute")
            object.__setattr__(self, "scratch", scratch)
        for value in (
            self.container_worktree_ro,
            self.container_worktree_rw,
            self.container_archive,
            self.container_session,
            self.container_scratch,
            self.container_git_dir,
            self.container_git_common_dir,
        ):
            _validate_container_path(value)
        if self.network != "bridge":
            raise ValueError("task containers must use the default bridge network")
        if self.daemon_uid != 0:
            raise ValueError("daemon wrapper must be root inside the task container")
        if self.task_write_gid <= 0 or self.validation_gid <= 0:
            raise ValueError("role groups must be positive")
        labels = dict(self.labels)
        labels.setdefault("coquic.steward.task", self.task_id)
        labels.setdefault("coquic.steward.image-digest", self.image_digest)
        labels.setdefault("coquic.steward.runtime", "task-container-v1")
        labels.setdefault("coquic.steward.owner", "steward")
        labels.setdefault("coquic.steward.restart-policy", "no")
        if self.epoch_id is not None:
            if not _SAFE_ID.fullmatch(self.epoch_id):
                raise ValueError("invalid task epoch identity")
            labels.setdefault("coquic.steward.epoch", self.epoch_id)
        if self.release_id is not None:
            if not _SAFE_ID.fullmatch(self.release_id):
                raise ValueError("invalid task release identity")
            labels.setdefault("coquic.steward.release", self.release_id)
        for key, value in labels.items():
            if not _SAFE_ID.fullmatch(str(key).replace("/", "-")):
                raise ValueError(f"invalid container label key: {key!r}")
            if not value or "\n" in value:
                raise ValueError(f"invalid container label value: {key!r}")
        object.__setattr__(self, "labels", labels)

    @property
    def container_name(self) -> str:
        return f"coquic-steward-task-{self.task_id}"

    @property
    def read_only_mounts(self) -> tuple[ContainerMount, ...]:
        mounts = [
            ContainerMount(self.worktree, self.container_worktree_ro),
            ContainerMount(self.archive, self.container_archive),
            # The trusted root wrapper creates per-session homes here, then
            # applies DAC ownership before dropping to the session UID.
            ContainerMount(self.private_sessions, self.container_session, read_only=False),
            ContainerMount(self.git_dir, self.container_git_dir),
            ContainerMount(self.git_common_dir, self.container_git_common_dir),
        ]
        return tuple(mounts)

    def mounts_for(self, role: TaskRole | str) -> tuple[ContainerMount, ...]:
        selected = TaskRole(role)
        mounts = list(self.read_only_mounts)
        if selected.can_write_worktree:
            mounts.append(
                ContainerMount(
                    self.worktree,
                    self.container_worktree_rw,
                    read_only=False,
                )
            )
        if selected.needs_scratch and self.scratch is not None:
            mounts.append(
                ContainerMount(self.scratch, self.container_scratch, read_only=False)
            )
        return tuple(mounts)

    def environment(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
    ) -> dict[str, str]:
        selected = TaskRole(role)
        if session_uid < 10000 or session_uid > 60000:
            raise ValueError("session UID is outside the reserved range")
        if not _SAFE_ID.fullmatch(session_id):
            raise ValueError("invalid session identity")
        return {
            "GIT_DIR": self.container_git_dir,
            "GIT_COMMON_DIR": self.container_git_common_dir,
            "GIT_WORK_TREE": self.container_worktree_rw
            if selected.can_write_worktree
            else self.container_worktree_ro,
            "COQUIC_STEWARD_ROLE": selected.value,
            "COQUIC_STEWARD_TASK_ID": self.task_id,
            "HOME": f"{self.container_session}/{session_id}",
            "CODEX_HOME": f"{self.container_session}/{session_id}",
        }

    def container_path(self, host_path: Path, role: TaskRole | str) -> str:
        """Translate one task-owned host path to its stable container path."""

        selected = TaskRole(role)
        path = Path(host_path).resolve()
        mappings = [
            (
                self.worktree.resolve(),
                self.container_worktree_rw
                if selected.can_write_worktree
                else self.container_worktree_ro,
            ),
            (self.archive.resolve(), self.container_archive),
            (self.private_sessions.resolve(), self.container_session),
            (self.git_dir.resolve(), self.container_git_dir),
            (self.git_common_dir.resolve(), self.container_git_common_dir),
        ]
        if self.scratch is not None:
            mappings.append((self.scratch.resolve(), self.container_scratch))
        for source, target in mappings:
            try:
                relative = path.relative_to(source)
            except ValueError:
                continue
            return target if relative == Path(".") else f"{target}/{relative.as_posix()}"
        raise ValueError(f"path is outside task container mounts: {host_path}")


ContainerConfig = TaskContainerConfig


@dataclass(frozen=True)
class PlannerContainerConfig:
    """Mount/identity contract for the daemon-owned global planner container."""

    image: str
    image_digest: str
    history_root: Path
    private_root: Path
    output_root: Path
    limits: ContainerLimits = field(default_factory=ContainerLimits)
    network: str = "bridge"
    container_history: str = "/planner/history"
    container_session: str = "/planner/session"
    container_output: str = "/planner/output"
    labels: dict[str, str] = field(default_factory=dict)
    epoch_id: str | None = None
    release_id: str | None = None

    def __post_init__(self) -> None:
        if not _IMAGE_REF.fullmatch(self.image):
            raise ValueError("invalid planner image")
        if not _DIGEST.fullmatch(self.image_digest):
            raise ValueError("planner image must be locked by digest")
        for name in ("history_root", "private_root", "output_root"):
            value = Path(getattr(self, name))
            if not value.is_absolute() or value.is_symlink():
                raise ValueError(f"planner {name} must be an absolute non-symlink path")
            object.__setattr__(self, name, value)
        if self.network != "bridge":
            raise ValueError("planner container must use the locked provider-egress network")
        for value in (self.container_history, self.container_session, self.container_output):
            if not value.startswith("/") or ".." in PurePosixPath(value).parts:
                raise ValueError("invalid planner container mount path")
        labels = dict(self.labels)
        labels.setdefault("coquic.steward.planner", "true")
        labels.setdefault("coquic.steward.image-digest", self.image_digest)
        labels.setdefault("coquic.steward.runtime", "planner-container-v1")
        labels.setdefault("coquic.steward.owner", "steward")
        labels.setdefault("coquic.steward.restart-policy", "no")
        if self.epoch_id is not None:
            if not _SAFE_ID.fullmatch(self.epoch_id):
                raise ValueError("invalid planner epoch identity")
            labels.setdefault("coquic.steward.epoch", self.epoch_id)
        if self.release_id is not None:
            if not _SAFE_ID.fullmatch(self.release_id):
                raise ValueError("invalid planner release identity")
            labels.setdefault("coquic.steward.release", self.release_id)
        object.__setattr__(self, "labels", labels)

    @property
    def container_name(self) -> str:
        return "coquic-steward-planner"

    @property
    def mounts(self) -> tuple[ContainerMount, ...]:
        return (
            ContainerMount(self.history_root, self.container_history),
            ContainerMount(self.private_root, self.container_session, read_only=False),
            ContainerMount(self.output_root, self.container_output, read_only=False),
        )

    def environment(
        self,
        role: TaskRole | str,
        *,
        session_uid: int,
        session_id: str,
    ) -> dict[str, str]:
        if TaskRole(role) is not TaskRole.planner:
            raise ValueError("planner container accepts only planner executions")
        if session_uid < 10000 or session_uid > 60000:
            raise ValueError("planner session UID is outside the reserved range")
        if not _SAFE_ID.fullmatch(session_id):
            raise ValueError("invalid planner session id")
        return {
            "COQUIC_STEWARD_ROLE": "scheduler-planner",
            "HOME": f"{self.container_session}/{session_id}",
            "CODEX_HOME": f"{self.container_session}/{session_id}",
        }

    def container_path(self, host_path: Path, role: TaskRole | str) -> str:
        if TaskRole(role) is not TaskRole.planner:
            raise ValueError("planner container accepts only planner paths")
        path = Path(host_path).resolve()
        for source, target in (
            (self.history_root.resolve(), self.container_history),
            (self.private_root.resolve(), self.container_session),
            (self.output_root.resolve(), self.container_output),
        ):
            try:
                relative = path.relative_to(source)
            except ValueError:
                continue
            return target if relative == Path(".") else f"{target}/{relative.as_posix()}"
        raise ValueError(f"path is outside planner container mounts: {host_path}")


@dataclass(frozen=True)
class ValidationContainerConfig:
    """One-shot no-Codex boundary for the canonical four validation gates."""

    run_id: str
    image: str
    image_digest: str
    worktree: Path
    output: Path
    store: Path
    git_common_dir: Path | None = None
    scratch: Path | None = None
    limits: ContainerLimits = field(default_factory=ContainerLimits)
    labels: dict[str, str] = field(default_factory=dict)
    uid: int = 10000
    gid: int = 10000

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.run_id):
            raise ValueError("invalid validation run identity")
        if not _IMAGE_REF.fullmatch(self.image) or not _DIGEST.fullmatch(self.image_digest):
            raise ValueError("validation image must be a locked digest")
        for name in ("worktree", "output", "store"):
            value = Path(getattr(self, name))
            if not value.is_absolute() or value.is_symlink():
                raise ValueError(f"validation {name} must be an absolute non-symlink path")
            object.__setattr__(self, name, value)
        if self.git_common_dir is not None:
            git_common_dir = Path(self.git_common_dir)
            if not git_common_dir.is_absolute() or git_common_dir.is_symlink():
                raise ValueError(
                    "validation Git metadata must be an absolute non-symlink path"
                )
            object.__setattr__(self, "git_common_dir", git_common_dir)
        if self.scratch is not None:
            scratch = Path(self.scratch)
            if not scratch.is_absolute() or scratch.is_symlink():
                raise ValueError("validation scratch must be an absolute non-symlink path")
            object.__setattr__(self, "scratch", scratch)
        if not 1 <= self.uid <= 65535 or not 1 <= self.gid <= 65535:
            raise ValueError("validation identity must be a non-root numeric UID/GID")
        labels = dict(self.labels)
        labels.setdefault("coquic.steward.owner", "steward")
        labels.setdefault("coquic.steward.runtime", "validation-container-v1")
        labels.setdefault("coquic.steward.run", self.run_id)
        labels.setdefault("coquic.steward.image-digest", self.image_digest)
        labels.setdefault("coquic.steward.restart-policy", "no")
        if labels["coquic.steward.runtime"] != "validation-container-v1":
            raise ValueError("validation runtime label is fixed")
        if any(not value or "\n" in value for value in labels.values()):
            raise ValueError("validation label values are invalid")
        object.__setattr__(self, "labels", labels)

    @property
    def container_name(self) -> str:
        return f"coquic-steward-validation-{self.run_id}"

    @property
    def mounts(self) -> tuple[ContainerMount, ...]:
        mounts = (
            ContainerMount(self.worktree, "/validation/worktree"),
            ContainerMount(
                self.worktree,
                self.worktree.as_posix(),
                exact_host_target=True,
            ),
            ContainerMount(self.output, "/validation/output", read_only=False),
            ContainerMount(self.store, "/nix/var/nix", read_only=False),
        )
        if self.git_common_dir is not None:
            mounts += (
                ContainerMount(
                    self.git_common_dir,
                    self.git_common_dir.as_posix(),
                    exact_host_target=True,
                ),
                ContainerMount(self.git_common_dir, "/validation/git-common-ro"),
            )
        if self.scratch is not None:
            mounts += (ContainerMount(self.scratch, "/validation/scratch", read_only=False),)
        return mounts

    def container_path(self, host_path: Path) -> str:
        path = Path(host_path).resolve()
        mappings = [
            (self.worktree.resolve(), "/validation/worktree"),
            (self.output.resolve(), "/validation/output"),
            (self.store.resolve(), "/nix/var/nix"),
        ]
        if self.scratch is not None:
            mappings.append((self.scratch.resolve(), "/validation/scratch"))
        for source, target in mappings:
            try:
                relative = path.relative_to(source)
            except ValueError:
                continue
            return target if relative == Path(".") else f"{target}/{relative.as_posix()}"
        raise ValueError(f"path is outside validation mounts: {host_path}")


PlannerConfig = PlannerContainerConfig


def _validate_container_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"container path must be absolute: {value!r}")
    path = PurePosixPath(value)
    if ".." in path.parts or "//" in value or str(path) != value:
        raise ValueError(f"container path is not normalized: {value!r}")
    return value
