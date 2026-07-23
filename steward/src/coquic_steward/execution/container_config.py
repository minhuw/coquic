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
}


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

    def __post_init__(self) -> None:
        if self.memory_bytes <= 0:
            raise ValueError("memory_bytes must be positive")
        if self.pids < 32:
            raise ValueError("pids must be at least 32")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.scratch_bytes <= 0:
            raise ValueError("scratch_bytes must be positive")


@dataclass(frozen=True)
class ContainerMount:
    source: Path
    target: str
    read_only: bool = True

    def __post_init__(self) -> None:
        source = Path(self.source)
        if not source.is_absolute():
            raise ValueError(f"mount source must be absolute: {source}")
        if source.is_symlink():
            raise ValueError(f"mount source must not be a symlink: {source}")
        target = _validate_container_path(self.target)
        if target not in _CONTAINER_ROOTS and not any(
            target.startswith(root + "/") for root in _CONTAINER_ROOTS
        ):
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


def _validate_container_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"container path must be absolute: {value!r}")
    path = PurePosixPath(value)
    if ".." in path.parts or "//" in value or str(path) != value:
        raise ValueError(f"container path is not normalized: {value!r}")
    return value
