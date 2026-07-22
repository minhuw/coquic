from __future__ import annotations

import fnmatch
from dataclasses import dataclass
import shutil
import tempfile
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import IntegrationMode, TaskRecord
from ..core.subprocesses import CommandResult, run_command


FORBIDDEN_PATH_PARTS = {
    ".coquic-steward",
    ".remote-ci",
    ".rag",
    ".zig-cache",
    "zig-cache",
}


@dataclass(frozen=True)
class WorktreeIdentity:
    task_id: str
    path: Path
    base_commit: str
    expected_tree: str
    phase: str
    owning_pipeline_id: str
    active_session_id: str | None = None
    active_run_id: str | None = None
    image_version: str | None = None
    runtime_version: str | None = None


class Worktrees:
    def __init__(self, config: StewardConfig):
        self.config = config

    def create(
        self,
        task: TaskRecord,
        *,
        checkpoint: WorktreeIdentity | object | None = None,
    ) -> tuple[Path, str]:
        branch = task.branch_name or f"steward/{_slug(task.spec.kind)}/{_slug(task.id)}"
        path = task.worktree_path or self.config.worktrees_dir / task.id
        if path.exists():
            if checkpoint is not None and not self.validate_checkpoint(path, checkpoint):
                raise RuntimeError(
                    f"existing worktree does not match its durable checkpoint: {path}"
                )
            return path, branch
        base = self._new_worktree_base()
        self.config.worktrees_dir.mkdir(parents=True, exist_ok=True)
        run_command(
            [
                "git",
                "worktree",
                "add",
                "-B",
                branch,
                str(path),
                base,
            ],
            cwd=self.config.repo_root,
            check=True,
        )
        return path, branch

    def validate_checkpoint(self, path: Path, checkpoint: WorktreeIdentity | object) -> bool:
        """Verify an existing worktree before recovery can adopt it."""
        if not path.is_dir() or (path / ".git").exists() is False:
            return False
        expected_base = getattr(checkpoint, "base_commit", None)
        expected_tree = getattr(checkpoint, "expected_tree", None)
        if expected_base is not None:
            actual_base = run_command(
                ["git", "rev-parse", "HEAD"], cwd=path
            )
            if not actual_base.ok or actual_base.stdout.strip() != str(expected_base):
                return False
        if expected_tree is not None:
            actual_tree = _worktree_tree(path)
            if actual_tree is None or actual_tree != str(expected_tree):
                return False
        return True

    def identity(
        self,
        task: TaskRecord,
        path: Path,
        *,
        owning_pipeline_id: str,
        phase: str,
        active_session_id: str | None = None,
        active_run_id: str | None = None,
        image_version: str | None = None,
        runtime_version: str | None = None,
    ) -> WorktreeIdentity:
        base_commit = run_command(["git", "rev-parse", "HEAD"], cwd=path, check=True).stdout.strip()
        expected_tree = _worktree_tree(path)
        if expected_tree is None:
            raise RuntimeError(f"could not determine worktree identity: {path}")
        return WorktreeIdentity(
            task_id=task.id,
            path=path,
            base_commit=base_commit,
            expected_tree=expected_tree,
            phase=phase,
            owning_pipeline_id=owning_pipeline_id,
            active_session_id=active_session_id,
            active_run_id=active_run_id,
            image_version=image_version,
            runtime_version=runtime_version,
        )

    def _new_worktree_base(self) -> str:
        if (
            self.config.integration_mode != IntegrationMode.push_main.value
            or self.config.local_only
        ):
            return self.config.main_branch
        run_command(
            ["git", "fetch", self.config.git_remote, self.config.main_branch],
            cwd=self.config.repo_root,
            check=True,
        )
        return f"{self.config.git_remote}/{self.config.main_branch}"

    def has_changes(self, path: Path) -> bool:
        result = run_command(["git", "status", "--porcelain"], cwd=path, check=True)
        return bool(result.stdout.strip())

    def diff(self, path: Path) -> str:
        tracked = run_command(
            ["git", "diff", "--binary", "HEAD", "--"], cwd=path, check=True
        ).stdout
        untracked = run_command(
            ["git", "ls-files", "--others", "--exclude-standard", "-z", "--"],
            cwd=path,
            check=True,
        ).stdout
        patches = [tracked]
        for relative_path in sorted(filter(None, untracked.split("\0"))):
            result = run_command(
                [
                    "git",
                    "diff",
                    "--binary",
                    "--no-index",
                    "--",
                    "/dev/null",
                    relative_path,
                ],
                cwd=path,
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError(
                    f"could not diff untracked file {relative_path!r}: "
                    f"{result.stderr.strip()}"
                )
            patches.append(result.stdout)
        return "".join(patches)

    def save_patch(self, path: Path, patch_path: Path) -> None:
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text(self.diff(path), encoding="utf-8")

    def apply_patch(self, path: Path, patch_text: str) -> None:
        run_command(
            ["git", "apply", "--binary", "-"],
            cwd=path,
            input_text=patch_text,
            check=True,
        )

    def reset_to_main(self, path: Path) -> None:
        run_command(
            ["git", "fetch", self.config.git_remote, self.config.main_branch],
            cwd=path,
            check=True,
        )
        run_command(
            [
                "git",
                "reset",
                "--hard",
                f"{self.config.git_remote}/{self.config.main_branch}",
            ],
            cwd=path,
            check=True,
        )

    def stage_tree(self, path: Path) -> str:
        run_command(["git", "add", "-A", "--"], cwd=path, check=True)
        return run_command(["git", "write-tree"], cwd=path, check=True).stdout.strip()

    def commit_all(
        self,
        path: Path,
        message: str,
        body: str = "",
        *,
        expected_tree: str | None = None,
    ) -> str | None:
        if expected_tree is None and not self.has_changes(path):
            return None
        staged_tree = self.stage_tree(path)
        if expected_tree is not None and staged_tree != expected_tree:
            raise RuntimeError(
                f"staged tree changed after validation: expected {expected_tree}, "
                f"found {staged_tree}"
            )
        if not self.has_changes(path):
            return None
        run_command(
            _commit_command(
                path,
                message,
                body,
                skip_hooks=expected_tree is not None,
            ),
            cwd=path,
            check=True,
        )
        sha = run_command(
            ["git", "rev-parse", "HEAD"], cwd=path, check=True
        ).stdout.strip()
        if expected_tree is not None:
            committed_tree = run_command(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=path, check=True
            ).stdout.strip()
            if committed_tree != expected_tree:
                raise RuntimeError(
                    f"committed tree differs from validated tree: expected "
                    f"{expected_tree}, found {committed_tree}"
                )
        return sha

    def push_head_to_main(self, path: Path) -> CommandResult:
        return run_command(
            ["git", "push", self.config.git_remote, f"HEAD:{self.config.main_branch}"],
            cwd=path,
            check=True,
        )

    def branch_has_commits_not_on_main(self, branch: str) -> bool:
        branch_ref = f"refs/heads/{branch}"
        main_refs = [
            f"refs/remotes/{self.config.git_remote}/{self.config.main_branch}",
            f"refs/heads/{self.config.main_branch}",
        ]
        existing_main_refs = [
            ref
            for ref in main_refs
            if run_command(
                ["git", "show-ref", "--verify", "--quiet", ref],
                cwd=self.config.repo_root,
            ).ok
        ]
        if not existing_main_refs:
            return False
        result = run_command(
            [
                "git",
                "rev-list",
                "--max-count=1",
                branch_ref,
                "--not",
                *existing_main_refs,
            ],
            cwd=self.config.repo_root,
        )
        return result.ok and bool(result.stdout.strip())

    def forbidden_paths(self, path: Path) -> list[str]:
        output = run_command(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=path,
            check=True,
        ).stdout
        forbidden: list[str] = []
        for changed in _changed_paths_from_porcelain(output):
            parts = set(Path(changed).parts)
            if parts & FORBIDDEN_PATH_PARTS:
                forbidden.append(changed)
        return forbidden

    def frozen_paths(self, path: Path, task: TaskRecord) -> list[str]:
        patterns = self.config.path_policy.frozen_for_kind(task.spec.kind)
        if not patterns:
            return []
        output = run_command(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=path,
            check=True,
        ).stdout
        return _matching_paths(_changed_paths_from_porcelain(output), patterns)

    def remove(self, path: Path, branch: str | None = None) -> None:
        if path.exists():
            result = run_command(
                ["git", "worktree", "remove", "--force", str(path)],
                cwd=self.config.repo_root,
            )
            if not result.ok and path.exists():
                shutil.rmtree(path)
        run_command(["git", "worktree", "prune"], cwd=self.config.repo_root)
        if branch and branch.startswith("steward/"):
            run_command(["git", "branch", "-D", branch], cwd=self.config.repo_root)


def _worktree_tree(path: Path) -> str | None:
    """Hash tracked and non-ignored worktree content without changing its index."""
    with tempfile.TemporaryDirectory(prefix="coquic-steward-index-") as temporary:
        index_path = Path(temporary) / "index"
        environment = {"GIT_INDEX_FILE": str(index_path)}
        read_tree = run_command(
            ["git", "read-tree", "HEAD"], cwd=path, env=environment
        )
        if not read_tree.ok:
            return None
        add = run_command(
            ["git", "add", "--all", "--", "."], cwd=path, env=environment
        )
        if not add.ok:
            return None
        tree = run_command(["git", "write-tree"], cwd=path, env=environment)
        return tree.stdout.strip() if tree.ok else None


def _slug(value: object) -> str:
    text = str(value).lower()
    chars = [
        char if char.isalnum() or char in {"-", "_", "/"} else "-" for char in text
    ]
    return "".join(chars).strip("-/") or "task"


def _changed_paths_from_porcelain(output: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        if not line:
            continue
        changed = line[3:] if len(line) > 3 else line
        for path in _porcelain_paths(changed):
            if not path or path in seen:
                continue
            paths.append(path)
            seen.add(path)
    return paths


def _porcelain_paths(changed: str) -> list[str]:
    return [
        part.strip().strip('"').replace("\\", "/")
        for part in changed.split(" -> ")
    ]


def _matching_paths(paths: list[str], patterns: tuple[str, ...]) -> list[str]:
    return [
        path
        for path in paths
        if any(_path_matches_pattern(path, pattern) for pattern in patterns)
    ]


def _path_matches_pattern(path: str, pattern: str) -> bool:
    normalized_path = path.strip().replace("\\", "/")
    normalized_pattern = pattern.strip().replace("\\", "/").rstrip("/")
    if not normalized_path or not normalized_pattern:
        return False
    if any(char in normalized_pattern for char in "*?["):
        return fnmatch.fnmatchcase(normalized_path, normalized_pattern)
    return (
        normalized_path == normalized_pattern
        or normalized_path.startswith(normalized_pattern + "/")
    )


def _commit_command(
    path: Path,
    message: str,
    body: str = "",
    *,
    skip_hooks: bool = False,
) -> list[str]:
    commit_args = ["git", "commit", "-m", message]
    if body.strip():
        commit_args.extend(["-m", body.strip()])
    if skip_hooks:
        commit_args.insert(2, "--no-verify")
        return commit_args
    if (path / "flake.nix").exists() and shutil.which("nix"):
        return ["nix", "develop", "-c", *commit_args]
    return commit_args
