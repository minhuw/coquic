from __future__ import annotations

import shutil
from pathlib import Path

from ..core.config import StewardConfig
from ..core.models import TaskRecord
from ..core.subprocesses import run_command


FORBIDDEN_PATH_PARTS = {
    ".coquic-steward",
    ".remote-ci",
    ".rag",
    ".zig-cache",
    "zig-cache",
}


class Worktrees:
    def __init__(self, config: StewardConfig):
        self.config = config

    def create(self, task: TaskRecord) -> tuple[Path, str]:
        branch = task.branch_name or f"steward/{_slug(task.spec.kind)}/{_slug(task.id)}"
        path = task.worktree_path or self.config.worktrees_dir / task.id
        if path.exists():
            return path, branch
        self.config.worktrees_dir.mkdir(parents=True, exist_ok=True)
        run_command(
            [
                "git",
                "worktree",
                "add",
                "-B",
                branch,
                str(path),
                self.config.main_branch,
            ],
            cwd=self.config.repo_root,
            check=True,
        )
        return path, branch

    def has_changes(self, path: Path) -> bool:
        result = run_command(["git", "status", "--porcelain"], cwd=path, check=True)
        return bool(result.stdout.strip())

    def diff(self, path: Path) -> str:
        return run_command(["git", "diff", "--binary"], cwd=path, check=True).stdout

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

    def commit_all(self, path: Path, message: str, body: str = "") -> str | None:
        if not self.has_changes(path):
            return None
        run_command(["git", "add", "-A"], cwd=path, check=True)
        run_command(_commit_command(path, message, body), cwd=path, check=True)
        return run_command(
            ["git", "rev-parse", "HEAD"], cwd=path, check=True
        ).stdout.strip()

    def push_head_to_main(self, path: Path) -> None:
        run_command(
            ["git", "push", self.config.git_remote, f"HEAD:{self.config.main_branch}"],
            cwd=path,
            check=True,
        )

    def forbidden_paths(self, path: Path) -> list[str]:
        output = run_command(
            ["git", "status", "--porcelain"], cwd=path, check=True
        ).stdout
        forbidden: list[str] = []
        for line in output.splitlines():
            if not line:
                continue
            changed = line[3:] if len(line) > 3 else line
            parts = set(Path(changed).parts)
            if parts & FORBIDDEN_PATH_PARTS:
                forbidden.append(changed)
        return forbidden

    def remove(self, path: Path, branch: str | None = None) -> None:
        if path.exists():
            result = run_command(
                ["git", "worktree", "remove", "--force", str(path)],
                cwd=self.config.repo_root,
            )
            if not result.ok and path.exists():
                shutil.rmtree(path)
        if branch:
            run_command(["git", "branch", "-D", branch], cwd=self.config.repo_root)


def _slug(value: object) -> str:
    text = str(value).lower()
    chars = [
        char if char.isalnum() or char in {"-", "_", "/"} else "-" for char in text
    ]
    return "".join(chars).strip("-/") or "task"


def _commit_command(path: Path, message: str, body: str = "") -> list[str]:
    commit_args = ["git", "commit", "-m", message]
    if body.strip():
        commit_args.extend(["-m", body.strip()])
    if (path / "flake.nix").exists() and shutil.which("nix"):
        return ["nix", "develop", "-c", *commit_args]
    return commit_args
