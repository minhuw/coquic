from __future__ import annotations

from hashlib import sha256
from dataclasses import dataclass
from typing import Any
import shutil
import tempfile
from pathlib import Path

from ..core.config import StewardConfig, _frozen_path_matches
from ..core.github_auth import git_remote_environment
from ..core.models import TaskRecord
from ..core.subprocesses import CommandResult, run_command


FORBIDDEN_PATH_PARTS = {
    ".coquic-steward",
    ".remote-ci",
    ".rag",
    ".zig-cache",
    "zig-cache",
}


PATH_POLICY_STATUS_PARSE_SUMMARY = "path policy status could not be parsed"
_PORCELAIN_STATUS_CODES = frozenset(" MADRCUT?!")


def _validate_remote_operation(config: StewardConfig, path: Path) -> None:
    # Import lazily because orchestration imports the execution package.
    from ..orchestration.preflight import validate_remote_operation

    validate_remote_operation(config, path)


class _PathPolicyStatusParseError(ValueError):
    """A bounded, stable failure while decoding Git status records."""

    def __init__(self, output: str | None = None) -> None:
        super().__init__(PATH_POLICY_STATUS_PARSE_SUMMARY)
        self.diagnostic = (
            _path_policy_status_diagnostic(output) if output is not None else None
        )


@dataclass(frozen=True)
class WorktreeIdentity:
    task_id: str
    execution_id: str
    path: Path
    base_commit: str
    expected_tree: str
    phase: str
    owning_pipeline_id: str
    active_session_id: str | None = None
    active_run_id: str | None = None
    image_version: str | None = None
    runtime_version: str | None = None


@dataclass(frozen=True)
class PreparedPatchWorktree:
    path: Path
    branch: str
    base_identity: str
    input_identity: str
    output_identity: str
    patch_identity: str
    applied: bool
    detail: str = ""


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
        task_id = getattr(checkpoint, "task_id", None)
        execution_id = getattr(checkpoint, "execution_id", None)
        owning_pipeline_id = getattr(checkpoint, "owning_pipeline_id", None)
        declared_path = getattr(checkpoint, "worktree_path", None) or getattr(
            checkpoint, "path", None
        )
        if not all((task_id, execution_id, owning_pipeline_id, declared_path)):
            return False
        actual_path = path.resolve()
        if actual_path != Path(declared_path).resolve():
            return False
        if actual_path != (self.config.worktrees_dir / str(task_id)).resolve():
            return False
        if not self.config.db_path.is_file():
            return False
        from ..storage import TaskStore

        store = TaskStore.open(self.config.db_path)
        try:
            durable = store.get_checkpoint(str(execution_id))
            execution = store.get_execution(str(execution_id))
            pipeline = store.get_pipeline(str(owning_pipeline_id))
        except KeyError:
            return False
        if (
            execution.task_id != task_id
            or pipeline.task_id != task_id
            or pipeline.execution_id != execution_id
        ):
            return False
        fields = (
            "task_id",
            "execution_id",
            "base_commit",
            "expected_tree",
            "phase",
            "owning_pipeline_id",
            "active_session_id",
            "active_run_id",
            "image_version",
            "runtime_version",
        )
        if any(
            getattr(durable, field) != getattr(checkpoint, field, None)
            for field in fields
        ):
            return False
        if durable.worktree_path is None or durable.worktree_path.resolve() != actual_path:
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
        from ..storage import TaskStore

        execution = TaskStore.open(self.config.db_path).get_execution(task.id)
        base_commit = run_command(["git", "rev-parse", "HEAD"], cwd=path, check=True).stdout.strip()
        expected_tree = _worktree_tree(path)
        if expected_tree is None:
            raise RuntimeError(f"could not determine worktree identity: {path}")
        return WorktreeIdentity(
            task_id=task.id,
            execution_id=execution.id,
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
        # Dry-run still provisions an ordinary local worktree.  A configured
        # live run refreshes the remote-read base before integration.
        if self.config.dry_run:
            return self.config.main_branch
        _validate_remote_operation(self.config, self.config.repo_root)
        run_command(
            ["git", "fetch", self.config.git_remote, self.config.main_branch],
            cwd=self.config.repo_root,
            check=True,
            env=git_remote_environment(self.config),
        )
        return f"{self.config.git_remote}/{self.config.main_branch}"

    def has_changes(self, path: Path) -> bool:
        result = run_command(["git", "status", "--porcelain"], cwd=path, check=True)
        return bool(result.stdout.strip())

    def base_commit(self, path: Path) -> str:
        """Return the exact commit from which the worktree is being edited."""

        return run_command(["git", "rev-parse", "HEAD"], cwd=path, check=True).stdout.strip()

    def tree(self, path: Path) -> str:
        """Hash the complete, non-ignored worktree without changing its index."""

        value = _worktree_tree(path)
        if value is None:
            raise RuntimeError(f"could not determine worktree tree: {path}")
        return value

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

    def patch_bytes(self, path: Path) -> bytes:
        """Return the authoritative binary patch for the current worktree."""

        return self.diff(path).encode("utf-8", errors="surrogateescape")

    def patch_identity(self, path: Path) -> str:
        return sha256(self.patch_bytes(path)).hexdigest()

    binary_patch = patch_bytes
    patch_digest = patch_identity
    output_tree = tree

    def snapshot(self, path: Path) -> tuple[str, str, str]:
        """Return ``(base_commit, output_tree, patch_digest)`` atomically enough
        for a single trusted process; callers persist it before advancing a
        phase and re-check it before consuming the result.
        """

        return self.base_commit(path), self.tree(path), self.patch_identity(path)

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

    def patch_preparation_intent(
        self, task: TaskRecord, *, ordinal: int, base_identity: str,
        patch_text: str, accepted_tree: str | None,
    ) -> dict[str, Any]:
        """Calculate authorized trees before touching the worktree or stash."""
        if task.worktree_path is None:
            raise RuntimeError("base-change preparation requires accepted worktree identity")
        path = Path(task.worktree_path)
        accepted_tree = accepted_tree or self.tree(path)
        source_base = self.base_commit(path)
        if self.tree(path) != accepted_tree:
            raise RuntimeError("source worktree differs from the accepted tree")
        existing_patch = self.diff(path)
        if existing_patch and existing_patch != patch_text:
            raise RuntimeError("source worktree differs from the accepted patch")
        source_branch = task.branch_name or f"steward/{_slug(task.spec.kind)}/{_slug(task.id)}"
        branch = f"{source_branch}-pipeline-{ordinal}"
        if run_command(["git", "show-ref", "--verify", f"refs/heads/{branch}"], cwd=path).ok:
            raise RuntimeError("preparation branch already exists without durable intent")
        with tempfile.TemporaryDirectory(prefix="coquic-steward-prepare-") as temporary:
            env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
            run_command(["git", "read-tree", base_identity], cwd=path, env=env, check=True)
            input_tree = run_command(["git", "write-tree"], cwd=path, env=env, check=True).stdout.strip()
            result = run_command(["git", "apply", "--cached", "--binary", "-"], cwd=path, env=env, input_text=patch_text)
            output_tree = run_command(["git", "write-tree"], cwd=path, env=env, check=True).stdout.strip()
        return {
            "source_base": source_base, "source_branch": source_branch,
            "accepted_tree": accepted_tree, "base_identity": base_identity,
            "input_tree": input_tree, "output_tree": output_tree,
            "branch": branch, "ordinal": ordinal, "applied": result.ok,
            "detail": (result.stderr or result.stdout).strip()[-2000:],
            "stash_marker": f"steward-base-change-{task.id}-{ordinal}",
        }

    def prepare_patch_worktree(
        self, task: TaskRecord, *, ordinal: int, base_identity: str,
        patch_text: str, accepted_tree: str | None = None,
        preparation: dict[str, Any] | None = None,
    ) -> PreparedPatchWorktree:
        """Reconcile only exact states authorized by the persisted preparation."""
        if task.worktree_path is None:
            raise RuntimeError("base-change preparation requires the task worktree")
        accepted_tree = accepted_tree or (
            preparation["accepted_tree"] if preparation else self.tree(Path(task.worktree_path))
        )
        intent = preparation or self.patch_preparation_intent(
            task, ordinal=ordinal, base_identity=base_identity,
            patch_text=patch_text, accepted_tree=accepted_tree,
        )
        path = Path(task.worktree_path)
        branch = intent["branch"]
        marker = intent["stash_marker"]
        if (intent["base_identity"], intent["accepted_tree"], intent["ordinal"]) != (base_identity, accepted_tree, ordinal):
            raise RuntimeError("preparation intent mismatch")

        def owned_stashes() -> list[tuple[str, str]]:
            rows = run_command(["git", "stash", "list", "--format=%gd%x09%H%x09%gs"], cwd=path, check=True).stdout.splitlines()
            return [(ref, oid) for ref, oid, subject in (row.split("\t", 2) for row in rows) if subject.endswith(": " + marker)]

        owned = owned_stashes()
        if len(owned) > 1:
            raise RuntimeError("ambiguous preparation stash ownership")
        def verify_stash(oid: str) -> None:
            if run_command(["git", "rev-parse", oid + "^1"], cwd=path, check=True).stdout.strip() != intent["source_base"]:
                raise RuntimeError("preparation stash base mismatch")
            with tempfile.TemporaryDirectory(prefix="coquic-steward-stash-") as temporary:
                env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
                run_command(["git", "read-tree", oid], cwd=path, env=env, check=True)
                if run_command(["git", "rev-parse", "--verify", oid + "^3"], cwd=path).ok:
                    run_command(["git", "read-tree", "--prefix=", oid + "^3"], cwd=path, env=env, check=True)
                tree = run_command(["git", "write-tree"], cwd=path, env=env, check=True).stdout.strip()
                if tree != accepted_tree:
                    raise RuntimeError("preparation stash differs from accepted bytes")

        for _, oid in owned:
            verify_stash(oid)
        head = self.base_commit(path)
        tree = self.tree(path)
        if head == intent["source_base"] and head != base_identity:
            source_branch = run_command(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], cwd=path).stdout.strip()
            if source_branch != intent["source_branch"]:
                raise RuntimeError("source branch differs from durable intent")
            if tree == accepted_tree:
                if self.has_changes(path):
                    if owned:
                        raise RuntimeError("source patch and preparation stash both present")
                    run_command(["git", "stash", "push", "--include-untracked", "--message", marker], cwd=path, check=True)
                    owned = owned_stashes()
            elif self.has_changes(path) or not owned:
                raise RuntimeError("source changed outside recorded preparation")
            if self.has_changes(path):
                raise RuntimeError("preparation did not preserve the accepted patch")
            for _, oid in owned:
                verify_stash(oid)
            run_command(["git", "switch", "--detach", "--no-overwrite-ignore", base_identity], cwd=path, check=True)
            head, tree = self.base_commit(path), self.tree(path)
        if head != base_identity or tree not in {intent["input_tree"], intent["output_tree"]}:
            raise RuntimeError("worktree differs from authorized preparation states")
        current_branch = run_command(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], cwd=path).stdout.strip()
        if current_branch != branch:
            if current_branch and not (
                current_branch == intent["source_branch"]
                and intent["source_base"] == base_identity
            ):
                raise RuntimeError("unexpected branch during preparation")
            exists = run_command(["git", "show-ref", "--verify", f"refs/heads/{branch}"], cwd=path).ok
            if exists:
                raise RuntimeError("preparation branch is owned elsewhere")
            run_command(["git", "switch", "-c", branch, base_identity], cwd=path, check=True)
        if tree == intent["input_tree"] and intent["applied"]:
            run_command(["git", "apply", "--binary", "-"], cwd=path, input_text=patch_text, check=True)
        if self.tree(path) != intent["output_tree"]:
            raise RuntimeError("prepared tree does not match durable intent")
        # Drop only our exact stash, never the shared repository's newest entry.
        for ref, oid in owned_stashes():
            if run_command(["git", "rev-parse", ref], cwd=path, check=True).stdout.strip() != oid:
                raise RuntimeError("stash ownership changed during preparation")
            run_command(["git", "stash", "drop", ref], cwd=path, check=True)
        return PreparedPatchWorktree(
            path, branch, base_identity, intent["input_tree"], intent["output_tree"],
            self.patch_identity(path), intent["applied"], intent["detail"],
        )

    def reset_to_main(self, path: Path) -> None:
        _validate_remote_operation(self.config, path)
        run_command(
            ["git", "fetch", self.config.git_remote, self.config.main_branch],
            cwd=path,
            check=True,
            env=git_remote_environment(self.config),
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

    def staged_tree(self, path: Path) -> str:
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
        if self.config.dry_run:
            raise RuntimeError("git push requires a live effect decision")
        _validate_remote_operation(self.config, path)
        return run_command(
            ["git", "push", self.config.git_remote, f"HEAD:{self.config.main_branch}"],
            cwd=path,
            check=True,
            env=git_remote_environment(self.config),
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
        output = self._status_output(path)
        forbidden: list[str] = []
        for changed in _changed_paths_from_porcelain(output):
            parts = set(Path(changed).parts)
            if parts & FORBIDDEN_PATH_PARTS:
                forbidden.append(changed)
        return forbidden

    def frozen_paths(self, path: Path, task: TaskRecord) -> list[str]:
        return [
            changed
            for changed in _changed_paths_from_porcelain(self._status_output(path))
            if _frozen_path_matches(self.config.path_policy, task.spec.kind, changed)
        ]

    @staticmethod
    def _status_output(path: Path) -> str:
        return run_command(
            [
                "git",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            cwd=path,
            check=True,
        ).stdout

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
    if not output:
        return []
    records = output.split("\0")
    if records[-1] != "":
        raise _PathPolicyStatusParseError(output)

    paths: list[str] = []
    seen: set[str] = set()
    index = 0
    while index < len(records) - 1:
        record = records[index]
        if len(record) < 4 or record[2] != " " or not record[3:]:
            raise _PathPolicyStatusParseError(output)
        status = record[:2]
        if (
            status == "  "
            or not all(code in _PORCELAIN_STATUS_CODES for code in status)
            or ("?" in status and status != "??")
            or ("!" in status and status != "!!")
        ):
            raise _PathPolicyStatusParseError(output)
        destination = record[3:]
        if status[0] in {"R", "C"}:
            if index + 1 >= len(records) - 1 or not records[index + 1]:
                raise _PathPolicyStatusParseError(output)
            raw_paths = (records[index + 1], destination)
            index += 2
        else:
            raw_paths = (destination,)
            index += 1

        for raw_path in raw_paths:
            path = _normalize_policy_path(raw_path)
            if not path or path in seen:
                continue
            paths.append(path)
            seen.add(path)
    return paths


def _normalize_policy_path(path: str) -> str:
    return path.strip().replace("\\", "/")


def _path_policy_status_diagnostic(output: str) -> dict[str, object]:
    raw = output.encode("utf-8")
    return {
        "raw_prefix": repr(raw[:256]),
        "byte_length": len(raw),
    }

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
