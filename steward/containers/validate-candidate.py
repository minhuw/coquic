"""Pinned gate driver; only the candidate supplies Steward imports and tests."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Keep this policy in the image, not in the candidate's pytest configuration.
SHARED_INPUTS = {"flake.nix", "flake.lock", "build.zig", "build.zig.zon", ".pre-commit-config.yaml"}
SHARED_PREFIXES = ("steward/", "contracts/", "scripts/", ".github/")


def main() -> int:
    worktree = Path(sys.argv[1]).resolve(strict=True)
    # A validation index/object overlay belongs to the outer repository, never
    # to the fresh Git repositories created by pytest fixtures.
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("GIT_", "PYTHON", "PYTEST"))
    }
    changed = subprocess.check_output(
        ["git", "-c", "safe.directory=*", "diff", "--name-only", "--no-renames", "-z", "HEAD", "--"],
        cwd=worktree, env=environment,
    ) + subprocess.check_output(
        ["git", "-c", "safe.directory=*", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=worktree, env=environment,
    )
    paths = changed.decode("utf-8", errors="surrogateescape").split("\0")
    if not any(path in SHARED_INPUTS or path.startswith(SHARED_PREFIXES) for path in paths):
        print("Steward pytest: skipped (no Steward/shared input changes)")
        return 0

    source = worktree / "steward" / "src"
    tests = worktree / "steward" / "tests"
    if not (source / "coquic_steward" / "__init__.py").is_file() or not tests.is_dir():
        raise RuntimeError("candidate Steward source/tests are missing; packaged fallback forbidden")
    # In production this is an isolated writable exec tmpfs, not source. /tmp
    # remains noexec; pytest's fake executable fixtures need this bounded mount.
    scratch = worktree / ".zig-cache"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="steward-pytest-", dir=scratch) as temporary:
        environment.update(
            HOME=temporary, COQUIC_HOME=temporary, TMPDIR=temporary,
            XDG_CACHE_HOME=temporary, XDG_CONFIG_HOME=temporary,
            PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1",
            PYTHONNOUSERSITE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
        )
        return subprocess.call(
            [sys.executable, "-B", "-s", "-c", """
import pathlib, sys
import coquic_steward
expected = pathlib.Path(sys.argv[1])
if pathlib.Path(coquic_steward.__file__).resolve() != expected:
    raise RuntimeError('Steward import escaped candidate source')
import pytest
raise SystemExit(pytest.main(sys.argv[2:]))
""", str(source / "coquic_steward" / "__init__.py"),
             str(tests), "-q", "-p", "no:cacheprovider",
             "--basetemp", str(Path(temporary) / "pytest")],
            cwd=worktree, env=environment,
        )


if __name__ == "__main__":
    raise SystemExit(main())
