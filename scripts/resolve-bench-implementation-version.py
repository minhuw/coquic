#!/usr/bin/env python3
import argparse
import json
import os
import subprocess  # nosec B404: this script runs fixed git commands only.
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=repo_root / "bench/implementations.json", type=Path)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--server-implementation")
    parser.add_argument("--commit")
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise ValueError(f"failed to read `{path}`: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse `{path}` JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"`{path}` root must be an object")
    if data.get("schema_version") != 1:
        raise ValueError(f"`{path}` schema_version must be 1")
    implementations = data.get("implementations")
    if not isinstance(implementations, dict):
        raise ValueError(f"`{path}` field `implementations` must be an object")
    return data


def local_git_commit() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    git = "/usr/bin/git"
    try:
        return subprocess.check_output(
            [git, "-C", str(repo_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()  # nosec B603: command arguments are fixed except for repo_root.
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def version_for(data: dict, label: str, commit: str | None) -> str:
    implementation = data["implementations"].get(label)
    if not isinstance(implementation, dict):
        raise ValueError(f"implementation `{label}` is missing from implementations manifest")
    version = implementation.get("library_version")
    if version in (None, ""):
        return "unknown"
    version = str(version)
    if version in ("${GITHUB_SHA}", "$GITHUB_SHA"):
        return commit or os.environ.get("GITHUB_SHA") or local_git_commit()
    return version


def main() -> int:
    args = parse_args()
    try:
        data = load_manifest(args.manifest)
        client_version = version_for(data, args.implementation, args.commit)
        server = args.server_implementation or args.implementation
        if server == args.implementation:
            print(client_version)
        else:
            server_version = version_for(data, server, args.commit)
            print(f"{args.implementation}:{client_version} -> {server}:{server_version}")
        return 0
    except ValueError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
