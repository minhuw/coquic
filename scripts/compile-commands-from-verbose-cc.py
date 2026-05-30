#!/usr/bin/env python3

import json
import pathlib
import shlex
import sys


def is_project_file(path: pathlib.Path, repo_root: pathlib.Path) -> bool:
    try:
        relative = path.resolve().relative_to(repo_root)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0] in {"src", "tests"}


def strip_output_arguments(argv: list[str]) -> list[str]:
    stripped: list[str] = []
    skip_next = False
    value_flags = {
        "-MF",
        "-MJ",
        "-MQ",
        "-MT",
        "-o",
        "--serialize-diagnostics",
        "-serialize-diagnostics",
    }
    joined_prefixes = (
        "-MF",
        "-MJ",
        "-MQ",
        "-MT",
        "-o",
        "--serialize-diagnostics=",
        "-serialize-diagnostics=",
    )
    dependency_flags = {
        "-M",
        "-MD",
        "-MG",
        "-MM",
        "-MMD",
        "-MP",
        "-MV",
    }

    for arg in argv:
        if skip_next:
            skip_next = False
            continue

        if arg in value_flags:
            skip_next = True
            continue

        if arg in dependency_flags:
            continue

        if any(arg.startswith(prefix) and arg != prefix for prefix in joined_prefixes):
            continue

        stripped.append(arg)

    return stripped


def normalize_arguments(argv: list[str], source_idx: int) -> list[str]:
    source_path = pathlib.Path(argv[source_idx])
    driver = "clang" if source_path.suffix == ".c" else "clang++"
    return [driver] + strip_output_arguments(argv[source_idx:])


def find_zig_clang_source_index(argv: list[str]) -> int | None:
    for idx, token in enumerate(argv):
        if idx + 2 >= len(argv):
            break
        if pathlib.Path(token).name != "zig":
            continue
        if argv[idx + 1] != "clang":
            continue
        return idx + 2
    return None


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: compile-commands-from-verbose-cc.py <repo-root>"
        )

    repo_root = pathlib.Path(sys.argv[1]).resolve()
    entries_by_file: dict[str, dict[str, object]] = {}

    for raw_line in sys.stdin:
        line = raw_line.strip()

        try:
            argv = shlex.split(line)
        except ValueError:
            continue

        source_idx = find_zig_clang_source_index(argv)
        if source_idx is None or "-c" not in argv:
            continue

        source_path = pathlib.Path(argv[source_idx]).resolve()
        if not is_project_file(source_path, repo_root):
            continue

        entries_by_file[str(source_path)] = {
            "directory": str(repo_root),
            "file": str(source_path),
            "arguments": normalize_arguments(argv, source_idx),
        }

    entries = [entries_by_file[key] for key in sorted(entries_by_file)]
    if not entries:
        raise SystemExit(
            "no compile commands captured from zig --verbose-cc output"
        )

    json.dump(entries, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
