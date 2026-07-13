#!/usr/bin/env python3
"""Enforce removal of the local Steward web stack."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


FORBIDDEN_DEPENDENCIES = {"fastapi", "uvicorn", "httpx"}


@dataclass(frozen=True)
class TextRule:
    name: str
    pattern: re.Pattern[str]
    negative_fixture: str


TEXT_RULES = (
    TextRule(
        "python web package import",
        re.compile(r"\bcoquic_steward\.web\b"),
        "from coquic_steward.web import app",
    ),
    TextRule(
        "web runtime",
        re.compile(r"\bStewardWebRuntime\b"),
        "runtime = StewardWebRuntime(config)",
    ),
    TextRule(
        "web command or flags",
        re.compile(r"(?:--(?:no-)?web\b|coquic-steward\s+web\b)"),
        "coquic-steward daemon --no-web",
    ),
    TextRule("FastAPI dependency", re.compile(r"\bfastapi\b", re.IGNORECASE), "fastapi"),
    TextRule("Uvicorn dependency", re.compile(r"\buvicorn\b", re.IGNORECASE), "uvicorn"),
    TextRule("HTTPX dependency", re.compile(r"\bhttpx\b", re.IGNORECASE), "httpx"),
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def tracked_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        text=False,
    )
    return [item.decode() for item in result.stdout.split(b"\0") if item]


def active_scan_paths(root: Path, tracked: list[str]) -> list[str]:
    operator_files = {
        "steward/README.md",
        "steward/pyproject.toml",
        "steward/steward.example.toml",
    }
    return sorted(
        path
        for path in tracked
        if path in operator_files
        or (path.startswith("steward/src/") and path.endswith(".py"))
    )


def check_text(path: str, text: str) -> list[str]:
    return [f"{path}: contains forbidden {rule.name}" for rule in TEXT_RULES if rule.pattern.search(text)]


def direct_dependencies(root: Path) -> set[str]:
    document = tomllib.loads((root / "steward" / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project", {})
    values: list[str] = list(project.get("dependencies", []))
    for group in document.get("dependency-groups", {}).values():
        values.extend(group)
    names = set()
    for value in values:
        match = re.match(r"\s*([A-Za-z0-9_.-]+)", value)
        if match:
            names.add(match.group(1).lower().replace("_", "-"))
    return names


def validate_repository(root: Path) -> list[str]:
    tracked = tracked_paths(root)
    violations = [
        f"tracked forbidden path: {path}"
        for path in tracked
        if path == "steward/web-ui"
        or path.startswith("steward/web-ui/")
        or path == "steward/src/coquic_steward/web"
        or path.startswith("steward/src/coquic_steward/web/")
    ]
    for path in active_scan_paths(root, tracked):
        violations.extend(check_text(path, (root / path).read_text(encoding="utf-8")))
    for dependency in sorted(FORBIDDEN_DEPENDENCIES & direct_dependencies(root)):
        violations.append(f"steward direct dependency remains: {dependency}")
    return violations


def run_self_test() -> None:
    for rule in TEXT_RULES:
        if not rule.pattern.search(rule.negative_fixture):
            raise AssertionError(f"negative fixture does not exercise {rule.name}")
    for dependency in FORBIDDEN_DEPENDENCIES:
        if dependency not in direct_dependencies_from_fixture(f"{dependency}>=1"):
            raise AssertionError(f"negative dependency fixture does not exercise {dependency}")


def direct_dependencies_from_fixture(value: str) -> set[str]:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", value)
    if not match:
        return set()
    return {match.group(1).lower().replace("_", "-")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="exercise every negative guard fixture")
    args = parser.parse_args()
    run_self_test()
    if args.self_test:
        print("Steward migration guard negative fixtures passed")
        return 0
    violations = validate_repository(repository_root())
    if violations:
        print("Steward migration guard failed:", file=sys.stderr)
        print("\n".join(f"- {violation}" for violation in violations), file=sys.stderr)
        return 1
    print("Steward migration guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
