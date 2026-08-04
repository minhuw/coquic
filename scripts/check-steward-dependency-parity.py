#!/usr/bin/env python3
"""Check Steward's direct uv and production Python dependencies agree.

The uv lock is the version authority for the direct runtime dependencies
declared by ``steward/pyproject.toml``.  The production interpreter supplies
the other side of the comparison through ``importlib.metadata``.  This guard
deliberately does not resolve PEP 508 markers: a lock that needs marker
evaluation is ambiguous for this small, deterministic check and must be
revisited when the production dependency policy is changed.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import re
import sys
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PROJECT_NAME = "coquic-steward"
_MISSING = "<missing>"


class DependencyParityError(ValueError):
    """One or more deterministic dependency parity violations."""

    def __init__(self, violations: Iterable[str]):
        self.violations = tuple(sorted(set(violations)))
        super().__init__("; ".join(self.violations))


@dataclass(frozen=True)
class DirectDependency:
    """A direct runtime dependency as declared by the project."""

    name: str
    declaration: str


def normalize_distribution_name(name: str) -> str:
    """Return a PEP 503 normalized distribution name."""

    if not isinstance(name, str) or not _DISTRIBUTION_NAME.fullmatch(name):
        raise ValueError(f"invalid distribution name: {name!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(value: Any, *, source: str) -> DirectDependency:
    if not isinstance(value, str):
        raise DependencyParityError((f"{source}: dependency must be a string",))
    match = _REQUIREMENT_NAME.match(value)
    if match is None:
        raise DependencyParityError((f"{source}: invalid dependency declaration",))
    # Marker evaluation belongs to uv.  The current production set has no
    # markers, and silently choosing a side of one would make this check
    # platform-dependent.
    if ";" in value:
        raise DependencyParityError((f"{source}: dependency markers are unsupported",))
    try:
        name = normalize_distribution_name(match.group(1))
    except ValueError as error:
        raise DependencyParityError((f"{source}: invalid distribution name",)) from error
    return DirectDependency(name=name, declaration=value)


def _unique_names(dependencies: Iterable[DirectDependency], *, source: str) -> set[str]:
    names: set[str] = set()
    violations: list[str] = []
    for dependency in dependencies:
        if dependency.name in names:
            violations.append(f"{source}: duplicate normalized dependency {dependency.name}")
        names.add(dependency.name)
    if violations:
        raise DependencyParityError(violations)
    return names


def direct_runtime_dependencies(pyproject: Mapping[str, Any]) -> set[str]:
    """Read only ``project.dependencies``; dependency groups are dev-only."""

    project = pyproject.get("project")
    if not isinstance(project, Mapping):
        raise DependencyParityError(("pyproject.toml: missing project table",))
    values = project.get("dependencies")
    if not isinstance(values, list):
        raise DependencyParityError(("pyproject.toml: project.dependencies must be a list",))
    dependencies = (
        _requirement_name(value, source="pyproject.toml") for value in values
    )
    return _unique_names(dependencies, source="pyproject.toml")


def _lock_dependency(value: Any, *, source: str) -> DirectDependency:
    if not isinstance(value, Mapping):
        raise DependencyParityError((f"{source}: lock dependency must be a table",))
    if "marker" in value or "markers" in value:
        raise DependencyParityError((f"{source}: dependency markers are unsupported",))
    return _requirement_name(value.get("name"), source=source)


def _editable_package(lock: Mapping[str, Any]) -> Mapping[str, Any]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise DependencyParityError(("uv.lock: missing package records",))
    matches = []
    for package in packages:
        if not isinstance(package, Mapping):
            raise DependencyParityError(("uv.lock: package record must be a table",))
        raw_name = package.get("name")
        try:
            is_project = isinstance(raw_name, str) and normalize_distribution_name(raw_name) == _PROJECT_NAME
        except ValueError:
            is_project = False
        if is_project and isinstance(package.get("source"), Mapping):
            source = package["source"]
            if source.get("editable") is not None:
                matches.append(package)
    if len(matches) != 1:
        raise DependencyParityError(
            (f"uv.lock: expected one editable {_PROJECT_NAME} package record",)
        )
    return matches[0]


def _lock_direct_dependencies(lock: Mapping[str, Any]) -> set[str]:
    package = _editable_package(lock)
    values = package.get("dependencies")
    if not isinstance(values, list):
        raise DependencyParityError(("uv.lock: editable package has no dependencies list",))
    dependencies = (
        _lock_dependency(value, source="uv.lock editable package") for value in values
    )
    return _unique_names(dependencies, source="uv.lock editable package")


def _lock_metadata_dependencies(lock: Mapping[str, Any]) -> set[str]:
    package = _editable_package(lock)
    metadata = lock.get("package.metadata")
    # tomllib represents [package.metadata] as a child of the editable package
    # table only when the source file uses that form.  uv currently emits the
    # metadata table nested under the package record, so accept both layouts.
    if not isinstance(metadata, Mapping):
        metadata = package.get("metadata")
    if not isinstance(metadata, Mapping):
        return set()
    values = metadata.get("requires-dist")
    if not isinstance(values, list):
        return set()
    dependencies: list[DirectDependency] = []
    for value in values:
        if isinstance(value, Mapping):
            if "marker" in value or "markers" in value:
                raise DependencyParityError(
                    ("uv.lock metadata: dependency markers are unsupported",)
                )
            dependencies.append(
                _requirement_name(value.get("name"), source="uv.lock metadata")
            )
        else:
            dependencies.append(_requirement_name(value, source="uv.lock metadata"))
    return _unique_names(dependencies, source="uv.lock metadata")


def _record_marker(record: Mapping[str, Any]) -> bool:
    """Whether a lock package record carries marker-dependent resolution."""

    for key in ("marker", "markers", "resolution-markers"):
        if key not in record:
            continue
        value = record[key]
        if value in (None, "", []):
            continue
        return True
    return False


def locked_runtime_versions(lock: Mapping[str, Any], names: set[str]) -> dict[str, str]:
    """Select one unmarked registry version for each direct dependency."""

    packages = lock.get("package")
    if not isinstance(packages, list):
        raise DependencyParityError(("uv.lock: missing package records",))
    records: dict[str, list[Mapping[str, Any]]] = {name: [] for name in names}
    for package in packages:
        if not isinstance(package, Mapping):
            continue
        raw_name = package.get("name")
        if not isinstance(raw_name, str):
            continue
        try:
            name = normalize_distribution_name(raw_name)
        except ValueError:
            continue
        if name in records:
            records[name].append(package)

    violations: list[str] = []
    versions: dict[str, str] = {}
    for name in sorted(names):
        candidates = records[name]
        if not candidates:
            violations.append(f"uv.lock: missing runtime package {name}")
            continue
        if any(_record_marker(candidate) for candidate in candidates):
            violations.append(f"uv.lock: marker-dependent versions are unsupported for {name}")
            continue
        if len(candidates) != 1:
            values = sorted(str(candidate.get("version", _MISSING)) for candidate in candidates)
            violations.append(f"uv.lock: ambiguous versions for {name}: {', '.join(values)}")
            continue
        version = candidates[0].get("version")
        if not isinstance(version, str) or not version:
            violations.append(f"uv.lock: missing version for {name}")
            continue
        versions[name] = version
    if violations:
        raise DependencyParityError(violations)
    return versions


def _production_version(
    name: str,
    version_lookup: Callable[[str], str],
) -> str:
    try:
        return version_lookup(name)
    except importlib.metadata.PackageNotFoundError:
        return _MISSING


def check_dependency_parity(
    pyproject: Mapping[str, Any],
    lock: Mapping[str, Any],
    version_lookup: Callable[[str], str] | None = None,
) -> None:
    """Validate names and exact versions, raising deterministic violations."""

    if version_lookup is None:
        version_lookup = importlib.metadata.version
    project_names = direct_runtime_dependencies(pyproject)
    lock_names = _lock_direct_dependencies(lock)
    violations: list[str] = []
    for name in sorted(project_names - lock_names):
        violations.append(f"uv.lock: missing direct runtime dependency {name}")
    for name in sorted(lock_names - project_names):
        violations.append(f"uv.lock: extra direct runtime dependency {name}")

    metadata_names = _lock_metadata_dependencies(lock)
    if metadata_names and metadata_names != project_names:
        for name in sorted(project_names - metadata_names):
            violations.append(f"uv.lock metadata: missing direct runtime dependency {name}")
        for name in sorted(metadata_names - project_names):
            violations.append(f"uv.lock metadata: extra direct runtime dependency {name}")

    versions: dict[str, str] = {}
    if not violations:
        versions = locked_runtime_versions(lock, project_names)
    else:
        # Still inspect the records when names differ so the resulting error
        # lists remain useful, but do not turn a missing name into a fake
        # version comparison.
        try:
            versions = locked_runtime_versions(lock, project_names & lock_names)
        except DependencyParityError as error:
            violations.extend(error.violations)

    for name in sorted(project_names):
        expected = versions.get(name, _MISSING)
        actual = _production_version(name, version_lookup)
        if expected == _MISSING:
            continue
        if actual == _MISSING:
            violations.append(f"{name}: expected {expected}, actual {_MISSING}")
        elif actual != expected:
            violations.append(f"{name}: expected {expected}, actual {actual}")
    if violations:
        raise DependencyParityError(violations)


def _load_toml(path: Path, label: str) -> Mapping[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DependencyParityError((f"{label}: unable to parse TOML",)) from error
    return value


def validate_repository(root: Path) -> None:
    pyproject = _load_toml(root / "steward" / "pyproject.toml", "pyproject.toml")
    lock = _load_toml(root / "steward" / "uv.lock", "uv.lock")
    check_dependency_parity(pyproject, lock)


def _expect_failure(callback: Callable[[], None], fragment: str) -> None:
    try:
        callback()
    except DependencyParityError as error:
        if not any(fragment in violation for violation in error.violations):
            raise AssertionError(
                f"negative fixture raised the wrong violation: {error.violations}"
            ) from error
        return
    raise AssertionError(f"negative fixture did not detect {fragment}")


def _fixture_lock(names: Iterable[str], versions: Mapping[str, str]) -> dict[str, Any]:
    dependencies = [{"name": name} for name in names]
    packages: list[dict[str, Any]] = [
        {
            "name": _PROJECT_NAME,
            "version": "0.1.0",
            "source": {"editable": "."},
            "dependencies": dependencies,
        }
    ]
    packages.extend(
        {"name": name, "version": version, "source": {"registry": "fixture"}}
        for name, version in versions.items()
    )
    return {"package": packages}


def run_self_test() -> None:
    """Exercise every negative fixture promised by the dependency contract."""

    assert normalize_distribution_name("Pillow") == "pillow"
    assert normalize_distribution_name("SQLAlchemy") == "sqlalchemy"
    assert normalize_distribution_name("my_pkg-name") == "my-pkg-name"

    pyproject = {
        "project": {"dependencies": ["Pillow", "SQLAlchemy>=2"]},
        "dependency-groups": {"dev": ["pytest>=9"]},
    }
    assert direct_runtime_dependencies(pyproject) == {"pillow", "sqlalchemy"}
    lock = _fixture_lock(("pillow", "sqlalchemy"), {"pillow": "1", "sqlalchemy": "2"})
    lookup = {"pillow": "1", "sqlalchemy": "2"}.__getitem__
    check_dependency_parity(pyproject, lock, lookup)

    _expect_failure(
        lambda: check_dependency_parity(
            pyproject,
            _fixture_lock(("pillow",), {"pillow": "1"}),
            lookup,
        ),
        "missing direct runtime dependency sqlalchemy",
    )
    _expect_failure(
        lambda: check_dependency_parity(
            pyproject,
            _fixture_lock(("pillow", "sqlalchemy", "extra"), {"pillow": "1", "sqlalchemy": "2", "extra": "3"}),
            lookup,
        ),
        "extra direct runtime dependency extra",
    )

    ambiguous = _fixture_lock(("pillow", "sqlalchemy"), {"pillow": "1", "sqlalchemy": "2"})
    ambiguous["package"].append(
        {"name": "pillow", "version": "9", "source": {"registry": "fixture"}, "resolution-markers": ["fixture"]}
    )
    _expect_failure(
        lambda: check_dependency_parity(pyproject, ambiguous, lookup),
        "marker-dependent versions are unsupported for pillow",
    )

    missing_distribution: dict[str, str] = {}

    def missing_lookup(name: str) -> str:
        if name not in missing_distribution:
            raise importlib.metadata.PackageNotFoundError(name)
        return missing_distribution[name]

    _expect_failure(
        lambda: check_dependency_parity(
            {"project": {"dependencies": ["Pillow"]}},
            _fixture_lock(("pillow",), {"pillow": "1"}),
            missing_lookup,
        ),
        "pillow: expected 1, actual <missing>",
    )
    _expect_failure(
        lambda: check_dependency_parity(
            {"project": {"dependencies": ["Pillow"]}},
            _fixture_lock(("pillow",), {"pillow": "1"}),
            lambda _name: "2",
        ),
        "pillow: expected 1, actual 2",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root (defaults to the checkout containing this script)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise all negative fixtures without inspecting installed packages",
    )
    args = parser.parse_args()
    try:
        run_self_test()
        if args.self_test:
            print("Steward dependency parity negative fixtures passed")
            return 0
        root = args.root.resolve() if args.root is not None else Path(__file__).resolve().parents[1]
        validate_repository(root)
    except DependencyParityError as error:
        print("Steward dependency parity failed:", file=sys.stderr)
        print("\n".join(f"- {violation}" for violation in error.violations), file=sys.stderr)
        return 1
    print("Steward dependency parity passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
