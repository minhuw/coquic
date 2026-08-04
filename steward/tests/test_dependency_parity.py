from __future__ import annotations

import importlib.util
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-steward-dependency-parity.py"


def _checker_module():
    spec = importlib.util.spec_from_file_location("steward_dependency_parity", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load dependency parity checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    return _checker_module()


def _lock(checker, names: list[str], versions: dict[str, str]):
    return checker._fixture_lock(names, versions)


def test_self_test_command_exercises_negative_fixtures() -> None:
    subprocess.run([sys.executable, str(CHECKER), "--self-test"], cwd=ROOT, check=True)


def test_name_normalization_and_dev_dependencies_are_separate(checker) -> None:
    assert checker.normalize_distribution_name("SQLAlchemy") == "sqlalchemy"
    assert checker.normalize_distribution_name("my_pkg-name") == "my-pkg-name"
    document = {
        "project": {"dependencies": ["Pillow", "SQLAlchemy>=2"]},
        "dependency-groups": {"dev": ["pytest>=9"]},
    }
    assert checker.direct_runtime_dependencies(document) == {"pillow", "sqlalchemy"}


def test_exact_versions_pass_and_mismatch_is_deterministic(checker) -> None:
    document = {"project": {"dependencies": ["Pillow"]}}
    lock = _lock(checker, ["pillow"], {"pillow": "12.3.0"})
    checker.check_dependency_parity(document, lock, lambda _name: "12.3.0")
    with pytest.raises(checker.DependencyParityError, match="pillow: expected 12.3.0, actual 12.2.0"):
        checker.check_dependency_parity(document, lock, lambda _name: "12.2.0")


def test_missing_and_extra_direct_dependencies_fail(checker) -> None:
    document = {"project": {"dependencies": ["Pillow", "SQLAlchemy"]}}
    missing = _lock(checker, ["pillow"], {"pillow": "12.3.0"})
    with pytest.raises(checker.DependencyParityError, match="missing direct runtime dependency sqlalchemy"):
        checker.check_dependency_parity(document, missing, lambda _name: "12.3.0")

    extra = _lock(
        checker,
        ["pillow", "sqlalchemy", "extra"],
        {"pillow": "12.3.0", "sqlalchemy": "2.0.51", "extra": "1"},
    )
    with pytest.raises(checker.DependencyParityError, match="extra direct runtime dependency extra"):
        checker.check_dependency_parity(document, extra, lambda _name: "12.3.0")


def test_ambiguous_marker_and_missing_production_distribution_fail(checker) -> None:
    document = {"project": {"dependencies": ["Pillow"]}}
    lock = _lock(checker, ["pillow"], {"pillow": "12.3.0"})
    lock["package"].append(
        {
            "name": "pillow",
            "version": "12.2.0",
            "source": {"registry": "fixture"},
            "resolution-markers": ["python_full_version >= '3.13'"],
        }
    )
    with pytest.raises(checker.DependencyParityError, match="marker-dependent versions are unsupported"):
        checker.check_dependency_parity(document, lock, lambda _name: "12.3.0")

    def missing(_name: str) -> str:
        raise PackageNotFoundError("pillow")

    lock = _lock(checker, ["pillow"], {"pillow": "12.3.0"})
    with pytest.raises(checker.DependencyParityError, match="pillow: expected 12.3.0, actual <missing>"):
        checker.check_dependency_parity(document, lock, missing)
