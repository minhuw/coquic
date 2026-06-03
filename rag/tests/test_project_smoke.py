from pathlib import Path

import pytest

from coquic_rag.config import ProjectPaths, discover_repo_root


def test_default_paths(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("COQUIC_RFC_SOURCE", raising=False)
    paths = ProjectPaths.default()

    assert (paths.repo_root / "build.zig").is_file()
    assert paths.rfc_source is None
    assert paths.state_dir == paths.repo_root / ".rag"


def test_default_paths_use_explicit_source_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "source"
    monkeypatch.setenv("COQUIC_RFC_SOURCE", str(source_dir))

    paths = ProjectPaths.default()

    assert paths.rfc_source == source_dir


def test_discover_repo_root_fails_without_sentinel(tmp_path: Path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)

    with pytest.raises(RuntimeError):
        discover_repo_root(nested)
