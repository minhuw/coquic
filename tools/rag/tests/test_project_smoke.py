from pathlib import Path

import pytest

from coquic_rag.config import ProjectPaths, discover_repo_root


def test_default_paths():
    paths = ProjectPaths.default()

    assert (paths.repo_root / "build.zig").is_file()
    assert (paths.repo_root / "docs" / "rfc").is_dir()
    assert paths.rfc_source == paths.repo_root / "docs" / "rfc"
    assert paths.state_dir == paths.repo_root / ".rag"


def test_discover_repo_root_fails_without_sentinel(tmp_path: Path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)

    with pytest.raises(RuntimeError):
        discover_repo_root(nested)
