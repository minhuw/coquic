from coquic_rag.config import ProjectPaths


def test_default_leaves_qdrant_url_unset_without_env(monkeypatch):
    monkeypatch.delenv("COQUIC_QDRANT_URL", raising=False)

    paths = ProjectPaths.default()

    assert paths.qdrant_url is None


def test_default_reads_qdrant_url_from_env(monkeypatch):
    qdrant_url = "http://127.0.0.1:6333"
    monkeypatch.setenv("COQUIC_QDRANT_URL", qdrant_url)

    paths = ProjectPaths.default()

    assert paths.qdrant_url == qdrant_url


def test_default_state_dir_is_dot_rag():
    paths = ProjectPaths.default()

    assert paths.state_dir == paths.repo_root / ".rag"


def test_project_paths_constructor_defaults_qdrant_url_to_none(tmp_path):
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=tmp_path / "docs" / "rfc",
        state_dir=tmp_path / ".rag",
        model_cache_dir=tmp_path / ".rag" / "cache" / "models",
    )

    assert paths.qdrant_url is None
