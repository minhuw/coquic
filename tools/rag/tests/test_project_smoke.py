from coquic_rag.config import ProjectPaths


def test_default_paths():
    paths = ProjectPaths.default()

    assert paths.rfc_source.as_posix().endswith("docs/rfc")
    assert paths.state_dir.as_posix().endswith(".rag")
