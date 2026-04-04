import json
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


def test_manifest_tracks_qlog_drafts_with_generic_doc_metadata() -> None:
    paths = ProjectPaths.default()
    manifest = json.loads(
        (paths.repo_root / "docs" / "rfc" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    entries = {entry["doc_id"]: entry for entry in manifest["entries"]}

    expected_entries = {
        "draft-ietf-quic-qlog-main-schema-13": {
            "title": "qlog: Structured Logging for Network Protocols",
            "local_path": "docs/rfc/draft-ietf-quic-qlog-main-schema-13.txt",
            "url": "https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-13.txt",
        },
        "draft-ietf-quic-qlog-quic-events-12": {
            "title": "QUIC event definitions for qlog",
            "local_path": "docs/rfc/draft-ietf-quic-qlog-quic-events-12.txt",
            "url": "https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-12.txt",
        },
        "draft-ietf-quic-qlog-h3-events-12": {
            "title": "HTTP/3 qlog event definitions",
            "local_path": "docs/rfc/draft-ietf-quic-qlog-h3-events-12.txt",
            "url": "https://www.ietf.org/archive/id/draft-ietf-quic-qlog-h3-events-12.txt",
        },
    }

    for doc_id, expected in expected_entries.items():
        assert doc_id in entries
        entry = entries[doc_id]
        assert entry["doc_id"] == doc_id
        assert entry["doc_kind"] == "internet-draft"
        assert entry["draft_name"] == doc_id
        assert entry["title"] == expected["title"]
        assert entry["local_path"] == expected["local_path"]
        assert entry["url"] == expected["url"]
        assert (paths.repo_root / entry["local_path"]).is_file()


def test_manifest_covers_every_tracked_source_document() -> None:
    paths = ProjectPaths.default()
    manifest = json.loads(
        (paths.repo_root / "docs" / "rfc" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    manifest_paths = {entry["local_path"] for entry in manifest["entries"]}
    source_paths = {
        str(path.relative_to(paths.repo_root))
        for path in (paths.repo_root / "docs" / "rfc").glob("*.txt")
    }

    assert manifest_paths == source_paths
