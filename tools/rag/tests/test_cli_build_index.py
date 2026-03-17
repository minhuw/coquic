from __future__ import annotations

import shutil
from pathlib import Path

from coquic_rag.cli.main import main
from coquic_rag.store.artifacts import (
    read_graph_edges,
    read_graph_nodes,
    read_section_records,
)
from coquic_rag.store.qdrant_store import QdrantSectionStore


def _copy_fixture_rfc(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path("docs/rfc/rfc9000.txt"), source_dir / "rfc9000.txt")


def test_build_index_writes_artifacts_and_qdrant_state(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_fixture_rfc(source_dir)

    exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )

    assert exit_code == 0
    artifacts_dir = state_dir / "artifacts"
    assert read_section_records(artifacts_dir / "sections.jsonl")
    assert read_graph_nodes(artifacts_dir / "graph_nodes.jsonl")
    assert read_graph_edges(artifacts_dir / "graph_edges.jsonl")
    assert QdrantSectionStore(state_dir / "qdrant").collection_exists()

    output = capsys.readouterr().out
    assert "indexed 1 RFC" in output


def test_doctor_reports_ready_after_build_index(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_fixture_rfc(source_dir)

    build_exit_code = main(
        [
            "build-index",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
        ]
    )
    assert build_exit_code == 0
    capsys.readouterr()

    doctor_exit_code = main(
        [
            "doctor",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
        ]
    )

    assert doctor_exit_code == 0
    output = capsys.readouterr().out
    assert "source_docs: ok" in output
    assert "artifacts: ok" in output
    assert "qdrant: ok" in output
    assert "ready: yes" in output
