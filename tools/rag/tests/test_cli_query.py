from __future__ import annotations

import json
import shutil
from pathlib import Path

from coquic_rag.cli.main import main


def _copy_query_fixtures(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("rfc9000.txt", "rfc9369.txt"):
        shutil.copyfile(Path("docs/rfc") / filename, source_dir / filename)


def _build_index(source_dir: Path, state_dir: Path) -> None:
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


def test_search_sections_returns_json_results(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    _build_index(source_dir, state_dir)
    capsys.readouterr()

    exit_code = main(
        [
            "search-sections",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
            "--top-k",
            "3",
            "ACK frame behavior",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["results"]
    assert payload["results"][0]["rfc"] == 9000
    assert payload["results"][0]["citations"]


def test_get_section_returns_json_payload(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    _build_index(source_dir, state_dir)
    capsys.readouterr()

    exit_code = main(
        [
            "get-section",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--rfc",
            "9000",
            "--section-id",
            "18.2",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["found"] is True
    assert payload["citation"] == "RFC 9000 Section 18.2"


def test_trace_term_returns_definitions_and_mentions(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    _build_index(source_dir, state_dir)
    capsys.readouterr()

    exit_code = main(
        [
            "trace-term",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "max_udp_payload_size",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["term"] == "max_udp_payload_size"
    assert payload["definitions"][0]["citation"] == "RFC 9000 Section 18.2"


def test_search_sections_reports_missing_index_without_traceback(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)

    exit_code = main(
        [
            "search-sections",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--embedder",
            "fake",
            "ACK frame behavior",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    error_output = captured.err
    assert "QUIC index is not ready" in error_output
    assert "Traceback" not in error_output
