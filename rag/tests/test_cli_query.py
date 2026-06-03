from __future__ import annotations

import json
from pathlib import Path

from coquic_rag.cli.main import main
from fixtures import write_query_fixtures


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
    write_query_fixtures(source_dir)
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
    assert any(result["doc_id"] == "rfc9000" for result in payload["results"])
    assert payload["results"][0]["citations"]


def test_get_section_returns_json_payload_for_draft_doc(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    write_query_fixtures(source_dir)
    _build_index(source_dir, state_dir)
    capsys.readouterr()

    exit_code = main(
        [
            "get-section",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--doc",
            "draft-ietf-quic-qlog-main-schema-13",
            "--section-id",
            "1",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["found"] is True
    assert payload["citation"] == "draft-ietf-quic-qlog-main-schema-13 Section 1"


def test_trace_term_returns_definitions_and_mentions(tmp_path: Path, capsys) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    write_query_fixtures(source_dir)
    _build_index(source_dir, state_dir)
    capsys.readouterr()

    exit_code = main(
        [
            "trace-term",
            "--source",
            str(source_dir),
            "--state-dir",
            str(state_dir),
            "--doc",
            "rfc9000",
            "max_udp_payload_size",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["term"] == "max_udp_payload_size"
    assert payload["definitions"][0]["citation"] == "RFC 9000 Section 18.2"


def test_search_sections_returns_empty_results_when_collection_is_missing(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    write_query_fixtures(source_dir)

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

    assert exit_code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"results": []}
    assert captured.err == ""
