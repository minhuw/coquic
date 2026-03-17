from __future__ import annotations

import shutil
from pathlib import Path

import anyio
import pytest

import coquic_rag.mcp_server.server as mcp_server_module
import coquic_rag.query.service as query_service_module
from coquic_rag.cli.main import main as cli_main
from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import FakeEmbedder
from coquic_rag.mcp_server.server import create_mcp_server, main as mcp_main
from coquic_rag.query.service import IndexNotBuiltError, IndexStatus, QueryService
from coquic_rag.store.qdrant_store import QdrantSectionStore


def _copy_query_fixtures(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("rfc9000.txt", "rfc9369.txt"):
        shutil.copyfile(Path("docs/rfc") / filename, source_dir / filename)


def _build_server(tmp_path: Path):
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)

    _build_index(source_dir, state_dir)

    service = QueryService(
        paths=ProjectPaths(
            repo_root=tmp_path,
            rfc_source=source_dir,
            state_dir=state_dir,
            model_cache_dir=state_dir / "cache" / "models",
        ),
        embedder=FakeEmbedder(),
    )
    return create_mcp_server(service=service)


def _build_index(source_dir: Path, state_dir: Path) -> None:
    exit_code = cli_main(
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


def test_mcp_server_exposes_query_tools(tmp_path: Path) -> None:
    server = _build_server(tmp_path)

    tools = anyio.run(server.list_tools)
    tool_names = {tool.name for tool in tools}
    assert tool_names == {
        "search_sections",
        "get_section",
        "trace_term",
        "related_sections",
        "lookup_term",
    }

    _, get_section_result = anyio.run(
        server.call_tool,
        "get_section",
        {"rfc": 9000, "section_id": "18.2"},
    )
    assert get_section_result["citation"] == "RFC 9000 Section 18.2"

    _, trace_term_result = anyio.run(
        server.call_tool,
        "trace_term",
        {"term": "max_udp_payload_size"},
    )
    assert trace_term_result["definitions"][0]["citation"] == "RFC 9000 Section 18.2"

    _, related_sections_result = anyio.run(
        server.call_tool,
        "related_sections",
        {"rfc": 9369, "section_id": "5"},
    )
    assert any(
        section["section_id"] in {"4", "4.1"}
        for section in related_sections_result["sections"]
    )

    _, search_sections_result = anyio.run(
        server.call_tool,
        "search_sections",
        {"query": "ACK frame behavior", "top_k": 3},
    )
    assert search_sections_result["results"][0]["rfc"] == 9000

    _, lookup_term_result = anyio.run(
        server.call_tool,
        "lookup_term",
        {"term_type": "transport_parameter", "name": "max_udp_payload_size"},
    )
    assert lookup_term_result["term_class"] == "transport_parameter"


def test_mcp_server_exposes_section_resource_template(tmp_path: Path) -> None:
    server = _build_server(tmp_path)

    resource_templates = anyio.run(server.list_resource_templates)
    assert any(
        template.uriTemplate == "quic://rfc/{rfc}/section/{section_id}"
        for template in resource_templates
    )

    contents = anyio.run(
        server.read_resource,
        "quic://rfc/9000/section/18.2",
    )
    assert "Transport Parameter Definitions" in contents[0].content


def test_create_mcp_server_fails_fast_when_index_is_incomplete(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )

    with pytest.raises(IndexNotBuiltError, match="ready: no"):
        create_mcp_server(paths=paths)


def test_mcp_main_returns_nonzero_when_index_is_incomplete(
    tmp_path: Path,
    capsys,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )

    assert mcp_main(paths=paths) == 1

    error_output = capsys.readouterr().err
    assert "QUIC index is not ready" in error_output


def test_mcp_main_returns_nonzero_with_clear_remote_backend_error(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )
    remote_url = "http://127.0.0.1:6333"
    monkeypatch.setenv("COQUIC_QDRANT_URL", remote_url)
    _build_index(source_dir, state_dir)

    def _raise_connection_error(_self: QdrantSectionStore) -> int | None:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(QdrantSectionStore, "section_count", _raise_connection_error)

    assert mcp_main(paths=paths) == 1

    error_output = capsys.readouterr().err
    assert remote_url in error_output
    assert "nix run .#qdrant-dev -- start" in error_output


def test_mcp_main_remote_unreachable_probes_status_once(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=tmp_path / "source",
        state_dir=tmp_path / ".rag",
        model_cache_dir=tmp_path / ".rag" / "cache" / "models",
    )
    remote_url = "http://127.0.0.1:6333"
    monkeypatch.setenv("COQUIC_QDRANT_URL", remote_url)

    probe_count = 0

    def _fake_status(_paths: ProjectPaths, *, collection_name: str) -> IndexStatus:
        del collection_name
        nonlocal probe_count
        probe_count += 1
        return IndexStatus(
            source_ok=True,
            artifacts_ok=True,
            qdrant_ok=False,
            qdrant_status="unreachable",
            qdrant_backend="remote",
            section_count=10,
            indexed_count=None,
        )

    monkeypatch.setattr(query_service_module, "get_index_status", _fake_status)
    monkeypatch.setattr(mcp_server_module, "get_index_status", _fake_status)

    assert mcp_main(paths=paths) == 1

    error_output = capsys.readouterr().err
    assert remote_url in error_output
    assert probe_count == 1


def test_mcp_main_preserves_incomplete_index_message_when_remote_unreachable_with_missing_artifacts(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )
    monkeypatch.setenv("COQUIC_QDRANT_URL", "http://127.0.0.1:6333")

    def _raise_connection_error(_self: QdrantSectionStore) -> int | None:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(QdrantSectionStore, "section_count", _raise_connection_error)

    assert mcp_main(paths=paths) == 1

    error_output = capsys.readouterr().err
    assert "QUIC index is not ready" in error_output
    assert "artifacts: missing" in error_output
    assert "nix run .#qdrant-dev -- start" not in error_output


def test_mcp_main_returns_nonzero_with_clear_local_lock_error(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "source"
    state_dir = tmp_path / ".rag"
    _copy_query_fixtures(source_dir)
    paths = ProjectPaths(
        repo_root=tmp_path,
        rfc_source=source_dir,
        state_dir=state_dir,
        model_cache_dir=state_dir / "cache" / "models",
    )
    monkeypatch.delenv("COQUIC_QDRANT_URL", raising=False)

    def _raise_local_lock_error(_self: QdrantSectionStore) -> int | None:
        raise RuntimeError(
            f"Storage folder {state_dir / 'qdrant'} is already accessed by another "
            "instance of Qdrant client. If you require concurrent access, use Qdrant "
            "server instead."
        )

    monkeypatch.setattr(QdrantSectionStore, "section_count", _raise_local_lock_error)

    assert mcp_main(paths=paths) == 1

    error_output = capsys.readouterr().err
    assert "shared server workflow" in error_output
    assert "nix run .#qdrant-dev -- start" in error_output
