from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP

from coquic_rag.config import ProjectPaths
from coquic_rag.query.service import (
    IndexStatus,
    IndexNotBuiltError,
    QueryService,
    get_index_status,
)

_QDRANT_DEV_START_COMMAND = "nix run .#qdrant-dev -- start"
_LOCAL_QDRANT_LOCK_MARKER = "is already accessed by another instance of Qdrant client"


def _configured_qdrant_url(paths: ProjectPaths) -> str | None:
    return paths.qdrant_url or os.getenv("COQUIC_QDRANT_URL")


def _is_remote_qdrant_only_blocker(
    status: IndexStatus,
) -> bool:
    return (
        status.source_ok
        and status.artifacts_ok
        and status.qdrant_backend == "remote"
        and status.qdrant_status == "unreachable"
    )


def _remote_backend_error_message(qdrant_url: str) -> str:
    return "\n".join(
        [
            "Unable to start the QUIC MCP server: remote Qdrant backend is unreachable.",
            f"configured COQUIC_QDRANT_URL: {qdrant_url}",
            "Start the shared server workflow and retry:",
            f"  {_QDRANT_DEV_START_COMMAND}",
        ]
    )


def _is_local_qdrant_lock_error(error: RuntimeError) -> bool:
    return _LOCAL_QDRANT_LOCK_MARKER in str(error)


def _local_qdrant_lock_error_message(error: RuntimeError) -> str:
    return "\n".join(
        [
            "Unable to start the QUIC MCP server: local Qdrant state is locked.",
            f"details: {error}",
            "Use the shared server workflow instead:",
            f"  {_QDRANT_DEV_START_COMMAND}",
        ]
    )


def create_mcp_server(
    service: QueryService | None = None,
    *,
    paths: ProjectPaths | None = None,
    collection_name: str = "quic_sections",
) -> FastMCP:
    query_service = service
    if query_service is None:
        resolved_paths = paths or ProjectPaths.default()
        status = get_index_status(resolved_paths, collection_name=collection_name)
        if not status.ready:
            qdrant_url = _configured_qdrant_url(resolved_paths)
            if qdrant_url and _is_remote_qdrant_only_blocker(status):
                raise IndexNotBuiltError(_remote_backend_error_message(qdrant_url))
            raise IndexNotBuiltError(status.failure_message(resolved_paths))
        query_service = QueryService(
            paths=resolved_paths,
            collection_name=collection_name,
        )
    app = FastMCP(
        name="coquic-rag",
        instructions="Local QUIC RFC and Internet-Draft knowledge base for Codex queries.",
    )

    @app.tool(structured_output=True)
    def search_sections(
        query: str,
        doc_id: str | None = None,
        category: str | None = None,
        top_k: int = 5,
    ) -> dict[str, object]:
        return {
            "results": query_service.search_sections(
                query,
                doc_id=doc_id,
                category=category,
                top_k=top_k,
            )
        }

    @app.tool(structured_output=True)
    def get_section(doc_id: str, section_id: str) -> dict[str, object]:
        return query_service.get_section(doc_id, section_id)

    @app.tool(structured_output=True)
    def trace_term(term: str, doc_id: str | None = None) -> dict[str, object]:
        return query_service.trace_term(term, doc_id=doc_id)

    @app.tool(structured_output=True)
    def related_sections(
        doc_id: str,
        section_id: str,
        edge_types: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "sections": query_service.related_sections(
                doc_id,
                section_id,
                edge_types=(
                    tuple(edge_types)
                    if edge_types is not None
                    else ("cites", "mentions", "defines")
                ),
            )
        }

    @app.tool(structured_output=True)
    def lookup_term(term_type: str, name: str) -> dict[str, object]:
        return query_service.lookup_term(term_type, name)

    @app.resource(
        "quic://doc/{doc_id}/section/{section_id}",
        name="document_section",
        description="Canonical QUIC RFC or Internet-Draft section text",
        mime_type="text/plain",
    )
    def document_section(doc_id: str, section_id: str) -> str:
        return query_service.render_section_resource(doc_id, section_id)

    return app


def main(
    *,
    paths: ProjectPaths | None = None,
    collection_name: str = "quic_sections",
) -> int:
    resolved_paths = paths or ProjectPaths.default()
    try:
        create_mcp_server(paths=resolved_paths, collection_name=collection_name).run()
    except IndexNotBuiltError as error:
        print(error, file=sys.stderr)
        return 1
    except RuntimeError as error:
        if _is_local_qdrant_lock_error(error):
            print(_local_qdrant_lock_error_message(error), file=sys.stderr)
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
