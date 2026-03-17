from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from coquic_rag.config import ProjectPaths
from coquic_rag.query.service import IndexNotBuiltError, QueryService, require_index_ready


def create_mcp_server(
    service: QueryService | None = None,
    *,
    paths: ProjectPaths | None = None,
    collection_name: str = "quic_sections",
) -> FastMCP:
    query_service = service
    if query_service is None:
        resolved_paths = paths or ProjectPaths.default()
        require_index_ready(resolved_paths, collection_name=collection_name)
        query_service = QueryService(
            paths=resolved_paths,
            collection_name=collection_name,
        )
    app = FastMCP(
        name="coquic-rag",
        instructions="Local QUIC RFC knowledge base for Codex queries.",
    )

    @app.tool(structured_output=True)
    def search_sections(
        query: str,
        rfc: int | None = None,
        category: str | None = None,
        top_k: int = 5,
    ) -> dict[str, object]:
        return {
            "results": query_service.search_sections(
                query,
                rfc=rfc,
                category=category,
                top_k=top_k,
            )
        }

    @app.tool(structured_output=True)
    def get_section(rfc: int, section_id: str) -> dict[str, object]:
        return query_service.get_section(rfc, section_id)

    @app.tool(structured_output=True)
    def trace_term(term: str, rfc: int | None = None) -> dict[str, object]:
        return query_service.trace_term(term, rfc=rfc)

    @app.tool(structured_output=True)
    def related_sections(
        rfc: int,
        section_id: str,
        edge_types: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "sections": query_service.related_sections(
                rfc,
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
        "quic://rfc/{rfc}/section/{section_id}",
        name="rfc_section",
        description="Canonical QUIC RFC section text",
        mime_type="text/plain",
    )
    def rfc_section(rfc: int, section_id: str) -> str:
        return query_service.render_section_resource(rfc, section_id)

    return app


def main(
    *,
    paths: ProjectPaths | None = None,
    collection_name: str = "quic_sections",
) -> int:
    try:
        create_mcp_server(paths=paths, collection_name=collection_name).run()
    except IndexNotBuiltError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
