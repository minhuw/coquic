from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from coquic_rag.query.service import QueryService


def create_mcp_server(service: QueryService | None = None) -> FastMCP:
    query_service = service or QueryService()
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


def main() -> None:
    create_mcp_server().run()


if __name__ == "__main__":
    main()
