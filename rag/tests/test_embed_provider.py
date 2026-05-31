from __future__ import annotations

import httpx
import pytest

from coquic_rag.embed.provider import OpenRouterEmbedder, RemoteEmbeddingError


def test_openrouter_embedder_posts_embeddings_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]},
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    embedder = OpenRouterEmbedder(
        api_key="test-key",
        model_name="nvidia/llama-nemotron-embed-vl-1b-v2:free",
        client=client,
    )

    embeddings = embedder.embed(["ack delay", "stream flow control"])

    assert embeddings == [[1.0, 0.0], [0.0, 1.0]]
    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer test-key"
    assert requests[0].url == "https://openrouter.ai/api/v1/embeddings"
    assert requests[0].read()
    assert b"nvidia/llama-nemotron-embed-vl-1b-v2:free" in requests[0].content


def test_openrouter_embedder_requires_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    embedder = OpenRouterEmbedder(api_key=None)

    with pytest.raises(RemoteEmbeddingError, match="OPENROUTER_API_KEY"):
        embedder.embed(["ack"])


def test_openrouter_embedder_rejects_incomplete_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"index": 0, "embedding": [1.0]}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    embedder = OpenRouterEmbedder(api_key="test-key", client=client)

    with pytest.raises(RemoteEmbeddingError, match="incomplete"):
        embedder.embed(["one", "two"])
