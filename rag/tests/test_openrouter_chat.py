from __future__ import annotations

import json

import httpx

from coquic_rag.qa.openrouter_chat import OpenRouterChatClient, normalize_answer_model, _system_prompt


def test_openrouter_chat_client_uses_free_model_and_tracks_response_model() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "QUIC differs from TCP by integrating TLS and running over UDP.",
                        }
                    }
                ],
                "model": "openai/gpt-oss-120b:free",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    chat = OpenRouterChatClient(api_key="test-key", client=client)

    result = chat.answer(
        question="What's the difference between QUIC and TCP?",
        sections=[],
        max_tokens=650,
    )

    payload = json.loads(requests[0].read())
    assert payload["model"] == "openai/gpt-oss-120b:free"
    assert "thinking" not in payload
    assert result.answer.startswith("QUIC differs")
    assert result.model == "openai/gpt-oss-120b:free"
    assert result.usage.total_tokens == 15


def test_openrouter_chat_client_direct_answer_omits_retrieved_context() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "QUIC runs over UDP and integrates TLS.",
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    chat = OpenRouterChatClient(api_key="test-key", client=client)

    result = chat.answer_direct(
        question="What's the difference between QUIC and TCP?",
        max_tokens=650,
        model="moonshotai/kimi-k2.6:free",
    )

    payload = json.loads(requests[0].read())
    assert payload["model"] == "moonshotai/kimi-k2.6:free"
    assert "retrieved context" not in payload["messages"][1]["content"].lower()
    assert "Do not use or refer to retrieved context" in payload["messages"][0]["content"]
    assert result.answer.startswith("QUIC runs")


def test_system_prompt_uses_retrieved_context_as_supporting_evidence() -> None:
    prompt = _system_prompt()

    assert "supporting evidence" in prompt
    assert "general networking and protocol knowledge" in prompt
    assert "Do not cite a section for claims it does not support" in prompt
    assert "using only the supplied" not in prompt


def test_normalize_answer_model_rejects_non_allowlisted_models() -> None:
    assert normalize_answer_model(None) == "openai/gpt-oss-120b:free"
    assert normalize_answer_model(" qwen/qwen3-coder:free ") == "qwen/qwen3-coder:free"

    try:
        normalize_answer_model("openrouter/free")
    except ValueError as error:
        assert "unsupported free answer model" in str(error)
    else:
        raise AssertionError("expected unsupported model to be rejected")
