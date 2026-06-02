from __future__ import annotations

import json

import httpx

from coquic_rag.qa.deepseek_chat import (
    ChatStreamChunk,
    DeepSeekChatClient,
    normalize_answer_model,
    _direct_system_prompt,
    _system_prompt,
)


def test_deepseek_chat_client_uses_v4_model_and_tracks_response_model() -> None:
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
                "model": "deepseek-v4-pro",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    chat = DeepSeekChatClient(api_key="test-key", client=client)

    result = chat.answer(
        question="What's the difference between QUIC and TCP?",
        sections=[],
        max_tokens=650,
        user_id="session-hash",
    )

    payload = json.loads(requests[0].read())
    assert payload["model"] == "deepseek-v4-pro"
    assert payload["user_id"] == "session-hash"
    assert payload["thinking"] == {"type": "disabled"}
    assert result.answer.startswith("QUIC differs")
    assert result.model == "deepseek-v4-pro"
    assert result.usage.total_tokens == 15


def test_deepseek_chat_client_direct_answer_omits_retrieved_context() -> None:
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
    chat = DeepSeekChatClient(api_key="test-key", client=client)

    result = chat.answer_direct(
        question="What's the difference between QUIC and TCP?",
        max_tokens=650,
        model="deepseek-v4-pro",
    )

    payload = json.loads(requests[0].read())
    assert payload["model"] == "deepseek-v4-pro"
    assert "retrieved context" not in payload["messages"][1]["content"].lower()
    assert "Do not use or refer to retrieved context" in payload["messages"][0]["content"]
    assert result.answer.startswith("QUIC runs")


def test_deepseek_chat_client_streams_answer_chunks() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            content=(
                'data: {"model":"deepseek-v4-pro","choices":[{"delta":{"content":"QUIC "}}]}\n\n'
                'data: {"choices":[{"delta":{"content":"streams."}}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}\n\n'
                "data: [DONE]\n\n"
            ),
            headers={"Content-Type": "text/event-stream"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    chat = DeepSeekChatClient(api_key="test-key", client=client)

    chunks = list(
        chat.stream_answer(
            question="How does QUIC stream data?",
            sections=[],
            max_tokens=100,
        )
    )

    payload = json.loads(requests[0].read())
    assert payload["stream"] is True
    assert "".join(chunk.delta for chunk in chunks) == "QUIC streams."
    assert chunks[-1] == ChatStreamChunk(
        usage=chunks[-1].usage,
        model="deepseek-v4-pro",
        done=True,
    )
    assert chunks[-1].usage is not None
    assert chunks[-1].usage.total_tokens == 6


def test_system_prompt_uses_retrieved_context_as_supporting_evidence() -> None:
    prompt = _system_prompt()

    assert "supporting evidence" in prompt
    assert "general networking and protocol knowledge" in prompt
    assert "Do not cite a section for claims it does not support" in prompt
    assert "same natural language as the user's question" in prompt
    assert "using only the supplied" not in prompt


def test_direct_prompt_matches_user_question_language() -> None:
    assert "same natural language as the user's question" in _direct_system_prompt()


def test_normalize_answer_model_rejects_non_allowlisted_models() -> None:
    assert normalize_answer_model(None) == "deepseek-v4-pro"
    assert normalize_answer_model(" deepseek-v4-pro ") == "deepseek-v4-pro"

    for model in ("openrouter/free", "deepseek-v4-flash"):
        try:
            normalize_answer_model(model)
        except ValueError as error:
            assert "unsupported DeepSeek answer model" in str(error)
        else:
            raise AssertionError("expected unsupported model to be rejected")
