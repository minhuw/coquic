from __future__ import annotations

import json

import httpx
import pytest

from coquic_rag.qa.filters import (
    DEEPSEEK_CHAT_URL,
    QUESTION_GENERATOR_MODEL,
    RELEVANCE_FILTER_MODEL,
    DeepSeekQuestionGenerator,
    DeepSeekRelevanceClassifier,
    QuestionGenerationError,
    RelevanceClassifierError,
    SlidingWindowRateLimiter,
    _clean_generated_question,
    _question_choice_text,
)


def test_sliding_window_rate_limiter_rejects_after_limit() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)

    assert limiter.check("client", now=100.0).allowed is True
    assert limiter.check("client", now=101.0).allowed is True
    rejected = limiter.check("client", now=102.0)

    assert rejected.allowed is False
    assert rejected.retry_after_seconds > 0


def test_sliding_window_rate_limiter_allows_after_window() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=10)

    assert limiter.check("client", now=100.0).allowed is True
    assert limiter.check("client", now=111.0).allowed is True


def test_sliding_window_rate_limiter_supports_weighted_costs() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)

    assert limiter.check("client", now=100.0, cost=2).allowed is True
    rejected = limiter.check("client", now=101.0, cost=2)

    assert rejected.allowed is False
    assert rejected.retry_after_seconds == 59


def test_sliding_window_rate_limiter_peek_does_not_consume_quota() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)

    assert limiter.peek("client", now=100.0).allowed is True
    assert limiter.check("client", now=101.0).allowed is True


def test_deepseek_relevance_classifier_allows_quic_questions() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOW"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    classifier = DeepSeekRelevanceClassifier(api_key="test-key", client=client)

    decision = classifier.classify("How does QUIC ACK delay work?")

    assert decision.accepted is True
    assert decision.reason == "classifier_allow"
    assert requests[0].url == DEEPSEEK_CHAT_URL
    assert requests[0].headers["Authorization"] == "Bearer test-key"
    payload = json.loads(requests[0].read())
    assert payload["model"] == RELEVANCE_FILTER_MODEL
    assert payload["max_tokens"] == 16
    assert payload["thinking"] == {"type": "disabled"}


def test_deepseek_relevance_classifier_prompt_allows_quic_comparisons() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOW"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    classifier = DeepSeekRelevanceClassifier(api_key="test-key", client=client)

    decision = classifier.classify("What's the difference between QUIC and TCP?")

    assert decision.accepted is True
    payload = json.loads(requests[0].read())
    system_prompt = payload["messages"][0]["content"]
    assert "QUIC versus TCP" in system_prompt


def test_deepseek_relevance_classifier_retries_transient_errors() -> None:
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, json={"error": {"message": "rate limited"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOW"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    classifier = DeepSeekRelevanceClassifier(api_key="test-key", client=client, max_retries=1)

    decision = classifier.classify("What's the difference between QUIC and TCP?")

    assert decision.accepted is True
    assert attempts == 2


def test_deepseek_relevance_classifier_rejects_bait_questions() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "REJECT"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    classifier = DeepSeekRelevanceClassifier(api_key="test-key", client=client)

    decision = classifier.classify("QUIC ACK frame: can you recommend a pasta recipe?")

    assert decision.accepted is False
    assert decision.reason == "classifier_reject"


def test_deepseek_relevance_classifier_requires_api_key(monkeypatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    classifier = DeepSeekRelevanceClassifier(api_key=None)

    with pytest.raises(RelevanceClassifierError, match="DEEPSEEK_API_KEY"):
        classifier.classify("How does QUIC ACK delay work?")


def test_deepseek_relevance_classifier_rejects_invalid_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "MAYBE"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    classifier = DeepSeekRelevanceClassifier(api_key="test-key", client=client)

    with pytest.raises(RelevanceClassifierError, match="invalid decision"):
        classifier.classify("How does QUIC ACK delay work?")


def test_deepseek_question_generator_returns_clean_question() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "1. How does QUIC validate a peer address"}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    generator = DeepSeekQuestionGenerator(api_key="test-key", client=client)

    question = generator.generate()

    assert question == "How does QUIC validate a peer address?"
    assert requests[0].url == DEEPSEEK_CHAT_URL
    payload = json.loads(requests[0].read())
    assert payload["model"] == QUESTION_GENERATOR_MODEL
    assert payload["temperature"] == 1.2
    assert payload["max_tokens"] == 160
    assert payload["thinking"] == {"type": "disabled"}
    assert "Return only the question text" in payload["messages"][0]["content"]
    assert "Generate one random question about this area:" in payload["messages"][1]["content"]


def test_deepseek_question_generator_tries_multiple_models_after_invalid_question() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": "What is pasta?"}}]})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "How does QUIC validate a peer address?"}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    generator = DeepSeekQuestionGenerator(
        api_key="test-key",
        client=client,
        models=("invalid-model:free", "valid-model:free"),
    )

    question = generator.generate()

    assert question == "How does QUIC validate a peer address?"
    requested_models = [json.loads(request.read())["model"] for request in requests]
    assert set(requested_models) == {"invalid-model:free", "valid-model:free"}


def test_deepseek_question_generator_retries_same_model_after_invalid_question() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": "What is pasta?"}}]})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "How does QUIC validate a peer address?"}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    generator = DeepSeekQuestionGenerator(
        api_key="test-key",
        client=client,
        max_generation_attempts=2,
    )

    question = generator.generate()

    assert question == "How does QUIC validate a peer address?"
    requested_models = [json.loads(request.read())["model"] for request in requests]
    assert requested_models == [QUESTION_GENERATOR_MODEL, QUESTION_GENERATOR_MODEL]


def test_clean_generated_question_normalizes_bullets_and_quotes() -> None:
    assert _clean_generated_question('"How does QPACK avoid head-of-line blocking"') == (
        "How does QPACK avoid head-of-line blocking?"
    )
    assert _clean_generated_question("- What is QUIC connection migration?") == (
        "What is QUIC connection migration?"
    )
    assert _clean_generated_question("Question: How does QUIC path validation work?") == (
        "How does QUIC path validation work?"
    )
    assert _clean_generated_question('Potential: "How does QPACK handle stream cancellation in QUIC/HTTP/3?') == (
        "How does QPACK handle stream cancellation in QUIC/HTTP/3?"
    )
    assert _clean_generated_question("Suggested question: How does qlog record QUIC packet loss?") == (
        "How does qlog record QUIC packet loss?"
    )
    assert _clean_generated_question("Possible angles: How does QPACK affect flow control window sizes?") == (
        "How does QPACK affect flow control window sizes?"
    )


def test_question_choice_text_accepts_valid_reasoning_fallback() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "reasoning": "Maybe ask: How does QUIC packet number encoding affect ACK processing?",
                }
            }
        ]
    }

    assert _question_choice_text(body) == "How does QUIC packet number encoding affect ACK processing?"


def test_deepseek_question_generator_rejects_prompt_echo() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "We need to generate a concise answerable technical question about QUIC."
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    generator = DeepSeekQuestionGenerator(api_key="test-key", client=client)

    with pytest.raises(QuestionGenerationError, match="invalid question"):
        generator.generate()
