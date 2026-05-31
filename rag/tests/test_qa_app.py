from __future__ import annotations

from fastapi.testclient import TestClient

from coquic_rag.qa.app import create_app
from coquic_rag.qa.filters import RelevanceDecision
from coquic_rag.qa.openrouter_chat import FREE_ANSWER_MODELS
from coquic_rag.qa.openrouter_chat import ChatUsage
from coquic_rag.qa.service import QaResponse


class FakeQaService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def answer(
        self,
        question: str,
        *,
        user_id: str | None = None,
        model: str | None = None,
    ) -> QaResponse:
        self.calls.append({"question": question, "user_id": user_id, "model": model})
        return QaResponse(
            answer=f"answer for {question}",
            accepted=True,
            reason="answered",
            citations=[
                {
                    "citation": "RFC 9000 Section 1",
                    "doc_id": "rfc9000",
                    "section_id": "1",
                    "title": "Introduction",
                    "score": 0.9,
                    "text": "Full RFC section text.",
                    "url": "https://www.rfc-editor.org/rfc/rfc9000.html#section-1",
                }
            ],
            retrieved_sections=[],
            usage=ChatUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            direct_answer="direct answer",
            direct_usage=ChatUsage(prompt_tokens=4, completion_tokens=2, total_tokens=6),
            direct_model="moonshotai/kimi-k2.6:free",
            rag_answer=f"answer for {question}",
            rag_usage=ChatUsage(prompt_tokens=6, completion_tokens=3, total_tokens=9),
            rag_model="qwen/qwen3-coder:free",
        )


class FakeQuestionGenerator:
    def __init__(self, question: str = "How does QUIC packet number encoding work?") -> None:
        self.question = question
        self.calls = 0

    def generate(self) -> str:
        self.calls += 1
        return self.question


class FakeRelevanceClassifier:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[str] = []

    def classify(self, question: str) -> RelevanceDecision:
        self.calls.append(question)
        return RelevanceDecision(self.accepted, "classifier_allow" if self.accepted else "classifier_reject")


def test_qa_endpoint_returns_answer_payload(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.qa_service.cache_clear()
    qa_app.rate_limiter.cache_clear()
    fake_service = FakeQaService()
    monkeypatch.setattr(qa_app, "qa_service", lambda: fake_service)
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/qa",
        json={
            "question": "How does QUIC ACK delay work?",
            "model": "moonshotai/kimi-k2.6:free",
        },
        headers={"X-Session-Id": "test-session"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["reason"] == "answered"
    assert payload["usage"]["total_tokens"] == 15
    assert payload["citations"][0]["text"] == "Full RFC section text."
    assert payload["citations"][0]["url"] == "https://www.rfc-editor.org/rfc/rfc9000.html#section-1"
    assert payload["direct_answer"] == "direct answer"
    assert payload["direct_usage"]["total_tokens"] == 6
    assert payload["direct_model"] == "moonshotai/kimi-k2.6:free"
    assert payload["rag_answer"] == "answer for How does QUIC ACK delay work?"
    assert payload["rag_usage"]["total_tokens"] == 9
    assert payload["rag_model"] == "qwen/qwen3-coder:free"
    assert fake_service.calls[0]["model"] == "moonshotai/kimi-k2.6:free"


def test_qa_endpoint_enforces_rate_limit(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.qa_service.cache_clear()
    qa_app.rate_limiter.cache_clear()
    monkeypatch.setenv("COQUIC_QA_RATE_LIMIT", "1")
    monkeypatch.setenv("COQUIC_QA_RATE_WINDOW_SECONDS", "60")
    monkeypatch.setattr(qa_app, "qa_service", lambda: FakeQaService())
    app = create_app()
    client = TestClient(app)

    first = client.post(
        "/api/qa",
        json={"question": "How does QUIC ACK delay work?"},
        headers={"X-Session-Id": "same-session"},
    )
    second = client.post(
        "/api/qa",
        json={"question": "How does QUIC ACK delay work?"},
        headers={"X-Session-Id": "same-session"},
    )

    assert first.status_code == 200
    assert second.status_code == 429
    assert "Retry-After" in second.headers


def test_qa_endpoint_rejects_non_free_answer_model(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.qa_service.cache_clear()
    qa_app.rate_limiter.cache_clear()
    monkeypatch.setattr(qa_app, "qa_service", lambda: FakeQaService())
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/qa",
        json={
            "question": "How does QUIC ACK delay work?",
            "model": "anthropic/claude-sonnet-4",
        },
        headers={"X-Session-Id": "bad-model-session"},
    )

    assert response.status_code == 400
    assert "unsupported free answer model" in response.json()["detail"]


def test_health_reports_hardcoded_models_when_old_override_env_is_set(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.paths.cache_clear()
    monkeypatch.setenv("OPENROUTER_EMBEDDING_MODEL", "override-embedding")
    monkeypatch.setenv("COQUIC_QDRANT_COLLECTION", "override_collection")
    monkeypatch.setattr(
        qa_app,
        "get_index_status",
        lambda _paths, *, collection_name: type(
            "Status",
            (),
            {
                "ready": True,
                "source_ok": True,
                "artifacts_ok": True,
                "qdrant_backend": "remote",
                "qdrant_status": "ok",
                "section_count": 7,
                "indexed_count": 7,
                "collection_name": collection_name,
            },
        )(),
    )
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["embedding_model"] == "nvidia/llama-nemotron-embed-vl-1b-v2:free"
    assert "relevance_filter_model" not in payload
    assert payload["llm_model"] == "openai/gpt-oss-120b:free"
    assert payload["answer_models"][0] == {
        "id": "openai/gpt-oss-120b:free",
        "label": "OpenAI: gpt-oss-120b (free)",
    }


def test_random_question_endpoint_returns_validated_question(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.question_rate_limiter.cache_clear()
    generator = FakeQuestionGenerator()
    classifier = FakeRelevanceClassifier()
    monkeypatch.setattr(qa_app, "question_generator", lambda: generator)
    monkeypatch.setattr(qa_app, "relevance_classifier", lambda: classifier)
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/questions/random",
        headers={"X-Session-Id": "random-session"},
    )

    assert response.status_code == 200
    assert response.json() == {"question": "How does QUIC packet number encoding work?"}
    assert generator.calls == 1
    assert classifier.calls == []


def test_default_random_question_generator_uses_free_model_pool(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.question_generator.cache_clear()
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")

    generator = qa_app.question_generator()

    assert set(generator.models) == {model_id for model_id, _label in FREE_ANSWER_MODELS}
    assert generator.max_generation_attempts == len(FREE_ANSWER_MODELS)


def test_random_question_endpoint_rejects_invalid_generated_questions(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.question_rate_limiter.cache_clear()
    monkeypatch.setattr(qa_app, "question_generator", lambda: FakeQuestionGenerator("What is pasta?"))
    classifier = FakeRelevanceClassifier(False)
    monkeypatch.setattr(qa_app, "relevance_classifier", lambda: classifier)
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/questions/random",
        headers={"X-Session-Id": "invalid-random-session"},
    )

    assert response.status_code == 503
    assert classifier.calls == []


def test_random_question_endpoint_enforces_rate_limit(monkeypatch) -> None:
    import coquic_rag.qa.app as qa_app

    qa_app.question_rate_limiter.cache_clear()
    monkeypatch.setenv("COQUIC_RANDOM_QUESTION_RATE_LIMIT", "1")
    monkeypatch.setenv("COQUIC_RANDOM_QUESTION_RATE_WINDOW_SECONDS", "60")
    monkeypatch.setattr(qa_app, "question_generator", lambda: FakeQuestionGenerator())
    monkeypatch.setattr(qa_app, "relevance_classifier", lambda: FakeRelevanceClassifier())
    app = create_app()
    client = TestClient(app)

    first = client.post(
        "/api/questions/random",
        headers={"X-Session-Id": "same-random-session"},
    )
    second = client.post(
        "/api/questions/random",
        headers={"X-Session-Id": "same-random-session"},
    )

    assert first.status_code == 200
    assert second.status_code == 429
