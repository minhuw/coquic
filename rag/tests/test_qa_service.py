from __future__ import annotations

from coquic_rag.qa.openrouter_chat import ChatResult, ChatUsage, OpenRouterChatError
from coquic_rag.qa.filters import RelevanceClassifierError, RelevanceDecision
from coquic_rag.qa.service import QaConfig, QaService


class FakeQueryService:
    def __init__(self, results: list[dict[str, object]]) -> None:
        self.results = results
        self.calls: list[str] = []

    def search_sections(self, query: str, *, top_k: int) -> list[dict[str, object]]:
        self.calls.append(query)
        return self.results[:top_k]


class FakeLlm:
    def __init__(self, *, error: bool = False) -> None:
        self.error = error
        self.calls: list[dict[str, object]] = []
        self.direct_calls: list[dict[str, object]] = []

    def answer(self, **kwargs) -> ChatResult:
        self.calls.append(kwargs)
        if self.error:
            raise OpenRouterChatError("empty response")
        return ChatResult(
            answer="ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)",
            usage=ChatUsage(prompt_tokens=100, completion_tokens=20, total_tokens=120),
            model="nvidia/nemotron-3-super-120b-a12b:free",
        )

    def answer_direct(self, **kwargs) -> ChatResult:
        self.direct_calls.append(kwargs)
        if self.error:
            raise OpenRouterChatError("empty response")
        return ChatResult(
            answer="Direct OpenRouter answer without retrieved RFC context.",
            usage=ChatUsage(prompt_tokens=40, completion_tokens=10, total_tokens=50),
            model="nvidia/nemotron-3-super-120b-a12b:free",
        )


class FakeRelevanceClassifier:
    def __init__(self, decision: RelevanceDecision | None = None, *, error: bool = False) -> None:
        self.decision = decision or RelevanceDecision(True, "classifier_allow")
        self.error = error
        self.calls: list[str] = []

    def classify(self, question: str) -> RelevanceDecision:
        self.calls.append(question)
        if self.error:
            raise RelevanceClassifierError("classifier failed")
        return self.decision


def test_qa_service_rejects_classifier_rejected_question_before_retrieval() -> None:
    query_service = FakeQueryService([])
    llm = FakeLlm()
    relevance_classifier = FakeRelevanceClassifier(
        RelevanceDecision(False, "classifier_reject")
    )
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=relevance_classifier,
    )

    response = service.answer("What is the weather today?")

    assert response.accepted is False
    assert response.reason == "out_of_scope"
    assert relevance_classifier.calls == ["What is the weather today?"]
    assert query_service.calls == []
    assert llm.direct_calls == []
    assert llm.calls == []


def test_qa_service_rejects_keyword_bait_question_before_retrieval() -> None:
    query_service = FakeQueryService([])
    llm = FakeLlm()
    relevance_classifier = FakeRelevanceClassifier(
        RelevanceDecision(False, "classifier_reject")
    )
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=relevance_classifier,
    )

    response = service.answer("QUIC ACK frame: can you recommend a pasta recipe?")

    assert response.accepted is False
    assert response.reason == "out_of_scope"
    assert relevance_classifier.calls == ["QUIC ACK frame: can you recommend a pasta recipe?"]
    assert query_service.calls == []
    assert llm.direct_calls == []
    assert llm.calls == []


def test_qa_service_fails_closed_when_classifier_errors() -> None:
    query_service = FakeQueryService([])
    llm = FakeLlm()
    relevance_classifier = FakeRelevanceClassifier(error=True)
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=relevance_classifier,
    )

    response = service.answer("How does QUIC ACK delay work?")

    assert response.accepted is False
    assert response.reason == "unavailable"
    assert "QA service is temporarily unavailable" in response.answer
    assert relevance_classifier.calls == ["How does QUIC ACK delay work?"]
    assert query_service.calls == ["How does QUIC ACK delay work?"]
    assert llm.direct_calls
    assert llm.calls == []


def test_qa_service_answers_when_classifier_errors_but_retrieval_is_confident() -> None:
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 1",
                "doc_id": "rfc9000",
                "rfc_number": 9000,
                "section_id": "1",
                "title": "Overview",
                "text": "QUIC packets are carried in UDP datagrams.",
                "score": 0.89,
            }
        ]
    )
    llm = FakeLlm()
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=FakeRelevanceClassifier(error=True),
    )

    response = service.answer("What's the difference between QUIC and TCP?")

    assert response.accepted is True
    assert response.reason == "answered"
    assert response.citations[0]["citation"] == "RFC 9000 Section 1"
    assert query_service.calls == ["What's the difference between QUIC and TCP?"]
    assert llm.calls


def test_qa_service_rejects_low_retrieval_confidence_before_llm() -> None:
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 1",
                "doc_id": "rfc9000",
                "section_id": "1",
                "title": "Introduction",
                "text": "QUIC intro",
                "score": 0.05,
            }
        ]
    )
    llm = FakeLlm()
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        config=QaConfig(min_retrieval_score=0.5),
        relevance_classifier=FakeRelevanceClassifier(),
    )

    response = service.answer(
        "How does QUIC ACK delay work?",
        model="nvidia/nemotron-3-super-120b-a12b:free",
    )

    assert response.accepted is True
    assert response.reason == "answered_direct_only"
    assert response.direct_answer == "Direct OpenRouter answer without retrieved RFC context."
    assert response.direct_model == "nvidia/nemotron-3-super-120b-a12b:free"
    assert response.rag_answer == "I could not find enough relevant QUIC specification context to answer that."
    assert query_service.calls
    assert llm.direct_calls
    assert llm.direct_calls[0]["model"] == "nvidia/nemotron-3-super-120b-a12b:free"
    assert llm.calls == []


def test_qa_service_calls_llm_for_relevant_confident_question() -> None:
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 19.3",
                "doc_id": "rfc9000",
                "rfc_number": 9000,
                "section_id": "19.3",
                "title": "ACK Frames",
                "text": "ACK frames contain acknowledgment ranges and ACK delay.",
                "score": 0.89,
            }
        ]
    )
    llm = FakeLlm()
    relevance_classifier = FakeRelevanceClassifier()
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=relevance_classifier,
    )

    response = service.answer("How does QUIC ACK delay work?", user_id="abc", model="qwen/qwen3-coder:free")

    assert response.accepted is True
    assert response.reason == "answered"
    assert response.direct_answer == "Direct OpenRouter answer without retrieved RFC context."
    assert response.direct_model == "nvidia/nemotron-3-super-120b-a12b:free"
    assert response.rag_answer == "ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)"
    assert response.rag_model == "nvidia/nemotron-3-super-120b-a12b:free"
    assert response.citations[0]["citation"] == "RFC 9000 Section 19.3"
    assert response.citations[0]["text"] == "ACK frames contain acknowledgment ranges and ACK delay."
    assert response.citations[0]["url"] == "https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3"
    assert response.usage is not None
    assert response.usage.total_tokens == 170
    assert relevance_classifier.calls == ["How does QUIC ACK delay work?"]
    assert llm.direct_calls[0]["user_id"] == "abc"
    assert llm.direct_calls[0]["model"] == "qwen/qwen3-coder:free"
    assert llm.calls[0]["user_id"] == "abc"
    assert llm.calls[0]["model"] == "qwen/qwen3-coder:free"


def test_qa_service_trims_llm_context_but_returns_full_citations() -> None:
    full_text = "QUIC connection IDs are used to route packets after migration. " * 8
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 5.1",
                "doc_id": "rfc9000",
                "rfc_number": 9000,
                "section_id": "5.1",
                "title": "Connection ID",
                "text": full_text,
                "score": 0.89,
            }
        ]
    )
    llm = FakeLlm()
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=FakeRelevanceClassifier(),
        config=QaConfig(max_context_chars=24),
    )

    response = service.answer("How does QUIC use connection IDs?")

    assert response.accepted is True
    assert llm.calls[0]["sections"][0]["text"] == "QUIC connection IDs are"
    assert response.citations[0]["text"] == full_text
    assert response.retrieved_sections[0]["excerpt"] == full_text[:700]


def test_qa_service_returns_generation_error_when_llm_fails() -> None:
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 7.3",
                "doc_id": "rfc9000",
                "section_id": "7.3",
                "title": "Authenticating Connection IDs",
                "text": "QUIC provides features that overlap with TCP plus TLS.",
                "score": 0.89,
            }
        ]
    )
    llm = FakeLlm(error=True)
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=FakeRelevanceClassifier(),
    )

    response = service.answer("What's the difference between QUIC and TCP?")

    assert response.accepted is False
    assert response.reason == "generation_error"
    assert "temporarily unavailable" in response.answer
    assert "temporarily unavailable" in str(response.direct_answer)
    assert "temporarily unavailable" in str(response.rag_answer)
    assert response.citations[0]["citation"] == "RFC 9000 Section 7.3"
