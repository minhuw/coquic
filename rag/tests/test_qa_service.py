from __future__ import annotations

from coquic_rag.qa.deepseek_chat import ChatResult, ChatStreamChunk, ChatUsage, DeepSeekChatError
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
            raise DeepSeekChatError("empty response")
        return ChatResult(
            answer="ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)",
            usage=ChatUsage(prompt_tokens=100, completion_tokens=20, total_tokens=120),
            model="deepseek-v4-pro",
        )

    def answer_direct(self, **kwargs) -> ChatResult:
        self.direct_calls.append(kwargs)
        if self.error:
            raise DeepSeekChatError("empty response")
        return ChatResult(
            answer="Direct DeepSeek answer without retrieved RFC context.",
            usage=ChatUsage(prompt_tokens=40, completion_tokens=10, total_tokens=50),
            model="deepseek-v4-pro",
        )

    def stream_answer(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise DeepSeekChatError("empty response")
        yield ChatStreamChunk(delta="ACK delay ")
        yield ChatStreamChunk(delta="is encoded in ACK frames. (RFC 9000 Section 19.3)")
        yield ChatStreamChunk(
            usage=ChatUsage(prompt_tokens=100, completion_tokens=20, total_tokens=120),
            model="deepseek-v4-pro",
            done=True,
        )

    def stream_answer_direct(self, **kwargs):
        self.direct_calls.append(kwargs)
        if self.error:
            raise DeepSeekChatError("empty response")
        yield ChatStreamChunk(delta="Direct DeepSeek ")
        yield ChatStreamChunk(delta="answer without retrieved RFC context.")
        yield ChatStreamChunk(
            usage=ChatUsage(prompt_tokens=40, completion_tokens=10, total_tokens=50),
            model="deepseek-v4-pro",
            done=True,
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
        model="deepseek-v4-pro",
    )

    assert response.accepted is True
    assert response.reason == "answered_direct_only"
    assert response.direct_answer == "Direct DeepSeek answer without retrieved RFC context."
    assert response.direct_model == "deepseek-v4-pro"
    assert response.rag_answer == "I could not find enough relevant QUIC specification context to answer that."
    assert query_service.calls
    assert llm.direct_calls
    assert llm.direct_calls[0]["model"] == "deepseek-v4-pro"
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

    response = service.answer("How does QUIC ACK delay work?", user_id="abc", model="deepseek-v4-pro")

    assert response.accepted is True
    assert response.reason == "answered"
    assert response.direct_answer == "Direct DeepSeek answer without retrieved RFC context."
    assert response.direct_model == "deepseek-v4-pro"
    assert response.rag_answer == "ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)"
    assert response.rag_model == "deepseek-v4-pro"
    assert response.rag_confidence == 0.89
    assert response.citations[0]["citation"] == "RFC 9000 Section 19.3"
    assert response.citations[0]["text"] == "ACK frames contain acknowledgment ranges and ACK delay."
    assert response.citations[0]["url"] == "https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3"
    assert response.usage is not None
    assert response.usage.total_tokens == 170
    assert relevance_classifier.calls == ["How does QUIC ACK delay work?"]
    assert llm.direct_calls[0]["user_id"] == "abc"
    assert llm.direct_calls[0]["model"] == "deepseek-v4-pro"
    assert llm.calls[0]["user_id"] == "abc"
    assert llm.calls[0]["model"] == "deepseek-v4-pro"


def test_qa_service_streams_rag_answer_events() -> None:
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
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=FakeRelevanceClassifier(),
    )

    events = list(service.answer_stream("How does QUIC ACK delay work?", model="deepseek-v4-pro"))

    assert events[0].event == "metadata"
    assert events[-1].event == "done"
    assert events[0].payload["rag_confidence"] == 0.89
    direct_chunks = [event.payload["delta"] for event in events if event.event == "direct"]
    rag_chunks = [event.payload["delta"] for event in events if event.event == "rag"]
    assert "".join(str(chunk) for chunk in direct_chunks) == "Direct DeepSeek answer without retrieved RFC context."
    assert "".join(str(chunk) for chunk in rag_chunks) == "ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)"
    assert events[-1].payload["rag_answer"] == "ACK delay is encoded in ACK frames. (RFC 9000 Section 19.3)"
    assert events[-1].payload["direct_answer"] == "Direct DeepSeek answer without retrieved RFC context."
    assert events[-1].payload["rag_usage"] == {
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "total_tokens": 120,
    }


def test_qa_service_filters_low_score_sections_before_rag_context() -> None:
    query_service = FakeQueryService(
        [
            {
                "citation": "RFC 9000 Section 19.3",
                "doc_id": "rfc9000",
                "rfc_number": 9000,
                "section_id": "19.3",
                "title": "ACK Frames",
                "text": "ACK frames contain acknowledgment ranges and ACK delay.",
                "score": 0.91,
            },
            {
                "citation": "RFC 9000 Section 99",
                "doc_id": "rfc9000",
                "rfc_number": 9000,
                "section_id": "99",
                "title": "Unrelated",
                "text": "This low-score section should not be sent to the LLM.",
                "score": 0.12,
            },
        ]
    )
    llm = FakeLlm()
    service = QaService(
        query_service=query_service,
        llm_client=llm,
        relevance_classifier=FakeRelevanceClassifier(),
        config=QaConfig(min_retrieval_score=0.5),
    )

    response = service.answer("How does QUIC ACK delay work?")

    assert response.accepted is True
    assert len(llm.calls[0]["sections"]) == 1
    assert llm.calls[0]["sections"][0]["section_id"] == "19.3"
    assert [citation["section_id"] for citation in response.citations] == ["19.3"]
    assert response.rag_confidence == 0.91


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
