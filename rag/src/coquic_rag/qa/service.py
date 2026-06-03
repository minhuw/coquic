from __future__ import annotations

import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from coquic_rag.query.service import QueryService
from coquic_rag.qa.deepseek_chat import (
    ChatResult,
    ChatStreamChunk,
    ChatUsage,
    DeepSeekChatClient,
    DeepSeekChatError,
)
from coquic_rag.qa.filters import (
    RelevanceClassifierError,
    RelevanceDecision,
)


DEFAULT_TOP_K = 10
DEFAULT_MAX_CONTEXT_CHARS = 6500
DEFAULT_MIN_RETRIEVAL_SCORE = 0.4
DEFAULT_MAX_OUTPUT_TOKENS = 650
FALLBACK_NOT_QUIC = (
    "This question does not look related to QUIC, HTTP/3, QPACK, qlog, "
    "or the related RFC material. Please ask a QUIC-related question."
)
FALLBACK_FILTER_UNAVAILABLE = (
    "The QA service is temporarily unavailable. Please retry in a moment."
)
FALLBACK_NOT_FOUND = "I could not find enough relevant QUIC specification context to answer that."
FALLBACK_GENERATION_UNAVAILABLE = (
    "The answer generator is temporarily unavailable. Please retry in a moment."
)
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class QaConfig:
    top_k: int = DEFAULT_TOP_K
    max_context_chars: int = DEFAULT_MAX_CONTEXT_CHARS
    min_retrieval_score: float = DEFAULT_MIN_RETRIEVAL_SCORE
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS


@dataclass(frozen=True)
class QaResponse:
    answer: str
    accepted: bool
    reason: str
    citations: list[dict[str, object]]
    retrieved_sections: list[dict[str, object]]
    rag_confidence: float | None = None
    usage: ChatUsage | None = None
    direct_answer: str | None = None
    direct_usage: ChatUsage | None = None
    direct_model: str | None = None
    rag_answer: str | None = None
    rag_usage: ChatUsage | None = None
    rag_model: str | None = None


@dataclass(frozen=True)
class QaStreamEvent:
    event: str
    payload: dict[str, object]


@dataclass(frozen=True)
class _StreamWorkerEvent:
    side: str
    chunk: ChatStreamChunk | None = None
    error: bool = False
    finished: bool = False


class RelevanceClassifier(Protocol):
    def classify(self, question: str) -> RelevanceDecision:
        """Return whether a question is relevant enough for the full QA path."""


class QaService:
    def __init__(
        self,
        *,
        query_service: QueryService,
        llm_client: DeepSeekChatClient,
        relevance_classifier: RelevanceClassifier,
        config: QaConfig | None = None,
    ) -> None:
        self._query_service = query_service
        self._llm_client = llm_client
        self._config = config or QaConfig()
        self._relevance_classifier = relevance_classifier

    def answer(
        self,
        question: str,
        *,
        user_id: str | None = None,
        model: str | None = None,
    ) -> QaResponse:
        classifier_failed = False
        try:
            classifier_relevance = self._relevance_classifier.classify(question)
        except RelevanceClassifierError as error:
            classifier_failed = True
            LOGGER.warning("relevance classifier unavailable; falling back to retrieval gate: %s", error)
        if not classifier_failed and not classifier_relevance.accepted:
            return _not_quic_response()

        with ThreadPoolExecutor(max_workers=1) as executor:
            direct_future = executor.submit(self._answer_direct, question, user_id, model)
            retrieved = self._query_service.search_sections(
                question,
                top_k=self._config.top_k,
            )
            filtered_retrieved = _filter_sections_by_score(retrieved, self._config.min_retrieval_score)

            if not filtered_retrieved:
                if classifier_failed:
                    direct_result, direct_error = direct_future.result()
                    return QaResponse(
                        answer=FALLBACK_FILTER_UNAVAILABLE,
                        accepted=False,
                        reason="unavailable",
                        citations=[],
                        retrieved_sections=_public_sections(retrieved),
                        rag_confidence=_rag_confidence(retrieved),
                        direct_answer=_generation_fallback(direct_error)
                        if direct_result is None
                        else direct_result.answer,
                        direct_usage=direct_result.usage if direct_result is not None else None,
                        direct_model=direct_result.model if direct_result is not None else None,
                        rag_answer=FALLBACK_NOT_FOUND,
                    )
                direct_result, direct_error = direct_future.result()
                answer = direct_result.answer if direct_result is not None else FALLBACK_NOT_FOUND
                accepted = direct_result is not None
                reason = "answered_direct_only" if direct_result is not None else "low_retrieval_confidence"
                return QaResponse(
                    answer=answer,
                    accepted=accepted,
                    reason=reason,
                    citations=[],
                    retrieved_sections=_public_sections(retrieved),
                    rag_confidence=_rag_confidence(retrieved),
                    usage=direct_result.usage if direct_result is not None else None,
                    direct_answer=direct_result.answer if direct_result is not None else _generation_fallback(direct_error),
                    direct_usage=direct_result.usage if direct_result is not None else None,
                    direct_model=direct_result.model if direct_result is not None else None,
                    rag_answer=FALLBACK_NOT_FOUND,
                )

            sections_for_llm = _trim_sections(filtered_retrieved, self._config.max_context_chars)
            try:
                chat_result = self._llm_client.answer(
                    question=question,
                    sections=sections_for_llm,
                    max_tokens=self._config.max_output_tokens,
                    user_id=user_id,
                    model=model,
                )
            except DeepSeekChatError:
                direct_result, direct_error = direct_future.result()
                if direct_result is not None:
                    return QaResponse(
                        answer=direct_result.answer,
                        accepted=True,
                        reason="answered_direct_only",
                        citations=_citations(filtered_retrieved),
                        retrieved_sections=_public_sections(filtered_retrieved),
                        rag_confidence=_rag_confidence(filtered_retrieved),
                        usage=direct_result.usage,
                        direct_answer=direct_result.answer,
                        direct_usage=direct_result.usage,
                        direct_model=direct_result.model,
                        rag_answer=FALLBACK_GENERATION_UNAVAILABLE,
                    )
                return QaResponse(
                    answer=FALLBACK_GENERATION_UNAVAILABLE,
                    accepted=False,
                    reason="generation_error",
                    citations=_citations(filtered_retrieved),
                    retrieved_sections=_public_sections(filtered_retrieved),
                    rag_confidence=_rag_confidence(filtered_retrieved),
                    direct_answer=_generation_fallback(direct_error),
                    rag_answer=FALLBACK_GENERATION_UNAVAILABLE,
                )
            direct_result, direct_error = direct_future.result()
            return QaResponse(
                answer=chat_result.answer,
                accepted=True,
                reason="answered",
                citations=_citations(filtered_retrieved),
                retrieved_sections=_public_sections(filtered_retrieved),
                rag_confidence=_rag_confidence(filtered_retrieved),
                usage=_combine_usage(direct_result.usage if direct_result is not None else None, chat_result.usage),
                direct_answer=direct_result.answer if direct_result is not None else _generation_fallback(direct_error),
                direct_usage=direct_result.usage if direct_result is not None else None,
                direct_model=direct_result.model if direct_result is not None else None,
                rag_answer=chat_result.answer,
                rag_usage=chat_result.usage,
                rag_model=chat_result.model,
            )

    def answer_stream(
        self,
        question: str,
        *,
        user_id: str | None = None,
        model: str | None = None,
    ) -> Iterator[QaStreamEvent]:
        classifier_failed = False
        try:
            classifier_relevance = self._relevance_classifier.classify(question)
        except RelevanceClassifierError as error:
            classifier_failed = True
            LOGGER.warning("relevance classifier unavailable; falling back to retrieval gate: %s", error)
        if not classifier_failed and not classifier_relevance.accepted:
            response = _not_quic_response()
            yield QaStreamEvent(
                "done",
                {
                    "accepted": response.accepted,
                    "reason": response.reason,
                    "answer": response.answer,
                    "direct_answer": response.answer,
                    "rag_answer": response.answer,
                    "citations": [],
                    "retrieved_sections": [],
                },
            )
            return

        retrieved = self._query_service.search_sections(
            question,
            top_k=self._config.top_k,
        )
        filtered_retrieved = _filter_sections_by_score(retrieved, self._config.min_retrieval_score)
        citations = _citations(filtered_retrieved)
        rag_confidence = _rag_confidence(filtered_retrieved if filtered_retrieved else retrieved)
        yield QaStreamEvent(
            "metadata",
            {
                "citations": citations,
                "retrieved_sections": _public_sections(filtered_retrieved if filtered_retrieved else retrieved),
                "rag_confidence": rag_confidence,
            },
        )

        if not filtered_retrieved:
            direct_answer, direct_usage, direct_model, direct_error = yield from _stream_direct_answer(
                self,
                question,
                user_id,
                model,
            )
            if classifier_failed:
                final_answer = FALLBACK_FILTER_UNAVAILABLE
                reason = "unavailable"
                accepted = False
            elif not direct_error:
                final_answer = direct_answer
                reason = "answered_direct_only"
                accepted = True
            else:
                final_answer = FALLBACK_NOT_FOUND
                reason = "low_retrieval_confidence"
                accepted = False
            yield QaStreamEvent(
                "rag",
                {
                    "delta": FALLBACK_NOT_FOUND,
                    "done": True,
                },
            )
            yield QaStreamEvent(
                "done",
                {
                    "accepted": accepted,
                    "reason": reason,
                    "answer": final_answer,
                    "direct_answer": direct_answer,
                    "direct_usage": _usage_dict(direct_usage),
                    "direct_model": direct_model,
                    "rag_answer": FALLBACK_NOT_FOUND,
                    "citations": [],
                    "retrieved_sections": _public_sections(retrieved),
                    "rag_confidence": rag_confidence,
                },
            )
            return

        sections_for_llm = _trim_sections(filtered_retrieved, self._config.max_context_chars)
        direct_answer, direct_usage, direct_model, direct_error, rag_answer, rag_usage, rag_model, rag_error = (
            yield from _stream_direct_and_rag_answers(
                self,
                question,
                sections_for_llm,
                user_id,
                model,
            )
        )

        if rag_error:
            rag_answer = FALLBACK_GENERATION_UNAVAILABLE
            yield QaStreamEvent(
                "rag",
                {
                    "delta": rag_answer,
                    "done": True,
                },
            )
            if not direct_error:
                yield QaStreamEvent(
                    "done",
                    {
                        "accepted": True,
                        "reason": "answered_direct_only",
                        "answer": direct_answer,
                        "direct_answer": direct_answer,
                        "direct_usage": _usage_dict(direct_usage),
                        "direct_model": direct_model,
                        "rag_answer": rag_answer,
                        "citations": citations,
                        "retrieved_sections": _public_sections(filtered_retrieved),
                        "rag_confidence": rag_confidence,
                    },
                )
                return
            yield QaStreamEvent(
                "done",
                {
                    "accepted": False,
                    "reason": "generation_error",
                    "answer": FALLBACK_GENERATION_UNAVAILABLE,
                    "direct_answer": direct_answer,
                    "rag_answer": rag_answer,
                    "citations": citations,
                    "retrieved_sections": _public_sections(filtered_retrieved),
                    "rag_confidence": rag_confidence,
                },
            )
            return

        yield QaStreamEvent(
            "done",
            {
                "accepted": True,
                "reason": "answered",
                "answer": rag_answer,
                "usage": _usage_dict(_combine_usage(direct_usage, rag_usage)),
                "direct_answer": direct_answer,
                "direct_usage": _usage_dict(direct_usage),
                "direct_model": direct_model,
                "rag_answer": rag_answer,
                "rag_usage": _usage_dict(rag_usage),
                "rag_model": rag_model,
                "citations": citations,
                "retrieved_sections": _public_sections(filtered_retrieved),
                "rag_confidence": rag_confidence,
            },
        )

    def _answer_direct(
        self,
        question: str,
        user_id: str | None,
        model: str | None,
    ) -> tuple[ChatResult | None, bool]:
        try:
            return (
                self._llm_client.answer_direct(
                    question=question,
                    max_tokens=self._config.max_output_tokens,
                    user_id=user_id,
                    model=model,
                ),
                False,
            )
        except DeepSeekChatError:
            return None, True


def _not_quic_response() -> QaResponse:
    return QaResponse(
        answer=FALLBACK_NOT_QUIC,
        accepted=False,
        reason="out_of_scope",
        citations=[],
        retrieved_sections=[],
    )


def _generation_fallback(had_error: bool) -> str | None:
    if had_error:
        return FALLBACK_GENERATION_UNAVAILABLE
    return None


def _combine_usage(first: ChatUsage | None, second: ChatUsage | None) -> ChatUsage | None:
    if first is None:
        return second
    if second is None:
        return first
    return ChatUsage(
        prompt_tokens=_sum_optional_int(first.prompt_tokens, second.prompt_tokens),
        completion_tokens=_sum_optional_int(first.completion_tokens, second.completion_tokens),
        total_tokens=_sum_optional_int(first.total_tokens, second.total_tokens),
    )


def _sum_optional_int(first: int | None, second: int | None) -> int | None:
    if first is None and second is None:
        return None
    return (first or 0) + (second or 0)


def _stream_direct_answer(
    service: QaService,
    question: str,
    user_id: str | None,
    model: str | None,
) -> Iterator[QaStreamEvent]:
    stream_queue: queue.Queue[_StreamWorkerEvent] = queue.Queue()
    _start_stream_worker(
        stream_queue,
        "direct",
        service._llm_client.stream_answer_direct(
            question=question,
            max_tokens=service._config.max_output_tokens,
            user_id=user_id,
            model=model,
        ),
    )
    return cast(Any, (yield from _drain_single_stream(stream_queue, "direct")))


def _stream_direct_and_rag_answers(
    service: QaService,
    question: str,
    sections: Sequence[dict[str, object]],
    user_id: str | None,
    model: str | None,
) -> Iterator[QaStreamEvent]:
    stream_queue: queue.Queue[_StreamWorkerEvent] = queue.Queue()
    _start_stream_worker(
        stream_queue,
        "direct",
        service._llm_client.stream_answer_direct(
            question=question,
            max_tokens=service._config.max_output_tokens,
            user_id=user_id,
            model=model,
        ),
    )
    _start_stream_worker(
        stream_queue,
        "rag",
        service._llm_client.stream_answer(
            question=question,
            sections=sections,
            max_tokens=service._config.max_output_tokens,
            user_id=user_id,
            model=model,
        ),
    )
    return cast(Any, (yield from _drain_paired_streams(stream_queue)))


def _start_stream_worker(
    stream_queue: "queue.Queue[_StreamWorkerEvent]",
    side: str,
    chunks: Iterator[ChatStreamChunk],
) -> None:
    def run() -> None:
        try:
            for chunk in chunks:
                stream_queue.put(_StreamWorkerEvent(side=side, chunk=chunk))
        except DeepSeekChatError:
            stream_queue.put(_StreamWorkerEvent(side=side, error=True))
        finally:
            stream_queue.put(_StreamWorkerEvent(side=side, finished=True))

    threading.Thread(target=run, daemon=True).start()


def _drain_single_stream(
    stream_queue: "queue.Queue[_StreamWorkerEvent]",
    side: str,
) -> Iterator[QaStreamEvent]:
    parts: list[str] = []
    usage: ChatUsage | None = None
    actual_model: str | None = None
    error = False

    while True:
        event = stream_queue.get()
        if event.error:
            error = True
            continue
        if event.chunk is not None:
            if event.chunk.delta:
                parts.append(event.chunk.delta)
            if event.chunk.usage is not None:
                usage = event.chunk.usage
            if event.chunk.model:
                actual_model = event.chunk.model
            yield QaStreamEvent(side, _stream_chunk_payload(event.chunk))
        if event.finished:
            break

    answer = "".join(parts).strip()
    if error or not answer:
        error = True
        answer = FALLBACK_GENERATION_UNAVAILABLE
        yield QaStreamEvent(side, {"delta": answer, "done": True})
    return answer, usage, actual_model, error


def _drain_paired_streams(
    stream_queue: "queue.Queue[_StreamWorkerEvent]",
) -> Iterator[QaStreamEvent]:
    direct_parts: list[str] = []
    rag_parts: list[str] = []
    direct_usage: ChatUsage | None = None
    rag_usage: ChatUsage | None = None
    direct_model: str | None = None
    rag_model: str | None = None
    direct_error = False
    rag_error = False
    finished = {"direct": False, "rag": False}

    while not all(finished.values()):
        event = stream_queue.get()
        if event.error:
            if event.side == "direct":
                direct_error = True
            elif event.side == "rag":
                rag_error = True
            continue
        if event.chunk is not None:
            chunk = event.chunk
            if event.side == "direct":
                if chunk.delta:
                    direct_parts.append(chunk.delta)
                if chunk.usage is not None:
                    direct_usage = chunk.usage
                if chunk.model:
                    direct_model = chunk.model
                yield QaStreamEvent("direct", _stream_chunk_payload(chunk))
            elif event.side == "rag":
                if chunk.delta:
                    rag_parts.append(chunk.delta)
                if chunk.usage is not None:
                    rag_usage = chunk.usage
                if chunk.model:
                    rag_model = chunk.model
                yield QaStreamEvent("rag", _stream_chunk_payload(chunk))
        if event.finished:
            finished[event.side] = True

    direct_answer = "".join(direct_parts).strip()
    rag_answer = "".join(rag_parts).strip()
    if direct_error or not direct_answer:
        direct_error = True
        direct_answer = FALLBACK_GENERATION_UNAVAILABLE
        yield QaStreamEvent("direct", {"delta": direct_answer, "done": True})
    if not rag_answer:
        rag_error = True
    return direct_answer, direct_usage, direct_model, direct_error, rag_answer, rag_usage, rag_model, rag_error


def _direct_answer_text(result: ChatResult | None, had_error: bool) -> str:
    if result is not None:
        return result.answer
    return _generation_fallback(had_error) or FALLBACK_GENERATION_UNAVAILABLE


def _direct_stream_event(result: ChatResult | None, answer: str) -> QaStreamEvent:
    return QaStreamEvent(
        "direct",
        {
            "delta": answer,
            "model": result.model if result is not None else None,
            "usage": _usage_dict(result.usage) if result is not None else None,
            "done": True,
        },
    )


def _usage_dict(usage: ChatUsage | None) -> dict[str, int | None] | None:
    if usage is None:
        return None
    return {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
    }


def _stream_chunk_payload(chunk: ChatStreamChunk) -> dict[str, object]:
    payload: dict[str, object] = {
        "delta": chunk.delta,
        "done": chunk.done,
    }
    if chunk.usage is not None:
        payload["usage"] = _usage_dict(chunk.usage)
    if chunk.model:
        payload["model"] = chunk.model
    return payload


def _filter_sections_by_score(
    sections: Sequence[dict[str, object]],
    min_score: float,
) -> list[dict[str, object]]:
    return [section for section in sections if _section_score(section) >= min_score]


def _rag_confidence(sections: Sequence[dict[str, object]]) -> float | None:
    scores = [_section_score(section) for section in sections if _has_numeric_score(section)]
    if not scores:
        return None
    top_scores = scores[: min(3, len(scores))]
    weighted = (max(scores) * 0.6) + ((sum(top_scores) / len(top_scores)) * 0.4)
    return round(max(0.0, min(1.0, weighted)), 3)


def _has_numeric_score(section: dict[str, object]) -> bool:
    return isinstance(section.get("score"), (int, float))


def _section_score(section: dict[str, object]) -> float:
    score = section.get("score")
    if isinstance(score, (int, float)):
        return float(score)
    return 0.0


def _trim_sections(
    sections: Sequence[dict[str, object]],
    max_context_chars: int,
) -> list[dict[str, object]]:
    trimmed: list[dict[str, object]] = []
    remaining = max_context_chars
    for section in sections:
        if remaining <= 0:
            break
        copy = dict(section)
        text = str(copy.get("text", ""))
        if len(text) > remaining:
            text = text[:remaining].rsplit(" ", 1)[0].rstrip()
        copy["text"] = text
        remaining -= len(text)
        trimmed.append(copy)
    return trimmed


def _citations(sections: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    citations = []
    seen: set[tuple[str, str]] = set()
    for section in sections:
        key = (str(section.get("doc_id", "")), str(section.get("section_id", "")))
        if key in seen:
            continue
        seen.add(key)
        citations.append(
            {
                "citation": section.get("citation"),
                "doc_id": section.get("doc_id"),
                "section_id": section.get("section_id"),
                "title": section.get("title"),
                "score": section.get("score"),
                "text": section.get("text"),
                "url": _section_url(section),
            }
        )
    return citations


def _section_url(section: dict[str, object]) -> str | None:
    rfc_number = section.get("rfc_number")
    section_id = str(section.get("section_id", "")).strip()
    if rfc_number is None or not section_id:
        return None
    return f"https://www.rfc-editor.org/rfc/rfc{int(rfc_number)}.html#section-{section_id}"


def _public_sections(sections: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    public = []
    for section in sections:
        text = str(section.get("text", ""))
        public.append(
            {
                "citation": section.get("citation"),
                "doc_id": section.get("doc_id"),
                "section_id": section.get("section_id"),
                "title": section.get("title"),
                "score": section.get("score"),
                "excerpt": text[:700],
            }
        )
    return public
