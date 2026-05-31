from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from coquic_rag.query.service import QueryService
from coquic_rag.qa.openrouter_chat import (
    ChatResult,
    ChatUsage,
    OpenRouterChatClient,
    OpenRouterChatError,
)
from coquic_rag.qa.filters import (
    RelevanceClassifierError,
    RelevanceDecision,
    best_retrieval_score,
)


DEFAULT_TOP_K = 10
DEFAULT_MAX_CONTEXT_CHARS = 6500
DEFAULT_MIN_RETRIEVAL_SCORE = 0.18
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
    usage: ChatUsage | None = None
    direct_answer: str | None = None
    direct_usage: ChatUsage | None = None
    direct_model: str | None = None
    rag_answer: str | None = None
    rag_usage: ChatUsage | None = None
    rag_model: str | None = None


class RelevanceClassifier(Protocol):
    def classify(self, question: str) -> RelevanceDecision:
        """Return whether a question is relevant enough for the full QA path."""


class QaService:
    def __init__(
        self,
        *,
        query_service: QueryService,
        llm_client: OpenRouterChatClient,
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
            classifier_relevance = RelevanceDecision(True, "classifier_unavailable")
            LOGGER.warning("relevance classifier unavailable; falling back to retrieval gate: %s", error)
        if not classifier_failed and not classifier_relevance.accepted:
            return _not_quic_response()

        with ThreadPoolExecutor(max_workers=1) as executor:
            direct_future = executor.submit(self._answer_direct, question, user_id, model)
            retrieved = self._query_service.search_sections(
                question,
                top_k=self._config.top_k,
            )

            if not retrieved or best_retrieval_score(retrieved) < self._config.min_retrieval_score:
                if classifier_failed:
                    direct_result, direct_error = direct_future.result()
                    return QaResponse(
                        answer=FALLBACK_FILTER_UNAVAILABLE,
                        accepted=False,
                        reason="unavailable",
                        citations=[],
                        retrieved_sections=_public_sections(retrieved),
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
                    usage=direct_result.usage if direct_result is not None else None,
                    direct_answer=direct_result.answer if direct_result is not None else _generation_fallback(direct_error),
                    direct_usage=direct_result.usage if direct_result is not None else None,
                    direct_model=direct_result.model if direct_result is not None else None,
                    rag_answer=FALLBACK_NOT_FOUND,
                )

            sections_for_llm = _trim_sections(retrieved, self._config.max_context_chars)
            try:
                chat_result = self._llm_client.answer(
                    question=question,
                    sections=sections_for_llm,
                    max_tokens=self._config.max_output_tokens,
                    user_id=user_id,
                    model=model,
                )
            except OpenRouterChatError:
                direct_result, direct_error = direct_future.result()
                if direct_result is not None:
                    return QaResponse(
                        answer=direct_result.answer,
                        accepted=True,
                        reason="answered_direct_only",
                        citations=_citations(retrieved),
                        retrieved_sections=_public_sections(retrieved),
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
                    citations=_citations(retrieved),
                    retrieved_sections=_public_sections(retrieved),
                    direct_answer=_generation_fallback(direct_error),
                    rag_answer=FALLBACK_GENERATION_UNAVAILABLE,
                )
            direct_result, direct_error = direct_future.result()
            return QaResponse(
                answer=chat_result.answer,
                accepted=True,
                reason="answered",
                citations=_citations(retrieved),
                retrieved_sections=_public_sections(retrieved),
                usage=_combine_usage(direct_result.usage if direct_result is not None else None, chat_result.usage),
                direct_answer=direct_result.answer if direct_result is not None else _generation_fallback(direct_error),
                direct_usage=direct_result.usage if direct_result is not None else None,
                direct_model=direct_result.model if direct_result is not None else None,
                rag_answer=chat_result.answer,
                rag_usage=chat_result.usage,
                rag_model=chat_result.model,
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
        except OpenRouterChatError:
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
