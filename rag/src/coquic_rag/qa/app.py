from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from coquic_rag.config import ProjectPaths
from coquic_rag.embed.provider import (
    FakeEmbedder,
)
from coquic_rag.query.service import get_index_status
from coquic_rag.qa.filters import (
    DeepSeekRelevanceClassifier,
    DeepSeekQuestionGenerator,
    MAX_QUESTION_CHARS,
    RELEVANCE_FILTER_MODEL,
    QuestionGenerationError,
    QUESTION_GENERATOR_MODEL,
    SlidingWindowRateLimiter,
    is_valid_generated_question,
    normalize_question,
)
from coquic_rag.qa.deepseek_chat import (
    ANSWER_MODELS,
    DEFAULT_ANSWER_MODEL,
    ChatUsage,
    DeepSeekChatClient,
    normalize_answer_model,
)
from coquic_rag.qa.service import QaConfig, QaResponse, QaService
from coquic_rag.query.service import QueryService


DEFAULT_ALLOWED_ORIGINS = (
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
)
QA_COLLECTION_NAME = "quic_sections"
QA_SEARCH_EMBEDDING_MODEL = "local-keyword-v1"
LOGGER = logging.getLogger(__name__)
GLOBAL_DEEPSEEK_RATE_KEY = "deepseek:global"
QA_RATE_LIMIT_REQUESTS = 12
QA_RATE_WINDOW_SECONDS = 60
QA_IP_RATE_LIMIT_REQUESTS = 24
QA_IP_RATE_WINDOW_SECONDS = 60
RANDOM_QUESTION_RATE_LIMIT_REQUESTS = 10
RANDOM_QUESTION_RATE_WINDOW_SECONDS = 60
RANDOM_QUESTION_IP_RATE_LIMIT_REQUESTS = 20
RANDOM_QUESTION_IP_RATE_WINDOW_SECONDS = 60
DEEPSEEK_RATE_LIMIT_REQUESTS = 90
DEEPSEEK_RATE_WINDOW_SECONDS = 60
QA_DEEPSEEK_COST = 3
RANDOM_QUESTION_DEEPSEEK_COST = 1
RATE_LIMIT_LOCK = threading.Lock()


@dataclass(frozen=True)
class ClientIdentity:
    ip_key: str
    session_key: str | None
    user_key: str


class QaRequest(BaseModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    model: str | None = None


class UsagePayload(BaseModel):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class QaResponsePayload(BaseModel):
    answer: str
    accepted: bool
    reason: str
    citations: list[dict[str, object]]
    retrieved_sections: list[dict[str, object]]
    rag_confidence: float | None = None
    usage: UsagePayload | None = None
    direct_answer: str | None = None
    direct_usage: UsagePayload | None = None
    direct_model: str | None = None
    rag_answer: str | None = None
    rag_usage: UsagePayload | None = None
    rag_model: str | None = None


class RandomQuestionPayload(BaseModel):
    question: str


class HealthPayload(BaseModel):
    ready: bool
    source_docs: bool
    artifacts: bool
    qdrant_backend: str
    qdrant: str
    indexed_sections: str | None = None
    embedding_model: str
    llm_model: str
    answer_models: list[dict[str, str]]


@lru_cache
def app_config() -> QaConfig:
    return QaConfig(
        top_k=_env_int("COQUIC_QA_TOP_K", 10),
        max_context_chars=_env_int("COQUIC_QA_MAX_CONTEXT_CHARS", 6500),
        min_retrieval_score=_env_float("COQUIC_QA_MIN_RETRIEVAL_SCORE", 0.4),
        max_output_tokens=_env_int("COQUIC_QA_MAX_OUTPUT_TOKENS", 650),
    )


@lru_cache
def paths() -> ProjectPaths:
    repo_root = Path(os.getenv("COQUIC_REPO_ROOT", Path.cwd())).resolve()
    state_dir = Path(os.getenv("COQUIC_RAG_STATE_DIR", repo_root / ".rag"))
    source_dir = Path(os.getenv("COQUIC_RFC_SOURCE", repo_root / "references" / "rfc"))
    return ProjectPaths(
        repo_root=repo_root,
        rfc_source=source_dir,
        state_dir=state_dir,
        qdrant_url=os.getenv("COQUIC_QDRANT_URL"),
        qdrant_api_key=os.getenv("COQUIC_QDRANT_API_KEY"),
    )


@lru_cache
def qa_service() -> QaService:
    embedder = FakeEmbedder()
    query_service = QueryService(
        paths=paths(),
        embedder=embedder,
        collection_name=QA_COLLECTION_NAME,
        require_artifacts_for_search=False,
    )
    llm_client = DeepSeekChatClient(model=DEFAULT_ANSWER_MODEL)
    relevance_classifier = DeepSeekRelevanceClassifier(model=RELEVANCE_FILTER_MODEL)
    return QaService(
        query_service=query_service,
        llm_client=llm_client,
        config=app_config(),
        relevance_classifier=relevance_classifier,
    )


@lru_cache
def rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=QA_RATE_LIMIT_REQUESTS,
        window_seconds=QA_RATE_WINDOW_SECONDS,
    )


@lru_cache
def qa_ip_rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=QA_IP_RATE_LIMIT_REQUESTS,
        window_seconds=QA_IP_RATE_WINDOW_SECONDS,
    )


@lru_cache
def question_rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=RANDOM_QUESTION_RATE_LIMIT_REQUESTS,
        window_seconds=RANDOM_QUESTION_RATE_WINDOW_SECONDS,
    )


@lru_cache
def question_ip_rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=RANDOM_QUESTION_IP_RATE_LIMIT_REQUESTS,
        window_seconds=RANDOM_QUESTION_IP_RATE_WINDOW_SECONDS,
    )


@lru_cache
def deepseek_rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=DEEPSEEK_RATE_LIMIT_REQUESTS,
        window_seconds=DEEPSEEK_RATE_WINDOW_SECONDS,
    )


@lru_cache
def relevance_classifier() -> DeepSeekRelevanceClassifier:
    return DeepSeekRelevanceClassifier(model=RELEVANCE_FILTER_MODEL)


@lru_cache
def question_generator() -> DeepSeekQuestionGenerator:
    return DeepSeekQuestionGenerator(
        model=QUESTION_GENERATOR_MODEL,
        timeout=12,
        max_generation_attempts=5,
    )


def create_app() -> FastAPI:
    app = FastAPI(title="CoQUIC QUIC QA", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Session-Id"],
    )

    @app.get("/api/health", response_model=HealthPayload)
    def health() -> HealthPayload:
        status = get_index_status(
            paths(),
            collection_name=QA_COLLECTION_NAME,
        )
        indexed_sections = None
        if status.section_count is not None and status.indexed_count is not None:
            indexed_sections = f"{status.indexed_count}/{status.section_count}"
        return HealthPayload(
            ready=_semantic_search_ready(status),
            source_docs=status.source_ok,
            artifacts=status.artifacts_ok,
            qdrant_backend=status.qdrant_backend,
            qdrant=status.qdrant_status,
            indexed_sections=indexed_sections,
            embedding_model=QA_SEARCH_EMBEDDING_MODEL,
            llm_model=DEFAULT_ANSWER_MODEL,
            answer_models=_answer_models_payload(),
        )

    @app.post("/api/qa", response_model=QaResponsePayload)
    async def answer(
        payload: QaRequest,
        request: Request,
        x_session_id: Annotated[str | None, Header()] = None,
        service: QaService = Depends(qa_service),
    ) -> QaResponsePayload:
        normalized_question = normalize_question(payload.question)
        client_identity = _client_identity(request, x_session_id)
        _enforce_rate_limits(
            _qa_rate_limit_checks(client_identity),
            deepseek_cost=QA_DEEPSEEK_COST,
        )
        try:
            answer_model = normalize_answer_model(payload.model)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        result = await run_in_threadpool(
            service.answer,
            normalized_question,
            user_id=_hashed_user_id(client_identity.user_key),
            model=answer_model,
        )
        return _to_payload(result)

    @app.post("/api/qa/stream")
    async def answer_stream(
        payload: QaRequest,
        request: Request,
        x_session_id: Annotated[str | None, Header()] = None,
        service: QaService = Depends(qa_service),
    ) -> StreamingResponse:
        normalized_question = normalize_question(payload.question)
        client_identity = _client_identity(request, x_session_id)
        _enforce_rate_limits(
            _qa_rate_limit_checks(client_identity),
            deepseek_cost=QA_DEEPSEEK_COST,
        )
        try:
            answer_model = normalize_answer_model(payload.model)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        def stream_events():
            try:
                for event in service.answer_stream(
                    normalized_question,
                    user_id=_hashed_user_id(client_identity.user_key),
                    model=answer_model,
                ):
                    yield _sse(event.event, event.payload)
            except Exception as error:  # pragma: no cover - defensive stream boundary
                LOGGER.exception("streaming QA failed: %s", error)
                yield _sse(
                    "error",
                    {"detail": "QA stream failed"},
                )

        return StreamingResponse(
            stream_events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/questions/random", response_model=RandomQuestionPayload)
    def random_question(
        request: Request,
        x_session_id: Annotated[str | None, Header()] = None,
        generator: DeepSeekQuestionGenerator = Depends(question_generator),
    ) -> RandomQuestionPayload:
        client_identity = _client_identity(request, x_session_id)
        _enforce_rate_limits(
            _random_question_rate_limit_checks(client_identity),
            deepseek_cost=RANDOM_QUESTION_DEEPSEEK_COST,
        )

        try:
            question = normalize_question(generator.generate())
        except QuestionGenerationError as error:
            LOGGER.info("random question generation failed: %s", error)
            raise HTTPException(
                status_code=503,
                detail="random question generator unavailable",
            ) from error
        if is_valid_generated_question(question):
            return RandomQuestionPayload(question=question)

        raise HTTPException(
            status_code=503,
            detail="random question generator returned an invalid question",
        )

    return app


def _to_payload(response: QaResponse) -> QaResponsePayload:
    return QaResponsePayload(
        answer=response.answer,
        accepted=response.accepted,
        reason=response.reason,
        citations=response.citations,
        retrieved_sections=response.retrieved_sections,
        rag_confidence=response.rag_confidence,
        usage=_usage_payload(response.usage),
        direct_answer=response.direct_answer,
        direct_usage=_usage_payload(response.direct_usage),
        direct_model=response.direct_model,
        rag_answer=response.rag_answer,
        rag_usage=_usage_payload(response.rag_usage),
        rag_model=response.rag_model,
    )


def _answer_models_payload() -> list[dict[str, str]]:
    return [{"id": model_id, "label": label} for model_id, label in ANSWER_MODELS]


def _semantic_search_ready(status: object) -> bool:
    indexed_count = getattr(status, "indexed_count", None)
    return bool(getattr(status, "qdrant_ok", False) and indexed_count != 0)


def _usage_payload(usage: ChatUsage | None) -> UsagePayload | None:
    if usage is None:
        return None
    return UsagePayload(
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        total_tokens=usage.total_tokens,
    )


def _sse(event: str, payload: dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


def _allowed_origins() -> list[str]:
    configured = os.getenv("COQUIC_QA_ALLOWED_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return list(DEFAULT_ALLOWED_ORIGINS)


def _qa_rate_limit_checks(
    client_identity: ClientIdentity,
) -> tuple[tuple[SlidingWindowRateLimiter, str, int], ...]:
    return (
        (rate_limiter(), client_identity.session_key or client_identity.ip_key, 1),
        (qa_ip_rate_limiter(), client_identity.ip_key, 1),
    )


def _random_question_rate_limit_checks(
    client_identity: ClientIdentity,
) -> tuple[tuple[SlidingWindowRateLimiter, str, int], ...]:
    return (
        (question_rate_limiter(), client_identity.session_key or client_identity.ip_key, 1),
        (question_ip_rate_limiter(), client_identity.ip_key, 1),
    )


def _enforce_rate_limits(
    checks: tuple[tuple[SlidingWindowRateLimiter, str, int], ...],
    *,
    deepseek_cost: int,
) -> None:
    with RATE_LIMIT_LOCK:
        all_checks = (
            *checks,
            (deepseek_rate_limiter(), GLOBAL_DEEPSEEK_RATE_KEY, deepseek_cost),
        )
        retry_after_seconds = 0
        for limiter, key, cost in all_checks:
            limit = limiter.peek(key, cost=cost)
            if not limit.allowed:
                retry_after_seconds = max(retry_after_seconds, limit.retry_after_seconds)

        if retry_after_seconds > 0:
            _raise_rate_limit(retry_after_seconds)

        for limiter, key, cost in all_checks:
            limit = limiter.check(key, cost=cost)
            if not limit.allowed:
                _raise_rate_limit(limit.retry_after_seconds)


def _raise_rate_limit(retry_after_seconds: int) -> None:
    raise HTTPException(
        status_code=429,
        detail="rate limit exceeded",
        headers={"Retry-After": str(retry_after_seconds)},
    )


def _client_identity(request: Request, session_id: str | None) -> ClientIdentity:
    ip_key = _client_ip_key(request)
    session_key = _client_session_key(session_id)
    user_key = "|".join(key for key in (ip_key, session_key) if key)
    return ClientIdentity(ip_key=ip_key, session_key=session_key, user_key=user_key)


def _client_key(request: Request, session_id: str | None) -> str:
    return _client_identity(request, session_id).user_key


def _client_session_key(session_id: str | None) -> str | None:
    if session_id and session_id.strip():
        return "session:" + _bounded_header_value(session_id)
    return None


def _client_ip_key(request: Request) -> str:
    if request.client is not None:
        return "ip:" + _bounded_header_value(request.client.host)
    return "ip:unknown"


def _bounded_header_value(value: str) -> str:
    return " ".join(value.strip().split())[:80] or "unknown"


def _hashed_user_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    return float(value)


app = create_app()
