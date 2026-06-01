from __future__ import annotations

import hashlib
import json
import logging
import os
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
    DEFAULT_EMBEDDING_MODEL,
    OpenRouterEmbedder,
)
from coquic_rag.query.service import get_index_status
from coquic_rag.qa.filters import (
    MAX_QUESTION_CHARS,
    RELEVANCE_FILTER_MODEL,
    OpenRouterRelevanceClassifier,
    OpenRouterQuestionGenerator,
    QuestionGenerationError,
    QUESTION_GENERATOR_MODEL,
    SlidingWindowRateLimiter,
    is_valid_generated_question,
    normalize_question,
)
from coquic_rag.qa.openrouter_chat import (
    DEFAULT_ANSWER_MODEL,
    FREE_ANSWER_MODELS,
    ChatUsage,
    OpenRouterChatClient,
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
LOGGER = logging.getLogger(__name__)


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
    embedder = OpenRouterEmbedder(model_name=DEFAULT_EMBEDDING_MODEL)
    query_service = QueryService(
        paths=paths(),
        embedder=embedder,
        collection_name=QA_COLLECTION_NAME,
        require_artifacts_for_search=False,
    )
    llm_client = OpenRouterChatClient(model=DEFAULT_ANSWER_MODEL)
    relevance_classifier = OpenRouterRelevanceClassifier(model=RELEVANCE_FILTER_MODEL)
    return QaService(
        query_service=query_service,
        llm_client=llm_client,
        config=app_config(),
        relevance_classifier=relevance_classifier,
    )


@lru_cache
def rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=_env_int("COQUIC_QA_RATE_LIMIT", 12),
        window_seconds=_env_int("COQUIC_QA_RATE_WINDOW_SECONDS", 60),
    )


@lru_cache
def question_rate_limiter() -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(
        max_requests=_env_int("COQUIC_RANDOM_QUESTION_RATE_LIMIT", 10),
        window_seconds=_env_int("COQUIC_RANDOM_QUESTION_RATE_WINDOW_SECONDS", 60),
    )


@lru_cache
def relevance_classifier() -> OpenRouterRelevanceClassifier:
    return OpenRouterRelevanceClassifier(model=RELEVANCE_FILTER_MODEL)


@lru_cache
def question_generator() -> OpenRouterQuestionGenerator:
    return OpenRouterQuestionGenerator(
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
            embedding_model=DEFAULT_EMBEDDING_MODEL,
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
        client_key = _client_key(request, x_session_id)
        limit = rate_limiter().check(client_key)
        if not limit.allowed:
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
                headers={"Retry-After": str(limit.retry_after_seconds)},
            )
        try:
            answer_model = normalize_answer_model(payload.model)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        result = await run_in_threadpool(
            service.answer,
            normalized_question,
            user_id=_hashed_user_id(client_key),
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
        client_key = _client_key(request, x_session_id)
        limit = rate_limiter().check(client_key)
        if not limit.allowed:
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
                headers={"Retry-After": str(limit.retry_after_seconds)},
            )
        try:
            answer_model = normalize_answer_model(payload.model)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        def stream_events():
            try:
                for event in service.answer_stream(
                    normalized_question,
                    user_id=_hashed_user_id(client_key),
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
        generator: OpenRouterQuestionGenerator = Depends(question_generator),
    ) -> RandomQuestionPayload:
        client_key = _client_key(request, x_session_id)
        limit = question_rate_limiter().check(client_key)
        if not limit.allowed:
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
                headers={"Retry-After": str(limit.retry_after_seconds)},
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
    return [{"id": model_id, "label": label} for model_id, label in FREE_ANSWER_MODELS]


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


def _client_key(request: Request, session_id: str | None) -> str:
    if session_id:
        return f"session:{session_id[:80]}"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return f"ip:{forwarded.split(',', 1)[0].strip()}"
    if request.client is not None:
        return f"ip:{request.client.host}"
    return "ip:unknown"


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
