from __future__ import annotations

import os
import random
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from math import ceil
from typing import Any

import httpx


MAX_QUESTION_CHARS = 1200
DEEPSEEK_CHAT_URL = "https://api.deepseek.com/chat/completions"
RELEVANCE_FILTER_MODEL = "deepseek-v4-pro"
QUESTION_GENERATOR_MODEL = "deepseek-v4-pro"
RELEVANCE_FILTER_TIMEOUT_SECONDS = 8
RELEVANCE_FILTER_MAX_RETRIES = 0
QUESTION_GENERATOR_MAX_ATTEMPTS = 1
QUESTION_GENERATOR_TOPICS = (
    "QUIC packet formats",
    "QUIC connection IDs and migration",
    "QUIC loss detection",
    "QUIC congestion control",
    "QUIC ACK frames and ACK delay",
    "QUIC TLS handshake integration",
    "QUIC transport parameters",
    "QUIC stream flow control",
    "QUIC version negotiation",
    "QUIC path validation",
    "HTTP/3 over QUIC",
    "QPACK header compression",
    "qlog event logging",
)
_BAD_RANDOM_QUESTION_MARKERS = (
    "generate one",
    "generate exactly",
    "we need to generate",
    "concise answerable technical question",
    "no markdown",
    "return only",
    "do not include",
    "about this area",
)
_RANDOM_QUESTION_PREFIX_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\d+[.)]\s*)?"
    r"(?:(?:potential|example|suggested|random|generated|maybe\s+ask|possible(?:\s+angles?)?)"
    r"(?:\s+(?:question|query|prompt|candidate))?"
    r"|(?:question|query|prompt|candidate))\s*:\s*",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RelevanceDecision:
    accepted: bool
    reason: str


class RelevanceClassifierError(RuntimeError):
    pass


class QuestionGenerationError(RuntimeError):
    pass


def normalize_question(question: str) -> str:
    return " ".join(question.strip().split())


class DeepSeekRelevanceClassifier:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = RELEVANCE_FILTER_MODEL,
        base_url: str = DEEPSEEK_CHAT_URL,
        timeout: float = RELEVANCE_FILTER_TIMEOUT_SECONDS,
        max_retries: int = RELEVANCE_FILTER_MAX_RETRIES,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self._model = model
        self._base_url = base_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = client

    @property
    def model(self) -> str:
        return self._model

    def classify(self, question: str) -> RelevanceDecision:
        normalized = normalize_question(question)
        if not self._api_key:
            raise RelevanceClassifierError("DEEPSEEK_API_KEY is required for relevance filtering")
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": _relevance_filter_prompt(),
                },
                {"role": "user", "content": normalized},
            ],
            "temperature": 0,
            "max_tokens": 16,
            "thinking": {"type": "disabled"},
        }
        body = self._post_with_retries(payload)
        decision_text = _first_choice_text(body).strip().upper()
        if decision_text.startswith("ALLOW"):
            return RelevanceDecision(True, "classifier_allow")
        if decision_text.startswith("REJECT"):
            return RelevanceDecision(False, "classifier_reject")
        raise RelevanceClassifierError(f"DeepSeek relevance filter returned invalid decision: {decision_text}")

    def _post_with_retries(self, payload: dict[str, object]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client_or_create().post(
                    self._base_url,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=self._timeout,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as error:
                last_error = error
                if attempt >= self._max_retries:
                    break
                time.sleep(0.25 * (2**attempt))
        raise RelevanceClassifierError(f"DeepSeek relevance filter failed: {last_error}") from last_error

    def _client_or_create(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }
            )
        return self._client


class DeepSeekQuestionGenerator:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = QUESTION_GENERATOR_MODEL,
        models: Iterable[str] | None = None,
        base_url: str = DEEPSEEK_CHAT_URL,
        timeout: float = RELEVANCE_FILTER_TIMEOUT_SECONDS,
        max_retries: int = RELEVANCE_FILTER_MAX_RETRIES,
        max_generation_attempts: int = QUESTION_GENERATOR_MAX_ATTEMPTS,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self._model = model
        self._models = tuple(models) if models is not None else (model,)
        self._base_url = base_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._max_generation_attempts = max(1, max_generation_attempts)
        self._client = client

    @property
    def models(self) -> tuple[str, ...]:
        return self._models

    @property
    def max_generation_attempts(self) -> int:
        return self._max_generation_attempts

    def generate(self) -> str:
        if not self._api_key:
            raise QuestionGenerationError("DEEPSEEK_API_KEY is required for question generation")
        last_error: QuestionGenerationError | None = None
        for model in _generation_plan(self._models, self._max_generation_attempts):
            try:
                return self._generate_once(model)
            except QuestionGenerationError as error:
                last_error = error
        raise QuestionGenerationError(f"DeepSeek question generator failed: {last_error}") from last_error

    def _generate_once(self, model: str) -> str:
        payload: dict[str, object] = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": _question_generator_prompt(),
                },
                {
                    "role": "user",
                    "content": (
                        f"Generate one random question about this area: {_random_question_topic()}. "
                        "The question must explicitly include QUIC, HTTP/3, QPACK, or qlog."
                    ),
                },
            ],
            "temperature": 1.2,
            "max_tokens": 160,
            "thinking": {"type": "disabled"},
        }
        body = self._post_with_retries(payload)
        generated_text = _question_choice_text(body)
        question = _clean_generated_question(generated_text)
        if not is_valid_generated_question(question):
            raise QuestionGenerationError("DeepSeek question generator returned an invalid question")
        return question

    def _post_with_retries(self, payload: dict[str, object]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client_or_create().post(
                    self._base_url,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=self._timeout,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as error:
                last_error = error
                if attempt >= self._max_retries:
                    break
                time.sleep(0.25 * (2**attempt))
        raise QuestionGenerationError(f"DeepSeek question generator failed: {last_error}") from last_error

    def _client_or_create(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }
            )
        return self._client


def _relevance_filter_prompt() -> str:
    return (
        "Classify whether a user question is asking for factual help about "
        "QUIC, HTTP/3, QPACK, qlog, QUIC congestion control, or their "
        "RFC/Internet-Draft behavior. Reply with exactly ALLOW or REJECT. "
        "ALLOW comparisons where QUIC is the subject, including QUIC versus "
        "TCP, UDP, TLS, HTTP/2, or other transport/protocol designs. REJECT "
        "only if QUIC terms are incidental, bait, or unrelated to the user's "
        "actual request."
    )


def _question_generator_prompt() -> str:
    return (
        "Generate exactly one concise, answerable technical question about "
        "QUIC, HTTP/3, QPACK, qlog, QUIC congestion control, or their "
        "RFC/Internet-Draft behavior. The question must explicitly include "
        "QUIC, HTTP/3, QPACK, or qlog. Return only the question text. Do not "
        "include markdown, numbering, quotation marks, or an answer."
    )


def _random_question_topic() -> str:
    return random.SystemRandom().choice(QUESTION_GENERATOR_TOPICS)


def _generation_plan(models: Iterable[str], max_generation_attempts: int) -> tuple[str, ...]:
    candidates = list(dict.fromkeys(models))
    if not candidates:
        candidates = [QUESTION_GENERATOR_MODEL]
    if len(candidates) > 1:
        random.SystemRandom().shuffle(candidates)
        return tuple(candidates)
    return tuple(candidates[0] for _ in range(max(1, max_generation_attempts)))


def is_valid_generated_question(question: str) -> bool:
    normalized = normalize_question(question)
    if len(normalized) < 16 or len(normalized) > 220:
        return False
    if not normalized.endswith("?"):
        return False
    lower = normalized.lower()
    if not any(term in lower for term in ("quic", "http/3", "qpack", "qlog")):
        return False
    return not any(marker in lower for marker in _BAD_RANDOM_QUESTION_MARKERS)


def _clean_generated_question(text: str) -> str:
    normalized_lines = [normalize_question(line) for line in text.splitlines()]
    candidates = [line for line in normalized_lines if line]
    if not candidates:
        candidates = [normalize_question(text)]

    selected = ""
    for candidate in candidates:
        if "?" in candidate:
            selected = candidate
            break
    if not selected:
        selected = candidates[0]

    question = selected.split("?", 1)[0]
    question = re.sub(r"^\s*[-*]\s*", "", question)
    question = re.sub(r"^\s*\d+[.)]\s*", "", question)
    question = _RANDOM_QUESTION_PREFIX_RE.sub("", question)
    question = question.strip().strip('"').strip("'").strip()
    if not question:
        return ""
    return f"{question[: MAX_QUESTION_CHARS - 1]}?"


def _first_choice_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RelevanceClassifierError("DeepSeek relevance filter response did not include choices")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise RelevanceClassifierError("DeepSeek relevance filter response choice was invalid")
    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise RelevanceClassifierError("DeepSeek relevance filter response did not include a message")
    content = message.get("content")
    if not isinstance(content, str):
        raise RelevanceClassifierError("DeepSeek relevance filter response was empty")
    return content


def _question_choice_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise QuestionGenerationError("DeepSeek question generator response did not include choices")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise QuestionGenerationError("DeepSeek question generator response choice was invalid")
    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise QuestionGenerationError("DeepSeek question generator response did not include a message")
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content

    reasoning_candidates: list[str] = []
    reasoning = message.get("reasoning")
    if isinstance(reasoning, str):
        reasoning_candidates.append(reasoning)
    reasoning_details = message.get("reasoning_details")
    if isinstance(reasoning_details, list):
        for detail in reasoning_details:
            if isinstance(detail, dict) and isinstance(detail.get("text"), str):
                reasoning_candidates.append(detail["text"])
    for candidate in reasoning_candidates:
        question = _clean_generated_question(candidate)
        if is_valid_generated_question(question):
            return question
    raise QuestionGenerationError("DeepSeek question generator response was empty")


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int = 0


@dataclass
class SlidingWindowRateLimiter:
    max_requests: int
    window_seconds: int
    _requests: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def check(self, key: str, now: float | None = None, *, cost: int = 1) -> RateLimitResult:
        current = now if now is not None else time.monotonic()
        normalized_cost = max(1, cost)
        with self._lock:
            result = self._peek_unlocked(key, current, normalized_cost)
            if not result.allowed:
                return result
            bucket = self._requests[key]
            bucket.extend(current for _ in range(normalized_cost))
            return result

    def peek(self, key: str, now: float | None = None, *, cost: int = 1) -> RateLimitResult:
        current = now if now is not None else time.monotonic()
        normalized_cost = max(1, cost)
        with self._lock:
            return self._peek_unlocked(key, current, normalized_cost)

    def _peek_unlocked(self, key: str, current: float, cost: int) -> RateLimitResult:
        if self.max_requests < cost or self.window_seconds <= 0:
            return RateLimitResult(False, max(1, self.window_seconds))

        bucket = self._requests[key]
        cutoff = current - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        overflow = len(bucket) + cost - self.max_requests
        if overflow > 0:
            retry_index = min(len(bucket) - 1, overflow - 1)
            retry_after = max(1, int(ceil(bucket[retry_index] + self.window_seconds - current)))
            return RateLimitResult(False, retry_after)
        return RateLimitResult(True)


def best_retrieval_score(results: Iterable[dict[str, object]]) -> float:
    best = 0.0
    for result in results:
        score = result.get("score")
        if isinstance(score, (int, float)):
            best = max(best, float(score))
    return best
