from __future__ import annotations

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx


OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_ANSWER_MODEL = "openai/gpt-oss-120b:free"
OPENROUTER_CHAT_TIMEOUT_SECONDS = 20
FREE_ANSWER_MODELS = (
    ("openai/gpt-oss-120b:free", "OpenAI: gpt-oss-120b (free)"),
    ("nvidia/nemotron-3-super-120b-a12b:free", "NVIDIA: Nemotron 3 Super (free)"),
    ("z-ai/glm-4.5-air:free", "Z.AI: GLM 4.5 Air (free)"),
    ("google/gemma-4-31b-it:free", "Google: Gemma 4 31B IT (free)"),
)
FREE_ANSWER_MODEL_IDS = frozenset(model_id for model_id, _label in FREE_ANSWER_MODELS)


class OpenRouterChatError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChatUsage:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(frozen=True)
class ChatResult:
    answer: str
    usage: ChatUsage
    model: str


@dataclass(frozen=True)
class ChatStreamChunk:
    delta: str = ""
    usage: ChatUsage | None = None
    model: str | None = None
    done: bool = False


class OpenRouterChatClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_ANSWER_MODEL,
        base_url: str = OPENROUTER_CHAT_URL,
        timeout: float = OPENROUTER_CHAT_TIMEOUT_SECONDS,
        max_retries: int = 0,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self._model = normalize_answer_model(model)
        self._base_url = base_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = client

    @property
    def model(self) -> str:
        return self._model

    def answer(
        self,
        *,
        question: str,
        sections: Sequence[dict[str, object]],
        max_tokens: int,
        user_id: str | None = None,
        model: str | None = None,
    ) -> ChatResult:
        selected_model = self._selected_model(model)
        payload: dict[str, object] = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, sections)},
            ],
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }
        if user_id:
            payload["user"] = user_id

        return self._chat(payload, requested_model=selected_model)

    def answer_direct(
        self,
        *,
        question: str,
        max_tokens: int,
        user_id: str | None = None,
        model: str | None = None,
    ) -> ChatResult:
        selected_model = self._selected_model(model)
        payload: dict[str, object] = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": _direct_system_prompt()},
                {"role": "user", "content": question.strip()},
            ],
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }
        if user_id:
            payload["user"] = user_id

        return self._chat(payload, requested_model=selected_model)

    def stream_answer(
        self,
        *,
        question: str,
        sections: Sequence[dict[str, object]],
        max_tokens: int,
        user_id: str | None = None,
        model: str | None = None,
    ):
        selected_model = self._selected_model(model)
        payload: dict[str, object] = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, sections)},
            ],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if user_id:
            payload["user"] = user_id
        yield from self._chat_stream(payload, requested_model=selected_model)

    def stream_answer_direct(
        self,
        *,
        question: str,
        max_tokens: int,
        user_id: str | None = None,
        model: str | None = None,
    ):
        selected_model = self._selected_model(model)
        payload: dict[str, object] = {
            "model": selected_model,
            "messages": [
                {"role": "system", "content": _direct_system_prompt()},
                {"role": "user", "content": question.strip()},
            ],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if user_id:
            payload["user"] = user_id
        yield from self._chat_stream(payload, requested_model=selected_model)

    def _selected_model(self, model: str | None) -> str:
        try:
            return normalize_answer_model(model or self._model)
        except ValueError as error:
            raise OpenRouterChatError(str(error)) from error

    def _chat(self, payload: dict[str, object], *, requested_model: str) -> ChatResult:
        if not self._api_key:
            raise OpenRouterChatError("OPENROUTER_API_KEY is required for answer generation")
        response = self._post_with_retries(payload)
        choices = response.get("choices")
        if not isinstance(choices, list) or not choices:
            raise OpenRouterChatError("OpenRouter response did not include choices")
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise OpenRouterChatError("OpenRouter response choice was invalid")
        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise OpenRouterChatError("OpenRouter response did not include a message")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise OpenRouterChatError("OpenRouter response was empty")
        return ChatResult(
            answer=content.strip(),
            usage=_usage_from_response(response),
            model=_model_from_response(response, requested_model),
        )

    def _post_with_retries(self, payload: dict[str, object]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client_or_create().post(
                    self._base_url,
                    json=payload,
                    timeout=self._timeout,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as error:
                last_error = error
                if attempt >= self._max_retries:
                    break
                time.sleep(0.3 * (2**attempt))
        raise OpenRouterChatError(f"OpenRouter request failed: {last_error}") from last_error

    def _chat_stream(self, payload: dict[str, object], *, requested_model: str):
        if not self._api_key:
            raise OpenRouterChatError("OPENROUTER_API_KEY is required for answer generation")
        last_model = requested_model
        last_usage: ChatUsage | None = None
        try:
            with self._client_or_create().stream(
                "POST",
                self._base_url,
                json=payload,
                timeout=self._timeout,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    event = _parse_sse_line(line)
                    if event is None:
                        continue
                    if event == "[DONE]":
                        yield ChatStreamChunk(usage=last_usage, model=last_model, done=True)
                        return
                    try:
                        body = json.loads(event)
                    except ValueError as error:
                        raise OpenRouterChatError("OpenRouter stream returned invalid JSON") from error
                    model = _model_from_response(body, last_model)
                    last_model = model
                    usage = _usage_from_response(body)
                    if usage != ChatUsage():
                        last_usage = usage
                    delta = _delta_from_stream_response(body)
                    if delta:
                        yield ChatStreamChunk(delta=delta, model=model)
                yield ChatStreamChunk(usage=last_usage, model=last_model, done=True)
        except httpx.HTTPError as error:
            raise OpenRouterChatError(f"OpenRouter stream failed: {error}") from error

    def _client_or_create(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }
            )
        return self._client


def normalize_answer_model(model: str | None) -> str:
    if model is None or not model.strip():
        return DEFAULT_ANSWER_MODEL
    normalized = model.strip()
    if normalized not in FREE_ANSWER_MODEL_IDS:
        raise ValueError(f"unsupported free answer model: {normalized}")
    return normalized


def _system_prompt() -> str:
    return (
        "You answer questions about QUIC, HTTP/3, qlog, QPACK, and related "
        "transport-protocol topics. Use the retrieved RFC or Internet-Draft "
        "excerpts as supporting evidence. Prefer them for normative statements, "
        "exact requirements, frame names, parameter names, and section-specific "
        "behavior. Cite retrieved material by RFC or draft section label, for "
        "example '(RFC 9000 Section 1)'; do not use source line markers such as "
        "''. You may also use your general networking and protocol "
        "knowledge to explain concepts, compare protocols, and fill in common "
        "background. Cite retrieved sections when they directly support a claim. "
        "Do not cite a section for claims it does not support. If the retrieved "
        "excerpts are weak or incomplete, still answer from general knowledge "
        "when the question is clearly in scope, and say which parts are based "
        "on general protocol knowledge rather than the provided excerpts. Keep "
        "the answer concise and practical. Answer in the same natural language "
        "as the user's question unless the user explicitly asks for another "
        "language. Wrap packet diagrams, frame layouts, and other fixed-width "
        "ASCII art in triple-backtick Markdown code blocks."
    )


def _direct_system_prompt() -> str:
    return (
        "You answer questions about QUIC, HTTP/3, qlog, QPACK, and related "
        "transport-protocol topics from your general networking and protocol "
        "knowledge. Do not use or refer to retrieved context, a local corpus, "
        "or citations. Keep the answer concise, practical, and clear about "
        "protocol tradeoffs. Answer in the same natural language as the user's "
        "question unless the user explicitly asks for another language."
    )


def _user_prompt(question: str, sections: Sequence[dict[str, object]]) -> str:
    context_blocks = []
    for index, section in enumerate(sections, start=1):
        citation = str(section.get("citation", "unknown section"))
        title = str(section.get("title", "")).strip()
        text = str(section.get("text", "")).strip()
        context_blocks.append(f"[{index}] {citation}: {title}\n{text}")
    context = "\n\n---\n\n".join(context_blocks)
    return (
        f"Question:\n{question.strip()}\n\n"
        f"Retrieved context:\n{context}\n\n"
        "Answer with a concise explanation and cite supporting sections by "
        "their labels, for example '(RFC 9000 Section 1)'. Do not use source "
        "line markers such as ''. Answer in the same natural language as the "
        "question unless the user explicitly asks for another language. "
        "Use triple-backtick Markdown code blocks for packet diagrams, frame "
        "layouts, and fixed-width ASCII art."
    )


def _usage_from_response(response: dict[str, Any]) -> ChatUsage:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return ChatUsage()
    return ChatUsage(
        prompt_tokens=_optional_int(usage.get("prompt_tokens")),
        completion_tokens=_optional_int(usage.get("completion_tokens")),
        total_tokens=_optional_int(usage.get("total_tokens")),
    )


def _model_from_response(response: dict[str, Any], fallback: str) -> str:
    model = response.get("model")
    if isinstance(model, str) and model.strip():
        return model.strip()
    return fallback


def _delta_from_stream_response(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""
    delta = first_choice.get("delta")
    if isinstance(delta, dict):
        content = delta.get("content")
        return content if isinstance(content, str) else ""
    message = first_choice.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        return content if isinstance(content, str) else ""
    return ""


def _parse_sse_line(line: str) -> str | None:
    if not line:
        return None
    if line.startswith(":"):
        return None
    if not line.startswith("data:"):
        return None
    return line.removeprefix("data:").strip()


def _optional_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None
