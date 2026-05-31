from __future__ import annotations

import math
import os
import re
import time
from collections import Counter
from collections.abc import Sequence
from typing import Protocol
from typing import Any

import httpx

DEFAULT_EMBEDDING_MODEL = "nvidia/llama-nemotron-embed-vl-1b-v2:free"
OPENROUTER_EMBEDDINGS_URL = "https://openrouter.ai/api/v1/embeddings"
REMOTE_EMBEDDING_TIMEOUT_SECONDS = 12
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_DEFAULT_KEYWORDS = (
    "ack",
    "transport",
    "parameter",
    "payload",
    "limit",
    "appendix",
    "version",
    "negotiation",
    "token",
    "tls",
    "frame",
    "error",
    "structured",
    "logging",
    "network",
    "protocol",
    "qlog",
    "event",
    "schema",
    "draft",
)


class EmbeddingProvider(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector per input text."""


def _normalize_token(token: str) -> str:
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"
    if token.endswith("s") and len(token) > 3:
        return token[:-1]
    return token


def _tokenize(text: str) -> list[str]:
    tokens = _TOKEN_RE.findall(text.lower().replace("_", " "))
    return [_normalize_token(token) for token in tokens]


def _normalize_vector(values: list[float]) -> list[float]:
    magnitude = math.sqrt(sum(value * value for value in values))
    if magnitude == 0.0:
        return values
    return [value / magnitude for value in values]


class FakeEmbedder:
    def __init__(self, keywords: Sequence[str] = _DEFAULT_KEYWORDS) -> None:
        self._keywords = tuple(_normalize_token(keyword) for keyword in keywords)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        token_counts = Counter(_tokenize(text))
        vector = [float(token_counts.get(keyword, 0)) for keyword in self._keywords]
        if not any(vector):
            vector[0] = 1.0
        return _normalize_vector(vector)


class RemoteEmbeddingError(RuntimeError):
    pass


class OpenRouterEmbedder:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
        base_url: str = OPENROUTER_EMBEDDINGS_URL,
        timeout: float = REMOTE_EMBEDDING_TIMEOUT_SECONDS,
        max_retries: int = 0,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self._model_name = model_name
        self._base_url = base_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = client

    @property
    def model_name(self) -> str:
        return self._model_name

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        if not self._api_key:
            raise RemoteEmbeddingError("OPENROUTER_API_KEY is required for OpenRouter embeddings")

        payload = {
            "model": self._model_name,
            "input": list(texts),
        }
        response = self._post_with_retries(payload)
        data = response.get("data")
        if not isinstance(data, list):
            raise RemoteEmbeddingError("OpenRouter embedding response did not include data")

        vectors_by_index: dict[int, list[float]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            index = item.get("index")
            embedding = item.get("embedding")
            if not isinstance(index, int) or not isinstance(embedding, list):
                continue
            vectors_by_index[index] = [float(value) for value in embedding]

        try:
            return [vectors_by_index[index] for index in range(len(texts))]
        except KeyError as error:
            raise RemoteEmbeddingError("OpenRouter embedding response was incomplete") from error

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
        raise RemoteEmbeddingError(f"OpenRouter embedding request failed: {last_error}") from last_error

    def _client_or_create(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                }
            )
        return self._client
