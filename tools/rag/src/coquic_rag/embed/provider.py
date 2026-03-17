from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

from coquic_rag.config import ProjectPaths

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

DEFAULT_EMBEDDING_MODEL = "mixedbread-ai/mxbai-embed-large-v1"
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


class SentenceTransformerEmbedder:
    def __init__(
        self,
        paths: ProjectPaths | None = None,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:
        self._paths = paths or ProjectPaths.default()
        self._model_name = model_name
        self._model: SentenceTransformer | None = None

    @property
    def model_name(self) -> str:
        return self._model_name

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        model = self._get_model()
        embeddings = model.encode(
            list(texts),
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return [[float(value) for value in row] for row in embeddings.tolist()]

    def _get_model(self) -> SentenceTransformer:
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._paths.model_cache_dir.mkdir(parents=True, exist_ok=True)
            self._model = SentenceTransformer(
                self._model_name,
                cache_folder=str(self._paths.model_cache_dir),
            )
        return self._model
