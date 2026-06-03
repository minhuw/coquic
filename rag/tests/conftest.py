from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_qdrant_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COQUIC_QDRANT_URL", raising=False)
    monkeypatch.delenv("COQUIC_QDRANT_API_KEY", raising=False)
