from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectPaths:
    repo_root: Path
    rfc_source: Path
    state_dir: Path
    model_cache_dir: Path

    @classmethod
    def default(cls) -> "ProjectPaths":
        repo_root = Path(__file__).resolve().parents[4]
        return cls(
            repo_root=repo_root,
            rfc_source=repo_root / "docs" / "rfc",
            state_dir=repo_root / ".rag",
            model_cache_dir=repo_root / ".rag" / "cache" / "models",
        )

