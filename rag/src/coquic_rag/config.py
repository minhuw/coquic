from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def discover_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "build.zig").is_file():
            return candidate
    raise RuntimeError(f"Unable to find repository root from {start}")


@dataclass(frozen=True)
class ProjectPaths:
    repo_root: Path
    rfc_source: Path | None
    state_dir: Path
    qdrant_url: str | None = None
    qdrant_api_key: str | None = None

    @property
    def artifacts_dir(self) -> Path:
        return self.state_dir / "artifacts"

    @property
    def qdrant_dir(self) -> Path:
        return self.state_dir / "qdrant"

    @classmethod
    def default(cls) -> "ProjectPaths":
        repo_root = discover_repo_root(Path(__file__).resolve().parent)
        return cls(
            repo_root=repo_root,
            rfc_source=(
                Path(source)
                if (source := os.getenv("COQUIC_RFC_SOURCE")) is not None
                else None
            ),
            state_dir=repo_root / ".rag",
            qdrant_url=os.getenv("COQUIC_QDRANT_URL"),
            qdrant_api_key=os.getenv("COQUIC_QDRANT_API_KEY"),
        )
