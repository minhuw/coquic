from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def discover_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "build.zig").is_file() and (candidate / "docs" / "rfc").is_dir():
            return candidate
    raise RuntimeError(f"Unable to find repository root from {start}")


@dataclass(frozen=True)
class ProjectPaths:
    repo_root: Path
    rfc_source: Path
    state_dir: Path
    model_cache_dir: Path

    @classmethod
    def default(cls) -> "ProjectPaths":
        repo_root = discover_repo_root(Path(__file__).resolve().parent)
        return cls(
            repo_root=repo_root,
            rfc_source=repo_root / "docs" / "rfc",
            state_dir=repo_root / ".rag",
            model_cache_dir=repo_root / ".rag" / "cache" / "models",
        )
