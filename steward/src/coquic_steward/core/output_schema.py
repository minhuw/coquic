"""Shared filesystem implementation for runtime output schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .config import StewardConfig


def write_output_schema_file(
    config: StewardConfig,
    filename: str,
    schema: Mapping[str, Any],
    *,
    trailing_newline: bool = False,
) -> Path:
    """Write one runtime output schema and return its path."""

    path = config.state_dir / "schemas" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(schema, indent=2)
    if trailing_newline:
        content += "\n"
    path.write_text(content, encoding="utf-8")
    return path
