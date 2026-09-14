"""Shared stdlib-only private TOML reader for daemon and host bootstrap."""
from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from typing import Any


def _read_toml(path: Path, *, required: bool) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if required:
            raise FileNotFoundError("Steward configuration file is unavailable") from None
        return {}
    except OSError:
        raise ValueError("Steward configuration must be a readable non-symlink regular file") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Steward configuration must be a non-symlink regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            try:
                data = tomllib.load(handle)
            except (tomllib.TOMLDecodeError, UnicodeDecodeError):
                raise ValueError("invalid Steward TOML configuration") from None
        steward = data.get("steward", data)
        if isinstance(steward, dict) and "authentication" in steward:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o400}
            ):
                raise ValueError(
                    "steward.authentication requires a configuration file owned by "
                    "the current user with mode 0600 or 0400"
                )
        return data
    finally:
        os.close(descriptor)
