from __future__ import annotations

import asyncio
import sys

from . import PerfError
from .client import run_client
from .config import Role, parse_runtime_args
from .metrics import emit_summary, finalize_summary, new_run_summary
from .server import run_server


async def async_main(argv: list[str]) -> int:
    try:
        config = parse_runtime_args(argv)
    except Exception as error:
        print(error, file=sys.stderr)
        return 2

    if config.role == Role.SERVER:
        try:
            await run_server(config)
            return 0
        except Exception as error:
            print(error, file=sys.stderr)
            return 1

    summary = new_run_summary(config)
    try:
        summary = await run_client(config)
    except Exception as error:
        summary.status = "failed"
        summary.failure_reason = str(error)

    finalize_summary(summary)
    try:
        emit_summary(summary, config.json_out)
    except PerfError as error:
        print(error, file=sys.stderr)
        return 1
    return 0 if summary.status == "ok" else 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main(sys.argv[1:])))


if __name__ == "__main__":
    main()
