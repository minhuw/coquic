#!/usr/bin/env python3
import argparse
import datetime
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, help="latest perf-results.json payload")
    parser.add_argument("--history", help="existing perf-history.json payload")
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--max-days", type=int, default=180)
    return parser.parse_args()


def load_json(path: Path, required: bool) -> dict:
    try:
        content = path.read_text()
    except FileNotFoundError:
        if required:
            raise ValueError(f"missing required JSON file: {path}")
        return {}
    except OSError as exc:
        raise ValueError(f"failed to read `{path}`: {exc}") from exc
    if not content.strip() and not required:
        return {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse `{path}` JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"`{path}` root must be an object")
    return data


def snapshot_date(snapshot: dict) -> str:
    generated_at = str(snapshot.get("generated_at") or "")
    if generated_at.endswith("Z"):
        generated_at = generated_at[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(generated_at)
    except ValueError:
        parsed = datetime.datetime.now(datetime.UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC).date().isoformat()


def validate_snapshot(snapshot: dict) -> None:
    if snapshot.get("schema_version") != 1:
        raise ValueError("snapshot schema_version must be 1")
    if not isinstance(snapshot.get("sources"), list):
        raise ValueError("snapshot field `sources` must be a list")
    if not isinstance(snapshot.get("rows"), list):
        raise ValueError("snapshot field `rows` must be a list")


def build_history(existing: dict, snapshot: dict, max_days: int) -> dict:
    validate_snapshot(snapshot)
    if max_days <= 0:
        raise ValueError("--max-days must be positive")

    snapshots = existing.get("snapshots", [])
    if snapshots is None:
        snapshots = []
    if not isinstance(snapshots, list):
        raise ValueError("history field `snapshots` must be a list")

    date = snapshot_date(snapshot)
    compact_snapshot = {
        "date": date,
        "generated_at": snapshot.get("generated_at"),
        "event_name": snapshot.get("event_name"),
        "commit": snapshot.get("commit"),
        "sources": snapshot.get("sources", []),
        "rows": snapshot.get("rows", []),
    }

    by_date = {}
    for entry in snapshots:
        if not isinstance(entry, dict):
            continue
        entry_date = entry.get("date")
        if isinstance(entry_date, str) and entry_date:
            by_date[entry_date] = entry
    by_date[date] = compact_snapshot

    ordered = [by_date[key] for key in sorted(by_date)][-max_days:]
    return {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "max_days": max_days,
        "snapshots": ordered,
    }


def main() -> int:
    args = parse_args()
    try:
        snapshot = load_json(Path(args.snapshot), required=True)
        history = load_json(Path(args.history), required=False) if args.history else {}
        output = build_history(history, snapshot, args.max_days)
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(output, indent=2) + "\n")
        latest = output["snapshots"][-1]["date"] if output["snapshots"] else "none"
        print(f"perf history contains {len(output['snapshots'])} daily snapshots; latest={latest}")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
