#!/usr/bin/env python3
import argparse
import datetime
import json
import re
import sys
from pathlib import Path


SAFE_HISTORY_FILE = re.compile(r"^[0-9A-Za-z._-]+\.json$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, help="latest perf-results.json payload")
    parser.add_argument("--history", help="existing legacy perf-history.json payload")
    parser.add_argument("--history-index", help="existing perf-history/index.json payload")
    parser.add_argument("--json-out", help="write legacy perf-history.json payload")
    parser.add_argument("--out-dir", help="write append-style perf-history directory")
    parser.add_argument("--run-id", help="unique CI run identifier to include in new history file names")
    parser.add_argument("--max-days", type=int, default=180)
    parser.add_argument("--max-snapshots", type=int, default=365)
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


def parse_instant(value: object) -> datetime.datetime | None:
    generated_at = str(value or "")
    if not generated_at:
        return None
    if generated_at.endswith("Z"):
        generated_at = generated_at[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(generated_at)
    except ValueError:
        try:
            parsed_date = datetime.date.fromisoformat(generated_at)
        except ValueError:
            return None
        parsed = datetime.datetime.combine(parsed_date, datetime.time(), tzinfo=datetime.UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC)


def entry_instant(entry: dict) -> datetime.datetime:
    return parse_instant(entry.get("generated_at")) or parse_instant(entry.get("date")) or datetime.datetime.now(datetime.UTC)


def snapshot_date(snapshot: dict) -> str:
    date = snapshot.get("date")
    if isinstance(date, str) and date:
        return date
    return entry_instant(snapshot).date().isoformat()


def safe_file_component(value: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z._-]+", "-", value).strip("-._")
    return normalized[:80]


def history_file_name(snapshot: dict, suffix: str | None = None) -> str:
    instant = entry_instant(snapshot)
    stamp = instant.strftime("%Y-%m-%dT%H%M%SZ")
    safe_suffix = safe_file_component(suffix or "")
    if safe_suffix:
        return f"{stamp}-{safe_suffix}.json"
    commit = safe_file_component(str(snapshot.get("commit") or ""))[:12]
    if commit:
        return f"{stamp}-{commit}.json"
    return f"{stamp}.json"


def validate_snapshot(snapshot: dict) -> None:
    if snapshot.get("schema_version") != 1:
        raise ValueError("snapshot schema_version must be 1")
    if not isinstance(snapshot.get("sources"), list):
        raise ValueError("snapshot field `sources` must be a list")
    if not isinstance(snapshot.get("rows"), list):
        raise ValueError("snapshot field `rows` must be a list")


def compact_snapshot(snapshot: dict, run_id: str | None = None) -> dict:
    compact = {
        "schema_version": 1,
        "date": snapshot_date(snapshot),
        "generated_at": snapshot.get("generated_at"),
        "event_name": snapshot.get("event_name"),
        "commit": snapshot.get("commit"),
        "sources": snapshot.get("sources", []),
        "rows": snapshot.get("rows", []),
    }
    if run_id:
        compact["run_id"] = run_id
    return compact


def metadata_from_snapshot(path: str, snapshot: dict) -> dict:
    metadata = {
        "date": snapshot_date(snapshot),
        "generated_at": snapshot.get("generated_at"),
        "event_name": snapshot.get("event_name"),
        "commit": snapshot.get("commit"),
        "path": path,
    }
    if snapshot.get("run_id"):
        metadata["run_id"] = snapshot.get("run_id")
    return {key: value for key, value in metadata.items() if value not in (None, "")}


def metadata_from_index_entry(entry: dict) -> dict | None:
    path = entry.get("path")
    if not isinstance(path, str) or not SAFE_HISTORY_FILE.fullmatch(path) or path == "index.json":
        return None
    metadata = {
        "date": entry.get("date"),
        "generated_at": entry.get("generated_at"),
        "event_name": entry.get("event_name"),
        "commit": entry.get("commit"),
        "path": path,
    }
    if entry.get("run_id"):
        metadata["run_id"] = entry.get("run_id")
    if not isinstance(metadata.get("date"), str) or not metadata["date"]:
        metadata["date"] = entry_instant(metadata).date().isoformat()
    return {key: value for key, value in metadata.items() if value not in (None, "")}


def append_entry(entries_by_path: dict[str, dict], metadata: dict, payload: dict | None) -> None:
    path = metadata["path"]
    existing = entries_by_path.get(path)
    if existing is None or payload is not None:
        entries_by_path[path] = {
            "metadata": metadata,
            "payload": payload,
        }


def add_index_entries(entries_by_path: dict[str, dict], index: dict) -> int:
    snapshots = index.get("snapshots", [])
    if snapshots is None:
        snapshots = []
    if not isinstance(snapshots, list):
        raise ValueError("history index field `snapshots` must be a list")
    added = 0
    for entry in snapshots:
        if not isinstance(entry, dict):
            continue
        metadata = metadata_from_index_entry(entry)
        if metadata is None:
            continue
        append_entry(entries_by_path, metadata, None)
        added += 1
    return added


def add_legacy_entries(entries_by_path: dict[str, dict], history: dict) -> int:
    snapshots = history.get("snapshots", [])
    if snapshots is None:
        snapshots = []
    if not isinstance(snapshots, list):
        raise ValueError("legacy history field `snapshots` must be a list")
    added = 0
    for entry in snapshots:
        if not isinstance(entry, dict):
            continue
        if not isinstance(entry.get("sources"), list) or not isinstance(entry.get("rows"), list):
            continue
        payload = compact_snapshot(entry)
        path = history_file_name(payload)
        append_entry(entries_by_path, metadata_from_snapshot(path, payload), payload)
        added += 1
    return added


def retain_entries(entries_by_path: dict[str, dict], max_days: int, max_snapshots: int) -> list[dict]:
    if max_days <= 0:
        raise ValueError("--max-days must be positive")
    if max_snapshots <= 0:
        raise ValueError("--max-snapshots must be positive")

    entries = list(entries_by_path.values())
    if not entries:
        return []
    entries.sort(key=lambda entry: (entry_instant(entry["metadata"]), entry["metadata"]["path"]))
    latest = max(entry_instant(entry["metadata"]) for entry in entries)
    cutoff = latest - datetime.timedelta(days=max_days)
    retained = [entry for entry in entries if entry_instant(entry["metadata"]) >= cutoff]
    if len(retained) > max_snapshots:
        retained = retained[-max_snapshots:]
    return retained


def build_index(entries: list[dict], max_days: int, max_snapshots: int) -> dict:
    return {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "max_days": max_days,
        "max_snapshots": max_snapshots,
        "snapshots": [entry["metadata"] for entry in entries],
    }


def build_history(snapshot: dict, history_index: dict, legacy_history: dict, max_days: int, max_snapshots: int, run_id: str | None) -> tuple[dict, list[dict]]:
    validate_snapshot(snapshot)

    entries_by_path: dict[str, dict] = {}
    index_count = add_index_entries(entries_by_path, history_index)
    if index_count == 0:
        add_legacy_entries(entries_by_path, legacy_history)

    latest_snapshot = compact_snapshot(snapshot, run_id)
    latest_path = history_file_name(latest_snapshot, run_id)
    append_entry(entries_by_path, metadata_from_snapshot(latest_path, latest_snapshot), latest_snapshot)

    entries = retain_entries(entries_by_path, max_days, max_snapshots)
    return build_index(entries, max_days, max_snapshots), entries


def write_append_history(out_dir: Path, index: dict, entries: list[dict]) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    emitted = 0
    for entry in entries:
        payload = entry.get("payload")
        if payload is None:
            continue
        output_path = out_dir / entry["metadata"]["path"]
        output_path.write_text(json.dumps(payload, indent=2) + "\n")
        emitted += 1
    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    keep = "\n".join(entry["metadata"]["path"] for entry in entries) + "\n"
    (out_dir / ".keep.txt").write_text(keep)
    return emitted


def write_legacy_history(json_out: Path, index: dict, entries: list[dict]) -> int:
    snapshots = [entry["payload"] for entry in entries if entry.get("payload") is not None]
    output = {
        "schema_version": 1,
        "generated_at": index["generated_at"],
        "max_days": index["max_days"],
        "snapshots": snapshots,
    }
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(output, indent=2) + "\n")
    return len(snapshots)


def main() -> int:
    args = parse_args()
    if not args.out_dir and not args.json_out:
        print("error: at least one of --out-dir or --json-out is required", file=sys.stderr)
        return 1
    try:
        snapshot = load_json(Path(args.snapshot), required=True)
        history_index = load_json(Path(args.history_index), required=False) if args.history_index else {}
        legacy_history = load_json(Path(args.history), required=False) if args.history else {}
        index, entries = build_history(snapshot, history_index, legacy_history, args.max_days, args.max_snapshots, args.run_id)
        emitted = 0
        if args.out_dir:
            emitted = write_append_history(Path(args.out_dir), index, entries)
        legacy_count = 0
        if args.json_out:
            legacy_count = write_legacy_history(Path(args.json_out), index, entries)
        latest = index["snapshots"][-1]["path"] if index["snapshots"] else "none"
        print(
            f"perf history index contains {len(index['snapshots'])} snapshots; "
            f"emitted={emitted}; legacy_snapshots={legacy_count}; latest={latest}"
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
