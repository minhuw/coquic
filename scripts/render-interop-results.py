#!/usr/bin/env python3
import argparse
import datetime
import json
import sys
from pathlib import Path


RESULT_ORDER = {
    "succeeded": 0,
    "unsupported": 1,
    "failed": 2,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--result",
        action="append",
        required=True,
        help="official runner results JSON as LABEL=PATH; may be repeated",
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--json-out")
    return parser.parse_args()


def markdown(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def parse_result_spec(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        label, path = spec.split("=", 1)
        label = label.strip()
        path = path.strip()
        if not label:
            raise ValueError(f"result spec has an empty label: {spec}")
        if not path:
            raise ValueError(f"result spec has an empty path: {spec}")
        return label, Path(path)

    path = Path(spec)
    return path.parent.name or path.stem, path


def load_results(path: Path) -> dict:
    try:
        content = path.read_text()
    except OSError as exc:
        raise ValueError(f"failed to read result `{path}`: {exc}") from exc
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse result `{path}` JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"result `{path}` root must be an object")
    return data


def only_string(values: object, field_name: str, path: Path) -> str:
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise ValueError(f"result `{path}` field `{field_name}` must contain exactly one string")
    return values[0]


def result_entries(cell: object, field_name: str, path: Path) -> list[dict]:
    if cell is None:
        return []
    if not isinstance(cell, list):
        raise ValueError(f"result `{path}` field `{field_name}` must be a matrix list")
    if len(cell) == 0:
        return []
    if len(cell) != 1 or not isinstance(cell[0], list):
        raise ValueError(f"result `{path}` field `{field_name}` must contain one matrix row")
    entries = []
    for entry in cell[0]:
        if not isinstance(entry, dict):
            raise ValueError(f"result `{path}` field `{field_name}` entries must be objects")
        entries.append(entry)
    return entries


def status_counts(entries: list[dict]) -> dict:
    counts = {"succeeded": 0, "failed": 0, "unsupported": 0, "other": 0}
    for entry in entries:
        result = str(entry.get("result", ""))
        if result in counts:
            counts[result] += 1
        else:
            counts["other"] += 1
    counts["total"] = len(entries)
    return counts


def row_sort_key(row: dict) -> tuple[str, int, str]:
    return (row["peer"], RESULT_ORDER.get(row["result"], 100), row["name"])


def testcase_sort_key(row: dict) -> tuple[int, str]:
    order = {
        "handshake": 0,
        "handshakeloss": 1,
        "transfer": 2,
        "keyupdate": 3,
        "transferloss": 4,
        "handshakecorruption": 5,
        "transfercorruption": 6,
        "blackhole": 7,
        "chacha20": 8,
        "longrtt": 9,
        "ipv6": 10,
        "multiplexing": 11,
        "retry": 12,
        "resumption": 13,
        "zerortt": 14,
        "v2": 15,
        "amplificationlimit": 16,
        "rebind-port": 17,
        "rebind-addr": 18,
        "connectionmigration": 19,
        "ecn": 20,
        "goodput": 21,
        "crosstraffic": 22,
    }
    return (order.get(row["name"], 1000), row["name"])


def rows_from_result(label: str, path: Path, data: dict) -> tuple[dict, list[dict]]:
    server = only_string(data.get("servers"), "servers", path)
    client = only_string(data.get("clients"), "clients", path)
    peer = client if server == "coquic" else server
    direction = "coquic-server" if server == "coquic" else "coquic-client"
    rows = []

    for kind, entries in (
        ("test", result_entries(data.get("results"), "results", path)),
        ("measurement", result_entries(data.get("measurements"), "measurements", path)),
    ):
        for entry in entries:
            name = str(entry.get("name", ""))
            if not name:
                raise ValueError(f"result `{path}` has an entry without a name")
            result = str(entry.get("result", "unknown"))
            rows.append(
                {
                    "label": label,
                    "peer": peer,
                    "server": server,
                    "client": client,
                    "direction": direction,
                    "kind": kind,
                    "abbr": str(entry.get("abbr", "")),
                    "name": name,
                    "result": result,
                    "details": str(entry.get("details", "")),
                }
            )

    counts = status_counts(rows)
    source = {
        "label": label,
        "path": str(path),
        "missing": False,
        "server": server,
        "client": client,
        "peer": peer,
        "direction": direction,
        "start_time": data.get("start_time"),
        "end_time": data.get("end_time"),
        "quic_version": data.get("quic_version", ""),
        "succeeded": counts["succeeded"],
        "failed": counts["failed"],
        "unsupported": counts["unsupported"],
        "other": counts["other"],
        "total": counts["total"],
    }
    return source, sorted(rows, key=testcase_sort_key)


def rows_from_snapshot(label: str, path: Path, data: dict) -> tuple[list[dict], list[dict]]:
    sources = data.get("sources")
    rows = data.get("rows")
    if not isinstance(sources, list) or not isinstance(rows, list):
        raise ValueError(f"snapshot `{path}` must contain sources and rows lists")

    normalized_sources = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError(f"snapshot `{path}` source entries must be objects")
        source_copy = dict(source)
        if not source_copy.get("missing"):
            source_copy["path"] = str(path)
        if not source_copy.get("label"):
            source_copy["label"] = label
        normalized_sources.append(source_copy)

    normalized_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"snapshot `{path}` row entries must be objects")
        normalized_rows.append(dict(row))

    return normalized_sources, normalized_rows


def build_payload(result_specs: list[str]) -> tuple[list[dict], list[dict]]:
    sources = []
    rows = []
    for spec in result_specs:
        label, path = parse_result_spec(spec)
        if not path.exists():
            sources.append({"label": label, "path": str(path), "missing": True})
            continue
        data = load_results(path)
        if "schema_version" in data and "sources" in data and "rows" in data:
            snapshot_sources, snapshot_rows = rows_from_snapshot(label, path, data)
            sources.extend(snapshot_sources)
            rows.extend(snapshot_rows)
        else:
            source, result_rows = rows_from_result(label, path, data)
            sources.append(source)
            rows.extend(result_rows)
    return sources, sorted(rows, key=row_sort_key)


def write_json_payload(args: argparse.Namespace, sources: list[dict], rows: list[dict]) -> None:
    output = {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_name": args.event_name,
        "commit": args.commit,
        "sources": sources,
        "rows": rows,
    }
    output_path = Path(args.json_out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n")


def print_summary(sources: list[dict], rows: list[dict], event_name: str, commit: str) -> None:
    print("## Official QUIC Interop Results")
    print()
    print(f"Event: `{event_name}`")
    print(f"Commit: `{commit}`")
    print()
    print("### Sources")
    print()
    for source in sources:
        if source.get("missing"):
            print(f"- `{markdown(source['label'])}`: missing `{markdown(source['path'])}`")
            continue
        if "server" not in source or "client" not in source:
            print(f"- `{markdown(source['label'])}`: `{markdown(source['path'])}`")
            continue
        print(
            f"- `{markdown(source['label'])}`: `{markdown(source['server'])}` -> `{markdown(source['client'])}` "
            f"({source['succeeded']}/{source['total']} succeeded)"
        )
    print()
    print("### Failed Or Unsupported Cases")
    print()
    notable = [row for row in rows if row["result"] != "succeeded"]
    if not notable:
        print("All loaded interop cases succeeded.")
        return
    print("| Peer | Direction | Case | Result | Details |")
    print("| --- | --- | --- | --- | --- |")
    for row in notable:
        print(
            f"| {markdown(row['peer'])}"
            f" | {markdown(row['direction'])}"
            f" | {markdown(row['name'])}"
            f" | {markdown(row['result'])}"
            f" | {markdown(row['details'])} |"
        )


def main() -> int:
    args = parse_args()
    try:
        sources, rows = build_payload(args.result)
        if args.json_out:
            write_json_payload(args, sources, rows)
        print_summary(sources, rows, args.event_name, args.commit)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
