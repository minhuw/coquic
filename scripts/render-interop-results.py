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
    parser.add_argument(
        "--upstream-result",
        help=(
            "optional upstream interop.seemann.io result JSON used to annotate "
            "failed rows that are known to fail for the peer across all supported peers"
        ),
    )
    parser.add_argument(
        "--require-complete-sources",
        action="store_true",
        help="fail if any requested result source is missing",
    )
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


def matrix_entries(data: dict, field_name: str, path: Path) -> list[list[dict]]:
    value = data.get(field_name)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"result `{path}` field `{field_name}` must be a matrix list")
    matrix = []
    for cell in value:
        if not isinstance(cell, list):
            raise ValueError(f"result `{path}` field `{field_name}` matrix cells must be lists")
        entries = []
        for entry in cell:
            if not isinstance(entry, dict):
                raise ValueError(f"result `{path}` field `{field_name}` entries must be objects")
            entries.append(entry)
        matrix.append(entries)
    return matrix


def row_known_broken_key(row: dict) -> tuple[str, str, str] | None:
    if row.get("result") != "failed":
        return None
    if row.get("server") == "coquic":
        return ("client", str(row.get("client", "")), str(row.get("name", "")))
    if row.get("client") == "coquic":
        return ("server", str(row.get("server", "")), str(row.get("name", "")))
    return None


def build_known_broken_index(upstream_path: Path) -> dict[tuple[str, str, str], dict]:
    data = load_results(upstream_path)
    servers = data.get("servers")
    clients = data.get("clients")
    if not isinstance(servers, list) or not all(isinstance(item, str) for item in servers):
        raise ValueError(f"upstream result `{upstream_path}` field `servers` must be a string list")
    if not isinstance(clients, list) or not all(isinstance(item, str) for item in clients):
        raise ValueError(f"upstream result `{upstream_path}` field `clients` must be a string list")

    expected_cells = len(servers) * len(clients)
    matrices = (
        ("results", matrix_entries(data, "results", upstream_path)),
        ("measurements", matrix_entries(data, "measurements", upstream_path)),
    )
    for field_name, cells in matrices:
        if len(cells) not in (0, expected_cells):
            raise ValueError(
                f"upstream result `{upstream_path}` field `{field_name}` has {len(cells)} "
                f"matrix cells, expected {expected_cells}"
            )

    observations: dict[tuple[str, str, str], dict[str, object]] = {}
    for _field_name, cells in matrices:
        for index, entries in enumerate(cells):
            client = clients[index // len(servers)]
            server = servers[index % len(servers)]
            for entry in entries:
                name = entry.get("name")
                result = entry.get("result")
                if not isinstance(name, str) or not isinstance(result, str):
                    continue
                for role, peer, counterpart in (
                    ("client", client, server),
                    ("server", server, client),
                ):
                    key = (role, peer, name)
                    observed = observations.setdefault(
                        key,
                        {
                            "role": role,
                            "peer": peer,
                            "name": name,
                            "failed": 0,
                            "succeeded": 0,
                            "unsupported": 0,
                            "other": 0,
                            "failed_peers": [],
                            "succeeded_peers": [],
                        },
                    )
                    if result == "failed":
                        observed["failed"] = int(observed["failed"]) + 1
                        observed["failed_peers"].append(counterpart)
                    elif result == "succeeded":
                        observed["succeeded"] = int(observed["succeeded"]) + 1
                        observed["succeeded_peers"].append(counterpart)
                    elif result == "unsupported":
                        observed["unsupported"] = int(observed["unsupported"]) + 1
                    else:
                        observed["other"] = int(observed["other"]) + 1

    run_id = str(data.get("log_dir") or "latest")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    known = {}
    for key, observed in observations.items():
        failed = int(observed["failed"])
        succeeded = int(observed["succeeded"])
        other = int(observed["other"])
        if failed == 0 or succeeded != 0 or other != 0:
            continue
        known[key] = {
            "source": "interop.seemann.io",
            "run": run_id,
            "start_time": start_time,
            "end_time": end_time,
            "role": observed["role"],
            "peer": observed["peer"],
            "case": observed["name"],
            "failed_supported_peers": failed,
            "succeeded_supported_peers": succeeded,
            "supported_peers": failed + succeeded + other,
            "unsupported_peers": int(observed["unsupported"]),
            "failed_peers": sorted(str(peer) for peer in observed["failed_peers"]),
            "reason": "upstream peer fails this case against every supported peer",
        }
    return known


def annotate_known_broken(rows: list[dict], known: dict[tuple[str, str, str], dict]) -> None:
    for row in rows:
        key = row_known_broken_key(row)
        if key is not None and key in known:
            row["known_broken"] = known[key]


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


def validate_complete_sources(sources: list[dict]) -> None:
    missing = [
        str(source.get("label", source.get("path", "unknown")))
        for source in sources
        if source.get("missing")
    ]
    if missing:
        raise ValueError(f"missing required interop result sources: {', '.join(missing)}")


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
            f"({source['succeeded']}/{source['total']} succeeded, "
            f"{source['unsupported']} unsupported, {source['failed']} failed)"
        )
    print()
    print("### Failed Cases")
    print()
    failed = [row for row in rows if row["result"] == "failed"]
    if not failed:
        print("No loaded interop cases failed.")
    else:
        print("| Peer | Direction | Case | Details |")
        print("| --- | --- | --- | --- |")
        for row in failed:
            known = row.get("known_broken")
            known_note = ""
            if isinstance(known, dict):
                known_note = (
                    f" known peer-broken: all {known.get('supported_peers', 0)} "
                    "supported upstream peers failed"
                )
            print(
                f"| {markdown(row['peer'])}"
                f" | {markdown(row['direction'])}"
                f" | {markdown(row['name'])}"
                f" | {markdown((row['details'] + ';' if row['details'] and known_note else row['details']) + known_note)} |"
            )
    unsupported = [row for row in rows if row["result"] == "unsupported"]
    if not unsupported:
        return
    print()
    print("### Unsupported Cases")
    print()
    print("| Peer | Direction | Case | Result | Details |")
    print("| --- | --- | --- | --- | --- |")
    for row in unsupported:
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
        if args.upstream_result:
            try:
                annotate_known_broken(rows, build_known_broken_index(Path(args.upstream_result)))
            except ValueError as exc:
                print(f"warning: ignoring upstream interop result: {exc}", file=sys.stderr)
        if args.require_complete_sources:
            validate_complete_sources(sources)
        if args.json_out:
            write_json_payload(args, sources, rows)
        print_summary(sources, rows, args.event_name, args.commit)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
