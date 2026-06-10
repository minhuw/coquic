#!/usr/bin/env python3
import argparse
import datetime
import json
import sys
from pathlib import Path


MODE_ORDER = {
    "bulk": 0,
    "rr": 1,
    "persistent-rr": 2,
    "crr": 3,
}

CONGESTION_ORDER = {
    "newreno": 0,
    "cubic": 1,
    "bbr": 2,
    "copa": 3,
    "default": 4,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        action="append",
        required=True,
        help="benchmark manifest as LABEL=PATH; may be repeated",
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--json-out")
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def markdown(value: object) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def parse_manifest_spec(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        label, path = spec.split("=", 1)
        label = label.strip()
        path = path.strip()
        if not label:
            raise ValueError(f"manifest spec has an empty label: {spec}")
        if not path:
            raise ValueError(f"manifest spec has an empty path: {spec}")
        return label, Path(path)

    path = Path(spec)
    label = path.parent.name or path.stem
    return label, path


def load_manifest(path: Path) -> dict:
    try:
        content = path.read_text()
    except OSError as exc:
        raise ValueError(f"failed to read manifest `{path}`: {exc}") from exc
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse manifest `{path}` JSON: {exc.msg}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"manifest `{path}` root must be an object")
    runs = manifest.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError(f"manifest `{path}` field `runs` must be a list")
    return manifest


def number(record: dict, field_name: str, default: float = 0.0) -> float:
    value = record.get(field_name, default)
    if isinstance(value, (int, float)):
        return float(value)
    raise ValueError(f"run field `{field_name}` must be numeric")


def latency_number(record: dict, field_name: str) -> int:
    latency = record.get("latency", {})
    if latency is None:
        latency = {}
    if not isinstance(latency, dict):
        raise ValueError("run field `latency` must be an object")
    value = latency.get(field_name, 0)
    if isinstance(value, (int, float)):
        return int(value)
    raise ValueError(f"latency field `{field_name}` must be numeric")


def format_decimal(value: float) -> str:
    return f"{value:.3f}"


def algorithm_display_name(algorithm: str) -> str:
    names = {
        "newreno": "NewReno",
        "cubic": "CUBIC",
        "bbr": "BBR",
        "copa": "Copa",
        "default": "default",
    }
    return names.get(algorithm, algorithm)


def mode_display_name(mode: str) -> str:
    names = {
        "bulk": "Bulk Download",
        "rr": "Request/Response",
        "persistent-rr": "Persistent Request/Response",
        "crr": "Connection Request/Response",
    }
    return names.get(mode, mode)


def mode_sort_key(mode: str) -> tuple[int, str]:
    return (MODE_ORDER.get(mode, 100), mode)


def congestion_sort_key(algorithm: str) -> tuple[int, str]:
    return (CONGESTION_ORDER.get(algorithm, 100), algorithm)


def implementation_pair(manifest: dict) -> str:
    client = str(manifest.get("client_impl") or "coquic")
    server = str(manifest.get("server_impl") or client)
    return f"{client} -> {server}"


def library_version(manifest: dict) -> str:
    value = manifest.get("library_version")
    if value in (None, ""):
        return "unknown"
    return str(value)


def result_display(manifest_path: Path, record: dict) -> str:
    result_file = record.get("result_file", "-")
    if result_file in (None, ""):
        return "-"
    result_file = str(result_file)
    parent = manifest_path.parent.name
    if parent and parent != ".bench-results":
        return f"{parent}/{result_file}"
    return result_file


def artifact_display(manifest_path: Path, record: dict, field_name: str) -> str:
    value = record.get(field_name)
    if value in (None, ""):
        return ""
    value = str(value)
    parent = manifest_path.parent.name
    if parent and parent != ".bench-results" and "/" not in value:
        return f"{parent}/{value}"
    return value


def copy_object(record: dict, field_name: str) -> dict:
    value = record.get(field_name)
    if isinstance(value, dict):
        return value
    return {}


def normalize_profiles(manifest_path: Path, record: dict) -> dict:
    profiles = copy_object(record, "profiles")
    normalized = {}
    for role in ("client", "server"):
        profile = profiles.get(role)
        if not isinstance(profile, dict):
            continue
        entry = dict(profile)
        for file_field in ("svg_file", "log_file"):
            if entry.get(file_field):
                parent = manifest_path.parent.name
                value = str(entry[file_field])
                if parent and parent != ".bench-results" and "/" not in value:
                    entry[file_field] = f"{parent}/{value}"
        normalized[role] = entry
    return normalized


def row_from_run(label: str, manifest_path: Path, manifest: dict, record: dict) -> dict:
    if not isinstance(record, dict):
        raise ValueError("each run must be an object")
    mib = number(record, "throughput_mib_per_s")
    if "throughput_gbit_per_s" in record:
        gbit = number(record, "throughput_gbit_per_s")
    else:
        gbit = mib * 1024.0 * 1024.0 * 8.0 / 1_000_000_000.0
    return {
        "implementation": label,
        "pair": implementation_pair(manifest),
        "library_version": library_version(manifest),
        "mode": str(record.get("mode", "-")),
        "status": str(record.get("status", "-")),
        "congestion_control": str(record.get("congestion_control", "newreno")),
        "elapsed_ms": record.get("elapsed_ms", "-"),
        "throughput_mib_per_s": mib,
        "throughput_gbit_per_s": gbit,
        "requests_per_s": number(record, "requests_per_s"),
        "p50_us": latency_number(record, "p50_us"),
        "p99_us": latency_number(record, "p99_us"),
        "skipped_setup_errors": int(number(record, "skipped_setup_errors", 0.0)),
        "result": result_display(manifest_path, record),
        "stats_file": artifact_display(manifest_path, record, "stats_file"),
        "utilization": copy_object(record, "utilization"),
        "profiles": normalize_profiles(manifest_path, record),
        "failure_reason": str(record.get("failure_reason", "")),
    }


def rows_from_snapshot(label: str, path: Path, snapshot: dict) -> tuple[list[dict], list[dict]]:
    sources = snapshot.get("sources")
    rows = snapshot.get("rows")
    if not isinstance(sources, list) or not isinstance(rows, list):
        raise ValueError(f"snapshot `{path}` must contain sources and rows lists")

    normalized_sources = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError(f"snapshot `{path}` source entries must be objects")
        source_copy = dict(source)
        if not source_copy.get("label"):
            source_copy["label"] = label
        if not source_copy.get("library_version"):
            source_copy["library_version"] = "unknown"
        if not source_copy.get("missing"):
            source_copy["path"] = str(path)
        normalized_sources.append(source_copy)

    source_versions = {
        str(source.get("label")): str(source.get("library_version") or "unknown")
        for source in normalized_sources
    }
    normalized_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"snapshot `{path}` row entries must be objects")
        row_copy = dict(row)
        if not row_copy.get("library_version"):
            row_copy["library_version"] = source_versions.get(str(row_copy.get("implementation")), "unknown")
        normalized_rows.append(row_copy)

    return normalized_sources, normalized_rows


def primary_metric(row: dict) -> tuple[str, float, str]:
    if row["mode"] == "bulk":
        return ("Throughput MiB/s", row["throughput_mib_per_s"], format_decimal(row["throughput_mib_per_s"]))
    return ("Requests/s", row["requests_per_s"], format_decimal(row["requests_per_s"]))


def print_result_table(rows: list[dict]) -> None:
    print("| Implementation | Version | Pair | CC | Status | Elapsed ms | MiB/s | Gbit/s | Requests/s | P50 us | P99 us | Skipped Setup | Result |")
    print("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for row in rows:
        print(
            f"| {markdown(row['implementation'])}"
            f" | {markdown(row['library_version'])}"
            f" | {markdown(row['pair'])}"
            f" | {markdown(algorithm_display_name(row['congestion_control']))}"
            f" | {markdown(row['status'])}"
            f" | {markdown(row['elapsed_ms'])}"
            f" | {format_decimal(row['throughput_mib_per_s'])}"
            f" | {format_decimal(row['throughput_gbit_per_s'])}"
            f" | {format_decimal(row['requests_per_s'])}"
            f" | {row['p50_us']}"
            f" | {row['p99_us']}"
            f" | {row['skipped_setup_errors']}"
            f" | {markdown(row['result'])} |"
        )


def build_payload(manifest_specs: list[str]) -> tuple[list[dict], list[dict]]:
    sources = []
    rows = []
    for spec in manifest_specs:
        label, path = parse_manifest_spec(spec)
        if not path.exists():
            sources.append({"label": label, "path": str(path), "missing": True, "library_version": "unknown"})
            continue
        manifest = load_manifest(path)
        if "schema_version" in manifest and "sources" in manifest and "rows" in manifest:
            snapshot_sources, snapshot_rows = rows_from_snapshot(label, path, manifest)
            sources.extend(snapshot_sources)
            rows.extend(snapshot_rows)
            continue
        runs = manifest.get("runs", [])
        ok_count = sum(1 for record in runs if isinstance(record, dict) and record.get("status") == "ok")
        sources.append(
            {
                "label": label,
                "path": str(path),
                "missing": False,
                "preset": manifest.get("preset", "unknown"),
                "library_version": library_version(manifest),
                "ok_runs": ok_count,
                "total_runs": len(runs),
            }
        )
        for record in runs:
            rows.append(row_from_run(label, path, manifest, record))
    return sources, rows


def write_json_payload(args: argparse.Namespace, sources: list[dict], rows: list[dict]) -> None:
    output = {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_name": args.event_name,
        "commit": args.commit,
        "sources": sources,
        "rows": rows,
    }
    json_out = Path(args.json_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(output, indent=2) + "\n")


def main() -> int:
    args = parse_args()
    try:
        sources, rows = build_payload(args.manifest)
        if args.json_out:
            write_json_payload(args, sources, rows)

        print("## Advisory QUIC Perf Comparison")
        print()
        print(f"Event: `{args.event_name}`")
        print(f"Commit: `{args.commit}`")
        print()
        print("Benchmark data from GitHub-hosted runners is advisory and may vary between runs.")
        print()
        print("### Manifests")
        print()
        for source in sources:
            if source["missing"]:
                print(f"- `{markdown(source['label'])}`: missing `{markdown(source['path'])}`")
                continue
            print(
                f"- `{markdown(source['label'])}`: `{markdown(source['path'])}`"
                f" ({source['ok_runs']}/{source['total_runs']} ok, preset `{markdown(source['preset'])}`)"
                f", version `{markdown(source['library_version'])}`"
            )
        print()

        if not rows:
            print("No benchmark runs were recorded.")
            return 0

        print("### Best By Mode")
        print()
        print("| Mode | Leader | Version | Pair | CC | Metric | Value |")
        print("| --- | --- | --- | --- | --- | --- | ---: |")
        for mode in sorted({row["mode"] for row in rows}, key=mode_sort_key):
            ok_rows = [row for row in rows if row["mode"] == mode and row["status"] == "ok"]
            if not ok_rows:
                continue
            best = max(ok_rows, key=lambda row: primary_metric(row)[1])
            metric_name, _, value = primary_metric(best)
            print(
                f"| {markdown(mode_display_name(mode))}"
                f" | {markdown(best['implementation'])}"
                f" | {markdown(best['library_version'])}"
                f" | {markdown(best['pair'])}"
                f" | {markdown(algorithm_display_name(best['congestion_control']))}"
                f" | {markdown(metric_name)}"
                f" | {value} |"
            )
        print()

        for mode in sorted({row["mode"] for row in rows}, key=mode_sort_key):
            mode_rows = [row for row in rows if row["mode"] == mode]
            mode_rows.sort(
                key=lambda row: (
                    [source["label"] for source in sources].index(row["implementation"]),
                    congestion_sort_key(row["congestion_control"]),
                )
            )
            print(f"### {mode_display_name(mode)}")
            print()
            print_result_table(mode_rows)
            print()

        failures = [row for row in rows if row["status"] != "ok"]
        if failures:
            print("### Failures")
            print()
            for row in failures:
                reason = row["failure_reason"] or "unknown failure"
                print(
                    f"- `{markdown(row['implementation'])}/{markdown(row['congestion_control'])}/{markdown(row['mode'])}`:"
                    f" {markdown(reason)}"
                )
            print()

        return 0
    except ValueError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
