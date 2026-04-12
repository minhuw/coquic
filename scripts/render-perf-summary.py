#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def format_decimal(record: dict, field_name: str) -> str:
    value = record.get(field_name, 0.0)
    if isinstance(value, (int, float)):
        return f"{float(value):.3f}"
    raise ValueError(f"run field `{field_name}` must be numeric")


def load_manifest(path: Path) -> dict:
    try:
        content = path.read_text()
    except OSError as exc:
        raise ValueError(f"failed to read manifest: {exc}") from exc
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse manifest JSON: {exc.msg}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be an object")
    return manifest


def latency_value(latency: dict, field_name: str) -> int:
    value = latency.get(field_name, 0)
    if isinstance(value, (int, float)):
        return int(value)
    raise ValueError(f"latency field `{field_name}` must be numeric")


def row(record: dict) -> str:
    if not isinstance(record, dict):
        raise ValueError("each run must be an object")
    latency = record.get("latency", {})
    if latency is None:
        latency = {}
    if not isinstance(latency, dict):
        raise ValueError("run field `latency` must be an object")
    return (
        f"| {record.get('backend', '-')}"
        f" | {record.get('mode', '-')}"
        f" | {record.get('status', '-')}"
        f" | {record.get('elapsed_ms', '-')}"
        f" | {format_decimal(record, 'throughput_mib_per_s')}"
        f" | {format_decimal(record, 'requests_per_s')}"
        f" | {latency_value(latency, 'p50_us')}"
        f" | {latency_value(latency, 'p99_us')}"
        f" | {record.get('result_file', '-')} |"
    )


def main() -> int:
    args = parse_args()
    try:
        manifest = load_manifest(Path(args.manifest))
        runs = manifest.get("runs", [])
        if not isinstance(runs, list):
            raise ValueError("manifest field `runs` must be a list")

        print("## Advisory QUIC Perf")
        print()
        print(f"Event: `{args.event_name}`")
        print(f"Commit: `{args.commit}`")
        print(f"Preset: `{manifest.get('preset', 'unknown')}`")
        print(f"Image: `{manifest.get('image_tag', 'unknown')}`")
        print()
        print("Benchmark data from GitHub-hosted runners is advisory and may vary between runs.")
        print()

        if not runs:
            print("No benchmark runs were recorded.")
            return 0

        print("| Backend | Mode | Status | Elapsed (ms) | Throughput MiB/s | Requests/s | P50 us | P99 us | Result |")
        print("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |")
        for record in runs:
            print(row(record))

        failures = [record for record in runs if record.get("status") != "ok"]
        if failures:
            print()
            print("### Failures")
            for record in failures:
                backend = record.get("backend", "-")
                mode = record.get("mode", "-")
                reason = str(record.get("failure_reason", "unknown failure")).replace("\n", " ")
                print(f"- `{backend}/{mode}`: {reason}")
        return 0
    except ValueError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
