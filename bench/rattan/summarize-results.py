#!/usr/bin/env python3
"""Flatten Rattan benchmark result directories into CSV and JSON summaries."""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
from typing import Any


FIELDNAMES = [
    "run",
    "status",
    "trace_id",
    "source_trace_id",
    "source_window_index",
    "source_start_ms",
    "window_seconds",
    "corpus",
    "network",
    "mobility",
    "base_rtt_ms",
    "up_synthesized",
    "avg_down_mbps",
    "avg_up_mbps",
    "queue_bytes",
    "loss_rate",
    "congestion_control",
    "mode",
    "direction",
    "elapsed_ms",
    "warmup_ms",
    "bytes_sent",
    "bytes_received",
    "throughput_mib_per_s",
    "throughput_gbit_per_s",
    "requests_per_s",
    "requests_completed",
    "latency_avg_us",
    "latency_p50_us",
    "latency_p90_us",
    "latency_p99_us",
    "failure_reason",
]


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_exit_status(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def summarize_run(run_dir: pathlib.Path) -> dict[str, Any] | None:
    result = load_json(run_dir / "result.json")
    metadata_files = list(run_dir.glob("*.rattan.toml.json"))
    metadata = load_json(metadata_files[0]) if metadata_files else {}
    if not result and not metadata:
        return None

    trace = metadata.get("trace", {})
    latency = result.get("latency", {})
    exit_status = load_exit_status(run_dir / "rattan.exit")
    status = result.get("status")
    failure_reason = result.get("failure_reason", "")
    if not status:
        if exit_status and exit_status != "0":
            status = "rattan_failed"
            failure_reason = failure_reason or f"rattan exited {exit_status}"
        else:
            status = "missing"
    return {
        "run": run_dir.name,
        "status": status,
        "trace_id": trace.get("id", ""),
        "source_trace_id": trace.get("source_trace_id", ""),
        "source_window_index": trace.get("source_window_index", ""),
        "source_start_ms": trace.get("source_start_ms", ""),
        "window_seconds": trace.get("window_seconds", ""),
        "corpus": trace.get("corpus", ""),
        "network": trace.get("network", ""),
        "mobility": trace.get("mobility", ""),
        "base_rtt_ms": metadata.get("base_rtt_ms", trace.get("base_rtt_ms", "")),
        "up_synthesized": trace.get("up_synthesized", ""),
        "avg_down_mbps": metadata.get("avg_down_mbps", ""),
        "avg_up_mbps": metadata.get("avg_up_mbps", ""),
        "queue_bytes": metadata.get("queue_bytes", ""),
        "loss_rate": metadata.get("loss_rate", ""),
        "congestion_control": result.get("congestion_control", metadata.get("congestion_control", "")),
        "mode": result.get("mode", metadata.get("mode", "")),
        "direction": result.get("direction", metadata.get("direction", "")),
        "elapsed_ms": result.get("elapsed_ms", ""),
        "warmup_ms": result.get("warmup_ms", ""),
        "bytes_sent": result.get("bytes_sent", ""),
        "bytes_received": result.get("bytes_received", ""),
        "throughput_mib_per_s": result.get("throughput_mib_per_s", ""),
        "throughput_gbit_per_s": result.get("throughput_gbit_per_s", ""),
        "requests_per_s": result.get("requests_per_s", ""),
        "requests_completed": result.get("requests_completed", ""),
        "latency_avg_us": latency.get("avg_us", ""),
        "latency_p50_us": latency.get("p50_us", ""),
        "latency_p90_us": latency.get("p90_us", ""),
        "latency_p99_us": latency.get("p99_us", ""),
        "failure_reason": failure_reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root", type=pathlib.Path)
    args = parser.parse_args()

    rows = []
    for run_dir in sorted(path for path in args.results_root.iterdir() if path.is_dir()):
        row = summarize_run(run_dir)
        if row is not None:
            rows.append(row)

    csv_path = args.results_root / "summary.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    json_path = args.results_root / "summary.json"
    json_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(csv_path)
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
