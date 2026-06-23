#!/usr/bin/env python3
"""Download WAN traces and convert them to Rattan-friendly Mahimahi traces."""

from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import re
import shutil
import sys
import urllib.request
from dataclasses import dataclass
from typing import Iterable


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = REPO_ROOT / "bench" / "rattan" / "trace-corpus.json"
DEFAULT_STATE_DIR = REPO_ROOT / ".bench-traces"
MTU_BYTES = 1500


@dataclass(frozen=True)
class PreparedTrace:
    trace_id: str
    catalog_entry: dict
    down_trace: pathlib.Path
    up_trace: pathlib.Path
    metadata_path: pathlib.Path


def load_catalog(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


def selected_entries(catalog: dict, subset: str, trace_ids: set[str]) -> list[dict]:
    entries = []
    for entry in catalog["traces"]:
        if trace_ids and entry["id"] not in trace_ids:
            continue
        subsets = set(entry.get("subset", []))
        if trace_ids or subset in subsets:
            entries.append(entry)
    return entries


def download_file(url: str, output: pathlib.Path, force: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not force:
        return
    tmp = output.with_suffix(output.suffix + ".tmp")
    with urllib.request.urlopen(url) as response, tmp.open("wb") as output_file:
        shutil.copyfileobj(response, output_file)
    tmp.replace(output)


def parse_float_tokens(line: str) -> list[float]:
    return [float(match) for match in re.findall(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?", line)]


def bandwidth_value_mbps(text: str, values: list[float]) -> float | None:
    if not values:
        return None
    throughput = values[0] if len(values) == 1 else values[-1]
    lowered = text.lower()
    if "kbits/sec" in lowered or "kbit/sec" in lowered or "kbps" in lowered:
        throughput /= 1000.0
    elif "bits/sec" in lowered or "bit/sec" in lowered or "bps" in lowered:
        if "mbits/sec" not in lowered and "mbit/sec" not in lowered and "mbps" not in lowered:
            throughput /= 1_000_000.0
    return throughput


def parse_time_throughput(path: pathlib.Path) -> list[tuple[float, float]]:
    samples: list[tuple[float, float]] = []
    fallback_time = 0.0
    with path.open("r", encoding="utf-8", errors="replace") as input_file:
        for raw_line in input_file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            values = parse_float_tokens(line)
            if not values:
                continue
            if len(values) >= 2:
                timestamp = values[0]
                throughput_mbps = bandwidth_value_mbps(line, values[1:])
            else:
                timestamp = fallback_time
                throughput_mbps = bandwidth_value_mbps(line, values)
            if throughput_mbps is None:
                continue
            if math.isfinite(timestamp) and math.isfinite(throughput_mbps):
                samples.append((max(timestamp, 0.0), max(throughput_mbps, 0.0)))
                fallback_time = max(fallback_time + 1.0, timestamp + 1.0)
    return samples


def parse_throughput_csv(path: pathlib.Path) -> list[tuple[float, float]]:
    samples: list[tuple[float, float]] = []
    timestamp = 0.0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as input_file:
        reader = csv.reader(input_file)
        for row in reader:
            text = ",".join(row).strip()
            if not text or text.startswith("#"):
                continue
            values = parse_float_tokens(text)
            if not values:
                continue
            throughput_mbps = bandwidth_value_mbps(text, values)
            if throughput_mbps is None:
                continue
            if math.isfinite(throughput_mbps):
                samples.append((timestamp, max(throughput_mbps, 0.0)))
                timestamp += 1.0
    return samples


def write_mahimahi_from_samples(samples: list[tuple[float, float]], output: pathlib.Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if not samples:
        raise ValueError(f"no bandwidth samples for {output}")

    expanded: list[int] = []
    sorted_samples = sorted(samples)
    for index, (timestamp, throughput_mbps) in enumerate(sorted_samples):
        next_timestamp = (
            sorted_samples[index + 1][0]
            if index + 1 < len(sorted_samples)
            else max(timestamp + 1.0, timestamp)
        )
        duration_s = max(next_timestamp - timestamp, 0.001)
        packet_count = int(round(throughput_mbps * 1_000_000.0 * duration_s / (8.0 * MTU_BYTES)))
        start_ms = int(round(timestamp * 1000.0))
        duration_ms = max(int(round(duration_s * 1000.0)), 1)
        for packet_index in range(max(packet_count, 1 if throughput_mbps > 0 else 0)):
            expanded.append(start_ms + int(packet_index * duration_ms / max(packet_count, 1)))

    if not expanded:
        expanded = [0]
    with output.open("w", encoding="utf-8") as output_file:
        for timestamp_ms in expanded:
            output_file.write(f"{timestamp_ms}\n")


def copy_mahimahi(input_path: pathlib.Path, output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(input_path, output_path)


def synthesize_reverse_trace(forward_trace: pathlib.Path, output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if forward_trace.resolve() == output_path.resolve():
        return
    shutil.copyfile(forward_trace, output_path)


def convert_time_series_entry(fmt: str, input_path: pathlib.Path, output_path: pathlib.Path) -> None:
    if fmt == "time-throughput-mbps":
        write_mahimahi_from_samples(parse_time_throughput(input_path), output_path)
        return
    if fmt == "throughput-mbps-csv":
        write_mahimahi_from_samples(parse_throughput_csv(input_path), output_path)
        return
    raise ValueError(f"unsupported time-series trace format: {fmt}")


def convert_entry(
    entry: dict,
    raw_dir: pathlib.Path,
    rattan_dir: pathlib.Path,
    force: bool,
    direction_model: str = "symmetric",
) -> PreparedTrace:
    trace_id = entry["id"]
    entry_raw_dir = raw_dir / trace_id
    entry_out_dir = rattan_dir / trace_id
    fmt = entry["format"]
    downloads = entry.get("download", {})
    up_synthesized = False

    if fmt == "zip-manual":
        archive_url = downloads.get("archive")
        raise RuntimeError(
            f"{trace_id} is a large/manual archive. Download explicitly from {archive_url} "
            "and add a source-specific converter before including it in automated runs."
        )

    raw_down = entry_raw_dir / "down.raw"
    raw_up = entry_raw_dir / "up.raw"
    if "down" in downloads:
        download_file(downloads["down"], raw_down, force)
    if "up" in downloads:
        download_file(downloads["up"], raw_up, force)

    down_trace = entry_out_dir / "down.trace"
    up_trace = entry_out_dir / "up.trace"

    if fmt == "mahimahi-pair":
        if "down" not in downloads or "up" not in downloads:
            raise ValueError(f"{trace_id} mahimahi-pair entries need both down and up downloads")
        copy_mahimahi(raw_down, down_trace)
        if direction_model == "measured":
            copy_mahimahi(raw_up, up_trace)
        else:
            synthesize_reverse_trace(down_trace, up_trace)
            up_synthesized = True
    elif fmt in {"time-throughput-mbps", "throughput-mbps-csv"}:
        convert_time_series_entry(fmt, raw_down, down_trace)
        if direction_model == "measured" and "up" in downloads:
            convert_time_series_entry(fmt, raw_up, up_trace)
        else:
            synthesize_reverse_trace(down_trace, up_trace)
            up_synthesized = True
    else:
        raise ValueError(f"unsupported trace format for {trace_id}: {fmt}")

    metadata = {
        "id": trace_id,
        "source": entry,
        "down_trace": str(down_trace),
        "up_trace": str(up_trace),
        "up_synthesized": up_synthesized,
        "direction_model": direction_model,
        "base_rtt_ms": entry.get("base_rtt_ms", 50),
        "format": fmt,
        "generated_by": "bench/rattan/prepare-traces.py",
    }
    metadata_path = entry_out_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return PreparedTrace(trace_id, entry, down_trace, up_trace, metadata_path)


def write_manifest(prepared: Iterable[PreparedTrace], output_path: pathlib.Path, catalog: dict) -> None:
    records = []
    for item in prepared:
        records.append(
            {
                "id": item.trace_id,
                "corpus": item.catalog_entry.get("corpus"),
                "subset": item.catalog_entry.get("subset", []),
                "network": item.catalog_entry.get("network"),
                "mobility": item.catalog_entry.get("mobility"),
                "base_rtt_ms": item.catalog_entry.get("base_rtt_ms", 50),
                "down_trace": str(item.down_trace),
                "up_trace": str(item.up_trace),
                "up_synthesized": json.loads(item.metadata_path.read_text(encoding="utf-8")).get(
                    "up_synthesized", False
                ),
                "direction_model": json.loads(item.metadata_path.read_text(encoding="utf-8")).get(
                    "direction_model", "symmetric"
                ),
                "format": item.catalog_entry.get("format"),
                "metadata": str(item.metadata_path),
            }
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "schema_version": catalog.get("schema_version", 1),
                "traces": records,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=pathlib.Path, default=DEFAULT_CATALOG)
    parser.add_argument("--state-dir", type=pathlib.Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--subset", default=None, help="Trace subset to prepare, default from catalog.")
    parser.add_argument("--trace-id", action="append", default=[], help="Prepare a specific trace id.")
    parser.add_argument("--force", action="store_true", help="Redownload existing raw files.")
    parser.add_argument("--allow-large-manual", action="store_true", help="Try entries marked manual/large.")
    parser.add_argument(
        "--direction-model",
        choices=["symmetric", "measured"],
        default="symmetric",
        help="Use downlink traces for both directions, or preserve measured uplink where available.",
    )
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    subset = args.subset or catalog.get("default_subset", "smoke")
    trace_ids = set(args.trace_id)
    entries = selected_entries(catalog, subset, trace_ids)
    if not entries:
        print(f"no traces selected for subset={subset!r}", file=sys.stderr)
        return 2

    raw_dir = args.state_dir / "raw"
    rattan_dir = args.state_dir / "rattan"
    prepared: list[PreparedTrace] = []
    for entry in entries:
        if entry.get("format") == "zip-manual" and not args.allow_large_manual:
            print(f"skip manual/large trace {entry['id']}", file=sys.stderr)
            continue
        prepared.append(convert_entry(entry, raw_dir, rattan_dir, args.force, args.direction_model))
        print(f"prepared {entry['id']}", file=sys.stderr)

    manifest_path = args.state_dir / "manifest.json"
    write_manifest(prepared, manifest_path, catalog)
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
