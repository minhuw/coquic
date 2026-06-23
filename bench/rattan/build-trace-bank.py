#!/usr/bin/env python3
"""Build a fast, symmetric, windowed Rattan trace bank from prepared traces."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import shutil
from bisect import bisect_left
from dataclasses import dataclass
from typing import Iterable


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_STATE_DIR = REPO_ROOT / ".bench-traces"
DEFAULT_INPUT_MANIFEST = DEFAULT_STATE_DIR / "manifest.json"
DEFAULT_OUTPUT_DIR = DEFAULT_STATE_DIR / "banks" / "quick"
DEFAULT_OUTPUT_MANIFEST = DEFAULT_OUTPUT_DIR / "manifest.json"
MTU_BYTES = 1500
DEFAULT_RATTAN_SAMPLE_MS = 100
DEFAULT_RATTAN_MIN_MBPS = 0.001


@dataclass(frozen=True)
class WindowCandidate:
    trace: dict
    window_index: int
    start_ms: int
    end_ms: int
    timestamps_ms: list[int]
    avg_mbps: float
    cv: float
    outage_ratio: float

    @property
    def id(self) -> str:
        return f"{self.trace['id']}-w{self.window_index:04d}"

    @property
    def stratum(self) -> tuple[str, str, str]:
        return (
            str(self.trace.get("network", "unknown")),
            str(self.trace.get("mobility", "unknown")),
            str(self.trace.get("corpus", "unknown")),
        )


def load_manifest(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_mahimahi_trace(path: pathlib.Path) -> list[int]:
    timestamps: list[int] = []
    with path.open("r", encoding="utf-8", errors="replace") as input_file:
        for line in input_file:
            text = line.strip()
            if not text:
                continue
            try:
                timestamps.append(int(float(text)))
            except ValueError:
                continue
    return sorted(timestamp for timestamp in timestamps if timestamp >= 0)


def write_mahimahi_trace(timestamps: Iterable[int], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        for timestamp in timestamps:
            output_file.write(f"{timestamp}\n")


def format_duration_ms(duration_ms: int) -> str:
    if duration_ms <= 0:
        raise ValueError(f"duration must be positive: {duration_ms}")
    if duration_ms % 1000 == 0:
        return f"{duration_ms // 1000}s"
    return f"{duration_ms}ms"


def format_bandwidth_bps(bps: int) -> str:
    return f"{max(bps, 1)}bps"


def write_rattan_bw_trace(
    timestamps_ms: list[int],
    path: pathlib.Path,
    window_ms: int,
    sample_ms: int,
    min_mbps: float,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sample_ms = max(sample_ms, 1)
    min_bps = max(1, int(round(min_mbps * 1_000_000.0)))
    samples: list[tuple[int, int]] = []
    timestamp_index = 0
    sorted_timestamps = sorted(timestamps_ms)
    bucket_start = 0
    while bucket_start < window_ms:
        bucket_end = min(bucket_start + sample_ms, window_ms)
        count = 0
        while timestamp_index < len(sorted_timestamps) and sorted_timestamps[timestamp_index] < bucket_start:
            timestamp_index += 1
        scan_index = timestamp_index
        while scan_index < len(sorted_timestamps) and sorted_timestamps[scan_index] < bucket_end:
            count += 1
            scan_index += 1
        timestamp_index = scan_index
        duration_ms = bucket_end - bucket_start
        duration_s = duration_ms / 1000.0
        bps = int(round(count * MTU_BYTES * 8.0 / duration_s)) if count else min_bps
        samples.append((duration_ms, max(bps, min_bps)))
        bucket_start = bucket_end

    pattern = [
        [format_duration_ms(duration_ms), [format_bandwidth_bps(bps)]]
        for duration_ms, bps in samples
    ]
    path.write_text(
        json.dumps(
            {
                "RepeatedBwPatternConfig": {
                    "pattern": [{"TraceBwConfig": {"pattern": pattern}}],
                    "count": 0,
                }
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def window_features(timestamps_ms: list[int], window_ms: int) -> tuple[float, float, float]:
    duration_s = max(window_ms / 1000.0, 0.001)
    avg_mbps = len(timestamps_ms) * MTU_BYTES * 8.0 / duration_s / 1_000_000.0
    bucket_count = max(1, math.ceil(duration_s))
    buckets = [0] * bucket_count
    for timestamp in timestamps_ms:
        bucket = min(int(timestamp / 1000), bucket_count - 1)
        buckets[bucket] += 1
    mean_packets = sum(buckets) / len(buckets)
    if mean_packets > 0:
        variance = sum((count - mean_packets) ** 2 for count in buckets) / len(buckets)
        cv = math.sqrt(variance) / mean_packets
    else:
        cv = 0.0
    outage_ratio = sum(1 for count in buckets if count == 0) / len(buckets)
    return avg_mbps, cv, outage_ratio


def build_candidates(
    manifest: dict,
    window_seconds: float,
    window_stride_seconds: float | None,
    min_packets: int,
    min_avg_mbps: float,
    max_outage_ratio: float,
) -> list[WindowCandidate]:
    window_ms = max(1, int(round(window_seconds * 1000.0)))
    stride_ms = window_ms if window_stride_seconds is None else max(
        1, int(round(window_stride_seconds * 1000.0))
    )
    candidates: list[WindowCandidate] = []
    for trace in manifest.get("traces", []):
        down_path = pathlib.Path(trace["down_trace"])
        source_timestamps = read_mahimahi_trace(down_path)
        if not source_timestamps:
            continue
        first_start = (source_timestamps[0] // window_ms) * window_ms
        window_index = 0
        while first_start + window_index * stride_ms <= source_timestamps[-1]:
            start_ms = first_start + window_index * stride_ms
            end_ms = start_ms + window_ms
            start_index = bisect_left(source_timestamps, start_ms)
            end_index = bisect_left(source_timestamps, end_ms, lo=start_index)
            timestamps = [timestamp - start_ms for timestamp in source_timestamps[start_index:end_index]]
            if len(timestamps) >= min_packets:
                avg_mbps, cv, outage_ratio = window_features(timestamps, window_ms)
                if avg_mbps < min_avg_mbps:
                    window_index += 1
                    continue
                if outage_ratio > max_outage_ratio:
                    window_index += 1
                    continue
                candidates.append(
                    WindowCandidate(
                        trace=trace,
                        window_index=window_index,
                        start_ms=start_ms,
                        end_ms=end_ms,
                        timestamps_ms=timestamps,
                        avg_mbps=avg_mbps,
                        cv=cv,
                        outage_ratio=outage_ratio,
                    )
                )
            window_index += 1
    return candidates


def spread_candidates(candidates: list[WindowCandidate]) -> list[WindowCandidate]:
    ordered = sorted(candidates, key=lambda item: (item.avg_mbps, item.cv, item.outage_ratio, item.id))
    spread: list[WindowCandidate] = []
    left = 0
    right = len(ordered) - 1
    while left <= right:
        spread.append(ordered[left])
        if right != left:
            spread.append(ordered[right])
        left += 1
        right -= 1
    return spread


def select_stratified(candidates: list[WindowCandidate], max_windows: int) -> list[WindowCandidate]:
    if max_windows <= 0 or len(candidates) <= max_windows:
        return sorted(candidates, key=lambda item: (item.stratum, item.start_ms, item.id))

    strata: dict[tuple[str, str, str], list[WindowCandidate]] = {}
    for candidate in candidates:
        strata.setdefault(candidate.stratum, []).append(candidate)
    queues = {key: spread_candidates(value) for key, value in strata.items()}

    selected: list[WindowCandidate] = []
    keys = sorted(queues)
    while len(selected) < max_windows and any(queues.values()):
        for key in keys:
            queue = queues[key]
            if not queue:
                continue
            selected.append(queue.pop(0))
            if len(selected) >= max_windows:
                break
    return selected


def target_window_count(args: argparse.Namespace) -> int:
    if args.max_windows is not None:
        return args.max_windows
    per_run_seconds = max(args.window_seconds + args.per_run_overhead_seconds, 1.0)
    matrix_multiplier = max(args.matrix_multiplier, 1)
    return max(1, int(args.target_wallclock_seconds // (per_run_seconds * matrix_multiplier)))


def write_bank(
    selected: list[WindowCandidate],
    output_dir: pathlib.Path,
    output_manifest: pathlib.Path,
    input_manifest: pathlib.Path,
    subset_name: str,
    window_seconds: float,
    window_stride_seconds: float | None,
    max_windows: int,
    min_avg_mbps: float,
    max_outage_ratio: float,
    rattan_sample_ms: int,
    rattan_min_mbps: float,
) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    for rank, candidate in enumerate(selected, start=1):
        trace_dir = output_dir / candidate.id
        down_path = trace_dir / "down.trace"
        up_path = trace_dir / "up.trace"
        rattan_down_path = trace_dir / "down.bw.json"
        rattan_up_path = trace_dir / "up.bw.json"
        write_mahimahi_trace(candidate.timestamps_ms, down_path)
        shutil.copyfile(down_path, up_path)
        window_ms = max(1, int(round(window_seconds * 1000.0)))
        write_rattan_bw_trace(candidate.timestamps_ms, rattan_down_path, window_ms, rattan_sample_ms, rattan_min_mbps)
        shutil.copyfile(rattan_down_path, rattan_up_path)

        source = candidate.trace
        records.append(
            {
                "id": candidate.id,
                "source_trace_id": source.get("id", ""),
                "source_window_index": candidate.window_index,
                "source_start_ms": candidate.start_ms,
                "source_end_ms": candidate.end_ms,
                "window_seconds": window_seconds,
                "selection_rank": rank,
                "subset": [subset_name, "windowed"],
                "corpus": source.get("corpus", ""),
                "network": source.get("network", ""),
                "mobility": source.get("mobility", ""),
                "base_rtt_ms": source.get("base_rtt_ms", 50),
                "down_trace": str(down_path),
                "up_trace": str(up_path),
                "rattan_down_trace": str(rattan_down_path),
                "rattan_up_trace": str(rattan_up_path),
                "up_synthesized": True,
                "direction_model": "symmetric-downlink-window",
                "format": "mahimahi-window",
                "rattan_format": "netem-trace-bw-json",
                "rattan_sample_ms": rattan_sample_ms,
                "rattan_min_mbps": rattan_min_mbps,
                "avg_down_mbps": candidate.avg_mbps,
                "avg_up_mbps": candidate.avg_mbps,
                "packet_count": len(candidate.timestamps_ms),
                "throughput_cv": candidate.cv,
                "outage_ratio": candidate.outage_ratio,
            }
        )

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    output_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_by": "bench/rattan/build-trace-bank.py",
                "source_manifest": str(input_manifest),
                "subset": subset_name,
                "window_seconds": window_seconds,
                "window_stride_seconds": window_stride_seconds or window_seconds,
                "max_windows": max_windows,
                "min_avg_mbps": min_avg_mbps,
                "max_outage_ratio": max_outage_ratio,
                "rattan_sample_ms": rattan_sample_ms,
                "rattan_min_mbps": rattan_min_mbps,
                "direction_model": "symmetric-downlink-window",
                "selection_strategy": "round-robin-stratified-by-network-mobility-corpus",
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
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_INPUT_MANIFEST)
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--output-manifest", type=pathlib.Path, default=DEFAULT_OUTPUT_MANIFEST)
    parser.add_argument("--subset-name", default="quick")
    parser.add_argument("--window-seconds", type=float, default=30.0)
    parser.add_argument(
        "--window-stride-seconds",
        type=float,
        default=None,
        help="Distance between candidate window starts; default equals --window-seconds.",
    )
    parser.add_argument("--max-windows", type=int)
    parser.add_argument("--target-wallclock-seconds", type=float, default=30 * 60)
    parser.add_argument("--per-run-overhead-seconds", type=float, default=7.0)
    parser.add_argument("--matrix-multiplier", type=int, default=1)
    parser.add_argument("--min-packets", type=int, default=1)
    parser.add_argument(
        "--min-avg-mbps",
        type=float,
        default=0.05,
        help="Drop windows below this average throughput from the quick bank.",
    )
    parser.add_argument(
        "--max-outage-ratio",
        type=float,
        default=0.5,
        help="Drop quick-bank windows with more than this fraction of empty 1s buckets.",
    )
    parser.add_argument(
        "--rattan-sample-ms",
        type=int,
        default=DEFAULT_RATTAN_SAMPLE_MS,
        help="Sample width for generated Rattan bandwidth-model JSON traces.",
    )
    parser.add_argument(
        "--rattan-min-mbps",
        type=float,
        default=DEFAULT_RATTAN_MIN_MBPS,
        help="Minimum nonzero bandwidth used in generated Rattan bandwidth-model traces.",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    candidates = build_candidates(
        manifest,
        args.window_seconds,
        args.window_stride_seconds,
        args.min_packets,
        args.min_avg_mbps,
        args.max_outage_ratio,
    )
    if not candidates:
        raise SystemExit("no trace windows available")
    max_windows = target_window_count(args)
    selected = select_stratified(candidates, max_windows)
    write_bank(
        selected,
        args.output_dir,
        args.output_manifest,
        args.manifest,
        args.subset_name,
        args.window_seconds,
        args.window_stride_seconds,
        max_windows,
        args.min_avg_mbps,
        args.max_outage_ratio,
        args.rattan_sample_ms,
        args.rattan_min_mbps,
    )
    print(args.output_manifest)
    print(
        f"selected={len(selected)} candidates={len(candidates)} "
        f"window_seconds={args.window_seconds} "
        f"window_stride_seconds={args.window_stride_seconds or args.window_seconds}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
