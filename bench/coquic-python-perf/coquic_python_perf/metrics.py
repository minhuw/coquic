from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import PerfError
from .config import (
    APPLICATION_PROTOCOL,
    PerfConfig,
    congestion_control_name,
    direction_name,
    mode_name,
)


@dataclass(slots=True)
class LatencySummary:
    min_us: int = 0
    avg_us: int = 0
    p50_us: int = 0
    p90_us: int = 0
    p99_us: int = 0
    max_us: int = 0


@dataclass(slots=True)
class ServerCounters:
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_completed: int = 0


@dataclass(slots=True)
class RunSummary:
    schema_version: int
    status: str
    mode: str
    direction: str
    backend: str
    congestion_control: str
    remote_host: str
    remote_port: int
    alpn: str
    elapsed_ms: int
    warmup_ms: int
    bytes_sent: int
    bytes_received: int
    server_counters: ServerCounters
    requests_completed: int
    streams: int
    connections: int
    requests_in_flight: int
    request_bytes: int
    response_bytes: int
    throughput_mib_per_s: float
    throughput_gbit_per_s: float
    requests_per_s: float
    latency: LatencySummary
    latency_samples: list[float] = field(default_factory=list, repr=False)
    failure_reason: str | None = None


def new_run_summary(config: PerfConfig) -> RunSummary:
    return RunSummary(
        schema_version=1,
        status="ok",
        mode=mode_name(config.mode),
        direction=direction_name(config.direction),
        backend="asyncio",
        congestion_control=congestion_control_name(config.congestion_control),
        remote_host=config.host,
        remote_port=config.port,
        alpn=APPLICATION_PROTOCOL.decode(),
        elapsed_ms=0,
        warmup_ms=duration_millis(config.warmup),
        bytes_sent=0,
        bytes_received=0,
        server_counters=ServerCounters(),
        requests_completed=0,
        streams=config.streams,
        connections=config.connections,
        requests_in_flight=config.requests_in_flight,
        request_bytes=config.request_bytes,
        response_bytes=config.response_bytes,
        throughput_mib_per_s=0.0,
        throughput_gbit_per_s=0.0,
        requests_per_s=0.0,
        latency=LatencySummary(),
    )


def reset_measurement(summary: RunSummary) -> None:
    summary.elapsed_ms = 0
    summary.bytes_sent = 0
    summary.bytes_received = 0
    summary.server_counters = ServerCounters()
    summary.requests_completed = 0
    summary.latency = LatencySummary()
    summary.latency_samples.clear()
    summary.throughput_mib_per_s = 0.0
    summary.throughput_gbit_per_s = 0.0
    summary.requests_per_s = 0.0


def finalize_summary(summary: RunSummary) -> None:
    summary.latency = summarize_latency_samples(summary.latency_samples)
    seconds = max(summary.elapsed_ms, 1) / 1000.0
    transfer_bytes = summary.bytes_sent + summary.bytes_received
    summary.throughput_mib_per_s = transfer_bytes / (1024.0 * 1024.0) / seconds
    summary.throughput_gbit_per_s = (transfer_bytes * 8.0) / 1_000_000_000.0 / seconds
    summary.requests_per_s = summary.requests_completed / seconds


def emit_summary(summary: RunSummary, json_out: Path | None) -> None:
    print(render_summary(summary))
    if json_out is not None:
        try:
            json_out.write_text(json.dumps(_summary_dict(summary), separators=(",", ":")))
        except OSError as error:
            raise PerfError(f"failed to write {json_out}: {error}") from error


def render_summary(summary: RunSummary) -> str:
    return (
        f"status={summary.status} mode={summary.mode} cc={summary.congestion_control} "
        f"direction={summary.direction} throughput_mib/s={summary.throughput_mib_per_s:.3f} "
        f"throughput_gbit/s={summary.throughput_gbit_per_s:.3f} "
        f"requests/s={summary.requests_per_s:.3f}"
    )


def summarize_latency_samples(samples: list[float]) -> LatencySummary:
    if not samples:
        return LatencySummary()
    micros = sorted(duration_micros(sample) for sample in samples)
    total = sum(micros)
    return LatencySummary(
        min_us=micros[0],
        avg_us=total // len(micros),
        p50_us=_percentile_value(micros, 50),
        p90_us=_percentile_value(micros, 90),
        p99_us=_percentile_value(micros, 99),
        max_us=micros[-1],
    )


def duration_millis(seconds: float) -> int:
    return min(int(seconds * 1000), (1 << 64) - 1)


def duration_micros(seconds: float) -> int:
    return min(int(seconds * 1_000_000), (1 << 64) - 1)


def _percentile_value(sorted_values: list[int], percentile: int) -> int:
    rank = int(((percentile / 100.0) * len(sorted_values)) + 0.999999)
    index = 0 if rank == 0 else min(rank - 1, len(sorted_values) - 1)
    return sorted_values[index]


def _summary_dict(summary: RunSummary) -> dict:
    data = asdict(summary)
    data.pop("latency_samples", None)
    if data.get("failure_reason") is None:
        data.pop("failure_reason", None)
    return data
