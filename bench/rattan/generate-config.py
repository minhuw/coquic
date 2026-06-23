#!/usr/bin/env python3
"""Generate a Rattan TOML config for a prepared trace and coquic-perf run."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import shlex
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_TRACE_MANIFEST = REPO_ROOT / ".bench-traces" / "manifest.json"
DEFAULT_RESULTS_ROOT = REPO_ROOT / ".bench-results" / "rattan"
MTU_BYTES = 1500


def toml_string(value: str) -> str:
    return json.dumps(value)


def toml_array(values: list[str]) -> str:
    return "[" + ", ".join(toml_string(value) for value in values) + "]"


def toml_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError(f"non-finite TOML float: {value}")
    return f"{value:.12g}"


def parse_duration_ms(value: str) -> int:
    text = value.strip()
    if text.endswith("ms"):
        return int(text[:-2])
    if text.endswith("s"):
        return int(text[:-1]) * 1000
    raise ValueError(f"unsupported duration: {value}")


def load_manifest(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def find_trace(manifest: dict, trace_id: str) -> dict:
    for trace in manifest.get("traces", []):
        if trace.get("id") == trace_id:
            return trace
    raise KeyError(f"trace not found in manifest: {trace_id}")


def average_mahimahi_mbps(path: pathlib.Path) -> float:
    timestamps = []
    with path.open("r", encoding="utf-8", errors="replace") as input_file:
        for line in input_file:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                timestamps.append(int(float(stripped)))
            except ValueError:
                continue
    if len(timestamps) < 2:
        return 1.0
    duration_s = max((max(timestamps) - min(timestamps) + 1) / 1000.0, 0.001)
    return max(len(timestamps) * MTU_BYTES * 8.0 / duration_s / 1_000_000.0, 0.001)


def command_script(
    argv: list[str],
    log_path: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    prefix = ""
    if env:
        prefix = "".join(f"{shlex.quote(key)}={shlex.quote(value)} " for key, value in env.items())
    quoted = prefix + "exec " + " ".join(shlex.quote(arg) for arg in argv)
    if log_path is not None:
        quoted = f"{quoted} > {shlex.quote(str(log_path))} 2>&1"
    return ["bash", "-lc", quoted]


def build_perf_args(args: argparse.Namespace, results_root: pathlib.Path, role: str) -> list[str]:
    binary = str(args.perf_bin)
    common = [
        binary,
        role,
        "--host",
        "0.0.0.0" if role == "server" else args.server_host,
        "--port",
        str(args.port),
        "--io-backend",
        args.io_backend,
        "--congestion-control",
        args.congestion_control,
    ]
    if role == "server":
        common.extend(
            [
                "--certificate-chain",
                str(args.certificate_chain),
                "--private-key",
                str(args.private_key),
            ]
        )
        return common

    common.extend(
        [
            "--mode",
            args.mode,
            "--request-bytes",
            str(args.request_bytes),
            "--response-bytes",
            str(args.response_bytes),
            "--streams",
            str(args.streams),
            "--connections",
            str(args.connections),
            "--requests-in-flight",
            str(args.requests_in_flight),
            "--warmup",
            args.warmup,
            "--duration",
            args.duration,
            "--json-out",
            str(results_root / "result.json"),
        ]
    )
    if args.mode == "bulk":
        common.extend(["--direction", args.direction])
        if args.total_bytes:
            common.extend(["--total-bytes", str(args.total_bytes)])
    elif args.requests:
        common.extend(["--requests", str(args.requests)])
    return common


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_TRACE_MANIFEST)
    parser.add_argument("--trace-id", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--results-root", type=pathlib.Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--perf-bin", type=pathlib.Path, default=REPO_ROOT / "zig-out" / "bin" / "coquic-perf")
    parser.add_argument("--congestion-control", default="newreno")
    parser.add_argument("--mode", default="bulk", choices=["bulk", "rr", "crr", "persistent-rr"])
    parser.add_argument("--direction", default="download", choices=["download", "upload"])
    parser.add_argument("--request-bytes", type=int, default=64)
    parser.add_argument("--response-bytes", type=int, default=64)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--requests-in-flight", type=int, default=1)
    parser.add_argument("--requests", type=int)
    parser.add_argument("--total-bytes", type=int)
    parser.add_argument("--warmup", default="5s")
    parser.add_argument("--duration", default="20s")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--server-host", default="10.2.1.1")
    parser.add_argument("--io-backend", default="socket")
    parser.add_argument("--certificate-chain", type=pathlib.Path, default=REPO_ROOT / "tests/fixtures/quic-server-cert.pem")
    parser.add_argument("--private-key", type=pathlib.Path, default=REPO_ROOT / "tests/fixtures/quic-server-key.pem")
    parser.add_argument("--queue-bdp-multiplier", type=float, default=2.0)
    parser.add_argument("--min-queue-bytes", type=int, default=64 * 1024)
    parser.add_argument("--loss-rate", type=float, default=0.0, help="Optional fixed per-packet loss rate.")
    parser.add_argument("--spy-pcap", type=pathlib.Path)
    args = parser.parse_args()
    if not 0.0 <= args.loss_rate <= 1.0:
        print("--loss-rate must be between 0.0 and 1.0", file=sys.stderr)
        return 2

    trace = find_trace(load_manifest(args.manifest), args.trace_id)
    down_trace = pathlib.Path(trace["down_trace"]).resolve()
    up_trace = pathlib.Path(trace["up_trace"]).resolve()
    rattan_down_trace = pathlib.Path(trace.get("rattan_down_trace", trace["down_trace"])).resolve()
    rattan_up_trace = pathlib.Path(trace.get("rattan_up_trace", trace["up_trace"])).resolve()
    base_rtt_ms = float(trace.get("base_rtt_ms", 50))
    one_way_delay_ms = max(base_rtt_ms / 2.0, 0.0)
    avg_down_mbps = average_mahimahi_mbps(down_trace)
    avg_up_mbps = average_mahimahi_mbps(up_trace)
    avg_mbps = max(avg_down_mbps, avg_up_mbps, 0.001)
    queue_bytes = max(
        args.min_queue_bytes,
        int(math.ceil(avg_mbps * 1_000_000.0 / 8.0 * (base_rtt_ms / 1000.0) * args.queue_bdp_multiplier)),
    )

    run_root = args.results_root.resolve()
    run_root.mkdir(parents=True, exist_ok=True)
    server_log = run_root / "server.log"
    client_log = run_root / "client.log"
    run_ms = parse_duration_ms(args.warmup) + parse_duration_ms(args.duration)
    server_exit_ms = max(run_ms + int(math.ceil(base_rtt_ms)) + 5000, 10_000)
    left_command = command_script(build_perf_args(args, run_root, "client"), client_log)
    right_command = command_script(
        build_perf_args(args, run_root, "server"),
        server_log,
        {"COQUIC_PERF_SERVER_EXIT_AFTER_MS": str(server_exit_ms)},
    )

    spy_up = ""
    if args.spy_pcap:
        spy_path = args.spy_pcap.resolve()
        spy_up = f'\n[cells.spy]\ntype = "Spy"\npath = {toml_string(str(spy_path))}\n'

    loss_cells = ""
    if args.loss_rate > 0.0:
        loss_cells = f"""
[cells.up_loss]
type = "Loss"
pattern = [{toml_float(args.loss_rate)}]

[cells.down_loss]
type = "Loss"
pattern = [{toml_float(args.loss_rate)}]
"""

    up_link = [
        ("left", "up_bw"),
        ("up_bw", "up_delay"),
    ]
    if args.loss_rate > 0.0:
        up_link.append(("up_delay", "up_loss"))
        tail = "up_loss"
    else:
        tail = "up_delay"
    if args.spy_pcap:
        up_link.append((tail, "spy"))
        up_link.append(("spy", "right"))
    else:
        up_link.append((tail, "right"))

    down_link = [
        ("right", "down_bw"),
        ("down_bw", "down_delay"),
    ]
    if args.loss_rate > 0.0:
        down_link.append(("down_delay", "down_loss"))
        down_link.append(("down_loss", "left"))
    else:
        down_link.append(("down_delay", "left"))
    link_lines = "\n".join(f"{source} = {toml_string(dest)}" for source, dest in up_link + down_link)

    config = f"""# Generated by bench/rattan/generate-config.py
[general]

[env]
mode = "Isolated"
left_veth_count = 1
right_veth_count = 1

[cells]

[cells.up_bw]
type = "BwReplay"
trace = {toml_string(str(rattan_up_trace))}
queue = "DropTail"
queue_config = {{ byte_limit = {queue_bytes} }}

[cells.up_delay]
type = "Delay"
delay = {toml_string(f"{one_way_delay_ms:.3f}ms")}

[cells.down_bw]
type = "BwReplay"
trace = {toml_string(str(rattan_down_trace))}
queue = "DropTail"
queue_config = {{ byte_limit = {queue_bytes} }}

[cells.down_delay]
type = "Delay"
delay = {toml_string(f"{one_way_delay_ms:.3f}ms")}
{spy_up}
{loss_cells}
[links]
{link_lines}

[commands]
right = {toml_array(right_command)}
left = {toml_array(left_command)}
shell = "Default"
"""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(config, encoding="utf-8")
    metadata = {
        "trace": trace,
        "avg_down_mbps": trace.get("avg_down_mbps", avg_down_mbps),
        "avg_up_mbps": trace.get("avg_up_mbps", avg_up_mbps),
        "rattan_down_trace": str(rattan_down_trace),
        "rattan_up_trace": str(rattan_up_trace),
        "queue_bytes": queue_bytes,
        "base_rtt_ms": base_rtt_ms,
        "loss_rate": args.loss_rate,
        "congestion_control": args.congestion_control,
        "mode": args.mode,
        "direction": args.direction,
        "duration": args.duration,
        "warmup": args.warmup,
        "server_exit_after_ms": server_exit_ms,
        "server_host": args.server_host,
        "results_root": str(run_root),
    }
    args.output.with_suffix(args.output.suffix + ".json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
