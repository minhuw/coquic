# QUIC Perf Benchmarks

`coquic-perf` exercises the QUIC stack in three modes:

- `bulk` for sustained transfer throughput
- `rr` for established-connection request-response throughput and latency
- `crr` for connection-request-response throughput and latency

The client prints a human-readable summary to stdout and can also write a machine-readable JSON result with `--json-out`.

## Build The Binary

```bash
nix develop -c zig build
./zig-out/bin/coquic-perf server --host 127.0.0.1 --port 9443 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```

## Run A Direct Local `rr` Client

```bash
./zig-out/bin/coquic-perf client --host 127.0.0.1 --port 9443 --mode rr \
  --request-bytes 32 --response-bytes 48 --requests 1000 --requests-in-flight 4 \
  --json-out rr.json
```

## Run The Direct Host Matrix

```bash
bash bench/run-host-matrix.sh --preset smoke
```

The harness builds one optimized `coquic-perf` binary through Nix, launches the
server and client directly on the host with `taskset -c`, writes per-run text
and JSON files plus `.bench-results/manifest.json`, and records
`.bench-results/environment.txt` with runner details that help interpret noisy
GitHub-hosted measurements.

Useful environment overrides:

- `PERF_RESULTS_ROOT` to choose a different output directory
- `PERF_BINARY_ATTR` to choose a different Nix build attr for `coquic-perf`
- `PERF_BUILD_TARGET` to override the summary label written into `manifest.json`
- `PERF_SERVER_CPUS` and `PERF_CLIENT_CPUS` to pin different cores
- `PERF_PORT` to move the benchmark listener port
