# QUIC Perf Benchmarks

`coquic-perf` exercises the QUIC stack in three modes:

- `bulk` for sustained transfer throughput
- `rr` for established-connection request-response throughput and latency
- `crr` for connection-request-response throughput and latency

The client prints a human-readable summary to stdout and can also write a machine-readable JSON result with `--json-out`.

## Build The Binary

```bash
nix develop -c zig build -Doptimize=ReleaseFast
./zig-out/bin/coquic-perf server --host 127.0.0.1 --port 9443 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem \
  --congestion-control bbr
```

Use `-Doptimize=ReleaseFast` for throughput measurements. A plain `zig build`
produces a debug binary and can understate bulk throughput by orders of
magnitude. The Docker image used by `bench/run-host-matrix.sh` and
`.github/workflows/perf.yml` is built with ReleaseFast.

## Run A Direct Local Bulk Download

```bash
./zig-out/bin/coquic-perf client --host 127.0.0.1 --port 9443 --mode bulk \
  --direction download --response-bytes 67108864 --streams 4 --connections 1 \
  --requests-in-flight 1 --warmup 1s --duration 3s \
  --congestion-control bbr --json-out bulk-bbr.json
```

## Run A Direct Local `rr` Client

```bash
./zig-out/bin/coquic-perf client --host 127.0.0.1 --port 9443 --mode rr \
  --request-bytes 32 --response-bytes 48 --requests 1000 --requests-in-flight 4 \
  --congestion-control bbr --json-out rr.json
```

## Run The Container Matrix

```bash
bash bench/run-host-matrix.sh --preset smoke
```

The harness builds and loads the Nix `coquic-perf` image, launches separate
server and client containers on a Docker bridge network with `--cpuset-cpus`,
writes per-run text and JSON files plus `.bench-results/manifest.json`, and
records `.bench-results/environment.txt` with runner and Docker details that
help interpret noisy GitHub-hosted measurements. By default the matrix runs each
tuple once with NewReno, once with CUBIC, once with BBR, and once with Copa,
using matching `--congestion-control` settings on both endpoints. The bridge network avoids host-loopback-only
behavior such as oversized loopback MTU.

Paired external baseline runs are available with `PERF_CLIENT_IMPL` and
`PERF_SERVER_IMPL` set to the same implementation name. The current baseline
set is `quic-go`, `quinn`, `picoquic`, `msquic`, `quiche`, `mvfst`,
`s2n-quic`, `xquic`, `aioquic`, `ngtcp2`, `lsquic`, and `neqo`; those runs use
`PERF_CONGESTION_CONTROLS=default` so each implementation keeps its own default
congestion-control configuration.

Useful environment overrides:

- `PERF_RESULTS_ROOT` to choose a different output directory
- `PERF_IMAGE_ATTR` to choose a different Nix image attr for `coquic-perf`
- `PERF_IMAGE_TAG` to choose the loaded Docker image tag
- `PERF_SERVER_CPUS` and `PERF_CLIENT_CPUS` to pin different container CPU sets
- `PERF_PORT` to move the benchmark listener port
- `PERF_RUN_TIMEOUT_SECONDS` to adjust the per-client container timeout
- `PERF_CONGESTION_CONTROLS` to choose algorithms, for example `bbr` or
  `newreno cubic bbr copa`
- `PERF_MSQUIC_BULK_TOTAL_BYTES` to override the paired MSQUIC fixed bulk
  transfer size used when the CI bulk tuple otherwise requests an unbounded
  timed transfer (default: `134217728`)
