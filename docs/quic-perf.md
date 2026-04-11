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

## Build And Load The Perf Image

```bash
nix build .#perf-image-quictls-musl
docker load -i "$(nix path-info .#perf-image-quictls-musl)"
```

## Run The Host-Network Matrix

```bash
bash bench/run-host-matrix.sh --preset smoke
```

The harness uses `--network host` and `--cpuset-cpus` to keep Docker overhead low, adds `seccomp=unconfined` plus `IPC_LOCK`/`memlock` overrides so the containerized `io_uring` backend can initialize, mounts the repo fixture certificates into the server container, and writes per-run text and JSON files plus `.bench-results/manifest.json`.

Useful environment overrides:

- `PERF_RESULTS_ROOT` to choose a different output directory
- `PERF_SERVER_CPUS` and `PERF_CLIENT_CPUS` to pin different cores
- `PERF_PORT` to move the benchmark listener port
- `PERF_IMAGE_ATTR` and `PERF_IMAGE_TAG` to swap in a different image build

If the runtime probe detects unsupported UDP `recvmsg` via `io_uring` on the local kernel, the backend falls back to the poll engine so benchmark runs still complete.
