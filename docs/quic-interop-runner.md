# QUIC Interop Runner

This repository now exposes a runner-oriented HTTP/0.9 surface above `QuicCore`.
The current slice targets:

- `handshake`
- ideal-case `transfer`

It does not yet target lossy recovery, congestion-control competition, or full
interop-runner scenario coverage beyond those two cases.

## Runner Contract

The wrapper script mirrors the official runner environment contract:

```bash
ROLE=server TESTCASE=handshake ./scripts/run_endpoint.sh
ROLE=client TESTCASE=transfer REQUESTS="https://server/file1 https://server/file2" ./scripts/run_endpoint.sh
```

The script passes the runner-facing environment through to `coquic` and applies
the expected mounted paths:

- server document root: `/www`
- client download root: `/downloads`
- TLS certificate chain: `/certs/cert.pem`
- TLS private key: `/certs/priv.key`

When running inside `quic-network-simulator`, the wrapper also invokes
`/setup.sh` and waits for `sim:57832` on the client side before starting the
QUIC client process.

For ad-hoc local container runs outside the simulator, you can bypass those
hooks with:

```bash
COQUIC_SKIP_SETUP=1 COQUIC_SKIP_WAIT=1
```

## Local Manual Runs

Build the binary with quictls:

```bash
nix develop -c zig build -Dtls_backend=quictls
```

Run a server directly from the repo:

```bash
TESTCASE=handshake \
HOST=0.0.0.0 \
PORT=443 \
DOCUMENT_ROOT=/tmp/www \
CERTIFICATE_CHAIN_PATH=tests/fixtures/quic-server-cert.pem \
PRIVATE_KEY_PATH=tests/fixtures/quic-server-key.pem \
./zig-out/bin/coquic interop-server
```

Run a client directly from the repo:

```bash
TESTCASE=transfer \
HOST=127.0.0.1 \
PORT=443 \
SERVER_NAME=localhost \
DOWNLOAD_ROOT=/tmp/downloads \
REQUESTS="https://localhost/hello.txt" \
./zig-out/bin/coquic interop-client
```

## Docker Image

Build the official-runner image:

```bash
docker build -t coquic-interop:latest .
```

The image:

- builds `coquic` with `quictls`
- copies the resulting binary plus its runtime shared-library closure
- uses `martenseemann/quic-network-simulator-endpoint:latest` as the final base
- starts with `/run_endpoint.sh`

## quic-interop-runner Usage

Point the runner at the built image in your local implementation entry, then
run the `handshake` and `transfer` scenarios. The wrapper script expects the
standard runner environment:

- `ROLE=server` or `ROLE=client`
- `TESTCASE=handshake` or `TESTCASE=transfer`
- `REQUESTS` for client-side transfer runs

For client-side runner invocations, the default network target is `server` and
the default SNI is also `server`, matching the `https://server/...` request URLs
used by the official HTTP/0.9 transfer cases.

## quic-network-simulator Usage

The same image can be used directly with `quic-network-simulator`, because the
wrapper script cooperates with the simulator endpoint hooks:

- `/setup.sh`
- `/wait-for-it.sh sim:57832`

That keeps the image aligned with the endpoint expectations documented by the
simulator project instead of re-implementing simulator-specific setup in C++.
