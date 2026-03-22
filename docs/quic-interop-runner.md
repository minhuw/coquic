# QUIC Interop Runner

This repository now exposes a runner-oriented HTTP/0.9 surface above `QuicCore`.
The current slice targets:

- `handshake`
- ideal-case `transfer`
- `chacha20`

It does not yet target lossy recovery, congestion-control competition, or full
interop-runner scenario coverage beyond those three cases.

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

Build the packaged binary with quictls:

```bash
nix build .#coquic-quictls
```

`coquic-quictls` is the default quictls package and statically links
non-system dependencies (including the quictls TLS stack).

Run a server directly from the package output:

```bash
TESTCASE=handshake \
HOST=0.0.0.0 \
PORT=443 \
DOCUMENT_ROOT=/tmp/www \
CERTIFICATE_CHAIN_PATH=tests/fixtures/quic-server-cert.pem \
PRIVATE_KEY_PATH=tests/fixtures/quic-server-key.pem \
$(nix path-info .#coquic-quictls)/bin/coquic interop-server
```

Run a client directly from the package output:

```bash
TESTCASE=transfer \
HOST=127.0.0.1 \
PORT=443 \
SERVER_NAME=localhost \
DOWNLOAD_ROOT=/tmp/downloads \
REQUESTS="https://localhost/hello.txt" \
$(nix path-info .#coquic-quictls)/bin/coquic interop-client
```

If you want an editable build environment instead of a packaged binary, use the
matching backend shell:

```bash
nix develop .#quictls
nix develop .#boringssl
```

## Container Image

Build the canonical quictls interop runner image tarball (musl-linked static
`coquic` endpoint image on the simulator base):

```bash
nix build .#interop-image-quictls
```

`.#interop-image` is kept as a stable alias to the same image output.

Load it into Docker:

```bash
docker load -i "$(nix path-info .#interop-image-quictls)"
```

The resulting image tag is:

```bash
coquic-interop:quictls
```

Build and load the boringssl image the same way:

```bash
nix build .#interop-image-boringssl
docker load -i "$(nix path-info .#interop-image-boringssl)"
```

That image loads as:

```bash
coquic-interop:boringssl
```

For the boringssl musl image layered on top of the official simulator endpoint
base image:

```bash
nix build .#interop-image-boringssl-musl
docker load -i "$(nix path-info .#interop-image-boringssl-musl)"
```

That image loads as:

```bash
coquic-interop:boringssl-musl
```

The corresponding static package and shell are:

```bash
nix build .#coquic-boringssl-musl
nix develop .#boringssl-musl
```

`chacha20` continues to route through the `quictls` interop image
(`.#interop-image-quictls`) in the checked-in official runner wrapper. Our
current `coquic` BoringSSL backend/integration in
`coquic-interop:boringssl-musl` does not expose TLS 1.3 cipher-suite
selection controls, so it cannot reliably advertise a ChaCha20-only client
offer.

## Local quic-go Smoke Matrix

Run the checked-in mixed-image smoke matrix against `quic-go` with:

```bash
bash tests/nix/quicgo_interop_smoke_test.sh
```

That script builds and loads `coquic-interop:boringssl-musl`, pulls
`martenseemann/quic-go-interop:latest`, and runs the four currently supported
cases:

- `quic-go` client -> `coquic` server: `handshake`, `transfer`
- `coquic` client -> `quic-go` server: `handshake`, `transfer`

When `INTEROP_TESTCASES` includes `chacha20`, the checked-in official runner
wrapper switches to `coquic-interop:quictls` / `.#interop-image-quictls`
automatically so the client can offer a ChaCha20-only TLS 1.3 cipher suite.

The separate GitHub Actions workflow in `.github/workflows/interop.yml` calls
the same script.

The Nix-native images are built with `dockerTools.buildLayeredImage`. They
embed the `coquic` package closure plus the runner wrapper and vendored
simulator helper scripts:

- `/run_endpoint.sh`
- `/setup.sh`
- `/wait-for-it.sh`

## quic-interop-runner Usage

Point the runner at the built image in your local implementation entry, then
run the `handshake`, `transfer`, or `chacha20` scenarios. The wrapper script
expects the standard runner environment:

- `ROLE=server` or `ROLE=client`
- `TESTCASE=handshake`, `TESTCASE=transfer`, or `TESTCASE=chacha20`
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
simulator project without a separate Dockerfile path.
