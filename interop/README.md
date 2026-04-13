# QUIC Interop Runner

Interop-specific repo assets now live under [`interop/`](/home/minhu/projects/coquic/interop).
The GitHub Actions workflow stays in [`.github/workflows/interop.yml`](/home/minhu/projects/coquic/.github/workflows/interop.yml) because GitHub requires that location.

This repository now exposes runner-oriented HTTP/0.9 and HTTP/3 surfaces above
`QuicCore`. The current slice targets:

- `handshake`
- ideal-case `transfer`
- `chacha20`
- `http3`

It does not yet target lossy recovery, congestion-control competition, or full
interop-runner scenario coverage beyond those core lanes.

## Runner Contract

The wrapper script mirrors the official runner environment contract:

```bash
ROLE=server TESTCASE=handshake ./interop/entrypoint.sh
ROLE=client TESTCASE=transfer REQUESTS="https://server/file1 https://server/file2" ./interop/entrypoint.sh
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

## HTTP/3 Testcase Dispatch

`interop-server` and `interop-client` remain the HTTP/0.9 interop surface.
For `TESTCASE=http3`, the wrapper dispatches to `h3-interop-server` and
`h3-interop-client` instead. This split is handled inside
[`interop/entrypoint.sh`](/home/minhu/projects/coquic/interop/entrypoint.sh), while all
non-`http3` testcases continue to use the HTTP/0.9 commands.

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
nix build .#interop-image-quictls-musl
```

Load it into Docker:

```bash
docker load -i "$(nix path-info .#interop-image-quictls-musl)"
```

The resulting image tag is:

```bash
coquic-interop:quictls-musl
```

Build and load the boringssl musl image layered on top of the official
simulator endpoint base image:

```bash
nix build .#interop-image-boringssl-musl
docker load -i "$(nix path-info .#interop-image-boringssl-musl)"
```

That image loads as:

```bash
coquic-interop:boringssl-musl
```

The corresponding static musl packages and shells are:

```bash
nix build .#coquic-quictls-musl
nix develop .#quictls-musl
nix build .#coquic-boringssl-musl
nix develop .#boringssl-musl
```

The checked-in official runner wrapper always builds and loads the musl-linked
quictls image (`.#interop-image-quictls-musl` /
`coquic-interop:quictls-musl`) for interop testing. That keeps the CI and local
official-runner path on a single image regardless of testcase selection,
including `chacha20`.

## Official Runner Smoke Matrix

Run the checked-in official runner wrapper against `quic-go` with:

```bash
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
nix develop -c bash interop/run-official.sh
```

To run only the HTTP/3 testcase locally with the pinned `quic-go` image:

```bash
INTEROP_TESTCASES=http3 \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
INTEROP_DIRECTIONS=both \
nix develop -c bash interop/run-official.sh
```

To run Chromium-as-client against `coquic` as server for the official `http3`
case only, use the repo-owned wrapper:

```bash
nix develop -c bash tests/nix/chrome_http3_interop_smoke_test.sh
```

That wrapper pins the current `martenseemann/chrome-quic-interop-runner`
digest, forces `INTEROP_TESTCASES=http3`, and forces
`INTEROP_DIRECTIONS=coquic-server` because the Chrome runner is client-only.

That script builds and loads `coquic-interop:quictls-musl`, pulls the pinned
official `quic-go`, simulator, and iperf images, and runs the requested
testcases in both directions. The separate GitHub Actions workflow in
`.github/workflows/interop.yml` calls the same script.

The image verification scripts live under `interop/tests/`.

The Nix-native interop images are built with `dockerTools.buildLayeredImage`.
Repo-owned interop assets provide the runner wrapper:

- `/entrypoint.sh`

The only checked-in interop images are the official-base musl variants. They
are layered on top of
`martenseemann/quic-network-simulator-endpoint`, so they inherit the
simulator's own `/setup.sh` and `/wait-for-it.sh` instead of overriding them.

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

The official-base musl images can be used directly with
`quic-network-simulator`, because the wrapper script cooperates with the
simulator endpoint hooks inherited from the official endpoint base image:

- `/setup.sh`
- `/wait-for-it.sh sim:57832`

That keeps the image aligned with the endpoint expectations documented by the
simulator project without a separate Dockerfile path.
