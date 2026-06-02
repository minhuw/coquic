# Demo Deployment

This document covers the remote continuous deployment flow for the public
`coquic` demo.

## Repo Layout

- `site/next/` is the framework-backed browser demo source. It owns the
  homepage, workbench, performance, interop, and coverage HTML routes, plus the
  browser runtime assets in `site/next/public/`.
- `site/h3-server/Dockerfile` is the optional container wrapper for serving
  the built `h3-server` binary and packaged demo app.
- `npm --prefix site/next run build:wasm` builds the WASM dependencies,
  compiles the Zig WASM module, and smoke-tests the result. The generated
  module is written to
  `zig-out/share/wasm-quic/coquic-wasm-quic.wasm`.
- `npm --prefix site/next run build:demo` runs `build:wasm`, then writes a
  standalone Next.js server bundle under `site/next/.next/standalone/`.
- `site/deploy/package-demo.sh` packages the standalone Next.js server bundle
  and overlays the generated WASM module. `npm --prefix site/next run
  package:demo` is the Next.js project wrapper for this packaging step.
- `site/deploy/run-demo.sh` starts the packaged Next.js server on loopback and
  starts `h3-server` as the public HTTP/3 reverse proxy.
- `site/deploy/deploy-remote.sh` uploads the built binary, prepared app
  directory, runner script, and TLS material to the remote host.
- `site/deploy/coquic-demo.service` is the systemd unit installed on the
  remote host.
- `.github/workflows/deploy-demo.yml` is the GitHub Actions entrypoint.
- `.github/workflows/perf.yml` uploads the latest `perf-results.json` snapshot
  and appends `perf-history.json` into the live demo site after `main` branch
  perf runs.
- `.github/workflows/interop.yml` uploads the latest `interop-results.json`
  snapshot into the live demo site after `main` branch interop runs.
- `.github/workflows/test.yml` uploads the latest `coverage-results.json`
  summary and the full LLVM coverage HTML report into the live demo site after
  `main` branch test runs.

The current workflow builds `h3-server`, then uses the Next.js project scripts
to build the WASM dependencies, compile and smoke-test the WASM module, build
the standalone Next.js server, and package the app with
`coquic-wasm-quic.wasm` copied in from `zig-out/share/wasm-quic/`. The deploy
script accepts any prepared app directory as its second argument.

## GitHub Actions Inputs

GitHub Actions secrets:

- `COQUIC_DEMO_REMOTE_SSH_KEY`
- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`
- `OPENROUTER_API_KEY`
- `COQUIC_QDRANT_URL`
- `COQUIC_QDRANT_API_KEY`

GitHub Actions variables:

The workflow currently hardcodes both the SSH target host and the public
verification host to `coquic.minhuw.dev`, and it hardcodes the public port to
`443`. It also hardcodes the deploy user to `minhuw` and the SSH port to `22`.
The workflow writes `COQUIC_DEMO_REMOTE_SSH_KEY` to
`${RUNNER_TEMP}/coquic-demo.key`, and the deploy script uses that path by
default. The workflow also writes a pinned `known_hosts` file for
`coquic.minhuw.dev`, including its `ssh-rsa`, `ecdsa-sha2-nistp256`, and
`ssh-ed25519` host keys.

The workflow runs on pushes to `main` that touch the demo deployment surface,
and it also supports manual `workflow_dispatch` runs. The OpenRouter and
Qdrant secrets enable the `/qa` Ask page; if all three are omitted, the app
still deploys but the private RAG API is not started.

The perf workflow reuses `COQUIC_DEMO_REMOTE_SSH_KEY` to upload
`.bench-results/perf-results.json` and `.bench-results/perf-history.json` to:

- `/opt/coquic-demo/current/app/public/perf-results.json`
- `/opt/coquic-demo/current/app/public/perf-history.json`

The interop workflow reuses the same secret to upload
`.interop-results/interop-results.json` to:

- `/opt/coquic-demo/current/app/public/interop-results.json`

The test workflow reuses the same secret to upload `coverage/coverage-results.json`
and `coverage/html/` to:

- `/opt/coquic-demo/current/app/public/coverage-results.json`
- `/opt/coquic-demo/current/app/public/coverage/`

Those files are read by the public performance, interop, and coverage
dashboards. The performance dashboard uses `perf-results.json` for the latest
snapshot and `perf-history.json` for daily trends. The coverage dashboard links
to the full LLVM report at `/coverage/index.html`. The perf and interop
workflows run daily or via manual `workflow_dispatch`; the test workflow runs
on pushes and pull requests and can also be dispatched manually. Only runs on
the `main` branch publish snapshots to the demo machine.

## Remote Host Requirements

The remote machine must provide:

- Linux with `systemd`
- Node.js 20 or newer
- `curl`
- `uv` when the Ask/RAG API is enabled
- a deploy user reachable over SSH
- non-interactive `sudo` for `/opt/coquic-demo`, `/etc/coquic-demo/tls`,
  `/etc/systemd/system/coquic-demo.service`, and the required `systemctl`
  operations

Successful deploys leave `coquic-demo.service` enabled and active. Failed
deploys roll back the symlink, service unit, TLS files, and previous service
state before the temporary upload directory is removed.

## Release Layout

Each deployment writes a versioned release under:

- `/opt/coquic-demo/releases/<git-sha>/h3-server`
- `/opt/coquic-demo/releases/<git-sha>/run-demo.sh`
- `/opt/coquic-demo/releases/<git-sha>/app/`

The live release is selected through:

- `/opt/coquic-demo/current`

TLS material is installed at:

- `/etc/coquic-demo/tls/fullchain.pem`
- `/etc/coquic-demo/tls/privkey.pem`

When Ask/RAG credentials are provided, deploy writes them to:

- `/etc/coquic-demo/rag.env`

The file is mode `600` and is sourced by `run-demo.sh` before starting the
loopback FastAPI service.

## Verification

`site/deploy/deploy-remote.sh` verifies the release before it is kept:

- bootstrap HTTPS headers return `HTTP/1.1 200 OK`
- `Alt-Svc` advertises HTTP/3 on the public port
- direct `curl-http3 --http3-only` returns HTTP version `3`
- the fetched HTML still contains the stable `coquic-wasm-demo-v1` marker
- the wasm module is served from `coquic-wasm-quic.wasm` with
  `application/wasm`
- when Ask/RAG secrets are configured, `/rag-api/api/health` returns ready

## Manual Operation

Local packaging:

```bash
npm --prefix site/next install
npm --prefix site/next run build:demo
npm --prefix site/next run package:demo -- "${RUNNER_TEMP:-/tmp}/demo-app"
```

Manual CI-style deployment from a prepared workspace:

```bash
site/deploy/deploy-remote.sh "$(pwd)/zig-out/bin/h3-server" "/path/to/app-dir"
```

## Next.js Reverse Proxy Mode

Production uses `h3-server` as an HTTP/3 edge in front of a loopback Next.js
server. The Next.js server handles application routing and forwards `/rag-api/*`
to the loopback FastAPI service when that service is running.

```bash
npm --prefix site/next run build:wasm
npm --prefix site/next run dev
./zig-out/bin/h3-server \
  --host 127.0.0.1 \
  --port 4433 \
  --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3001 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```

The proxy target must currently be an `http://HOST:PORT` origin. CoQUIC
terminates TLS and HTTP/3, forwards requests to the upstream over HTTP/1.1, and
returns buffered upstream responses to the QUIC client.

## Manual Certificate Refresh

For this slice, manual certificate refresh is expected. Update these GitHub
Actions secrets:

- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`

Then rerun the `Deploy Demo` workflow via `workflow_dispatch`.
