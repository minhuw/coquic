# Demo Deployment

This document covers the remote continuous deployment flow for the public
`coquic` demo.

## Repo Layout

- `demo/next/` is the framework-backed browser demo source. It owns the
  homepage, workbench, performance, interop, and coverage HTML routes.
- `demo/wasm-quic/` contains browser runtime assets used by those routes:
  shared theme/logo files, dashboard scripts, benchmark snapshots, and the
  installed WASM module.
- `demo/h3-server/Dockerfile` is the optional container wrapper for serving
  the built `h3-server` binary and packaged demo assets.
- `zig build wasm-quic` writes the deployable document root to
  `zig-out/share/wasm-quic/`, including `coquic-wasm-quic.wasm`.
- `npm --prefix demo/next run build` writes the Next.js static export to
  `demo/next/out/`.
- `demo/deploy/package-demo.sh` packages the built wasm runtime assets, then
  overlays the Next.js HTML routes and `_next/` assets.
- `demo/deploy/deploy-remote.sh` uploads the built binary, prepared site
  directory, and TLS material to the remote host.
- `demo/deploy/coquic-demo.service` is the systemd unit installed on the
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

The current workflow builds the wasm demo first, builds the Next.js static
export, then packages `zig-out/share/wasm-quic/` with the exported Next.js
HTML routes and `_next/` assets from `demo/next/out/`. The deploy script keeps
the built wasm runtime assets authoritative for JavaScript, CSS, images, data,
and `coquic-wasm-quic.wasm` so a Next public symlink cannot overwrite the
fresh build output. The deploy script accepts any prepared document-root
directory as its second argument, so the remote release layout stays stable.

## GitHub Actions Inputs

GitHub Actions secrets:

- `COQUIC_DEMO_REMOTE_SSH_KEY`
- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`

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
and it also supports manual `workflow_dispatch` runs.

The perf workflow reuses `COQUIC_DEMO_REMOTE_SSH_KEY` to upload
`.bench-results/perf-results.json` and `.bench-results/perf-history.json` to:

- `/opt/coquic-demo/current/site/perf-results.json`
- `/opt/coquic-demo/current/site/perf-history.json`

The interop workflow reuses the same secret to upload
`.interop-results/interop-results.json` to:

- `/opt/coquic-demo/current/site/interop-results.json`

The test workflow reuses the same secret to upload `coverage/coverage-results.json`
and `coverage/html/` to:

- `/opt/coquic-demo/current/site/coverage-results.json`
- `/opt/coquic-demo/current/site/coverage/`

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
- `/opt/coquic-demo/releases/<git-sha>/site/`

The live release is selected through:

- `/opt/coquic-demo/current`

TLS material is installed at:

- `/etc/coquic-demo/tls/fullchain.pem`
- `/etc/coquic-demo/tls/privkey.pem`

## Verification

`demo/deploy/deploy-remote.sh` verifies the release before it is kept:

- bootstrap HTTPS headers return `HTTP/1.1 200 OK`
- `Alt-Svc` advertises HTTP/3 on the public port
- direct `curl-http3 --http3-only` returns HTTP version `3`
- the fetched HTML still contains the stable `coquic-wasm-demo-v1` marker
- the wasm module is served from `coquic-wasm-quic.wasm` with
  `application/wasm`

## Manual Operation

Local packaging:

```bash
nix develop -c zig build wasm-quic -Doptimize=ReleaseSmall --summary all
npm --prefix demo/next install
npm --prefix demo/next run build
demo/deploy/package-demo.sh "${RUNNER_TEMP:-/tmp}/demo-site" "$(pwd)/zig-out/share/wasm-quic" "$(pwd)/demo/next/out"
```

Manual CI-style deployment from a prepared workspace:

```bash
demo/deploy/deploy-remote.sh "$(pwd)/zig-out/bin/h3-server" "/path/to/site-dir"
```

## Next.js Reverse Proxy Mode

`h3-server` can also serve as an HTTP/3 edge in front of a running Next.js
server:

```bash
npm --prefix demo/next run dev
./zig-out/bin/h3-server \
  --host 127.0.0.1 \
  --port 4433 \
  --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3000 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```

The proxy target must currently be an `http://HOST:PORT` origin. CoQUIC
terminates TLS and HTTP/3, forwards requests to the upstream over HTTP/1.1, and
returns buffered upstream responses to the QUIC client. The static export path
remains the production deploy path.

## Manual Certificate Refresh

For this slice, manual certificate refresh is expected. Update these GitHub
Actions secrets:

- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`

Then rerun the `Deploy Demo` workflow via `workflow_dispatch`.
