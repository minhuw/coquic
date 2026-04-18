# Demo Deployment

This document covers the remote continuous deployment flow for the public
`coquic` demo.

## Repo Layout

- `demo/site/` is the current repo-owned demo source.
- `demo/deploy/package-demo.sh` packages the current demo document root.
- `demo/deploy/deploy-remote.sh` uploads the built binary, prepared site
  directory, and TLS material to the remote host.
- `demo/deploy/coquic-demo.service` is the systemd unit installed on the
  remote host.
- `.github/workflows/deploy-demo.yml` is the GitHub Actions entrypoint.

The current workflow packages `demo/site/`, but the deploy script already
accepts any prepared document-root directory as its second argument. That keeps
the remote release layout stable if the site later comes from a richer build
step instead of a checked-in static directory.

## GitHub Actions Inputs

GitHub Actions secrets:

- `COQUIC_DEMO_REMOTE_SSH_KEY`
- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`

GitHub Actions variables:

- `COQUIC_DEMO_REMOTE_HOST`
- `COQUIC_DEMO_REMOTE_USER`
- `COQUIC_DEMO_REMOTE_SSH_PORT`
- `COQUIC_DEMO_PUBLIC_HOST`
- `COQUIC_DEMO_PUBLIC_PORT`
- `COQUIC_DEMO_REMOTE_KNOWN_HOSTS`

The workflow runs on pushes to `main` that touch the demo deployment surface,
and it also supports manual `workflow_dispatch` runs.

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
- the fetched HTML still contains the stable `coquic-demo-v1` marker

## Manual Operation

Local packaging:

```bash
demo/deploy/package-demo.sh "${RUNNER_TEMP:-/tmp}/demo-site"
```

Manual CI-style deployment from a prepared workspace:

```bash
demo/deploy/deploy-remote.sh "$(pwd)/zig-out/bin/h3-server" "/path/to/site-dir"
```

## Manual Certificate Refresh

For this slice, manual certificate refresh is expected. Update these GitHub
Actions secrets:

- `COQUIC_DEMO_CERT_CHAIN_PEM`
- `COQUIC_DEMO_PRIVATE_KEY_PEM`

Then rerun the `Deploy Demo` workflow via `workflow_dispatch`.
