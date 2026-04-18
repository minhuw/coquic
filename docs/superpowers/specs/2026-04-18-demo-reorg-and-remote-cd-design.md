# Demo Reorg And Remote CD Design

Date: 2026-04-18
Repo: `coquic`
Status: Approved

## Summary

Reorganize the public demo into a dedicated `demo/` directory, remove the
current smoke-test-based demo workflow, and replace the ad hoc localhost demo
setup with a GitHub Actions driven remote deployment flow.

The first deployment mode remains static-site serving through `h3-server`.
The repo layout must still anticipate a future Next.js-based site under the
same `demo/` umbrella, without assuming the site will always be a simple static
`www/` directory.

The deployment target is a remote Linux machine managed through SSH and a
system-level `systemd` service. The built `h3-server` binary, packaged site
artifact, certificate chain, and private key are all supplied during CI
deployment. Certificate rotation is explicitly manual in this slice.

The existing signed certificate material should be kept, but the live demo
served from the current localhost machine should be removed.

## Problem

The current demo layout is spread across unrelated locations:

- the site source of truth lives under `docker/h3-server/www/`
- validation relies on repo-local smoke tests rather than deployment-oriented
  release verification
- the live demo has been managed locally on this machine rather than through a
  repeatable remote deployment path

That layout makes the demo harder to manage and does not line up with the next
phase, where the demo site may evolve into a larger application, potentially a
Next.js project, while still being served behind `h3-server`.

## Goals

- Move the demo into a dedicated `demo/` directory.
- Keep `demo/` stable even if the site becomes a Next.js project later.
- Remove the current smoke tests for the demo.
- Add a checked-in deployment path for remote continuous deployment from
  GitHub Actions.
- Deploy the built `h3-server` QUIC binary to the remote machine as part of CD.
- Run the public demo on a remote Linux host as a system-level `systemd`
  service.
- Keep the deployment static-site-first for now.
- Preserve the existing signed certificate material, but stop serving the demo
  locally on this machine.

## Non-Goals

- No reverse-proxy mode in this slice.
- No Next.js runtime deployment in this slice.
- No automatic certificate renewal in this slice.
- No containerized demo deployment in this slice.
- No attempt to preserve the existing localhost live service after the new
  deployment model is introduced.

## Chosen Architecture

### Repo Layout

The demo moves under a dedicated top-level `demo/` directory with separate
source and deployment concerns.

Planned structure:

- `demo/site/`
  - source for the public demo site
  - today this can hold a minimal static page
  - later this can become a Next.js app root without changing the top-level
    layout
- `demo/deploy/package-demo.sh`
  - packages `demo/site/` into a deployable artifact
  - hides whether the site started as plain static files or a future app build
- `demo/deploy/deploy-remote.sh`
  - CI-facing deployment entrypoint
  - uploads release artifacts and installs them on the remote host
- `demo/deploy/coquic-demo.service`
  - systemd service template for the remote host
- `.github/workflows/deploy-demo.yml`
  - builds the binary, packages the site, deploys to the remote host, and
    verifies the public URL
- `docs/demo-deployment.md`
  - operator-facing deployment and secrets documentation

### Runtime Model

The first deployment mode is direct static serving through `h3-server`.

- `h3-server` remains the public edge process
- it owns TLS, QUIC/HTTP/3, and the public service port
- it serves the packaged site artifact directly from disk

This model is intentionally simpler than a reverse proxy. It preserves a clean
path to a future model where `h3-server` can become the HTTP/3 front end for a
dynamic app, but that future mode is not part of this design.

### Remote Host Layout

The remote host uses durable, versioned release directories plus a stable
service unit.

Planned layout:

- `/opt/coquic-demo/releases/<git-sha>/h3-server`
- `/opt/coquic-demo/releases/<git-sha>/site/`
- `/opt/coquic-demo/current`
  - symlink to the active release
- `/etc/coquic-demo/tls/fullchain.pem`
- `/etc/coquic-demo/tls/privkey.pem`
- `/etc/systemd/system/coquic-demo.service`
- `/var/log/coquic-demo/`
  - optional if journald alone is insufficient

### Remote Service Behavior

The remote service is a system-level `systemd` unit.

- service name: `coquic-demo.service`
- runs `h3-server` directly
- serves content from `/opt/coquic-demo/current/site`
- reads TLS from `/etc/coquic-demo/tls`
- uses restart-on-failure behavior
- binds the public demo port directly

This assumes the remote deployment user can use `sudo` non-interactively for
installation and service restart steps.

### Deployment Flow

GitHub Actions performs the deployment.

High-level flow:

1. Build `h3-server` for `x86_64-linux-musl`
2. Package `demo/site/` through `demo/deploy/package-demo.sh`
3. Materialize GitHub Secrets in CI:
   - SSH private key
   - remote host/user configuration
   - certificate chain
   - certificate private key
4. Run `demo/deploy/deploy-remote.sh`
5. Install a versioned release on the remote host
6. Update `/opt/coquic-demo/current`
7. Restart `coquic-demo.service`
8. Verify the public deployment over HTTPS bootstrap and HTTP/3

The workflow should run on:

- pushes to `main` that affect the demo deployment surface
- manual `workflow_dispatch` for operator-triggered redeploys

### Rollback Behavior

The deploy script should keep the previous release available during rollout.

If post-deploy verification fails:

- restore the previous `/opt/coquic-demo/current` symlink target
- restart `coquic-demo.service`
- fail the workflow

This gives the deployment path a basic rollback mechanism without requiring a
container registry or release manager.

## Packaging Contract

`demo/deploy/package-demo.sh` is the single packaging boundary for the demo
site.

Responsibilities:

- accept `demo/site/` as the site source
- produce a deployable directory or archive for remote installation
- hide whether the source was:
  - a minimal static page
  - a future generated static artifact
  - a future app-oriented build output

`demo/deploy/deploy-remote.sh` should consume only:

- the built `h3-server` binary
- the packaged site artifact
- certificate material
- remote connection settings

It should not need to understand how the site was authored internally.

## CI Workflow Contract

The GitHub Actions workflow should:

- run on the chosen deployment trigger
- build the Linux musl demo binary
- package the site
- authenticate to the remote host over SSH
- install release files and TLS material
- restart the systemd service
- verify:
  - bootstrap HTTPS response
  - `Alt-Svc` presence
  - direct HTTP/3 response
  - expected demo markers in fetched HTML

The verification step replaces the role previously played by the deleted smoke
tests for the public demo workflow.

## Files To Remove Or Replace

The implementation should remove the current demo smoke-test structure.

Expected removals:

- `tests/nix/h3_demo_page_contract_test.sh`
- `tests/nix/h3_server_container_smoke_test.sh`

Expected source-of-truth move:

- move the demo page out of `docker/h3-server/www/index.html`
- replace it with the new `demo/site/` source layout

Docs should be updated so deployment-oriented demo documentation lives under a
dedicated demo deployment path rather than container-smoke-oriented guidance.

## Localhost Teardown

The existing localhost-served live demo should be removed.

Implementation expectations:

- stop the local demo service currently serving the demo on this machine
- disable it so it does not continue serving locally
- keep the existing signed certificate files on disk
- do not keep the localhost demo active after this design is implemented

This preserves the signed certificate material while removing the now-obsolete
local live-serving arrangement.

## Security And Secrets

Secrets used by CI:

- SSH private key
- remote host/user configuration
- certificate chain
- certificate private key

The workflow should also receive explicit remote and verification settings, for
example:

- remote SSH port if non-default
- public demo host
- public demo port

The design assumes these are provided through GitHub Actions secrets and are
materialized only during deployment.

The remote deployment should write TLS material into `/etc/coquic-demo/tls`
with restrictive permissions suitable for a root-managed service.

## Future Evolution

This design intentionally leaves room for a future Next.js-based site.

The stable contract is:

- `demo/site/` is the site source area
- `demo/deploy/package-demo.sh` is the packaging boundary
- `h3-server` remains the public edge

Later, if the site stops being purely static, the deploy model can evolve from
direct static serving to an `h3-server` front end plus reverse-proxy behavior.
That change should not require another top-level repo reorganization.

## Risks

- Manual certificate handling means cert refreshes can be forgotten.
- Remote host setup depends on correct `sudo` and `systemd` access for the
  deploy user.
- Removing smoke tests reduces local demo-specific guardrails unless the CI
  deployment verification is implemented well.
- Future Next.js requirements may require packaging changes sooner than
  expected, so the packaging boundary should stay simple and explicit.

## Acceptance Criteria

- Demo source lives under `demo/`.
- The current demo smoke tests are removed.
- A checked-in remote deployment path exists under `demo/deploy/`.
- GitHub Actions can deploy:
  - the built `h3-server` binary
  - the packaged demo site
  - certificate material from CI secrets
- The remote host runs the public demo through a system-level `systemd`
  service.
- The deployment supports rollback to the previous release on failed
  verification.
- The localhost live demo is stopped and disabled.
- Existing signed certificate files are preserved on disk.
- The design keeps a clear migration path to a future Next.js site behind the
  same `h3-server` public edge.
