# CoQUIC Perf Runner Container

This image layers CoQUIC's Nix setup on top of
`myoung34/github-runner:2.334.0-ubuntu-noble`, which provides the GitHub Actions
self-hosted runner lifecycle and common CI tools.

The container intentionally uses the host Docker socket. The benchmark endpoint
containers created by `bench/run-host-matrix.sh` therefore run as sibling
containers on the host Docker daemon, so `PERF_SERVER_CPUS` and
`PERF_CLIENT_CPUS` pin real host CPUs instead of nested Docker CPUs.

The upstream image is GPL-3.0 licensed. Keep that in mind if publishing a
derived image outside this repository.

## Run

Create `.github/perf-runner/.env`:

```sh
REPO_URL=https://github.com/minhuw/coquic
RUNNER_TOKEN=short_lived_registration_token_from_github
RUNNER_NAME=coquic-perf-1
LABELS=coquic-perf,docker,nix
RUNNER_WORKDIR=/home/minhu/coquic-perf-runner/_work
CONFIGURED_ACTIONS_RUNNER_FILES_DIR=/home/minhu/coquic-perf-runner/config
DISABLE_AUTOMATIC_DEREGISTRATION=true
RUN_AS_ROOT=true
```

Then start the runner:

```sh
docker compose --env-file .github/perf-runner/.env \
  -f .github/perf-runner/compose.yml up -d --build
```

The registration token expires after one hour. Persisting
`CONFIGURED_ACTIONS_RUNNER_FILES_DIR` keeps the configured runner identity on
the host, so the token is only needed for first registration or if the GitHub
runner record is deleted.

Run a single runner container on the benchmark host. If multiple containers have
the same `coquic-perf` label, GitHub may run matrix entries concurrently and the
benchmark numbers will be noisy.

`RUNNER_WORKDIR` must be an absolute host path that is mounted at the same
absolute path inside the runner container. The perf script starts sibling
containers through the host Docker socket, and those sibling containers bind
mount the checked-out repository and result directories by absolute path.

## Workflow Routing

`.github/workflows/perf.yml` routes only the benchmark implementation matrix to
`self-hosted`, `Linux`, `X64`, and `coquic-perf`. Keep `perf-config` and
`publish-perf-results` on `ubuntu-latest`; the publish job uses deployment
credentials and does not need benchmark hardware.

## Host Notes

- Keep the host dedicated while the perf workflow is running.
- Prefer a fixed CPU governor such as `performance`.
- Start the runner container on housekeeping CPUs, for example CPU `0-1`, while
  the benchmark script keeps using CPU `2` for the server and CPU `3` for the
  client.
- Keep Docker Engine current on the host. The runner image provides the Docker
  CLI, but the mounted host daemon runs the benchmark containers.
- Mounting `/var/run/docker.sock` gives jobs effective control of host Docker.
  Only route trusted workflows to this runner.
- The compose file runs the runner as root by default because Docker socket
  group IDs vary by host. This does not materially change the trust boundary
  once `/var/run/docker.sock` is mounted.
