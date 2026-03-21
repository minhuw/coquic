# GitHub Interop CI Design

## Status

Approved in conversation on 2026-03-21.

## Goal

Add a separate GitHub Actions workflow dedicated to QUIC interop smoke testing
against `quic-go`, while keeping the existing main CI focused on formatting,
linting, build, unit tests, and coverage.

## Scope

This workflow covers only the currently supported external interop slice:

- `quic-go` as client against `coquic` as server:
  - `handshake`
  - ideal-case `transfer`
- `coquic` as client against `quic-go` as server:
  - `handshake`
  - ideal-case `transfer`

## Non-Goals

- full `quic-interop-runner` or `quic-network-simulator` integration in GitHub CI
- lossy-network or congestion-competition scenarios
- testing against implementations other than `quic-go`
- folding interop execution into the existing `ci.yml`

## Decisions

### 1. Use A Separate Workflow

Add `.github/workflows/interop.yml` instead of extending `ci.yml`.

Triggers:

- `pull_request`
- `push`
- `workflow_dispatch`

This keeps interop status independently visible and avoids coupling slower
Docker-based smoke tests to the main build / coverage job.

### 2. Reuse A Repo-Owned Local Smoke Script

Add a checked-in shell script that performs the mixed-image `coquic` / `quic-go`
interop matrix locally and in GitHub Actions.

The workflow should call that script directly rather than embedding a large
inline Docker script into YAML.

### 3. Build Only The Musl Interop Image

The workflow should build and load only:

- `.#interop-image-boringssl-musl`
- Docker tag `coquic-interop:boringssl-musl`

That is the canonical interop image and already aligns with the official
endpoint wrapper contract.

### 4. Keep The Workflow Single-Job

Use one `interop-quicgo` job that:

1. checks out the repo
2. installs Nix and enables cache
3. builds / loads the musl interop image
4. pulls `martenseemann/quic-go-interop:latest`
5. runs the local smoke script

This avoids redundant image builds across matrix jobs while still giving a
separate workflow result in GitHub.

### 5. Preserve Debuggability

The smoke script should print per-case names and container logs on failure so
GitHub job logs are sufficient for first-pass debugging without rerunning
locally immediately.
