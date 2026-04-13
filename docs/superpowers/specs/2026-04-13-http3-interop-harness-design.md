# HTTP/3 Interop Harness Design

Date: 2026-04-13
Repo: `coquic`
Status: Approved

## Summary

Add a dedicated HTTP/3 official-runner harness alongside the existing QUIC
HTTP/0.9 interop harness.

This slice keeps the current `interop-server` / `interop-client` surface
unchanged for the existing QUIC transport matrix and adds a separate
runner-facing HTTP/3 surface for the official runner's `http3` testcase only.

The new surface should:

- add `h3-interop-server` and `h3-interop-client` subcommands in the existing
  `coquic` binary
- reuse the already working `src/http3/` runtime and protocol stack
- support both directions of the official runner's `http3` testcase
- leave the existing HTTP/0.9 interop path untouched for non-`http3` cases

## Problem

The repository now has a working first-class HTTP/3 runtime:

- `h3-server`
- `h3-client`
- dynamic-table QPACK
- local `curl --http3` verification
- browser bootstrap via HTTPS plus `Alt-Svc`

However, the checked-in official interop harness under `interop/` still targets
the older QUIC HTTP/0.9 runner surface:

- `interop-server`
- `interop-client`

That harness was designed for the runner's generic QUIC testcase matrix, where
most transfer-style cases use HTTP/0.9. The pinned official
`quic-interop-runner` revision used by this repo also defines a distinct
`http3` testcase for parallel file downloads over HTTP/3.

Without a dedicated HTTP/3 runner-facing surface:

- the repo cannot run the official runner's HTTP/3 testcase against the new
  HTTP/3 implementation
- the current interop wrapper cannot prove HTTP/3 runner compatibility in CI or
  locally
- the HTTP/3 runtime remains verified by repo-native tests and ad hoc external
  clients, but not by the repo-owned official-runner flow

## Goals

- Add a dedicated official-runner-facing HTTP/3 harness.
- Keep the existing HTTP/0.9 interop harness unchanged.
- Support the official runner's `http3` testcase in both directions:
  - `coquic` as server
  - `coquic` as client
- Reuse the existing HTTP/3 runtime and avoid duplicating H3 protocol logic.
- Keep the first slice narrowly scoped to the official `http3` testcase only.
- Make the checked-in `interop/run-official.sh` path usable for local and CI
  HTTP/3 interop validation.

## Non-Goals

- No changes to the semantics of the current HTTP/0.9 `interop-server` /
  `interop-client` path.
- No attempt to support the entire existing QUIC testcase matrix through the
  new HTTP/3 harness.
- No browser bootstrap or `Alt-Svc` behavior in the HTTP/3 runner harness.
- No new standalone executable in this slice.
- No attempt to expose runner-specific behavior through the public
  developer-facing `h3-server` / `h3-client` CLI.

## Official Runner Contract

The pinned `quic-interop-runner` revision used by this repo defines a dedicated
QUIC testcase:

- `http3`

That testcase is distinct from the generic `transfer` case. It expects:

- HTTPS request URLs
- multiple files
- parallel downloads over HTTP/3
- a single successful QUIC handshake

The runner continues to use the standard QUIC implementation manifest and the
existing simulator contract. The relevant environment passed into the
implementation containers remains:

- `ROLE`
- `TESTCASE`
- `HOST`
- `PORT`
- `CERTS`
- `REQUESTS`
- mounted server document root `/www`
- mounted client download root `/downloads`

The new harness should fit into that existing container contract rather than
introducing a second packaging model.

## Chosen Architecture

### Separate Runner-Facing HTTP/3 Commands

Add two new subcommands to the existing `coquic` binary:

- `h3-interop-server`
- `h3-interop-client`

These are runner-facing commands, not general developer-facing commands.

They exist to preserve a clean protocol boundary:

- `interop-server` / `interop-client` remain the HTTP/0.9 interop surface
- `h3-interop-server` / `h3-interop-client` become the HTTP/3 interop surface

This keeps the existing harness stable while still allowing the official runner
to exercise the new HTTP/3 implementation.

### Thin Wrapper Layer

The new interop commands should be thin wrappers over `src/http3/` runtime
behavior, not a second independent HTTP/3 implementation.

Recommended ownership:

- `src/http3/http3_interop.h`
- `src/http3/http3_interop.cpp`

This layer should:

- parse runner-oriented env or CLI inputs
- validate testcase support
- translate runner contract into HTTP/3 runtime operations
- return runner-compatible exit codes

It should not absorb HTTP/3 connection semantics, QPACK logic, or request /
response protocol machinery. Those stay in the existing HTTP/3 runtime and
endpoint layers.

### `main.cpp` Dispatch

`src/main.cpp` should dispatch these new subcommands directly to the HTTP/3
interop layer, alongside the existing:

- `h3-server`
- `h3-client`
- HTTP/0.9 runtime path

The existing HTTP/0.9 runtime parser should not need to know about the new H3
interop commands.

## Wrapper Dispatch

The checked-in container wrapper under `interop/entrypoint.sh` should dispatch
by testcase family.

Behavior:

- if `ROLE=server` and `TESTCASE=http3`, exec `coquic h3-interop-server`
- if `ROLE=client` and `TESTCASE=http3`, exec `coquic h3-interop-client`
- otherwise preserve the current behavior:
  - `coquic interop-server`
  - `coquic interop-client`

This keeps HTTP/0.9 behavior fully stable for the existing transport-oriented
QUIC matrix, while letting the same official wrapper drive the new H3 testcase.

## Server Behavior

`h3-interop-server` should:

- support only `TESTCASE=http3`
- return `127` for any other testcase
- serve static files from the runner-mounted document root
- listen on the runner-provided UDP host and port
- use the runner-mounted certificate and private key
- run pure HTTP/3 on QUIC without starting the browser bootstrap HTTPS listener

The browser bootstrap listener is a developer/browser discovery feature, not a
requirement of the official `http3` testcase.

## Client Behavior

`h3-interop-client` should:

- support only `TESTCASE=http3`
- return `127` for any other testcase
- read the runner-provided `REQUESTS` list of HTTPS URLs
- establish one HTTP/3 connection to the runner server
- issue the file requests in parallel on distinct request streams
- write the downloaded files into the runner-mounted download directory using
  the expected output filenames
- fail the testcase if any transfer fails, any output file is missing, or the
  HTTP/3 transaction layer reports failure

This is intentionally different from the existing developer-facing `h3-client`
shape, which currently focuses on a single request. The runner-facing H3 client
needs a small multi-request orchestration layer above the existing runtime
primitives.

## Error Handling

The new H3 interop commands should use runner-compatible exit behavior:

- `127` for unsupported testcase values
- `1` for invalid or incomplete runner inputs
- `1` for protocol, transport, or transfer failure
- `0` only when the requested H3 transfer lane completes successfully

Error messages should stay short and operational. The main audience is the
official runner logs.

## Testing

Add focused coverage for:

- CLI and env parsing for `h3-interop-server`
- CLI and env parsing for `h3-interop-client`
- unsupported testcase behavior returning `127`
- wrapper dispatch in `interop/entrypoint.sh` for `TESTCASE=http3`
- preservation of the current HTTP/0.9 wrapper dispatch for non-`http3` cases
- multi-request H3 client behavior:
  - repeated HTTPS URL parsing
  - one connection
  - parallel request submission
  - output file writes into the download root

The first slice does not require the entire official runner to be exercised in
unit tests, but it does require at least one checked local verification path
through `interop/run-official.sh` for the `http3` testcase.

## Documentation

Update `interop/README.md` to describe:

- the unchanged HTTP/0.9 interop surface
- the new HTTP/3 interop surface
- the fact that official `TESTCASE=http3` dispatches to the H3 interop commands
- how to run the official runner locally for the H3 testcase

## Acceptance Criteria

- The current HTTP/0.9 interop harness behavior is unchanged for non-`http3`
  testcases.
- `interop/entrypoint.sh` dispatches `TESTCASE=http3` to dedicated H3 runner
  commands.
- `coquic` can act as both H3 server and H3 client for the official runner's
  `http3` testcase.
- The H3 interop client downloads the runner-provided files over one HTTP/3
  connection and writes the expected outputs.
- The checked-in local official-runner wrapper can execute the `http3` lane
  against the new H3 harness.
- Local verification includes at least:
  - focused H3 interop tests
  - wrapper-dispatch coverage
  - one local official-runner `http3` execution path

## Deferred Work

This first slice deliberately defers:

- extending the new H3 interop harness to additional QUIC testcase families
- merging the H3 interop client orchestration into the general developer-facing
  `h3-client` CLI
- browser-oriented verification through the official runner path
- broader HTTP/3 interop CI expansion beyond the initial `http3` testcase
