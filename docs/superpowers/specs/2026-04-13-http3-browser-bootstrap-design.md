# HTTP/3 Browser Bootstrap Design

Date: 2026-04-13
Repo: `coquic`
Status: Approved

## Summary

Add an in-repo HTTPS bootstrap origin for `coquic h3-server` so browsers can
discover the existing UDP HTTP/3 endpoint through `Alt-Svc`.

This slice does not change the HTTP/3 core protocol engine. It adds a
runtime-only TCP/TLS listener that:

- serves the same static content root as the H3 runtime for `GET` and `HEAD`
- uses the same certificate identity and hostname as the H3 runtime
- emits `Alt-Svc: h3=":<udp-port>"; ma=<seconds>` on bootstrap responses
- remains isolated from `src/quic/`

## Problem

The current HTTP/3 runtime can already serve real QUIC+HTTP/3 traffic to the
repo-native client, but it still lacks the browser discovery path required by
the approved full HTTP/3 milestone.

Browsers generally learn that an origin supports HTTP/3 from an HTTPS response
that advertises `Alt-Svc`. Without that bootstrap origin:

- Chromium and Firefox cannot discover the repo-native H3 endpoint in-repo
- the runtime does not yet satisfy the approved browser-discovery requirement
- browser interop remains blocked even though the H3 endpoint itself exists

## Goals

- Start a minimal HTTPS bootstrap origin from `coquic h3-server`.
- Keep the bootstrap implementation runtime-only and out of `src/quic/`.
- Share certificate identity and document root with the H3 runtime.
- Emit configurable `Alt-Svc` headers advertising the UDP H3 endpoint.
- Keep the bootstrap origin minimal: synchronous HTTP/1.1 over TLS, `GET` and
  `HEAD` only.
- Add loopback test coverage for bootstrap content serving and `Alt-Svc`
  emission.
- Add a repo-owned browser setup note describing local certificate trust and
  manual discovery steps.

## Non-Goals

- No HTTP/2 bootstrap listener.
- No attempt to expose the bootstrap origin as a general-purpose web framework.
- No browser automation in this slice.
- No support for bootstrap `POST`, trailers, or dynamic application handlers.
- No runtime support for external reverse proxies as the primary discovery path.

## Chosen Architecture

### Module Layout

Add a focused runtime-only bootstrap module:

- `src/http3/http3_bootstrap.h`
- `src/http3/http3_bootstrap.cpp`

The existing runtime stays responsible for QUIC/H3. The new bootstrap module is
responsible for:

- TCP listener setup
- TLS accept and handshake
- minimal HTTP/1.1 request parsing
- static file response generation for `GET` and `HEAD`
- `Alt-Svc` header emission

### Runtime Integration

`Http3RuntimeConfig` grows these fields:

- `bootstrap_port`
- `alt_svc_max_age`

`h3-server` starts:

- the existing UDP HTTP/3 runtime on `config.port`
- the bootstrap HTTPS origin on `config.bootstrap_port`

If `--bootstrap-port` is not provided, it defaults to the same numeric port as
the UDP H3 listener. This keeps the origin coherent while still allowing
alternate layouts for testing.

The bootstrap origin runs in a dedicated runtime-owned thread so the existing
endpoint-driven QUIC loop can remain focused on UDP progress.

### TLS Model

The bootstrap origin reuses the configured certificate chain and private key.
It uses the same TLS backend libraries already linked into the project and
sticks to a small common OpenSSL-compatible surface that works across the repo’s
supported TLS backends.

The bootstrap listener only needs server-side TLS 1.3 with ordinary TCP I/O; it
does not reuse the QUIC TLS adapter.

### HTTP/1.1 Bootstrap Behavior

Supported requests:

- `GET /path`
- `HEAD /path`

Response behavior:

- `200` with file body for `GET`
- `200` with headers only for `HEAD`
- `404` for missing or invalid paths
- `405` with `Allow: GET, HEAD` for unsupported methods

All successful and error responses emit:

- `Alt-Svc`
- `Content-Length`
- `Connection: close`

Content serving should mirror the H3 runtime’s static-file path behavior:

- `/` maps to `index.html`
- lexical path containment only; no raw dot-segment traversal
- same document root as `h3-server`

### `Alt-Svc` Value

The default advertised value is:

- `h3=":<udp-port>"; ma=60`

`ma` is configurable through `--alt-svc-max-age`.

The bootstrap listener always advertises the UDP H3 port from the same runtime
configuration, not the TCP bootstrap port.

## Testing

Add dedicated bootstrap/runtime tests that cover:

- parsing `--bootstrap-port` and `--alt-svc-max-age`
- `Alt-Svc` value formatting
- loopback HTTPS bootstrap `GET`
- loopback HTTPS bootstrap `HEAD`
- bootstrap body/content parity with the runtime’s static files

The loopback tests should use a small TLS client helper in the test binary
rather than an external tool.

## Documentation

Add a short repo doc for manual Chromium and Firefox setup covering:

- trusting the local certificate
- starting `coquic h3-server` with bootstrap enabled
- visiting the HTTPS bootstrap origin first
- inspecting the `Alt-Svc` response header
- confirming that the browser upgrades subsequent requests to HTTP/3

## Acceptance Criteria

- `coquic h3-server` starts both the UDP H3 listener and a TCP/TLS bootstrap
  listener.
- The bootstrap listener serves static `GET` and `HEAD` responses over HTTPS.
- Bootstrap responses emit `Alt-Svc` advertising the H3 endpoint.
- The H3 runtime and bootstrap origin share certificate and document root.
- Focused loopback tests verify bootstrap HTTPS content and `Alt-Svc`.
- The broader `QuicHttp3*` suite remains green.
