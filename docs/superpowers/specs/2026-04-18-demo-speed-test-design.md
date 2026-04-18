# Demo HTTP/3 Speed Test Design

## Summary

Replace the current demo diagnostics page with a focused HTTP/3 speed test that mirrors the
core interaction model of `https://speed.cloudflare.com/` without attempting to become a
general-purpose benchmarking product.

The new demo will:

- remove all existing diagnostics-oriented page content
- present a single speed-test experience with one primary `Start test` action
- measure browser-observable latency, download throughput, and upload throughput against the
  running `h3-server`
- extend the runtime HTTP/3 demo routes with dedicated speed-test endpoints instead of reusing
  the existing inspect and echo diagnostics routes for measurement semantics

This design is intentionally narrow. It optimizes for a credible public demo that is easy to
understand, quick to run, and low-risk to operate.

## Goals

- provide a clean, public-facing QUIC/HTTP/3 demo page instead of a diagnostics console
- measure the client-to-server path that the browser actually uses against the deployed `h3-server`
- keep the run balanced, with a total duration around 10 to 15 seconds
- use browser-side JavaScript only for the page itself
- keep the implementation inside the existing `h3-server` runtime and `demo/site/index.html`

## Non-Goals

- no historical charts or saved benchmark history
- no packet loss, jitter, or route quality analytics
- no multi-region comparison or CDN-style geo selection
- no server-side session tracking or persistent telemetry
- no claim that JavaScript can directly prove negotiated QUIC version or ALPN details
- no extended benchmarking mode beyond the default balanced test

## User Experience

### Page Shape

The page becomes a single-column speed test with no diagnostics affordances.

Visible content at rest:

- a compact hero with the title `coquic HTTP/3 speed test`
- a one-line description explaining that the test measures QUIC latency, download, and upload
  against `coquic.minhuw.dev`
- one primary `Start test` button
- three metric cards: `Latency`, `Download`, `Upload`
- one minimal progress region with a slim bar and a single current-phase label
- one compact footer summary region shown after a run

The following existing content must be removed:

- showcase and technical mode toggles
- all live diagnostics copy
- all DevTools instructions
- all raw JSON panels
- all inspect and echo status boxes
- all remnants of the previous diagnostics experience

### Run Flow

The run sequence is linear and minimal:

1. `Connecting`
2. `Latency`
3. `Download`
4. `Upload`
5. `Complete`

Behavior rules:

- only one phase is visually active at a time
- the `Start test` button is disabled during a run
- metric cards update only when their phase completes, not as noisy live counters
- a failed phase stops the run immediately
- successful prior phases keep their completed values on failure
- the page exposes only one retry action: run the same test again

### Result Presentation

Displayed result units:

- `Latency`: median round-trip time in milliseconds
- `Download`: aggregate throughput in megabits per second
- `Upload`: aggregate throughput in megabits per second

Footer summary fields:

- run timestamp
- tested host
- latency sample count
- download duration and worker count
- upload duration and worker count
- final run state: complete or failed

## Measurement Model

The page measures browser-observable behavior only. It does not attempt to infer protocol
internals that browser JavaScript cannot access directly.

### Latency

Use `GET /_coquic/speed/ping` for several small round trips.

Default behavior:

- 7 samples
- each request uses `cache: "no-store"`
- report the median latency in milliseconds

The page should measure wall-clock round-trip time using `performance.now()`.

### Download

Use `GET /_coquic/speed/download?bytes=N` to fetch generated response bodies.

Default behavior:

- 4 parallel workers
- target phase duration about 4.5 seconds
- each worker repeatedly fetches payloads until the phase deadline expires
- throughput is computed from total received bytes divided by elapsed phase time

The browser should consume the response body as bytes and count actual transferred bytes rather
than assuming `Content-Length` alone.

### Upload

Use `POST /_coquic/speed/upload` to submit binary payloads that the server counts and discards.

Default behavior:

- 4 parallel workers
- target phase duration about 4.5 seconds
- each worker repeatedly POSTs generated payloads until the phase deadline expires
- throughput is computed from total submitted bytes divided by elapsed phase time

The server must not echo the upload body back. Returning the payload would distort semantics and
roughly double traffic.

## Server Route Design

The dedicated speed routes should live in the existing runtime HTTP/3 server path alongside the
existing demo routes.

### `GET /_coquic/speed/ping`

Purpose:

- provide a minimal request for browser RTT measurement

Response:

- status `204 No Content`
- no body
- `cache-control: no-store`

Method handling:

- allow `GET` and `HEAD`
- return `405` with `allow: GET, HEAD` for other methods

### `GET /_coquic/speed/download?bytes=N`

Purpose:

- provide explicit server-generated download payloads sized by request

Request rules:

- require a `bytes` query parameter
- `bytes` must parse as a positive integer
- reject zero, malformed, negative-like, or over-limit values with `400`

Response:

- status `200`
- body length exactly `N`
- `content-type: application/octet-stream`
- `cache-control: no-store`

Method handling:

- allow `GET` and `HEAD`
- return `405` with `allow: GET, HEAD` for other methods

Payload generation:

- generate bytes in memory for the current request
- use deterministic content; cryptographic randomness is unnecessary
- do not read from disk for these speed-test payloads

### `POST /_coquic/speed/upload`

Purpose:

- accept upload bodies and return only a tiny acknowledgement

Request rules:

- allow `POST` only
- accept binary request bodies
- count received bytes from the request body
- enforce a maximum accepted request size

Response:

- status `200`
- compact JSON body containing at least `received_bytes`
- `content-type: application/json`
- `cache-control: no-store`

Method handling:

- return `405` with `allow: POST` for non-POST methods

## Safety And Limits

Because this demo is public-facing, the speed routes need bounded behavior.

Required server-side limits:

- maximum allowed `bytes` for a single download request
- maximum accepted request body size for a single upload request
- reject out-of-range requests with `400` rather than attempting partial behavior

Recommended initial sizing:

- per-download request cap: low single-digit megabytes
- per-upload request cap: low single-digit megabytes

The exact constants should be implementation-level configuration, but the public behavior should
remain conservative enough to avoid obvious abuse while still supporting the balanced test.

All speed routes must send `cache-control: no-store` so browser and intermediary caches do not
pollute results.

## UI Implementation Boundaries

- keep the page in the existing static `demo/site/index.html`
- use plain HTML, CSS, and browser JavaScript only
- do not add a frontend framework
- do not add third-party analytics or visualization libraries
- default to a light, technical, deliberate visual style
- use large numeric result presentation with restrained motion
- respect `prefers-reduced-motion`

### Visual Direction

The page should feel like a focused technical measurement tool, not a marketing landing page and
not a developer console.

Recommended direction:

- light theme
- high-contrast, precise typography
- large metric numerals
- restrained accent color
- subtle progress animation only where it adds phase clarity
- generous whitespace

## Testing Strategy

### Server Tests

Add HTTP/3 server tests for:

- `/_coquic/speed/ping` success path
- `/_coquic/speed/download?bytes=N` success path with exact content length
- `/_coquic/speed/upload` success path with counted byte acknowledgement
- bad method handling for each route
- missing `bytes` query parameter
- malformed `bytes` query parameter
- out-of-range `bytes` rejection
- oversized upload rejection

### Demo Page Contract Tests

Update demo page contract coverage to assert:

- the old diagnostics content is gone
- the new page exposes only the focused speed-test experience
- the stable deployment marker remains present
- the page contains the expected metric labels and primary action

### Deployment Verification

Deployment verification can continue using:

- page reachability
- HTTP/3 transport confirmation via the existing deploy script probes
- the stable page marker check

The verification text assumptions should be updated to align with the new speed-test page, not the
old diagnostics page.

## Implementation Notes

- route handling should be added in the same runtime response path that currently serves
  `/_coquic/echo`, `/_coquic/inspect`, and static files
- implementation should avoid introducing new long-lived service state
- the page should generate its own upload payload bytes in the browser
- the page should add cache-busting query parameters for active measurements

## Risks

### Browser Variability

Browser scheduling, tab throttling, and device performance will affect results. This is acceptable
for a public demo as long as the page presents measurements as run-local observations, not
certified benchmarks.

### Public Endpoint Abuse

The dedicated speed routes are intentionally abusable if left unbounded. Explicit payload caps and
short balanced defaults are required.

### UI Overreach

It would be easy to turn this into a richer benchmark dashboard. This design explicitly rejects
that direction for this iteration.

## Acceptance Criteria

The work is complete when:

- the deployed demo page no longer contains diagnostics content
- the page presents a single focused speed-test flow
- latency, download, and upload metrics are measured through dedicated speed routes
- the h3 runtime exposes the three new speed endpoints with bounded behavior
- automated coverage exists for the new server routes and page contract
- the deployment workflow still verifies and publishes the updated demo successfully
