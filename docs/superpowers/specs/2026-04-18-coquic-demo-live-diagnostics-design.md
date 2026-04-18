# Coquic Demo Live Diagnostics Design

Date: 2026-04-18
Repo: `coquic`
Status: Approved

## Summary

Refine the public HTTP/3 demo page served by `h3-server` at
`https://coquic.minhuw.dev:4433/` so it works as both:

- a lightweight showcase page for first-time visitors
- a browser-visible verification page for technical users

The page stays as a single static HTML document with a small amount of
browser-side JavaScript. It defaults to `Showcase` mode and exposes a visible
toggle that switches to `Technical` mode without changing routes.

The diagnostics shown on the page must be limited to information the current
runtime can already provide cheaply and truthfully:

- page origin and hostname
- static deployment facts for the current demo
- response metadata the browser can fetch from the same origin
- live probe results from the existing `/_coquic/inspect` and `/_coquic/echo`
  endpoints

The page must not pretend to know browser-internal transport facts that it
cannot directly observe from JavaScript, such as the actual negotiated browser
protocol on the current navigation. Those remain DevTools-driven checks.

## Problem

The current demo page is useful as a smoke artifact but weak as a public-facing
demo:

- it is visually minimal and does not explain why the page is interesting
- it does not surface the repo-native diagnostics the runtime already exposes
- it does not distinguish between “show me the demo” and “help me verify the
  stack”
- it makes users jump out to terminal commands or browser DevTools too early

The desired result is a page that is still static and cheap to serve, but is
substantially more informative and easier to use during local browser
validation.

## Goals

- Keep the demo page served directly by `h3-server` from the static document
  root.
- Default the page to `Showcase` mode.
- Add a visible in-page toggle between:
  - `Showcase`
  - `Technical`
- Use browser-side JavaScript to run live same-origin probes.
- Reuse the existing runtime endpoints:
  - `POST /_coquic/inspect`
  - `POST /_coquic/echo`
- Surface concrete fields that help users understand and validate the current
  deployment.
- Preserve a no-build, static-asset demo workflow for the page itself.

## Non-Goals

- No SPA framework, bundler, or client-side build pipeline.
- No server-side templating.
- No new dynamic server endpoint just for the page in this slice.
- No attempt to expose browser-negotiated protocol, ALPN, or QUIC version as
  “live page facts” if they are not observable from browser JavaScript.
- No replacement for DevTools-based transport verification.
- No qlog viewer, packet trace viewer, or log streaming UI in this slice.

## Chosen Architecture

### Page Ownership

The page remains a single static HTML file in the demo document root.

For the current live demo setup, that is:

- `/tmp/coquic-h3-demo/www/index.html`

For repo-owned packaging paths, the same structure should remain compatible
with:

- `docker/h3-server/www/index.html`

The implementation should keep the page self-contained:

- HTML
- inline CSS
- inline JavaScript

This preserves the current “drop a document root into `h3-server`” workflow.

### Single-Page Mode Toggle

The page has two presentation modes controlled by a client-side toggle:

- `Showcase`
- `Technical`

The toggle behavior is:

- `Showcase` is the default on first load.
- Switching modes does not navigate away or reload the page.
- The selected mode is stored in `localStorage` so refreshes preserve the most
  recent choice for the current browser.

This is preferred over separate routes because:

- the same live diagnostics power both views
- there is only one page to maintain
- the public entry URL remains simple
- the demo can shift from “marketing-lite” to “verification” instantly

### Live Data Model

The page should have one small client-side state object, populated from:

- static baked-in constants for known deployment facts
- same-origin fetch probes

The state categories are:

- `deployment`
  - demo hostname
  - demo port
  - document title
  - expected certificate subject
  - certificate issuer label
  - certificate expiry string
- `bootstrap_probe`
  - success/failure
  - HTTP status
  - observed `Alt-Svc` header if readable
- `inspect_probe`
  - success/failure
  - returned JSON from `/_coquic/inspect`
- `echo_probe`
  - success/failure
  - round-trip payload match result
- `ui`
  - current mode
  - last probe time
  - loading/error state

The page should not require all probes to succeed before rendering. The hero and
showcase content render immediately; diagnostics fill in progressively.

### Probe Strategy

The page should run three browser-side probes:

1. `HEAD /`
   - Purpose:
     - confirm the current origin is responding
     - read the `Alt-Svc` header when accessible through same-origin fetch
   - Result fields:
     - status code
     - `alt_svc`
   - Failure handling:
     - mark bootstrap probe unavailable and show a readable error state

2. `POST /_coquic/inspect`
   - Request body:
     - empty body is sufficient
   - Purpose:
     - demonstrate that the runtime’s inspect endpoint is live
     - surface the current request handling shape returned by the server
   - Result fields:
     - method
     - content_length
     - body_bytes
     - trailers

3. `POST /_coquic/echo`
   - Request body:
     - a small deterministic payload like `demo-echo`
   - Purpose:
     - prove request body round-trip behavior
   - Result fields:
     - payload echoed successfully or not
     - echoed byte count

The page should run these probes:

- once on initial load
- again on explicit user action via a `Run Live Checks` button

The page should not poll continuously.

### Showcase Mode

`Showcase` mode should prioritize clarity and visual polish over density.

The visible structure should be:

- hero section
  - short explanation of what `coquic` is serving
  - current public demo URL
  - primary status line, for example:
    - live origin
    - public certificate
    - live probe availability
- compact facts row
  - hostname / port
  - certificate issuer
  - certificate validity window
- action row
  - `Run Live Checks`
  - `How To Verify In Chrome`
- concise diagnostics preview
  - current `Alt-Svc` value
  - inspect endpoint status
  - echo endpoint status

This mode should feel like a real product demo, not a raw dashboard.

### Technical Mode

`Technical` mode should present the same underlying facts in a denser,
scan-friendly layout.

The visible structure should be:

- transport/bootstrap panel
  - current origin
  - HTTP status from `HEAD /`
  - observed `Alt-Svc`
  - guidance:
    - first load may be `http/1.1`
    - reload and inspect DevTools `Protocol` column for `h3`
- certificate panel
  - expected subject
  - issuer
  - expiry
- request probe panel
  - `/_coquic/inspect` JSON rendered in readable form
  - `/_coquic/echo` payload match result
- browser verification panel
  - explicit steps for Chrome DevTools verification

This mode should look intentional, but it can be more compact and
information-dense than `Showcase`.

### Field Definitions

The page should show these fields.

Fields that are safe to treat as live:

- current page URL from `window.location`
- hostname and port from `window.location`
- `Alt-Svc` header from same-origin `HEAD /`, if readable
- `/_coquic/inspect` JSON body
- `/_coquic/echo` success/failure
- probe status and last refresh time

Fields that should be shipped as curated deployment facts for this demo:

- certificate subject: `coquic.minhuw.dev`
- certificate issuer label: `Let's Encrypt`
- certificate expiry string
- expected technical verification language for Chrome

Fields that should be framed as external verification, not page-observed facts:

- browser-negotiated protocol on the current navigation
- negotiated ALPN
- QUIC version

For those, the page should say:

- “Verify in DevTools”
- not “Current protocol: h3”

### Error Handling

The page should degrade clearly rather than failing silently.

If a probe fails:

- show a visible warning badge on the corresponding card
- keep the rest of the page usable
- preserve the last successful data until a new probe replaces it

If `Alt-Svc` is missing:

- show the actual observed value or `missing`
- do not invent a success state

If `/_coquic/inspect` or `/_coquic/echo` fails:

- show the HTTP status or a network error label
- keep `Showcase` mode readable

If JavaScript is disabled:

- the page still renders a static showcase shell
- live diagnostics and mode switching are unavailable

## Implementation Notes

### Static HTML Structure

The file should be organized as:

- page shell
- toggle controls
- showcase container
- technical container
- inline script at the end

Mode switching should be done with class toggles or `hidden` attributes, not
DOM reconstruction.

### JavaScript Boundaries

The JavaScript should stay small and explicit:

- one startup function
- one `runLiveChecks()` function
- one `setMode()` function
- a few narrow render helpers

No generalized state management library is needed.

### Styling Direction

The page should preserve the repo’s current demo tone:

- strong color contrast
- intentional hero treatment
- no generic dashboard grayness

The toggle itself should be visually prominent because it is the main
interaction control.

## Testing

### Manual Browser Validation

Validate against the real public demo:

- `https://coquic.minhuw.dev:4433/`

Checks:

- page defaults to `Showcase`
- toggle switches to `Technical` without reload
- refresh preserves the selected mode
- `Run Live Checks` updates the probe cards
- `/_coquic/inspect` and `/_coquic/echo` results render correctly
- Chrome verification text matches the actual demo flow

### Automated Coverage

Add or extend repo-owned tests so they cover:

- the updated `index.html` is present in the demo document root or packaging
  path
- the page contains both mode labels
- the page references the existing probe endpoints
- the page still works with the current static file serving behavior

If a lightweight shell test is cheaper than a browser automation path, prefer
the shell test in this slice.

## Risks

- The page could over-claim transport certainty if the wording is sloppy.
  Avoid this by separating page-observed facts from DevTools verification.
- Certificate facts can go stale if they are hardcoded and not refreshed when
  the demo certificate changes.
  The implementation should keep those values localized and easy to update.
- The technical mode could become visually noisy if it tries to expose too much
  at once.
  Keep the field set narrow and tied to existing endpoints.

## Acceptance Criteria

- Visiting `https://coquic.minhuw.dev:4433/` shows a refined page that defaults
  to `Showcase`.
- A visible toggle switches between `Showcase` and `Technical` on the same page.
- Browser-side JS runs live checks against the existing same-origin endpoints.
- The page shows truthful live diagnostics for:
  - `Alt-Svc` when readable
  - `/_coquic/inspect`
  - `/_coquic/echo`
- The page gives correct Chrome DevTools guidance for verifying HTTP/3.
- The page does not claim to know negotiated browser protocol from JavaScript
  alone.
