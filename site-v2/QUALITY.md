# Cross-Cutting Quality Contract

## Accessibility

- Target WCAG 2.2 AA. Automated critical/serious violations MUST be zero on
  every primary route and representative state; automation does not replace
  manual review.
- Keyboard users MUST reach and operate every command, link, tab, disclosure,
  locally scrollable region, matrix cell, chart datum, and dialog.
- Focus MUST be visible, logically ordered, never trapped outside a modal, and
  restored after temporary surfaces close.
- Dynamic loading, completion, errors, result counts, and copy actions MUST be
  announced with appropriately polite or assertive live regions.
- Color MUST NOT be the only carrier of status. Forced-colors mode MUST retain
  state distinctions and focus.
- Reduced-motion preference MUST remove nonessential animation.
- Touch targets SHOULD be at least 44 by 44 CSS pixels on coarse pointers.
- Charts MUST have an equivalent semantic table or list.
- Steward trajectories MUST expose named headings and landmarks, unique record
  anchors, keyboard-operable outline and disclosure controls, and visible
  focus. Failed tool disclosures open by default. Loading, completion, empty,
  transient Retry, and terminal unavailable states use live status text with no
  ambiguous color-only distinction.

## Responsive behavior

- Required widths: 320, 375, 414, 768, 1024, 1440, and 1920 CSS pixels, plus
  844x390 landscape.
- Required zoom probe: 200% browser text/page scaling at a 1280px viewport.
- The document MUST NOT horizontally overflow. Wide code, tables, matrices,
  graphs, traces, and packet data MAY scroll inside clearly named regions.
- Content and commands MUST remain reachable without hover.
- Steward proof MUST include 1600x1000, 390x844, and 320x900 screenshots, a
  200%-scale probe, and nonoverlap checks. Image evidence reserves a stable
  contained frame; valid image loads MUST have nonzero intrinsic dimensions.

## Resilience and state integrity

- Never equate absent, malformed, delayed, partial, empty, and numeric zero.
- Retain last valid evidence when a secondary request fails.
- Abort stale search/detail requests and ignore late responses after navigation.
- Retry MUST be idempotent from the user's perspective and MUST not duplicate
  listeners, streams, timers, or records.
- Client-only enhancements MUST have a deterministic loading/unavailable state.
- External payloads MUST be schema-validated before rendering.
- The trajectory client MUST issue one cancellable request for the selected run,
  ignore late responses after selection or unmount, and expose manual Retry only
  for retryable transient failures. Empty, malformed, integrity, ownership,
  resource, and schema failures are terminal and never fall back to a prefix.

## Security and privacy

- Render Markdown and transcript content through an allowlist; never execute
  embedded script or event-handler content.
- Validate dynamic slugs, task IDs, session IDs, filenames, artifact paths, and
  proxy paths against explicit allowlists or safe patterns.
- Published artifacts are read-only and served with safe content disposition
  and type.
- The RAG proxy forwards only documented headers and has a bounded timeout.
- Steward publications are read-only and sanitized at the producer boundary.
- External links opened in a new context use appropriate opener isolation.
- Do not expose filesystem paths, credentials, private prompts, or raw internal
  Steward state beyond fields declared in the public schema.

### Steward cloud reader trust boundary

- Cloud configuration has exactly four server-side values: Cloudflare account
  ID, D1 database ID, account-scoped D1 Read token, and anonymous public R2 base
  URL. Account ID, D1 database ID, and token MUST never reach client bundles,
  browser responses, task/validation containers, or logs. The validated
  anonymous public R2 base URL MAY appear only as the prefix of the derived
  artifact `Location` header; it MUST not appear elsewhere in client bundles,
  browser responses, task/validation containers, or logs. Missing or unsafe
  values fail closed.
- D1 acquisition MUST use fixed parameterized statements with bounded timeout,
  response bytes, result sets, and rows. Queries join only a `visible` task
  head to its `visible` publication; staged, superseded, hidden, malformed,
  dangling, and private-shaped rows are rejected before normalization.
- D1 responses and R2 object descriptors, including trajectory descriptors, MUST
  pass strict schema, ownership, disclosure, size, and SHA-256 validation before
  rendering. Validation failures are terminal and retain no unsafe payload.
- Artifact URLs MUST be derived only from validated task identity and
  content-addressed public keys below the configured R2 base. The same-origin
  action returns one `307 Temporary Redirect`, never proxies bytes, and ignores
  caller-supplied URLs.
- Trajectory Markdown links MUST use the allowlist, external links MUST isolate
  their opener, and image/download actions MUST remain same-origin logical-path
  routes. Browser assertions MUST never depend on a direct private or R2 URL.
- The reader has no D1 mutation, local SQLite/cache, filesystem archive,
  Worker, sidecar, compatibility reader, history migration, automatic polling,
  or raw fallback. Public output contains no private locator, credential,
  matched secret, scanner record, or filesystem path.

## Performance budgets

- Server-render meaningful route identity and loading state without JavaScript.
- Route JavaScript SHOULD stay below 250 KiB compressed; exceptions for the
  Workbench WASM loader and large visualization libraries require measurement.
- Shared initial JavaScript SHOULD stay below 100 KiB compressed.
- Largest Contentful Paint SHOULD be under 2.5s and Interaction to Next Paint
  under 200ms at the 75th percentile on an agreed preview profile.
- Long tables/lists SHOULD paginate or virtualize without breaking findability,
  browser history, or accessibility.
- Images, frames, and charts MUST reserve stable dimensions to avoid layout
  shift.

## Compatibility and observability

- Support current stable Chromium, Firefox, and WebKit, with progressive
  enhancement for unsupported APIs.
- Every fetch failure SHOULD log resource, status/category, request correlation
  ID, and schema version without logging sensitive content.
- Visible provenance MUST include generation time and commit/run identity where
  the producer supplies it.
- Contract tests MUST cover happy, empty, partial, missing, malformed, delayed,
  keyboard, compact, dark, reduced-motion, and 200%-zoom states.

## Steward cloud reader gates

- Mocked cloud unit and route tests MUST cover available, valid empty, transient
  unavailable, terminal unavailable, malformed, and integrity-failure states;
  visible-head/generation filtering; active-after-planning visibility;
  relational task ownership/count/sequence checks; complete trajectory
  validation; one same-origin `307` redirect; R2 base/key containment; and the
  absence of raw, partial, private, cached, or compatibility fallback data.
- The mocked suites MUST prove account-scoped credentials stay server-only, D1
  statements remain fixed and parameterized, and D1 transport/result limits
  bound timeout, response bytes, result sets, and rows. They MUST exercise
  invalid identifiers, unsafe logical paths, dangling rows, private-shaped data,
  and caller-supplied URL rejection without leaking diagnostic values.
- Deployment-path tests MUST prove the four protected values are validated,
  redacted from output, preserved across ordinary deploy/repair/rollback, and
  passed only to the Next.js process. They MUST prove missing, insecure, or
  symlinked host configuration fails before mutation.
- The on-demand checker MUST accept a valid empty publication with explicit
  detail/trajectory/artifact skips. With one real task it MUST select the first
  visible task, verify ownership and complete trajectory content, and prove one
  same-origin `307` redirect to a validated public key. It MUST not require a
  scheduled monitor, canary, polling loop, or fabricated task.
- Run the executable cloud reader gates with no live credential:
  `nix develop -c npm --prefix site-v2 run test:unit` and
  `nix develop -c npm --prefix site-v2 run test:steward`.
- Keep the direct route/page harness separate from the browser gate. The
  deterministic browser proof is:
  `nix develop -c npm --prefix site-v2 run test:visual -- tests/steward.spec.ts --workers=1`;
  it starts a loopback fixture server with dummy credentials by default. An
  explicitly supplied `PLAYWRIGHT_BASE_URL` may target a preview without
  making that preview a required CI dependency.
- Validate schemas, examples, and documentation with
  `nix develop -c uv run --project site-v2 python site-v2/scripts/validate_contracts.py`.
- `nix develop -c npm --prefix site-v2 run typecheck` and
  `nix develop -c npm --prefix site-v2 run build` MUST pass without cloud
  credentials or a live publication.
- Complete ATIF browser proof MUST cover clean, redacted multimodal, tool-heavy,
  empty, transient Retry, and terminal states; source order and unique anchors;
  safe links; failed-open tools; image decode and frame geometry; one validated
  same-origin `307`; Axe critical/serious zero; dark, forced-colors,
  reduced-motion, desktop, compact, 320px, and 200%-zoom states. Retained
  screenshots MUST be inspected for nonblank, correctly framed, nonoverlapping
  content. Validated byte-preserved JPEG/PNG/GIF/WebP evidence may animate under
  reduced motion as the documented WCAG 2.2.2 residual risk.
- The Site V2 CI job MUST install Chromium, run the focused browser command, and
  retain Playwright test results and reports when that gate fails.
