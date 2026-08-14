# Contract Decisions

## D-001: Visual clean room

V2 preserves behavior but has no dependency on legacy presentation. This avoids
turning accidental markup and styling into design requirements.

## D-002: Separate application

V2 SHOULD be implemented as an independent application rooted in `site-v2/`.
Sharing a route group inside the legacy Next.js application would reintroduce
global CSS, component, and build-time coupling.

## D-003: Canonical V2 envelopes

All first-party JSON resources use a common envelope with `schemaVersion`,
`generatedAt`, and `data`. Snapshot provenance is explicit. Missing resources
use HTTP errors; missing optional measurements use `null` or an availability
enum. Missing values are never encoded as numeric zero.

## D-004: Base units in data

Canonical payloads use unscaled units in field names: bits per second,
requests per second, microseconds, milliseconds, bytes, and ratios from 0 to 1.
The UI chooses human-readable scaling. This prevents unit strings and display
rounding from contaminating domain data.

## D-005: Stable identifiers

Implementations, measurements, sessions, tasks, artifacts, and snapshots have
stable opaque IDs. Human labels are separate and may change without breaking
URLs or joins.

## D-006: Errors are data, not fake success

HTTP failures use a shared problem format. Partial collections declare their
completeness. A valid empty collection is distinct from an unavailable or
malformed resource.

## D-007: Data-driven catalogs

Documentation navigation, Workbench scenarios, benchmark implementations, and
search entries SHOULD come from validated catalogs rather than duplicated UI
constants.

## D-008: Prototype stack

The non-normative prototype uses Next.js 16, React 19, TypeScript, Tailwind CSS
4, source-owned shadcn-style Radix primitives, Motion, and Lucide icons. Staying
with React preserves repository operating familiarity; Nuxt would add a second
frontend runtime without a product benefit for this site.

Visual decisions are no longer recorded in this stack decision. See D-009 and
the normative `DESIGN.md`.

## D-009: Calm scientific instrumentation

The approved visual foundation is a calm scientific evidence interface with top
navigation, system sans for interface/prose, and Google Sans Code for exact
technical data. Complete measurements, synchronized analytical figures, exact
rankings, visible ranking rules, provenance, and method form the visual identity.

This supersedes the rejected Archivo/Instrument/IBM typography and the earlier
flight-recorder-led proposal in D-008. `DESIGN.md` is the normative visual source
and contains the review ledger for decisions that remain open.

## D-010: Futurism through working evidence

Research of the official xAI homepage, API and company pages, and developer
documentation on 2026-07-19 refined the direction from calm scientific
instrumentation to calm scientific futurism. CoQUIC adopts xAI's reduction,
black/white polarity, purposeful spatial pauses, direct product artifacts, and
restrained transitions as principles rather than visual assets.

CoQUIC does not adopt xAI's proprietary typography, branding, marketing-scale
whitespace, pill-heavy calls to action, or large rounded documentation panels.
The approved font pairing and complete-evidence requirements remain unchanged.
An optional single contrast field may hold a route's primary working artifact;
it must never be decorative or replace exact accessible evidence.

## D-011: Metadata does not balance page openings

Page-opening status and provenance sit in one compact line beneath the page
purpose. They do not occupy an isolated right column merely to fill negative
space. A right-aligned element in this row must be a real page action. This
preserves useful operational context without making metadata look decorative.

## D-012: Versioned DESIGN.md contract

The approved visual direction is fixed as DESIGN.md version 1.0.0 using the
awesome-design-md structure: machine-readable YAML tokens followed by human
guidance for theme, color, typography, layout, components, visualization,
responsive behavior, guardrails, and agent implementation.

This is a documentation and synchronization change, not a new visual direction.
It replaces the working-draft label, records the implemented 64px shell height,
and makes token and prose updates an atomic requirement for future changes.

## D-013: Tailwind, shadcn/ui, and shadcn/typeset

The Site V2 implementation foundation uses Tailwind CSS 4 with semantic tokens
derived from DESIGN.md. Tailwind is an implementation vocabulary and does not
permit default or arbitrary visual decisions to supersede the design contract.

shadcn/ui supplies source-owned accessible components through the shadcn CLI.
Generated component behavior is retained while generated visual styling is
retokenized for CoQUIC. shadcn/typeset supplies a source-owned CSS file for
sanitized prose and rendered Markdown. It is not an npm runtime dependency and
does not style operational UI or evidence fields.

This decision supersedes the provisional component wording in D-008. STACK.md
is the normative implementation reference.

## D-014: Daily growth report as the Home thesis

Home leads with the established CoQUIC mark, product name, and a concise project
slogan beside a Steward daily summary. The report groups model usage, repository
output, and fixes landed for one explicit UTC date. This makes autonomous growth
inspectable without turning Home into either a marketing hero or a full monitor.

Daily values come from a dedicated sanitized contract. Git-derived
`fixesLanded` counts Conventional Commit subjects with the `fix` type and is not
presented as a complete regression count. Missing producer data remains
unavailable rather than zero.

## D-015: Steward dashboard as a derived archive index

The Steward dashboard consumes a compact snapshot derived from sanitized monitor
and retained task publications. It exposes archive-wide outcomes and public
artifact counts while embedding bounded recent task, signal, provider, and wakeup
records for fast rendering.

The dashboard is an index, not a second source of truth. Raw task publications
remain authoritative for attempts, transcripts, patches, validation logs, review
findings, and event timelines. Aggregate totals remain explicit when embedded
lists are truncated, and unavailable runtime state is never synthesized from
archival evidence.

## D-016: Steward configuration remains private

Public Steward payloads exclude daemon and operator configuration. Integration
policy, mutation limits, timeouts, and other control-plane values are not needed
to inspect public work evidence and create avoidable operational disclosure.

Observed state such as queue occupancy, active work, and available source
capacity remains public because it describes the sanitized publication boundary,
not how an operator configured the daemon. Audit findings remain producer data;
they surface beside the affected domain only when actionable and do not receive
an empty dedicated view.

## D-017: Steward follows the causal control loop

The primary Steward information architecture is Signals, Planning, and Tasks,
with Tasks as the default and deepest surface. This mirrors the causal model in
the public producer: source evidence enters as a signal, a planner run consumes
evidence and proposes bounded work, and a task advances through plan,
implementation, validation, review, and integration.

A generic State view, a dedicated Audit view, and public Configuration are not
top-level destinations. Operational counts remain visible inside the control
loop, while non-empty invariant findings may appear beside the domain evidence
they affect.

Task detail preserves feedback rather than presenting execution as a simple
linear success path. Validation, review, and integration can return work to
implementation; attempts, transcripts, tool calls, patches, checks, findings,
and timeline events remain connected. Partial and contradictory publications are
shown as producer evidence, not repaired in the presentation layer.

Wide Steward surfaces use a master/detail dashboard geometry because the core
inspection task is comparative: queue beside execution beside evidence, source
beside pending and scheduled signals, or wakeups beside a planner decision and
its diagnostics. Mobile preserves the same semantic order as a single column;
the desktop layout does not create a separate reduced data model.

## D-018: Task planning is first-class execution evidence

Task detail exposes implementation-planning runs separately from implementation
attempts. A planning run records retry order, status, timing, model settings,
diagnostics, transcript completeness, and locally available usage and cadence.
The accepted structured plan remains the Run brief immediately after this run
history.

This preserves Steward's actual lifecycle: planning can retry until it produces
one valid plan, then implementation, validation, and review revisions reuse that
plan. The interface must not imply that each worker attempt received a new plan,
and unavailable planning telemetry remains unavailable rather than zero.

## D-019: Preview access is an explicit construction notice

Site V2 has an optional shared-password gate for its construction preview. When
enabled by deployment configuration, every application route redirects to one
under-construction screen and returns reviewers to their requested URL after
entry. The screen uses the established product identity, status language,
form controls, and responsive design tokens rather than introducing a separate
preview visual language.

The gate is deliberately described as a convenience notice, not authentication
or a security boundary. It is enabled only by deployment configuration, stores
no account data, and remains disabled in ordinary local development.

## D-023: Standalone Site V2 reads the public cloud publication

Site V2 uses one initial architecture for public Steward data: a standalone
Next.js Node reader over validated Cloudflare D1 metadata and immutable,
sanitized Cloudflare R2 objects. This is the sole current reader contract.

### Context

Steward publishes public task metadata, relationships, and sanitized evidence
as a visible D1 publication with immutable R2 objects. Site separates acquisition,
validation, domain state, and rendering. It uses server-side native `fetch` for
the Cloudflare D1 REST API and resolves anonymous R2 objects only from validated
artifact identity.

### Choice

- The reader uses four server-only values: Cloudflare account ID, D1 database
  ID, an account-scoped D1 Read token, and an anonymous public R2 base URL.
- Cloudflare cannot scope a D1 Read token to one database. The token therefore
  stays server-only, and every queried row must be public-safe. D1 reads join a
  `visible` task head to its referenced `visible` publication; staged,
  superseded, hidden, malformed, dangling, or private-shaped data fails closed.
- Cloud responses use `schemaVersion: "4.0"` for status, task pages, task
  detail, complete trajectory descriptors, usage summaries, and problems. A
  trajectory response is a complete descriptor for one immutable sanitized JSON
  artifact, not partial content or an unvalidated fallback.
- Artifact actions accept a validated logical path, derive the content-addressed
  public key, and return exactly one same-origin `307 Temporary Redirect` to the
  anonymous R2 object. Site never proxies bytes or accepts a caller-supplied URL.
- Global Signals, Planning, and revision are product states rather than initial
  cloud resources. The UI keeps the destinations discoverable and renders them
  unavailable until a current public contract exists.

### Consequences and ownership

Cloud publication identity is visible through task, pipeline, run, event, and
artifact relationships. Public artifact descriptors carry their logical path,
content-addressed `publicKey`, media type, byte size, SHA-256, availability, and
disclosure flags. The reader can expose an active task after a completed planning
run while retaining a complete descriptor; it never invents a partial result.

The current publication producer owns schema, validation, and exposure. Site
owns read-only acquisition, validation, domain state, and rendering. The
contract stays current by updating the sole schema, examples, and reader
behavior together before any first launch.

### Security and non-goals

D1 and R2 values that reach Site are public-safe: they contain no credentials,
private bucket/key/URL, matched secret, scanner record, or private filesystem
path. The account-scoped token is never serialized to a response or client
bundle. R2 objects are immutable and addressed only by validated task identity
and SHA-256. There is no D1 mutation path, local persistence, sidecar process,
filesystem archive input, alternate publication reader, or raw fallback.

## D-024: Transcript reads return normalized complete trajectories

The task transcript route is the one breaking reader boundary for complete
trajectory content. It resolves the visible D1 descriptor and owned artifact
map before one bounded anonymous R2 load, verifies the digest and ATIF bytes,
projects the document to the public display model, and validates the closed
`schemaVersion: "4.0"` envelope before returning it with `Cache-Control:
no-store`. It emits no raw ATIF, private locator, direct R2 key, or partial
compatibility shape. Invalid selectors, missing selections, bounded resource
rejections, integrity/schema/ownership failures, and transient backend failures
remain distinct `400`/`404`/`413`/`422`/`503` categories; only transient `503`
responses are retryable. Artifact delivery remains the existing same-origin
validated `307` redirect and never proxies bytes.

The production Next configuration sets only `turbopack.root` to the repository
root because the shared ATIF schema remains outside `site-v2`; copying or
relocating that schema would create a second contract.

## D-025: Byte-preserved published image evidence may animate

Validated JPEG, PNG, GIF, and WebP evidence renders immediately through a
plain image element and its normalized same-origin artifact action. The image
bytes are never recompressed or transformed by Site. A bounded contained frame
keeps the evidence stable even though public descriptors do not carry
dimensions, and every image keeps an accessible alternative and download
action.

This immutable-evidence rule is an intentional exception to Site-authored
reduced-motion behavior: multi-frame PNG, GIF, and WebP evidence may animate
when the user prefers reduced motion. The exception carries the accepted
residual WCAG 2.2.2 risk. Site-authored transitions and other nonessential
motion continue to honor the general reduced-motion contract; revisit this
decision if reliable browser controls for published animation become available.

## D-026: Usage is a clean, precomputed Steward projection

On 2026-08-04, Site V2 adopts the clean usage projection published by Steward
alongside each visible task generation. This is a breaking cloud response
revision; it does not add a compatibility reader, historical R2 scan, or
request-time calculation.

### Context

Private Steward telemetry contains provider and process details that cannot
cross the public boundary. Sanitized ATIF is the evidence source for each
task-owned invocation, retry, and turn, while calls without an authenticated
task relationship are only `Steward overhead` aggregate evidence. D1 must be
query-ready for lifetime totals, UTC-daily totals, model breakdowns, and
bounded drill-down without parsing R2 during ordinary requests.

### Choice

- Steward owns a versioned `usage projection`: a staged usage generation,
  task/run summaries, invocation/retry rows, bounded turn rows, price-entry
  provenance, and precomputed daily/lifetime global rows. Each level carries
  six Token totals (`prompt`, `cached`, `uncached`, `completion`, `reasoning`,
  `total`) and four integer micro-USD cost totals.
- A task publication and its first usage head become visible in one D1
  transaction. Later usage-only generations may swap the usage head while the
  visible task head remains stable. All child rows are immutable after
  exposure; failed swaps leave the previous heads and rows untouched.
- The invocation UTC start selects one exact effective-dated catalog entry.
  Numeric costs retain an immutable price-entry digest and are never repriced.
  Missing rates leave all four cost fields `null` and display `N.A.`. Token
  evidence remains distinct from cost availability, including zero-token,
  `Partial`, and `N.A.` states.
- Site remains the D-023 stateless, read-only server-side D1/R2 reader. It
  selects visible heads, validates ownership/counts/rollups and bounded cursor
  order, and renders cached summaries. It never writes D1, caches locally,
  calls a provider, or recomputes usage from R2. A usage read failure leaves
  the task reachable with `Usage unavailable`.
- Public usage responses use `schemaVersion: "4.0"`; fixed limits and opaque
  publication/generation-scoped turn cursors prevent unbounded responses.
  Overhead rows expose aggregates only, never individual invocation or turn
  drill-down. They use independent D1 generations with null task/publication
  ownership; one guarded swap advances the daily and lifetime heads together,
  and stale writers leave both prior heads unchanged. Hidden tasks contribute
  to neither task nor global totals.

### Rejected alternatives

The contract rejects a dual-write or compatibility envelope, old-D1 migration,
historical R2 backfill, request-time pricing, fuzzy model matching, a Site
cache/write path, actual catalog rates in public rows, and individual overhead
detail. Direction 1 stages this contract on a new D1 database; live Cloudflare
mutation and credential installation remain outside this decision.

## D-027: Canonical trajectory display arrays

Complete trajectory display models expose each step's content, tool calls, and
observations once, and each observation exposes one normalized content array.
The projector converts raw ATIF strings and standard content fields at the
validation boundary; renderers do not retain parallel aliases or infer between
old and new shapes. Explicit notes and reasoning remain text fields, while
empty arrays render honestly as unavailable. Raw ATIF validation and its
standard input fields remain unchanged.
