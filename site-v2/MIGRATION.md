# V2 Delivery and Parity Gates

## Stage 1: Contract fixtures

- Validate all schemas and examples.
- Capture one complete, empty, partial, unavailable, and malformed fixture per
  external resource.
- Build adapters from legacy producers to canonical V2 payloads. Adapter tests
  compare semantic values, not markup.

## Stage 2: Independent foundation

- Scaffold a new application entirely inside `site-v2/`.
- Implement routing, metadata, theme preference, search, error boundaries, and
  shared data validation without importing the legacy presentation layer.
- Establish automated accessibility, browser, viewport, and payload-contract tests.

## Stage 3: Representative vertical slices

Implement one route from each domain before expanding breadth:

1. Docs: content rendering and navigation.
2. Performance: generated evidence, filtering, tables, charts, and dialogs.
3. Steward: dense operational state, pagination, and task navigation.
4. Transcript: URL-driven master/detail data exploration and downloads.

Product review approves the new visual language only from V2 builds. Legacy
screenshots MUST NOT be used as acceptance references.

## Stage 4: Remaining routes

Implement Home, Blog, QA, Workbench, Interop, Coverage, Duvet, Planner, and task
detail. Each route closes its functional and quality checklist before the next
deployment cohort.

## Stage 5: Compatibility deployment

- Deploy V2 behind a preview hostname with production-shaped artifacts.
- Run route, API, keyboard, accessibility, compact, theme, and failure-state tests.
- Verify canonical routes and aliases.
- Verify every stable artifact/download URL.
- Compare domain outputs from legacy and V2 adapters for the same fixtures.

## Stage 6: Cutover and deletion

- Switch public routing to V2 with rollback available for one release window.
- Observe schema errors, failed fetches, Web Vitals, 404s, and download failures.
- After acceptance, remove the legacy app and legacy visual snapshots.
- Retain adapters only while legacy producers still publish old schemas.

## Per-route acceptance checklist

- Correct title, primary heading, canonical URL, alias behavior, and 404 behavior.
- Complete happy-path functionality and every documented state.
- Keyboard-only and touch completion of primary workflow.
- No critical/serious automated accessibility findings.
- No document overflow at required viewports or 200% zoom.
- Dark/light, reduced-motion, and forced-colors behavior.
- Payload validation, stale-request cancellation, retry, and partial-data handling.
- Direct links/downloads preserve filenames, media types, and content.
