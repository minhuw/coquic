# Product Contract

## Purpose

CoQUIC is an experimental, open-source QUIC and HTTP/3 research environment. It
lets people inspect the implementation, learn its API, exercise protocol
behavior, compare evidence, study its development history, and observe the
automation that maintains it.

The website MUST not imply production readiness. Claims about compatibility,
coverage, performance, or compliance MUST be traceable to dated evidence.

## Audiences and primary jobs

| Audience | Primary job |
| --- | --- |
| QUIC implementer | Inspect protocol behavior, interop outcomes, and RFC evidence. |
| Library integrator | Understand APIs, wrappers, runtime integration, and examples. |
| Researcher | Compare benchmark results and inspect reproducible metadata. |
| Contributor | Locate weak coverage, compliance gaps, tasks, and automation state. |
| Dataset user | Search, inspect, and download public development transcripts. |
| Curious reader | Understand why CoQUIC exists and how it was developed. |

## Information architecture

Navigation grouping and visual placement are open design decisions. The
following destinations MUST remain discoverable from every primary page:

| Area | Canonical route | Purpose |
| --- | --- | --- |
| Home | `/` | Product identity and route index. |
| Ask | `/qa` | Direct and RFC-grounded specification answers. |
| Docs | `/docs` | Project, API, binding, and integration documentation. |
| Blog | `/blog` | Project articles and research notes. |
| Dataset | `/transcript` | Searchable public development transcripts. |
| Workbench | `/workbench` | In-browser QUIC protocol simulation. |
| Performance | `/performance` | LAN benchmark ranking and history. |
| Interop | `/interop` | Directional peer/testcase evidence. |
| Coverage | `/coverage` | LLVM source coverage evidence. |
| Duvet | `/duvet` | RFC requirement traceability. |
| Steward | `/steward` | Read-only repository automation monitor. |

Compatibility aliases MUST continue to resolve with the same title, primary
heading, and data contract:

- `/perf-comparison` -> `/performance`
- `/interop-results` -> `/interop`
- `/coverage-results` -> `/coverage`

Dynamic routes:

- `/docs/[...slug]`
- `/blog/[slug]`
- `/steward/tasks/[taskId]`

Steward domain selection is shareable query state on `/steward`: `signals`,
`planning`, or `tasks` (default).

## Content inventory

V2 MUST support a data-driven documentation catalog. The initial catalog
contains Overview, Public API, Core API, QUIC facade, HTTP/3 API, C FFI API,
C FFI reference, Rust wrapper, JavaScript wrapper, Python wrapper, Go wrapper,
and Runtime Integration.

V2 MUST support Markdown and MDX blog posts with front matter for title,
description, publication date, author, writing/polish attribution, tags, and
estimated reading time. The current initial posts are `why-coquic` and
`coquic-steward`; the implementation MUST NOT hard-code that count.

## Global capabilities

- Site search over routes, documentation, articles, dashboards, and Workbench
  scenarios, with suggestions, no-result handling, and keyboard navigation.
- Persisted light/dark preference with system preference when no override exists.
- Skip navigation, stable document titles, canonical headings, footer, GitHub,
  contact, and license access.
- Factual not-found responses for invalid content and task identifiers.
- Deep links and browser back/forward behavior wherever route state is encoded.
