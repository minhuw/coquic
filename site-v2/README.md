# CoQUIC Site V2

Site V2 is the standalone Next.js Node application for CoQUIC's public
Steward publication. The server reads validated metadata from Cloudflare D1
and immutable sanitized objects from anonymous public R2. Browser code uses
only validated same-origin routes; it never receives a Cloudflare token or a
provider locator.

This directory is a clean-room product and interface specification. An
implementation MUST be buildable from it without reading `site/next`, its
styles, components, screenshots, or generated DOM.

## Production boundary

Site V2 owns the reader and its Node deployment. Cloudflare infrastructure and
Steward publication are separate operator concerns. Site has no Worker,
sidecar, D1 write path, local database or cache, filesystem archive importer,
raw fallback, compatibility reader, or history migration.

The server receives exactly four protected values:

| Value | Use | Exposure |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | D1 REST account path | server only |
| `COQUIC_STEWARD_D1_DATABASE_ID` | D1 REST database path | server only |
| `COQUIC_STEWARD_D1_READ_TOKEN` | account-scoped D1 Read authorization | server only |
| `COQUIC_STEWARD_PUBLIC_R2_BASE_URL` | validated public artifact prefix | server-derived redirects only |

The values are installed manually through the protected SSH handoff owned by
`site/deploy/install-cloud-config.sh`. Ordinary Site deployment preserves them
and passes them only to the standalone Next server. Builds and tests use
mocked cloud responses and do not require live credentials.

## Preview access

Set `COQUIC_V2_PREVIEW_PASSWORD` on a preview deployment to place every V2
route behind the shared under-construction notice. Successful entry sets an
HTTP-only cookie for seven days. Leaving the variable unset disables the gate
for local development and normal test runs.

This is a convenience gate for reviewers, not an authentication or security
boundary. Do not use it to protect sensitive data.

## Contract map

- [AGENTS.md](AGENTS.md): clean-room rules for implementation agents.
- [PRODUCT.md](PRODUCT.md): product purpose, audiences, information
  architecture, and route inventory.
- [FUNCTIONAL.md](FUNCTIONAL.md): required behavior for every user-facing
  route.
- [QUALITY.md](QUALITY.md): accessibility, resilience, security, performance,
  and browser requirements.
- [DESIGN.md](DESIGN.md): normative visual language, tokens, components, data
  visualization, responsive behavior, and design guardrails.
- [STACK.md](STACK.md): approved framework, Tailwind, shadcn/ui, and
  shadcn/typeset integration rules plus the deployment boundary.
- [DATA.md](DATA.md): canonical cloud publication data model, naming rules,
  resources, and validation policy. It supersedes the historical raw archive
  notes in `STEWARD_DATASET.md`.
- [API.md](API.md): HTTP and event-stream contracts.
- [WORKBENCH.md](WORKBENCH.md): clean UI-to-WASM command/event boundary.
- [MIGRATION.md](MIGRATION.md): independent cloud rollout, activation,
  rollback, and cutover gates.
- `schemas/`: normative JSON Schema 2020-12 documents.
- `examples/`: representative valid payloads for implementers and tests.

`STEWARD_DATASET.md` is retained only as historical context. It is not a Site
reader input or a production deployment contract.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` have their RFC 2119
meanings. Prose and schemas are both normative. If they conflict, the schema
wins for payload shape and the prose wins for user-visible behavior.

## Implementation state

The global shell, Home route, and Steward cloud reader are implemented V2
surfaces. Remaining routes are rebuilt independently against their contracts;
none may reintroduce a filesystem archive reader or provider-specific browser
access.

The foundation is Next.js 16, React 19, strict TypeScript, Tailwind CSS 4,
source-owned shadcn/ui components, shadcn/typeset, Motion, and Lucide.

## Definition of done

V2 is ready to replace the current site only when:

1. Every route in `PRODUCT.md` satisfies `FUNCTIONAL.md`.
2. Every API and artifact validates against the schemas in this directory.
3. Every requirement in `QUALITY.md` has automated evidence.
4. The cloud reader, same-origin artifact actions, aliases, and stable download
   contracts are verified without exposing private or provider-only values.
5. Cloud rollout, Site deploy/rollback, and the on-demand empty/real-task
   checker are all proven independently of live credentials in tests.
6. Product review approves the new visual language independently of legacy
   screenshots.

## Validate this package

```sh
nix develop -c uv run --project site-v2 python site-v2/scripts/validate_contracts.py
```
