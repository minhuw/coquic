# CoQUIC Site V2 Contract

This directory contains the complete clean-room specification and visual
prototype for a future CoQUIC website. An implementation MUST be buildable from
this directory without reading `site/next`, its styles, components, screenshots,
or generated DOM.

## Preview access

Set `COQUIC_V2_PREVIEW_PASSWORD` on a preview deployment to place every V2 route
behind the shared under-construction notice. Successful entry sets an HTTP-only
cookie for seven days. Leaving the variable unset disables the gate for local
development and normal test runs.

This is a convenience gate for reviewers, not an authentication or security
boundary. Do not use it to protect sensitive data.

The contract preserves the useful behavior of the existing website and defines
a new visual system while leaving component structure and framework choices
open.

## Contract map

- [AGENTS.md](AGENTS.md): clean-room rules for implementation agents.
- [PRODUCT.md](PRODUCT.md): product purpose, audiences, information architecture,
  and route inventory.
- [FUNCTIONAL.md](FUNCTIONAL.md): required behavior for every user-facing route.
- [QUALITY.md](QUALITY.md): accessibility, resilience, security, performance, and
  browser requirements.
- [DESIGN.md](DESIGN.md): normative visual language, tokens, components, data
  visualization, responsive behavior, and design guardrails.
- [STACK.md](STACK.md): approved framework, Tailwind, shadcn/ui, and
  shadcn/typeset integration rules.
- [DATA.md](DATA.md): canonical V2 data model, naming rules, resources, and legacy
  normalization policy.
- [API.md](API.md): HTTP and event-stream contracts.
- [WORKBENCH.md](WORKBENCH.md): clean UI-to-WASM command/event boundary.
- [MIGRATION.md](MIGRATION.md): parity gates and replacement strategy.
- `schemas/`: normative JSON Schema 2020-12 documents.
- `examples/`: representative valid payloads for implementers and tests.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` have their RFC 2119
meanings. Prose and schemas are both normative. If they conflict, the schema
wins for payload shape and the prose wins for user-visible behavior.

## What is intentionally absent

The product and data contracts do not prescribe a component tree or page
markup. `STACK.md` fixes the implementation foundation, and `DESIGN.md` fixes
visual outcomes. Legacy DOM IDs, CSS class names, presentation code, and
accidental layout constraints are intentionally excluded.

## Implementation state

The global shell and Home route are the first implemented V2 surfaces. Other
routes remain intentionally absent until they are rebuilt against their
contracts. The foundation is Next.js 16, React 19, strict TypeScript, Tailwind
CSS 4, source-owned shadcn/ui components, shadcn/typeset, Motion, and Lucide.

## Definition of done

V2 is ready to replace the current site only when:

1. Every route in `PRODUCT.md` satisfies `FUNCTIONAL.md`.
2. Every API and artifact validates against the schemas in this directory.
3. Every requirement in `QUALITY.md` has automated evidence.
4. The legacy aliases and public download URLs remain compatible.
5. Product review approves the new visual language independently of legacy
   screenshots.

## Validate this package

```sh
uv run --project site-v2 python site-v2/scripts/validate_contracts.py
```
