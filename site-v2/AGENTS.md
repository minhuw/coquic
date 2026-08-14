# AGENTS: Clean-Room V2

These instructions apply to all work under `site-v2/`.

## Design firewall

- Treat this directory as the sole product and interface specification.
- Do not inspect, copy, import, translate, or imitate presentation code from
  `site/next`.
- Do not inspect CSS, visual snapshots, component markup, or page screenshots
  from another application when making design decisions.
- Do not import runtime code directly from `site/next`.
- Data from another application, deployment, or publication is not a Site V2
  input. Do not add an adapter, fallback reader, or conversion layer for it.
- Tests outside `site-v2` are not a product specification. Consult V2 tests
  only after the behavior is captured in this contract; tests from another
  application do not create V2 requirements.

## Product rules

- Site V2 is greenfield. Assume no prior clients, URLs, payloads, datasets,
  caches, databases, deployments, or cookie/configuration continuity.
- Do not add adapters, redirects, alternate paths, tombstones, compatibility
  envelopes, fallback readers, backfills, or conversion recipes.
- Before first launch, a breaking change updates the sole current contract,
  schema, and synchronized examples in place; there is no older consumer or
  compatibility window to preserve.
- Read `DESIGN.md` before any visual, layout, component, or interaction work.
- Read `STACK.md` before creating application structure, adding frontend
  dependencies, or generating shadcn components.
- Treat `DESIGN.md` as normative for presentation. Record cross-route visual
  changes in `DECISIONS.md` rather than creating a page-local design language.
- Preserve routes, data access, downloads, keyboard workflows, accessibility,
  and honest failure states described here.
- Do not preserve accidental limitations. In particular, never silently hide
  matching benchmark results or fabricate zero values for missing evidence.
- Keep data acquisition, normalization, domain state, and rendering separate.
- Validate external and generated data at the boundary before it reaches UI
  components.
- Derive display values such as percentages from canonical numeric fields.
- Use semantic controls and landmarks before custom interaction code.
- Make mobile and keyboard behavior part of the initial implementation, not a
  later adaptation.

## Change control

- Contract changes require a short rationale in `DECISIONS.md`.
- After launch, breaking payload changes require a new major `schemaVersion`.
- New optional fields require a minor schema version and MUST be safe for
  current consumers to ignore.
- Examples and schemas MUST change together.
