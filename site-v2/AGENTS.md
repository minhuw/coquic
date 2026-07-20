# AGENTS: Clean-Room V2

These instructions apply to all work under `site-v2/`.

## Design firewall

- Treat this directory as the sole product and interface specification.
- Do not inspect, copy, import, translate, or imitate presentation code from
  `site/next`.
- Do not inspect legacy CSS, visual snapshots, component markup, or page
  screenshots when making design decisions.
- Do not import runtime code directly from `site/next`.
- A narrowly scoped legacy adapter MAY read an old payload only when `DATA.md`
  explicitly identifies that migration source. Keep adapters outside the new
  presentation layer.
- Existing Playwright tests MAY be consulted only to confirm behavior after the
  behavior has been captured in this contract. Legacy visual assertions are not
  V2 requirements.

## Product rules

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
- Breaking payload changes require a new major `schemaVersion`.
- New optional fields require a minor schema version and MUST be safe for older
  consumers to ignore.
- Examples and schemas MUST change together.
