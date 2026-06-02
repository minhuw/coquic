# CoQUIC Design System

This file is the design source of truth for CoQUIC UI work. Agents should read it before changing `site/next/*` or adding new demo, dashboard, documentation, benchmark, or interop views.

CoQUIC inherits the design-md convention from VoltAgent's `awesome-design-md` collection and the Cursor-inspired developer-tool baseline used in that collection: quiet confidence, flat editorial surfaces, restrained type, code/data-friendly rhythm, and minimal decoration. CoQUIC does not copy Cursor branding, IBM branding, logos, copywriting, or proprietary identity assets. The CoQUIC identity is its own: protocol engineering, generated implementation, benchmark evidence, and documentation-grade clarity.

## Brand Summary

- Product: CoQUIC, an experimental QUIC implementation and demo/benchmark suite.
- Slogan: `CoQUIC, from Prompt to Packet.`
- Visual personality: precise, technical, calm, inspectable.
- Surface model: white canvas, light gray muted panels, hairline borders, no heavy shadows.
- Component style: documentation-friendly, compact, predictable, accessible.
- Primary accent: CoQUIC Blue.
- Avoid: marketing-heavy gradients, decorative blobs, glassmorphism, loud illustrations, IBM or Cursor proprietary identity cues.

## Color Tokens

Use these semantic tokens first. Do not hard-code one-off brand colors in page CSS unless there is a local semantic state that is not covered here.

| Token | Hex | Role |
| --- | --- | --- |
| `--primary` | `#0F62FE` | Primary actions, active nav, focused CoQUIC highlights |
| `--primary-hover` | `#0050E6` | Hover state for primary actions and selected controls |
| `--primary-active` | `#002D9C` | Pressed/active state, deep blue text accents |
| `--ink` | `#161616` | Main text, dense table values, strong labels |
| `--bg` | `#FFFFFF` | Page canvas |
| `--surface` | `#FFFFFF` | Cards, panels, nav background |
| `--surface-2` | `#F4F4F4` | Muted panels, inactive controls, table hover surfaces |
| `--surface-3` | `#E8E8E8` | Hover background and secondary track surfaces |
| `--muted` | `#6F6F6F` | Secondary labels, captions, axis labels |
| `--soft` | `#393939` | Body copy and tertiary detail |
| `--line` | `#E0E0E0` | Default border and grid line |
| `--line-strong` | `#C6C6C6` | Sticky table separators, strong boundaries |
| `--ok` | `#1F8A65` | Passing status |
| `--warning` | `#8D6D00` | Unsupported/partial status |
| `--danger` | `#CF2D56` | Failing/destructive status |

Supporting protocol/data colors may be used where a second channel is needed:

| Token | Hex | Role |
| --- | --- | --- |
| `--server` | `#78A9FF` | Server lane or peer-side accents |
| `--server-ink` | `#0043CE` | Server text accent |
| `--packet` | `#A6C8FF` | Packet, stream, or timeline accent |
| `--packet-ink` | `#002D9C` | Packet text accent |

Status backgrounds:

| State | Background | Border Guidance |
| --- | --- | --- |
| Pass | `#EDF8F4` | Green at 24-28 percent alpha |
| Unsupported | `#FCF4D6` | Warning at 26-30 percent alpha |
| Fail | `#FFF1F1` | Danger at 24-28 percent alpha |
| CoQUIC highlight | `#EDF5FF` | Primary at 28-32 percent alpha |

## Typography

Use the inherited Cursor-style type model but remove brand-specific type dependencies.

- Primary family: `CursorGothic`, then system UI fallbacks.
- Monospace family: `JetBrains Mono`, `Fira Code`, then system monospace.
- Letter spacing: `0` for CoQUIC UI. Do not use negative tracking.
- Weight: prefer 400 for display, 500-600 for labels and controls.
- Body text: 14-16px, line height 1.45-1.6.
- Compact metadata: 11-12px monospace.
- Table and metric values: monospace where scanning numeric data matters.
- Avoid oversized headings inside panels, tables, sidebars, or tool surfaces.

Recommended scale:

| Role | Size | Weight | Line Height |
| --- | --- | --- | --- |
| Page display | 46-104px by breakpoint | 400 | 1.0-1.08 |
| Page h1 | 38-46px | 400 | 1.08 |
| Section h2 | 22-26px | 600 | 1.25 |
| Panel h3 | 16-18px | 600 | 1.3 |
| Body | 14-16px | 400 | 1.5 |
| Caption/meta | 11-13px | 500-600 | 1.4 |
| Code/data | 11-13px | 400-600 | 1.4-1.5 |

## Layout

The layout inherits the Cursor/design-md idea of an editorial developer-tool canvas: spacious, flat, and content-led. CoQUIC applies that to protocol tools and data dashboards.

- Main container: centered, max width around `1340px`, page padding `24px` desktop, `12-18px` mobile.
- Navigation: sticky top nav, Home left, Workbench/Performance/Interop right.
- Page sections: full-width within the centered container; do not nest cards inside cards.
- Panels: use a 1px hairline border, white surface, no ornamental shadow.
- Radius: `4px` default for a crisp documentation feel.
- Vertical rhythm: compact on operational pages; generous only on the homepage slogan.
- Dense data: prefer tables, bars, tabs, and fixed-width columns over marketing cards.
- Mobile: allow horizontal scrolling for dense matrices and charts; do not squeeze status labels until unreadable.

## Components

### Navigation

- Background: `--surface` with slight translucency if sticky.
- Active page: `--primary` background, white text.
- Hover: `--surface-3` for inactive links.
- Height: about 64px desktop, 58px mobile.
- Keep text simple: Home, Workbench, Performance, Interop.

### Buttons And Links

- Primary button: `--primary` background, white text.
- Hover: `--primary-hover`.
- Active: `--primary-active`.
- Secondary button: white or muted surface with `--line` border.
- Link buttons on the homepage should look like compact docs CTAs, not marketing pills.
- All clickable controls need visible hover and keyboard focus states.

### Cards And Panels

- Use cards only for repeated items, framed tools, modals, and chart/table panels.
- Border: `1px solid --line`.
- Background: `--surface`.
- Shadow: none by default. Modal shadows may be subtle and neutral.
- Avoid floating section cards and card-in-card layouts.

### Data Tables

- Use hairline separators and sticky identity columns where helpful.
- Keep participant/client/server columns wide enough for avatars and names.
- Keep result columns wide enough for full `PASS`, `FAIL`, and `SKIP` labels.
- Use `--line-strong` for the boundary between row identity and test columns.
- Use monospace for test/status details where scanability matters.

### Charts And Benchmarks

- Bars may use implementation colors for differentiation, but the CoQUIC highlight uses `--primary`.
- Prefer clear units in labels: `MiB/s`, `Reqs/s`.
- Trend charts must support hover tooltips.
- Keep axis/grid lines quiet: `--line`.
- CoQUIC rows should be highlighted without dominating the leaderboard.

### Interop Matrix

- The matrix is CoQUIC-focused, not N x N.
- Show explicit `Client` and `Server` columns.
- Highlight any CoQUIC participant with the CoQUIC highlight background.
- Use peer GitHub avatars or vendor favicons where already available.
- Result cells use `PASS`, `FAIL`, `SKIP`, or `-`.

### Workbench

- The Workbench is a protocol inspector, not a landing page.
- Prioritize packet lanes, endpoint state, timeline, and detail inspection.
- Use stable dimensions for controls, packet rows, and detail panes.
- Avoid explanatory marketing copy inside the tool surface.

## Homepage

The homepage should remain minimal:

- Shared top nav.
- Centered slogan: `CoQUIC, from Prompt to Packet.`
- Three direct jump buttons: Workbench, Performance, Interop.
- No status cards, source lists, or implementation tables on the homepage.

The slogan may use subtle CoQUIC blue gradient text effects, but the page must still read as a restrained technical project page.

## Accessibility And Interaction

- Minimum touch target: 40px for buttons and icon controls.
- Focus ring: blue outline using `rgba(15, 98, 254, 0.48)`.
- Do not rely on color alone for status; include labels such as `PASS`.
- Text must not overflow buttons, cards, or table cells.
- Hover states must not shift layout.
- Avoid viewport-width font scaling for normal UI text. Use breakpoints and stable component constraints.

## Guardrails

Do:

- Use the tokens in this file and `site/next/app/globals.css`.
- Keep surfaces flat, borders crisp, and spacing predictable.
- Preserve dense but readable dashboards for benchmark and interop views.
- Use icons/logos only when they clarify identity or action.
- Keep generated preview data untracked unless explicitly requested.

Do not:

- Use IBM logos, copywriting, proprietary assets, or Carbon-specific identity language.
- Use Cursor logos, copywriting, or proprietary identity assets.
- Add decorative gradient orbs, bokeh blobs, or unrelated illustrations.
- Turn operational pages into marketing landing pages.
- Add rounded text badges where a standard icon, label, table cell, or button would be clearer.
- Reintroduce broad source panels, implementation matrix tables, or homepage metric cards unless explicitly requested.

## Implementation Notes

- Primary implementation file: `site/next/app/globals.css`.
- Page-level styles may exist, but shared brand rules should live in Tailwind component layers in `globals.css`.
- Root design source: this `DESIGN.md`.
- Packaging must include the Next.js generated CSS assets.
- When changing UI, run:
  - `npm --prefix site/next run build`
  - `node --check site/next/public/perf-comparison.js`
  - `node --check site/next/public/interop-results.js`
  - `git diff --check`

## Agent Prompt Guide

When building new CoQUIC UI, follow this prompt:

> Build a flat, documentation-friendly CoQUIC interface using a white canvas, muted gray surfaces, 1px hairline borders, restrained type, and CoQUIC Blue `#0F62FE` for primary actions and CoQUIC highlights. Preserve dense operational layouts for protocol inspection, benchmarks, and interop matrices. Do not copy IBM, Cursor, or other proprietary brand assets.
