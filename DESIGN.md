# CoQUIC Design System

Last updated: 2026-07-13

This file is the design source of truth for CoQUIC UI work. Read it before
changing `site/next/*` or adding a demo, tool, dashboard, report,
documentation, benchmark, or interop view.

This document defines the target system. Existing screens may predate it. Do
not preserve an older color, layout, or component pattern only because it is
already present in the site. Migrate deliberately, keep behavior intact, and
prefer shared tokens and primitives over page-local styling.

When rules conflict, use this priority order:

1. Accessibility and task completion.
2. Page-specific rules in this document.
3. Shared component rules.
4. Global visual foundations.
5. Decorative preference.

## Product And Audience

CoQUIC is an experimental QUIC implementation and a public body of engineering
evidence. The site serves several jobs:

- Explain the API and implementation to protocol engineers and integrators.
- Let contributors inspect QUIC behavior in the Workbench.
- Publish benchmark, interop, coverage, and RFC traceability evidence.
- Expose the transcript dataset and Steward operating state.
- Answer specification questions with grounded references.

The primary context is focused technical work on desktop. Documentation,
project status, evidence summaries, and essential controls must remain complete
and usable on mobile. Dense desktop tools may simplify their arrangement on
small screens, but must not become clipped, hidden, or globally scrollable.

## Brand Foundation

### Brand Idea

- Name: CoQUIC.
- Slogan: `CoQUIC, from Prompt to Packet.`
- Design concept: packet-native precision.
- Promise: generated implementation made inspectable through protocol state,
  reproducible evidence, and clear documentation.
- Personality: precise, calm, direct, curious, rigorous, and modern.
- Not the personality: corporate, cinematic, playful, luxurious, nostalgic,
  futuristic for its own sake, or visually noisy.

CoQUIC must look like a protocol instrument and an open engineering project,
not a generic SaaS dashboard or a copy of another developer tool.

### Signature Visual Language

Use these recurring signals to make the identity recognizable:

- The split-Q logo and its packet tail.
- Thin directional paths, endpoint pairing, packet markers, and timestamps.
- Strong alignment between labels, values, and evidence.
- Sans-serif language for reading and monospace language for machine state.
- Cobalt for CoQUIC identity and actions; cyan for the server-side protocol
  channel; semantic colors only for semantic states.

The protocol motif uses 1px paths, compact arrowheads, and square packet markers
with at most a 1px radius. It may clarify flow, selection, progress, or real
packet state. Do not scatter decorative network diagrams across pages.

### Logo

- Use the repository CoQUIC logo. Do not redraw or distort it.
- Keep clear space around the mark equal to at least half its visible height.
- Navigation mark: 28-32px. Primary display mark: 72-104px by breakpoint.
- In light mode, use near-black with the cobalt packet tail.
- In dark mode, use near-white with the cobalt packet tail.
- Do not place the mark in a rounded tile unless the surrounding platform
  requires an application icon.
- Do not apply glow, shadow, bevel, or a multicolor gradient to the logo.

## Design Principles

### Operational First

Tools and reports must expose state, relationships, units, and available
actions before explanation. Operational pages are not landing pages.

### Evidence Has Hierarchy

Lead with the conclusion or current state, then expose the supporting detail.
Use progressive disclosure for logs, transcripts, diffs, tooltips, and dense
metadata. Do not hide the primary result behind decorative summary cards.

### Dense, Not Cramped

Dense interfaces are welcome when alignment, grouping, and typographic rhythm
make scanning easier. Small text, weak contrast, and stacked border boxes are
not acceptable substitutes for density.

### Flat, Not Unfinished

Flat design does not mean every surface is white or every region needs a
hairline box. Use canvas, surface, subtle surface, dividers, and whitespace to
create hierarchy. Reserve shadow for overlays.

### Beauty Through Precision

Beauty comes from consistent geometry, intentional whitespace, restrained
color, crisp typography, and stable interaction. It does not come from blobs,
glass effects, broad gradients, oversized type, or ornamental animation.

### Both Themes Are First-Class

Light and dark themes must communicate the same hierarchy and states. Dark mode
uses neutral near-black surfaces, not a page dominated by blue-gray tones.

## Color System

Use semantic tokens. A component consumes a role such as `--text-muted` or
`--status-danger-surface`; it must not choose a raw brand shade. During
migration, old token names may alias these values, but new work uses the names
in this document.

### Core Theme Tokens

| Token | Light | Dark | Role |
| --- | --- | --- | --- |
| `--canvas` | `#F7F9FC` | `#0D0F12` | Page background |
| `--surface` | `#FFFFFF` | `#15181C` | Primary working surface |
| `--surface-subtle` | `#F0F3F7` | `#1C2025` | Grouped rows, hover, quiet regions |
| `--surface-strong` | `#E5EAF1` | `#262B32` | Selected tracks and strong separation |
| `--code-surface` | `#F3F5F8` | `#0F1216` | Code, logs, packet bytes |
| `--text-strong` | `#111318` | `#F5F7FA` | Headings, key values, controls |
| `--text` | `#303640` | `#D5DBE3` | Body copy and table values |
| `--text-muted` | `#5F6B7A` | `#9AA5B3` | Metadata, captions, axes |
| `--border` | `#D8DEE8` | `#30363F` | Quiet dividers and panel boundaries |
| `--border-strong` | `#B6C0CD` | `#4A535F` | Sticky boundaries and selected regions |
| `--control-border` | `#8A96A6` | `#626D7A` | Inputs and controls requiring a visible edge |
| `--accent` | `#1463FF` | `#1768E8` | Filled actions and CoQUIC emphasis |
| `--accent-hover` | `#0A54D6` | `#2B70E8` | Hovered filled actions |
| `--accent-active` | `#083FA6` | `#0A54D6` | Pressed filled actions |
| `--accent-ink` | `#0A54D6` | `#82AEFF` | Links, active text, lines, icons |
| `--accent-soft` | `#EAF1FF` | `#182A49` | Selection and CoQUIC row highlight |
| `--on-accent` | `#FFFFFF` | `#FFFFFF` | Text and icons on filled actions |
| `--focus-ring` | `rgb(20 99 255 / 48%)` | `rgb(130 174 255 / 58%)` | Keyboard focus halo |
| `--scrim` | `rgb(17 19 24 / 48%)` | `rgb(0 0 0 / 68%)` | Modal and drawer backdrop |

The light canvas is intentionally off-white so white working surfaces have
quiet depth without shadow. The dark canvas and surfaces are neutral, not navy.

Verified contrast anchors:

- `--accent` with `--on-accent`: at least 4.9:1 in both themes.
- Light `--text-muted` on `--surface`: 5.4:1.
- Dark `--text-muted` on `--surface`: 7.1:1.
- `--control-border` against its theme surface: at least 3:1.

### Protocol Roles

Protocol-role colors describe topology, never success or failure.

| Token | Light | Dark | Role |
| --- | --- | --- | --- |
| `--client` | `#1463FF` | `#82AEFF` | Client endpoint, client-originated path |
| `--client-soft` | `#EAF1FF` | `#182A49` | Client selection or lane surface |
| `--client-ink` | `#0A54D6` | `#82AEFF` | Client labels and icons |
| `--server` | `#00758F` | `#5DD8E9` | Server endpoint, server-originated path |
| `--server-soft` | `#E4F6FA` | `#112B31` | Server selection or lane surface |
| `--server-ink` | `#006278` | `#5DD8E9` | Server labels and icons |
| `--packet-neutral` | `#5F6B7A` | `#9AA5B3` | Direction-neutral packet metadata |

Client-to-server traffic uses the client channel. Server-to-client traffic
uses the server channel. Packet type is communicated with label, marker shape,
or line style instead of adding another ambiguous color.

### Status Roles

Each state has text, surface, and border tokens. Name them
`--status-<state>-ink`, `--status-<state>-surface`, and
`--status-<state>-border`. Always show a text label or icon in addition to
color.

| State/Token | Light Text | Light Surface | Light Border | Dark Text | Dark Surface | Dark Border |
| --- | --- | --- | --- | --- | --- | --- |
| Success | `#0E6B48` | `#E8F7F1` | `#9BD4BF` | `#55D6A0` | `#142A22` | `#275E49` |
| Warning | `#7A5200` | `#FFF6D8` | `#E3C468` | `#F2C14E` | `#2A2415` | `#64521F` |
| Danger | `#B42345` | `#FFF0F3` | `#E6A0B1` | `#FF829D` | `#2B171D` | `#693241` |
| Neutral | `#5F6B7A` | `#F0F3F7` | `#C4CCD7` | `#9AA5B3` | `#1C2025` | `#3A424C` |
| Known-peer | `#6842B8` | `#F3EEFF` | `#C7B6ED` | `#C4A8FF` | `#231B31` | `#51406B` |

Map `PASS` to success, `UNSUPPORTED` to warning, `FAIL` to danger,
`PEER BROKEN` and `NOT REPORTED` to neutral, and `KNOWN PEER ISSUE` to
known-peer.

Use warning for a degraded or incomplete state, not as decoration. Use danger
only when the task or evidence has actually failed. An expected offline or
not-yet-published state is neutral unless user action is required.

### Categorical Data

Charts that need distinct series use this ordered palette. A series keeps the
same index across charts on the same page.

| Token | Light | Dark |
| --- | --- | --- |
| `--chart-1` | `#1463FF` | `#82AEFF` |
| `--chart-2` | `#00758F` | `#5DD8E9` |
| `--chart-3` | `#7257D5` | `#B9A7FF` |
| `--chart-4` | `#A15C00` | `#FFB45E` |
| `--chart-5` | `#B6427A` | `#F28BC0` |
| `--chart-6` | `#4F667A` | `#AAB7C4` |

Do not use status colors as an unlabeled categorical palette. Vendor colors may
appear in official logos or a legend, but CoQUIC highlighting still uses the
accent token. Every chart also needs labels, a legend, or an accessible data
table so color is never the only key.

### Color Guardrails

- Do not use the old IBM Carbon blue and gray scale as a substitute palette.
- Do not introduce page-local hex values when a semantic role exists.
- Do not create text colors by lowering opacity; use a contrast-tested token.
- Do not use broad gradients on page backgrounds, panels, buttons, or charts.
- The wordmark uses solid `--text-strong` and `--accent-ink`, not gradient text.
- Official third-party logos retain their approved colors and proportions.

## Typography

### Families

- Sans: `Instrument Sans`, then `ui-sans-serif`, `system-ui`, `-apple-system`,
  `BlinkMacSystemFont`, and `Segoe UI`.
- Mono: `Commit Mono`, then `ui-monospace`, `SFMono-Regular`, `Cascadia Code`,
  `Consolas`, and `Liberation Mono`.

Self-host Instrument Sans and Commit Mono through the Next.js font tooling with
`font-display: swap`. Keep their license files with the font assets. Do not
depend on a font name that is not shipped, and do not import runtime fonts from
a third-party CDN. Use 400, 500, 600, and 700 weights only.

### Type Scale

Use fixed sizes at breakpoints. Do not scale normal UI text with viewport width.
Letter spacing is `0` throughout the site; do not use negative tracking.

| Role | Desktop | Mobile | Weight | Line Height |
| --- | --- | --- | --- | --- |
| Brand display | 72px | 40px | 500 | 1.0 |
| Brand support | 32px | 24px | 400 | 1.15 |
| Page title | 40px | 30px | 500 | 1.1 |
| Section title | 24px | 22px | 600 | 1.25 |
| Panel title | 16px | 16px | 600 | 1.3 |
| Body | 15-16px | 15-16px | 400 | 1.5-1.6 |
| UI label | 14px | 14px | 500-600 | 1.35 |
| Metadata | 12px | 12px | 500-600 | 1.4 |
| Code/data | 12-13px | 12-13px | 400-600 | 1.45 |

Rules:

- When a portal uses the brand display, make `CoQUIC` the `h1` and keep the
  slogan as supporting copy.
- Each page has one clear `h1`. Heading levels must not skip.
- Use sans-serif for prose and decisions. Use monospace for code, identifiers,
  timestamps, units, protocol state, and numeric comparison values.
- Keep long-form text between 60 and 76 characters per line.
- Do not set paragraphs, navigation, or long labels entirely in monospace.
- Avoid all-caps copy except short protocol/status labels. Keep letter spacing
  at `0` even for uppercase metadata.
- Never use 10px text. Use 11px only for short machine metadata when 12px does
  not fit; never use it for prose or essential actions.

## Spacing And Geometry

### Spacing Scale

| Token | Value | Typical Use |
| --- | --- | --- |
| `--space-1` | 4px | Icon-to-label micro gap |
| `--space-2` | 8px | Compact control and row gap |
| `--space-3` | 12px | Control padding and compact groups |
| `--space-4` | 16px | Default component padding |
| `--space-5` | 24px | Panel padding and page gutter |
| `--space-6` | 32px | Section separation |
| `--space-7` | 48px | Major page rhythm |
| `--space-8` | 64px | Brand display and editorial separation |

Use values from this scale. A child gap should normally be one step smaller
than its container padding.

### Radii

| Token | Value | Use |
| --- | --- | --- |
| `--radius-control` | 4px | Buttons, inputs, tabs, status cells |
| `--radius-panel` | 6px | Cards, panels, code blocks |
| `--radius-overlay` | 8px | Dialogs, popovers, drawers |

Use a full circle only for avatars, status dots, radio controls, and circular
icon buttons. Do not turn ordinary labels or actions into pills.

### Control And Icon Sizes

- Compact desktop control: 36px high, only in dense fine-pointer tools.
- Default desktop control: 40px high.
- Coarse-pointer and mobile control: at least 44px high and 44px wide.
- Icon sizes: 16px compact, 18px default, 20px prominent, 24px navigation.
- Use Lucide outline icons with a consistent 1.75-2px stroke.
- Reserve dimensions for icons, counters, loading indicators, and dynamic
  labels so state changes do not shift layout.

Density follows input capability and task context, not viewport width alone.
Operational tables may use compact density on a fine pointer. Touch layouts use
comfortable density even when the screen is wide.

### Borders, Elevation, And Stacking

- Default divider: 1px `--border`.
- Strong boundary: 1px `--border-strong`.
- Input boundary: 1px `--control-border` when the field cannot be identified
  without its edge.
- Focus: 2px solid accent with a 2-3px offset and `--focus-ring` halo.
- Panels and cards have no shadow.
- Dropdown shadow (`--shadow-dropdown`):
  `0 12px 32px rgb(17 19 24 / 14%)` in light mode and
  `0 16px 40px rgb(0 0 0 / 48%)` in dark mode.
- Modal shadow (`--shadow-modal`):
  `0 24px 64px rgb(17 19 24 / 20%)` in light mode and
  `0 28px 72px rgb(0 0 0 / 64%)` in dark mode.

Use this stacking scale:

| Token | Layer | Z Index |
| --- | --- | --- |
| `--z-base` | Base content | 0 |
| `--z-sticky` | Sticky page controls | 10 |
| `--z-navigation` | Global navigation | 20 |
| `--z-dropdown` | Dropdown and tooltip | 30 |
| `--z-drawer` | Scrim and drawer | 40 |
| `--z-modal` | Modal | 50 |
| `--z-toast` | Toast | 60 |

Do not invent arbitrary z-index values.

## Motion

Motion communicates cause and state. It is not ambient decoration.

| Token | Duration | Use |
| --- | --- | --- |
| `--motion-fast` | 120ms | Press, color, icon feedback |
| `--motion-standard` | 180ms | Menu, disclosure, tooltip |
| `--motion-slow` | 240ms | Dialog and drawer entrance |

- Standard easing: `cubic-bezier(0.2, 0, 0, 1)`.
- Exit motion may be 20-30 percent faster than entrance motion.
- Animate opacity and transform only when possible.
- Never animate layout dimensions on dense tables or packet lanes.
- Infinite motion is limited to progress indicators and live status signals.
- Under `prefers-reduced-motion: reduce`, remove nonessential motion, stop live
  pulses, and make scrolling immediate.

## Layout System

### Containers And Measures

- Main application container: `1340px` maximum width.
- Extra-wide evidence matrix or timeline: up to `1520px` when the viewport
  allows it; it must still have page gutters.
- Reading measure: `760px` maximum.
- Editorial article: `860px` maximum including code examples.
- Dialog: `640px` default, `840px` for search or diff inspection.
- Page gutter: 12px at 320-479px, 16px at 480-767px, 20px at 768-1199px,
  and 24px at 1200px and above.

Recommended breakpoints are 480px, 768px, 1024px, and 1280px. Break at the
point where content stops working, not merely because a device name changes.

### Page Anatomy

Most pages use this order:

1. Skip link.
2. Global navigation.
3. Unframed page header.
4. Primary controls or summary band.
5. Main content.
6. Compact project footer where appropriate.

The page header contains an optional category label, one `h1`, optional
supporting copy, and page-level actions. Use a 6px square packet marker before
the category label. Actions align to the right on desktop and wrap beneath the
title on mobile. Do not put the entire page header in a card.

Operational page headers are compact. Editorial pages may use more vertical
space, but content should enter the first viewport. A blank lower viewport is
not a design goal.

### Surface Composition

- Use full-width unframed sections for page structure.
- Use panels for a genuinely bounded tool, table, chart, or repeated item.
- Do not put a card inside another card.
- Prefer dividers, background changes, or grid alignment over boxing every
  region.
- A row may be clickable without being styled as a floating card.
- Keep one dominant visual anchor per viewport: the active tool, result,
  dataset detail, matrix, or article.

### Responsive Behavior

- The document must never be wider than the viewport at 320px.
- Global navigation must never use horizontal scrolling.
- Editorial navigation must not appear as a long block before the article on
  mobile.
- Dense matrices, timelines, and data tables may scroll inside a labeled
  region. Keep identity columns sticky and add a subtle edge shadow or fade to
  reveal additional content.
- Never hide essential actions, theme control, or current-page context solely
  because the viewport is narrow.
- Actions wrap; text does not shrink below its role size.
- At 200 percent zoom, content must reflow without loss of operation.

## Global Navigation

The global navigation reflects user tasks, not the repository directory tree.
Keep three to five high-frequency destinations visible on wide screens and
group the remainder by user intent. Utilities such as search, theme, project
contact, and source hosting remain visually separate from destinations. Use one
stable label for each destination across navigation, headings, and search.

Desktop behavior:

- Height: 56px.
- Logo at the left, followed by Search.
- Destination groups align right.
- Active destination uses `--accent-soft`, `--accent-ink`, and a 2px bottom
  marker. Do not use a large solid blue block for routine active navigation.
- Sticky background uses a 96 percent opaque `--surface`; backdrop blur is
  optional and must not create a glass effect.

Mobile behavior:

- Height: 52px.
- Show logo, Search, current section, and one familiar menu icon.
- Open the complete destination list in a drawer or anchored menu.
- Put theme, contact, and GitHub utilities inside that menu.
- Do not show a clipped, scrollbar-free row of destination labels.
- Restore focus to the menu trigger when the menu closes.

All menus close on Escape and outside activation, support arrow-key movement
where appropriate, and expose expanded/current state semantically. Include a
visible-on-focus skip link before the navigation.

## Components

### Buttons And Command Links

Variants:

- Primary: `--accent` fill, `--on-accent` content.
- Secondary: `--surface` fill, `--control-border` edge, strong text.
- Ghost: transparent, strong text, subtle hover surface.
- Danger: danger surface, danger text, danger border.
- Icon: familiar symbol with an accessible name and tooltip when needed.

Rules:

- Use icons for familiar tool actions such as copy, download, theme, close,
  search, previous, next, and expand.
- Use icon plus text when the command is consequential or ambiguous.
- Use text buttons for clear commands such as Ask, Run, Apply, and Reset.
- Hover, pressed, focus, disabled, and loading states are required.
- A loading button retains its width, becomes disabled, and shows progress.
- Disabled controls remain legible and expose native disabled semantics.
- Hover and pressed feedback must not move surrounding layout.
- Links in prose remain visibly identifiable without relying on hover.

### Forms

- Every input has a persistent label unless its purpose is completely explicit
  from an adjacent tool label and accessible name.
- Placeholder text is an example, not a label.
- Help and error text appears below the field without shifting neighboring
  columns.
- Error messages state what failed and what the user can do next.
- Use native controls where possible and the correct `inputmode` on mobile.
- Textareas start at a purposeful height; do not fill most of the viewport
  before the user has entered content.
- Search fields include a search icon, clear action when populated, and stable
  result count or loading feedback.

### Tabs, Segmented Controls, And Filters

- Tabs switch views of the same object. Segmented controls switch compact modes.
- A tablist has one clear active item and supports arrow keys.
- Use a menu, select, or disclosure for more than six compact options.
- Filters show active state and result count. Reset is disabled when no filter
  is active.
- On mobile, substantial filter sets open in a drawer or disclosure instead of
  occupying the first viewport.
- Never use decorative rounded text chips as substitutes for tabs or filters.

### Cards And Panels

- Card radius: `--radius-panel`; border: `--border`; shadow: none.
- Use cards for repeated blog posts, bounded tools, modals, or individually
  selectable records.
- Use panels for charts, tables, logs, and inspector regions.
- A panel header is compact and aligned; it does not need a tinted background
  unless it remains sticky.
- Avoid cards for page sections, isolated headings, and single metrics that can
  live in a summary band.
- Never nest a card inside another card. Use an inset row or `--surface-subtle`
  region instead.

### Status Labels And Badges

- Status labels use compact rectangular geometry, not pills.
- Include a label such as `PASS`, `FAIL`, `UNSUPPORTED`, `PEER BROKEN`,
  `KNOWN PEER ISSUE`, or `NOT REPORTED`.
- In dense matrices, tint the result cell rather than placing a bordered badge
  inside every bordered cell.
- Use a dot only as a secondary signal beside text.
- Badges are reserved for short metadata such as a language, tag, or version;
  they must not look like buttons.

### Tables And Matrices

- Use semantic table markup when the content is tabular.
- Keep headers sticky when rows extend beyond one viewport.
- Keep identity columns sticky for wide comparison tables.
- Right-align numeric values and align decimals where comparison matters.
- Use monospace for values and units, not participant names or explanations.
- Give columns enough width for complete labels. Abbreviations need an
  accessible full name.
- Row hover may use `--surface-subtle`; selection uses `--accent-soft` plus a
  non-color marker.
- Horizontal scrolling belongs to the table wrapper, never the page.
- Keyboard focus and hover must reveal the same contextual detail.

### Charts And Comparisons

- Prefer bars for ranking, lines for trends, and small multiples for comparing
  a few metrics. Avoid pie and donut charts for precise engineering evidence.
- Show units in axis labels and values: `MiB/s`, `req/s`, `ms`, and `%`.
- Trend charts support pointer and keyboard tooltips.
- Grid lines use `--border`; axes use `--text-muted`.
- CoQUIC is highlighted with an accent marker or soft row, not an oversized
  saturated bar that overwhelms competitors.
- Preserve a stable chart area while data loads.
- Provide a table or text equivalent for important chart values.

### Code, Logs, And Packet Data

- Use `--code-surface`, a 1px border, and `--radius-panel`.
- Show language or payload type in a compact header only when useful.
- Copy and download use familiar icons with accessible names.
- Long lines scroll within the code region; the page does not overflow.
- Logs and transcript views preserve whitespace and use tabular numerals.
- Syntax colors must meet contrast requirements in both themes.
- Do not use terminal-green styling as a general design motif.

### Search And Overlays

- Search opens as a command dialog up to 840px wide.
- Autofocus the query, group results by destination type, and keep the selected
  result visible.
- Dialogs trap focus, close on Escape, restore trigger focus, and use `--scrim`.
- Tooltips supplement an accessible name; they never contain essential actions.
- Drawers are for navigation or substantial mobile filters, not ordinary
  confirmation messages.

### Loading, Empty, Offline, And Error States

- Show feedback for operations lasting longer than 300ms.
- Skeletons reserve the final geometry for tables, charts, metric bands, and
  inspector panes. Use a spinner for compact commands.
- Set `aria-busy` on the affected region and announce completion politely.
- Do not render a viewport-sized empty bordered panel while waiting for data.
- Empty states contain a short title, a factual reason, and one relevant action
  when an action exists. They remain visually attached to the region they
  describe.
- Offline and stale states show last-updated time and whether displayed data is
  retained. Do not label an expected missing snapshot as a failure.
- Errors preserve surrounding navigation and recovery actions.
- Never populate loading states with fake production metrics.

## Reusable Layout Patterns

These patterns are compositional tools, not page specifications. A product
screen may use one pattern, combine compatible parts of two, or define a
documented exception. Route names, exact content order, and feature behavior
belong in product requirements beside the implementation.

### Portal

Use for a compact project entry point or task launcher.

- Make the product or tool identity the first-viewport signal.
- Keep one concise supporting statement and two or three direct actions.
- Use an unframed composition with one real product-state visual when useful.
- Keep the primary composition short enough to reveal the next useful region.
- Do not turn the portal into a grid of marketing cards or fabricated metrics.

### Editorial

Use for documentation, articles, API guidance, and technical explanation.

- Keep the article between 60 and 76 characters per line.
- A desktop section navigator may remain sticky beside the article.
- On mobile, show content first and move navigation into a disclosure or drawer.
- Let code, tables, and figures extend beyond the prose measure when needed.
- Use anchored headings, visible links, and copyable code without boxing every
  section.

### Inspector

Use for protocol state, timelines, packet detail, and other active tools.

- Order controls, shared context, topology or timeline, then detailed state.
- Give the main inspected object most of the available space.
- Keep controls, lanes, counters, and detail panes dimensionally stable.
- Use role colors for topology and status colors for outcomes; never conflate
  the two.
- On narrow screens, switch among peer or detail views instead of duplicating
  long side-by-side panes vertically.

### Evidence

Use for comparisons, reports, matrices, coverage, and compliance data.

- Lead with current scope, timestamp, filters, and the primary result.
- Prefer a divided summary band, table, bar ranking, or trend over metric cards.
- Keep units, baselines, thresholds, and result vocabulary explicit.
- Wide evidence scrolls within a labeled region with sticky identity columns.
- Loading preserves final geometry; generated or embedded reports inherit the
  system at their generator or wrapper boundary.

### Master-Detail

Use for datasets, sessions, tasks, artifacts, and other selectable records.

- Keep search and filters close to the collection they affect.
- Desktop may show the collection and selected record side by side.
- Mobile uses a list/detail transition or mode switch rather than one long
  stacked page.
- Preserve selection, scroll position, and browser history when moving between
  list and detail.
- Reserve the detail pane while content loads and keep record identity and
  actions consistently aligned.

## Accessibility And Interaction

Meet WCAG 2.2 AA as the minimum target.

- Body text contrast: at least 4.5:1.
- Large text and essential graphics: at least 3:1.
- Control boundaries and focus indicators: at least 3:1 against adjacent color.
- Touch targets: at least 44x44px on coarse pointers.
- Keyboard focus is always visible and never clipped by overflow.
- Keyboard order follows visual order. Do not use positive `tabindex` values.
- Every page has one `h1` and a sequential heading structure.
- All icon-only actions have accessible names.
- Tooltips are available to keyboard users and are not the sole source of
  essential information.
- Status never relies on color alone.
- Charts provide labels and a nonvisual equivalent for important values.
- Live updates use polite announcements and do not repeatedly steal focus.
- Dialogs and drawers manage focus correctly.
- Support 200 percent zoom and reflow down to 320px without global horizontal
  scrolling.
- Respect `prefers-reduced-motion`, `prefers-color-scheme`, and forced-color
  mode.
- Theme choice follows the system on first visit, can be changed everywhere,
  and persists without a flash of the wrong theme.
- Hover-only interactions must have focus and touch alternatives.

## Content And Data Language

- Use sentence case for headings, labels, tabs, menus, and buttons.
- Preserve standard casing for CoQUIC, QUIC, HTTP/3, RFC, API, WASM, JSON, and
  implementation names.
- Prefer direct commands: `Download JSON`, `Copy`, `Run`, `Open report`.
- Use exact units: `MiB/s`, `req/s`, `ms`, `bytes`, and `%`.
- Put a space between a value and unit except `%` where local conventions
  require no space.
- Use tabular numerals for aligned metrics.
- Show timezone or `UTC` for timestamps when ambiguity matters.
- Keep operational copy factual. Avoid marketing claims inside tools.
- Error copy names the failed operation, preserves useful technical detail, and
  offers a recovery path.
- Do not expose internal placeholder or generated filename language as the main
  user-facing title when a clearer label exists.

## Guardrails

Do:

- Use the semantic tokens and shared primitives defined here.
- Use neutral canvas and surface hierarchy to make dense content legible.
- Keep the logo, packet paths, endpoint pairing, and telemetry rhythm coherent.
- Preserve clear endpoint topology in inspectors and the evidence-first
  character of reports.
- Use icons when they improve command recognition.
- Keep mobile documentation and project evidence genuinely usable.
- Reserve stable space for asynchronous content.

Do not:

- Copy IBM Carbon, Cursor, Vercel, or another product's visual identity.
- Use unavailable brand-specific fonts.
- Use decorative gradient orbs, bokeh, glassmorphism, glow, or heavy shadow.
- Use broad blue or purple gradients as the site identity.
- Make dark mode a one-note navy or slate interface.
- Turn operational pages into marketing landing pages.
- Put cards inside cards or style every section as a floating card.
- Use pills for ordinary labels, navigation, or commands.
- Use emoji as structural icons.
- Horizontally scroll the global navigation.
- Hide essential utilities on mobile.
- Shrink text to make a broken layout fit.
- Add page-local colors, radii, spacing, or z-index values without updating the
  system when a new semantic role is genuinely required.
- Use fake data to make loading or empty states look complete.

## Implementation And Governance

### Token And Style Ownership

- `DESIGN.md` owns design intent, semantic roles, values, components, and
  reusable layout patterns.
- `design-reference/` is a non-normative evaluation surface. It may illustrate
  the system, but it does not define route requirements or override this file.
- `site/next/app/globals.css` remains the global CSS entry point.
- As the implementation is modernized, split imported styles by responsibility:
  foundations/tokens, base elements, shared components, then feature styles.
- Shared React primitives live under `site/next/src/components/ui/`.
- Feature styles may consume semantic tokens; they may not redefine the global
  brand palette.
- Temporary migration aliases are acceptable:
  - `--bg` -> `--canvas`
  - `--ink` -> `--text-strong`
  - `--soft` -> `--text`
  - `--muted` -> `--text-muted`
  - `--line` -> `--border`
  - `--primary` -> `--accent`
- Remove aliases after all consumers move. Do not maintain two permanent token
  vocabularies.

### Exceptions

A page-specific exception must satisfy all of these conditions:

1. It represents a real semantic or interaction need not covered here.
2. It works in light, dark, mobile, keyboard, and reduced-motion contexts.
3. It does not create a second version of an existing component.
4. Its new rule is added to this document when it should be reused.

Third-party and generated reports should be normalized at their generator or
wrapper boundary. Do not scatter override hacks through unrelated page styles.

### Validation

For UI changes, validate at minimum:

- 320px and 375px phone widths.
- 768px tablet width and landscape orientation.
- 1024px desktop width.
- 1440px wide desktop.
- Light, dark, and initial system theme.
- Keyboard-only navigation and visible focus.
- Reduced motion and 200 percent zoom.
- Empty, loading, error, offline, long-label, and populated states.
- No global horizontal overflow.
- No serious or critical automated accessibility findings.

Use Playwright screenshots for every reusable pattern affected by a change and
add focused screenshots for any exceptional composition.

Run the repository checks appropriate to the change, including:

- `npm --prefix site/next run typecheck`
- `npm --prefix site/next run test`
- `npm --prefix site/next run build`
- `node --check site/next/public/perf-comparison.js`
- `node --check site/next/public/interop-results.js`
- `git diff --check`

Keep generated preview data, screenshots, build output, and downloaded state
untracked unless explicitly requested.

## Review Checklist

Before merging UI work, confirm:

- The page has one obvious primary task or result.
- Product and page identity are visible in the first viewport.
- Typography follows the scale and no font dependency is missing.
- All colors come from semantic roles and work in both themes.
- Client, server, status, and categorical data colors are not conflated.
- Spacing, radius, icon, motion, and stacking values use the shared scales.
- Panels are genuinely bounded tools or repeated items, with no nested cards.
- Navigation and essential actions remain complete on mobile.
- Dense tables scroll locally with sticky identity and visible continuation.
- Loading preserves final geometry; empty and error states are informative.
- Hover, focus, pressed, disabled, loading, and selected states are implemented.
- Text does not overflow, truncate critical meaning, or become unreadably small.
- Keyboard, touch, zoom, reduced motion, and screen reader behavior are covered.
- Screenshots show no incoherent overlap, clipping, or unintended blank canvas.

## Agent Prompt Guide

When building or revising CoQUIC UI, use this direction:

> Build a packet-native CoQUIC interface with an off-white or neutral-black
> canvas, crisp white or near-black working surfaces, independent cobalt brand
> actions, cyan server-side protocol roles, restrained sans typography, and
> monospace telemetry. Use alignment, surface hierarchy, directional paths, and
> evidence density to create beauty. Preserve complete light, dark, desktop,
> mobile, keyboard, and loading states. Do not copy another developer-tool
> identity, introduce decorative effects, nest cards, or trade readability for
> density.
