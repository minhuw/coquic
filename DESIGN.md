# CoQUIC Design System

Last updated: 2026-07-14

This file is the design source of truth for CoQUIC UI work. Read it before
changing `site/next/*` or adding a demo, tool, dashboard, report,
documentation, benchmark, or interop view.

This document defines the target system. Existing screens may predate it. Do
not preserve an older color, layout, or component pattern only because it is
already present in the site. Migrate deliberately, keep behavior intact, and
prefer shared tokens and primitives over page-local styling.

This document intentionally does not specify individual routes. Information
architecture, route content, and feature behavior belong with product
requirements and implementation. Add a decision here only when it is reusable
across surfaces or establishes a system-wide constraint.

When rules conflict, use this priority order:

1. Accessibility and task completion.
2. Information meaning and product behavior.
3. The applicable reusable layout pattern.
4. Shared component rules.
5. Global visual foundations.
6. Decorative preference.

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
- Personality: precise, calm, direct, editorial, rigorous, and modern.
- Not the personality: corporate, cinematic, playful, luxurious, nostalgic,
  futuristic for its own sake, or visually noisy.

CoQUIC must look like a protocol instrument and an open engineering project,
not a generic SaaS dashboard or a copy of another developer tool.

### Signature Visual Language

Use these recurring signals to make the identity recognizable:

- The split-Q logo and its packet tail.
- Thin directional paths, endpoint pairing, packet markers, and timestamps.
- Strong alignment between labels, values, and evidence, with generous neutral
  space around the primary result.
- Sans-serif language for reading and monospace language for machine state.
- Near-black or near-white for ordinary commands and application chrome.
- Cobalt for CoQUIC identity, links, focus, selection, and the client-side
  protocol channel; cyan for the server-side channel; semantic colors only for
  semantic states.

The protocol motif uses 1px paths, compact arrowheads, and square packet markers
with at most a 1px radius. It may clarify flow, selection, progress, or real
packet state. Do not scatter decorative network diagrams across pages.

### Logo

- Use the repository split-Q artwork as the canonical geometry. Do not redraw
  or distort it.
- Keep clear space around the mark equal to at least half its visible height.
- Navigation mark: 24-28px. Primary display mark: 56-80px by breakpoint.
- In light mode, use near-black with the cobalt packet tail.
- In dark mode, use near-white with the cobalt packet tail.
- Implement theme-aware logo color in one shared asset or logo component. Do
  not use CSS filters or maintain page-local copies of the artwork.
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

### Color Must Earn Attention

Most application chrome is neutral. Brand, protocol, status, and categorical
colors appear only when they communicate identity, topology, state, or data.
Do not spend cobalt on large routine surfaces, every primary command, or active
navigation backgrounds. A quiet shell makes real protocol evidence more vivid.

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
| `--canvas` | `#FAFAF8` | `#111210` | Page background |
| `--surface` | `#FFFFFF` | `#171916` | Primary working surface |
| `--surface-subtle` | `#F4F5F2` | `#1E211D` | Grouped rows, hover, quiet regions |
| `--surface-strong` | `#E9EBE7` | `#292D28` | Disabled controls and strong separation |
| `--code-surface` | `#F5F6F3` | `#131512` | Code, logs, packet bytes |
| `--text-strong` | `#111310` | `#F5F6F3` | Headings, key values, controls |
| `--text` | `#323630` | `#D6DAD2` | Body copy and table values |
| `--text-muted` | `#626960` | `#A4ABA0` | Metadata, captions, axes |
| `--border` | `#DDDFDA` | `#30342F` | Quiet dividers and panel boundaries |
| `--border-strong` | `#B8BDB5` | `#50564E` | Sticky boundaries and selected regions |
| `--control-border` | `#7C8379` | `#6A7267` | Inputs and controls requiring a visible edge |
| `--command` | `#141613` | `#F5F6F3` | Primary command fill |
| `--command-hover` | `#2B2E29` | `#DFE3DB` | Hovered primary command |
| `--command-active` | `#090A09` | `#C8CEC4` | Pressed primary command |
| `--on-command` | `#FFFFFF` | `#111310` | Content on primary commands |
| `--accent` | `#175CD3` | `#75A7F5` | CoQUIC identity and rare filled brand action |
| `--accent-hover` | `#124AA8` | `#91B9F7` | Hovered brand emphasis |
| `--accent-active` | `#0E397F` | `#5A93EA` | Pressed brand emphasis |
| `--accent-ink` | `#174EA6` | `#82AEFF` | Links, focus, selection, and brand line work |
| `--accent-soft` | `#EEF3FC` | `#1A2840` | Selection and CoQUIC row highlight |
| `--on-accent` | `#FFFFFF` | `#111310` | Content on a rare filled brand action |
| `--inverse-surface` | `#111310` | `#F2F3F0` | Deliberate contrast band |
| `--inverse-text` | `#F7F8F5` | `#111310` | Primary content in a contrast band |
| `--inverse-muted` | `#B8BDB5` | `#5E655B` | Secondary content in a contrast band |
| `--inverse-border` | `#343831` | `#CACEC7` | Dividers in a contrast band |
| `--inverse-accent-ink` | `#82AEFF` | `#174EA6` | Links and focus within a contrast band |
| `--inverse-focus-ring` | `rgb(130 174 255 / 54%)` | `rgb(23 78 166 / 42%)` | Focus halo within a contrast band |
| `--focus-ring` | `rgb(23 92 211 / 42%)` | `rgb(130 174 255 / 54%)` | Keyboard focus halo |
| `--scrim` | `rgb(17 19 16 / 48%)` | `rgb(0 0 0 / 70%)` | Modal and drawer backdrop |

The light canvas is only slightly off-white. Large pages should read as a calm
white field, not as a blue-gray dashboard. The dark canvas and surfaces are
neutral, not navy. Use inverse tokens for at most one deliberate editorial or
evidence band in a view; they are not a second page theme. All content inside
that band uses the inverse roles, including `--inverse-accent-ink` and
`--inverse-focus-ring` for links and keyboard focus.

Tokens may share a raw value while retaining different semantics. For example,
brand, client, and chart colors may currently match, but components consume the
token for their role rather than substituting one because its hex value is the
same.

Verified contrast anchors:

- `--command` with `--on-command`: at least 15:1 in both themes.
- `--accent` with `--on-accent`: at least 4.5:1 in both themes.
- `--text-muted` on `--surface`: at least 5.3:1 in both themes.
- `--control-border` against its theme surface: at least 3:1.
- `--inverse-accent-ink` on `--inverse-surface`: at least 7:1 in both themes.

### Protocol Roles

Protocol-role colors describe topology, never success or failure.

| Token | Light | Dark | Role |
| --- | --- | --- | --- |
| `--client` | `#175CD3` | `#82AEFF` | Client endpoint, client-originated path |
| `--client-soft` | `#EEF3FC` | `#1A2840` | Client selection or lane surface |
| `--client-ink` | `#174EA6` | `#82AEFF` | Client labels and icons |
| `--server` | `#087A83` | `#67D1D8` | Server endpoint, server-originated path |
| `--server-soft` | `#EAF6F6` | `#142D2E` | Server selection or lane surface |
| `--server-ink` | `#006A73` | `#67D1D8` | Server labels and icons |
| `--packet-neutral` | `#626960` | `#A4ABA0` | Direction-neutral packet metadata |

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
| Neutral | `#626960` | `#F4F5F2` | `#C8CCC5` | `#A4ABA0` | `#1E211D` | `#3B4039` |
| Known-peer | `#6842B8` | `#F3EEFF` | `#C7B6ED` | `#C4A8FF` | `#231B31` | `#51406B` |

Map `PASS` to success, `UNSUPPORTED` to warning, `FAIL` to danger,
`PEER BROKEN` and `NOT REPORTED` to neutral, and `KNOWN PEER ISSUE` to
known-peer.

Use warning for a degraded or incomplete state, not as decoration. Use danger
only when the task or evidence has actually failed. An expected offline or
not-yet-published state is neutral unless user action is required.

### Categorical Data

Charts that need distinct series use this ordered palette. Assign colors in
legend order and keep a series on the same token throughout a comparison
surface. Do not imply global ownership of a palette slot by a third party.

| Token | Light | Dark |
| --- | --- | --- |
| `--chart-1` | `#175CD3` | `#82AEFF` |
| `--chart-2` | `#087A83` | `#67D1D8` |
| `--chart-3` | `#7257D5` | `#B9A7FF` |
| `--chart-4` | `#B76500` | `#FFB45E` |
| `--chart-5` | `#B6427A` | `#F28BC0` |
| `--chart-6` | `#52665A` | `#B2C1B5` |

Do not use status colors as an unlabeled categorical palette. Vendor colors may
appear in official logos or a legend, but CoQUIC highlighting still uses the
accent token. Every chart also needs labels, a legend, or an accessible data
table so color is never the only key. Use chart tokens, not client or server
tokens, for categorical series even when their current values coincide.

### Color Guardrails

- Do not use the old IBM Carbon blue and gray scale as a substitute palette.
- Do not introduce page-local hex values when a semantic role exists.
- Do not create text colors by lowering opacity; use a contrast-tested token.
- Do not use accent fill as the default treatment for ordinary primary commands.
- Do not use broad gradients on page backgrounds, panels, buttons, or charts.
- The wordmark uses solid `--text-strong` and `--accent-ink`, not gradient text.
- Official third-party logos retain their approved colors and proportions.

## Typography

### Families

- Sans: `Host Grotesk`, then `ui-sans-serif`, `system-ui`, `-apple-system`,
  `BlinkMacSystemFont`, and `Segoe UI`.
- Mono: `Google Sans Code`, then `ui-monospace`, `SFMono-Regular`,
  `Cascadia Code`, `Consolas`, and `Liberation Mono`.

Both families are licensed under the SIL Open Font License 1.1 and may be
bundled and embedded with the site. Self-host published Host Grotesk and Google
Sans Code builds through the Next.js font tooling with `font-display: swap`.
Keep each upstream copyright notice and OFL text with the font assets. Use the
Google Sans Code name only to identify the font; do not imply Google affiliation
or incorporate the mark into CoQUIC identity. Do not depend on a font name that
is not shipped, and do not import runtime fonts from a third-party CDN. Use 400,
500, 600, and 700 weights only.

### Type Scale

Use fixed sizes at breakpoints. Do not scale normal UI text with viewport width.
Letter spacing is `0` throughout the site; do not use negative tracking.

| Role | Desktop | Mobile | Weight | Line Height |
| --- | --- | --- | --- | --- |
| Brand display | 64px | 40px | 500 | 1.0 |
| Brand support | 24px | 20px | 400 | 1.25 |
| Page title | 36px | 30px | 500 | 1.12 |
| Section title | 24px | 22px | 500 | 1.3 |
| Panel title | 15px | 15px | 600 | 1.35 |
| Body | 16px | 15-16px | 400 | 1.55-1.65 |
| UI label | 14px | 14px | 500 | 1.4 |
| Metadata | 12px | 12px | 500 | 1.45 |
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
| `--space-9` | 96px | Rare transition between major editorial bands |

Use values from this scale. A child gap should normally be one step smaller
than its container padding. Reserve `--space-9` for a true composition shift;
do not use it repeatedly inside operational tools.

### Radii

| Token | Value | Use |
| --- | --- | --- |
| `--radius-control` | 2px | Buttons, inputs, tabs, status cells |
| `--radius-panel` | 3px | Cards, panels, code blocks |
| `--radius-overlay` | 6px | Dialogs, popovers, drawers |

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
- Focus: 2px solid `--accent-ink` with a 2-3px offset and `--focus-ring` halo.
- Panels and cards have no shadow.
- Dropdown shadow (`--shadow-dropdown`):
  `0 12px 32px rgb(17 19 16 / 14%)` in light mode and
  `0 16px 40px rgb(0 0 0 / 48%)` in dark mode.
- Modal shadow (`--elevation-modal`):
  `0 24px 64px rgb(17 19 16 / 20%)` in light mode and
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
| `--z-skip-link` | Focused skip link | 70 |

Do not invent arbitrary z-index values. Create stacking contexts intentionally,
and render overlays in a shared overlay root when a local stacking context
would prevent this ordering from working.

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

- Focused content container: `1024px` maximum width. Use it for portals,
  task detail, ordinary evidence, and mixed text/data compositions.
- Application container: `1280px` maximum width. Use it only when a tool or
  master-detail composition benefits from the added room.
- Extra-wide evidence matrix or timeline: up to `1520px` when the viewport
  allows it; it must still have page gutters and must not become the default.
- Reading measure: `720px` maximum.
- Editorial article: `800px` maximum including code examples.
- Dialog: `640px` default and for search, `840px` for diff inspection.
- Page gutter: 12px at 320-479px, 16px at 480-767px, 20px at 768-1199px,
  and 24px at 1200px and above.

Choose the narrowest measure that lets the content work. A route may move from
reading to focused to application width as a figure or tool demands, while its
header and prose remain narrow. Recommended breakpoints are 480px, 768px,
1024px, and 1280px. Break at the point where content stops working, not merely
because a device name changes.

### Page Anatomy

Most pages use this order:

1. Skip link.
2. Global navigation.
3. Unframed page header.
4. Primary controls or summary band.
5. Main content.
6. Compact project footer where appropriate.

The page header contains an optional quiet monospace category label, one `h1`,
optional supporting copy, and page-level actions. Use a packet marker only when
it communicates identity or flow; do not prefix every page with decoration.
Actions align to the right on desktop and wrap beneath the title on mobile. Do
not put the entire page header in a card.

Operational page headers are compact. Editorial pages may use more vertical
space, but content should enter the first viewport. A blank lower viewport is
not a design goal.

### Surface Composition

- Use full-width unframed sections for page structure.
- Use panels for a genuinely bounded tool, table, chart, log, or inspector.
- Use cards only for repeated or selectable records that need independent
  boundaries; prefer a divided list when they do not.
- Do not put a card inside another card.
- Prefer dividers, background changes, or grid alignment over boxing every
  region.
- Let plain white or neutral canvas carry adjacent text and simple lists without
  adding a second surface.
- A row may be clickable without being styled as a floating card.
- Keep one dominant visual anchor per viewport: the active tool, result,
  dataset detail, matrix, or article.
- When a real trace, chart, matrix, or task is available, use it as the anchor
  before explanatory prose or decorative illustration.
- An inverse band may punctuate one meaningful transition in a view. Keep its
  content within the normal measure and concise enough to read as one idea; do
  not turn it into a repeated section treatment or a marketing CTA block.

### Responsive Behavior

- The document must never be wider than the viewport at 320px.
- Global navigation must never use horizontal scrolling.
- Editorial navigation must not appear as a long block before the article on
  mobile.
- Dense matrices, timelines, and data tables may scroll inside a labeled
  region. Keep identity columns sticky and add a subtle edge shadow or fade to
  reveal additional content.
- The initial viewport of a locally scrollable figure must retain its identity,
  axes or headers, and the primary conclusion. Scrolling reveals detail; it
  must not be required to discover what the figure means.
- Do not make horizontal swipe the only way to reach navigation or an essential
  action.
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

- Navigation row height: 56px. Its 1px divider must not shrink the row or move
  controls between states.
- Keep the logo at the left. Destinations align toward the right, followed by a
  visual separator and compact utilities such as source, search, and theme.
- Active destination uses strong text and a 2px `--accent-ink` bottom marker.
  It does not need a tinted background.
- Sticky background uses a 96 percent opaque `--surface`; backdrop blur is
  optional and must not create a glass effect.

Mobile behavior:

- Navigation row height: 56px, plus safe-area inset when required.
- Show the logo, up to three high-value icon utilities, and one familiar menu
  icon. Each target remains at least 44px.
- Keep current-page context in the page heading and mark it in the open menu;
  do not force a long section label into the navigation bar.
- Open the complete destination list in a drawer or anchored menu.
- Put remaining utilities and contact actions inside that menu.
- Do not show a clipped, scrollbar-free row of destination labels.
- Restore focus to the menu trigger when the menu closes.

Navigation disclosures close on Escape and outside pointer activation, restore
focus to their trigger, and expose expanded and current state semantically.
Navigation links keep normal document Tab order; only a true application menu
uses menu semantics and arrow-key movement. Include a visible-on-focus skip link
before the navigation.

## Components

### Buttons And Command Links

Variants:

- Primary: `--command` fill, `--on-command` content.
- Brand, exceptional: `--accent` fill, `--on-accent` content.
- Secondary: `--surface` fill, `--control-border` edge, strong text.
- Ghost: transparent, strong text, subtle hover surface.
- Danger: danger surface, danger text, danger border.
- Icon: familiar symbol with an accessible name and tooltip when needed.

Rules:

- Use links for navigation and resource retrieval; use buttons for commands that
  change state. Visual hierarchy does not change the underlying semantics.
- Use icons for familiar tool actions such as copy, download, theme, close,
  search, previous, next, and expand.
- Use icon plus text when the command is consequential or ambiguous.
- Use text buttons for clear commands such as Ask, Run, Apply, and Reset.
- Use the brand variant only when CoQUIC identity itself is part of the command.
  Do not present neutral primary and brand actions as competing choices in one
  command group.
- Keep at most one filled action in a command group. Secondary actions remain
  secondary even when several are available.
- Hover, pressed, focus, disabled, and loading states are required.
- A loading button retains its width, becomes disabled, and shows progress.
- Disabled controls use `--surface-strong`, `--text-muted`, and `--border`,
  remain legible, and expose native disabled semantics. Do not lower opacity on
  a parent element because that also weakens text and icon contrast.
- Destructive commands use explicit verbs and require confirmation or an undo
  path when the consequence is difficult to reverse.
- Hover and pressed feedback must not move surrounding layout.
- Links in prose remain visibly identifiable without relying on hover.

### Forms

- Every input has a persistent label unless its purpose is completely explicit
  from an adjacent tool label and accessible name.
- Placeholder text is an example, not a label.
- Help and error text appears below the field without shifting neighboring
  columns.
- Error messages state what failed and what the user can do next.
- Associate help and error text with its field programmatically. Announce an
  asynchronous or submit-level error through an appropriate live region.
- Use native controls where possible and appropriate `type`, `inputmode`, and
  `autocomplete` values. Never block paste.
- After an invalid submission, focus the first invalid field or a linked error
  summary when several fields failed.
- Textareas start at a purposeful height; do not fill most of the viewport
  before the user has entered content.
- Search fields include a search icon, clear action when populated, and stable
  result count or loading feedback.

### Tabs, Segmented Controls, And Filters

- Tabs switch views of the same object. Segmented controls switch compact modes.
- A tablist has one clear active item and supports arrow keys.
- Use automatic tab activation only when the panel changes immediately.
  Otherwise arrows move focus and Enter or Space activates the focused tab.
- Unframed tabs use strong text and an underline. Segmented controls use a
  neutral filled selection; use protocol color only when the mode has protocol
  meaning.
- Use a menu, select, or disclosure for more than six compact options.
- Filters show active state and result count. Reset is disabled when no filter
  is active.
- On mobile, substantial filter sets open in a drawer or disclosure instead of
  occupying the first viewport.
- Never use decorative rounded text chips as substitutes for tabs or filters.

### Cards And Panels

- Cards and panels use `--radius-panel`, a `--border` edge, and no shadow.
- A card is a repeated or selectable record with an independent boundary.
  Prefer a divided list for article indexes and simple records when that
  boundary adds no meaning.
- A panel is a single bounded working region such as a chart, table, log, or
  inspector. It is not a generic wrapper for a whole section.
- Dialogs and popovers use overlay geometry and elevation; they are not cards.
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
- When a chart scrolls locally on a narrow screen, keep its primary series and
  enough axis context visible before scrolling.
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

- Search opens as a command dialog up to 640px wide.
- Autofocus the query, group results by destination type, and keep the selected
  result visible.
- Dialogs trap focus, close on Escape, restore trigger focus, and use `--scrim`.
- Keep overlays within the viewport and safe-area insets. Their title and close
  control remain reachable while a long body scrolls inside the overlay.
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
- Pair the identity with compact, real project facts when they aid orientation;
  do not use vanity metrics.
- Use an unframed composition with one real product-state visual. Prefer a
  packet trace, current result, or protocol snapshot over a decorative diagram.
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
- Use focused width by default and expand only the table, matrix, or timeline
  that genuinely needs application or extra-wide width.
- Prefer a divided summary band, table, bar ranking, or trend over metric cards.
- Place the primary evidence before methodology or long explanatory prose.
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

- Prefer native semantic elements and controls. ARIA supplements semantics; it
  does not replace them.
- Body text contrast: at least 4.5:1.
- Large text and essential graphics: at least 3:1.
- Control boundaries and focus indicators: at least 3:1 against adjacent color.
- Touch targets: at least 44x44px on coarse pointers.
- Keyboard focus is always visible and never clipped by overflow.
- Keyboard order follows visual order. Do not use positive `tabindex` values.
- Every page has one `h1` and a sequential heading structure.
- All icon-only actions have accessible names.
- Meaningful images and figures have useful text alternatives or captions.
  Decorative images use empty alternatives and stay out of the focus order.
- Tooltips are available to keyboard users and are not the sole source of
  essential information.
- Status never relies on color alone.
- Charts provide labels and a nonvisual equivalent for important values.
- Locally scrollable charts, tables, code, and timelines are keyboard focusable
  and have an accessible name when no native focusable element provides one.
- Field and submit errors are programmatically associated and announced.
- Live updates use polite announcements and do not repeatedly steal focus.
- Dialogs and drawers manage focus correctly.
- Sticky and fixed mobile UI respects safe-area insets and does not cover the
  focused target or the end of scrollable content.
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
- Put a space between a value and unit except before `%`: `42 ms`, `14.7 KiB`,
  and `93.8%`.
- Use tabular numerals for aligned metrics.
- Show timezone or `UTC` for timestamps when ambiguity matters.
- Keep operational copy factual. Avoid marketing claims inside tools.
- Error copy names the failed operation, preserves useful technical detail, and
  offers a recovery path.
- Do not expose internal placeholder or generated filename language as the main
  user-facing title when a clearer label exists.

## Implementation And Governance

### Token And Style Ownership

- `DESIGN.md` owns design intent, semantic roles, values, components, and
  reusable layout patterns.
- `design-reference/` is a non-normative evaluation surface. It may illustrate
  the system, but it does not define route requirements or override this file.
- `site/next/app/styles/theme.css` is the permanent minimal global entry point
  for Tailwind, canonical tokens, base elements, and layout foundations.
- `site/next/app/globals.css` is a temporary compatibility manifest that imports
  legacy, shared, and feature styles while their consumers migrate.
- Delete the compatibility manifest only after there are zero legacy variable
  consumers, zero emitted selectors owned only by compatibility sheets, and all
  route and visual tests are green.
- Shared React primitives live under `site/next/src/components/ui/`.
- Feature styles may consume semantic tokens; they may not redefine the global
  brand palette.
- Temporary migration aliases are acceptable:
  - `--bg` -> `--canvas`
  - `--ink` -> `--text-strong`
  - `--soft` -> `--text`
  - `--muted` -> `--text-muted`
  - `--line` -> `--border`
  - `--primary` -> `--command`
- These mappings describe expected roles, not a blind text replacement. Audit
  each old consumer when its meaning is ambiguous.
- Remove aliases after all consumers move. Do not maintain two permanent token
  vocabularies.

### Local Exceptions

A feature-local exception belongs with its product requirements or
implementation, not in a route section here. It must satisfy all of these
conditions:

1. It represents a real semantic or interaction need not covered here.
2. It works in light, dark, mobile, keyboard, and reduced-motion contexts.
3. It does not create a second version of an existing component.
4. Its new rule is added to this document when it should be reused.

Third-party and generated reports should be normalized at their generator or
wrapper boundary. Do not scatter override hacks through unrelated page styles.

### Validation

For UI changes, validate at minimum:

- 320px, 375px, and 414px phone widths.
- 768px tablet width and an 844x390px mobile landscape viewport.
- 1024px desktop width.
- 1440px wide desktop.
- Light, dark, and initial system theme.
- Keyboard-only navigation and visible focus.
- Reduced motion and 200 percent zoom.
- Empty, loading, error, offline, long-label, and populated states.
- No global horizontal overflow.
- No known WCAG 2.2 AA failures. Automated checks have no serious or critical
  findings and are supplemented by manual review.

Use Playwright screenshots for every reusable pattern affected by a change and
add focused screenshots for any exceptional composition.

Run the repository checks appropriate to the change, including:

- `nix develop -c npm --prefix site/next run typecheck`
- `nix develop -c npm --prefix site/next run test`
- `nix develop -c npm --prefix site/next run build`
- `nix develop -c node --check site/next/public/perf-comparison.js`
- `nix develop -c node --check site/next/public/interop-results.js`
- `nix develop -c pre-commit run --all-files`
- `git diff --check`

Keep generated preview data, screenshots, build output, and downloaded state
untracked unless explicitly requested. The reviewed shared-foundation baselines
under `site/next/tests/e2e/visual-foundation.spec.ts-snapshots/` are the explicit
exception: they are tracked golden screenshots used by the deterministic
Chromium visual gate.

## Review Checklist

Before merging UI work, confirm:

- The page has one obvious primary task or result.
- Product and page identity are visible in the first viewport.
- Typography follows the scale and no font dependency is missing.
- All colors come from semantic roles and work in both themes.
- Client, server, status, and categorical data colors are not conflated.
- Primary commands, exceptional brand actions, and navigation selection remain
  visually distinct.
- Spacing, radius, icon, motion, and stacking values use the shared scales.
- Panels bound working regions, cards bound repeated or selectable records, and
  neither is used to frame a whole page section.
- Navigation and essential actions remain complete on mobile.
- Dense tables scroll locally with sticky identity and visible continuation.
- Locally scrollable evidence exposes its conclusion before scroll and remains
  named and keyboard focusable.
- An inverse band, when present, appears once and carries one concise idea.
- Inverse-band links and focus use inverse roles rather than page-theme roles.
- Loading preserves final geometry; empty and error states are informative.
- Hover, focus, pressed, disabled, loading, and selected states are implemented.
- Text does not overflow, truncate critical meaning, or become unreadably small.
- Keyboard, touch, zoom, reduced motion, and screen reader behavior are covered.
- Screenshots show no incoherent overlap, clipping, or unintended blank canvas.

## Agent Prompt Guide

When building or revising CoQUIC UI, use this direction:

> Build a packet-native CoQUIC interface with an almost-white or neutral-black
> canvas, near-monochrome application chrome, sharp hairline geometry, neutral
> primary commands, independent cobalt client and brand roles, cyan server-side
> roles, restrained sans typography, and monospace telemetry. Choose the
> narrowest content measure that works and let real protocol evidence be the
> main visual event. Preserve complete light, dark, desktop, mobile, keyboard,
> and loading states. Do not copy another developer-tool identity, introduce
> decorative effects, nest cards, or trade readability for density.
