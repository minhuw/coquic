---
version: 1.0.0
status: approved
name: coquic-observatory
description: Calm scientific futurism for an inspectable QUIC and HTTP/3 research instrument. Exact evidence, complete rankings, measured provenance, and working technical artifacts carry the visual identity.

colors:
  canvas: "#F6F8FA"
  surface: "#FFFFFF"
  ink: "#15191D"
  text-muted: "#5F6871"
  text-faint: "#7B8790"
  line: "#D5DBE1"
  line-strong: "#929DA8"
  accent: "#1457FF"
  accent-soft: "#E8EFFF"
  positive: "#16825D"
  warning: "#9A5B00"
  negative: "#C94138"
  unavailable: "#6F7780"
  contrast-field: "#0A0C0E"
  contrast-ink: "#F6F8FA"

darkColors:
  canvas: "#11161B"
  surface: "#192027"
  ink: "#F3F6F8"
  text-muted: "#B0BAC3"
  text-faint: "#87939E"
  line: "#35404A"
  line-strong: "#6B7884"
  accent: "#78A0FF"
  accent-soft: "#1C315F"
  positive: "#45C59A"
  warning: "#F0AD55"
  negative: "#FF7168"
  unavailable: "#98A2AC"
  contrast-field: "#F3F5F7"
  contrast-ink: "#111519"

dataColors:
  blue: "#1457FF"
  teal: "#00A491"
  orange: "#E78B27"
  violet: "#8371ED"
  rose: "#DF5C70"
  green: "#638F45"
  umber: "#A87B57"
  cyan: "#25A9D6"

typography:
  display:
    fontFamily: systemSans
    fontSize: 44px
    compactFontSize: 32px
    fontWeight: 500
    lineHeight: 1.05
    letterSpacing: 0
  section:
    fontFamily: systemSans
    fontSize: 24px
    compactFontSize: 20px
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: 0
  subsection:
    fontFamily: systemSans
    fontSize: 20px
    compactFontSize: 18px
    fontWeight: 600
    lineHeight: 1.30
    letterSpacing: 0
  lead:
    fontFamily: systemSans
    fontSize: 19px
    compactFontSize: 17px
    fontWeight: 400
    lineHeight: 1.50
    letterSpacing: 0
  body:
    fontFamily: systemSans
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: 0
  ui:
    fontFamily: systemSans
    fontSize: 14px
    fontWeight: 500
    lineHeight: 1.35
    letterSpacing: 0
  data:
    fontFamily: googleSansCode
    fontSize: 13px
    compactFontSize: 12px
    fontWeight: 500
    lineHeight: 1.35
    letterSpacing: 0
  meta:
    fontFamily: systemSans
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.40
    letterSpacing: 0
  micro:
    fontFamily: systemSans
    fontSize: 11px
    fontWeight: 500
    lineHeight: 1.35
    letterSpacing: 0

rounded:
  none: 0px
  control: 4px
  layer: 8px
  full: 9999px

spacing:
  1: 4px
  2: 8px
  3: 12px
  4: 16px
  5: 24px
  6: 32px
  7: 48px
  8: 64px
  9: 96px

layout:
  headerHeight: 64px
  evidenceMaxWidth: 1240px
  readingMaxWidth: 760px
  docsMaxWidth: 1180px
  dialogMaxWidth: 620px
  evidenceDialogMaxWidth: 960px
  desktopGutter: 48px
  tabletGutter: 32px
  compactGutter: 16px

motion:
  fast: 120ms
  layer: 160ms
  route: 280ms
  figure: 400ms

components:
  top-navigation:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    typography: "{typography.ui}"
    height: "{layout.headerHeight}"
    activeIndicator: "2px solid {colors.accent}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canvas}"
    borderColor: "{colors.ink}"
    typography: "{typography.ui}"
    rounded: "{rounded.control}"
    height: 40px
  button-secondary:
    backgroundColor: transparent
    textColor: "{colors.ink}"
    borderColor: "{colors.line-strong}"
    typography: "{typography.ui}"
    rounded: "{rounded.control}"
    height: 40px
  button-tertiary:
    backgroundColor: transparent
    textColor: "{colors.accent}"
    typography: "{typography.ui}"
    rounded: "{rounded.none}"
  text-input:
    backgroundColor: transparent
    textColor: "{colors.ink}"
    borderColor: "{colors.line-strong}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
  status:
    backgroundColor: transparent
    textColor: "{colors.ink}"
    typography: "{typography.meta}"
    rounded: "{rounded.none}"
  selected-evidence:
    backgroundColor: "{colors.accent-soft}"
    textColor: "{colors.ink}"
    borderColor: "{colors.accent}"
    rounded: "{rounded.none}"
  contrast-field:
    backgroundColor: "{colors.contrast-field}"
    textColor: "{colors.contrast-ink}"
    rounded: "{rounded.none}"
  evidence-row:
    backgroundColor: transparent
    textColor: "{colors.ink}"
    borderColor: "{colors.line}"
    rounded: "{rounded.none}"
  dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    borderColor: "{colors.line}"
    rounded: "{rounded.layer}"
  footer:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text-muted}"
    typography: "{typography.meta}"
    borderColor: "{colors.line}"
---

# CoQUIC Observatory Design System

This is the normative visual contract for Site V2. Product behavior lives in
PRODUCT.md and FUNCTIONAL.md; data semantics live in DATA.md; quality
requirements live in QUALITY.md. If presentation conflicts with this file, this
file wins unless accessibility or factual integrity requires otherwise.

## Overview

CoQUIC Observatory is an instrument for observing an experimental QUIC and
HTTP/3 implementation. Its material is measured evidence: packets, benchmark
runs, resource utilization, interoperability outcomes, source coverage, RFC
requirements, transcripts, and repository automation.

The primary audience is a technically literate researcher, implementer, or
contributor. Curious readers are welcome, but evidence must not be diluted into
marketing claims.

The design has one job:

> Make complex technical evidence easy to scan, compare, verify, and revisit
> without overstating what the evidence proves.

**Key characteristics:**

- Calm scientific futurism rather than a generic dashboard.
- A quiet top-navigation shell and expressive, inspectable evidence.
- Exact values, complete fields, ranking rules, method, and provenance.
- System sans for interface and prose; Google Sans Code only for technical data.
- Optical-gray light canvas with a supported dark theme.
- Sharp black/white polarity and sparse flight-blue interaction.
- Few cards, few rounded surfaces, no decorative panels, and no nested cards.
- One working technical artifact may carry the character of a route.

## Visual Theme and Atmosphere

The interface feels like a well-made measurement instrument: quiet at rest,
precise under inspection, and dense only where evidence requires density.
Exact numbers, ordered observations, provenance, and changes over time form the
composition.

Futurism comes from reduction and behavior, not science-fiction decoration.
Use strong polarity, decisive scale changes, purposeful spatial pauses, direct
manipulation, and immediate feedback. A live plot, packet trace, matrix, or
simulation is more futuristic than an illustration of one.

Scientific character comes from measurement discipline. Do not manufacture it
with faux terminals, decorative grids, scan lines, packet rain, tiny monospace
labels, or laboratory imagery.

### Design principles

1. **Evidence before framing.** Show the measurement before interpretation.
2. **Precision without intimidation.** Use plain language around exact data.
3. **Structure carries meaning.** Alignment, rules, columns, and spacing encode
   real relationships.
4. **Quiet shell, expressive data.** Neutral chrome surrounds purposeful data.
5. **Future through function.** Working artifacts carry the atmosphere.
6. **Complete means complete.** An All control shows every matching result.
7. **One scale, one rhythm.** Never invent page-local typography or spacing.

### Signature pattern

The cross-route signature is the **synchronized evidence figure**:

1. one literal analytical visualization;
2. one complete exact-value ranking, matrix, or table;
3. shared selection between visual and exact evidence;
4. provenance and method adjacent to the evidence.

This pattern is most visible on Performance and should inform Interop, Coverage,
RFC traceability, Workbench, and Steward.

One route may use a single **contrast field** for its primary working artifact.
It is near-black in light mode and near-white in dark mode. It must contain real
data or a working tool, extend confidently across the evidence width, and remain
quiet until used. It is never a slogan or decorative hero.

### Reference calibration

| Reference             | Learn from                                                                | Do not copy                                            |
| --------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------ |
| CoQUIC, 2026-07-01    | Complete evidence, exact values, configuration identity, provenance       | Legacy layout limitations                              |
| DeepSWE v1.1          | Dominant figure, synchronized ranking, calm typography, immediate method  | Branding, copy, chart composition, palette             |
| Cloudflare Speed Test | Measurement cadence and confidence through clarity                        | Consumer theatrics and oversized scores                |
| OpenAI                | Typographic restraint and disciplined whitespace                          | Marketing scale on operational pages                   |
| xAI and xAI Docs      | Monochrome polarity, spatial pauses, direct artifacts, concise navigation | Branding, proprietary type, pills, marketing emptiness |

## Colors

The YAML tokens are canonical. Components consume semantic names rather than
copying hex values.

### Light theme

| Token                   | Value   | Role                                       |
| ----------------------- | ------- | ------------------------------------------ |
| {colors.canvas}         | #F6F8FA | Page background                            |
| {colors.surface}        | #FFFFFF | Menus, dialogs, bounded tools              |
| {colors.ink}            | #15191D | Primary text and strongest rules           |
| {colors.text-muted}     | #5F6871 | Secondary copy and labels                  |
| {colors.text-faint}     | #7B8790 | Nonessential metadata                      |
| {colors.line}           | #D5DBE1 | Row and section separation                 |
| {colors.line-strong}    | #929DA8 | Table heads and plot boundaries            |
| {colors.accent}         | #1457FF | Selection, links, active navigation, focus |
| {colors.accent-soft}    | #E8EFFF | Selected evidence surface                  |
| {colors.positive}       | #16825D | Verified success                           |
| {colors.warning}        | #9A5B00 | Partial, delayed, or known limitation      |
| {colors.negative}       | #C94138 | Failure and destructive consequence        |
| {colors.unavailable}    | #6F7780 | Unavailable or not reported                |
| {colors.contrast-field} | #0A0C0E | Primary instrument plane                   |
| {colors.contrast-ink}   | #F6F8FA | Content on the instrument plane            |

### Dark theme

The darkColors block remaps the same roles. Dark mode is not another design
language. Structure, density, hierarchy, and geometry remain unchanged.

### Data color rules

- Use dataColors for categorical series, with no more than eight hues.
- Beyond eight series, add marker shape, line style, labels, or selection.
- Never encode pass/fail with categorical series colors.
- Never use green and red without text or symbolic distinction.
- Exact values must remain understandable without color.
- Gradients are not part of the core interface palette.
- At most one contrast field may appear in a viewport.
- Do not place routine prose or forms on dark planes in light mode.

## Typography

### Font families

| Role                | Family                                                                                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Interface and prose | ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif |
| Data and code       | Google Sans Code Variable, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace                              |

On Apple platforms, interface text resolves to SF Pro. On Windows it resolves
to Segoe UI. Linux may resolve to DejaVu Sans. Do not claim a platform face is
bundled when it is not.

Use system sans for navigation, headings, prose, controls, labels, menus,
dialogs, errors, and empty states. Use Google Sans Code only for exact
measurements, units, timestamps, versions, hashes, IDs, paths, code, and packet
data. Monospace does not mean technical.

Components use --font-sans or --font-mono. No component declares a raw stack.

### Hierarchy

| Token                   | Desktop | Compact | Weight | Line height | Use                      |
| ----------------------- | ------- | ------- | ------ | ----------- | ------------------------ |
| {typography.display}    | 44px    | 32px    | 500    | 1.05        | Operational page title   |
| {typography.section}    | 24px    | 20px    | 600    | 1.25        | Major evidence section   |
| {typography.subsection} | 20px    | 18px    | 600    | 1.30        | Tool title               |
| {typography.lead}       | 19px    | 17px    | 400    | 1.50        | Page purpose, once       |
| {typography.body}       | 16px    | 16px    | 400    | 1.55        | Reading and explanation  |
| {typography.ui}         | 14px    | 14px    | 500    | 1.35        | Controls and navigation  |
| {typography.data}       | 13px    | 12px    | 500    | 1.35        | Exact values             |
| {typography.meta}       | 12px    | 12px    | 400    | 1.40        | Provenance               |
| {typography.micro}      | 11px    | 11px    | 500    | 1.35        | Axes and compact columns |

### Typography rules

- Visible interface text is never smaller than 11px.
- Body copy is never smaller than 16px.
- Use weights 400, 500, and 600.
- Letter spacing is always 0.
- Do not scale font size with viewport width.
- Sentence case is default. Uppercase is reserved for QUIC, HTTP/3, CPU, CSV,
  RFC, and other established abbreviations.
- Measurements use tabular numerals.
- Units remain subordinate but legible.
- Do not use text shadows or synthetic font widths.

## Layout

### Global shell

- Use a top navigation bar, never a permanent global sidebar.
- Desktop header height is {layout.headerHeight}.
- Keep the product name visible.
- Group secondary evidence routes in one clearly labeled menu.
- Search, snapshot state, repository, and theme are secondary actions.
- Below 781px, use a right-side drawer with identical navigation order.

### Content widths and gutters

| Context                             | Maximum width                   |
| ----------------------------------- | ------------------------------- |
| Evidence and operational pages      | {layout.evidenceMaxWidth}       |
| Documentation article               | {layout.readingMaxWidth}        |
| Documentation with local navigation | {layout.docsMaxWidth}           |
| Dialog                              | {layout.dialogMaxWidth}         |
| Evidence detail dialog              | {layout.evidenceDialogMaxWidth} |

Use 48px desktop gutters, 32px tablet gutters, and 16px compact gutters.
Retain maximum widths on very wide screens instead of stretching plots.

### Page opening

Operational and evidence pages use this sequence:

```text
Page title
One-sentence purpose

status / provenance                         real actions, when present
---------------------------------------------------------------------
primary modes, controls, or evidence
```

- The first analytical content appears within a 1440x1000 first viewport.
- An eyebrow appears only when route context is genuinely necessary.
- Provenance is one compact, left-aligned line below the purpose.
- Metadata never occupies an isolated balancing column.
- Right alignment is reserved for real actions.
- Operational pages never use marketing heroes.

### Spatial cadence

- **Compact:** navigation, filters, table rows, and metadata.
- **Focused:** plots, matrices, simulations, and reading passages.
- **Pause:** 48-96px between changes in evidence type or argument.

Whitespace clarifies a transition or focus. It must not fill a region, inflate
a sparse page, or push primary evidence below the first viewport.

### Grid rules

- Use CSS Grid for aligned evidence and Flexbox for short control rows.
- Text and chart tracks use minmax(0, 1fr).
- Grid children use min-width: 0 where content could force overflow.
- Stable boards, plots, matrices, toolbars, and counters have explicit sizes.
- Sidebars exist only for local document navigation, useful persistent filters,
  or inspectors.

## Elevation and Depth

| Level         | Treatment                                    | Use                             |
| ------------- | -------------------------------------------- | ------------------------------- |
| 0 - Canvas    | No shadow; surface polarity only             | Page and full-width sections    |
| 1 - Rule      | 1px line or line-strong                      | Rows, section boundaries, plots |
| 2 - Selected  | accent-soft plus 2px accent edge             | Selected evidence               |
| 3 - Temporary | Surface plus 0 18px 48px rgb(21 25 29 / 14%) | Menus and dialogs               |

Canvas and surface colors carry hierarchy. Permanent page content has no
shadow. Do not use glass, glow, inset decoration, gradient orbs, bokeh, or
spotlight effects.

## Shapes

| Token             | Value  | Use                                        |
| ----------------- | ------ | ------------------------------------------ |
| {rounded.none}    | 0px    | Evidence rows, sections, selected strips   |
| {rounded.control} | 4px    | Buttons, inputs, mode controls             |
| {rounded.layer}   | 8px    | Menus, dialogs, independent repeated items |
| {rounded.full}    | 9999px | Status dots and circular global controls   |

Rounded geometry communicates bounded interaction, not friendliness. Ordinary
labels, tabs, filters, and status text are not pills.

## Components

### Navigation

- Labels use {typography.ui}.
- Active state is accent text plus a 2px underline.
- Dropdown group labels use system sans at 12px/500 in sentence case.
- Menus use surface, layer radius, one border, and one shadow.
- Mobile navigation preserves desktop grouping and order.

### Buttons

- Primary: solid ink with inverse text.
- Secondary: transparent or surface with a 1px strong rule.
- Tertiary: text or icon only.
- Destructive: negative color and explicit wording.
- Default height is 40px; coarse-pointer targets are at least 44px.
- Use Lucide for familiar commands.
- Icon-only controls need an accessible name and tooltip.
- Disabled and busy states remain visible and announced.

### Inputs and selectors

- Labels sit above controls at 12px in muted sans.
- Compact evidence filters use a quiet bottom rule.
- Primary form inputs use a full 1px boundary.
- Focus is a visible 2px accent outline with at least 2px offset.
- Placeholder text supplements a label; it never replaces one.
- Search uses a search icon and offers a clear action when populated.

### Tabs and modes

- Tabs switch views of one object.
- Segmented modes switch the measurement itself.
- Active tabs use an accent underline.
- A mode selector may use a filled dark active state when it defines the whole
  evidence field.
- Dimensions remain stable when state or labels change.

### Status

Status is text plus a symbol; color is secondary. It is not a badge by default.
Positive, warning, negative, partial, delayed, unavailable, and not-reported
states remain distinct.

### Tables, rankings, and matrices

- Headers align with their columns.
- Text aligns left; numbers align right at the decimal edge where practical.
- Exact values, versions, and identifiers use Google Sans Code.
- Use horizontal rules. Vertical rules exist only when a matrix needs them.
- Selection uses accent-soft plus an accent edge or non-color marker.
- Ranking bars encode relative magnitude only; exact values remain visible.
- Filtering preserves original rank numbers.
- Wide fields scroll locally only when a compact row cannot preserve evidence.

### Selected evidence strip

Place an unrounded, lightly tinted strip between figure and exact ranking. It
contains one identity and up to four measurements. It is not a card and updates
synchronously with chart or row selection.

### Contrast field

- Contains a real plot, packet view, code sample, matrix, or simulation.
- Uses 0-4px radius and low-contrast internal rules.
- Never contains a slogan, routine prose, or decorative telemetry.
- Exact evidence remains accessible outside the field.
- No fake window controls, corner brackets, glow, or ornamental readouts.

### Cards and bounded surfaces

Cards are reserved for independent repeated items, dialogs, and genuinely
bounded tools. Page sections are unframed. Never nest cards or turn every
section into a floating rounded panel.

### Dialogs and popovers

- Use one surface, one title, and one explicit close action.
- Restore focus to the trigger on close.
- Constrain height and scroll the dialog body.
- Use popovers only for short contextual inspection.
- Full run, flamegraph, packet, or artifact detail uses a dialog or route.

### Empty, partial, and error states

- Empty states explain which action or filter can produce evidence.
- Errors identify the resource and a concrete recovery.
- Partial and unavailable are not styled as failure when distinction matters.
- Never fabricate zero values for unavailable data.
- Copy is literal, calm, and non-anthropomorphic.

## Data Visualization

Every analytical figure has:

1. a literal title naming compared measures;
2. one interpretive sentence;
3. the plot;
4. unit-bearing axes;
5. an exact semantic table, ranking, matrix, or list;
6. method and provenance.

### Axes and marks

- Axis labels use {typography.micro} in system sans.
- Exact tooltip values use {typography.data}.
- Put units on axes or column headers.
- Prefer horizontal grid lines.
- Document non-zero baselines when they could distort magnitude.
- Use at most five major ticks on compact plots.
- Points remain visible at 1x and 200% zoom.
- Selected marks use outline or shape in addition to color.
- Hover never provides the only exact value or explanation.

### Rankings and history

- State the ranking rule directly above the field.
- State inclusion and exclusion rules in the method note.
- Show the total number of matching configurations.
- Synchronize chart and ranking selection.
- Never present a featured subset as the complete field.
- Keep history chronological with stable series identities.
- Missing observations render as gaps, never zero.
- A series selector may reduce the plot, but not the semantic table.
- Keep generation time, environment, revision, and method near history.

## Icons and Technical Media

- Use Lucide icons at stroke width 1.8.
- Icons support commands and states; they do not decorate headings.
- Default icon size is 16px, dense table size 14px, emphasized size 20px.
- Stock photography and abstract protocol illustration are unnecessary.
- Prefer factual diagrams, packet captures, flamegraphs, screenshots, and plots.

## Motion

| Event               | Duration        | Treatment                           |
| ------------------- | --------------- | ----------------------------------- |
| Selection           | {motion.fast}   | Color, outline, or bar transition   |
| Menu or dialog      | {motion.layer}  | Opacity and small translation       |
| Route arrival       | {motion.route}  | Fade plus no more than 8px movement |
| Figure introduction | {motion.figure} | One coordinated reveal, optional    |

- No looping ambient animation on evidence pages.
- Do not animate dense table dimensions.
- Prefer one orchestrated reveal over staggered decoration.
- Interaction never waits for animation.
- Reduced-motion preferences remove nonessential animation.

## Responsive Behavior

| Range            | Behavior                                                    |
| ---------------- | ----------------------------------------------------------- |
| 1180px and above | Full top navigation and wide evidence columns               |
| 781-1179px       | Condensed header, 32px gutters, selective column collapse   |
| 480-780px        | Mobile header, drawer, 16px gutters, single-column sections |
| 320-479px        | Compact controls and purpose-built evidence rows            |

- Preserve navigation order in the mobile drawer.
- Scale page titles from 44px to 32px and sections from 24px to 20px.
- Wrap provenance naturally; do not create a metadata sidebar.
- Mode selectors scroll locally instead of shrinking labels.
- Control rows become two columns, then one.
- Rankings retain rank, identity, value, and magnitude in compact rows.
- Secondary measures may move into selected detail but remain reachable.
- Charts retain explicit height.
- The document never scrolls horizontally.
- At 200% zoom, every control and evidence object remains reachable.

## Accessibility and Input

- Meet WCAG 2.2 AA.
- Keyboard focus is a visible 2px accent outline.
- Color is never the only state or selection indicator.
- Charts have semantic table or list equivalents.
- Data points are keyboard- and touch-reachable.
- Dialogs trap focus and restore it on close.
- Use established semantics for menus, tabs, disclosures, sliders, and selects.
- Coarse-pointer targets are at least 44x44px.
- Forced-colors mode retains borders, focus, and selection.

## Content and Interface Language

- Use sentence case and active voice.
- Name controls by result: Download CSV, Reset filters, Inspect run.
- Keep action names consistent through completion and failure.
- Prefer literal measurement names over clever headings.
- A label labels, an example demonstrates, and a description explains.
- State ranking rule, unit, time, and provenance visibly.
- Never imply CoQUIC is production-ready or claim unmeasured compatibility.
- Empty and error copy directs the next action without mood or apology.

## Route Composition

### Home

Open with a split thesis: established CoQUIC mark, name, and project slogan on
the left; the latest exact Steward daily summary on the right. The summary may
use the contrast field and groups daily model work, repository output, and
reliability evidence without metric cards. Follow with a clear route index.

### Ask

Treat the question composer as the primary tool. Compare direct and grounded
answers with visible evidence provenance.

### Documentation and Journal

Optimize for reading near 70 characters per line. Local document navigation may
use a sidebar. Content comes first on compact screens.

### Dataset

Use a search-and-inspect workspace. Keep filters compact and result count next
to search. Preserve list/detail context on compact screens.

### Workbench

Use a stable simulation field with explicit controls and inspector views. Do
not add decorative framing around the simulation.

### Performance

Use modes, compact filters, analytical plot, selected evidence strip, complete
ranking, visible rule, method, and provenance. Keep selection synchronized.

### Interop

Make the directional matrix primary. Aggregate counts orient but never replace
cell evidence. Preserve participant role and direction in detail.

### Coverage and RFC Traceability

Lead with exact covered/total or mapped/unmapped counts and provenance.
Generated reports are primary artifacts, not decorative embeds.

### Steward

Use a quiet operational monitor with explicit freshness, conclusion, queues,
signals, audit, and publication evidence. Do not imitate a command center or
expose mutation controls. Metadata never occupies a balancing column.

## Do and Don't

### Do

- Let exact evidence occupy meaningful space.
- Keep controls beside the evidence they affect.
- Use one dominant analytical relationship per view.
- Let a real technical artifact carry the futuristic character.
- Pair every visualization with exact values.
- Preserve complete fields and explain ranking rules.
- Use whitespace to separate conceptual stages.
- Test light, dark, compact, keyboard, reduced motion, forced colors, and 200%
  zoom.

### Don't

- Don't use oversized editorial heroes on operational pages.
- Don't replace aligned evidence with summary-card grids.
- Don't place cards inside cards or make every section float.
- Don't use pills for ordinary labels, tabs, filters, or status.
- Don't use monospace as generic technical atmosphere.
- Don't use tiny uppercase eyebrows or randomly placed metadata.
- Don't use purple gradients, warm-cream palettes, acid-on-black, or broadsheet
  styling as a default.
- Don't use decorative sidebars, faux terminal chrome, blueprint grids, scan
  lines, packet rain, or scientific clip art.
- Don't equate futuristic with neon, glass, glow, black pages, or tiny labels.
- Don't copy xAI typography, marks, CTA shapes, or marketing whitespace.
- Don't invent statistics, featured rankings, or implied conclusions.
- Don't hide incomplete evidence behind zero values.

## Agent Implementation Guide

### Stack application

- Implement visual tokens through Tailwind CSS 4 semantic theme utilities.
- Use source-owned shadcn/ui components for behavior, then retokenize them.
- Use shadcn/typeset only for authored prose and sanitized rendered Markdown.
- Typeset presets and operational boundaries are defined in STACK.md.
- Default shadcn styling never overrides this design contract.

Before changing a page:

1. Read this file, PRODUCT.md, the route section in FUNCTIONAL.md, and QUALITY.md.
2. Name the primary user job and primary evidence object.
3. Select the route composition pattern above.
4. Resolve color, type, spacing, shape, and component decisions from YAML.
5. Identify loading, ready, empty, partial, unavailable, and malformed states.
6. Build desktop and compact layouts together.
7. Verify keyboard, focus restoration, overflow, dark theme, reduced motion,
   forced colors, 200% zoom, and exact-value access.

### Quick prompt

> Build a calm scientific-futurist evidence interface for CoQUIC Observatory.
> Use system sans for interface and prose, Google Sans Code only for exact data,
> an optical-gray canvas, sharp black/white polarity, sparse flight-blue
> interaction, restrained rules, compact controls adjacent to data, one primary
> working artifact, and a complete exact-value table or list. Futurism must come
> from the artifact and direct manipulation. Avoid marketing heroes, card grids,
> pills, decorative technical motifs, metadata filler, and hidden subsets.

## Review Ledger

### Approved foundation

- Calm scientific benchmark character.
- Top navigation and 64px desktop shell.
- System sans for interface and prose.
- Google Sans Code for exact technical data.
- DeepSWE-quality evidence hierarchy without copying its identity.
- Futurism grounded in working instruments.
- Complete results, exact values, visible rules, provenance, and method.
- Restrained borders, surfaces, rounding, color, and motion.

### Approved implementation choices

- Optical-gray light canvas with supported dark theme.
- Flight blue as the interaction accent.
- Synchronized figure plus exact evidence as the cross-route signature.
- One optional contrast field for a primary artifact.
- 1240px evidence width and the token scales in this file.
- Metadata belongs in provenance, never a balancing column.
- The established Q-shaped CoQUIC mark is the product identity.

### Open for review

- Final categorical palette after color-vision testing.
- Whether Documentation and Journal need a distinct reading mode.
- The boundary between selected strips, dialogs, and detail routes.

### Change protocol

1. Update YAML tokens and prose together.
2. Add a dated entry to DECISIONS.md for cross-route changes.
3. Update shared components instead of adding route-local overrides.
4. Capture desktop and compact screenshots.
5. Run type checking, production build, contract validation, and visual tests.
