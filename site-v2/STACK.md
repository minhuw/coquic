# Site V2 Technology Stack

Status: approved foundation

Last reviewed: 2026-07-20

This document fixes the implementation foundation without prescribing page
markup. PRODUCT.md, FUNCTIONAL.md, DATA.md, QUALITY.md, and DESIGN.md remain the
sources of truth for product behavior and presentation.

## Core

| Concern               | Choice                                                         |
| --------------------- | -------------------------------------------------------------- |
| Application framework | Next.js 16 App Router                                          |
| UI runtime            | React 19                                                       |
| Language              | TypeScript in strict mode                                      |
| Styling engine        | Tailwind CSS 4                                                 |
| Component source      | shadcn/ui through the shadcn CLI                               |
| Rich text             | shadcn/typeset, committed as source-owned CSS                  |
| Accessible primitives | The primitive selected by the installed shadcn component       |
| Icons                 | Lucide React                                                   |
| Motion                | Motion for React, used within DESIGN.md limits                 |
| Technical data font   | Google Sans Code Variable                                      |
| Boundary validation   | JSON Schema plus generated or hand-maintained typed validators |
| Browser verification  | Playwright                                                     |

## Tailwind CSS

Tailwind is the implementation vocabulary, not the source of visual decisions.
DESIGN.md owns the palette, typography, spacing, radius, depth, and responsive
rules.

The initial app scaffold MUST:

1. import Tailwind with `@import "tailwindcss"`;
2. expose every DESIGN.md semantic role as a CSS custom property;
3. map those properties into Tailwind 4 `@theme` tokens;
4. support the DESIGN.md dark-role remapping without changing component markup;
5. use semantic utilities such as `bg-canvas`, `text-ink`, and
   `border-line`.

Component code MUST NOT introduce raw hex colors or arbitrary typography,
radius, shadow, or spacing values. A genuine new token requires a DESIGN.md
change. Arbitrary values remain acceptable for data-driven chart coordinates,
measured dimensions, and values that cannot be known at build time.

Complex plots, matrices, and simulations MAY use authored SVG/CSS where utility
classes would obscure the analytical geometry.

## shadcn/ui

shadcn/ui is source code owned by this application, not a visual theme or
runtime component package.

- Add only components needed by an implemented workflow.
- Generate components through `npm run shadcn -- add <component>`.
- Keep generated components under `components/ui/`.
- Retain the component's semantic behavior, keyboard model, focus management,
  and accessibility attributes.
- Replace generated visual tokens with CoQUIC semantic tokens immediately.
- Do not import demo blocks, page templates, default card composition, default
  typography, or decorative examples.
- Shared variants use Class Variance Authority and `tailwind-merge`.
- Page files consume shared variants rather than restating long class lists.

The checked-in `components.json` uses CSS variables, the neutral New York
source style, Lucide icons, React Server Components, and the project aliases.
Its generated appearance is never authoritative; DESIGN.md is.

## shadcn/typeset

shadcn/typeset is not the unrelated npm package named `typeset`. The official
distribution is one `typeset.css` file copied from the shadcn Typeset builder
or official source and committed into this repository.

The first application scaffold MUST:

1. generate or copy the current official `typeset.css`;
2. place it beside the application's global Tailwind stylesheet;
3. import it after `@import "tailwindcss"`;
4. map its font, foreground, muted, border, radius, and focus variables to
   DESIGN.md tokens;
5. commit the file so builds never depend on a remote stylesheet.

Required presets:

| Preset            | Use                                        | Size | Leading | Flow   |
| ----------------- | ------------------------------------------ | ---- | ------- | ------ |
| `typeset-docs`    | Documentation and reference prose          | 16px | 1.70    | 1.35em |
| `typeset-journal` | Long-form project journal                  | 17px | 1.75    | 1.50em |
| `typeset-answer`  | QA answers and rendered transcript content | 16px | 1.60    | 1.00em |

Typeset is allowed for authored HTML and sanitized rendered Markdown. It is not
used for navigation, page openings, forms, filters, charts, evidence rankings,
matrices, status lines, metadata, or application controls. Interactive elements
embedded inside prose use `not-typeset` or `data-not-typeset`.

Wide prose tables use the Typeset `typeset-scroll` wrapper. Typeset does not
own reading width; the route layout retains the measures defined in DESIGN.md.

## State and Data

- Prefer React Server Components for validated snapshot and content loading.
- Put filter, mode, selected evidence, and pagination state in the URL when it
  should survive refresh or be shareable.
- Keep ephemeral interaction state local.
- Do not introduce a global state library until a verified cross-route need
  exists.
- Validate payloads at the server or worker boundary before rendering.
- Keep canonical values unformatted until the presentation layer.
- Run the Workbench WASM engine in a Web Worker behind WORKBENCH.md.

## Visualization

The charting implementation remains open until the first evidence page is
planned. It MUST support DESIGN.md's synchronized exact-evidence pattern,
keyboard and touch inspection, semantic equivalents, honest axes, and print.

Do not add a dashboard chart package merely to produce a first prototype.
Evaluate Visx/D3, Observable Plot, or purpose-built SVG against the actual
Performance and history requirements before fixing this dependency.

## Content

Documentation and Journal sources SHOULD use validated MDX or Markdown catalogs.
Rendering must sanitize untrusted Markdown and transcript content. Typeset owns
rich-text rhythm after sanitization; it does not own content loading or safety.

## Testing

The implementation baseline will include:

- TypeScript checking;
- schema and example validation;
- focused unit tests for normalization and formatting;
- Playwright route, interaction, keyboard, responsive, and overflow tests;
- automated accessibility checks;
- screenshot review at desktop and compact viewports;
- reduced-motion and dark-theme coverage.

No page is complete because it renders. It is complete when its contract states
and evidence interactions are verified.
