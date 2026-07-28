# M-16: Aero Fiduciary visual direction study

    VISUAL DIRECTION STUDY: READY FOR REVIEW

Three visual directions for one Mordant screen. This chooses a level of aesthetic risk. It is not
the final UI, not a navigation decision, and not an architecture.

    /design-lab/aero-fiduciary

One canonical screen, **deal detail with a conflict revealed and the cure window open**, rendered
three ways from the same data. Switching variants changes only the design.

`/deal-room` is untouched.

## The data, and what it is not

Face value 110 000, advance 100 000, bond 10 000, two holders at 50 000 units each, 100 000 MINV01
in adapter custody. These are the M-13 fork rehearsal figures, and the screen says so in its first
line: **fork rehearsal data, not a live deployment**.

One decision worth flagging. At six decimals, 110 000 atomic units is 0.11 aUSDC. Leading with
"0.11" would have made the screen unreadable and would have misrepresented what the rehearsal moved,
so the integer leads and the decimal equivalent sits underneath. If the product later runs at
realistic invoice scale, this reverses.

No button sends a transaction. The primary action is disabled and labelled as a prototype surface.

## The three variants

### 1. Aero Restrained

**Intention.** Find out how little Aero is enough. Light and depth live in the background and the
separators; the data leads.

**Composition.** Two-column decision band, then a full-width figure row divided by rules, then a
horizontal recourse line, then tables. No atmosphere layer at all.

**Palette.** Neutral cool greys, white planes, four semantic hues at high contrast.
**Typography.** Manrope for text, Space Mono for every figure, tabular throughout.
**Surfaces.** Opaque. Shadows are 1 to 4 px. No glass.
**Status language.** Word plus glyph plus colour, never colour alone.
**Evidence.** Collapsed to one line, expandable.
**Motion.** Transitions only, 140 ms.

**Strengths.** Reads as financial software immediately. Cheapest to extend. Nothing to defend in a
procurement review.
**Weaknesses.** Indistinguishable from a dozen competitors with the logo removed.
**Credibility risk.** Low.
**Usability risk.** Low.
**Differentiation.** Poor. This is the control, not a candidate.
**Cost to extend.** Low. Tokens map onto any table-heavy screen.

### 2. Aero Fiduciary

**Intention.** A lit environment around a precise core. Atmosphere between the planes, glass only
where something is sealed or revealed.

**Composition.** Same skeleton as Restrained, but the planes float in a soft field and the custody
vessel gains depth.

**Palette.** Aqua and pale green atmosphere behind near-white planes; the same four semantic hues,
darkened to hold contrast on a lighter ground.
**Surfaces.** `backdrop-filter` on the state plane and the vessel. Elsewhere opaque.
**Motion.** Transitions only. The atmosphere is static.

**Strengths.** Recognisable without being loud. Glass is load-bearing rather than decorative.
**Weaknesses.** Sits between the other two, which is also its risk: it may read as Restrained with a
gradient rather than as its own direction.
**Credibility risk.** Low to moderate. The atmosphere is calm enough for an institutional audience.
**Usability risk.** Low. Text never sits on texture.
**Differentiation.** Moderate.
**Cost to extend.** Moderate. Every new surface needs a decision about whether it is glass.

### 3. Aero Radical, recommended by the owner

**Intention.** The environment carries the state, and the material carries the custody.

**Composition, genuinely different.** The decision band becomes **one immersive stage**: a single
glass plane holding the state, the custody vessel and the countdown. The recourse line turns from a
horizontal strip into a **vertical spine** with nodes, where the current step separates from the
spine. The shell is wider, the headline larger.

**The custody vessel.** The screen's centre, and it is informative rather than decorative: it is
divided by holder, so its segments are the same 50 000 / 50 000 the table lists. Its surface is
refracted glass, which is the point: the commitment was sealed and opaque, the reveal made it
readable without moving the units.

**Palette.** Four atmospheric fields, aqua, mint, periwinkle and a warm sand, behind heavily blurred
planes.
**Surfaces.** Glass with saturation lift; inner highlights on the vessel.
**Motion.** One animation only: a 5.2 s drift of the atmosphere, **active solely while the cure
window is open**. It stops when the window closes and under `prefers-reduced-motion`.
**Evidence.** Same three-level structure; the proof panel is glass over the field.

**Strengths.** Identifiable without a logo. The material says something true about the protocol
rather than decorating it.
**Weaknesses.** The immersive stage costs vertical space; on a laptop the figure row sits below the
fold. The vessel needs a designed state for every lifecycle step, not just this one.
**Credibility risk.** Moderate. A conservative reviewer may read the atmosphere as unserious before
reading the figures.
**Usability risk.** Moderate but managed: every figure sits on a solid plane, contrast was checked,
and no status depends on colour.
**Differentiation.** Strong.
**Cost to extend.** High. Roughly two to three times Restrained. Each new screen needs a composition
decision, and the vessel metaphor has to hold for issuance, redemption and default, not only this
screen.

## Recommendation, and the honest caveat

The owner has chosen Radical. On differentiation the choice is clearly right, and the vessel is the
one element here that a competitor cannot copy without copying the protocol's logic.

The caveat is scope, not taste. Radical is a **composition**, not a skin, so it does not extend by
applying tokens to existing screens; each screen needs its own composition. Two things would reduce
that risk before committing the whole product to it: design the vessel for at least one more
lifecycle state, and check the stage against a laptop viewport where the figures matter more than
the atmosphere.

## Tokens

All three sets live in `src/app/design-lab/aero-fiduciary/aero.css`, scoped to `.lab[data-variant]`.
Shared scale, per-variant values.

| Group | Tokens |
| --- | --- |
| Semantic colour | `--sem-stable`, `--sem-cure`, `--sem-action`, `--sem-blocked`, `--sem-proof`, plus a wash for each |
| Atmosphere | `--atmos-a` to `--atmos-d`, `--glass`, `--glass-line` |
| Ink and ground | `--ink`, `--ink-soft`, `--ink-faint`, `--ground`, `--plane`, `--plane-sunk`, `--rule`, `--rule-strong` |
| Typography | `--face-sans`, `--face-mono`, `--size-micro` to `--size-hero`, `--track-caps` |
| Spacing | `--space-1` to `--space-9` |
| Radii | `--radius-tight`, `--radius-panel`, `--radius-plane` |
| Elevation | `--lift-1`, `--lift-2`, `--lift-3` |
| Motion | `--dur-quick`, `--dur-settle`, `--dur-breathe`, `--ease-out`, `--ease-material` |

## Density, in three levels

1. **Decision.** State, cure countdown, custody, the four figures, the next action and who may take
   it. Everything needed to act.
2. **Operational.** The recourse line and the holder table. Dense, aligned, tabular.
3. **Proof.** Collapsed to one line by default; the panel carries full hashes, blocks and timestamps.

## States shown

Loaded · refreshing, shown by dimming the figures rather than by a spinner · action unavailable, with
the reason in words · the cure deadline running · confirmed proof · the evidence panel open.

## Accessibility

Keyboard navigation with a visible focus ring on every control, asserted in the tests. WCAG 2.2 AA
contrast on ink and semantic colours. Touch targets at 48 px minimum on the primary action. No
status conveyed by colour alone: each carries a word and a glyph. `prefers-reduced-motion` stops the
atmosphere **and the countdown**, since a ticking figure is motion too.

## Verification

18 Playwright tests across desktop and mobile: the study declares itself a study, all three variants
carry identical content, the action is inert, the block is explained in words, evidence opens,
refreshing shows as a state, and focus is visible. Screenshots are stable because reduced motion
freezes the clock, so no masking is needed.

Screenshots: `docs/design/m16/`.

## Two defects this study surfaced

**The dev overlay was in every screenshot.** Next's indicator sat on top of the study and appeared
in the first captures; `devIndicators: false` removes it.

**Playwright was reusing a stale dev server.** `reuseExistingServer: true` meant a config change did
not reach the browser, and three captures were silently of an older build. Now `false`.

## Out of scope, untouched

No Solidity, no M-15 runner change, no public transaction, no application redesign, no navigation
decision, no marketing page, no logo, no generated assets.
