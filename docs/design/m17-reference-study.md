# M-17 Parts B, C, D: reference study and candidate territories

Twenty live references captured at fixed viewports, analysed formally, then reduced to three
candidate territories. **No Mordant screen is designed here.** "Aero Fiduciary" is not carried
forward as a name or as a direction.

    node scripts/m17-collect-references.mjs

Captures: `docs/design/m17/references/`, 46 images at 1440×900 and 1280×800, plus 390×844 for eight
references where the mobile case matters. Manifest with status, title and file per shot:
`docs/design/m17/reference-manifest.json`.

## What the collection actually returned

Twenty of twenty loaded. That number overstates the usable set, so two corrections first.

**Ramp is not a usable reference.** `ramp.com` detected an automated client and served a plain-text
"Machine Version" page addressed to AI agents: a markdown document listing products and a signup
bonus. It is a genuinely interesting artefact, but it is not Ramp's interface and must not be
analysed as one. **Excluded from the formal analysis.**

**Six captures include a consent wall** covering the lower band: Stripe, Teenage Engineering,
tldraw, AREA 17, Mercury, Monzo. The upper composition is intact and analysable; anything about
footer behaviour is not.

So: **19 references analysed, 1 excluded, 6 partially obstructed.** That leaves the set inside the
12 to 18 the brief asked for once obstruction is accounted for.

## Part C: formal analysis

Analysed from the captures, not from memory. Where I could only see the first viewport, the entry
says so.

### Raw systems and diagrammatic interfaces

**Observable Framework docs** (`observable-docs`). Two-column: a 272 px persistent nav rail with a
search field at top, then an unconstrained content column. The headline is set in a **monospace**
face at roughly 48 px with a single word coloured green, which is the whole brand gesture. Body is a
humanist sans at 16 px. Palette is white, near-black, one green accent. The proof of capability is
not an illustration: it is a grid of **actual dashboard screenshots**, dark, dense, unretouched, with
axis labels too small to read at thumbnail size. That is the argument, and it is not copyable without
having built the dashboards.
*Proprietary:* monospace display type plus real dense artefacts. *Generic:* the nav rail, the
copyable install command. *Extends to a complex product:* well. The rail scales, the content column
takes tables.

**tldraw** (`tldraw`). A live editor, not a page. Chrome is pushed to the four edges: brand top-left,
a floating tool bar bottom-centre, a style panel top-right, zoom bottom-left. The centre is
**entirely empty white**. Icons are single-weight line glyphs at one size; the only colour is a blue
selection state and the swatch grid. Density is near zero at rest and appears only where the user is
working.
*Proprietary:* the confidence to leave the middle empty. *Generic:* the icon set. *Extends:* poorly
to a data product; this composition assumes an infinite canvas, which Mordant does not have.

**Excalidraw**, similar structure, not re-described.

### Scientific and laboratory systems

**Plotly**, **Deepnote**, **Benchling**. All three use a light ground, a sans of the Inter class, and
prove capability with product screenshots rather than illustration. Benchling and Deepnote both lead
with a centred headline over a screenshot; Plotly leads with a chart. None of the three is
distinctive at the level of form: cover the logo and they are interchangeable with each other and
with much of the category. Their value to us is **evidence that a serious technical audience accepts
plain, screenshot-led layouts**, not the layouts themselves.

### Expressive editorial enterprise

**Stripe API reference** (`stripe-docs`). The most useful capture in the set, because it is an
operational surface rather than a pitch. Three columns: a 280 px nav, a prose column, and a right
column carrying code on a **dark slate panel** while everything else stays white. Type is small, 14
to 15 px, with generous leading; section titles at ~28 px. Colour does one job: links and the current
nav item are indigo, everything else is greyscale, and the dark code panel is the only mass. Client
libraries appear as a row of small brand marks inside a bordered box, aligned to a baseline.
Per-section utilities ("Ask about this section", "Copy for LLM", "View as Markdown") sit as quiet
text buttons at the right of each heading.
*Proprietary:* the two-tone split, prose light and machine dark, held over thousands of pages.
*Generic:* the three-column docs shell. *Extends:* very well, and it is the closest thing in the set
to a dense financial operator surface.

**Linear**, **Vercel**, **37signals**. Linear and Vercel share a near-identical formula: dark or
near-white ground, tight tracking on a geometric sans, a screenshot with a subtle gradient behind it.
37signals is the outlier, plain and text-led. None is distinctive enough to build on.

### Tactile and post-digital identities

**Teenage Engineering** (`teenage-engineering`). The strongest formal position in the set and the
least applicable. Navigation is a horizontal row of **large custom pictograms**, each with its label
and sub-items set in a small grotesque underneath: a propeller for products, a battery for store, a
square for latest, a magnifier-and-cog for finder. The hero is a die-cut orange ticket shape with
perforated edges, set in a heavy rounded display face, saying "please do not share this 30% secret
discount code with anyone". The cookie notice is a **yellow warning triangle with a hand pictogram**,
not a bar. Japanese text sits at small size beside the logo without translation.
*Proprietary:* essentially all of it. The pictogram system and the willingness to make a cookie
notice part of the identity cannot be copied without copying the company.
*Generic:* nothing. *Extends to an institutional product:* **no.** Amounts and deadlines have no
place in this register, and the humour is a liability at the moment a user is losing money.

**AREA 17** (`area17`). Left-aligned statement at ~56 px in a neutral grotesque, ranged left on a
white field with roughly 240 px of air above it, then a full-bleed image band. No colour at all in
the first viewport. Nav is five words, no marks.
*Proprietary:* very little; this is the studio default. *Generic:* most of it. *Extends:* the
typographic scale does, the emptiness does not survive contact with a data table.

**Panic**, similar family, not re-described.

### Material and dimensional

**Rive**, **Spline**. Both prove a runtime by animating in the hero. Neither capture is meaningful as
a still, which is itself the finding: **a direction whose argument only exists in motion cannot be
reviewed from screenshots, and will not survive `prefers-reduced-motion`.** Recorded, not carried
forward.

### Strongly branded financial

**Mercury** (`mercury`). A full-bleed photographic composite: a desk and office chair on a grass
ridge above a forested valley at dawn, mist in the folds, with the headline "Radically different
banking" in white at ~44 px over the sky. Nav and buttons are translucent white on the image. A
persistent dark band at the bottom carries the regulatory disclosure, "Mercury is a fintech company,
not an FDIC-insured bank", beside the cookie notice.
The composition is worth studying precisely because of that band: the brand takes an expressive image
and then **pins the legally required, unglamorous sentence to the bottom of every viewport**. That
tension, expressive surface plus non-negotiable disclosure, is the closest structural parallel to
Mordant in the whole set.
*Proprietary:* the image, and the nerve to run it. *Generic:* the nav, the pill buttons.
*Extends:* the hero does not, the disclosure band does.

**Monzo**, **Wise**. Bright flat colour, rounded geometric sans, product shots in device frames.
Competent, category-standard, not distinctive.

## Part D: three patterns, not three competing aesthetics

**Correction to an earlier draft.** These were presented as three rival directions to choose between.
That framing was wrong: the M-17 inventory describes three surfaces with different users, and these
three patterns map onto them. They are complementary, not competing.

    Technical reference  -> proof and diagnostics (Protocol Operations)
    Instrument panel     -> a possible composition for the Deal Workspace
    Disclosure-led       -> critical decisions, the Participant Deal Room, confirmations

**No final art direction is selected here.** A pattern says how a surface could be composed; it does
not decide typeface, palette, imagery or voice. That decision is human and comes next.

### Pattern 1: Technical reference, for proof and diagnostics

**Named lineage:** API and systems documentation. Stripe API reference, Observable Framework docs,
Observable's dense dashboard artefacts.
**References:** `stripe-docs`, `observable-docs`, `observable`, and Benchling/Plotly as evidence the
audience accepts it.

Light ground, greyscale, one accent colour used only for links and current position. Small type with
generous leading. Machine content, hashes, calldata, readbacks, on a dark panel; human content on
white. Persistent left rail for navigation, right column for proof.

| Situation | Treatment |
| --- | --- |
| Critical state | A ruled band above the content column, text-led, with the deadline as the largest figure on screen |
| Amount | Tabular monospace, right-aligned in a column, decimal equivalent one size down beneath |
| Proof | The dark panel: hash, block, timestamp, monospace, copyable |
| Irreversible action | A confirmation step listing exactly what will change, in the same table format as the state itself |
| Dense data | Its native form. This territory is built for it |
| Error | The revert selector and its decoded meaning in the dark panel, with the plain-language cause above |
| Operator daily screen | Not its job. This pattern serves Protocol Operations, where the reader is diagnosing, not working deals |

**Where it belongs:** Protocol Operations, and the proof level of the other two surfaces.
**Trust:** high. **Usability:** high for its user. **Differentiation:** low to moderate; a
well-populated category, and distinctiveness would have to come from the content. **Cost:** low.

### Pattern 2: Instrument panel, a possible Deal Workspace composition

**Named lineage:** laboratory and measurement instrumentation, plus the operational half of the docs
tradition. Observable's dark dense dashboards, tldraw's edge-anchored chrome, Stripe's two-tone split.
**References:** `observable`, `tldraw`, `stripe-docs`.

Chrome is pushed to the edges; the centre holds one thing, the deal. State is carried by a persistent
band rather than by scattered badges. Two tones only: a working surface and a reading surface.
Iconography is single-weight line glyphs used for actions, never for decoration.

| Situation | Treatment |
| --- | --- |
| Critical state | The edge chrome changes tone across the whole frame; the centre content does not move |
| Amount | Large in the centre when it is the subject; tabular in the rail when it is context |
| Proof | A drawer from the right edge, over the working surface, dismissible |
| Irreversible action | The action bar detaches from the edge and centres, which is the only time it moves |
| Dense data | Fits, in the rails |
| Error | Held in the same edge band as state, so failure and status occupy one place |
| Operator daily screen | Its reason to exist. This is the shape of a tool someone uses all day |

**Where it belongs:** the Deal Workspace. Its first-use cost is acceptable for a daily user and would
not be for an occasional participant.
**Trust:** moderate to high. **Usability:** high once learned, with a real learning cost on first
use. **Differentiation:** moderate to high; almost nothing in finance is composed this way.
**Cost:** moderate. The edge chrome is designed once and then holds for every screen.

### Pattern 3: Disclosure-led, for critical decisions and the Participant Deal Room

**Named lineage:** regulated financial communication, where the required statement is part of the
composition rather than hidden in a footer. Mercury's persistent disclosure band, 37signals' plain
text-led pages, AREA 17's typographic scale.
**References:** `mercury`, `37signals`, `area17`.

An expressive, editorial front, large ranged-left type and real air, with a **permanent, unglamorous
band** carrying the thing that must not be missed: what is at risk, what is not yet proven, what this
screen does not know. The band is not a footer and does not scroll away.

| Situation | Treatment |
| --- | --- |
| Critical state | The band takes it: the deadline and the exposure live there permanently |
| Amount | Editorial scale in the body, repeated in the band at small size so it is never off-screen |
| Proof | An expandable section in the body, prose-led, hashes in monospace |
| Irreversible action | Placed in the band, where it cannot be reached accidentally while reading |
| Dense data | Weakest of the three. Tables have to be designed against the editorial rhythm rather than with it |
| Error | The band changes register and states the cause in a full sentence |
| Operator daily screen | Not its job, and it should not be asked to do it |

**Where it belongs:** the Participant Deal Room, plus confirmation steps and critical-decision moments
inside the Deal Workspace.
**Trust:** high; it reads as something that has been through compliance. **Usability:** good for
occasional users, poor as a daily working surface. **Differentiation:** high. **Cost:** moderate to
high wherever it meets dense data, which is why it is scoped to the surfaces that carry least.

## What the earlier framing got wrong

The first draft concluded that no territory served both users and presented that as an unresolved
trade-off. The trade-off was an artefact of the framing: it came from merging a deal manager, an
occasional participant and a protocol administrator into one "operator", then looking for one
composition to serve all three.

With three surfaces named, the three patterns stop competing. The real questions become sequencing
and consistency:

- **Sequencing.** The Deal Workspace is used daily and should be designed first, per
  `OPERATOR-FIRST, PARTICIPANT-READABLE, DIAGNOSTICS-SEPARATE`.
- **Consistency.** Three patterns across three surfaces risks three products. What must be shared is
  the readiness vocabulary, the eight verdicts in Part A, and the treatment of amounts and proof.
  Those are the same facts everywhere; only the density and the register change.

A remaining open question, stated rather than answered: the Participant Deal Room shows a subset of
the Deal Workspace's data. Whether that is one implementation with a reduced mode, or two, is an
architecture decision that should follow the art direction rather than precede it.

## Method notes and limits

- Captures are single-viewport, above the fold. Scroll behaviour and interaction are not evidenced.
- Six captures are partly obstructed by consent walls; footer analysis is unavailable for those.
- Rive and Spline argue in motion and cannot be assessed from stills; recorded and set aside.
- Ramp served an agent-targeted text page and is excluded rather than analysed.
- No reference was chosen from Dribbble or Behance. All twenty are live products, documentation or
  studio sites.
