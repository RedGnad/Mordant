# M-18NWS — New Wave Swiss benchmark

Status: **candidate to validate**. M-18NWS replaces M-18R as the active benchmark, not as an
approved product direction. M-18R remains a research archive; its neo-brutalist expression is not
approved. This candidate is limited to `/design-lab/m18nws-deal-room` and does not authorise a
change to the production Deal Room, Workspace, Protocol Operations, the shared design system,
backend, contracts or transactions.

The direction is **New Wave Swiss Typography**. It can be described without a project-specific
style name: **Mordant uses a New Wave Swiss visual language.** The reference lineage is Wolfgang
Weingart, April Greiman and Dan Friedman, with Paula Scher used only as a secondary reference for
information hierarchy. Mordant takes disciplined grids, typographic contrast and controlled
displacement from that lineage; it does not reproduce a historic poster.

## Thesis: structured tension

The composition is approximately 80% order and 20% controlled displacement. A 12-column desktop,
8-column tablet and 4-column mobile grid remains perceptible through alignment and negative space,
not through an outline around every region. Only one macro element is allowed to disturb it.

The selected disturbance is the **large condensed deadline crossing one desktop gutter**. The time
is visually tied to `Facility B`, because actor and deadline are one responsibility. It is not a
free-standing decoration: it represents the only immediate time constraint in the `wrong-role`
scenario. On mobile, the same information becomes a full-width deadline row between responsibility
and the two economic domains. It is recomposed rather than scaled down.

The other two candidate gestures are deliberately excluded. There is no oblique connector and no
second macro typographic offset. Small reflow motion inside a disclosure does not count as another
gesture.

## Local candidate tokens

These values are scoped to the benchmark. They are neither production tokens nor permission to
alter shared styles.

```css
--nws-ground: #f3f4ef;
--nws-ink: #12141a;
--nws-receivable: #006c9c;
--nws-protection: #d62e68;
--nws-action: #6750d8;
--nws-proof: #161c28;
```

| Concern | Candidate rule |
| --- | --- |
| Interface family | Archivo Variable only; hierarchy comes from width, weight, size, spacing and case |
| Evidence family | IBM Plex Mono, restricted to the closed Level 3 evidence disclosure |
| Type-scale envelope | At most four material scales before scroll; `12 / 16 / 30 / 72` is the reference relationship, with responsive values allowed |
| Saturated colour | At most receivable, protection and action/deadline in the first viewport |
| Structural rule | `1px` maximum outside an accessible focus indicator |
| Controls | Flat, no shadow, `6–10px` radius and at least `44px` high |
| Functional motion | `160–220ms`, at most `8–16px`, no permanent motion; immediate final state under reduced motion |

Colour never carries state alone. Receivable is an open, stable and economically dominant plane;
protection is smaller, separate, conditional and contained. They share a typographic system but are
not twin cards with different fills. The proof colour is reserved for Level 3 and cannot become a
large participant-facing atmosphere.

The first level remains decision-only: verdict, no-action statement, responsible actor and
deadline, both amounts, missed-deadline consequence, exit and two closed disclosures. Level 2
explains why. Level 3 exposes source, before/action/after, limitations and identifiers. The three
levels must not compete in the initial viewport or be open together.

## Extension across the three product surfaces

This is a plausibility note, not migration authorisation.

| Surface | Stable system | Permitted displacement | Density boundary |
| --- | --- | --- | --- |
| Participant Deal Room | Human verdict, responsibility and the two economic domains follow a repeatable grid | One deadline, actor or critical transition may cross one gutter | Decision first; explanation and evidence stay closed |
| Deal Workspace | Instrument, ownership, tasks and schedule keep fixed column anchors; receivable remains more open than protection | Only the current blocking actor/deadline or the transition being prepared leaves the grid | More operational detail is allowed, but not a separate poster gesture per task or row |
| Protocol Operations | Tables, state changes and source records use the densest version of the same grid; proof may use the dark field | One unresolved conflict or operator-critical transition can interrupt the table rhythm | IBM Plex Mono and exact identifiers belong here or in Level 3, never in participant conclusions |

The system scales because the expressive unit is semantic — responsibility under time — rather
than an illustration, barcode, custom pictogram or hard-shadow component. A later migration would
still require separate approval and surface-specific comprehension checks.

## Distance matrix

The Lock-in observations below come from its public root on 29 July 2026 at `1280×800`. That page
resolved to the production deployment `dpl_HP3kZwxaxMLWkGYHcs4VE8oFCUJT`, created
`2026-07-28T15:57:02Z`. The associated deployment hostname
`lock-gdyc668e5-redgnads-projects.vercel.app` is protected by Vercel SSO, so the public
`https://lock-in.quest/` alias is the usable capture source. M-18R observations come from the
checked-in `1280×800` benchmark capture.

| Test | Lock-in — observed | M-18R — observed | M-18NWS pass condition |
| --- | --- | --- | --- |
| First-view silhouette | Full-width hero; huge two-part headline on the left, orbit/tilted circular mark on the right and a dark bottom strip | Large framed central composition with a right-hand two-block amount stack | No framed centre, no hero-orbit symmetry and no dark poster strip; an open grid with a deadline crossing one gutter |
| Box model | The hero is open, while controls and later surfaces use outlined boxes | The whole decision surface is a `2px` box subdivided into boxed regions | No global box; regions are formed by position, spacing, background and occasional `1px` separators |
| Shadow | Hard offset shadow on the wallet control and circular hero core | `10px` plum offset shadow on the main frame | No box shadow in the benchmark |
| Controls | Squared, outlined, uppercase control with a hard offset shadow | Full-width CTA split into text and arrow cells | Flat `6–10px` control; arrow may sit inline but has no compartment |
| Border density | Moderate in the hero, with outlined control and concentric orbit lines; higher in downstream UI | High: almost every macro region is enclosed or divided by `2px` rules | Sparse `1px` rules only; personality must survive if the rules are removed |
| Typographic rhythm | Large uppercase Arial statement, contrasting italic Georgia line and many uppercase micro-labels | Heavy sans headline plus pervasive uppercase labels and compact technical labels | One variable grotesque; sentence-case verdict and responsibility; uppercase reserved for a few orientation labels |
| Collision energy | Headline, tilted core, orbit, offset shadow and bottom strip create an online-poster composition | Strong rectangular collisions and an offset frame create neo-brutalist poster energy | One functional collision only: the deadline crossing a gutter; all other content remains calm and aligned |
| Colour grammar | Cream `#f3f0e7`, near-black `#10100f`, orange-red `#c93600` and acid lime `#d8ff36` | Paper, teal, magenta, plum and yellow in large hard-edged fields | Neutral ground plus blue receivable, pink protection and violet action; the grayscale silhouette must still be distinct |
| Domain structure | No receivable/protection pair; the first view expresses challenge and payout | Receivable and protection are same-size stacked boxed blocks with document/shield pictograms | Receivable is open and dominant; protection is smaller and contained; no new pictograms |
| Evidence posture | Slogans and a dark proof strip are visible in the hero | Technical language is mostly disclosed, but numbered disclosure rails remain visually loud | No proof vocabulary or technical ornament before disclosure; disclosure entries stay secondary |

Changing only the palette is a failure. M-18NWS also fails if the grayscale comparison preserves
Lock-in's poster silhouette, hard-shadow controls or collision energy, or M-18R's framed box, equal
domain cards, divided CTA and dense outline rhythm.

## Reference sources and capture protocol

### Source ledger

- **Lock-in runnable source:** `/Users/red.g/CascadeProjects/Lock in`, with the root composition in
  `app/page.tsx` and its visual grammar in `app/globals.css`. At inspection time the checkout was on
  `511232c6e2742b3acac12d20a998a4f276bcaf1f`, ten commits behind `origin/main`, and contained
  pre-existing user changes. It is therefore read-only context, not the capture source.
- **Lock-in public reference:** `https://lock-in.quest/`. The Vercel deployment was inspected
  read-only; no alias or deployment was changed. The inspection did not establish a Git SHA for the
  deployment, so this note does not claim one.
- **Existing M-18R captures:** `docs/design/m18r-deal-room-1280x800.png` and
  `docs/design/m18r-deal-room-390x844.png`.
- **M-18R runnable source:** `/design-lab/m18r-deal-room` in this repository.
- **M-18NWS runnable source:** `/design-lab/m18nws-deal-room` on the dedicated candidate branch and
  its preview deployment only.

No durable Lock-in screenshot existed in either repository when this inventory was taken.

### Reproducible renderer

`docs/design/m18nws/render.mjs` is the single capture entry point. It uses one Playwright Chromium
run, light colour scheme, reduced motion, fixed viewports, closed initial disclosures and loaded web
fonts. Grayscale is applied after layout with `filter: grayscale(1)`, so the colour and grayscale
frames share geometry. It also builds one six-panel desktop comparison sheet.

With the local candidate running on port `3100`:

```bash
M18NWS_BASE_URL=http://127.0.0.1:3100 \
M18NWS_LOCK_IN_URL=https://lock-in.quest \
node docs/design/m18nws/render.mjs
```

The Lock-in capture should record its UTC capture time and deployment ID in the PR because the
public alias can later move. The SSO-protected immutable hostname cannot be used by an unauthenticated
Playwright context. A future rerun against a moved alias is a new observation, not a byte-for-byte
reproduction of this reference.

### Expected artifact inventory

The renderer owns these files under `docs/design/m18nws/`:

| Artifact | Purpose |
| --- | --- |
| `lock-in-reference-1280x800.png` | Public Lock-in reference at the common desktop viewport |
| `lock-in-reference-1280x800-grayscale.png` | Lock-in silhouette and contrast reference |
| `m18r-deal-room-1280x800-reference.png` | Fresh M-18R render at the common desktop viewport |
| `m18r-deal-room-1280x800-grayscale.png` | M-18R silhouette and contrast reference |
| `m18nws-deal-room-1280x800.png` | Candidate desktop benchmark |
| `m18nws-deal-room-1280x800-grayscale.png` | Candidate desktop grayscale check |
| `m18nws-deal-room-390x844.png` | Candidate mobile benchmark |
| `m18nws-deal-room-390x844-grayscale.png` | Candidate mobile grayscale check |
| `m18nws-distance-comparison.png` | Lock-in / M-18R / M-18NWS in colour and grayscale |

The historical M-18R images remain in place as archive evidence. The fresh `-reference` render is
used in the comparison so all three desktop frames share the same browser and capture run.

The final capture run completed at `2026-07-29T15:57:35Z`. The Lock-in frame in that run came from
the public alias and the deployment ID recorded above; the Mordant frames came from this branch's
local source before publication.

## Validation record

| Check | Result |
| --- | --- |
| M-18NWS semantic and anti-pattern Playwright spec | `6/6` passed |
| Full repository Playwright suite | `46/46` passed |
| Repository validation | `pnpm validate` passed, including TypeScript, unit and runner tests, `89` Forge tests, formatting, evidence, secret scan and production build |
| Independent visual audit | `READY`; no visual blocker at `1280×800`, `390×844` or in the grayscale comparison |
| Product change boundary | No production surface, shared design-system file, backend, contract, transaction or public alias changed |

The existing lint warning for the unused `MONAD_CHAIN_ID` in `scripts/m05-runner-lib.mjs` remains
outside this benchmark's scope; validation reports it as a warning, not an error.

## Factual limits and approval gates

- Lock-in and Mordant show different products and scenarios. The comparison tests visual distance,
  not task equivalence or relative product usability.
- A screenshot can establish silhouette, hierarchy, border density and contrast. It cannot establish
  five-second comprehension, correct action or economic-domain understanding.
- No M-31 session has been run. Approval still requires five non-technical participants, at least
  four correct answers out of five for the first five questions, five out of five distinguishing
  receivable from protection, and zero unsafe interpretations.
- Grayscale is a distance and redundancy check, not a substitute for measured WCAG contrast or
  assistive-technology testing.
- The benchmark uses the canonical synthetic `wrong-role` model. It does not demonstrate a live
  transaction, external financing, legal priority, insurance or production safety.
- Passing Playwright checks protects semantics and explicit anti-patterns; it does not approve the
  art direction or authorise migration.

```text
NEW WAVE SWISS BENCHMARK: READY FOR REVIEW
PRODUCT MIGRATION: NOT AUTHORIZED
M-31 USER TESTS: NOT STARTED
```
