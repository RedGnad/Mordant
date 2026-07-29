# M-18R — Aicher-derived operational modernism

Status: **candidate to validate**. M-18 remains the selected direction until this brief and its Deal
Room benchmark are explicitly approved. Approval of this document alone does not authorise a general
UI migration.

## Decision

Reopen the art direction around **Aicher-derived operational modernism**: a small, repeatable visual
language that helps a hurried, non-technical person orient first, decide second and inspect third.
This is a principles-based lineage, not a reproduction of Munich 1972.

The reference is systemic rather than stylistic. Aicher's Munich identity joined many formats through
structural grids, an active colour system and economical pictograms; the pictograms themselves were
designed as one reduced, grid-governed language. See the [SFMOMA exhibition note on Otl Aicher's
Munich 1972 system](https://www.sfmoma.org/exhibition/otl-aicher/), the [history of the 1972 pictogram
system](https://www.piktogramm.de/en/history/), the [pictogram system and its construction
rules](https://www.piktogramm.de/en/system/) and the [Otl Aicher 100 account of the “Rainbow
Games”](https://www.otlaicher.de/en/articles/the-rainbow-games/).

Mordant takes the method: constrained elements, strict relationships, fast orientation and flexible
composition. It does not borrow Olympic assets, period styling or historical authority.

## Keep the product; reopen its expression

Keep:

- the product model, real states and transaction boundaries;
- the five readiness gates and eight canonical verdicts;
- distinct Workspace, Participant Deal Room and Protocol audiences;
- the economic separation between receivable and protection;
- the sequence **decision → explanation → proof**;
- semantic redundancy: text, shape, position and colour together.

Remove from decision surfaces or move behind disclosure:

- rootlines in the deal queue and Participant Deal Room;
- repeated folios where no cross-check task exists;
- proof classifications, hashes, roots, blocks, transactions and gate vectors for participants;
- permanently expanded causes, provenance and defensive caveats;
- technical vocabulary in conclusions and decorative mono labels;
- any visual device justified only because it is derived from data.

A rootline may survive in complete evidence, exports or a demonstrated reconciliation task. It is not
a primary brand signature and never implies verification.

## Mordant visual grammar

The recognisable product gesture is **Receivable ↔ Protection**, not a barcode. The two economic
domains must remain unmistakable before their labels are read.

| Element | Receivable | Protection | Responsibility / deadline | Proof |
| --- | --- | --- | --- | --- |
| Meaning | the participant's invoice units | the separate protection facility | who must act, and by when | inspectable basis for the conclusion |
| Colour role | open, high-chroma cool field | contained, high-chroma warm-violet field | one contrasting action/warning accent | neutral dark inspection field |
| Form | open plane or continuous edge | bounded inset or interrupted edge | directional marker joined to the actor/action | aligned layers and explicit source labels |
| Pictogram | document/unit | reserve/shield | actor/hand-off or clock | source/record |
| Language | “Your receivable” | “Protection concerned” | named party + verb + time | exact technical nouns only |

The current M-18 hex values are **not inherited automatically**. M-18R keeps semantic roles, then
chooses a fresh palette in the benchmark. It must:

- use colour as substantial orientation fields, not thin decorative rules;
- share no exact brand-token palette or tricolour grammar with Lock-in;
- preserve WCAG 2.2 AA and every distinction without colour;
- reserve the darkest mass for proof inspection, never the whole participant surface;
- use at most two domain colours plus one action/deadline accent in the first viewport.

Pictograms form one proprietary family on a common grid, stroke and optical weight. A pictogram is
admitted only when it accelerates domain, responsibility, time or action recognition. It remains
labelled in text; decorative symbols and literal copies of Aicher's copyrighted pictograms are out.

The layout uses a consistent modular grid across surfaces:

- fixed anchors for verdict, actor, deadline and action;
- asymmetry and large colour fields for macro orientation;
- stable alignment between the two economic domains;
- denser subdivisions only as the user enters explanation and proof;
- reflow at mobile widths, never miniaturisation or two-dimensional panning.

Typography serves the hierarchy rather than carrying the identity alone. Human conclusions use a
confident display voice; controls and explanations use a highly legible sans; monospace is restricted
to machine evidence. No technical voice appears in participant prose.

## Information contract

The three levels are separate states, not three panels shown together.

1. **Decision — visible immediately:** what happened, whether the user must act, who is responsible,
   the deadline, the two relevant amounts and one primary action.
2. **Explanation — one deliberate disclosure:** cause, blocking gate, consequence and what changes
   when the responsible party acts.
3. **Proof — another deliberate disclosure:** exact identifiers, before/action/after records,
   sources, evidence classifications and limitations.

Nothing required for a safe decision may be hidden in proof. Nothing useful only for audit may
compete with the decision.

## Refusals

M-18R is not:

- Munich 1972 cosplay: no rainbow quotation, Olympic blue, diagonal athlete silhouettes, Waldi,
  period poster composition or imitation Aicher pictograms;
- Lock-in with different copy: no black mass, acid yellow, primary-blue rails, red/yellow/blue bars,
  collision-as-energy or aggressive square controls;
- security-document cosplay: no rootline wallpaper, serial-number theatre, guilloché, passport or
  banknote proportions, simulated seals or implied authenticity;
- generic “Swiss” SaaS: no neutral card grid that removes Mordant's economic character;
- a technical control room for occasional participants.

## First benchmark: one Participant Deal Room

Produce **one** critical Deal Room composition at `1280×800` and `390×844` before migrating any other
surface. Use the fixture in which the participant's receivable units have not moved, the participant
cannot cure, and Facility B must act before the deadline.

The first viewport contains only:

- one plain-language conclusion: the receivable has not moved;
- one plain-language responsibility: the participant has nothing to do; Facility B must act;
- the participant's receivable and the protection concerned, explicitly distinguished;
- the missed-deadline consequence;
- one primary action, or a clear no-action state;
- one “Why?” disclosure and one “View evidence” entry point.

It contains no rootline, folio repetition, hash, root, block, transaction, proof classification or
five-gate vector.

## Review packet

The candidate is implemented only at `/design-lab/m18r-deal-room`, with search indexing disabled.
It reads the canonical `wrong-role` fixture and derives the holder's two exposures from the product
model; no amount, actor, deadline or proof state is restated as an independent UI fixture.

- [Desktop benchmark — 1280×800](./m18r-deal-room-1280x800.png)
- [Mobile benchmark — 390×844](./m18r-deal-room-390x844.png)

The benchmark palette is fresh rather than inherited from M-18: receivable `#087873`, protection
`#BD1F59`, responsibility/action `#3E223B`, deadline `#FFC85A`, proof/structure `#181C24` and paper
`#F3EFE7`. These are local candidate values, not product tokens.

Automated composition checks enforce the `WRONG_ROLE` source verdict, exact prorated amounts,
decision vocabulary, closed disclosure defaults, the 50/120-word ceilings, a visible mobile exit,
44 px targets, no horizontal overflow, domain contrast and the absence of participant-level proof
vocabulary. These checks do not replace the five non-technical comprehension sessions required for
approval.

## Approval thresholds

The candidate may replace M-18 only when the benchmark meets every condition:

- no more than **50 domain words** in the decision region and **120 words before scroll**;
- verdict, responsible party, deadline and safe next action are each identified in **5 seconds** by
  at least **4 of 5** non-technical participants, without coaching;
- **zero** confusion between receivable and protection, and **zero** unsafe action;
- each tested pictogram improves or preserves recognition versus its labelled text-only control; a
  pictogram that does not is removed;
- the primary action or explicit no-action state is visible at `390×844` without scrolling;
- no horizontal overflow at `390 px`, all actions are at least `44×44 px`, and tested colour pairs
  meet WCAG 2.2 AA;
- domain and state remain distinguishable in greyscale and with reduced motion;
- product, design and the accountable decision owner explicitly approve the desktop and mobile
  benchmark together.

If any threshold fails, revise only the benchmark and retest. Do not average a domain confusion or
unsafe action into a pass. After approval, record that M-18R supersedes M-18, migrate the Workspace,
keep the security-document language only where useful in Evidence and Protocol, then rewrite M-31
for audience-appropriate tasks before the full study.
