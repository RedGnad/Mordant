# M-18: final art direction — contemporary security-document design

Status: **selected**. This brief closes M-18. It does not migrate the live UI; that work starts in
M-19 only after these rules and the three static compositions have been reviewed together.

## Decision

Mordant will use the lineage of **contemporary security-document design**: modern banknotes,
passports and machine-readable identity documents in which recognition, value, inspection and
provenance are designed as one system.

This is not a metaphor that claims Mordant issues money, certifies invoice truth or creates legal
priority. It is a visual discipline for presenting an immutable deal identity, two distinct money
domains, a state transition and the evidence boundary around that transition.

The M-17 patterns remain valid beneath this direction:

    Deal Workspace        instrument-panel composition
    Participant Deal Room disclosure-led composition
    Protocol Operations   technical-reference composition

Those patterns determine density. Contemporary security-document design supplies the shared visual
language above them.

## Emotional thesis

**Calm authority under consequence.**

Mordant should feel most composed when a deal is least comfortable. It is exact without becoming
cold, materially rich only under inspection, and blunt about what is known, derived or unresolved.
The first glance answers; the second glance explains; the third glance proves.

It must not feel celebratory, punitive, nostalgic, luxurious or cybernetic.

## Why this direction, not the current structural prototype

The current implementation proved the product hierarchy, but its broken mineral ground, near-black
graphite, cobalt, sulfur, vermilion, square controls, hard borders and tricolour top rail share too
much of Lock-in's visual family. That is a complete grammar, not one stray colour.

High-Tech / structural expressionism was considered as the final direction. Its served/servant
logic maps cleanly to a deal centre and exposed readiness rails, but it carries three liabilities:

1. its most recognisable expression uses primary-colour services and exposed joints — precisely the
   part of the current prototype that reads as Lock-in;
2. it risks reducing the product to the technical or industrial diagram explicitly rejected in the
   original brief;
3. it gives Protocol Operations a natural home but makes the occasional participant feel as though
   they have entered a control room.

Security-document design better joins amount, identity, state, consequence and proof. Its risk —
performing legal or cryptographic authority — is real and is controlled by the refusals in this
brief.

## Approved reference set

These references are approved for principles, not for visual quotation.

| Reference | What Mordant takes | What Mordant refuses |
| --- | --- | --- |
| [De Nederlandsche Bank, *Designing Banknote Identity*](https://www.dnb.nl/publicaties/publicaties-onderzoek/occasional-study/nr-3-2012-designing-banknote-identity/) | Macro recognition through layout, typography, colour and one dominant figure; a series recognisable before close reading | Dutch imagery, humour as a default tone, denomination cosplay and literal banknote proportions |
| [Swiss National Bank, ninth-series lifecycle](https://www.snb.ch/en/the-snb/mandates-goals/cash/lifecycle) | A stable system across variants; functional layers; design and inspection features developed together | Swiss crosses, simulated foil, security-feature theatre and claims that a visual feature proves authenticity |
| [Norges Bank, Series VIII](https://www.norges-bank.no/en/news-events/news/Press-releases/2014/Press-release-7-october-2014/) | A descriptive face paired with a data-driven abstract face; abstraction controlled by a real scale | Maritime imagery, pixel art with no data relationship and decorative generative noise |
| [Bank of Canada, vertical $10 design](https://www.bankofcanada.ca/banknotes/vertical-10-note-security-features/vertical-10-note-design-elements/) | Vertical hierarchy, a dominant identifier and strong macro/micro reading on narrow formats | Portraiture, national symbolism and simulated metallic or colour-shift effects |
| [Norwegian passports, Neue Design Studio, Nasjonalmuseet](https://www.nasjonalmuseet.no/en/guide/collection/22/119/) | A calm continuous visual system across pages; progression without changing identity | Tourism illustration and hidden UV content carrying information needed for the task |
| [Bank of England, Series G design and launch](https://www.bankofengland.co.uk/quarterly-bulletin/2021/2021-q3/our-new-banknotes-the-journey-from-design-to-launch) | Common inspection features placed consistently; recognition and accessibility tested with people | Guilloché as wallpaper, institutional portraits and familiarity used to avoid necessary change |
| [Reserve Bank of Australia, accessible banknote features](https://www.banknotes.rba.gov.au/resources/for-people-with-vision-impairment/accessibility-features/) | Redundant recognition by position, scale, shape, count and contrast | Fake tactile claims on glass and any state encoded by colour alone |
| [ICAO Doc 9303, machine-readable travel documents](https://www.icao.int/publications/documents/9303_p1_cons_en.pdf) | Fixed visual and machine-readable zones; globally repeatable field order; strict separation of human and machine detail | Personal-document mimicry, MRZ cosplay and exposing identity fields merely because the format permits them |

## Anti-references

The following are explicit refusals, not loose cautions.

- **Lock-in's onlinepunk/brutalist grammar:** black mass, acid yellow, primary-blue rails,
  red/yellow/blue brand bars, aggressive squared buttons and collision as energy.
- **Neo-brutalist fintech kits:** cream ground, 1 px black boxes, monospace micro-labels and a bright
  sticker colour presented as a brand.
- **Web3 control rooms:** black-violet grounds, neon, glowing edges, node diagrams, terminal chrome
  and animated telemetry as atmosphere.
- **Literal banknote skeuomorphism:** portraits, seals, crests, signatures, serial-number theatre,
  guilloché behind body copy, metallic CSS and fake holograms.
- **Institutional editorial safety:** elegant serif headline, vast whitespace and discreet cards
  without a product-specific inspection grammar.
- **Glass and pastel identity:** blur, translucency and gradients whose only job is modernity.

## The signature system

Mordant is recognisable without its logo through four elements used together.

### 1. The rootline

Every deal has a narrow, deterministic line index derived from its immutable invoice root. It uses
six widths and three spacings, rendered as parallel ink strokes. The same rootline appears in the
deal ledger, deal header and proof export.

It is always labelled **visual index derived from invoice root**. It is a navigation and matching
aid, never a cryptographic proof and never called a security feature.

### 2. Repeated folio identity

The short deal ID appears twice on a deal surface: once in the human header and once adjacent to the
proof boundary. Repetition allows a visual cross-check after scrolling or printing. It is not a fake
banknote serial.

### 3. Domain edge grammar

Receivable and protection remain recognisable in greyscale:

| Domain | Edge | Number treatment | Required language |
| --- | --- | --- | --- |
| Receivable | continuous double rule | open, light field | `RECEIVABLE` plus economic name |
| Protection | interrupted rail with one inset notch | contained field | `PROTECTION` plus economic name |

Colour reinforces these shapes but never replaces them.

### 4. Evidence registration

Evidence is represented as aligned layers, not a badge collection:

- observed: solid rule and filled registration mark;
- attested: double rule and outlined registration mark;
- derived: dashed rule and offset registration mark;
- external / not established: open-ended rule and empty registration mark.

The classification word is always printed. No layer is called verified unless the underlying source
and verification method support that exact claim.

## Typography

The three voices are deliberately distinct from the current Helvetica/System Mono pair.

| Voice | Typeface | Use | Rules |
| --- | --- | --- | --- |
| Identity | **Newsreader Display** | Mordant wordmark, deal folio titles, critical participant statements, large economic figures | Never used below 28 px; no all caps; restrained italic only for an economic qualifier |
| Functional | **IBM Plex Sans** | navigation, controls, tables, explanations, verdict causes and resolutions | 12 px minimum for prose and controls; 11 px is reserved for dense auxiliary labels; sentence case; medium weight carries hierarchy before size |
| Probatory | **IBM Plex Mono** | blocks, addresses, transaction IDs, raw actions, timestamps and evidence sources | 11 px minimum; tabular figures; slashed zero; never used for participant prose |

Amount numerals use tabular figures even when set in the identity face. Decimal and asset symbol are
one optical step smaller, not superscript. Atomic units appear only in expanded proof or diagnostics.

Formats in the compositions:

    1,100,000.00 aUSDC     operator and proof
    1.10m synthetic aUSDC  participant summary, with exact value adjacent
    29 Jul 2026 · 14:32 UTC
    block #18,402,911
    0x82C1…91A7             compact context only; full value is copyable in proof

Locale behaviour belongs to M-28. M-18 fixes hierarchy, not the final locale policy.

## Palette

This palette is cool, ink-based and intentionally avoids Lock-in's cobalt/sulfur/vermilion triad.
These are design decisions; M-19 will convert them into enforced semantic tokens.

| Role | Value | Use | Never used for |
| --- | --- | --- | --- |
| background primary | `#EEF2EF` | default document field | selected navigation or evidence class |
| background operational | `#E1E8E4` | dense workspace rails | warnings |
| surface raised | `#FBFBF7` | human reading areas | proof raw-data mass |
| surface proof | `#241A2A` | raw machine evidence only | whole application or participant screen |
| text primary | `#211923` | primary ink | state by itself |
| text secondary | `#655D68` | context and explanatory copy | disabled controls below contrast |
| border structural | `#8D858F` | registration grid | decoration with no alignment role |
| action primary | `#49305C` | the single current action | navigation, evidence or amount domains |
| receivable domain | `#00696D` | receivable edge and label | positive state |
| protection domain | `#87506F` | protection edge and label | critical state |
| state critical | `#AF2858` | critical state and deadline | protection domain identity |
| state attention | `#945A30` | intervention required | selection or branding |
| state positive | `#276858` | completed or satisfied state | receivable identity |
| evidence observed | `#1E3D46` | observed layer | receivable domain |
| evidence attested | `#675879` | attested layer | protection domain |
| evidence derived | `#4E6A61` | derived layer | positive state |
| evidence external | `#73777C` | external / not established | disabled state |

No raw product colour belongs in component files after M-19. The proof surface is the only large dark
mass. Shadows, blur and generic gradients remain absent.

The M-18 contrast check returns `15.13:1` for primary ink on paper, `5.60:1` for secondary ink on
paper and between `5.38:1` and `6.31:1` for every semantic ink on the raised folio. Light ink on the
critical band is `6.37:1`; light ink on the proof surface is `16.56:1`. M-19 must preserve or improve
these pairs rather than assuming the hex values remain safe in every combination.

## Material logic

The material is **cool uncoated stock plus registered inks**, translated to a screen without paper
texture cosplay.

- Base surfaces are quiet and opaque.
- Shared edges make sections read as one continuous folio, not a card grid.
- Fine line structures exist only where two fields align or where provenance layers meet.
- Overprint occurs only where two facts genuinely overlap, such as an action joining before and
  after state.
- Empty apertures expose what is unknown or not established; they are never translucent glass.
- Large dark ink belongs to machine proof and nowhere else.

There are no rounded floating cards, soft elevation shadows, noise textures or decorative hairline
mazes.

## Composition

The system has two simultaneous scales.

**Macro recognition** answers in under ten seconds: verdict, amount domain, responsible party,
deadline and next action.

**Micro inspection** holds exact amounts, source, block, transaction and derivation. It never
competes with the macro layer.

At `1280×800`:

- persistent product chrome is at most 56 px high;
- no routine surface repeats a marketing-size page title;
- the workspace shows intervention list, selected deal, both economic domains, deadline, readiness
  verdict and primary action without initial vertical scroll;
- detailed state machines and allocations sit below or behind a deliberate secondary level;
- Protocol Operations may use the full viewport density but retains 44 px action targets.

## Iconography

The five gates receive a proprietary family of inspection marks on a 12×12 grid:

- identity: paired registration corners;
- role: keyed offset pair;
- time: open radial index;
- economic: nested denomination frame;
- protocol: closed cross-link.

Stroke is 1.5 px at standard size, square-ended but not industrially heavy. Pass, pending, blocked and
unknown change the internal mark, not the outer silhouette. Every glyph remains adjacent to its gate
name and verdict; no icon carries meaning alone.

General actions use a quiet, conventional icon family. Brand distinctiveness belongs to the five
gate marks, rootline and domain grammar, not to redrawing every utility icon.

## Motion

The motion model is **registration**, not machinery.

- A selected deal aligns its rootline and folio in one 160–200 ms movement.
- Before/action/after layers register once after a new observation.
- Readiness changes replace content in place; no count-up and no bouncing status.
- Pending transactions may use a textual elapsed time, but no infinite decorative spinner.
- No parallax, tilt, holographic cursor response or moving line texture.

With `prefers-reduced-motion`, every state is present immediately and in the same reading order.
Nothing becomes harder to understand.

## Behaviour across the three surfaces

### Deal Workspace — 100% density

The rootline is a fast index in the ledger. Folio identity, two domain records and one readiness
verdict dominate the selected deal. Search, urgency groups and responsibilities form the operational
rail. Proof remains a compact registered strip until opened.

### Participant Deal Room — 60% density

One folio, one personal conclusion, one exact exposure and one next responsibility. Wallet, role and
eligibility derive the view. A role switcher may exist only under a conspicuous demo control. The
evidence summary is readable prose; the complete proof is one disclosure deeper.

### Protocol Operations — 120% density

The proof surface becomes more prominent but never consumes the whole app. Event rail, selected
transition, raw receipt and recovery diagnostic share one registration grid. Access role, expected
actor and last safe state are permanent context.

## Mobile and reduced motion

The direction survives narrow screens by changing orientation, not by miniaturising.

- The vertical rootline becomes a 6 px horizontal folio index below compact chrome.
- Repeated folio identity remains at the beginning and proof boundary.
- The two domain records stack and retain different edge grammars.
- Workspace mobile is triage/read-only; Participant Deal Room keeps the complete action path;
  Protocol Operations exposes urgent inspection but not complex ceremony.
- Minimum action target is 44×44 px.
- At 200% zoom, proof tables linearise label before value and never require two-dimensional panning.
- Long addresses wrap only in proof; compact context uses a middle ellipsis plus a copy action.

## Accessibility contract

- WCAG 2.2 AA contrast is a floor, including state and evidence colours.
- Domain, state and evidence classification are redundant in text, line shape and position.
- Body copy is never microprint. The security-document lineage does not excuse text below 12 px.
- Amounts use tabular numerals and a stable decimal alignment.
- Focus uses a two-part ring: dark outer boundary plus light inner gap, independent of accent colour.
- Critical countdowns announce meaningful thresholds, not every second.
- Live regions never replace visible persistent results.
- The reading order remains verdict → cause → amount/consequence → next action → proof.

## What is difficult to copy

The moat is not the palette or a guilloché pattern. It is the product-specific chain:

    immutable invoice root
      → deterministic visual index
      → repeated folio identity
      → distinct receivable/protection edge grammar
      → registered before/action/after evidence layers

A competitor can copy the colours. They cannot reproduce this system convincingly without adopting
Mordant's model of immutable deal identity, independent accounting domains and classified evidence.

## Failure conditions

M-18 has failed if execution becomes any of the following:

- cream background, mono labels and decorative guilloché over the existing square-card UI;
- a simulated banknote, certificate, passport or legal instrument;
- colour alone separating receivable and protection;
- a root-derived pattern described as verification;
- a serif marketing layer pasted above generic SaaS tables;
- a dark proof aesthetic spread across every surface;
- eight readiness verdicts collapsed back into `4 / 5 clear`;
- the same colour used for a domain, navigation selection, evidence category and alert;
- ornamental detail that disappears in reduced motion or prevents 200% zoom.

## Static validation compositions

The source artboards and fixed screenshots live in `docs/design/m18/`:

1. `workspace.html` / `workspace-1280x800.png`
2. `participant-critical.html` / `participant-critical-1280x800.png`
3. `protocol-diagnostic.html` / `protocol-diagnostic-1280x800.png`

They are decision artefacts, not production components. No code should be copied from them before
M-19 translates the brief into semantic foundations.

## M-18 exit criteria

- One real, named aesthetic is selected: contemporary security-document design.
- Eight references are approved with explicit take/refuse boundaries.
- Type, palette, material, iconography and motion are fixed enough to judge execution.
- The three compositions share one identity at three densities.
- The workspace composition demonstrates the required `1280×800` first viewport.
- Every critical distinction survives greyscale and reduced motion by construction.
- All three compositions keep operational text at or above 11 px, actions at or above 44 px and
  produce no horizontal overflow at 390 px; `render.mjs` enforces these bounds.
- Participant capability is wallet-derived, not granted by a manual role selector.
- Protocol diagnostics belong to the selected record; synthetic fixture facts are never labelled
  as live on-chain observation.
- Each surface presents one of the eight canonical readiness verdicts rather than a readiness score.
- Lock-in's tricolour rail, sulfur accent, cobalt selection and brutalist action grammar are explicitly
  rejected.
- The live product remains unchanged until the M-19 migration has a token and regression plan.
