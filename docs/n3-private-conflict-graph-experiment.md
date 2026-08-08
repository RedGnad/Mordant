# N=3 private conflict graph experiment

Status: **bounded experimental architecture; not a qualification report**.

This document defines the architecture, privacy scopes, retention behavior and review boundary for
the isolated `experiment/n3-private-conflict-graph` work. The experiment started from
`9ea6652dbf61c6227e3a21183e628a7356b6df18`. A final source commit, retained execution evidence and
qualification result must be recorded separately after the implementation and real executions have
been validated. Nothing in this document means that those tests or executions have passed.

The repository remains a synthetic hackathon prototype. This experiment does not establish legal
priority, wallet ownership, production custody, universal duplicate-financing detection or fitness
for real funds.

## Bounded objective

The experiment adds a deterministic graph layer above the existing reviewed two-party BGV flow:

```text
one synthetic receivable
  + three separately represented private claims
  + three independent current two-party executions
  -> complete explicit pair-relation ledger
  -> aggregate conflict-evidence root
  -> review-ready facts
```

It is not an N-party FHE circuit, a graph database, a worker-concurrency change or ciphertext reuse.
The fixed circuit, parameter profile, evaluator, governed decryptor, governed-result signature
domain and single-slot worker architecture remain unchanged.

The fixed claims are:

| Graph claim | Private half-open interval |
| --- | --- |
| A | `[100, 400)` |
| B | `[200, 600)` |
| C | `[500, 800)` |

The required governed pair outcomes are:

| Pair | Required governed result |
| --- | --- |
| A/B | `CONFLICT` |
| A/C | `NO_CONFLICT_UNDER_POLICY` |
| B/C | `CONFLICT` |

These are qualification targets. The aggregate layer must not calculate or substitute these
Booleans in TypeScript. Each result must come from a real, separately prepared, evaluated and
released run of the existing pair engine, and each governed signature must verify.

## Incremental and sequential execution

The experiment models institutional admission in this exact order:

```text
admit A
  -> no pair exists
admit B
  -> freeze, bind and complete A/B
admit C
  -> seal the complete N=3 admission and expected-pair set
  -> freeze, bind and complete A/C
  -> freeze, bind and complete B/C
```

Canonical ordering inside a pair is derived from the two stable graph claim IDs; `PARTICIPANT_A`
and `PARTICIPANT_B` are pair-local roles, not graph identities. The order in which the two pairs
created by C are run is the admission order above, even if lexical claim-ID ordering differs from
the human labels A, B and C.

Only one pair may be active at a time. Admission must not advance while a pair created by the prior
admission remains active or unresolved. Retained chronology must bind each state-machine ordinal to
the same pair run, case, start time and completion time recorded by its evidence leaf. The three
execution ordinals must be unique and exactly sequential; caller-supplied timestamps alone are not
proof of sequential execution.

## Stable graph claim identity

A graph claim authorization binds:

- graph session and receivable identities;
- a random, opaque claim ID and positive claim version;
- a participant reference;
- a hiding commitment to the private opening and a high-entropy random salt;
- issue and expiry times;
- a claim-scoped authorization public key, digest and signature.

The private opening contains the exact interval plus the fixed `aUSDC` currency and exclusive-claim
assumption. The raw interval and salt never become part of a claimant or PUBLIC projection. A
pair-local run ID, pair role or current role-derived commitment must never replace the stable graph
claim identity.

The participant reference is only a reference. Hashing a low-entropy wallet address, email address
or other enumerable identifier does not make it hiding. Qualification must use a high-entropy
issuer handle or a keyed/salted construction when unlinkability is required.

The experiment's claim-scoped Ed25519 key proves possession of that graph authorization key. It
does **not** prove control of a referenced wallet, authority to act for a legal claimant, or legal
ownership of the receivable. No wallet-ownership claim is supported.

Every retained or supplied graph object must be treated as untrusted JSON at runtime. Validation
must require a plain object, exact fields, exact tuple lengths, canonical encodings, non-zero
digests, safe times and the intended Ed25519 key type before a digest or signature is accepted.
Unsigned extra fields must not be admitted into public claim records or graph roots.

## Pair intent, binding and evidence leaf

Each expected pair has three graph-layer records.

1. A pre-result intent freezes the full canonical pair, stable claim-node digests, claim versions,
   claim commitments, graph-to-local role mapping, pair run ID and creation time. Both graph claim
   authorization keys sign the intent body.
2. A pair binding extends that intent with the fresh FHE case and maps each stable graph claim to
   the corresponding pair-local participant identity. Both graph claim authorization keys sign
   the complete binding body before it is accepted.
3. A pair evidence leaf binds the graph session, full canonical claim pair, pair run/case, binding
   digest, ordered participant artifact digests, evaluated artifact digest, evaluator provenance,
   complete governed signed result, inspection reference, execution chronology and evidence
   digest.

Validation compares all three canonical-pair fields, not only a caller-supplied pair digest. The
graph receivable, pair binding asset, governed-result asset and trusted asset pin must be identical.
The case binding must satisfy the existing Go invariants, including exact participant order,
distinct participant identities and keys, non-zero cryptographic digests, a valid case lifetime,
the governed release-authority identity and participant binding signatures.

Every pair uses a fresh pair run, case, public key, evaluation-key set, participant artifacts and
evaluated artifact. Cross-pair uniqueness is checked when a leaf is admitted and when the aggregate
is verified. In particular, the two expected `CONFLICT` relations may not reuse one signed result.

The governed-result signature is the authenticity root for the Boolean and its FHE bindings. The
graph evidence digest and aggregate root are deterministic integrity commitments; they are not, by
themselves, signatures or proof that a binary hash came from a trusted build. Source and native
binary pins must be supplied from a separately recomputed, trusted qualification context rather
than trusted merely because the aggregate repeats them.

## Relation state and failure isolation

The evidence ledger represents every expected pair explicitly with one of:

- `PENDING`;
- `CONFLICT`;
- `NO_CONFLICT_UNDER_POLICY`;
- `FAILED`;
- `EXPIRED`.

Absence of a visual edge never means no conflict. The visual conflict graph may contain only true
`CONFLICT` edges, while the evidence ledger retains all three relations and their states.

A pair transition is create-only or an exact idempotent retry. A resolved relation cannot be
downgraded or overwritten by later malformed input. Failure handling identifies the affected
relation from a previously trusted expected-pair identity, never from an unverified leaf locator,
and updates that relation atomically. A bad A/C leaf therefore cannot change the already verified
A/B or B/C records.

One missing, failed or expired pair makes the aggregate `PARTIAL` and the review state
`AWAITING_EVIDENCE`. A global all-clear is permitted only when the exact three unique expected pairs
are present, all three have verified complete evidence, and all three signed results are
`NO_CONFLICT_UNDER_POLICY`. The required scenario is not globally clear because two verified target
relations are conflicts.

## Aggregate manifest

The deterministic aggregate manifest commits to:

- graph session identity, issue time and expiry time;
- the one receivable identity;
- the complete sorted node set and exact three-pair set;
- every explicit pair state, run, binding, evidence and governed-result digest;
- policy, service, circuit, parameter, source-tree and native-binary pins;
- verified execution ordinals and chronology digest;
- completeness and review state;
- true conflict edges as a derived view;
- retention and review-handoff declarations; and
- the aggregate root.

Completeness, global all-clear, conflict edges, chronology and projections are recomputed from
verified records when evidence is read. A type assertion or a matching embedded root is not enough:
the verifier must validate exact shapes, signatures, cross-references, expected-pair membership,
freshness, source pins and the root before projecting or reporting the aggregate.

## Audience scopes

“Non-secret cryptographic evidence” and “safe for the PUBLIC audience” are not synonyms. Pair
Booleans and relation membership may contain no raw opening but are still restricted information.

| Audience | Permitted view |
| --- | --- |
| Restricted operator/reviewer | A/B, A/C and B/C states and evidence references; complete signed pair results; aggregate and chronology; no need to expose raw openings in ordinary review views |
| Claimant A | A/B and A/C only |
| Claimant B | A/B and B/C only |
| Claimant C | A/C and B/C only |
| PUBLIC | Aggregate root, completeness/review metadata, node/pair counts and qualified source metadata only; no pair Boolean, claim pair, participant reference or raw interval |

A claimant projection is selected and authorized for one claim before delivery. An object containing
the operator view or all claimant projections together is restricted operator evidence; handing
that bundle to one claimant does not satisfy claimant isolation. The actual PUBLIC projection is a
separate derived object and must remain metadata-only.

## Evidence locations and retention

The experiment has three distinct storage/audience classes:

1. **Restricted operator evidence** contains the session manifest, public claim authorizations,
   pair intents and bindings, pair evidence leaves with signed results, aggregate, chronology,
   operator/claimant derivations, provenance and qualification report. It is retained for audit but
   is not the PUBLIC projection.
2. **Operator-private claim storage** contains exact openings and salts, but not claim-scoped
   authorization private keys. Those signing keys remain in caller-managed process memory until
   all references are released. JavaScript strings cannot be zeroized, and this experiment makes
   no garbage-collection timing claim. The private store must use a physically separate,
   restrictive, non-repository root. Path names and record identities must be cross-checked on
   write and read.
3. **PUBLIC projection storage** contains only the metadata-only PUBLIC projection derived from a
   verified aggregate.

An implementation name such as `publicRoot` may mean “contains no raw secret key/opening” at the
filesystem layer. It does not grant the contents PUBLIC audience scope. If that root contains pair
leaves or claimant views, it is a restricted audit root and must not be served as the PUBLIC
projection.

Public and private roots must be physically disjoint after real-path and filesystem-identity
resolution, including ancestor components. The private root must stay outside tracked repository
content. Records are create-only, durably published and verified after readback; domain validators
also require the path session/claim/pair identifiers to match the record body.

For this bounded experiment, private claim records retain the exact `activeFrom`, `activeUntil`,
fixed currency/exclusivity and salt until an explicit operator cleanup action. There is no
automatic terminal deletion. The retention declaration enumerates those fields and states that
the authorization private key is not persisted.

Explicit cleanup is ordinary storage management. The experiment makes no claim of secure erasure
from storage media, snapshots, backups, swap, core dumps or memory remnants. It also makes no claim
that all copies held outside the configured roots have been erased. Retained audit evidence must
not contain the raw openings or authorization private keys, and repository hygiene and secret scans
must check that separation.

## Review boundary and forbidden effects

The terminal experiment flow is:

```text
verified governed pair facts
  -> retained restricted evidence
  -> verified aggregate and scoped projections
  -> review-ready evidence references
  -> stop
```

The graph provides facts. A later policy and human review may decide whether several conflict edges
belong to no incident, one incident or several incidents. The experiment does not make that
decision and does not automatically open an incident or recourse case.

The experiment is not authorized to:

- open recourse;
- deploy an adapter or contract;
- create or advance a cure window;
- execute settlement;
- burn or transfer a claim;
- move tokens or other funds; or
- alter the public landing experience.

Boolean fields that merely say these effects are false are declarations, not proof of absence.
Qualification must independently inspect the pair work roots and operation chronology for absent
recourse/public-product-evidence/adapter/cure/settlement artifacts, check the repository diff and
confirm that no chain or token action was invoked.

## Qualification status and acceptance boundary

At the time this architecture document is added, no N=3 evidence or test result is claimed by this
document. Qualification remains pending until a retained report demonstrates all of the following:

- the exact incremental admission and sequential pair order;
- three distinct fresh pair executions of the existing BGV engine;
- the target true/false/true governed results and all governed signatures;
- stable claim reuse across its incident pair bindings;
- rejection of cross-session evidence and wrong asset/policy/circuit/profile pins;
- `PARTIAL` for missing, failed, expired or corrupt evidence;
- isolation of a corrupt A/C leaf from valid A/B and B/C signatures;
- refusal of an incomplete global all-clear;
- exact operator, per-claimant and PUBLIC projections without raw-opening leakage;
- absence of recourse, adapter, cure, settlement and token side effects;
- source commit/tree and independently recomputed binary provenance; and
- retained evidence readback, root recomputation and repository hygiene.

Until those checks and the real pair executions pass, supported claims are limited to the bounded
architecture and intended invariants described here. Real N=3 execution, production privacy,
multi-party FHE, concurrent scheduling, threshold release, wallet authorization, legal priority,
secure erasure and automated recourse remain unsupported.
