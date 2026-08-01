# RC2 threshold-FHE ceremony decision

Decision date: 2026-08-02

Decision status: **CEREMONY DESIGN DECISION READY**

RC2 evidence profile: **GO — EPHEMERAL ONE-SHOT LATTIGO**

Selected design: **Option A — ephemeral session key, abort on failure**.

Post-MVP product target: a bounded **ReusableKeyEpoch** per privacy domain,
created and held by three distinct administrative principals, with explicit query and
session budgets, short immutable expiry, overlapping rotation, and monotonic revocation.

RC2 monotonicity selection: **option 3 — three-operator signed append-only
transparency witness**.

Overall product verdict: **PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN**.

Unresolved owner decisions: **none**.

## Independent-review disposition

The complete read-only adversarial review of checkpoint
`20bef1f9d8cb6f831c686667f6ce9e6d4d5d3719` was supplied after the provisional decision.
Its SHA-256 is
`66368916e5e1dcc7e8e8c0d3966139a3b151d2f2ee274d4a4cd355ce2b5dbd4b`.
It reports `CEREMONY REVIEW FAIL` across secret separation, recovery safety, public-bundle
consistency, manifest authentication, and evidence integrity. The exact C-01, C-02,
H-01 through H-10, and M-01 through M-05 findings are now mapped below.

The review invalidates the implemented recoverable strategy, not the frozen V5 contracts
or the feasibility of a new Lattigo ceremony under passive-operator assumptions. Option A
removes the vulnerable recovery mechanism and closes the coordinator-substitution path by
requiring every operator to reconstruct and attest the concrete keys. It also strengthens
the accepted RC2 topology from merely three hosts to **three hosts controlled by three
genuinely distinct administrative principals**. Those principals need not be separate
organizations, and no independent-organizational-custody claim is authorized.

Accordingly:

- checkpoint `20bef1f9d8cb6f831c686667f6ce9e6d4d5d3719` remains **FAILED INDEPENDENT
  REVIEW** and **OBSOLETE AS ACCEPTED CEREMONY EVIDENCE**;
- the recoverable/resumable mechanism must not be repaired, migrated, or reused;
- a new one-shot ceremony implementation may begin only after this decision is committed
  as a clean documentation checkpoint;
- client, enrollment, evaluator, release, Monad, ABI, and contract implementation remains
  out of scope until fresh three-host ceremony evidence passes independent review.

## Repository and evidence baseline

The review was performed on branch `remediation/private-matching-v4-rc2` at HEAD
`20bef1f9d8cb6f831c686667f6ce9e6d4d5d3719`; the upstream branch pointed to the same
commit. Before these decision documents, the tracked tree was clean. Five pre-existing
classified untracked files were present and were not read as ceremony evidence or
modified.

Frozen-source verification remained intact:

- RC1: 16 of 16 frozen sources matched the recorded freeze;
- V5: 12 of 12 frozen sources matched the recorded freeze;
- no frozen ABI, contract, runtime, client, enrollment, evaluator, or release source was
  changed by this decision.

The exact dependency is `github.com/tuneinsight/lattigo/v6 v6.2.0`, with Go module sum
`h1:HZrksD5u87bOr/4hWHI1Jhps14Tafdvb84Fxmi3dou0=`. Mordant's ceremony source imports
`core/rlwe`, `multiparty`, `schemes/bgv`, and `utils/sampling`; the failed recovery layer
also imports `ring/ringqp` and `utils/structs`. Recovery-specific use is historical, not a
recommendation. The pinned Lattigo source is Apache-2.0 licensed.

The retained local ceremony record reports 207,397 ms total wall time across restarts,
a 322,528,527-byte public bundle, operator disk footprints of 216,319,463,
216,319,462, and 216,319,461 bytes, and 1,040,403,950 combined bytes at the completed
snapshot. It used three processes on one host, recorded no Monad broadcast, and did not
measure peak per-process memory. These numbers describe the rejected recoverable design;
they are not accepted security evidence.

The separate historical performance record reports a 9,214 ms evaluator, 86 ms key
load, 37,751,700-byte ciphertext transport, 215 ms threshold release, 19,989 ms
end-to-end time, and process-wide peaks of 886 MB heap / 1,537 MB system memory. It is a
different one-process measurement and must not be presented as three-host ceremony
capacity.

## Claim vocabulary

The remainder of this record uses these labels deliberately:

- **Paper:** a security or construction property argued by the cited research paper.
- **Lattigo:** behavior implemented or explicitly documented in exact v6.2.0.
- **Mordant orchestration:** an application-layer rule that would have to be implemented,
  tested, and independently reviewed.
- **Operational assumption:** a property of hosts, administrators, channels, or process
  handling not provided by the cryptographic primitive.
- **Inference:** a bounded conclusion from source or a local probe, not an upstream
  guarantee.
- **Unresolved:** evidence or upstream meaning not available today.

Passing tests never upgrades passive security to malicious security.

## Exact threat model

The candidate design is evaluated against exactly this model:

- the coordinator may be malicious;
- the evaluator may be malicious;
- all three key operators are honest but curious and follow the specified algorithms;
- fewer than two operators collude, so one operator alone cannot satisfy a 2-of-3
  release;
- one operator may abort; safety is required, liveness is not;
- accepted evidence must use three separate hosts controlled by three genuinely distinct
  administrative principals;
- those principals may belong to one organization, so RC2 makes no claim of independent
  organizational custody;
- RC2 makes no claim of secure physical erasure;
- Lattigo's passive-adversary and retry limitations apply without silent strengthening.

This model does not protect against an actively Byzantine operator that equivocates,
submits a malformed or adversarial share, leaks its secrets, or signs a false statement.
It also does not protect against two colluding operators, compromise of two administrative
domains, host compromise, or traffic analysis.

The fixed product objectives remain separate from ceremony claims. Coordinator key
substitution is addressed by independent operator reconstruction. Evaluator release of
arbitrary ciphertext is addressed by the already frozen operator recomputation design,
not by this ceremony. Single-operator decryption is addressed by the 2-of-3 access
structure. Cross-session use is addressed by key scope and schema binding.

## Independent design axes

| Axis | RC2 disposition | Reason |
|---|---|---|
| Key scope | One fresh key per bilateral session | Minimizes query budget and compromise blast radius; `maximumSessions = 1`. |
| Failure | Terminal abort, never cryptographic resume | Exact v6.2.0 warns that retrying any MHE protocol is insecure. |
| Coordinator/operator resistance | Malicious coordinator; passive operators only | Independent reconstruction removes coordinator selection; v6.2.0 has no active contribution proofs. |
| Custody | Three hosts and three distinct administrative principals; no separate-organization claim | Distinct administration closes multi-share access by one RC2 principal without overstating organizational independence. |
| Monotonicity | Three signed append-only operator witnesses | Bounded, off-chain, no new contract, and compatible with the less-than-two-collude assumption. |

No row follows automatically from another. In particular, an ephemeral key could still
have been resumable, a reusable epoch can still abort during setup, and three hosts do not
imply three custodians.

## Options matrix

| Property | A — ephemeral one-shot | B — reusable epoch, abort setup | C — established active-secure alternative |
|---|---|---|---|
| Technical disposition | **Selected for RC2** | Rejected for RC2 | Not demonstrated; no pivot |
| Key scope | One signed session, `maximumSessions = 1` | Bounded privacy domain and epoch, multiple sessions | Depends on alternative |
| Failure | Entire attempt terminal; completely fresh retry | Setup attempt terminal; completed epoch reusable | Depends on alternative |
| Coordinator substitution | Prevented under honest operators by independent reconstruction and three exact-byte attestations | Same mechanism could apply | Would require evidence for the alternative's DKG and transcript |
| Malicious operator | Residual; malformed/equivocated contributions are not proved correct | Same residual with a larger blast radius | Candidate must provide verifiable contributions |
| Lifecycle surface | Smallest | Requires activation, budget, expiry, rotation, revocation, client compatibility | Requires protocol and integration redesign |
| Availability | A single abort kills the attempt | Setup aborts, but a completed epoch serves many sessions | Unknown |
| Compromise blast radius | One session | Every permitted session/query in the epoch | Unknown |
| Existing measurements | Rejected recovery evidence only; one-shot setup not measured | Not measured | Not measured |
| RC2 result | **GO for ceremony-only implementation and fresh evidence** | Deferred | Evidence burden not met |

Option B uses a capability that the Lattigo README explicitly describes: setup keys can
be reused across evaluation phases. That fact does not provide Mordant's missing lifecycle
controls. Reuse would multiply the effect of release-oracle misuse, rollback, custody
failure, or key compromise. Without implemented budgets, status distribution, rotation,
and Edge Client compatibility it is not an RC2 evidence profile.

For Option C, official OpenFHE material demonstrates threshold examples for BGV/BFV/CKKS
and a BSD-2-Clause implementation. The official material reviewed did not establish the
complete combination required here: malicious-secure distributed key generation,
verifiable contributions, exact compatibility with Mordant's BGV circuit and concrete
serialization, 2-of-3 release, and a bounded integration path. This is an absence of
sufficient evidence, not a claim that OpenFHE cannot support any such construction. NIST
IR 8214C and the NIST threshold-cryptography project provide taxonomy and an evaluation
process; they are not a certification of a Mordant-compatible library. Inventing a new
ZK contribution proof is prohibited.

## Lattigo v6.2 feasibility answers

| # | Answer | Evidence class |
|---|---|---|
| 1 | Yes. Every operator can receive all public-key shares, call `AggregateShares`, and call `GenPublicKey` using the shared CRP. | Lattigo source and README. |
| 2 | Yes within the exact tested build when the same valid shares, parameters, and CRP are used. Modular addition is mathematically commutative. Cross-OS/architecture canonical-byte behavior is not an upstream guarantee found in the documentation. | Lattigo source; same-platform probe; portability unresolved. |
| 3 | Yes. Every operator can aggregate all round-one shares, use that exact aggregate for round two, aggregate all round-two shares, and call `GenRelinearizationKey`. | Lattigo source. |
| 4 | Yes. For each required Galois element, every operator can aggregate all corresponding shares and call `GenGaloisKey`. | Lattigo source. |
| 5 | Ring additions are order-independent, but protocol order is not: relinearization round two depends on the complete round-one aggregate. Mordant transcripts must order stages, senders, and Galois elements canonically. | Lattigo plus Mordant orchestration. |
| 6 | Threshold setup has one private pairwise share round; public-key generation has one public round; relinearization generation has two public rounds; each Galois element has one public round. | Lattigo README/source. |
| 7 | Fresh randomness enters local secret-key sampling, Shamir-polynomial coefficients, public-key share noise, relinearization round-one ephemeral keys/noise, relinearization round-two noise, Galois/evaluation-key share noise, and each party's CRS reveal. CRPs are then deterministically sampled from the combined CRS. | Lattigo source; CRS ceremony is Mordant orchestration. |
| 8 | Yes. Lattigo exposes binary serialization and leaves networking to the application, so a signed ceremony-bound envelope can carry the unmodified bytes. | Lattigo README/source; envelope is Mordant orchestration. |
| 9 | Yes. Each operator can hash the exact concrete public key, relinearization key, ordered Galois-key set, parameters, context, and roster to derive the same KeyID. | Mordant orchestration, conditional on exact-byte agreement. |
| 10 | Yes under honest-but-curious operators. A coordinator cannot substitute a key it chose if all three operators reconstruct and sign the exact same concrete bytes and consumers require all three signatures. | Inference under the stated model. |
| 11 | A malicious operator can send malformed, poisoned, or different shares, bias or disrupt an application-defined CRS exchange, leak secrets, falsely attest, or cause denial of service. Lattigo v6.2.0 does not implement proofs of correct contribution. | Lattigo README/security guidance. |
| 12 | Yes operationally. Plaintext pairwise Shamir evaluations can remain in RAM only until authenticated receipt and aggregation; relinearization ephemerals can remain in RAM for their attempt. On success retain only the aggregate Shamir share; on any failure abandon all attempt secrets. This supports best-effort cleanup, not secure erasure. | Mordant orchestration and operational assumption. |

### Independent aggregation probe

A minimal probe outside the repository used exact v6.2.0 and the same generated shares
and CRP, aggregating in canonical and reverse sender order on `darwin/amd64`. It produced
byte-identical results:

| Material | Bytes | Result |
|---|---:|---|
| Public key | 7,864,600 | identical |
| Relinearization key | 31,458,448 | identical |
| Galois key | 31,458,464 | identical |

This confirms the source-level expectation on that build only. It does not prove
cross-platform canonical serialization, malicious security, or valid-contribution
checking. Accepted evidence would require three independently built hosts to reconstruct
and compare the concrete bytes.

## Authenticated message specification

All cryptographic payloads remain exact Lattigo v6.2.0 binary serializations. Mordant's
envelope changes the transport and transcript, not the primitive.

Every signed envelope contains:

- `schemaVersion` and `serializationVersion`;
- `ceremonyId`;
- `contextDigest`;
- `rosterDigest`;
- `keyScope` and `scopeBinding` (`sessionCommitment` for RC2);
- `keyEpoch` (`0` for an ephemeral RC2 key);
- `senderOperatorId`;
- `recipientOperatorId` for a private message, or an explicit `BROADCAST` value;
- `operation`;
- `round` or exact `galoisElement`, with a canonical not-applicable encoding;
- `previousTranscriptDigest`;
- `payloadDigest` over the exact canonical payload bytes;
- `signatureAlgorithm`, signing-key identifier, and signature over a
  domain-separated deterministic binary encoding of every preceding field.

The caller-supplied sender is never authoritative. A receiver verifies the signature
against the pinned roster, requires exactly one roster key to validate, derives the
signer from that key, then requires the derived identity to equal `senderOperatorId` and
the authenticated transport identity. Ambiguity, an unknown key, or mismatch is terminal.

| Message | Operation-specific binding and handling |
|---|---|
| CRS commitment | `CRS_COMMIT`; payload is a domain-separated commitment to that operator's fresh reveal. No reveal is accepted until all three commitments are fixed. |
| CRS reveal | `CRS_REVEAL`; binds the matching commitment and previous transcript. The CRS is a domain-separated hash of the canonical ordered reveals and full context. |
| Private Shamir share | `PRIVATE_SHAMIR_SHARE`; exact recipient is mandatory. The signed plaintext envelope is encrypted over a pinned mutually authenticated recipient channel. Only the recipient sees the plaintext payload digest; the public transcript retains a ciphertext digest and signed receipt, never the share. |
| Public-key share | `PUBLIC_KEY_SHARE`, public round 1; binds the public-key CRP digest. |
| Relinearization round one | `RELIN_SHARE`, round 1; binds its CRP digest. |
| Relinearization round two | `RELIN_SHARE`, round 2; additionally binds the exact complete aggregate-round-one digest reconstructed locally. |
| Galois share | `GALOIS_SHARE`, round 1; binds the exact `galoisElement` and its CRP digest. One independently aggregated result is required per manifest element. |
| Final transcript attestation | `FINAL_TRANSCRIPT_ATTESTATION`; payload is the full manifest statement and the exact concrete public-key, relinearization-key, ordered Galois-key bundle, and transcript digests reconstructed by the signer. |

Public transport permits retransmission only of the exact already-generated bytes while
the originating process and attempt remain live. Receivers content-address and deduplicate
the envelope; a different payload for the same operation/sender is equivocation and
terminal. Calling a randomized `GenShare` method again is never retransmission. Whether
upstream's retry warning formally distinguishes exact-byte network duplication is an
explicit maintainer question; the rule above is a bounded application inference.

## Closing share-to-public-key correspondence (ceremony C-01)

Assuming the ceremony review's C-01 is the share-to-public-key correspondence issue named
in the mandate, Option A closes it as follows:

1. Every operator receives and verifies every authenticated public contribution and the
   common context; the coordinator provides transport only.
2. Every operator independently aggregates the public-key shares, both relinearization
   rounds, and every Galois-key share using its locally pinned v6.2.0 runtime.
3. Every operator independently recomputes the policy-circuit commitment from the frozen
   circuit and locally trusted policy/context inputs; a coordinator-provided nonzero value
   has no authority.
4. Every operator serializes the concrete final objects, derives the KeyID, and compares
   the full transcript against the canonical manifest.
5. Every operator signs the full manifest statement containing the exact concrete-byte
   digests it reconstructed.
6. Clients, evaluator, and release operators accept the key only if all three roster
   signatures verify over one identical manifest and the loaded bytes recompute every
   digest and KeyID.

A malicious coordinator cannot replace those bytes with a public/evaluation key whose
secret it knows: it would need the honest operators to sign digests different from their
local reconstruction. Merely announcing a commitment is insufficient.

This does not prove that a contribution was correctly formed, that an operator lacks the
key, or that all operators saw the same share when an operator is Byzantine. Such active
operator behavior remains outside RC2 and would require an established proof-bearing
protocol, not more coordinator signatures.

## Failure and abort model

The complete state machine is:

```text
NOT_STARTED -> RUNNING -> COMPLETED
                       `-> FAILED_TERMINAL
```

`COMPLETED` and `FAILED_TERMINAL` are terminal. A CeremonyID is never reused. A timeout,
transport ambiguity, signature failure, process exit, host restart, lost transient
message, transcript mismatch, regenerated payload, missing operator, or concrete-byte
mismatch transitions the attempt to `FAILED_TERMINAL`.

There is no persisted cryptographic-round checkpoint and no resume. Starting again for
the same bilateral session requires a new attempt ordinal, new CeremonyID, fresh CRS
contributions, fresh local secret keys, fresh Shamir polynomials/evaluations, and fresh
public/evaluation-key shares. Nothing secret or public from the failed attempt enters the
new one. A signed failure witness for the abandoned attempt remains. No secret is sampled
until all three operators have durably witnessed the new attempt.

Exact-byte transport retransmission is distinguished from randomized regeneration as
specified above. Private Shamir wires are never persisted in plaintext. They remain in
the sending and recipient operator processes only until authenticated aggregation receipt
or terminal failure. Loss after process failure therefore sacrifices liveness, which is
the intended trade-off.

One operator may safely abort, but the ceremony will not complete. The 2-of-3 threshold
applies to later release availability; it does not permit setup to omit one of the three
roster members because every operator must attest the same full setup.

Each operator also acquires an exclusive local process lease before opening its keystore
or creating ceremony state. A second process, stale lease, conflicting process-instance
identifier, or unexpected boot/session identifier terminally poisons the attempt. This is
defense against accidental concurrency under the honest-operator model, not resistance to
a malicious host administrator.

## Custody topology

| Topology | Claim supported |
|---|---|
| Three processes on one host | Functional process separation only. No host isolation, independent custody, or rollback claim. Not accepted RC2 evidence. |
| Three hosts under one administrator | Host/process fault separation only. The administrator can obtain two shares or roll back all witnesses. Not accepted RC2 evidence. |
| Three hosts under separate administrative principals | Administrative share separation under the fewer-than-two-collude assumption, provided identities, access, backups, debugging, and witness storage are actually separate. **Minimum RC2 evidence topology and required to close C-02.** It does not by itself prove separate organizations. |
| Client A operator + Client B operator + neutral operator | Strongest bilateral target: each client controls one share and neither client alone can release. The neutral operator must be a genuinely separate principal. Post-MVP target. |

Filesystem separation alone never establishes custody independence. RC2 closes C-02
operationally only when the evidence identifies three genuinely distinct administrative
principals and demonstrates that the coordinator, runner, audit process, and any one
administrator cannot open a second operator's storage. The claim remains administrative
share separation, not independent organizational custody.

## External monotonicity

| Option | Rollback / CeremonyID reuse | Leakage | Surface and dependency | RC2 disposition |
|---|---|---|---|---|
| 1. New on-chain registry | Strong once finalized, subject to chain assumptions | Ceremony timing and opaque identifiers become public | New contract, ABI, deployment, gas, audit, and chain availability | Prohibited and disproportionate |
| 2. Existing Mordant registry | Could witness only semantics already supported | Same public timing/linkability risks | Reuse would require a frozen semantic/ABI fit that does not exist; extension is a contract change | Rejected |
| 3. Three signed append-only witnesses | Resists coordinator or one-operator rollback under fewer-than-two collusion when the witnesses have distinct administrators | Can retain only domain-separated digests, ordinal, and state | Off-chain protocol, storage, reconciliation, and audit surface; no chain | **Selected** |
| 4. Remote/hardware witness | Potentially strongest depending on product | Provider-dependent | New service/hardware trust, availability, credentials, and audit | Not available for RC2 |
| 5. No external witness | Explicitly no rollback resistance | Lowest | Smallest | Rejected because retry safety depends on non-reuse |

Before generating any secret, every operator atomically creates a no-replace local
reservation under its exclusive process lease and appends a signed
`ATTEMPT_RESERVATION` containing the CeremonyID, scope binding, attempt ordinal,
context/roster digests, process-instance identifier, boot/session identifier, and previous
local witness head. The three reservations are exchanged and stored by every operator.
Each operator then appends `ATTEMPT_STARTED`, binding the canonical ordered set of all
three reservation digests. Secrets may be sampled only after all three signed start
records are mutually observed. This two-stage construction avoids a circular start-record
dependency.

Each operator refuses a CeremonyID, scope/ordinal pair, or witness transition already
present or not extending its chain. A terminal `COMPLETED` or `FAILED_TERMINAL` record
links the final transcript or failure digest. A new attempt for the same session may start
only after the prior attempt has a 2-of-3 terminal failure record; the missing operator
must reconcile that record before it may run again. All public shares remain bound to the
old CeremonyID, so an isolated late process cannot contribute to the new attempt.
Acceptance requires all three witness chains to agree.

This mechanism is an operational monotonicity layer, not consensus. It is sufficient only
under the stated fewer-than-two-collude model and three distinct administrative failure
domains. It does not survive compromise or collusion of two principals.

## Public key manifest

All three operators sign one deterministic, versioned manifest statement containing:

- `schemaVersion`, `serializationVersion`, `envelopeVersion`, and ceremony protocol
  version;
- exact `lattigoModule`, version and module checksum;
- `sourceCommit` and digests of each exact operator/runtime binary;
- `keyScope`, scope discriminator, `sessionCommitment` for RC2 or
  `privacyDomainDigest` for a future epoch, `maximumSessions`, and maximum release/query
  budget;
- `keyEpoch` (`0` for RC2 ephemeral; positive and monotonically increasing for future
  reusable epochs);
- `ceremonyId`, attempt ordinal, `contextDigest`, and monotonic-witness head digest;
- full canonical roster: operator identifiers, Shamir public points, signing public keys,
  transport certificate fingerprints, and administrative-principal identifiers/claims;
- `rosterDigest`, `partyCount = 3`, `threshold = 2`;
- `chainId`, policy identifier and version, circuit version and digest, release-layout
  version;
- full parameter encoding and `parameterFingerprint`;
- CRS construction/version and `crsCommitment`;
- exact concrete `publicKeyDigest`;
- exact concrete `relinearizationKeyDigest`;
- canonical ordered list of required Galois elements, each concrete key digest, and an
  evaluation-key bundle digest;
- canonical ordered public-contribution digest set and `transcriptDigest`;
- `keyId`;
- immutable `activatesAt` and `expiresAt`;
- initial status-statement digest and status-mechanism version;
- signature domain, algorithm, signer key identifier, and all three operator signatures.

KeyID is derived independently and without a circular manifest dependency:

```text
SHA-256(
  "MordantFheKeyId/v2" ||
  contextDigest || rosterDigest || parameterFingerprint ||
  publicKeyDigest || relinearizationKeyDigest ||
  orderedGaloisElementAndDigestBundle || keyScope || scopeBinding || keyEpoch
)
```

Every field uses a length-delimited deterministic binary encoding. The JSON presentation
is not the signing preimage.

For an ephemeral RC2 key, activation occurs only after all three final attestations and
matching transparency terminal records. Expiry is the earlier of the immutable manifest
time and the bilateral session's terminal state. The key cannot be extended, re-scoped,
or activated for a second session. Its public bundle is intentionally single-session:
every consumer requires the exact signed session commitment and rejects use by any other
session even if every concrete key byte is otherwise valid.

## Mutable status, rotation, and emergency revocation

Revocation is not a mutable boolean inside the signed manifest. A separate deterministic
`KeyStatusStatement` contains `schemaVersion`, `keyId`, `statusSequence`, status
(`ACTIVE`, `REVOKED`, or `EXPIRED`), `effectiveAt`, `reasonDigest`, and
`previousStatusDigest`, signed by at least two of the three operators and appended to all
three transparency witnesses. Sequence numbers only increase. `REVOKED` and `EXPIRED`
are terminal; no reactivation is allowed.

Any single operator can immediately stop its own participation, which fail-closes 2-of-3
release only if at least one other operator also refuses. A globally consumable emergency
revocation requires 2-of-3 status signatures. Clients, evaluator, and release operators
must fetch and verify status independently; an evaluator-supplied status is never an
authority.

Post-MVP rotation creates a completely fresh positive `keyEpoch`, CeremonyID, key
material, manifest, and KeyID. A short overlap may allow new enrollment only under the
new epoch while policy-bounded completion under the old epoch remains explicit. No
ciphertext, enrollment, release share, or private bundle is silently migrated or accepted
under another key.

## Private operator bundle and artifact access

Each operator's new bundle has a new magic/schema discriminator and contains exactly one
operator's retained share plus:

- schema and serialization versions;
- exact source commit, Lattigo module/checksum, runtime/binary digests, Go/OS/architecture
  fingerprint, circuit/release-layout versions, and parameter fingerprint;
- key scope, scope binding, maximum sessions/query budget, and key epoch;
- CeremonyID, attempt ordinal, context/roster digests, threshold, party count, and the
  operator's Shamir public point;
- KeyID, signed-manifest digest, transcript digest, monotonic-witness head, concrete
  public/evaluation-key digests, activation/expiry, and current status reference;
- the operator's single aggregate Shamir secret share;
- a reference to, never a copy of, its signing and transport identity keys;
- authenticated-encryption/sealing metadata, integrity digest, and bundle format version.

Legacy `MCR1`, `MCL1`, or prior bundle formats are rejected unconditionally by the new
runtime. There is no silent migration, fallback parser, or inference of missing scope.
One bundle never contains two operators' shares.

Private artifact readers are strictly separated:

| Artifact | Process permitted to read it |
|---|---|
| Operator signing private key | That operator's ceremony/release process through its configured keystore handle; never coordinator, evaluator, or client. |
| Operator transport private key | That operator's network endpoint only. |
| Fresh additive secret key, Shamir polynomial, outbound/inbound plaintext evaluations | That operator's ceremony process for the live attempt only. |
| Aggregate Shamir share and sealed private bundle | That operator's ceremony process creates and seals its own bundle; that operator's release process may later open it after verifying manifest, status, context, and local identity. |
| Other operators' private wires or shares | Never; each recipient sees only evaluations addressed to itself and retains only its aggregate. |
| Public/evaluation keys, manifest, public transcript and status | Clients, coordinator, evaluator, and all operators after full verification. |

Cleanup and retention are event-defined:

- before completion, additive keys, Shamir polynomials, plaintext private wires,
  relinearization ephemerals, and randomized-share working state are RAM-only and never
  logged, swapped intentionally, or persisted by Mordant;
- an outgoing plaintext private wire is dropped after its authenticated recipient receipt;
  an incoming wire is dropped immediately after inclusion in the local aggregate and
  receipt emission;
- after successful bundle sealing and all three final attestations, each operator drops
  its additive key, polynomial, individual evaluations, ephemeral relinearization secret,
  and share-generation randomness, retaining only its aggregate Shamir share in the
  sealed bundle;
- on `FAILED_TERMINAL`, no private bundle is created; all attempt secrets and cached
  payloads are best-effort zeroed/freed and the process exits. No bytes from that attempt
  are reused;
- after terminal `REVOKED`/`EXPIRED` status and closure of every policy-authorized release
  window, the operator destroys the bundle encryption key and deletes the private bundle;
- signed public manifests, public contributions, public/evaluation keys, status chains,
  failure witnesses, binary digests, and audit evidence are retained as immutable public
  evidence; secret-bearing logs are forbidden;
- these are logical and cryptographic cleanup rules. Go memory, swap, snapshots, backups,
  storage media, and an administrator may retain copies, so no secure physical-erasure
  claim is made.

## Atomic publication and evidence boundary

No cross-host filesystem operation is called atomic. Acceptance instead uses a staged,
fail-closed publication state machine:

1. The coordinator assembles the complete public material in a newly created restricted
   directory using no-follow, relative-directory handles. Every file and the directory are
   fsynced. At this stage the material is `STAGED`, never active.
2. Every operator independently parses the staged concrete objects with the canonical
   verifier, recomputes the public/evaluation-key and circuit digests, transcript, KeyID,
   and full manifest, and signs only its locally reconstructed values.
3. Each operator atomically seals its own private bundle using no-replace publication,
   fsyncs the file and directory, and signs a private-ready statement containing only the
   bundle digest and public manifest/KeyID bindings. No other principal opens the bundle.
4. The coordinator constructs the complete public directory, including all three
   attestations and private-ready statements, verifies it, and publishes an authoritative
   index with a no-replace atomic rename followed by directory fsync.
5. All three operators independently fetch and verify that exact published index, append
   matching `COMPLETED` and initial `ACTIVE` witness records, and cross-store the signed
   heads. Consumers accept the bundle only after those records agree.

A crash or mismatch before step 5 makes the attempt `FAILED_TERMINAL`; no partial bundle
is accepted and no sealed private bundle is reused. Symlinks, replacement rename, partial
directories, missing artifacts, and post-publication mutation are terminal errors.

Secret-isolation evidence is operator-local. The ceremony process itself searches for the
exact bytes and required encodings of its additive secret, Shamir polynomial, each private
wire, relinearization ephemeral, aggregate share, and sealed bundle across every declared
non-authoritative local root before it exits, with explicit expected-location allowlists.
Scanner efficacy uses independently generated synthetic canaries of the same shape and
length—never a production share. Each operator signs only its result and root inventory;
the coordinator, runner, and central audit process receive no raw secret or secret needle.
Core dumps are disabled, debugging and backups are excluded by the administrative policy,
and swap/crash collection status is recorded. These controls support a bounded evidence
claim, not proof of secure erasure or absence from every physical remnant.

Accepted evidence records the exact clean Git commit and tree object, a complete tracked
source/configuration inventory, dependency sums, toolchain, build commands, exact binaries
or immutable content-addressed locations, raw public artifacts, canonical-verifier output,
all operator-local signed reports, witness chains, and complete runner output. Evidence
metadata is itself signed and externally witnessed; an unsigned JSON summary is not an
authority.

## Audit-finding matrix

The finding identifiers below refer to the supplied independent ceremony review, not the
older V5 product-audit matrix. A classification describes the selected architecture; it
does not claim that unimplemented code or fresh evidence already exists.

| Finding | A — ephemeral one-shot | B — reusable epoch | C — alternative |
|---|---|---|---|
| C-01 operators blind-sign unverified collective material | **Cryptographically closed:** all operators authenticate every public share, independently reconstruct concrete public/evaluation keys and the circuit commitment, derive KeyID, and sign exact digests plus the full transcript. | **Cryptographically closed** only with the same independent reconstruction. | **Deferred:** no specific active-secure alternative has been validated. |
| C-02 one administrator/lab can read two shares | **Operationally closed:** accepted evidence requires three hosts, three genuinely distinct administrators, operator-local audits, and no coordinator/runner/audit access to operator bundles. No separate-organization or HSM claim. | **Operationally closed** only with the same topology; epoch reuse increases consequence. | **Residual under the stated threat model:** a library cannot create custody independence. |
| H-01 plaintext historical wires recover local RLWE contributions | **Vulnerable mechanism removed:** no recovery ledger and no persistent plaintext private wire; only the final aggregate share is sealed. | **Vulnerable mechanism removed** for abort-on-failure setup; long-lived final epoch shares remain. | **Deferred** pending the alternative's private-state design. |
| H-02 randomized operation precedes durable commit | **Vulnerable mechanism removed:** after a witnessed start, any process/transport failure terminally abandons all attempt material; no operation is regenerated. | **Vulnerable mechanism removed** during setup by the same rule. | **Deferred** pending a specific retry model. |
| H-03 concurrent ledger owners emit different wires | **Operationally closed:** there is no recovery ledger; an exclusive process lease plus no-replace reservation and three witnesses refuses a second owner. | **Operationally closed** by the same setup control. | **Residual under the stated threat model** until an integration defines exclusive ownership. |
| H-04 missing ledger reopens an old CeremonyID | **Vulnerable mechanism removed:** external witnesses permanently record every ID; missing local state is terminal and a retry has a fresh ID and all-fresh secrets. | **Vulnerable mechanism removed** by the same setup rule. | **Residual under the stated threat model** unless the alternative is externally monotonic. |
| H-05 coherent rollback is undetectable | **Operationally closed** against coordinator/one-principal rollback by cross-stored, signed append-only witnesses under three distinct administrators. | **Operationally closed** under the same assumption; epoch lifecycle also uses the witness. | **Residual under the stated threat model:** operational monotonicity is still required. |
| H-06 public wires unauthenticated/unbound | **Cryptographically closed:** every share has the signed ceremony/context/roster/scope/epoch/sender/operation/round/transcript/payload envelope and sender is derived from its signature. | **Cryptographically closed** by the same envelope. | **Deferred** pending a concrete alternative transcript. |
| H-07 mutable unsigned KeyID and provenance-poor bundle | **Cryptographically closed:** every operator derives immutable KeyID from reconstructed bytes, signs it, and seals a new bundle binding ceremony, scope, roster, transcript, manifest, and runtime. | **Cryptographically closed** with positive epoch and privacy-domain fields. | **Deferred** pending an alternative key identity and bundle format. |
| H-08 unsigned activation/expiry/revocation | **Cryptographically closed:** immutable lifecycle fields are in the all-operator manifest; mutable status is a separate monotonic 2-of-3 statement. | **Cryptographically closed** by the same mechanism, but reusable lifecycle implementation is deferred from RC2. | **Deferred** pending an alternative lifecycle integration. |
| H-09 leak/isolation evidence tests the wrong properties | **Vulnerable mechanism removed:** no central process opens raw shares, no live share is a canary, and each administrator produces an operator-local signed audit over every named secret class and required storage root. Physical erasure remains unclaimed. | **Vulnerable mechanism removed** only with the same evidence design. | **Residual under the stated threat model:** evidence quality is independent of the library. |
| H-10 success evidence is not bound to reviewed source | **Operationally closed:** fresh evidence must run from a clean exact commit/tree, retain complete source/toolchain/build inventory, exact binaries or immutable CAS references, raw public artifacts, signed local reports, and runner output. | **Operationally closed** by the same evidence rules. | **Residual under the stated threat model:** the alternative still needs reproducible evidence. |
| M-01 positive control duplicates the live share | **Vulnerable mechanism removed:** positive controls use independent synthetic values of the same shape/length and never production secret bytes. | **Vulnerable mechanism removed** by the same rule. | **Residual under the stated threat model** until evidence tooling is specified. |
| M-02 public/private publication is non-atomic | **Operationally closed:** staged bundles are fsynced and no-replace published; activation occurs only after all public hashes, three private-ready attestations, and one signed authoritative index agree. | **Operationally closed** by the same publication state machine. | **Residual under the stated threat model** until integration publication is designed. |
| M-03 context binding optional on legacy resume | **Vulnerable mechanism removed:** context is mandatory for every process and verifier; legacy/contextless modes and old bundles are unconditionally rejected. | **Vulnerable mechanism removed** with the reusable-scope context discriminator. | **Deferred** pending a concrete alternative context. |
| M-04 JS inspector does not authenticate concrete binaries | **Operationally closed:** one canonical verifier parses every concrete public/evaluation object, recomputes the entire manifest/hash graph, and emits a signed/witnessed evidence report. | **Operationally closed** by the same verifier. | **Residual under the stated threat model** until an alternative canonical verifier exists. |
| M-05 source-tree evidence omits runner sources | **Operationally closed:** record the exact Git tree object plus a full tracked executable/configuration inventory covering Go, MJS, JS, TS, package and lock files, toolchain, build command, clean status, binaries, and raw outputs. | **Operationally closed** by the same evidence rule. | **Residual under the stated threat model:** reproducibility remains an integration duty. |

The review's informational positives—exact replay from an intact single-process ledger,
semantic reshare caching, capsule corruption detection, direct binding of private wires,
and the normal runner's session-context graph—remain historically accurate. They do not
justify retaining any part of the recovery mechanism in Option A.

## Performance and product trade-offs

Only historical measurements above are available. No latency, memory, or disk improvement
is assigned to the proposed one-shot design without a fresh run.

| Dimension | A — ephemeral one-shot | B — reusable epoch | C — alternative |
|---|---|---|---|
| Ceremony latency | Paid for every session; unmeasured. Rejected recovery record took 207.397 s across restarts. | Setup cost could be amortized, but no measurement exists. | Unknown. |
| Public bundle | New bundle each session; candidate size unmeasured. Rejected bundle was 322.5 MB. | One bundle serves bounded sessions, improving amortization only. | Unknown and format-changing. |
| Operator disk/memory | One live/retained session per key; candidate unmeasured. Historical figures are not transferable. | More retention and concurrent-session state; exact cost unknown. | Unknown. |
| Restart cost | Full fresh ceremony after terminal failure. | Full fresh epoch setup after setup failure; completed epoch remains available. | Unknown. |
| Availability | Lowest: one setup abort prevents completion. | Higher after successful setup, with larger shared failure domain. | Unknown. |
| Session throughput | Setup-bound and therefore lowest. | Higher in principle through amortization; no quantified claim. | Unknown. |
| Compromise blast radius | One bilateral session. | All sessions and allowed queries in epoch. | Unknown. |
| Client integration | KeyID/session binding and status check; narrowest new schema. | Epoch discovery, status freshness, rotation overlap, budget, and compatibility required. | Library/protocol and serialization port. |
| Future migration | Explicit discriminator preserves a clean path to positive epochs. | Target schema mode. | Likely widest migration. |

Removing persisted recovery mechanisms reduces retained secret-bearing artifacts by
design, but its performance effect is unmeasured. It must not be marketed as a latency or
storage improvement.

## Kill gates

| Gate | Option A technical result | Acceptance consequence |
|---|---|---|
| 1. Independent concrete-key reconstruction | Pass in source and same-build probe; three-host proof still required | Evidence gate remains before acceptance |
| 2. Authenticated ceremony-bound public shares without primitive change | Pass; serialization/networking are application-layer | Requires implementation and review |
| 3. Coordinator substitution blocked under honest operators | Pass with all-three independent exact-byte attestations | Does not cover malicious operators |
| 4. Custody supports intended claims | Pass only with three hosts and three genuinely distinct administrative principals | C-02 closes operationally; no separate-organization or HSM claim |
| 5. No invented active DKG/ZK | Pass; active operator security is explicitly excluded | Product claim remains bounded |
| 6. Evidence tied to clean source and exact binaries | Feasible for a future fresh run; failed checkpoint cannot satisfy it | New clean commit and exact binary digests required |

Option A passes all six architecture kill gates under the exact threat model. Gate 6 is a
fresh-evidence acceptance condition: the failed checkpoint does not satisfy it, but the
new design can produce evidence tied to a clean commit and exact binaries. The GO decision
authorizes implementation of the one-shot ceremony only; it does not convert future code
or evidence into an automatic pass.

## Post-MVP ReusableKeyEpoch target

The default post-MVP key scope is a bounded privacy domain, never a global Mordant key.
Each positive monotonically increasing epoch has an immutable maximum session count,
maximum release/query budget, short expiry, exact policy/circuit/parameter binding, and a
fresh KeyID.

The default topology is three genuinely separate administrative principals: one operator
run by client A, one by client B, and a neutral operator. Deployment claims must reflect
actual administrative control, not host count.

Lifecycle rules are:

- activate only after all three reconstruct and sign the exact manifest and witness the
  status;
- expire automatically at the immutable deadline or budget exhaustion;
- rotate through a wholly new ceremony and key epoch, with a short, policy-defined
  overlap and no cross-key evaluation;
- allow any operator to stop locally and require 2-of-3 signatures for public terminal
  revocation;
- forbid reactivation, expiry extension, scope widening, bundle migration, and silent
  compatibility fallback.

Edge Clients fetch the manifest and latest status from at least two independent witnesses,
reconstruct KeyID from concrete bytes, verify all three manifest signatures, enforce
scope/epoch/budget/expiry locally, and bind every encryption and enrollment to session,
KeyID, and epoch. They never trust a key or status supplied only by the evaluator.

Migration is schema-driven. RC2 ephemeral records use `keyScope = BILATERAL_SESSION`,
`keyEpoch = 0`, and `maximumSessions = 1`; future epoch records use
`keyScope = PRIVACY_DOMAIN`, a positive epoch, and explicit bounded budgets. Old keys are
expired, never reinterpreted. No architecture or runtime migration is authorized by this
document.

## Implementation sequence

This sequence is authorized only for the new ceremony. No implementation is performed by
this decision handoff.

1. Commit this decision, maintainer-question record, and obsolete-evidence marker as a
   clean documentation checkpoint. Any contradictory future primary evidence reopens the
   decision.
2. Resolve maintainer questions in source or conservatively: pin one build target, test
   exact bytes on all three hosts, and treat message uncertainty as terminal rather than
   depending on randomized regeneration.
3. Freeze the envelope, transcript, manifest, status, private-bundle, publication,
   canonical-verifier, operator-audit, and transparency schemas.
4. Implement only Option A as new code with new schema/magic identifiers. Do not call,
   adapt, migrate, or share durable state with the failed recovery layer, and do not invent
   an active-security proof system.
5. Add negative tests for every audit attack: coordinator key substitution, two-bundle
   access, plaintext-wire persistence, generation/commit crash, concurrent owner,
   missing-state ID reuse, coherent rollback, unsigned/cross-ceremony wire, KeyID drift,
   lifecycle mutation, live-secret positive control, partial/symlink publication,
   contextless mode, opaque-binary inspection, and incomplete source binding.
6. Produce fresh evidence on three separately administered hosts from a clean source
   commit, retaining the complete artifact set defined above and proving exact concrete
   reconstruction by all three operators.
7. Submit the new implementation and evidence to independent review. Only an explicit
   accepted review can authorize downstream client, enrollment, evaluator, release, or
   Monad work.

## Primary sources

- Exact implementation: [Lattigo v6.2.0 source](https://github.com/tuneinsight/lattigo/tree/v6.2.0)
- Network and protocol model: [Lattigo v6.2.0 multiparty README](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/README.md)
- Passive security and retry limitation: [Lattigo v6.2.0 SECURITY.md](https://github.com/tuneinsight/lattigo/blob/v6.2.0/SECURITY.md)
- Paper basis for passive MHE: [Multiparty Homomorphic Encryption from Ring-Learning-With-Errors, ePrint 2020/304](https://eprint.iacr.org/2020/304)
- Paper basis for the threshold access structure: [An Efficient Threshold Access-Structure for RLWE-Based Multiparty Homomorphic Encryption, ePrint 2022/780](https://eprint.iacr.org/2022/780)
- Threshold-cryptography context, not product certification: [NIST IR 8214C](https://doi.org/10.6028/NIST.IR.8214C) and [NIST threshold cryptography project](https://csrc.nist.gov/projects/threshold-cryptography)
- Alternative screened: [OpenFHE official repository](https://github.com/openfheorg/openfhe-development) and [OpenFHE design paper, ePrint 2022/915](https://eprint.iacr.org/2022/915)

## Final authorization

**CEREMONY DESIGN DECISION READY.**

Selected RC2 evidence profile: **GO — EPHEMERAL ONE-SHOT LATTIGO**.

Implementation of the new ceremony may begin after this documentation is committed as a
clean checkpoint. Client, enrollment, evaluator, release, Monad, ABI, and contract work
may **not** begin. The failed checkpoint remains historical only, and the product verdict
remains **PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN**.
