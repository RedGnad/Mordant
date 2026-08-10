# Decision log — network 2-of-3 release path

Tech lead: integrator. Working clone only, `main` untouched.

---

## D1 — Build the endpoint on `ReleaseOperatorV5`, not on `ThresholdOperator`

**Hypothesis going in:** `/v1/release-share` receives a ciphertext plus a `ReleaseDescriptor`,
the operator calls `ValidateReleaseRequest` then `GenerateReleaseShare`, the client combines
with `CombineZeroKeySwitchShares`.

**Code read:** `operator_release_v5.go` header records **external audit finding H-03**: in V4 the
operator's only check was that the ciphertext matched a digest *written by the evaluator*, so the
operator "decrypted whatever the evaluator chose, including a re-encryption of a private input.
The quorum was a signing service, not a check."

**Decision:** wrap `ReleaseOperatorV5`. The operator recomputes the circuit locally from the
enrollments and releases only against the ciphertext it produced.

**Reason:** the agreed spec was the V4 design. Negative control "participant ciphertext as target
must be refused" is literally the H-03 attack; it could not have passed.

**Rejected:** raw `ThresholdOperator.GenerateReleaseShare` behind an HTTP handler.

---

## D2 — No new target authority; the operator derives it

**Question:** how does the operator know the presented target is the authorized result without a
post-result administrative signature?

**Code read:** `OperatorReleaseRequestV5` carries "no plaintext, no result, no claim about what the
circuit evaluated to, and no digest the operator is expected to take on trust". Session facts are
chain-admitted (`v5-session` `chainInputs`: session commitment and nullifier already admitted on
chain, source-record commitments, governance records). `VerifyAndRecompute` emits a named check
list into the evidence.

**Decision:** no new authority. Authority = chain-admitted session + local recomputation.

**Reason:** there is no caller-supplied target, so there is nothing to substitute.

---

## D3 — The Shamir share never leaves the operator

**Code read:** `oneshotceremony/bundle.go:56` — "privateBundle and its thresholdShare field
deliberately remain internal to the completed operator boundary. Public callers can neither parse
nor hold a usable threshold share." And `clearCryptographicSecretsExceptThreshold()` proves the
share is deliberately retained after the ceremony to serve later releases.

**Decision:** add a method on the completed `Participant` that builds a `*ThresholdOperator`
**in memory** from its retained share, then wraps it in `ReleaseOperatorV5`. Nothing serialised.

**Rejected:** exporting a release-compatible operator bundle. Empirically the two formats are
disjoint (`NewThresholdOperator` on a real `completed-*.bin` returns
`invalid threshold operator material`), and bridging by export would breach a documented boundary.

---

## D4 — Import edge `oneshotceremony -> root`

**Code read:** the root package imports no subpackage of the module; nothing imports
`oneshotceremony` except `internal/oneshotruntime` and `cmd/oneshot-provenance`.

**Decision:** `oneshotceremony` may import the root package. No cycle.

---

## D5 — Wire format: compose existing serialisations, invent nothing

**Code read:** `ReleaseDescriptorV5` is 13 fixed-width fields and already has `Digest()`.
`CircuitInputsV5` is six `*rlwe.Ciphertext`, each with lattigo `MarshalBinary`.
`writeSized`/`readSized` already exist in `distributed_threshold.go`.

**Decision:** canonical bounded encoding by composition. No new primitive. ~3-4h.

---

## D6 — Keep the integrator role in one head

**Decision:** no parallel agents until the server interface is frozen. The H-03 trap is subtle
enough that a cold agent would plausibly rebuild the V4 path.

---

## Verified facts underpinning the above

- Dealerless 3-process ceremony runs for real: 243 operations, 33.8 s, evidence bundle exported
  and verified (`success-2aa4b29c074f595e`).
- Roots must be mode `0700` exactly (`runner.go:741`, `evidence.go:217`). Undocumented; cost one
  full cycle. To be documented in bootstrap.
- `MaximumReleaseQueries` and `ReleaseLayout` are sealed into the ceremony context and the private
  bundle, validated non-zero, and **never read by any logic**. Reserved semantics, enforcement to
  be built here.
- Audit finding **H-02** also already fixed in V5: two independently released bits
  (`SameEconomicAsset`, `PolicyConflict`) instead of one conjunction.
- Obsolete under `//go:build obsolete_recoverable_ceremony`: all `cmd/ceremony-*`,
  `thresholdnet/ceremony*.go`. Current in `thresholdnet`: `service.go`, `store.go`.

---

## FLAGGED FOR THE PRINCIPAL — ordering / ROI

`v5-session` already runs the full institutional lifecycle in-process, and it is stronger than the
product spine on every security property: dealerless ceremony, 2-of-3, recomputation-verified
release (H-03), two-bit release (H-02), session ledger, runtime identity pinning.

The product's public run uses none of it. It uses the single-party `mordant-fhe-decryptor`.

Two orderings:

- **Process-split first** (agreed): proves institutional separation. Does not change the product.
- **Spine connection first**: the public run gains recomputation-verified quorum release
  immediately, with zero new crypto and no process work. The
  "designated and Mordant-controlled decryptor" sentence disappears from the documentation.

This is an explicit escalation condition (sophistication vs pilotability), so it is flagged rather
than decided unilaterally. Recommendation below.

---

## D7 — Land the coalition ON the spine, in three increments (decided after scoping)

**Scoping result that decided it:** `governedfhe/decryptor.go` already implements the H-03 defence.
`prepareVerifiedRecomputation` calls `runtime.RecomputeCircuitV5(...)` on the participants' own
pledge ciphertexts and writes a terminal `recomputeMismatch` if the evaluator's result differs.
`release()` also already enforces the canonical release vector (`decoded[0] <= 1` and every other
slot zero), admission, exact retry and consumption markers.

**Therefore the spine is not the naive design.** It differs from the institutional path in exactly
two ways:

1. the decryption step reads the whole secret key and calls
   `rlwe.NewDecryptor(params, secretKey).DecryptNew(ciphertext)` — single party;
2. it releases only `outputs.PolicyConflict` and discards `outputs.SameEconomicAsset`, so H-02's
   two-bit separation exists in the circuit but not in the product.

**Insertion point (exact):** `governedfhe/decryptor.go`, inside `release()`, between the
`releaseAdmission` write and the result signing. Everything before and after is unchanged.

**Switch:** `profile.go:24` holds `ReleaseModeGovernedDecryptor = "governed-decryptor-v1"` as a
single constant, and `release()` already rejects anything else. Adding
`ReleaseModeThresholdCoalition` alongside it is the same union pattern used for
`settlementAuthorization`: the published mode is never weakened, a stronger sibling is added.

**Increment ladder. Each step leaves the spine working and strictly better; no parallel branch is
created at any point.**

| # | Increment | h | What the product gains |
|---|---|---|---|
| 1 | keygen provisions 3 operators (`ProvisionThresholdOperators` + `DetachThresholdParties`); release gains the coalition mode using `ReleaseOperatorV5` x2 + `CombineReleaseBitV5` | ~13 | 2-of-3 recomputation-verified release. **No party holds the whole key.** Both bits released |
| 2 | replace dealer provisioning with the dealerless network ceremony (needs the in-memory Participant -> ThresholdOperator bridge, D3) | ~8 | key never existed whole, anywhere |
| 3 | split the two release operators into separate processes over mTLS | ~10 | institutional separation, not just logical |

**Why this order:** increment 1 is the highest value per hour and the only one that changes the
product. It removes "the governed decryptor is currently designated and Mordant-controlled" from
the documentation. Increments 2 and 3 then upgrade a path that is already on the spine, rather
than perfecting a fourth parallel branch.

**Rejected:** building the network release endpoint first. It would have produced a fourth
architectural branch, unconnected to the spine, while the product kept its single-party decryptor.
That is the failure mode already diagnosed in this codebase (strong pieces never assembled in the
same run) and it trips the "sophistication over pilotability" escalation.

**Honest limit of increment 1:** dealer-based provisioning means the keygen process transiently
holds all three parties before `DetachThresholdParties()`. That is strictly better than one party
holding the whole secret key permanently, and strictly weaker than the dealerless ceremony. The
classification must say exactly that and nothing more.

---

## D8 — Three implementation invariants (principal, accepted without reservation)

**I1. No silent fallback.** If the coalition mode is selected and two operators are unavailable or
do not agree, the run fails closed. There is never a fallback to the central governed decryptor.
Otherwise the trust property degrades from an invariant into an execution preference.

**I2. Claim discipline, per increment.**

| After | May claim | May NOT claim |
|---|---|---|
| #1 | "online release requires 2 of 3 shares; no single provisioned operator can release the result" | "the key never existed whole" — the dealer keygen existed before `DetachThresholdParties` |
| #2 | "no full key ever existed" | |
| #3 | process separation, or host separation | "institutional separation" — that requires genuinely independent administrative domains |

**I3. H-02 preservation.** `SameEconomicAsset` is kept in the evidence and in the canonical result
even though the current policy engine consumes only `PolicyConflict`. It is preserved as a
verifiable fact. **No business consequence is invented for it** and the policy engine is not
changed to act on it. Compressing two distinct properties into one bit is the H-02 mistake.

---

## D9 — Make the 0700 precondition an explicit preflight

**Why:** `runner.go:741` and `evidence.go:217` require the publication, evidence and export roots
to have permission exactly `0700`. The requirement is deliberate and correct, but undocumented. It
cost a full ceremony run to diagnose from an intentionally opaque `ONESHOT_RUNNER_FAILED`. Tribal
knowledge that costs a run costs a pilot.

**Decision:** validate the three roots at `oneshot-runner configure` time, which is the step that
receives them as arguments and runs before anything else, and emit an actionable message naming
the offending path and the required mode. Document it in the runtime README.

**Not changed:** the requirement itself, nor the opaque failure of the ceremony proper. Only the
configuration step gains a useful diagnostic.

**D9 status: DONE.** `cmd/oneshot-runner/main.go` gains `requireExclusiveDirectory` and a preflight
loop in `runConfigure`; `examples/oneshot-runtime/README.md` documents the mode and the
`install -d -m 700` command. Four cases exercised: missing, not-a-directory, symlink, mode 0755,
plus the pass case. Regression: full three-process ceremony re-run green
(`ONESHOT_SUCCESS ceremony=51be169e…`, evidence exported); `go vet` clean; `internal/oneshotruntime`
and all `cmd/...` suites pass.

---

## D10 — Increment 1 has a hidden dependency: the product has no enrollment layer

**Measured, not guessed:**

- `SignedCiphertextEnrollment` (V4) appears **zero** times in `governedfhe/`. The product never
  adopted the V4 enrollment layer either.
- The product's participant model is `CipherPledge` only: 11 occurrences across 4 non-test files
  (`ciphertext_validation.go`, `client.go`, `evaluator.go`, `participant_originated_artifact.go`).
- The product is **V5 on the circuit** (`RecomputeCircuitV5`, `CircuitInputsV5/OutputsV5`) and has
  **no enrollment/issuer-signature layer at all**.

**Why it matters:** `ReleaseOperatorV5.VerifyAndRecompute` runs 14 named checks, of which
`enrollment-a-signature`, `enrollment-b-signature`, `bilateral-pairing`, `input-digests` and
`descriptor-session-binding` are all built on `CiphertextEnrollmentV5` / `SessionBindingV5`. Without
issuer-signed V5 enrollments those checks cannot pass, so `ReleaseOperatorV5` cannot be dropped into
the product's release path as scoped.

**The mapping is favourable, though.** `CipherPledge` already carries exactly the three ciphertexts
the V5 circuit reads (`PolicyBits`, `CurrencyBits`, `ReceivableIDBits`), and the product already has
a participant admission authority: the EIP-712 `ParticipantAdmissionV1` gated on Cleanverse A-Pass.
The V5 enrollment issuer role maps onto that existing authority rather than introducing a new one.

**Consequence:** increment 1 is larger than scoped (~13h assumed a drop-in). Escalated separately.

---

## D11 — A, in two deliverables. B eliminated.

**B eliminated on principle, not on cost.** It returns the authority to choose the ciphertext to the
spine and turns the operators into an execution quorum. That is the shape of H-03, which V5 exists
to remove by making every operator recompute. Saving 8-10 hours by buying a largely cosmetic
"2-of-3" is not a trade worth making.

**Corrected conceptual model** (my earlier phrasing "A-Pass signs the enrollment" was wrong):

```
Cleanverse-gated participant admission
  -> existing participant authorization (wallet, run, FHE case, asset identity,
     policy, role, participant signing key, encryption intent, claim commitment,
     exact encrypted artifact digest)
  -> durable V5 enrollment
  -> operator independently verifies the enrollment
  -> operator independently recomputes the circuit
  -> 2-of-3 release
```

Cleanverse gates admission. The existing signatures and commitments authenticate the participant and
its artifact. The V5 enrollment **transports that truth into the release boundary**. No new authority
is introduced; an existing one is expressed in the format the release operators can verify.

**Deliverable 1:** issue and verify durable V5 enrollments on the existing path. The product keeps
releasing through its current decryptor. Enrollments are real, stored and verified. Has standalone
value and de-risks deliverable 2.

**Deliverable 2:** the 2-of-3 coalition release consuming those enrollments.

**Why the surcharge is worth it:** today Cleanverse gates admission in TypeScript. After this, the
admission it gates becomes a cryptographic precondition consumed by the parties able to release the
result. That is the 30-point axis, and it is the only path that makes the sentence true rather than
staged.

---

## D12 — Field-by-field delta: the product does have a session, bilaterally signed

I revised increment 1's scope twice by discovery. Rather than revise a third time, here is the
complete delta between the product's session model and `SessionBindingV5`.

The product's session is `FHECaseManifest`: an `FHECaseBinding` plus `SignatureA` and `SignatureB`.
**Both participants sign it.** It is a real bilateral commitment; it is simply not chain-published
in the managed profile.

| `SessionBindingV5` field | Product source | Status |
|---|---|---|
| `SessionCommitment` | `FHECaseManifest.Digest()` | derivable; genuine commitment, locally bilateral rather than chain-admitted |
| `SessionNullifier` | `Binding.CaseNonce` | derivable |
| `OwnScopeCommitment` / `CounterpartyScopeCommitment` | `ParticipantA` / `ParticipantB` identity digests | derivable |
| `GovernanceRecord` | participant admission verification digest | derivable |
| `SourceRecordCommitment` | participant `ClaimCommitment` | derivable |
| `AuthorizationEpoch` / `SubmissionBudgetEpoch` | absent | fixed at 1 for the managed profile, documented |
| `InputSlot` | role: A = 0, B = 1 | trivial |

And for `CiphertextEnrollmentV5` the mapping is near-total from
`ParticipantOriginatedArtifactVerification`: `CiphertextDigest`, `FHEPublicKeyDigest` -> `KeyID`,
`ParameterFingerprint`, `ClaimCommitment` -> `AuthorizationCommitment`, `SubmissionNonce` -> `Nonce`,
`VerifiedAtUnix` -> `IssuedAt`, `ExpiresAtUnix` -> `ValidUntil`, `ParticipantID` -> `SubjectCommitment`,
`Role`, plus `PolicyID`/`PolicyVersion` from the case manifest.

**Decision:** populate `SessionBindingV5` from the bilaterally signed case binding. No chain work,
no new authority: the two participant signatures already are the authority. The evidence must state
explicitly that in the managed profile the session commitment is **locally bilateral, not
chain-admitted**.

**Forward-compatible, not a shortcut:** when the product later runs against a chain-admitted session
(the `v5-session` `chainInputs` model), the same code path takes chain values instead. Same
structure, different provenance.

**Estimate stabilised.** Deliverable 1 (issue, store and verify durable V5 enrollments on the
existing path): ~10h. Deliverable 2 (2-of-3 coalition release consuming them): ~13h. No third
revision expected: every field of every V5 structure now has a named source.

---

## D13 — The enrollment issuer is the participant, not a new authority

`SignEnrollmentV5`'s doc says the issuer is "the authorized ingress issuer". The product has no
such role, and inventing one would have added an administrative authority the invariants forbid.

Enumerating every `signCanonical` call site showed the product has exactly two signing identities:
the two participants, and the release authority. What a V5 enrollment asserts is a fact about one
participant's own submission, and both participants already sign the case binding that names each
other's keys.

**Decision:** each participant issues its own enrollment with the key the binding admitted for its
role. The release-side trust store is built by registering those two keys, read from the signed
binding, for exactly the session window. Nothing is configured.

This makes `PairEnrollmentsV5` meaningful here: each side independently names the counterparty it
consents to be compared against, which the product previously had only implicitly through a shared
binding signature.

## D14 — `AuthorizationClaim.Vault` is the deployed case adapter, verified on chain

`Vault` is `address vault` inside the EIP-712 type string `ConfidentialSubmitterAuthorization`.
Filling it from a truncated digest would put a non-address into a signed field that says it is one.
The product carries no 20-byte value anywhere, so there was no in-repo source.

Read at primary source (Monad testnet, chain 10143, `eth_getCode` + `eth_call`): the hardened case
adapter at `0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1` is live, 10088 runtime bytes, keccak
`0x3fe60ba9…`, matching `docs/evidence/hardened-case-adapter-deployment-2026-08-07.json` exactly.
Its immutables read back as `assetIdentityDigest 0x7613136e…`, `parameterFingerprint 0xd0f85e99…`,
`circuitHash 0x2c166039…` — the same values the FHE case computes.

**Decision:** a small asset-keyed table in `governedfhe/enrollment_v5.go` maps asset to deployed
adapter, with one on-chain-verified entry. Issuance refuses an asset with no deployed adapter
rather than inventing an address. Release requires both participants to have named the same vault.

**Correction to D12:** the chain admits more than D12 credited. Parameters, circuit and asset are
immutable on a live contract. What is *not* chain-admitted before the FHE runs is the per-case
session commitment: the adapter is per-asset, and the case binding digest reaches the chain only
when a result is settled. That is the honest statement, and it is stronger than "locally bilateral".

**Flagged for increment 3:** `expectedGovernedReleaseAuthorityId` is a single immutable authority
ID. A threshold coalition cannot satisfy it without a contract change. This blocks the end-to-end
"institutionally decentralized" story, not increments 1 or 2.

## D15 — Enrollments are derived, never re-serialized; issuance time is the session's own

Two decisions that removed wire surface rather than adding it.

The stored record carries the signature plus audit-legible facts, never a parallel encoding of
`fhe.CiphertextEnrollmentV5`. The enrollment is a pure function of the case facts, the artifact and
the role, so it is re-derived on every read and each stored field is compared against the
re-derivation. An edited record is refused even where the edit would not have changed the signature.

`IssuedAt` is the session's creation time, not a wall-clock reading. The participant and the
coordinator then derive identical bytes without agreeing on a clock, and no issuance timestamp has
to travel. When the participant actually signed is recorded by the artifact and the import journal.

`EnrollmentCaseFacts` is the intersection of what the two producers hold: the coordinator reads the
signed binding, a direct participant only ever receives its ceremony bundle. `CaseNonce` is in the
binding but not the bundle, so the session nullifier is derived from the binding digest under its
own domain. A test asserts both constructors produce identical facts for one case.

Consequence stated honestly: with no salt on the binding digest, the nullifier carries the same
information as the session commitment and adds no independent double-submission detection. The
code says so.

## D16 — Increment 1 delivered: what is true and what is not

**True, and tested.** Both product paths issue durable V5 enrollments signed by the participant.
The release boundary loads both, verifies each against a binding-derived trust store, pairs them
(the H-01 gate), and checks the pair authorizes the ciphertexts this case actually holds. It runs
before recomputation and fails closed: there is no path that releases a pair the enrollments do not
authorize. On the direct-participant path the enrollment is written before the manifest, so
manifest-last remains the single marker of a complete releasable input.

Negative controls, all passing: missing enrollment (either role) · six record edits including a
foreign ciphertext, a foreign vault, an extended validity and a restated signing digest · swapped
A/B records · a cross-session enrollment that is valid where it was issued and authorizes nothing
here · the counterparty's key · a key the binding never admitted · an asset with no deployed
adapter · the vault resolving to the on-chain-verified adapter.

**Not true yet, and not claimed.** Release is still performed by the single governed decryptor
holding the secret key. Enrollments authorize *which pair may be released*; they do not yet
distribute *who can release it*. That is deliverable 2. Nothing here is evidence of threshold
release, operator independence, or institutional decentralization.

## D17 — Deferred: recording enrollment digests in the public evidence bundle

The enrollments now gate release, so an evidence bundle that does not mention them under-describes
what authorized the result. Recording their digests in `PublicEvidence` is the right end state.

It is deferred rather than done, because the blast radius is cross-stack and unrelated to the
release path: `EvidenceSchema` is `mordant.governed-fhe-public-evidence/2`, pinned in two published
evidence documents under `docs/evidence/conflicting-pledge-protection/` and compared with strict
equality by `src/lib/protection/protection-evidence.ts` and `protection-evidence-metadata.ts`.
Bumping to /3 means regenerating both documents and updating the TypeScript verifier and its tests.

Done now instead, at no schema cost: both enrollment objects are in `expectedPublicFiles`, so an
unexpected file still fails the export, and both are in the secret-leak scan that every public
object passes before evidence is written.

Estimate for the deferred item: ~4h including regenerated documents and TypeScript verifier tests.
It should ride with the next change that already touches the evidence schema rather than alone.

---

## D18 — Pre-existing flake found while establishing the L2 baseline (not fixed, logged)

`TestParticipantOriginatedNonceClaimIsAtomicAcrossRoles` fails intermittently under load and
reproducibly at `-count=300`. It reproduces identically on a pristine tree, so it is not introduced
by L1.

Diagnosed rather than guessed. Over 400 races: 400 winners, 398 losers whose exclusive create fails
and whose subsequent read succeeds (so they correctly report a replay), and **2 failures coming from
`openObjectStore` itself** when two goroutines create the same not-yet-existing root at the same
time. The test sends open errors and claim errors down one channel, so its message blames the claim.

**Fail-closed, not a security finding.** Exclusivity is never at risk: the exclusive create still
admits exactly one winner. The loser is told the wrong reason for losing, and a first-time
concurrent open can fail where a retry would succeed.

I first "fixed" the claim path by letting the read decide instead of a separate existence probe.
The measurement showed that path was not the cause, so **the change was reverted**: an unjustified
edit to a security-sensitive journal path is not worth carrying, and a fix that fixes nothing
measurable is not a fix.

Left for a dedicated change, because the real fix touches `openObjectStore`'s root creation, pinning
and path-identity checks, which are security-sensitive and unrelated to the release path:
- make root creation idempotent under concurrent first open, or
- require the root to pre-exist, as the oneshot runtime already does (see D9).

Reachable in the product: two roles publishing concurrently on a journal root's first use.
Reproduction: `go test -run TestParticipantOriginatedNonceClaimIsAtomicAcrossRoles -count=300`.

---

# L2 — coalition release in the product spine

## D19 — SECURITY FINDING in L1, corrected: the enrollment bound the wrong digest

L2 surfaced a real defect in what L1 shipped, and it is a security finding rather than a
refinement, so the "do not revisit L1" instruction does not cover it.

L1 set `CiphertextEnrollmentV5.CiphertextDigest` to the sha256 of the stored submission object.
The V5 release operator compares that field against `CircuitSideDigestV5`, a keccak over exactly
the three ciphertexts the circuit reads for that side. The operator refused every release with
`input-digests: received ciphertexts are not the ones the enrollments authorize`.

The operator's definition is the correct one, and the reason is written in its own source: the
submission object also carries amount and obligation ciphertexts the circuit never reads, so its
digest cannot answer the question an operator has to answer, "are these the inputs this enrollment
authorized me to evaluate?". An enrollment binding the whole object leaves the operator trusting
whoever extracted the circuit inputs from it. That is the V4 weakness V5 exists to remove, and L1
had reintroduced it.

**Corrected.** The enrollment now binds `ParticipantCircuitSideDigest`, computed from the three
circuit ciphertexts. Both producers compute it from the ciphertext they just encrypted; the release
boundary recomputes it from the ciphertext the case holds and never reads it from the record. The
stored record keeps the submission-object digest as an audit field and adds `circuitInputsDigest`
as the value actually signed; both are compared against the re-derivation.

## D20 — Decisions taken while building the coalition path

**The ceremony driver is shared, not copied.** `runCeremony` lived in `cmd/v5-session`. Rather than
carry a second copy into the product, it moved to the library as `RunColocatedCeremony` and the
reference runner now calls it. One round sequence, two callers.

**`CreateCase` is parameterised, not forked.** A coalition case is `CreateCase` with
`ReleaseMode: ReleaseModeCoalitionV5` and three operator roots. It runs the ceremony instead of
generating a case secret key, publishes the threshold manifest, and writes one sealed share per
root. **No secret key object is created**, so "no fallback" is a property of the case, not a rule
someone has to remember to follow.

**The coalition has no authority key.** `FHECaseBinding.validate` is now mode-dependent: a governed
case carries one ed25519 authority key, a coalition case carries none and its authority identity is
the digest of the published threshold manifest. A key here would recreate the single signer the
coalition exists to remove, so one is refused rather than ignored.

**Custody labels follow the mode.** A ceremony key advertised as a governed ephemeral case key
would claim a single-party origin it does not have. Added `NewCeremonyExternalClient` and
`NewCoalitionEvaluationRuntime` as siblings of the governed constructors, and routed every client
construction through one mode-aware helper.

**Each operator has its own evaluator and derives its own trust store.** They do not share one
runtime object, and none is handed a list of issuers: each derives the enrollment trust store from
the signed case binding for itself. An operator told whom to trust is trusting the teller. This
also required the deterministic public circuit constant, otherwise two honest operators produce
different bytes and comparing their digests would be meaningless.

**The coalition is named before verification, and there is one attempt per session.** Each operator
checks that it is a member of the coalition it is asked to serve, so the coalition cannot be chosen
after the fact from whoever happened to accept. Its members are drawn from the operators that are
reachable, which is how the case survives losing one of three. A refusal is terminal for the
session because an operator's ledger admits a session once, so a second coalition sharing a member
could not be tried afterwards. This is stated in the code rather than worked around.

**Operator refusals are readable.** The fourteen named checks existed but their outcomes were
discarded. A quorum failure now names the failing check per operator, which is how each of the
three integration defects above was found in one run each instead of by bisection.

## D21 — The released result carries the operators' signatures, not just their digests

The first version of `CoalitionConflictResult` recorded `OperatorStatements` as bare digests. The
release path verified the real ed25519 signatures during share combination, but the published
result did not carry them, so a third party had to take the coordinator's word that the coalition
had attested. That is the gap between an auditable result and an assertion.

`ThresholdReleaseResponse` already carries a signature over the statement digest, from the key the
threshold manifest publishes for that operator's point. The result now records, per released bit
per serving operator: the point, the slot, the statement digest and the signature. A verifier reads
the threshold manifest for the public keys and checks them directly.

Done now rather than deferred because the schema is new and unpublished, so it cost nothing; the
same change against a published schema would have been D17's problem.

## D22 — L2 status

Delivered and tested: a 2-of-3 coalition releases both V5 bits on the canonical product path, each
operator verifying the L1 enrollments and recomputing the circuit on its own evaluator with a trust
store it derives itself. One operator is not enough. Losing one of three is survivable; losing two
fails closed. There is no secret key, no authority key and no private case manifest anywhere in a
coalition case, so there is nothing to fall back to rather than a rule not to.

Not delivered, and not claimed: operator process independence, institutional decentralization, and
any settlement of a coalition result on chain.

## D21 — The released result carries the operators' signatures, not just their digests

`ThresholdReleaseResponse` carries a real ed25519 signature over each statement digest, from the
operator's own key, and that key is in the published threshold manifest. The first version of
`CoalitionConflictResult` recorded only the digests.

The release path verified the signatures during combination, so the release itself was sound. But
the published result did not carry them, which means a third party had to take the coordinator's
word that the coalition attested. That is the difference between an auditable result and an
assertion, and the schema was new and unpublished, so fixing it cost nothing.

`OperatorStatements` is now one record per released bit per serving operator, carrying the point,
the slot, the statement digest and the signature. A verifier can check each signature against the
manifest's key for that point without trusting us.

## D22 — Operator unavailability is diagnosable, and a foreign share is refused by name

`openOperators` silently skipped any operator it could not load. An unavailable quorum caused by
three corrupt bundles then read exactly like one caused by three offline hosts, and those need
different responses. Each skip now records its reason and the quorum error reports them.

Added while doing it: a loaded share is checked against the case's published threshold manifest by
point, operator id and signing key together. A share from another ceremony is refused by name
rather than incidentally failing later.

## D23 — D18 was wrong. The store was right; the test's barrier was misplaced

D18 attributed the `TestParticipantOriginatedNonceClaimIsAtomicAcrossRoles` flake to a race in
`openObjectStore`'s root creation and left it as a product defect for a later change. That was a
guess dressed as a diagnosis, and it was wrong. Re-probing the exact creation sequence passed
1200/1200.

The real cause, and it is not a defect: `usedBytes()` runs during every open and **refuses outright**
if it sees a `.mordant-create-` temporary, because the store is a single-writer capability and a
stray temporary means either a crash remnant or a concurrent writer. Failing closed there is the
correct behaviour.

The test released its barrier with `close(start)` as soon as both goroutines were *spawned*, not
once both had finished opening. One side then began creating its claim temporary while the other
was still scanning, and that side reported a store failure instead of the replay the test is about.
The test also sends open errors and claim errors down one channel, so its message blamed the claim.

**Fixed in the test**: the barrier now waits on a `sync.WaitGroup` until both stores are open.
800 consecutive runs pass, where 300 previously failed reproducibly. No product code changed, and
no invariant was weakened to make a test pass.

This was the pre-existing `fhe-go` CI failure on `main`, including on the baseline `62504f2` this
work branched from. Two lessons, both mine: a diagnosis is not a diagnosis until it reproduces, and
"out of scope for this increment" is not the same as "not a blocker for the repository".

## D24 — Why the reserved name `threshold-2of3-v1` was not used

`ReleaseModeThreshold2Of3 = "threshold-2of3-v1"` already existed and reads like a reservation for
exactly this work. It was not taken, for two reasons. It is used across the suite as the canonical
"some other mode" in refusal tests, so promoting it to a known mode would silently delete those
tests' meaning. And it hardcodes the quorum in the identifier, which becomes a lie the first time
the threshold changes. `coalition-v5` names the property that matters, not today's parameters.

---

# L3 — settling a coalition release

## D25 — The seam was already right; only the identity changed

`deriveSettlementPlan` carries the comment "this is the only place where a governed result meets
committed economics, and it reads exactly one field from the result". That separation is what L3 had
to preserve, and preserving it turned out to require **no change to it at all**. The profile already
accepts a release authority as `sha256:<hex>` or `0x<hex>` and compares case-insensitively, so
committing the threshold manifest digest works unchanged.

What changed is one leg upstream: `verifyGovernedResultSignature` checks one Ed25519 signature, and
a coalition has no such key. `verifyCoalitionEvidence` replaces it and returns the same
`GovernedResultFacts`.

The enabling discovery was in the threshold layer: an operator's statement signature is
`ed25519.Sign(key, StatementDigest[:])`, a plain signature over 32 bytes the result already
publishes. Verifying a quorum in TypeScript therefore needs no reimplementation of the threshold
encoding, which is what would have made a second implementation a drift risk.

## D26 — Adapter V3 rather than reusing the deployed one

The deployed adapter compares `expectedGovernedReleaseAuthorityId` as data and never verifies a
signature, so a coalition digest would fit its logic untouched. It was still not reused, for two
reasons.

The immutable's name and NatSpec say "the Ed25519 governed release authority". Putting a coalition
manifest digest behind that name would be a field that lies, in a codebase whose whole discipline is
that names do not. And V2's single `conflict` Boolean has exactly the shape H-02 identifies as
unable to distinguish "different receivable" from "same receivable, no policy conflict".

A case-specific adapter is already the deployment pattern, not a workaround: the reviewed V2 doc
states a per-case deployment is required because the release authority is minted per case. A new
version is therefore the normal cost, not an escalation.

`MordantCoalitionAdapter` pins the manifest digest and the required quorum, carries both bits,
refuses `(sameEconomicAsset=false, policyConflict=true)`, and refuses a quorum of one **at
deployment** rather than only at release. Every economic control is byte-identical to V2 so the two
can be diffed.

## D27 — The proof uses the spine's own digests

The Foundry suite reads a fixture emitted by a real 2-of-3 coalition release rather than synthetic
keccaks. A test on synthetic values would show the contract is internally consistent; it would not
show that what the spine releases is what this adapter settles.

The fixture's `circuitDigest` and `parameterFingerprint` equal the immutables read from the deployed
adapter on chain, which is an independent cross-check that the coalition ran the circuit and
parameters that contract pins.

`fs_permissions` was added to `foundry.toml`, read-only and scoped to `./test/fixtures`.

## D28 — L3 status

**True and tested.** 14 Foundry tests, including the whole path from reserve through consume, cure
window, finalize and both claims, with solvency asserted throughout. 12 TypeScript tests over the
real evidence, including the unchanged `deriveSettlementPlan` producing a plan whose identity is the
coalition's and whose economics are the profile's. 322 contract tests still pass.

**Not true, and not claimed.** The adapter is executed locally, not deployed to testnet. The
TypeScript verifier does not re-derive each statement's binding to this release. Operator process
independence and institutional decentralization remain undelivered.

## D29 — The binding gap, and why it needed a second round

Review found that the settlement verifier authenticated a quorum of signatures over opaque statement
digests and then read `sameEconomicAsset` and `policyConflict` straight from the result. It could not
detect a result edited after production. The finding was correct, and I had flagged the same gap
without closing it.

The constraint that shapes the fix: **an operator generates its release share before any bit
exists.** That is what a threshold is for. No signature produced during the release can attest a
value, so the gap was not a missing encoding, it was a temporal impossibility.

**Fix: a short second round.** After combination, each serving operator recombines both bits itself
with `CombineReleaseBitV5`, against the ciphertexts it recomputed, and signs a canonical settlement
statement naming case, binding, asset, release identity, transcript, coalition and both bits, only
if it obtains those bits. The verifier rebuilds that statement and requires a quorum of signatures.

No new crypto: `CombineReleaseBitV5` and the canonical signing shape already existed. No new
authority: the signers are the same operators, with the keys the manifest already publishes. No
threshold encoding reimplemented in TypeScript.

Two properties made explicit in code rather than assumed. `SignSettlementStatement` requires the
domain prefix and a message longer than 32 bytes, while threshold statements are signed over a bare
32-byte digest, so neither signature can be replayed as the other. And sharing the quorum's shares
for these two ciphertexts grants no new capability: the operator contributed one, and the shares
decrypt those two ciphertexts only.

Three existing tests then failed, which was the fix working: they mutated the bits, and mutation now
breaks the signatures. Two were rebuilt on a genuinely released non-conflicting branch rather than an
edited one, which is stronger evidence anyway. The canonical-vector check stays as defence in depth,
now unreachable from an authentically signed result.

---

# Cleanverse-native path

## D30 — Why the two identities were unlinked, and where the join goes

`governed-fhe-product-server.ts:1128` mints the participant's Ed25519 key **server-side**, and the
wallet never sees it. `ParticipantAdmissionV1` proves a CVI-eligible wallet consented to a case; the
enrollments are signed by that server-minted key. Nothing tied them, so "the participant" was two
unrelated identities.

`ParticipantAdmissionV2` adds one field: the digest of the key authorized to sign that wallet's
enrollments. The digest is **derived from the key the case binding publishes**, never compared
between two supplied values, so an admission cannot name a key the case does not publish.

A new EIP-712 type rather than a field on V1: changing V1 would move its type hash and invalidate
every retained admission, and the governed path still uses V1 and gains nothing from a rule it was
not built under.

**Ordering consequence, not yet wired into the live server**: for a wallet to name the key, the key
must exist before the admission is signed. Today the server mints it during case creation. The
canonical scenario exercises the correct order with the real modules; moving the live server's key
minting ahead of admission is the remaining wiring.

## D31 — Live revalidation at the only boundary where value moves

`claim()` now consults two independent Cleanverse authorities, both read live:

- the holder's identity, through `isEligible` -> the CVI verifier -> the A-Pass;
- the asset's own policy, through `isAssetTransferAllowed`, which the settlement token resolves for
  itself and which can refuse what the identity gate allows.

`MordantInvoiceVault` already consults the second at its own release. This is the same boundary for
the same reason, so it is the repo's idiom rather than a new compliance layer. The two failures have
distinct errors because they call for different responses.

The checks are at `claim` only. `cure` and `finalize` move no value, and `fundReserve` /
`withdrawAvailable` are administrative transfers the token enforces for itself.

## D32 — A measurement I nearly reported as a finding, wrongly

Probing `isEligible(0xdEaD, ROLE_HOLDER)` returned true and I was about to report that the deployed
A-Pass admits everyone, which would have emptied this milestone of meaning.

It is false. `0x…0001` and `0x1111…` are refused; `0xdEaD` passes because it **holds a real A-Pass**
(`balanceOf` = 1). I generalised from one unlucky probe. The verified position is the opposite and
better: the A-Pass gate genuinely refuses arbitrary addresses, and `openRoleMask = 16` opens the
holder role to any address that holds a valid A-Pass.

**Claim discipline on the asset policy.** `canTransfer(aUSDC, adapter, …)` returned true for both
recipients tested. The policy is consulted and enforceable, and the adapter fails closed when it
refuses. It is **not** claimed that the currently deployed configuration has refused any recipient.

## D33 — Milestone status

One case demonstrates: eligible wallets -> V2 admissions naming the exact published keys -> real
enrollments -> 2-of-3 coalition -> released result -> settlement plan whose identity is the coalition
and whose economics are the pre-committed profile -> payout, with live identity and policy checks at
the claim. The negative controls run on the same path: a key no wallet admitted, a lapsed admission,
a profile committed to another coalition, an identity that lapses after the result, and a policy that
turns against a pending transfer.

Remaining, and not claimed: the live server still mints the signing key during case creation rather
than before admission; the adapter is executed locally, not deployed to testnet.

## D34 — Stabilisation pass: an admitted key is committed (F-05)

Branch `fix/admission-v2-stabilisation`, one commit per audit finding: F1 `6d63d52` (browser parser
pinned to V2, with a seam test that drives the real server challenge into the real browser parser),
F2 `2e9ce09` (per-schema projection in the bridge evidence), F3 `ca55425` (named measurement field
sets, both shapes recognised so retained evidence keeps its pinned digests), `19e8cef` (two stale e2e
assertions realigned on the shell header), F4 `6705233` (the live server itself follows the V2 order).

F-05 closed three holes in `rawParticipantKey`, not the one reported:

1. A **truncated** key was reminted whenever `recoverTruncated` was set. That flag is
   `preFoundation`, and under the V2 ordering admissions now happen before foundation, so the flag
   no longer means "nobody has committed to this key".
2. A **missing** key file was reminted unconditionally, ignoring `recoverTruncated` entirely. This
   was the wider hole and it was not in the finding as written.
3. A **substituted** well-formed key was accepted, because only the length was checked.

The fix does not tighten the flag; it changes what the decision is keyed on. The question is no
longer "are we before foundation" but "has a wallet already signed for this key", read from
`ParticipantAdmissionRecord.participantSigningKeyDigest`. Once one has, the key file must exist, be
64 bytes, and hash to the admitted digest; any other state is a fault reported at 409, never a mint.
Absence past foundation now also fails closed even with no admission digest, which covers V1-era
records that never named a key.

Recovery is deliberately not automatic. Reminting would publish a key no eligible wallet authorized,
and nothing downstream would notice, because every enrollment signed by it verifies on its own. Only
a fresh admission can authorize a new key, and that is the participant's decision, not the server's.

`assertPublishedKeysWereAdmitted` stays as a second lock on the publication itself. Its comment
claimed the remint as the threat it existed for; that comment was corrected rather than left to
mislead the next reader.

**Method note.** The four negative controls were run against a deliberately neutralised guard before
being trusted: the three refusals fail without it, the positive control passes in both states. A
negative control that also passes against the unfixed code proves nothing, and this pass exists
precisely because two green per-side suites could not see their own disagreement.

**Correction to D33.** Its remaining limitation, "the live server still mints the signing key during
case creation rather than before admission", was closed by F4 and is no longer accurate. Keys are
minted by `readParticipantAdmissionContext`, before the wallet signs. The testnet deployment of
`MordantCoalitionAdapter` remains outstanding.

## D35 — Re-audit of e89336a: the F-05 guard had broken the live product

The external re-audit returned NOT READY: one new BLOCKER, and F-03 still failing. Both were
reproduced here before being touched, and both were mine.

**N1 (BLOCKER) — a guard that refused a legitimate absence.** The real order is: A is challenged,
admitted, and *submits*; only then is B challenged. Submission deletes A's signing key on purpose
(`rmSync(state.participantKeys[role])`), because that key is consumed. But
`readParticipantAdmissionContextRuntime` materialised *both* roles' keys on every challenge, so B's
challenge met A's legitimate absence and the F-05 guard answered 409. The live product was dead at
B's admission.

The bug predates the guard. Before F-05 this path silently re-minted A's consumed key, which is
exactly the unauthorized substitution F-05 exists to forbid; the guard only turned a silent
vulnerability into a loud failure. So the fix is not to loosen the guard. The admission context is
now per-role: a challenge materialises its own role's key and touches nothing else. Both consumers
only ever read `[role]`, so nothing needed the second key.

**F-03 (HIGH) — the terminal size pin never learned about enrollments.** Measured here, not taken on
report: a real managed run publishes `participant-enrollment-{a,b}.json` at 940 bytes each, and
`governedFheEvidence.measurements.publicArtifactBytes` is 391,686,234 against a pin of 391,684,354.
The delta is exactly the two enrollments. Every new managed run died at `exportProtectionEvidence`.

The pins are now written as a pre-enrollment baseline plus `EXPECTED_ENROLLMENT_BYTES * 2`, so one
number governs both scenarios. Retained documents predate V5 and published no enrollment, so the
addend is conditional on the same marker the field list already uses: the presence of
`enrollmentBytes` in the submission measurement. The marker is read, never the value, because the
value is currently zeroed on the way through `measurements.json` while the files exist regardless.

**N2 (MEDIUM) — the only e2e covering this path never ran.** `e2e/direct-participant.spec.ts` had a
config but no script and no workflow referencing it. Run by hand it failed: the mock still served
`domain.version: "1"`, and, unreported, its message was missing `participantSigningKeyDigest`, which
F-01 had made mandatory. The mock now takes version, schema and primary type from the client's own
exported constants, so it cannot drift again, and the spec is chained into `test:e2e`, which is what
CI runs.

**What this says about the pass.** CI was 8/8 green and the product was broken at two separate
points. The export is not exercised by any CI job (`protection:smoke:*` is local-only), and the one
e2e that covers the two-wallet path was not wired in. Green meant less than it appeared to.

**Method note.** The F-05 controls each drove one damaged key through one call and passed. None
walked the real sequence, which is where the damage was. Isolated refusals are not a substitute for
the order the product actually runs in; the N1 regression test now walks it and fails against the
previous behaviour.
