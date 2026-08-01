# RC2 remediation matrix

Finding by finding, against the external audit that returned NO-GO on all five
RC1 public claims.

Each row states what the auditor found, what changed, and the specific test that
would fail if the correction were reverted. Where a correction is partial or
carries a residual limit, that is stated in the row rather than in a footnote.

RC1 is untouched: all sixteen frozen sources still match `af5baad`, verified by
`scripts/verify-frozen-sources.mjs` on every commit. V5 is a parallel
generation.

---

## Critical

### C-01 - pre-binding participant correlation

**Found.** `register` took the entire `SourceAssetAttestation` as an ABI
argument. Omitting `controller` from the emitted event protected nothing:
transaction calldata is public and permanent, so anyone could decode
`attestation.controller` and join it against the vault's public
`originatorTreasury`. In the M-PRIV8 run both sides used the same originator
address, so the two participants were linkable *before the session was even
committed*.

**Corrected.** `contracts/src/v5/MordantSourceCommitmentRegistry.sol`. A source
is admitted as one salted commitment and nothing else. Public state before
binding is exactly: the opaque commitment, its timestamp and block, and the
policy-authorized submitter address. The controller, invoice root, asset and
terms commitments, schemes, epochs and issuer signature all live in the
preimage, revealed once, at binding, by an authorized revealer, after both
parties have consented.

**Also.** Reveal refuses a commitment whose submitter turns out to be the
revealed controller. The allowlist is policy; this check is proof.

**Reverting breaks.** `testCommittingASourcePublishesNoCorrelatableField`,
`testASubmitterThatIsTheSourceControllerIsRefusedAtReveal`,
`testTheSameAttestationUnderADifferentSaltIsADifferentCommitment`.

**Residual.** Traffic analysis is not addressed and is not claimed. The
submitter address is public by construction.

---

## High

### H-01 - no cryptographic binding between the two enrollments and one session

**Found.** An enrollment authenticated a ciphertext against a policy and a
vault, and nothing else. Two enrollments issued for two entirely different
sessions shared that public context, so the evaluator could pair any A with any
B and both issuer signatures still verified. The pairing was chosen by the
evaluator and attested by nobody. Separately, the one-shot ledger was a Go map,
so a restarted evaluator forgot every session it had run.

**Corrected.** `fhe-lab/lattigo/enrollment_v5.go`. Each side binds the session
commitment, the session nullifier, its own scope, **the counterparty scope it
expects**, its governance record, its opaque source-record commitment, the
authorization epoch, the submission-budget epoch, the input slot, the ciphertext
digest, the input commitment, the policy, a nonce and an expiry. The two
enrollments cross-certify: A is pairable only with a B whose own scope is the
counterparty scope A named, and vice versa. No pair from different sessions
satisfies both directions.

`fhe-lab/lattigo/session_ledger.go` replaces the map with a bbolt ledger that
consumes the session commitment, the nullifier and both enrollment digests in
one fsynced transaction, surviving restart and crash.

**Reverting breaks.** `TestEnrollmentsFromDifferentSessionsDoNotPair`,
`TestASideThatIsNotTheNamedCounterpartyDoesNotPair`,
`TestAReservedSessionSurvivesAnEvaluatorRestart`,
`TestAResaltedSessionIsRefusedByItsNullifier`,
`TestTheSigningDigestCoversEveryBoundField` (17 sub-cases).

---

### H-02 - the circuit does not separately determine asset equality

**Found.** V4 derived both `exactMatchConfirmed` and `conflictConfirmed` from a
single released conjunction, so a false bit could mean "different receivable" OR
"same receivable, terms do not conflict", and the two were indistinguishable.
The system could not answer the question the product is named after.

**Corrected.** `fhe-lab/lattigo/circuit_v5.go` releases two independent
ciphertexts:

```
sameEconomicAsset = identityEqual
policyConflict    = identityEqual AND currencyEqual AND overlap
                    AND exclusiveA AND exclusiveB
```

`policyConflict` has `sameEconomicAsset` as a factor, which is what makes the
(false, true) state structurally impossible rather than merely rejected.
`contracts/src/identity/MordantMatchResultV5.sol` derives a three-state outcome
from the two bits and reverts on 01 at every boundary.

**Reverting breaks.** `TestADifferentReceivableReleasesFalseOnBothBits`,
`TestTheTwoReleasedBitsDecryptToACanonicalVector`,
`testTheImpossibleStateIsRejectedAtTheResultCore`,
`testADeclaredOutcomeMustMatchTheTwoBits`.

---

### H-03 - operators release any evaluator-chosen ciphertext

**Found.** An operator's only check on the ciphertext it was asked to decrypt
was that it matched a digest written into the release descriptor *by the
evaluator*. The operator therefore decrypted whatever the evaluator chose,
including a re-encryption of a private input. The quorum was a signing service,
not a check.

**Corrected.** `fhe-lab/lattigo/operator_release_v5.go`. Each operator
recomputes the circuit itself from the input ciphertexts the enrollments
authorize, and generates shares against **the ciphertext it computed**. The
coordinator's proposed output is never decrypted, only compared, byte for byte,
with no tolerance. Fourteen named pre-release checks run first and are emitted
into the verdict so a reviewer can see which ran.

**Precondition, measured not assumed.** Byte-exact recomputation is only
possible if Lattigo evaluation is deterministic. Gate 1 established this across
30 separate OS processes, two architectures, three key-loading orders, three
thread counts and six restart repeats: one output digest,
`694e3ec8…c702`. Raw data in `gate1-determinism.json`.

**Reverting breaks.** `TestAnOperatorRefusesACiphertextItDidNotCompute`,
`TestAnOperatorRefusesSubstitutedInputCiphertexts`,
`TestAnOperatorRunsEveryCheckBeforeReleasing`.

**Cost, not optimized away.** ~9.2 s of recomputation per operator; both
operators concurrently take 10.1 s wall against 20.1 s summed. A refused release
costs a full recomputation by construction, because an operator cannot know the
output differs until it has computed its own.

**Residual.** Gate 1's determinism is scoped to one host, one OS and one Go
toolchain; the `amd64` runs executed under Rosetta 2, not native x86-64. Cross-
host and cross-toolchain determinism is untested.

---

## Medium

### M-01 - terms registry initialisation

**Found.** `initialise` accepted the anchor id, asset commitment, initial terms
commitment and issuer key id as arguments from an arbitrary caller. Its own
comment claimed it "only mirrors values the anchor already carries immutably",
but it never read the anchor. Anyone could seed an unused anchor id with a
fabricated asset commitment and a fabricated issuer, and every later amendment
would then authenticate against that fabricated issuer.

**Corrected.** `contracts/src/identity/MordantTermsRegistry.sol` takes only an
anchor address, proves admission by reading the frozen factory
(`vaultForAttestation(anchor.sourceAttestationDigest()) == anchor`), and reads
every stored value from the anchor itself. The anchor id is derived, not
supplied. Amendments now require exactly one version step rather than merely
increasing, so a gap cannot leave a hole later reads cannot distinguish from a
missing amendment.

**Reverting breaks.** `testTermsCannotBeInitialisedForAnUnadmittedAnchor`,
`testTermsVersionGapIsRejected`.

---

### M-02 - session not one-shot

**Found.** V4 signed a `sessionNonce` and per-session budgets but consumed
neither. Because the commitment also took a free salt, one signed intent and its
three signatures produced unlimited distinct commitments, each accepted as a
fresh session: an unbounded private probing surface.

**Corrected.** `contracts/src/v5/MordantScopeGovernanceRegistryV5.sol` derives a
nullifier from the intent **without the salt** and consumes it at commitment
admission, not at reveal. Consuming at reveal would still allow unlimited
private evaluations under one authorization.

**Reverting breaks.** `testOneSignedIntentAdmitsExactlyOneSession`,
`testTheNullifierIsIndependentOfTheSalt`.

---

### M-03 / M-04 - same-block chronology ambiguity

**Found.** V4 compared `block.timestamp`, which is identical for every operation
in a block. A relayer contract could commit a session and register a source in
one transaction and satisfy `registeredAt <= committedAt`. Symmetrically, a
normal retirement in the commit block made `committedAt == retiredAt` and
stranded a session the comment promised would survive.

**Corrected.** Records carry block numbers and are compared strictly at both
ends: a record authorized in the commitment block is not earlier than the
commitment, and a record retired in the commitment block was not still live.
Same-block ambiguity fails closed in both directions, while an orderly handover
in a strictly later block still resolves.

**Reverting breaks.** `testARecordAuthorizedInTheCommitmentBlockIsRefused`,
`testARecordRetiredInTheCommitmentBlockIsRefused`,
`testARotationInALaterBlockDoesNotStrandACommittedSession`.

---

### M-05 - candidate reconciliation unauthenticated

**Found.** A tolerant "candidate alias" path whose suggestion nothing
authenticated.

**Corrected by removal.** The V5 circuit compares only the strict identifier,
under encryption, and produces exactly two bits. There is no tolerant result for
the schema to express, and `MordantMatchResultV5` no longer has the enum member,
the flags or the alias commitment. Removing the path rather than gating it is
what makes it unreachable instead of discouraged.

**Reverting breaks.** The enum no longer contains `ReconciliationRequired`;
reintroducing it requires reintroducing the fields the tests no longer
construct.

---

### M-06 / L-01 - binder invariants and factory admission

**Found.** The binder established that the anchor *behaved* like an anchored
receivable: interface, scheme version, state, protection, unit supply. It never
established that the anchor *was* one. Any contract implementing
`IAnchoredReceivable` and returning the expected values passed every check.

**Corrected.** `contracts/src/v5/PrivateMatchBinderV5.sol` proves provenance
first: the anchor's own source-attestation digest must resolve back to the
anchor's own address in the single configured authorized Factory V2. A generic
mock has no entry; a foreign anchor resolves in a different factory. The binder
additionally requires both scheme versions, that the revealed source names the
same issuer as the anchor, that the anchor is Outstanding, protected and holding
units, and that its asset commitment equals the revealed one.

**Reverting breaks.** `testAnInterfaceCompatibleMockIsRefused` (the mock is
constructed to satisfy every behavioural check V4 performed),
`testAForeignAnchorIsRefused`, `testAnEmptyAddressIsRefused`.

---

## Low

### L-02 - leak scanner never swept key material

**Found.** Every scan searched for canaries derived from a party's commercial
terms and identifiers. None searched for the threshold key material itself, so a
leaked Shamir share, RLWE secret or operator signing key would have passed the
gate silently. The text scans also skipped files over 8 MiB, which is exactly
the size class where key material lives.

**Corrected.** `fhe-lab/privacy-v4/leak-scan.mjs` adds `scanSecretMaterial`, a
streaming sweep over every file with **no size cap**, searching eight
representations of each secret including a 16-byte prefix for partial leaks,
with chunk-boundary carry-over so a needle spanning two reads is still found.

**Reverting breaks.** `secret material is detected in every representation`
(positive control per representation, each buried inside a 10 MB file).

---

### L-03 - terms scheme version signed but unchecked

**Found.** V4 signed `termsSchemeVersion` but never checked or stored it, so two
sources could be compared while interpreting their terms commitments under
incompatible schemes.

**Corrected.** `MordantSourceCommitmentRegistry.revealSource` validates both the
identity scheme and the terms scheme, and stores the terms scheme. The binder
requires the anchor and the revealed source to agree on both.

**Reverting breaks.** `testAnIncompatibleTermsSchemeIsRefused`.

---

## Beyond the findings

These were not audit findings. They were gaps found while correcting the
findings, and are reported because an auditor will otherwise find them.

| Gap | Where | Correction |
|---|---|---|
| The combiner read slot 0 and ignored the other 32767 | V4 threshold release | `CombineReleaseBitV5` asserts the complete decrypted slot vector; a value in any other slot fails closed |
| The entire evaluation context was outside the quorum signature | V4 result core | The V5 core binds circuit hash and version, release layout, parameter fingerprint, evaluation-key epoch and digest, runtime fingerprint, both ciphertext digests and the canonical output commitment |
| Four one-time identities, not covering session or output | V4 verifier | Six: replay key, decision key, session commitment, session nullifier, output ciphertext commitment, provider-proof commitment |
| The session nullifier was taken from the envelope | V4 verifier | Read from the governance registry's own admission record and required to match |
| Nothing pinned the build across operators | absent in V4 | A runtime fingerprint covering Lattigo version, Go version, GOOS/GOARCH, parameters, circuit build hash, serialization version, evaluation-key digest and epoch, derived locally by each operator and never accepted from the coordinator |
| RC1 remained selectable | product config | The live path fails closed below protocol V5, with the version parameter defaulting to the retired V4 so an omitted argument refuses |

---

## Verification state

| Gate | Result |
|---|---|
| Solidity tests | 262 / 262 |
| Go tests | pass, 502 s |
| Frozen RC1 sources | 16 / 16 match `af5baad` |
| V5 EIP-712 schema freeze | 4 / 4 types match |
| Solidity format | 29 checked, 15 frozen files excluded and pinned by hash |
| Repository hygiene | clean |
| Secret scan | clean |
| `fhe:test` | 74 / 74 |

## Not claimed

Zero knowledge, trustlessness, publicly proven FHE correctness, private
settlement, hidden transaction metadata, organizationally independent custody,
fraud detection, market completeness, absence of undisclosed pledges,
production readiness. Traffic-analysis privacy is not addressed.
