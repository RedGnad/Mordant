# M-PRIV8 — Final V4 process-separated Monad evidence

## COMMIT AND TREE BINDING

| | |
|---|---|
| Frozen contracts commit | `af5baad` |
| Evidence commit | `a7a9b7e` (descendant of `af5baad`) |
| Branch | `fhe-lab` |
| Working tree at run time | clean for all tracked code |

All 16 frozen sources compared by git blob SHA-1 against `af5baad:<path>`; every one identical:

```
e224b0d MordantNormalization.sol      3c9dcda MordantAssetIdentity.sol
bdb11e8 MordantMatchResult.sol        91c3fff MordantIssuerRegistry.sol
085b0ce MordantSourceAttestation.sol  dff600a MordantSourceIdentityRegistry.sol
a643880 IIdentityAnchor.sol           cfc1f61 MordantInvoiceVault.sol
9523dc2 MordantFactory.sol            4eab090 MordantInvoiceVaultV2.sol
2eea903 MordantFactoryV2.sol          d76999d MordantScopeGovernanceRegistry.sol
385ad46 ECDSAQuorumMatchVerifierV4.sol b6b68a2 PrivateMatchBinder.sol
49e88ba IAnchoredReceivable.sol        3f9832f foundry.toml
```

The runner recomputes this comparison at startup and refuses to proceed if any
frozen path differs. V1, V3 and Mode A were not touched.

## MODEL AND EFFORT

Claude Opus 5, extended reasoning. Three receivables were run; receivable 3 is
the evidence run. Receivables 1 and 2 are retained as prior attempts and are
described where they matter.

## FROZEN CONTRACT VERIFICATION · DEPLOYMENTS · BYTECODE AND IMMUTABLES

Chain 10143. Deployer `0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0`.

| Contract | Address |
|---|---|
| MordantIssuerRegistry | `0x184B3797bee9d83D8911cE121eA894232050bEcB` |
| MordantFactoryV2 | `0x7eCA98adb3EE5Bd11e09Cf4cb04d9ceF4914c7b0` |
| MordantSourceIdentityRegistry | `0xF62E401bE84e099CE3F00e3F193960Eb295259D8` |
| MordantScopeGovernanceRegistry | `0x3d550619c4c20Bd70D53B7c93fbAa46c0dCE1512` |
| ECDSAQuorumMatchVerifierV4 | `0x02D71361A2A27aa4067cc40A778Bf2ABd626C775` |
| PrivateMatchBinder | `0x1D152f44Ab215F8aFafA8CDB6317ce505a748233` |
| MordantInvoiceVaultV2 (anchor) | `0x103b7f01664314905A76085F46dDc537AF70b8C0` |

Deployed runtime bytecode was compared against the artifacts compiled from the
frozen tree. A byte-for-byte comparison would fail for any contract with
immutables, so the artifact's own `immutableReferences` map was used to blank
exactly those spans on both sides.

**10 of 10 contracts match the frozen artifact outside their immutable spans.
`MockEligibility` and `MordantIssuerRegistry` are identical including
immutables. Zero mismatches.**

Decoded immutables (`bytecode-verification.json`):

- **Verifier** — owner `0x981F…`, governance `0x3d55…`, quorum `2`, validatorSetId `0x8127f3e5…`
- **Binder** — verifier `0x02D7…`, governance `0x3d55…`, issuerRegistry `0x184B…`,
  sourceRegistry `0xF62E…`, policyId `0x2da948bf…`, policyVersion `1`,
  responsibleRole `0xe4e507c0…`, curePeriod `0xe10` (3600), consequenceId `0xc582d47a…`.
  There is no owner immutable: the binder has no administrative surface.

Configuration readbacks: binder authorized on the governance registry, relayer
authorized and not either controller, policy version 1 registered on the
verifier, both governance records live and neither retired nor hard-revoked.

## VAULT V2 · NON-VAULT SOURCE · GOVERNANCE RECORDS · ISSUER AUTHORIZATION

**Anchor** `0x103b7f01…` — `receivableState = 1` (Outstanding), `protectionState = 1`
(Active), totalSupply 100.000000 units, identity scheme 3, terms scheme 1,
brought to Outstanding through the vault's own `activate` path with an
originator-signed pledge. Test assets only.

**Non-vault source** — `anchorId 0x952a4eb0…`, registered at `1785548822`,
publishing only the opaque identity fields: no debtor, no face value, no
currency, no dates. Before binding there is nothing public on that record that
correlates it with the vault.

**Both sides carry the same canonical `StableAssetIdentity` and independently
derived salts**, so their published asset commitments differ while the private
strict identity is identical. Equality was discoverable only under encryption.

**Governance records** — scope A and scope B, distinct scopes, distinct
organization IDs, distinct controllers, `authorizationVersion 1`,
`controllerEpoch 1`, `validFrom` before the commitment, `retiredAt 0`,
`hardRevokedAt 0`.

**Issuer** `0x95631E47…`, registered at epoch 1, unrevoked. It signed the anchor
attestation, the source attestation and the session intent, each time in its own
process, each time recomputing the digest itself.

## BILATERAL INTENT · THREE INITIATION SIGNATURES · RUNNER PREFLIGHT

All 24 `BilateralSessionIntent` fields were independently reconstructed. Three
implementations were required to agree, and then checked against the deployed
bytecode:

| Value | client | runner | deployed bytecode |
|---|---|---|---|
| `intentHash` | ✓ | ✓ | ✓ |
| `intentDigest` | ✓ | — | ✓ |
| `signatureBundleDigest` | ✓ | ✓ | ✓ |
| `sessionCommitment` | ✓ | ✓ | ✓ |

The runner implementation is written separately against the frozen byte layout
rather than by calling the client module, so agreement is evidence rather than
tautology. Both are additionally pinned to Solidity vectors emitted by
`V4DigestVectors.t.sol` in a unit test that runs before any gas is spent.

Each signature was recovered to the address its process published, all three
signers distinct, all three canonical low-s with `v ∈ {27,28}`, in the fixed
order `controllerA, controllerB, issuer`. The run fails before FHE on any
mismatch; it does not rely on the on-chain reveal check.

## OPAQUE SESSION COMMITMENT · PUBLIC METADATA AUDIT

```
sessionCommitment  0x4af7d1dee1a3574b2faffec3eb8b1eecb117fa00d13a7e1ee6eacd96088ee8b1
transaction        0xddec4eb7257d960b6f41882f182cf1087143c3dc6d740d67f5ab478516c87f79
block              49828955          committedAt 1785548824      gas 116040
relayer            0x5b832ED718cAA91d49872e8A367ABa15Ffa433e3
```

One event, one indexed topic. The relayer was handed `{chainId, sessionCommitment}`
and refuses any request carrying additional session detail.

**Public metadata audit: 18 forbidden values checked against every 32-byte
window of the transaction input, every event topic and every data word.
Disclosed: none.** The checked set covered both scopes, both governance records,
both controllers, both organization IDs, the anchor address, both asset
commitments, the source anchor id, the strict asset identity, the session salt,
the intent hash, the signature bundle digest, the issuer key id and the policy id.

Before binding, the public surface is: the opaque commitment, its timestamp and
block, and the relayer address. Nothing else.

## CLIENT A / CLIENT B · FULL-FHE IDENTITY · COMMERCIAL-TERM EVALUATION

`identityMode = full_fhe_256`. The strict stable asset identity is encrypted bit
by bit; `ReceivableCommitment` is zero, so there is no public link commitment to
test. Both enrollments bind the same opaque session commitment, each side's
frozen governance record, its source registration and its asset commitment,
carried as the issuer-signed enrollment nonce. **The evaluator reported both
nonces and both matched the runner's independent recomputation.**

The released bit is the conjunction

```
overlap ∧ flags ∧ currencyEqual ∧ encryptedIdentityEqual
```

so a true bit proves strict identity equality without ever releasing it as a
separate value, and a false bit does not reveal which conjunct failed.

`exactMatchConfirmed = true`, `candidateMatchSuggested = false`,
`conflictConfirmed = true`. No tolerant candidate path ran: the intent set
`candidateAuthorized = false`, both controllers refuse to sign an intent that
sets it, and the binder's result invariants reject a candidate result before any
signature is checked.

## DEALERLESS OPERATORS · EVALUATOR CAPABILITY · PERFORMANCE

True dealerless 2-of-3, coalition `[1,2]`. Share isolation was verified by a
per-operator sequential sweep holding one share at a time: 63 files scanned,
zero files holding a foreign share, zero files holding more than one.

Evaluator capability, measured rather than asserted:

```
holdsThresholdParties      false
localDecryptAttempt        REFUSED: insufficient threshold shares
provisionOperatorsAttempt  REFUSED: invalid threshold operator material
releaseShareAttempt        REFUSED: invalid threshold operator material
sourceReferencesSecretMaterialAPIs   none
```

Clients also refused an evaluator-substituted public key and a partially
attested manifest.

Timings: ceremony 50.9 s; whole run 60.9 s excluding the interval between
commitment and binding. Commitment block 49828955 → binding block 49830594,
a gap of 1,639 blocks, because the run crashed on a full disk between the two
and was resumed from the journalled preimage.

## VALIDATOR SIGNERS · PRIVATE RESULT · DISCLOSURE CONSENTS

Three separate validator processes, each holding one key the runner never reads.
Each independently recomputed the V4 result core, the result digest and the
attestation digest, and each **verified against the chain that the session
commitment already existed before signing**. Exactly two signatures formed the
quorum. The runner's result core commitment equals the verifier's `eth_call`
recomputation.

Two distinct disclosure consents, one per controller, each binding the result
commitment, session commitment, match commitment, its own scope, its historical
governance record, controller key id and epoch, scope authorization version,
intended anchor, intended binder, policy id and version, disclosure version,
expiry and a one-shot nonce. Each consent digest was checked against the
binder's own `consentDigest` before use.

Neither controller alone can bind: a one-sided consent is rejected
(`ConsentScopeMismatch`), and a controller refuses in its own process to consent
to anything that is not a confirmed exact match.

## V4 VERIFIER · V4 BINDER · ATOMIC RECOURSE · MONAD TRANSACTION

```
transaction  0x3ebe719ed0214d9693b727cd7445ba1c9e52d09dd77339c7d404483ff30d2aa3
block        49830594     gas 1175690     value 0
```

One transaction atomically revealed and resolved the opaque intent, verified the
three historical initiation signatures, the governance chronology, source
anticipation, the issuer pre-authorization, result coherence and bindability,
the validator quorum and both disclosure consents; consumed the replay identity,
the order-independent decision identity, the match commitment, the provider-proof
commitment, the session commitment and both consent nonces; verified the live
anchor against its pre-existing asset commitment; derived responsibility, cure
deadline and consequence on-chain; and opened exactly one non-economic recourse
record.

## READBACKS

```
sessionCommitment       0x4af7d1de…      open                    true
resultCommitment        matches envelope conflictConfirmed       true
matchCommitment         matches envelope anchor                  0x103b7f01…
anchorCommitment        equals the vault's published commitment
counterpartyCommitment  equals the source record's commitment
policyId / version      0x2da948bf… / 1
boundAt → cureDeadline  exactly +3600, derived on-chain
responsibleRole         0xe4e507c0…     consequenceId            0xc582d47a…
anchorLive              true
```

All seven one-time identities read back `true`. Anchor still Outstanding with
Active protection.

## ASSET MOVEMENT

Transaction value `0`. Settlement balance in the vault, settlement in the binder,
receivable units in the binder, vault total supply and native balance in the
binder are byte-identical before and after. The binder holds no balance, has no
token interface and reaches the receivable only through a view-only interface.

## REPLAY

Eleven negatives, all by `eth_call`. No failing transaction was broadcast.

| Case | Rejected |
|---|---|
| exact calldata replay | ✓ |
| reversed input pair | ✓ |
| wrong anchor | ✓ |
| wrong binder | ✓ |
| wrong session commitment | ✓ |
| one-sided consent | ✓ |
| reused consent nonce | ✓ |
| candidate result submitted as bindable | ✓ |
| reused match commitment | ✓ (consumed) |
| reused provider-proof commitment | ✓ (consumed) |
| controller asked to consent to a candidate result | ✓ (refused in-process) |

## LEAK SCAN · POSITIVE CONTROLS

33 canaries across 12.3 representations each, 40 files.

```
never-class leaks        0
pre-binding leaks        0
positive controls        11 / 11 representations detected
manifests deleted        2, after the scan, with 18 field digests retained
```

The **never** class covers both clients' commercial terms and identity
preimages, the strict stable asset identity, its seller/debtor/invoice
components, both issuer master secrets, both per-anchor salts, all seven process
private keys and all three operator share bundles.

The **revealed-at-binding** class covers the session salt and the three
initiation signatures. These are published deliberately in the binding
transaction, so they are forbidden only before it: zero occurrences in the
pre-binding surface, and present in the binding calldata as designed.

The coarse field-name tripwire fired on 10 files. Every match was extracted and
classified; all are benign and none is material:

- `REFUSED: insufficient threshold shares`, `evaluatorSourceReferencesSecretMaterialAPIs`,
  `clientRejectsEvaluatorSubstitutedPublicKey` — refusals proving a protection held
- `holdsLocalSecretKey`, `threshold-share-sealed` — boolean flags and labels on
  operator statements proving share isolation
- `PlaintextModulus` — the BGV plaintext **modulus** `t = 65537`, which must be
  public for anyone to encrypt
- `authorization_credential` — a field **name** in the public coverage assertion,
  which carries only `canarySha256`, never the value

**A real leak was found and fixed during this mission.** The strict stable asset
identity was passed to the ceremony as a `-asset-id` command-line argument and
recorded verbatim in both clients' process records in the custody evidence, and
was visible to any local process through the process table. It is now passed in
a `0600` file (`-asset-id-file`) that is removed after the ceremony. The evidence
was not patched: the entire path was re-run on a fresh receivable.

## PROCESS SEPARATION

Fourteen roles, all as separate OS processes:

| Role | Process |
|---|---|
| anchor-side client | `ceremony-client-a` |
| non-vault-source client | `ceremony-client-b` |
| controller A | pid 77851, `0xd70FE258…` |
| controller B | pid 77852, `0x6CF8Ff04…` |
| issuer | pid 77853, `0x95631E47…` |
| dealerless operators 1–3 | `threshold-operator-1/2/3` |
| evaluator / coordinator | `ceremony-evaluator`, `ceremony-coordinator` |
| validator signers 1–3 | pids 77858–77860 |
| relayer | pid 77854, `0x5b832ED7…` |
| Monad binder runner | pid 77820 |

No process held both clients' plaintext, more than one operator share, more than
one validator key, both controller keys, or a controller key together with the
issuer key.

**One deviation, stated plainly.** The relayer runs as its own process, holds its
own key and accepts only `{chainId, sessionCommitment}` — it is given no intent,
no salt and no signatures. But to broadcast the commitment transaction the runner
reads the relayer's key from that process's storage directory. The *knowledge*
boundary holds; the *signing* boundary does not. A production relayer would sign
and submit inside its own process.

## RECOVERY

The mission survived two hard crashes, both from a full disk.

The journal records every transaction hash with atomic temp-and-rename **before**
the receipt is awaited. After the first crash, reconciliation showed 37/37
journalled steps on-chain, zero reverted, zero missing, and — the decisive check —
no deployer nonce above the highest journalled one, so nothing had been broadcast
without being recorded.

Two journal repairs were performed from chain evidence, each retaining the
original (`journal.pre-migration.json`, `journal.pre-relabel.json`) and recording
the reason in a `recovery` array.

Three design corrections came out of this:

1. A session's preimage is now journalled **before** its commitment is broadcast.
   A commitment is a one-shot on-chain artifact; losing its preimage strands it
   permanently. Five such stranded commitments exist from earlier attempts and
   are recorded in the evidence as unrevealable.
2. Resumability is decided **before** anyone signs, so signers never attest a
   digest that is then replaced by a restored one.
3. `return finishFromBinding(...)` inside `try/finally` ran the `finally` — killing
   every signer process — as soon as the promise was created. Now `return await`.

The evidence run itself exercised recovery: receivable 3 resumed a session whose
commitment was already published, from its journalled preimage.

## WHAT IS CRYPTOGRAPHICALLY ENFORCED

- The session commitment binds the intent **and** all three authorization
  signatures, so bilateral initiation and issuer authorization demonstrably
  predate publication.
- One decision per input pair, one binding per match commitment, one use per
  provider-proof commitment, one reveal per session commitment, one use per
  consent nonce — all enforced on-chain and all verified consumed.
- Both disclosure consents are required; neither controller can bind alone.
- Consent authority is read from the governance record the intent named, not from
  any mutable current mapping.
- Canonical low-s signature encoding on every signature that reaches a contract.
- The binder cannot move value: no balance, no token interface, view-only anchor access.

## WHAT IS QUORUM-ATTESTED

- That the FHE evaluation was performed, performed correctly, and performed after
  the commitment. Validators verified the commitment existed on-chain before
  signing; the computation itself is not publicly proven.
- That the released bit corresponds to the stated policy circuit.

## WHAT IS SOURCE-ATTESTED

- That both sides' namespaces and normalization profiles agree.
- That the non-vault source's identity corresponds to a real receivable.
- That the issuer's authorization of each anchor is truthful.

## WHAT IS PUBLIC

Before binding: the opaque session commitment, its timestamp and block, and the
policy-authorized non-controller relayer address.

After binding: the anchor address, both salted asset commitments, the match and
provider-proof commitments, the result commitment, the intent preimage, the
session salt, the three initiation signatures, both consents and the recourse
record. All of it disclosed only because both controllers consented.

Independently of any session, each anchor publishes its own salted asset
commitment at creation — that is the approved anchor design, and it is what the
session relationship must not link.

## WHAT REMAINS TRUSTED

- The governor of the scope governance registry, for future authorizations. It
  cannot reach backwards into a committed session.
- The issuer, for the truthfulness of its attestations.
- The relayer, for not correlating commitments with participants it may learn
  through other channels.
- Lab-grade HMAC-over-loopback authentication between the runner and each signer.

## WHAT REMAINS UNPROVEN

- Organizational independence. Every process ran on one machine under one
  operator. The separation is architectural, not administrative.
- Traffic-analysis privacy. One relayer address posted every commitment in this
  deployment; an observer sees a single address publishing many commitments.
- FHE execution correctness, as above.
- That two V2 vaults for one receivable cannot be correlated through their public
  economics. That was established as a permanent property of Candidate A and is
  unchanged.
- Production readiness of any kind.

## CLAIM VERDICTS

**1. Mordant can privately determine whether two mutually authorized submissions
refer to the same economic receivable and apply governed recourse after
bilateral disclosure consent.**

`SUPPORTED`

Two mutually authorized submissions describing one receivable under independent
salts were compared under encryption, the identity equality was established
without either identity leaving its client, and a non-economic recourse record
was opened in one atomic transaction only after both controllers consented.

**2. Mordant supports private matching for authorized cross-boundary receivables
exceptions.**

`SUPPORTED WITH REVISION`

The cross-boundary shape is real and was exercised end to end: a tokenized vault
on one side, a non-vault source registration on the other, distinct scopes,
distinct organization identifiers, distinct controllers, neither able to act
alone. The revision is that the boundary is architectural only — all processes
ran under one operator, so this demonstrates the mechanism, not organizational
separation.

**3. The shared evaluator does not receive the submitted receivable identities or
commercial terms.**

`SUPPORTED`

In `full_fhe_256` the receivable identity is encrypted bit by bit and no public
link commitment exists. The evaluator holds no threshold share and its decrypt,
provision and release-share attempts were all refused. A 33-canary sweep across
12.3 representations each over 40 files, with 11/11 positive controls detected,
found no client identity preimage or commercial term in any evaluator artifact.

## OVERALL VERDICT

**PRIVATE MATCHING AND GOVERNED RECOURSE: PROVEN**

Every acceptance criterion is met: contracts frozen from `af5baad`; the runner
preflight recomputed the complete opaque commitment across three implementations
and the deployed bytecode; all three initiation signatures predate and are bound
into the commitment; public commitment metadata revealed no participant
relationship; source and governance records predate the commitment; FullFHE256
exact equality was used; the evaluator cannot decrypt; dealerless 2-of-3 release
succeeded; validator signers were process-separated; both disclosure consents
were required; one atomic Monad binding and recourse transaction succeeded; all
readbacks pass; replay is rejected; no assets moved; the leak scan and positive
controls pass; the evidence is bound to the exact clean source tree.

## AUTHORIZED WORDING

- "Private matching for authorized bilateral receivables exceptions."
- "Governed recourse after bilateral disclosure consent."
- "The evaluator computes on ciphertexts it cannot decrypt."
- "Dealerless 2-of-3 threshold release."
- "No participant pairing is public before binding."
- "Non-economic recourse record."

## MANDATORY QUALIFIERS

Every claim above must be accompanied by:

- "Monad testnet, test assets only."
- "Quorum-attested computation; FHE execution correctness is not publicly proven."
- "Process separation is architectural; organizational independence is a
  production deployment property and was not established."
- "No traffic-analysis privacy is claimed."

## PROHIBITED WORDING

Not authorized by this run, and not to be used: fraud detection; open-book
screening; market surveillance; market completeness; absence of undisclosed
pledges; zero knowledge; trustlessness; publicly proven FHE correctness; private
settlement; hidden transaction metadata; organizationally independent custody;
production readiness.

## ESCALATION REQUIRED

**NO.**

## MY RECOMMENDATION

Freeze this evidence and stop building. The architecture has now survived four
consecutive adversarial reviews and one full end-to-end execution, and the last
two review cycles found design faults rather than implementation faults — which
is the signal that the design has converged.

Two things are worth doing next, and neither is architecture:

1. **Fix the relayer signing boundary.** It is the only process-separation
   deviation in the run and it is a small change: have the relayer sign and
   submit inside its own process. Leaving it is a standing asterisk on an
   otherwise clean topology.

2. **Decide what the relayer address means for the product.** A single relayer
   publishing every commitment is a metadata pattern an observer can follow. It
   does not identify participants, but "no participant pairing is public" is a
   stronger sentence than "no single address publishes every session." Batching
   or a relayer set would close it.

What I would not do is reopen the identity, governance or binding architecture.
The remaining gaps are operational, and the honest limits — organizational
independence, FHE execution correctness, traffic analysis — are the kind that
deployment closes, not code.
