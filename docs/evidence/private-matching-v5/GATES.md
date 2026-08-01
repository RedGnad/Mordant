# RC2 / V5 release-protocol gates

Status of the four gates the owner required to pass **before** the V5 verifier,
binder, result schema, provider-proof schema, validator digest and consent
digest may be frozen.

All four are green. Nothing below is a Monad run: no on-chain transaction has
been broadcast for V5, per the standing instruction that no Monad run precedes
the freeze.

| Gate | Subject | Result |
|---|---|---|
| 1 | Deterministic operator recomputation | PASS |
| 2 | Release-safe canonical output | PASS |
| 3 | Operator-side input validation | PASS |
| 4 | Release transcript binding | PASS |

---

## Gate 1 - deterministic recomputation

**Question.** Can two operator processes recompute the circuit and compare the
result as exact bytes? Operator-side recomputation (finding H-03) is only a real
check if they can. The instruction was explicit that Lattigo evaluation must not
be *assumed* byte-deterministic, and that a tolerant ciphertext comparison must
not be used to recover agreement.

**Method.** `fhe-lab/lattigo/cmd/determinism-probe` freezes one ceremony's
parameters, collective public key, relinearization key, Galois keys and six
input ciphertexts to disk (344 MB). A driver then runs `evaluate` as a
**separate OS process** across the matrix below, each process loading that same
frozen material from scratch, and compares the output digests byte for byte.
There is no tolerance parameter anywhere in the probe or the driver.

| Variable | Values |
|---|---|
| Processes | 30 distinct PIDs |
| Architecture | `arm64` (native) and `amd64` (Rosetta 2), separate binaries |
| Galois key loading order | `natural`, `reverse`, `element-sorted` |
| `GOMAXPROCS` | 1, 4, 8 |
| Process restarts | 6 repeats of the baseline per architecture |
| In-process repeats | 2 per run (60 recomputations total) |

**Result.**

```
distinctInputDigests   1   b358a777354afd7b2bca8b7d68a4cd00520322b757c88ae39256cbed353de6ee
distinctKeyDigests     1   49f44a241d8d4f6ca62893cb83edf73f04b26d3a3a104669643ac34df735c378
distinctOutputDigests  1   694e3ec8450b21157e9bff8656dfb60ad17de1baaf64e4005b1c2ae3e3efc702
deterministic          true
```

One output digest across every process, order, thread count and architecture.
Raw per-run data: `gate1-determinism.json`.

**Why it holds, structurally.** The V5 circuit path uses only `AddNew`,
`SubNew`, `MulNew` against plaintext masks and scalars, `MulRelinNew`, `Rescale`
and `RotateColumnsNew`. All are deterministic modular arithmetic over fixed NTT
tables and fixed public keys. The one randomized value in the runtime, the
freshly encrypted `one` ciphertext used by `oneMinus`, is dead code and never
enters the evaluation path. Randomness in the system is confined to key
generation and to the smudging noise added during threshold key-switching, both
of which happen outside recomputation.

**Scope limit, stated plainly.** Two architectures on **one host**, one Go
toolchain (`go1.24.0`), one OS (`darwin`). Determinism across a genuinely
different host, OS or Go version is not evidenced here. The `amd64` run executes
under Rosetta 2 rather than on native x86-64 silicon.

### Measured cost of recomputation, concurrent operators

Both selected operators recompute **concurrently**, which is how a release
actually runs. Raw data: `performance.json`, produced by
`TestV5ConcurrentOperatorPerformance`.

| Metric | Value |
|---|---|
| Evaluator evaluation | 9.2 s |
| Both operators, wall clock | 10.1 s |
| Both operators, summed | 20.1 s |
| Parallel speedup | 1.99x of a theoretical 2.00x |
| Threshold release, both bits | 0.2 s |
| **Total end to end** | **20.0 s** |
| Evaluation-key load | 0.5 s |
| Ciphertext transport to each operator | 37.75 MB |
| Peak process memory (evaluator + 2 operators, one address space) | 1537 MB |
| Refusal of a substituted output | 9.4 s, terminal |

The second operator costs almost no additional wall time on this host: 1.99x of
a theoretical 2.00x means the two ran essentially in parallel rather than
contending. That will not hold on a host with fewer than two free cores per
operator, and it is a single-host figure in any case; three separate operator
hosts would each carry roughly the single-operator memory figure rather than
sharing 1537 MB.

Refusal costs a full recomputation by construction. An operator cannot know the
proposed output differs until it has computed its own, so a rejected release is
as expensive as an accepted one. That is the correct trade and it was not
optimized away.

### Single-operator figures



| Metric | Value |
|---|---|
| Operator recomputation, median | 8.69 s |
| Operator recomputation, range | 6.67 s - 11.03 s |
| Evaluation key load per process | 0.35 s - 0.58 s |
| Peak `runtime.MemStats.Sys` per operator | 1089 MB |
| Frozen evaluation key material | 344 MB |

This is the accepted latency cost of finding H-03. RC1's whole ceremony ran in
about 51 s; V5 adds roughly one 8.7 s recomputation **per operator**, plus key
load and transport. The recomputation was not weakened to recover RC1 latency.

---

## Gate 2 - release-safe output

**Requirement.** Only `sameEconomicAsset` and `policyConflict` are released;
every other plaintext slot is zero by canonical construction; the complete
decrypted slot vector is asserted; states 00/10/11 are coherent, 01 is
structurally impossible, and only 11 is bindable.

**Two bits, not one.** `RecomputeCircuitV5` returns two ciphertexts:

```
sameEconomicAsset = identityEqual
policyConflict    = identityEqual AND currencyEqual AND overlap
                    AND exclusiveA AND exclusiveB
```

`policyConflict` has `sameEconomicAsset` as a factor, which is what makes the
(false, true) state impossible rather than merely rejected. This is the
correction to finding H-02: V4 released one conjunction, so a false bit could
not distinguish "different receivable" from "same receivable, terms do not
conflict".

**Complete slot vector.** The V4 combiner read slot 0, range-checked it, and
ignored the other 32767 slots. `CombineReleaseBitV5` decodes the full vector and
calls `requireCanonicalReleaseVector`, which fails closed unless slot 0 is a
Boolean and **every** remaining slot is zero.

**Evidence.** `operator_release_v5_test.go`, real ceremony and real 2-of-3
threshold decryption:

- `TestTheTwoReleasedBitsDecryptToACanonicalVector` - same receivable,
  conflicting terms, releases (true, true) through the canonical-vector check.
- `TestADifferentReceivableReleasesFalseOnBothBits` - different receivable
  releases (false, false); a conflict cannot be reported without an asset match.
- `TestANonCanonicalReleaseVectorIsRefused` - a vector with data in slot 7, and
  a non-Boolean slot 0, are both refused.

On chain, `MordantMatchResultV5.outcomeOf` reverts `PolicyConflictWithoutAssetMatch`
on (false, true), `requireCoherent` reverts `ReleasedBitsDisagreeWithOutcome`
when the declared outcome is not what the two bits imply, and `requireBindable`
admits only `SameAssetPolicyConflict`.

---

## Gate 3 - operator input validation

**Governing rule.** No load-bearing digest supplied by the coordinator is
trusted without local recomputation.

`ReleaseOperatorV5.VerifyAndRecompute` runs thirteen named checks, in order, and
emits them into the verdict so a reviewer can see which ran rather than trusting
that they did:

| # | Check | What it recomputes locally |
|---|---|---|
| 1 | `descriptor-shape` | structural completeness |
| 2 | `circuit-version` | the operator's own implemented version |
| 3 | `key-epoch` | the operator's sealed key id |
| 4 | `parameter-fingerprint` | the operator's sealed parameters |
| 5 | `descriptor-freshness` | expiry against local clock |
| 6 | `enrollment-signatures` | both issuer signatures, against the operator's own trust store |
| 7 | `bilateral-pairing` | `PairEnrollmentsV5` re-derived, not asserted |
| 8 | `descriptor-session-binding` | descriptor names the paired session and both enrollment digests |
| 9 | `input-digests` | each side's digest recomputed from the received ciphertexts |
| 10 | `inputs-digest` | the descriptor's inputs digest, recomputed |
| 11 | `coalition-membership` | the operator's own point |
| 12 | `operator-one-shot` | the operator's own durable ledger |
| 13 | `local-recomputation` | **the circuit itself**, compared byte for byte |

Check 13 is the H-03 correction. The operator releases shares against the
ciphertext **it computed**; the coordinator's proposed output is never decrypted,
only compared. No tolerance is applied.

**Harness fidelity, stated plainly.** In the Go tests the operators share one
in-process evaluation runtime and one ceremony fixture, so those tests exercise
the check logic and the threshold protocol, not process separation. Genuine
process separation is carried by Gate 1, whose 30 recomputations each ran in a
separate OS process. A process-separated V5 run has not yet been performed.

**Evidence.** `TestAnOperatorRunsEveryCheckBeforeReleasing` asserts all thirteen
by name and order. Adversarial cases, each refused:
`TestAnOperatorRefusesACiphertextItDidNotCompute` (the V4 substitution attack),
`TestAnOperatorRefusesSubstitutedInputCiphertexts`,
`TestAnOperatorRefusesADescriptorForAnotherSession`,
`TestAnOperatorRefusesAnExpiredDescriptor`,
`TestAnOperatorOutsideTheCoalitionRefuses`,
`TestAnOperatorRefusesAnUnknownCircuitVersion`.

---

## Gate 4 - release transcript

`ReleaseTranscriptV5.Digest` binds:

1. session commitment
2. session nullifier
3. enrollment digest A
4. enrollment digest B
5. inputs digest
6. outputs digest
7. circuit version
8. key id
9. parameter fingerprint
10. policy id and policy version
11. coalition, threshold and every operator statement digest

plus the two released bits and the release timestamp. `validate` refuses a
transcript claiming a policy conflict without an asset match, so the impossible
state is not representable in the record either.

**Evidence.** `TestTheReleaseTranscriptBindsEveryRequiredField` mutates each
bound field and requires the digest to change;
`TestATranscriptCannotClaimAConflictWithoutAnAssetMatch`.

---

## What is still not claimed

Nothing here establishes: zero knowledge, trustlessness, publicly proven FHE
correctness, private settlement, hidden transaction metadata, organizationally
independent custody, fraud detection, market completeness, absence of
undisclosed pledges, or production readiness. Gate 1's cross-host and
cross-toolchain determinism is untested. No V5 Monad run has been performed.

## Reproducing

```
cd fhe-lab/lattigo
GOARCH=arm64 go build -o /tmp/gate1/probe-arm64 ./cmd/determinism-probe
GOARCH=amd64 go build -o /tmp/gate1/probe-amd64 ./cmd/determinism-probe
/tmp/gate1/probe-arm64 setup -dir /tmp/gate1/material     # ~344 MB, ~14 s
node scripts/gate1-determinism.mjs                        # ~30 processes

go test -run 'V5|Operator|Release|Session|Enrollment' -count=1 .
```
