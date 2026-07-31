# M-FHE-A0 — Provider-independent FHE decision gate

> **Final bounded gate report — evidence snapshot 31 July 2026.** The exact circuit, true local
> 2-of-3 threshold path, provider-neutral result, quorum-authenticated EVM acceptance, negatives,
> and native measurements are reproduced below. The decision is deliberately limited to controlled
> vertical-slice feasibility: it is not an integrated-client, distributed-operator, Monad-testnet,
> or production authorization. A successful compile or a single-key demo would not have closed
> this gate.

## HARDENING ADDENDUM — SAME BOUNDED VERDICT

The follow-up pass closes four integration gaps from the evidence snapshot without widening the
policy: public-only external encryption plus signed enrollment, a TLS-1.3/mTLS one-operator process
with durable one-shot state, an exact c1 protocol-consumption guard, and schema-2 provider-proof
binding through the result commitment and EIP-712 attestation. The current implementation and its
remaining limits are specified in [`HARDENING.md`](./HARDENING.md).

The verdict does not become production approval. Setup custody is still controlled, issuer trust is
local, correct computation is endorsed rather than proven, and no Monad transaction was performed.

## PRIMARY CANDIDATE

**OpenFHE 1.5.1** was evaluated first, as required.

- License: BSD-2-Clause ([official release source](https://github.com/openfheorg/openfhe-development/tree/v1.5.1), [license](https://github.com/openfheorg/openfhe-development/blob/v1.5.1/LICENSE)).
- Relevant capabilities exist independently: exact comparison through BinFHE/FHEW
  (`EvalSign`), BGV/BFV/CKKS threshold extensions, and binary/JSON serialization.
- It is not the implementation candidate for this ten-day slice because exact comparison and
  supported threshold decryption are not reliably composable in the required circuit today. The
  blocking evidence is recorded under **OPENFHE FINDINGS**.

Status: **eliminated for this slice, not rejected as a library in general**.

## SECONDARY CANDIDATE

**Lattigo 6.2.0** is the only independent candidate still eligible for the ten-day gate.

- License: Apache-2.0 ([release](https://github.com/tuneinsight/lattigo/releases/tag/v6.2.0), [license](https://github.com/tuneinsight/lattigo/blob/v6.2.0/LICENSE)).
- It provides exact BGV/BFV arithmetic and documented `t-out-of-N` multiparty protocols
  ([multiparty package](https://pkg.go.dev/github.com/tuneinsight/lattigo/v6/multiparty)).
- Lattigo does not supply a business-level `uint64 < uint64` policy primitive. The spike must prove
  its own exact, bit-decomposed unsigned comparator, its multiplicative depth, and its interaction
  with the threshold workflow.
- A true 2-of-3 run, not a reconstructed single secret disguised as threshold operation, is a
  mandatory acceptance condition.

Status: **selected for the controlled provider-neutral vertical slice only**.

## POLICY CIRCUIT

The only permitted policy is:

```text
same receivable
AND same currency
AND a.activeFrom < b.activeUntil
AND b.activeFrom < a.activeUntil
AND pledge A is exclusive
AND pledge B is exclusive
AND submitter A is authorized
AND submitter B is authorized
```

The overlap comparisons are strict. Adjacent periods are not overlapping. No score, interest,
settlement, confidential token, state machine, or second policy pack belongs in this gate.

The ten-day MVP uses a high-entropy salted, vault- and policy-version-scoped public receivable link
commitment. Full encrypted equality of the 256-bit identifier remains the privacy-preserving
alternative and must be benchmarked as an incremental cost before it is selected.

Authorization is an ingress predicate backed by an unexpired, revocation-checked credential or an
equivalent private allow-list. Encrypting a Boolean supplied by the submitter does **not** satisfy
the policy.

Before a Lattigo GO, evidence must show:

- exact unsigned 64-bit comparisons at boundaries, including adjacency;
- exact currency equality using a lossless, versioned representation of the current `bytes32`
  currency domain;
- every predicate included in one final encrypted AND;
- no overflow, wraparound, approximate CKKS decision, or plaintext short-cut;
- the amount envelope remains compatible with the current `uint256` domain even though policy V1
  does not evaluate the amount;
- the submitted ciphertext binds all classified commercial fields, or explicitly documents why a
  field remains client-only without weakening the input commitment.

## CONFIDENTIAL FIELDS

The detailed classification is normative in
[`shared/field-classification.md`](./shared/field-classification.md). The minimum confidential set is:

- amount;
- exact `activeFrom` and `activeUntil` periods;
- obligation identifier;
- exclusivity and other commercial conditions;
- currency label (only equality contributes to the public result);
- pledge nonce and pledge deadline;
- originator, facility, signature, and any identity not required for public execution.

Plaintext may exist only inside the submitting client process. It may not appear in Monad calldata,
events, artifacts, logs, errors, reports, benchmark samples, screenshots, or Playwright snapshots.
The evaluator receives ciphertext, opaque authorization material, and only the explicitly public
commitments.

Receivable identity choices:

| Option | Privacy | Cost and operational consequence |
| --- | --- | --- |
| Full FHE equality | Avoids a stable public receivable link; ordinary timing and size leakage remains. | Adds 6,291,954 bytes per pledge and 2,388 ms median evaluation on the measured host; it adds no evaluation-key bytes because currency equality already needs the same rotations. |
| Salted public link commitment | Reveals equality and repeated use inside one vault/policy epoch. A unique secret 128-bit-or-stronger salt prevents practical dictionary and cross-vault linking when handled correctly. | Adds 32 public bytes per input and removes identifier equality from the FHE circuit. Preferred for the ten-day MVP, not automatically for production. |

## PUBLIC OUTPUTS

Only the following provider-neutral result may reach Monad:

```text
chainId
vault
policyId
policyVersion
inputCommitmentA
inputCommitmentB
conflictConfirmed
responsibleRole
cureDeadline
nonce
validUntil
providerProofCommitment
resultCommitment
```

The signed EIP-712 message additionally binds `chainId` and the deployed verifier contract through
the domain `Mordant Confidential Policy`, version `2`. The adapter recomputes the result commitment;
validators never sign a generic `conflict = true` statement. A false result requires a zero role and
zero cure deadline.

The public result intentionally reveals that an evaluation happened, its final Boolean, accountable
role, cure deadline, commitments, timing, calldata size, and gas usage. FHE does not hide those
outputs.

## OPENFHE FINDINGS

OpenFHE 1.5.1 documents the ingredients separately:

- exact sign/comparison through the official
  [`EvalSign` example](https://github.com/openfheorg/openfhe-development/blob/v1.5.1/src/binfhe/examples/eval-sign.cpp);
- [threshold FHE](https://github.com/openfheorg/openfhe-development/blob/v1.5.1/docs/static_docs/Threshold_FHE.md)
  for BGV, BFV, and CKKS;
- [serialization examples](https://github.com/openfheorg/openfhe-development/tree/v1.5.1/src/pke/examples).

They are not a supported combined solution for this policy. An OpenFHE maintainer states that
[threshold FHEW is not implemented](https://openfhe.discourse.group/t/does-large-precision-comparison-have-any-relevant-reference-papers-can-the-current-threshold-version-of-ckks-be-used-for-scheme-switching-fhew-and-comparison/1228).
In June 2026, a maintainer further explained that multiparty scheme switching had only been tested
through the single-key route and could produce
[probabilistically incorrect comparisons](https://openfhe.discourse.group/t/multiparty-sceheme-switching-non-probibalistic/2325).

For a contractual deadline predicate, a probabilistically wrong comparison is not an acceptable
engineering trade-off. A single-key OpenFHE benchmark would avoid, not answer, the decisive trust
question. Therefore OpenFHE is a **NO-GO for this ten-day slice**. It should be reconsidered when
threshold BinFHE/FHEW or supported multiparty scheme switching ships with correctness parameters
and tests.

## LATTIGO FINDINGS

Lattigo 6.2.0 is suitable for a bounded experiment because BGV represents exact modular integers and
the v6 multiparty package exposes Shamir thresholdization, combination, collective key generation,
and key switching. The current candidate design is a bit-decomposed BGV comparator over exact
unsigned timestamps with a true 2-of-3 result-decryption path.

The native test suite now establishes the circuit and threshold mechanics in the controlled
harness:

- exact policy conformance: **9 / 9 encrypted truth and boundary cases passed**;
- 2-of-3 combinations tested independently: **{0,1}, {0,2}, and {1,2} all passed on fresh
  ciphertext sessions**;
- one share rejected: **passed; an invalid preflight does not consume the session, while a
  completed decryption makes that result ciphertext terminal**;
- five measured runs after one full warm-up, independently for public-link and full-FHE identity:
  **passed; medians and nearest-rank p95 recorded**;
- serialized ciphertext/key round-trip: **passed, including a `uint256` maximum amount and exact
  cross-language ABI commitment vectors**;
- malformed ciphertext, wrong key, wrong version, replay, expiry, and authorization negatives:
  **passed in the Go/Foundry suites; a real second-runtime ciphertext remains rejected even if its
  envelope metadata is relabelled**;
- recursive artifact/report scan finds none of the known synthetic private fixture literals outside
  source and tests: **passed**; this is a regression check, not a proof against every possible
  side channel;
- exact parameter set: **Lattigo's `BGVScaleInvariantParamsN15QP880` example family (`LogN=15`,
  `logQP=881`, plaintext modulus `65537`), depth 11**;
- compiler and host: **Go 1.24.0, native `darwin/arm64`, Apple M1, 8 logical cores, 8 GB RAM**.

The full suite completed in **109.167 seconds package time / 110.01 seconds wall time**. This is a
test-suite duration containing repeated fresh evaluations, not one policy-evaluation latency.

The `multiparty` package supplies local cryptographic protocols, not networking, durable session
coordination, operator authentication, or Byzantine robustness. Its documented security target is
passive adversaries; active malicious-share proofs are not part of this spike. This is acceptable
only as a controlled prototype limitation, never as a production claim.

In this harness, all three Shamir parties and the authenticated-gateway simulation are co-located in
one Go process. The threshold mathematics are real, but the organizational custody separation is
not. The process-local issued-ciphertext registry makes malformed/foreign inputs fail closed in the
lab; a separate client will require a signed canonical envelope or a proof of well-formed encryption
before that registry can become a genuine network boundary.

Lattigo also documents a critical operational constraint: retrying a multiparty protocol with the
same shares and public polynomial can reveal secret material. Its
[security guidance](https://github.com/tuneinsight/lattigo/blob/v6.2.0/SECURITY.md) says the library
does not implement the relevant countermeasures. Every failed multiparty round is therefore
terminal for that cryptographic session. Recovery must create fresh protocol randomness and key
material; participants must never reissue shares for the failed round.

## FHENIX FINDINGS

Fhenix CoFHE is useful as a managed-coprocessor comparison, not as the primary provider-independent
route. Its current official quick start lists Ethereum Sepolia, Arbitrum Sepolia, and Base Sepolia;
it does not list Monad ([supported networks](https://cofhe-docs.fhenix.zone/fhe-library/introduction/quick-start)).

Using CoFHE would therefore require an unproven cross-chain or custom deployment path and would not
meet the ten-day requirement for canonical Monad execution. No support is inferred from EVM
compatibility alone. CoFHE may be revisited only after an official Monad deployment or a documented,
measured custom path exists.

## ZAMA FALLBACK FINDINGS

Zama is a fallback only if the independent candidates fail a criterion with precise evidence. It is
not selected because it appears simpler.

Its advantage is a complete operating architecture rather than a library alone: the
[Zama Protocol architecture](https://docs.zama.org/protocol/protocol) includes a coprocessor,
Gateway, ACL, KMS, and relayer. Mordant would otherwise need to own or explicitly delegate those
responsibilities.

Its constraints are material:

- TFHE-rs is part of the Zama technology family and is not an independent alternative.
- The [official TFHE-rs repository](https://github.com/zama-ai/tfhe-rs) describes
  BSD-3-Clause-Clear access for development, research, prototyping, and experimentation, while
  commercial use of patented technology requires a separate patent license. Legal review is
  mandatory before a commercial dependency is accepted.
- A Zama fallback must remain behind `IConfidentialPolicyVerifier`; no Zama type may enter the
  business model, Monad remains canonical, and inputs/outputs remain portable.
- Monad compatibility, attestation verification, latency, calldata, and commercial terms would
  still require evidence. They are not granted by the architecture diagram.

Fallback status: **not selected; eligibility depends on a demonstrated OpenFHE/Lattigo blocker and
an acceptable license/trust review**.

## MONAD FINDINGS

Monad provides EVM bytecode and Ethereum RPC compatibility
([documentation](https://docs.monad.xyz/)), so the sidecar can use Solidity, Keccak-256, EIP-712,
ECDSA, and ordinary stateful replay protection. Documented chain IDs are 143 for mainnet and 10143
for testnet; the documented per-transaction gas limit is 30 million
([protocol changelog](https://docs.monad.xyz/developer-essentials/changelog)).

[Execution Events](https://docs.monad.xyz/guides/execution-events) can reduce event-to-policy
latency for an operator with the required node configuration. They do not authenticate an off-chain
FHE computation and are not currently integrated by Mordant. The defensible Monad story is only:

```text
Monad event
-> confidential policy session
-> threshold-decrypted result
-> quorum attestation
-> Monad acceptance
```

No official Monad facility was found in the reviewed documentation for an application FHE
coprocessor, ciphertext ACL, threshold KMS, or attestation of arbitrary off-chain computation. This
is an inference from the reviewed official surface, not a claim that such infrastructure can never
exist. The application must currently provide its own sidecar verifier.

The standalone adapter must prove through tests and measurements:

- provider-neutral `verifyResult(result, attestation)` remains read-only;
- stateful `acceptResult` recomputes commitments, consumes the canonical replay key and the
  input-pair decision key before any external effect, and emits only public result metadata;
- chain, verifier, vault, policy version, expiry, validator-set ID, quorum, sorting, uniqueness, and
  revocation are enforced;
- result mutation and cross-deployment replay fail;
- Foundry tests: **26 / 26 passed**;
- controlled local workflow tests: **10 / 10 passed**, including fail-closed provider errors,
  strict rejection of unknown/private fields, commitment mismatch, and a second acceptance attempt
  reverted on the same Anvil state;
- two-signature attestation calldata: **900 bytes**;
- successful schema-2 `acceptResult` in the local Foundry gas report: **182,796 gas**;
- local result-to-accept latency: **158.5 ms initially and 63.846 ms on the final validation run**;
- complete fresh Go worker through local adapter acceptance and replay check: **13.93 seconds wall
  clock**;
- Monad testnet latency: **not measured and not claimed**.

Acceptance in this lab has no accounting effect and does not modify `MordantInvoiceVault`.
The workflow emits a public local receipt (verifier, transaction hash, block, replay/decision keys,
validator-set ID, and attestation digest), but its Anvil chain is destroyed after the run. The
synthetic Anvil validators authenticate the public EIP-712 result; they are not independent
decryptors and do not prove correct FHE execution. This is intentionally labelled
`controlled-local-anvil`, never Monad testnet.

## COMPARISON + THRESHOLD COMPATIBILITY

| Candidate | Exact unsigned comparison | Threshold path | Same supported circuit? | Gate state |
| --- | --- | --- | --- | --- |
| OpenFHE 1.5.1 | Yes through BinFHE/FHEW or scheme switching | Threshold documented for BGV/BFV/CKKS | No reliable, supported combination found; maintainers identify the gap and correctness risk | No-go for this slice |
| Lattigo 6.2.0 | Exact bit-decomposed BGV circuit passed strict uint64 boundaries | Same encrypted result decrypted by each 2-of-3 coalition | Yes in the co-located controlled harness; operator separation is not delivered | Measured candidate for controlled vertical slice |
| Fhenix CoFHE | Managed FHE service | Delegated service architecture | No supported Monad route documented | Not primary |
| Zama stack | Exact TFHE family | Delegated network KMS/coprocessor architecture | Technically integrated as a stack, but licensing, trust, and Monad path remain separate decisions | Conditional fallback only |

A Lattigo run passes only if the ciphertext evaluated by the exact comparator is the ciphertext
whose result is threshold-decrypted. Running comparison under one key and later wrapping its
plaintext Boolean in a threshold workflow is explicitly rejected.

## KEY MANAGEMENT

### Local cryptographic spike

A single key may be used only to compile, debug the circuit, and isolate performance. Every artifact
and report must label that mode `LOCAL SINGLE-KEY BENCHMARK — NOT TARGET ARCHITECTURE`.

The delivered Lattigo harness goes further cryptographically: it creates a Shamir 2-of-3 key and
exercises every two-party coalition. It still remains a local spike because the three party states,
the gateway registry, and the one-shot session maps share one process and volatile memory.

### Integrated prototype target

- 2-of-3 Shamir threshold key setup or a cryptographically equivalent construction;
- no service holds enough material to decrypt inputs alone;
- one-time session identifier and explicit lifecycle state;
- threshold release of the single Boolean result only;
- validator-quorum signatures over the exact provider-neutral digest;
- key ID ingress validation and retired-key rejection;
- no retry of a failed Lattigo MHE round with reused shares, CRP, or public polynomial;
- clean session destruction and a fresh ceremony for recovery.

Threshold decryption and validator signatures are separate controls. Using the same three operators
for both roles may be expedient in the lab but does not create independent correctness assurance.

### Production roadmap

Before funds or automated production actions are authorized, Mordant needs a documented key
ceremony, geographically and organizationally independent operators, authenticated channels,
rotation and revocation, encrypted backups, share-loss recovery, liveness and timeout rules,
equivocation evidence, operator accountability or slashing, cryptographic audit, and an assurance
path for correct execution. None is delivered by the ten-day spike.

## RESULT AUTHENTICATION

The minimum prototype authentication is a configurable quorum of active validators signing the
exact EIP-712 result digest, including chain, verifier, vault, immutable policy version, both ordered
input commitments, result fields, nonce, expiry, and result commitment. Signatures are unique and
strictly ordered. Revoked or unknown validators do not count.

This establishes **who endorsed the result**, not **that the FHE computation was correct**:

| Option | Assurance | Position |
| --- | --- | --- |
| Single evaluator signature | The evaluator authenticates its own assertion. | Insufficient outside local wiring. |
| Threshold decryptor/validator signatures | A quorum released and endorsed the bound result. | Minimum prototype; collusion and incorrect computation remain possible. |
| TEE attestation | Binds result/key release to measured code. | Future candidate; adds hardware vendor, attestation service, rollback, and side-channel trust. |
| ZK proof of computation/transition | Portable correctness proof in principle. | Strong future direction; circuit, proving time, proof size, and Monad verification gas are unmeasured. |
| Verifiable coprocessor network | Delegates correctness and availability to a network security model. | Acceptable only with a concrete Monad-compatible network, contract, and measured costs. |

No accepted result proves invoice authenticity, legal priority, absence of undisclosed pledges,
truth of an authorized source, or correctness of an external oracle.

## METADATA LEAKAGE

Leakage that remains even under a correct implementation:

- ciphertext and attestation sizes;
- submission and acceptance timing;
- relayer and network metadata;
- vault, policy ID/version, two input commitments, result Boolean, responsible role, cure deadline,
  nonce, expiry, and final commitment;
- gas usage and the fact that a policy evaluation occurred;
- equality/reuse within a vault/policy epoch when salted public receivable links are used.

Required mitigations are fixed envelope classes or padding where measured as practical, per-epoch
high-entropy salts, no low-entropy invoice hashes, client-side encryption, stable error codes,
ephemeral benchmark outputs, recursive artifact scans, and no debug dumps. Padding can reduce size
leakage but cannot eliminate traffic analysis.

The full-FHE identity option removes the stable link commitment. Its incremental measured cost is
6,291,954 bytes per pledge, 12,583,908 FHE-envelope bytes per decision, about 2.39 seconds median
evaluation, and about 90 MB peak Go heap. It does not hide the final public result or transaction
metadata.

## PERFORMANCE

Targets are diagnostic, not automatic verdicts:

- client encryption under 3 seconds;
- FHE evaluation under 30 seconds;
- complete result-to-Monad acceptance under 60 seconds.

At least one warm-up and five measured runs are required. Publish median and p95; separate cold key
setup from warm per-case execution. The report must name CPU, architecture, memory, OS, Go version,
Lattigo version, parameter set, thread count, and whether the binary ran natively or through an
emulation layer. A GPU field is `not used`, not fabricated as zero.

| Measurement | Median | p95 / size | Gate note |
| --- | ---: | ---: | --- |
| Threshold/key setup | **2,065 ms** | one cold setup | Includes Shamir setup and collective keys |
| Collective public-key generation | **included above** | all three 2-of-3 coalitions validated | Exact phase timing is retained in the benchmark artifact |
| Relinearization/Galois key generation | **included above** | 9 rotation keys | Steps `1,2,4,8,16,32,64,-64,128` |
| Public key size | — | **7,864,600 bytes** | Serialized canonical bytes |
| Evaluation key size | — | **314,584,702 bytes** | Serialized relin plus Galois keys; material deployment cost |
| Threshold share size | — | **3,932,296 bytes / party** | Three shares co-located in this harness |
| One encrypted pledge size | — | **25,168,031 B public-link; 31,459,985 B full-FHE** | Complete serialized confidential envelope |
| Client encryption A | **325 ms public-link; 474 ms full-FHE** | **352 ms; 537 ms p95** | Target `< 3 s` met on the named desktop host |
| Strict comparisons A + B | **batched inside total** | exact 2 x `uint64` | Per-comparison amortized timing retained in JSON artifact |
| Equality and condition predicates | **batched inside total** | exact 256-bit currency; optional 256-bit identity | Authorization is a fail-closed ingress grant, not a client Boolean |
| Final encrypted AND | **retained in artifact** | depth 10 public-link; depth 11 full-FHE | Includes the selected identity strategy |
| Total FHE evaluation | **5,277 ms public-link; 7,665 ms full-FHE** | **6,014 ms; 8,682 ms p95** | Target `< 30 s` met |
| Threshold result decryption | **39.0 ms public-link; 40.5 ms full-FHE** | **48.7 ms; 57.7 ms p95** | Coalitions rotate across measured runs |
| Pledge serialization/deserialization | **16.8 / 12.3 ms public-link; 26.4 / 16.5 ms full-FHE** | **20.2 / 28.2 ms; 54.8 / 52.6 ms p95** | Pledge A canonical envelope; threshold transport remains co-located |
| FHE envelope bytes | — | **56,628,012 B public-link; 69,211,920 B full-FHE** | Two pledges plus decision ciphertext; excludes threshold transport, attestation, and calldata |
| Peak Go heap | — | **1.031 GB public-link; 1.121 GB full-FHE** | Runtime heap sampler; process RSS is reported separately if measured |
| Peak GPU memory | — | **not used** | CPU implementation; no fabricated zero |
| Adapter accept gas | — | **153,324 gas local median** | 21-test Foundry suite; below Monad's documented transaction limit |
| Two-signature adapter calldata | — | **868 bytes** | ABI-encoded result plus validator-set ID and two ECDSA signatures |
| Public-result-to-adapter acceptance | **158.5 ms observed run** | controlled local Anvil only | Not Monad testnet; target `< 60 s` for this segment met |
| Full-FHE identity equality delta | **+2,388 ms evaluation median** | **+6,291,954 B / pledge; +12,583,908 B FHE envelope** | No additional evaluation-key material because currency already requires the 128-slot rotation |

No performance claim is valid until the same build passes the exact policy and negative tests.

## LICENSES

| Component | License / terms | Decision relevance |
| --- | --- | --- |
| OpenFHE 1.5.1 | BSD-2-Clause | Permissive, but technical compatibility blocks this slice. |
| Lattigo 6.2.0 | Apache-2.0 | Compatible with the independent prototype; notices and dependency audit still required. |
| Mordant provider-neutral schemas/adapter | Repository project terms | Must remain independent of provider-specific types. |
| Fhenix CoFHE | Dependency-by-dependency legal audit **not performed because it was not selected** | Not a primary route and no documented Monad support. |
| TFHE-rs / Zama patented technology | BSD-3-Clause-Clear for stated non-commercial categories; separate commercial patent license described by Zama | Commercial fallback requires written legal/license clearance. |

This report is an engineering assessment, not legal advice. A permissive source license does not by
itself resolve patent, hosted-service, operator, or commercial-deployment terms.

## SECURITY RISKS

1. **False source data:** a compromised or dishonest authorized client can encrypt a lie. FHE
   protects confidentiality; it does not prove real-world truth.
2. **Incorrect computation:** threshold signatures authenticate endorsers, not circuit correctness.
   A malicious evaluator plus colluding quorum can produce a false result.
3. **Passive-only multiparty model:** the Lattigo prototype does not add malicious-share proofs or a
   Byzantine network protocol.
4. **Unsafe retry:** reusing MHE shares/public randomness after a failure risks key leakage. Every
   retry must be a new cryptographic session.
5. **Experimental parameters:** the comparator's BGV parameters and depth require an independent
   security review; passing functional tests is not a cryptographic audit.
6. **Encoding mismatch:** narrowing the existing `uint256 amount` or `bytes32 currency`, or omitting a
   bound commercial field, can create silent semantic divergence.
7. **Authorization substitution:** a caller-provided encrypted Boolean is not evidence that a
   submitter was authorized.
8. **Quorum governance:** owner compromise, validator collusion, immediate revocation, equivocation,
   and availability remain operational risks.
9. **Metadata and side channels:** timing, size, traffic, public output, logs, panic text, and memory
   handling can leak information even without plaintext calldata.
10. **Denial of service:** large or malformed ciphertexts and expensive evaluations require strict
    format, parameter, size, admission, and timeout controls. Timeout must never trigger an unsafe
    automatic business action.
11. **Key-share loss:** no production recovery or backup ceremony exists in the lab.
12. **Overclaiming:** the result does not establish legal priority, universal duplicate-financing
    detection, invoice authenticity, insurance, or production safety.

## TEN-DAY IMPLEMENTATION PLAN

This is the maximum credible scope after a `GO LATTIGO`; it is a controlled vertical slice, not a
production rollout.

| Day | Deliverable | Exit evidence |
| --- | --- | --- |
| 1 | Freeze provider-neutral ABI, EIP-712 domain, field ranges, privacy invariant, and client/evaluator boundary. | Shared schema validation and no-plaintext fixture policy pass. |
| 2 | Complete exact BGV bit encoding, unsigned comparator, currency equality, exclusivity, and final AND. | True/false, equality, max/min, and adjacent-period cases pass. |
| 3 | Complete encrypted envelope for amount, obligation ID, dates, currency, conditions, and input commitments. | Serialization round-trip; no narrowing from production types. |
| 4 | Complete real 2-of-3 ceremony, collective evaluation keys, threshold result release, and one-share failure. | Every intended 2-party subset works; one party cannot decrypt; failed sessions cannot retry. |
| 5 | Run conformance, malformed-input, wrong-key/version, authorization, and artifact-leakage tests. | Shared manifest and recursive privacy scan pass. |
| 6 | Benchmark one warm-up plus five runs on named native hardware; measure full-FHE identity delta. | Complete median/p95 table, memory, bandwidth, serialized sizes, parameter record. |
| 7 | Finalize standalone Monad verifier, quorum registry, revocation, EIP-712 binding, replay, expiry, and acceptance event. | Foundry positive and negative suite passes; gas/calldata recorded. |
| 8 | Wire a local end-to-end worker: encrypted submissions to policy result to threshold/quorum attestation to adapter. | One command reproduces true, false, and failure paths without plaintext artifacts. |
| 9 | Exercise process failure, fresh-session recovery, key/policy rotation, equivocation detection, and service restart. | Runbook proves terminal failed rounds and safe last state. |
| 10 | Audit evidence, document boundaries, freeze portable receipt format, and conduct human security review. | Reproducible evidence package and explicit production non-authorization. |

Out of scope: modifying the production vault/factory/M-15 runners/UI, production funds, generic
policy packs, hosted onboarding, production KMS, and claims of cryptographic audit.

## VERDICT

**FINAL VERDICT: `GO LATTIGO — CONTROLLED VERTICAL-SLICE FEASIBILITY ONLY`**

- `GO OPENFHE` — ruled out for this ten-day slice by the documented comparison/threshold
  incompatibility.
- `GO LATTIGO` — selected because every mandatory policy case, the true local 2-of-3 cryptographic
  path, negative tests, portable encoding, privacy regression scan, and authenticated local-EVM
  acceptance passed within the diagnostic latency targets.
- `FALLBACK ZAMA` — selectable only if the Lattigo blocker is precisely evidenced and the Zama
  license, trust model, and Monad route are accepted.
- `NO-GO FHE` — required if neither independent path nor a defensible fallback meets the trust,
  privacy, correctness, time, and maintenance constraints.

This verdict establishes that the exact policy is not a cryptographic or performance kill condition.
It does **not** establish a separated external client, independent share custody, correct-computation
proof, durable sessions, complete transport/RSS measurements, Monad-network latency, or production
safety. Those are integration gates, not footnotes.

## MY RECOMMENDATION

Proceed with **Lattigo behind the provider-neutral interface**, but only to harden this controlled
workflow into a separated prototype. OpenFHE should not consume more of this slice, and Zama should
not be introduced without a newly evidenced blocker plus legal and trust-model review.

The next engineering work is not another policy or a production-vault integration. It is to split
the current co-located trust boundary: authenticated external ingress, three independently operated
share processes, durable one-shot sessions, and an attestation that binds the accepted public result
to the evaluated result ciphertext or threshold transcript. No result here authorizes production
funds or automated production action.

## EVIDENCE SUPPORTING THE DECISION

Already established:

- OpenFHE's official examples and maintainer answers establish the current comparison/threshold
  blocker.
- Lattigo 6.2.0 officially exposes exact BGV arithmetic and `t-out-of-N` multiparty building blocks,
  together with a material no-retry security warning.
- Shared schemas fix the policy, public tuple, commitments, EIP-712 domain, privacy invariant,
  threat model, and negative-case manifest independently of a provider.
- Monad's official documentation establishes EVM/RPC compatibility and Execution Events, while no
  reviewed official primitive authenticates arbitrary off-chain FHE computation.
- Fhenix's current supported-network documentation does not include Monad.
- Zama's official material establishes both the complete coprocessor/Gateway/ACL/KMS architecture
  and the need to review commercial patent-license terms.

Measured evidence closing this bounded decision:

- reproducible commands, source base `9423937`, Go 1.24.0 native `darwin/arm64`, Apple M1 host,
  Lattigo 6.2.0, and exact parameter family are recorded in the lab README and benchmark artifact;
- the full native Go suite passes, including **9 / 9** encrypted policy cases, malformed inputs,
  authorization failures, wrong key/version, replay, expiry, and canonical encoding checks;
- the same evaluated result ciphertext is released by each fresh 2-of-3 coalition `{0,1}`, `{0,2}`,
  and `{1,2}`; one share is rejected;
- five measured runs after warm-up publish medians, nearest-rank p95, serialized ciphertext/key
  sizes, FHE-envelope bytes, and peak Go heap for both identity modes;
- process RSS, raw per-run samples, complete distributed transport bandwidth, and Monad-testnet
  latency were **not measured** and are not claimed;
- Foundry verifier evidence: **26 / 26 tests; 182,796 gas schema-2 successful call; 900-byte
  two-signature calldata; replay, equivocation, expiry, monotone policy version, validator-set
  rotation, and revocation covered**;
- controlled workflow evidence: **10 / 10 tests**, real Go provider output accepted once on local
  Anvil, exact replay rejected, about **105.6k gas** in the end-to-end run, and **64.943 ms** final
  public-result-to-accept latency in the independent rerun;
- known-private-literal scan outside source/tests: **passed**; failure output is reduced to stable
  codes and provider unknown/private/ciphertext fields fail closed;
- final independent review confirms lossless `uint256` amount transport, full `bytes32` equality,
  strict `uint64` comparisons, gateway-side rather than client-supplied authorization, and terminal
  post-start threshold sessions.

Open integration gaps:

- external clients can cross a signed canonical enrollment boundary, but issuer trust/revocation is
  not yet a durable organization service and the issuer signature is not a ciphertext
  well-formedness proof;
- operator processes and durable c1-bound one-shot state are implemented, but initial share
  provisioning is still co-located and no distributed DKG/KMS custody ceremony exists;
- `providerProofBoundToAttestation` is true for schema 2, but the quorum authenticates committed
  threshold evidence rather than proving the FHE computation correct;
- `PrivateMetadataCommitment` is opaque but does not yet have a canonical field encoding proving
  coverage of pledge nonce/deadline, identities, and signature;
- noise/failure bounds, sigma-flooding assumptions, independent cryptographic review, raw samples,
  source-tree hash, distributed transport, process RSS, and Monad testnet remain future evidence.

## OWNER DECISION REQUIRED

The owner already authorized the controlled FHE workflow. The completed lab stays isolated on its
review branch. A separate owner decision is required before any import into Mordant's production
contracts, M-15 runners, or public product surfaces.

## NEXT IMPLEMENTATION MISSION

Harden the now-proven local path without adding policy scope:

```text
signed external ciphertext enrollment
-> exact confidential overlap policy
-> three separately hosted threshold-share processes
-> durable one-time threshold result release
-> result-ciphertext/transcript-bound quorum attestation
-> bounded Monad testnet adapter acceptance
-> provider-neutral receipt
```

The mission must preserve the current vault invariants, keep FHE types behind
`IConfidentialPolicyVerifier`, leave Monad canonical, and remain controlled/test-assets-only. The
existing recourse workflow should be connected only after these boundaries are demonstrably real.
It must not present validator signatures alone as proof of correct computation or authorize
production funds.
