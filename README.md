# Mordant

**The recourse layer for tokenized private credit.**

**Mordant protects investors when the same receivable is financed twice.** It turns an
authenticated private-credit case state into a policy-governed bounded action and
verifiable evidence. Its first implemented workflow is **Conflicting Pledge Protection**: two private
financing claims against one receivable are evaluated under encryption, the signed conflict status
enters a policy committed before result exposure, and the resulting managed operation is bound to a
receipt.

> Conflict became recourse.

## Verify the Cleanverse integration in 30 seconds

- **The live run is gated by a fresh on-chain A-Pass read.** Open the
  [live workflow](https://mordant-two.vercel.app/protection/live) and check eligibility for the
  preloaded holder: a launch token is minted only after
  [`ccp-eligibility.ts`](src/lib/protection/ccp-eligibility.ts) calls the Cleanverse validator's
  `complianceVerify` on Monad at submit time. An ineligible holder cannot start a run.
- **Institutional admission is Cleanverse-gated.** A participant wallet is admitted only after
  `verifyApass` runs against the wallet that actually signed; a Cleanverse refusal returns
  `APASS_DENIED`
  ([`participant-admission-service.ts`](src/lib/protection/participant-admission-service.ts)).
- **Role and payout gating is enforced in the contracts.** Case creation reverts unless
  `cviVerifier.isEligible` passes for the facility, buyer and originator roles
  ([`MordantFactoryV2.sol`](contracts/src/MordantFactoryV2.sol)), and the deployed
  [case adapter](https://testnet.monadexplorer.com/address/0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1)
  of the hardened run checked eligibility before opening the cure and before each aUSDC holder
  claim listed below.

| Product level | What is implemented or qualified |
| --- | --- |
| **Mordant** | Recourse infrastructure for tokenized private credit: governed result, precommitted policy, bounded operation and evidence. |
| **First implemented workflow** | Conflicting Pledge Protection. It establishes whether two submitted claim windows conflict; it is the concrete first workflow, not the entire product category. |
| **Current live managed proof** | A fresh real BGV evaluation followed by the current Governed Recourse Policy, a bounded local operation and operation-bound evidence. |
| **Qualified institutional privacy profile** | An opt-in native CLI lets each participant encrypt its claim in a participant-controlled environment before ciphertext-only Mordant coordination receives it. This profile is separate from the managed public proof and browser direct admission. |
| **Separate verified execution** | A retained hardened two-wallet Adapter V2 run with a real 600-second cure window, finalization, aUSDC claims and reconciliation on Monad testnet. |
| **Roadmap** | Production execution routing and N=3 private conflict graphs. These are not current capabilities on this branch. |

The current managed authority chain is:

```text
private claims
  → governed cryptographic result
  → precommitted Governed Recourse Policy
  → verified governed action plan
  → durable plan-derived operation authorization
  → bounded managed operation
  → verified action-compatible outcome
  → operation-bound evidence
```

**The governed result establishes conflict or no conflict only.** It does not independently
authorize recourse, operational action, settlement or legal judgment, and it establishes no legal
priority, responsibility, ownership, fraud, default, payout recipient or payout amount. The
precommitted policy selects the bounded managed branch. Human and institutional processes remain
responsible for legal and operational judgment.

This is a bounded hackathon MVP built for Cleanverse Build: Trusted Assets on Monad testnet. It is
not production authorized.

## What Mordant does

Private-credit exceptions are rarely useful as unauthenticated alerts. A usable recourse layer has
to preserve the private fact boundary, authenticate the case state, apply a policy that was fixed
before the answer was known, authorize only the operation that policy permits, and retain evidence
that binds the outcome back to that authority.

Mordant implements that chain for one concrete workflow today. The design separates:

- **result authority** — the signed conflict status;
- **policy authority** — a closed policy branch committed before result exposure;
- **operation authority** — a durable authorization derived from that selected plan;
- **evidence** — the verified operation and outcome bound back to the result and policy.

This separation is why a Boolean cannot silently become a cure, payout or legal conclusion.

## First implemented workflow: Conflicting Pledge Protection

One tokenized receivable can be referenced by two private financing claims. Conflicting Pledge
Protection evaluates whether their active windows intersect without requiring either counterparty
to disclose its window to the other.

The implementation is deliberately exact:

1. Cleanverse provenance identifies MINV01 and A-Pass establishes participant eligibility.
2. A fixed pinned BGV circuit evaluates two claim windows under encryption.
3. A designated governed decryptor recomputes the circuit and signs the conflict/no-conflict result.
4. The current managed policy consumes that result and selects one closed branch.
5. The resulting plan authorizes one existing bounded managed operation.
6. The terminal receipt binds the operation and its outcome to that authorization.

The circuit is `mordant.identity-full-fhe-256` v5 under profile
`mordant.bgv.identity-full-fhe-256.n15/v1`. The evaluator receives ciphertext artifacts and has no
decryption key. The governed decryptor is a separate, Mordant-controlled designated process; this
repository therefore does **not** make the global claim that “Mordant holds no decryption key.”

Conflicting Pledge Protection does not prove invoice authenticity, legal validity, enforceability,
assignment priority, fraud or default. It is also not a universal duplicate-financing detector.

## Try the current live managed proof

**<https://mordant-two.vercel.app>**

The public landing runs the first workflow through the existing managed execution path:

- the visitor places two synthetic financing claims on one shared demo timeline;
- the managed intake validates each claim independently and does not predict their relationship;
- Mordant managed infrastructure receives the demo values and prepares the encrypted artifacts;
- the fixed BGV evaluation is real, and the evaluator receives ciphertexts only;
- no outcome appears until the governed result exists;
- policy `mordant.managed-demo.facility-protection@1` was selected before result exposure;
- conflict selects a **24-hour local protocol-double cure path**; no conflict selects record-and-close;
- settlement authorization is `NOT_AUTHORIZED` in both managed branches;
- the bounded operation and terminal evidence are bound to the selected action plan.

This live proof is current and reproducible. It is **not** a fresh Monad/aUSDC settlement and it is
not two independent institutions. The public deployment exposes one BGV slot, so a concurrent
visitor receives an explicit busy response rather than an invented progress state.

The completed real on-chain execution is a separate proof surface:
**[verify the hardened run](https://mordant-two.vercel.app/protection/verified-run)**.

## Governed Recourse Policy

The managed policy is a real authority layer, not explanatory copy.

| Field | Current managed V2 value |
| --- | --- |
| Policy | `mordant.managed-demo.facility-protection@1` |
| Hash | `sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e` |
| Selection | Committed before result exposure |
| Conflict branch | `OPEN_LOCAL_CURE_PATH` |
| Managed cure duration | `86,400` seconds — 24 hours |
| No-conflict branch | `RECORD_AND_CLOSE` |
| Managed operation class | Local protocol double / evidence only |
| Settlement authorization | `NOT_AUTHORIZED` |

The policy is code/deployment committed. Mordant does not currently provide an institution-facing
policy editor or a cryptographic institution-approval attestation. The policy does not determine
legal truth and does not authorize settlement. See
[Governed Recourse Policy](docs/governed-recourse-policy.md) for the schemas and binding chain.

## Privacy and intake profiles

Privacy claims are scoped to the component and profile that actually provides them.

| Boundary | Current truth |
| --- | --- |
| **Managed combined intake** | Active public profile. Managed infrastructure receives both synthetic demo windows during intake/preparation, then performs real BGV evaluation. |
| **Direct participant admission** | Implemented and tested. Two distinct wallets separately sign `ParticipantAdmissionV1`; this proves separate authorization, not participant-local encryption. |
| **Participant-originated native CLI** | Current qualified capability. In this opt-in, disabled-by-default profile, each participant encrypts its claim in a participant-controlled environment before Mordant coordination receives it. It is not the managed public profile or the browser direct-admission profile. |
| **Evaluator** | Receives ciphertext artifacts only and has no decryption key. |
| **Governed decryptor** | Designated, trusted and Mordant-controlled; not threshold or independently operated. |

The workflow does not require one lender to disclose its pledge window to the counterparty. That is
different from claiming that no Mordant infrastructure receives plaintext. Browser/device BGV,
participant-controlled decryption, threshold release, semantic equality proofs and ERC-1271
support are not current capabilities.

The participant-originated capability is intentionally a profile of the same recourse system, not a
second product: encrypt in a participant-controlled native environment, authenticate the ciphertext
artifact, then admit it to Mordant coordination. Its supported surface is the qualified native CLI
and ciphertext-only coordinator service. It remains opt-in and is not wired into the universal
managed public demo or browser wallet-admission flow.

## Cleanverse responsibility boundary

| Primitive | What it establishes | Responsibility |
| --- | --- | --- |
| **MINV01** | Cleanverse provenance and asset identity used by this case; not invoice authenticity or legal enforceability. | Cleanverse |
| **A-Pass** | Participant eligibility observed from the configured on-chain policy. | Cleanverse |
| **Private conflict status** | Whether the submitted claim windows conflict. | Mordant governed result |
| **Bounded action branch** | The managed operation permitted for that result. | Mordant Governed Recourse Policy |
| **aUSDC rail** | The compliant rail used by the separate historical hardened settlement. | Cleanverse / Monad deployment configuration |

Cleanverse does not evaluate pledge windows. Mordant does not issue an A-Pass or mint the
receivable. The original receivable stays intact through both demonstrated outcomes.

## Proof surfaces

### Unified governed settlement

A governed Boolean cannot authorize payment on its own. Every economic term, the
case binding and the governing authority are committed and digest-bound before
the case produces a result, and the durable store refuses to commit once any
result-bearing artifact exists. `BridgeExecutor` then refuses to sign a paying
release without an authorization that matches it exactly, before the attestor key
is loaded.

One case settled end to end on Monad testnet under this discipline: real BGV
conflict, case-specific Adapter V2, `fundReserve`, `ReleaseConsumed`, a real
600-second cure window, permissionless finalization, both holder claims and exact
reconciliation. Full hashes and the strict chronology are in the
[unified settlement manifest](docs/evidence/unified-settlement-manifest.md); the
authority seam and its negative controls are in the
[settlement authority proof](docs/evidence/settlement-authority-proof.md).

### Current managed V2 proof

The fresh public run proves the current result-to-policy chain. Its receipt carries eligibility
observation, participant/evaluated artifact digests, governed result digest, policy selection,
selected plan, durable operation authorization and action-compatible evidence. Exact hashes and raw
records are progressively disclosed for technical verification.

For the conflict branch, the local cure deadline must satisfy:

```text
cureDeadlineUnix - boundAtUnix = 86,400 seconds
```

This local action does not move real funds and is not Adapter V2 settlement authorization.

### Qualified institutional privacy profile

Participant-originated encryption is a current, qualified native-CLI capability. Each participant
prepares and signs its own case- and role-bound encrypted artifact in a participant-controlled
environment. Mordant coordination receives authenticated encrypted artifacts rather than raw claim
window bounds in this profile.

This does not globalize the claim to the public managed profile or direct wallet admission. It does
not claim browser/device BGV, participant-controlled or threshold decryption, semantic equality
between a commitment and ciphertext plaintext, production institutional key management, or
production-cluster readiness. The profile is opt-in and disabled by default. See
[Participant-originated encryption](docs/participant-originated-encryption.md) and the retained
[qualification evidence](docs/evidence/participant-originated-encryption-product-qualification.json).

### Separate verified historical on-chain execution

Run `e618abc2-0ac7-4d79-b201-44959a54b68c` is a hardened two-wallet execution retained exactly as
it occurred. It predates the current managed V2 policy-authority chain and must not be presented as
a continuation of a fresh managed run.

| Evidence | Verified historical value |
| --- | --- |
| Case adapter | [`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`](https://testnet.monadexplorer.com/address/0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1) |
| Participants | Two canonical wallets, A-Pass checked and separately admitted |
| Governed result | Conflict confirmed under the historical architecture |
| Release consumed | [`0x09b9bbfb…3936d651`](https://testnet.monadexplorer.com/tx/0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651) |
| Cure window | **600 seconds**, allowed to expire uncured |
| Finalization | [`0xc74051d8…45e4fc34`](https://testnet.monadexplorer.com/tx/0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34), permissionless |
| Holder claims | [`0x4831b0a7…ecbea819`](https://testnet.monadexplorer.com/tx/0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819) 0.002400 aUSDC · [`0x36296bf9…430bfc50`](https://testnet.monadexplorer.com/tx/0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50) 0.001600 aUSDC |
| Reconciliation | Reserve cleared, both configured claims paid, adapter solvent, MINV01 unchanged |

In this historical run, the governed result established conflict, the preconfigured historical demo
policy applied, Adapter V2 opened the cure path, and deployment configuration determined holders
and payout amounts. The Boolean carried none of those amounts. Historical receipts and digested
evidence remain unchanged.

## What is real and what is bounded

### Real and qualified

- Cleanverse/Monad testnet provenance and live A-Pass observation.
- Real BGV evaluation on the fixed pinned circuit.
- Governed Ed25519 conflict status whose authority identity is derived from the signing key.
- Current managed V2 policy selection, closed branch, plan-derived operation authorization and
  operation-bound evidence.
- Direct-participant wallet authorization and exact admission retry semantics.
- Qualified participant-originated native-CLI encryption with ciphertext-only coordination, within
  its documented opt-in boundary.
- A separate completed Adapter V2 execution with a real 600-second cure, finalization and aUSDC
  reconciliation.
- Architectural N=2 evidence that multiple isolated existing worker slots can run concurrently.

### Bounded

- Claim windows and protected notionals are synthetic fixtures.
- Managed infrastructure sees demo plaintext during intake/preparation.
- The qualified participant-originated profile is a separate native-CLI surface; it is not wired
  into the managed public run or browser direct-admission flow.
- The designated decryptor is trusted and Mordant-controlled.
- The public deployment exposes one active BGV slot.
- The managed 24-hour cure action is a local protocol double and cannot authorize settlement.
- The verified real settlement is a retained historical hardened run, not replayed by each visitor.
- Testnet only, at deliberately small amounts; not production authorized.

## Architecture summary

Mordant's current product architecture has four separable authority layers:

1. **Private evaluation** — fixed BGV binaries separate preparation, evaluator and governed
   decryptor roles. The evaluator receives no secret key.
2. **Governed result** — an authenticated conflict/no-conflict status, and nothing more.
3. **Governed Recourse Policy** — code/deployment committed before result exposure; one closed branch
   becomes a verified action plan and durable operation authorization.
4. **Evidence** — the operation outcome is checked for compatibility and bound back to the selection,
   plan and result.

The repository also contains the specialised vault/Adapter V2 settlement architecture used by the
separate hardened on-chain run. It is a qualified execution proof, not the generic definition of
Mordant and not the managed V2 operation.

Deeper detail: [architecture](docs/architecture.md) ·
[Governed Recourse Policy](docs/governed-recourse-policy.md) ·
[reviewer access](docs/reviewer-access.md) ·
[direct-participant bridge](docs/direct-participant-bridge-evidence.md) ·
[historical Adapter V2 bridge](docs/governed-recourse-bridge.md).

## Scalability and research roadmap

Three layers must not be collapsed:

- **Public deployment:** one active BGV slot, with fail-closed busy handling.
- **Qualified architectural proof:** two isolated instances of the existing worker executed opposite
  real BGV cases concurrently, with simultaneous evaluator processes and isolated durable roots.
  The supported claim is exactly: **“Multiple isolated execution slots can run concurrently.”**
- **Production roadmap:** routing, pooling, load balancing, autoscaling, high availability,
  independent operators and capacity qualification. None is established by the N=2 proof.

See [N=2 isolated execution evidence](docs/evidence/n2-isolated-execution-proof-2026-08-08.md).

**N=3 Private Conflict Graph is research/roadmap only.** The current first workflow evaluates two
claims. N=3 and multi-funder graph semantics are not a live capability, current proof or primary
product claim.

Other future workflows may apply the same result → policy → authorized action → evidence model to
assignment conflicts, covenant exceptions, eligibility exceptions or document conflicts. They are
not implemented today.

## Security and verifiability

A reviewer can independently verify:

- the hardened settlement transactions on the public Monad testnet explorer;
- the reviewed Adapter V2 runtime against its immutable-aware deployment proof;
- the governed result signature and its derived authority identity;
- the current managed policy hash, selection, plan and operation authorization chain;
- exact participant admissions and the same-wallet/nonce/payload refusal controls;
- receipt cross-references and terminal arithmetic;
- the retained N=2 isolation evidence with its fail-closed validator.

Detailed boundaries: [threat model](docs/threat-model.md) ·
[security review](docs/security-review.md) ·
[production gates](docs/production-gates.md).

## Development and verification

```bash
pnpm install
pnpm typecheck
pnpm lint
pnpm build
pnpm protection:test
pnpm test:e2e:public
```

The complete release runner additionally covers the frozen-source, ABI, evidence, secret-scan,
integration and contract gates. Evidence replay is read-only by default; no real key or live write
is required for the product/presentation suites.

Useful focused commands:

```bash
pnpm recourse-policy:test
pnpm proof:n2-isolation:validate
pnpm secret:scan
```

Never commit Cleanverse credentials. `.env.local` is ignored.

## Hackathon

Built for **Cleanverse Build: Trusted Assets**, RWA track, on **Monad testnet**.

Stack: Next.js 16, React 19, TypeScript, Foundry, Lattigo BGV, Monad testnet, and Cleanverse
primitives including CVI/A-Pass, MINV01 and aUSDC.

## Documentation

| Document | Purpose |
| --- | --- |
| [Reviewer access](docs/reviewer-access.md) | Current public managed proof, direct-admission boundary and separate hardened run |
| [Governed Recourse Policy](docs/governed-recourse-policy.md) | Current managed result, policy, plan, authorization and evidence chain |
| [Conflicting Pledge Protection](docs/conflicting-pledge-protection.md) | First-workflow mechanism and current/historical execution boundaries |
| [Architecture](docs/architecture.md) | Current product authority layers and specialised historical settlement architecture |
| [Direct-participant bridge evidence](docs/direct-participant-bridge-evidence.md) | Separate wallet admission and hardened-run evidence |
| [Governed recourse bridge](docs/governed-recourse-bridge.md) | Historical Adapter V2 bridge and execution pins |
| [Cleanverse integration](docs/cleanverse-integration.md) | Classified provenance and integration evidence |
| [N=2 isolation evidence](docs/evidence/n2-isolated-execution-proof-2026-08-08.md) | Exact qualified concurrency claim and exclusions |
| [Shadow pilot](docs/product/shadow-pilot.md) | Permissioned human-led pilot boundary |
| [Production gates](docs/production-gates.md) | Hard gates before production or real-fund authorization |
