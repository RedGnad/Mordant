# Mordant

**The recourse layer for tokenized private credit.**

When something goes wrong with a financed asset, the question is rarely "did it happen". It is
"who is responsible, by when, and what is owed". Mordant turns a confirmed exception on a tokenized
receivable into a governed, auditable consequence, without requiring anyone to publish the private
records that revealed it.

Its first workflow is **Conflicting Pledge Protection**: detecting whether two lenders hold
overlapping financing claims against the same receivable, when neither will disclose its book.

> Conflict became recourse.

|  |  |
| --- | --- |
| **The problem** | One receivable can carry two financing claims. Publishing a pledge book is how a lender loses its book, so the windows stay private, the overlap stays invisible, and the safe decision is to stop lending. |
| **What Mordant adds** | The private decision, and the consequence that follows it. Mordant detects whether two claims collide **without either lender disclosing its window**, then turns a confirmed collision into recourse that anyone can verify afterwards. |
| **Why Cleanverse** | Cleanverse establishes what the asset is and who may hold a claim against it. Mordant needs all three of its primitives and provides none of them. |
| **What is genuinely live** | Real BGV homomorphic evaluation, a governed Ed25519 signed result, and a real bounded settlement on Monad testnet: a 600-second cure window that expired uncured, permissionless finalization, and both aUSDC claims paid and reconciled. |
| **Where to verify it** | Run the check yourself on the [live product](https://mordant-two.vercel.app), then inspect the [completed on-chain recourse](https://mordant-two.vercel.app/protection/verified-run). |

**Cleanverse verifies asset provenance and identity plus participant eligibility, not legal validity
or enforceability. Mordant privately evaluates whether claim windows conflict. The governed result
establishes only that conflict status; approved policy and human review determine recourse actions.**

This is a bounded hackathon MVP built for Cleanverse Build: Trusted Assets, on Monad testnet. It is
not production authorized. See [What is real, and what is bounded](#what-is-real-and-what-is-bounded).

## What Mordant does

A tokenized receivable can be public while the financing commitments against it stay private, held
separately by each lender. The token records the on-chain receivable position. It does not establish
legal ownership or say who else was already promised the same cash flow.

That gap is expensive. The workflow does not require either lender to disclose its pledge window to
the counterparty to determine whether two claims overlap. So the question that matters most, *is this
receivable already pledged elsewhere*, can be evaluated without that counterparty disclosure. While
it stays unanswered the position is stuck, because acting on a suspected conflict without proof is
as risky as ignoring it.

Mordant builds a confidential path from those private records to an auditable decision, and then
keeps going. A confirmed exception does not just produce an alert: approved policy and human review
determine the action owner, deadline and escalation, while deployment configuration determines
settlement terms.

### First workflow: Conflicting Pledge Protection

The wedge is deliberately narrow, because it is the one that can be proved end to end today.

An originator finances the same invoice twice. Lender A already holds a pledge over it. Lender B is
about to lend against it. Each holds a private window during which its claim is active. If those
windows overlap, the same cash flow is promised twice, and one of them will not be repaid.

The workflow does not require either lender to disclose its pledge window to the counterparty.
Mordant evaluates whether the two windows intersect while both remain encrypted, and releases a
single signed Boolean. Under the demo's preconfigured recourse policy, conflict maps to a cure window
against a funded reserve; no conflict maps to recourse refusal rather than silence.

The circuit is fixed and pinned (`mordant.identity-full-fhe-256` v5, profile
`mordant.bgv.identity-full-fhe-256.n15/v1`), so neither party chooses what gets computed.

## Try it live

**<https://mordant-two.vercel.app>**

The landing page runs a real encrypted check. There is no fixture path behind it.

- Two synthetic pledge windows, overlapping by default, are prepared under one eligible test context.
- Real BGV evaluation runs on the fixed circuit. The evaluator receives ciphertexts and holds no
  decryption key.
- A designated decryptor independently recomputes the circuit and signs the result. No outcome is
  shown before that signature exists.
- **Typically around 30 seconds** to the governed result. Two runs measured on the current
  production deployment took 28 and 30 seconds.
- One execution slot exists by design. A second visitor sees an explicit BUSY state and waits, rather
  than running in parallel or failing silently.

The check ends at the governed result. What happens next with real money is recorded, not re-run on
demand: **[see the completed on-chain recourse](https://mordant-two.vercel.app/protection/verified-run)**.

### Two execution profiles

Mordant implements two ways for claims to enter a case, and the worker holds exactly one BGV slot,
so they are mutually exclusive at deployment time.

| Profile | What it is | Status |
| --- | --- | --- |
| **Managed combined intake** | One eligible context submits both windows. Universal access, no wallet required. | **Active on the public deployment**, so every judge can run a real check. |
| **Direct participant admission** | Two separate wallets each sign their own `ParticipantAdmissionV1` claim and never see the other's window. | Implemented, tested and qualified. Proven end to end by the hardened run below. |

The public deployment selects the managed profile for universal access. The two-wallet rail is not
removed: it remains in the codebase, runs in CI on every change, and is what produced the
authoritative settlement recorded below. Re-enabling it is one environment variable and a worker
redeploy. Details in [reviewer access](docs/reviewer-access.md).

The managed check prepares both windows on the visitor's behalf. It is a real encrypted decision,
and it is **not** two independent wallets.

## Why Cleanverse

Mordant is a decision and consequence layer. It does not tokenize assets, decide who is allowed to
hold them, or operate a compliant settlement rail. Cleanverse provides all three, and without them
there is nothing to be private *about*.

| Primitive | What it establishes | Whose responsibility |
| --- | --- | --- |
| **MINV01** | Receivable identity with verified Cleanverse provenance. This is the RWA identity used in this case. | Cleanverse |
| **A-Pass** | Participant eligibility: which wallets may hold a claim against it. | Cleanverse |
| **aUSDC** | The compliant settlement rail the consequence is paid on. A rail, not the receivable. | Cleanverse / Monad |
| **Conflict decision** | Whether the private claims collide, and the governed signature over that answer. | **Mordant** |

These are not interchangeable branding around a generic application. The A-Pass is what makes
"eligible participant" a checkable on-chain fact rather than an assertion, and the compliance
verifier refuses a transfer to an ineligible address at the token level, which makes payout
eligibility token-policy-enforced rather than merely computed. Remove the A-Pass and the participants
are anonymous addresses; remove the compliant rail and the consequence is a number in a database.

Cleanverse never sees a pledge window, and does not perform the conflict evaluation. Mordant never
issues an A-Pass or mints the receivable.

## How it works

```text
Receivable identity            MINV01, with verified Cleanverse provenance
  ↓
Eligible participant context   A-Pass checked live on Monad at submit time
  ↓
Private claims                 two windows, encrypted before they leave their owner's control
  ↓
BGV encrypted evaluation       fixed circuit over ciphertexts; the evaluator holds no decryption key
  ↓
Governed signed result         a designated decryptor recomputes, must match, then signs one Boolean
  ↓
Recourse policy application    configured demo policy: cure window, permissionless finalize,
                               aUSDC claims on Adapter V2
  ↓
Verifiable evidence            a receipt binding every digest, publicly served and re-verified
```

The original receivable claim survives either outcome. There is no burn and no transfer of the
underlying note: the reserve is what moves.

## Verified live run

One hardened two-wallet journey, executed end to end on Monad testnet. This is the authoritative
qualification.

| | |
| --- | --- |
| Run | `e618abc2-0ac7-4d79-b201-44959a54b68c` |
| Case adapter | [`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`](https://testnet.monadexplorer.com/address/0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1) |
| Participants | two canonical wallets, each A-Pass verified and **separately admitted** under its own signature |
| Private decision | real BGV on the fixed circuit, governed Ed25519 result, **conflict confirmed** |
| ReleaseConsumed | [`0x09b9bbfb…3936d651`](https://testnet.monadexplorer.com/tx/0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651) |
| Cure window | a real 600 seconds, allowed to expire uncured |
| Finalize | [`0xc74051d8…45e4fc34`](https://testnet.monadexplorer.com/tx/0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34), permissionless |
| Claims | [`0x4831b0a7…ecbea819`](https://testnet.monadexplorer.com/tx/0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819) 0.002400 aUSDC · [`0x36296bf9…430bfc50`](https://testnet.monadexplorer.com/tx/0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50) 0.001600 aUSDC |
| Reconciliation | reserve 0.004000 to 0, both holders paid exactly, liabilities cleared, adapter solvent, **MINV01 untouched** |

Read it as a product receipt at
[`/protection/verified-run`](https://mordant-two.vercel.app/protection/verified-run), or as evidence
in [`docs/direct-participant-bridge-evidence.md`](docs/direct-participant-bridge-evidence.md) and the
`docs/evidence/hardened-*` artifacts.

An earlier complete journey, run `76005a0c…` on adapter `0x00efE6AA…`, is retained under
`docs/evidence/activation-*`. It settled for real, but it predates the settlement-time admission
proofs, the external source pin and the deployment-proof binding, so it is history rather than the
current qualification.

## What is real, and what is bounded

### Real

- Cleanverse and Monad testnet asset provenance, captured and pinned by digest.
- Live A-Pass eligibility checks, made against the chain at submit time rather than trusted from
  an earlier answer.
- Real BGV homomorphic evaluation on a fixed, pinned circuit.
- A governed Ed25519 signature whose authority identity is derived from the signing key.
- Two separately admitted wallet authorizations, re-verified at settlement.
- Real Adapter V2 execution on Monad testnet: `ReleaseConsumed`, a real 600-second cure window,
  permissionless finalization, and real aUSDC claims paid and reconciled.

### Bounded

- **Lender pledge windows are synthetic fixtures.** No real lender book is represented, and the
  protected notional is illustrative.
- **Managed Mordant infrastructure sees each role's plaintext during preparation.** There is no
  participant-device encryption in either deployed profile today. A separate, disabled-by-default
  [participant-originated CLI experiment](docs/participant-originated-encryption-poc.md) exercises
  local native encryption and bounded ciphertext import; it is not a production migration.
- The evaluator receives ciphertext artifacts only and holds no decryption key.
- The decryptor is **designated and trusted**, not distributed.
- Execution is supervised single-host, with **one active BGV slot**.
- One adapter is deployed per hardened case today.
- Testnet only, at deliberately small amounts. **Not production authorized.**

Mordant does **not** claim: browser or device-side BGV; participant-controlled FHE keys; that no
Mordant infrastructure sees plaintext; threshold release; trustless or decentralized decryption;
independent institutional operators; or production readiness.

It is also not a universal duplicate-financing detector, not proof that an invoice is authentic, not
a registry of assignment priority, not insurance against debtor default, and not a general RWA
tokenization platform.

## Architecture

Four layers, each verifiable on its own.

**Private evaluation.** A fixed BGV circuit implemented in Lattigo, with keygen, client, evaluator
and decryptor as separate binaries. The evaluator never receives a decryption key, and the decryptor
must independently recompute the circuit and land on the same ciphertext digest before anything is
released.

**Governed release.** A single signed Boolean is the sole authority for the conflict/no-conflict result. The
release authority identity is derived from the signing key rather than asserted alongside it, so a
forger cannot supply a matching pair.

**Settlement.** The signed Boolean supplies the confirmed-conflict result. The configured demo
recourse policy supplies the cure path, and deployment configuration determines holders and payout
amounts. `MordantRecourseAdapter` V2 on Monad testnet holds the pre-funded reserve and pays entitled
holders in aUSDC through the Cleanverse compliance verifier. Finalize and claim are permissionless
by design; `claim` takes no recipient, so the adapter can only pay its configured holder.

**Evidence.** Every run seals a receipt binding the authorization, the participant artifacts, the
evaluated artifact, the governed result and the recourse outcome. The public surface re-verifies each
envelope before rendering and refuses anything that disagrees with its pinned source commit.

Deeper detail: [participant admission and the direct-participant rail](docs/direct-participant-bridge-evidence.md) ·
[governed recourse bridge](docs/governed-recourse-bridge.md) ·
[architecture](docs/architecture.md) · [deployment](docs/railway-deployment.md).

## Security and verifiability

What a reviewer can check independently, without trusting this repository:

- **The settlement happened.** Every transaction in [Verified live run](#verified-live-run) is on the
  public Monad testnet explorer.
- **The adapter is the reviewed contract.** Solidity writes immutables into runtime code, so raw code
  hashes cannot be compared across case deployments. The retained deployment proof records the
  compiler's immutable-span masked equality against the reviewed artifact, and the executor hashes
  the live runtime and requires it to be the exact runtime that proof covers.
- **The result was not asserted by the artifact that carries it.** The expected source commit comes
  from server configuration, never from the evidence being judged.
- **Each participant really authorized its own claim.** The signed `ParticipantAdmissionV1` payload
  and signature are retained durably and re-verified at settlement, rather than accepted by digest.
- **The evidence is internally consistent.** The public loader refuses any set whose run, adapter,
  governed result, entitlement or balance arithmetic disagree.

Detailed findings, controls and residual risk: [threat model](docs/threat-model.md) ·
[security review](docs/security-review.md) · [production gates](docs/production-gates.md).

## Scalability roadmap

**Every item below is NOT IMPLEMENTED TODAY.** They are the concrete steps between this bounded MVP
and something that could carry real volume, stated so the current limits are legible rather than
hidden.

| Current constraint | Production evolution |
| --- | --- |
| The governed authority is minted per case and pinned as an adapter immutable, so each case needs its own deployment. | An adapter factory with a governed-authority registry, so one deployment serves many cases without weakening the pin. |
| One worker runs one case at a time, because the durable journal and the single-active-case guarantee depend on it. | Horizontally isolated execution slots that run in parallel without sharing that journal. |
| Managed infrastructure prepares and encrypts the inputs, so it sees participant plaintext. | Participant-side encryption, removing that trust entirely. The most valuable item on this list. |
| Admission verifies an EOA secp256k1 signature. | ERC-1271 contract-signature verification, which is what an institution would actually use. |
| Evaluator and decryptor run on one supervised host. | Separation across independent operators, making "the evaluator holds no key" an organizational fact rather than a process boundary. |
| A single designated decryptor signs the result. | Threshold or multi-party governed release, removing one party's ability to refuse or forge an answer. |

Beyond the first workflow, the same private-decision and recourse model extends to other
private-credit situations where confidential records must produce a governed action: assignment
priority conflicts, covenant and eligibility exceptions, document conflicts, collateral conflicts.
**None of these are implemented.** Conflicting Pledge Protection is the only policy in this
repository.

## Development and verification

```bash
pnpm install
pnpm validate        # lint, typecheck, unit, Foundry, evidence gate, secret scan, integration gates, build
```

`pnpm validate` is the single command that has to pass. It runs the complete Foundry suite, the
frozen-source and ABI-selector gates, the reproducible evidence gate and the secret scanner.

The focused suites, when you want one area:

```bash
pnpm protection:test   # protection product, admission, bridge executor, adversarial batteries
pnpm test:e2e:public   # the public experience at all seven qualified viewports
pnpm test:contracts    # Foundry only
```

The evidence gate re-derives what is true on chain rather than trusting any note in this repository.
The default run replays a recorded fixture and writes nothing; a live run is strictly read-only,
refuses every state-changing JSON-RPC method, aborts unless the chain is Monad testnet, and pins one
block for all readings.

```bash
pnpm evidence:cleanverse
```

Never commit Cleanverse credentials. Configure them in `.env.local`, which is git-ignored.

## Hackathon

Built for **Cleanverse Build: Trusted Assets**, RWA track, on **Monad testnet**.

Stack: Next.js 16, React 19, TypeScript, Foundry, Lattigo BGV, Monad testnet, and the Cleanverse
primitives (CVI / A-Pass, a dedicated invoice A-Token, aUSDC settlement and Validator Compliance).

## Documentation

| Document | Purpose |
| --- | --- |
| [Reviewer access](docs/reviewer-access.md) | How to exercise the live product, and the two execution profiles |
| [Direct-participant bridge evidence](docs/direct-participant-bridge-evidence.md) | The hardened two-wallet run, its evidence schema and verifier |
| [Governed recourse bridge](docs/governed-recourse-bridge.md) | Adapter V2 pins, the EIP-712 release and the case-specific deployment model |
| [Conflicting Pledge Protection](docs/conflicting-pledge-protection.md) | Execution boundary, governed release, evidence model |
| [Architecture](docs/architecture.md) | Recourse kernel, contracts, policy compatibility |
| [Cleanverse integration](docs/cleanverse-integration.md) | What is documented, observed and still blocked |
| [Threat model](docs/threat-model.md) | Attacker classes and mitigations |
| [Security review](docs/security-review.md) | Findings and residual risk |
| [Production gates](docs/production-gates.md) | Hard gates before real funds |
| [Railway deployment](docs/railway-deployment.md) | Worker runbook, required variables, resource profile |
| [Activation blockers](docs/activation-blockers.md) | **Superseded.** The historical record of what was refused before the architecture correction |
| [Shadow pilot](docs/product/shadow-pilot.md) | Scope, processing and measurements for a permissioned pilot |
