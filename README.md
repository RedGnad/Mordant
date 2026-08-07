# Mordant

**Mordant keeps tokenized credit moving when private claims collide.**

Mordant privately detects conflicting pledges on verified receivables and turns confirmed conflicts
into governed, auditable recourse, without exposing lender records.

The current MVP combines retained Cleanverse asset and participant provenance on Monad with real
local BGV FHE, a governed signed result, and publicly verifiable evidence.

> Conflict became recourse.

This is a working bounded hackathon MVP, built for Cleanverse Build: Trusted Assets. It is not
production-authorized. Pledge records are synthetic and no real lender funds move. See
[Current boundary](#current-boundary).

## Current state: verified live run on Monad

**A fresh two-wallet BGV journey has been executed end to end on Monad testnet.** This is the
authoritative status of the product. Any document describing an unresolved blocker is historical.

| | |
|---|---|
| Run | `e618abc2-0ac7-4d79-b201-44959a54b68c` |
| Network | Monad testnet, chain `10143` |
| Participant A / B | `0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685` / `0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9`, each A-Pass verified and separately admitted |
| Wallet authorization | Each participant's `ParticipantAdmissionV1` payload and signature retained durably and **re-verified at settlement**, not merely asserted by digest |
| Private decision | Real BGV on the fixed circuit, governed Ed25519 result, **conflict confirmed** |
| Case adapter | [`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`](https://testnet.monadexplorer.com/address/0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1) |
| Adapter identity | Masked runtime bytecode equal to the reviewed artifact, live runtime hashed to its deployment proof, all eleven immutables reconciled |
| ReleaseConsumed | [`0x09b9bbfb…3936d651`](https://testnet.monadexplorer.com/tx/0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651), block 51573394 |
| Cure window | Real 600 seconds, allowed to expire uncured |
| Finalize, permissionless | [`0xc74051d8…45e4fc34`](https://testnet.monadexplorer.com/tx/0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34), block 51575381 |
| Holder A claim | [`0x4831b0a7…ecbea819`](https://testnet.monadexplorer.com/tx/0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819) · 0.002400 aUSDC |
| Holder B claim | [`0x36296bf9…430bfc50`](https://testnet.monadexplorer.com/tx/0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50) · 0.001600 aUSDC |
| Reconciliation | Adapter reserve 0.004000 → 0, both holders paid exactly, liabilities cleared, adapter solvent, MINV01 untouched |
| Execution source pin | `5f2156107e61d9d88eb0d1eb82e8676827717dc4`, taken from server configuration and never from the artifact |

Read it in the product at **`/protection/verified-run`**, or as evidence in
[`docs/direct-participant-bridge-evidence.md`](docs/direct-participant-bridge-evidence.md) and the
`docs/evidence/hardened-*` artifacts.

An earlier complete journey, run `76005a0c-2787-4c50-b196-636e45b71781` on adapter
`0x00efE6AAcaC6Aa94A3c66d8F09D310197600D935`, is retained under `docs/evidence/activation-*`. It is
a real settled execution, kept as history: it predates the settlement-time admission proofs, the
external source pin and the deployment-proof binding above, so it is no longer what the product
shows.

[`docs/activation-blockers.md`](docs/activation-blockers.md) is **superseded** and kept only as the
historical record of what was refused before the architecture correction was authorized.

## Why Mordant

A tokenized receivable can be public while the financing commitments against it stay private, held
separately by each lender. The token says who owns the note. It does not say who else was already
promised the same cash flow.

That gap is expensive. An institution cannot hand its lender book to a counterparty just to find out
whether two claims overlap, and the counterparty cannot either. So the question that matters most,
*is this receivable already pledged elsewhere*, is the one question nobody can ask directly.

While it stays unanswered, the position is stuck. Funding waits, decisions wait, and recourse waits,
because acting on a suspected conflict without proof is as risky as ignoring it.

Mordant builds a confidential path from those private records to an auditable decision, and then
keeps going: a confirmed conflict does not just produce an alert, it opens a governed recourse
outcome that anyone can verify afterwards.

## Current product: Conflicting Pledge Protection

One receivable, two private pledge records, one governed answer.

1. A verified receivable is selected as the case root.
2. Two synthetic lender pledge records enter the private evaluation. Each holder authorizes only its
   own record; managed Mordant infrastructure prepares that record's encrypted artifact, and the
   evaluator receives encrypted participant artifacts only.
3. Real BGV FHE evaluates the fixed conflict circuit over the encrypted records.
4. The evaluator holds no decrypt key: it cannot inspect the records, and it cannot dictate the
   result.
5. A designated governed decryptor independently recomputes the fixed circuit and must land on the
   same ciphertext digest.
6. The signed Boolean enters the case chronology and the recourse workflow.
7. A confirmed conflict opens governed recourse.
8. No conflict produces an explicit, signed refusal rather than silence.
9. The original receivable claim remains intact either way: no burn, no transfer.
10. Final evidence is retained and publicly verifiable, digest by digest.

The circuit is fixed and pinned (`mordant.identity-full-fhe-256` v5, profile
`mordant.bgv.identity-full-fhe-256.n15/v1`), so neither party chooses what gets computed.

## Verified MVP

What is actually implemented and retained in this repository:

| Capability | Status |
| --- | --- |
| Cleanverse A-Token provenance observed on Monad testnet | retained observed evidence |
| Conflict and no-conflict scenarios | both retained and publicly served |
| BGV FHE evaluation | real, executed locally |
| Governed signed result | independent recomputation, digest match required |
| Retained public evidence | verified before rendering, digest-pinned |
| Exact source provenance | evidence pins its source commit and refuses a mismatch |
| Public verified-evidence experience | read-only, no local execution exposed |
| Supervised local end-to-end demonstration | optional, single-host, operator-run |

The governed decryptor's independent recomputation is checkable in the retained evidence: in the
conflict scenario, `fhe.independentlyRecomputedResultDigest` equals `fhe.resultCiphertext.sha256`.
A mismatch fails the case rather than publishing it.

## See it

The public surface serves retained evidence only. It verifies each envelope before rendering and
makes no local request:

```bash
pnpm install
pnpm build
MORDANT_PROTECTION_SOURCE_COMMIT=$(node -p "require('./docs/evidence/conflicting-pledge-protection/conflict.json').sourceCommit") pnpm start
```

Then open `/protection?scenario=conflict`. Both scenarios are deep-linkable:
`/protection?scenario=conflict` and `/protection?scenario=no-conflict`.

The source pin is required. It is the commit the retained evidence was produced from, and the
server refuses any envelope that disagrees with it. Without the pin the pages still load, but they
withhold the evidence and say so rather than showing anything unverified.

Run the deterministic gates:

```bash
pnpm typecheck
pnpm protection:test              # evidence, projection, recovery and adapter suites
```

The supervised local demonstration, which actually executes BGV on a single host, is operator-run
and separate from the public site:

```bash
pnpm protection:adapter           # local loopback adapter, development only
pnpm protection:smoke:conflict
pnpm protection:smoke:no-conflict
```

## Live execution

The deployed site can start a real BGV execution. A visitor enters two demo
pledge windows on `/protection/live` and receives a governed answer produced by
the same engine that generated the retained evidence.

A managed Mordant execution service prepares and encrypts the demo inputs, then
runs the fixed conflict circuit. The evaluator processes ciphertexts only: it
holds no decrypt key and cannot inspect the windows or steer the outcome. A
designated governed decryptor independently recomputes the circuit and must land
on the same ciphertext digest before anything is released.

The governed signed Boolean determines the result. Nothing before that release
reports an outcome, and the case is authorized under a neutral execution intent
that carries no expected answer. A confirmed conflict opens governed recourse; a
false result produces an explicit signed refusal. Either way the run ends in a
receipt that binds the authorization, the participant artifacts, the evaluated
artifact, the governed result and the recourse outcome, with the original
receivable intact.

Deployment settings and the measured resource profile are in
[`docs/railway-deployment.md`](docs/railway-deployment.md).

## Roadmap

Where this goes next, in order:

1. **Participant-side encryption.** Each lender prepares and encrypts its pledge
   on its own device, so plaintext never reaches a shared service.
2. **Independent participant clients.** Separate lender applications hold their
   own signing keys and input boundaries.
3. **Distributed governed release.** Replace the designated release service with
   an independently operated 2-of-3 release.
4. **Independent operator deployment.** Separate intake, evaluator and release
   administration across organizations.
5. **Cleanverse production integration.** Live CVI admission, asset workflows and
   governed settlement on Monad.

None of these are implemented today.

## Cleanverse and Monad

Mordant combines Cleanverse-observed asset and participant provenance on Monad with confidential
conflict evaluation and governed recourse. The layers are cumulative, not competing.

To be exact about who does what:

- Cleanverse asset and participant provenance is **retained observed evidence**, captured from
  Monad testnet and pinned by digest;
- Cleanverse **did not** detect the synthetic conflict, and is not asked to: the conflict lives in
  private lender records that never reach it;
- Mordant does **not** claim live Cleanverse settlement;
- BGV execution is **local and off-chain**;
- Monad provides the observed tokenized-asset environment and the retained provenance, **not**
  native FHE execution.

## Current boundary

Everything above is real. None of it is production. Specifically:

- pledge records are synthetic;
- no real lender submissions and no real funds;
- execution is local and single-host;
- the decryptor is designated and trusted, not distributed;
- cure timing is simulated protocol time, not observed wall-clock chronology;
- recourse runs against a local protocol double, not live settlement;
- no production custody proof;
- no threshold release;
- no native Monad FHE;
- no live Cleanverse settlement;
- artifact cleanup is operational, with no secure-erasure guarantee.

Production deployment is not authorized. Real funds require audit, governance and an operational
framework this prototype does not have. The public experience states these limits on the page
itself, not only here.

## Expansion territory

The same private-decision and recourse model extends naturally to other private-credit situations
where confidential records must produce a governed action:

- assignment-priority conflicts;
- covenant and eligibility exceptions;
- document or credit-note conflicts;
- collateral conflicts.

**None of these are implemented.** Conflicting Pledge Protection is the only policy in this
repository. Mordant is not a universal RWA conflict engine, and does not claim to be.

## Recourse kernel

Beneath the protection product sits the recourse kernel: the state machine that turns a confirmed
incident into an entitlement without touching the original claim.

| Stage | What happens |
| --- | --- |
| 1. Attest | An authorized source reports a confirmed incident on a funded receivable |
| 2. Seal | A record date is fixed by a hidden commitment, before disclosure |
| 3. Disclose | The incident is revealed and bound to the commitment |
| 4. Cure | The counterparty gets a window to resolve or dispute it |
| 5. Identify | The compliant holders carrying the exposure at the record date are resolved |
| 6. Assign | The pre-funded reserve becomes their entitlement |
| 7. Preserve | Verifiable proof is retained, and the original receivable claim survives |

> When an originator pledges one invoice twice, its holders inherit the bond.

```text
100 financing            ->   90 to the originator, 10 retained as reserve
100 invoice units        ->   holder A 60, holder B 40
confirmed conflict       ->   holder A claims 6, holder B claims 4
receivable settles       ->   holder A 66, holder B 44, units intact throughout
```

The reserve amortizes with outstanding protected principal: if 50 of 100 units remain at the record
date, at most 5 of the initial 10 stays exposed.

This kernel runs as real transactions on a deterministic local chain:

```bash
pnpm localnet       # fresh Anvil + deployment, one command, reproducible from an empty chain
pnpm dev            # then open http://localhost:3000/participant
```

Fourteen steps, each one a real transaction: fund the invoice 90/10, split the positions 60/40, sign
and seal the conflicting pledge, reveal it, let the cure window expire, activate the 6/4 entitlement,
claim from the reserve, then settle the receivable 66/44 on its own track. Every step waits for its
receipt and re-reads state from the contracts, and shows wallet, role, network, hash, block, status
and decoded events. Nothing advances on interface state alone.

The chain is local, the settlement and invoice tokens are protocol doubles, and the interface says so
in its header: `LOCAL / PROTOCOL DOUBLE / SYNTHETIC`.

Run the full checks:

```bash
pnpm validate       # lint, typecheck, unit, Foundry, evidence gate, secret scan, build
pnpm test:e2e       # browser flows (needs: pnpm exec playwright install chromium)
```

## Repository

| Path | Contents |
| --- | --- |
| `src/lib/protection` | Conflicting Pledge Protection: evidence model, validators, orchestrator, recovery |
| `fhe-lab/` | BGV circuit, Lattigo implementation, ceremony and identity suites |
| `docs/evidence/conflicting-pledge-protection/` | Retained public evidence envelopes for both scenarios |
| `scripts/protection-local-adapter.mjs` | Loopback adapter for the supervised local demonstration |
| `contracts/` | Solidity vault, factory, Cleanverse boundaries, Foundry tests |
| `src/app`, `src/components` | Next.js interface, protection experience, deal room and server routes |
| `src/lib/dealroom` | Transactional journey against the local chain |
| `src/lib/contracts` | Read-only chain layer and ABI parity gate |
| `src/lib/cleanverse` | Server-only Cleanverse v5.6 API client |
| `src/lib/evidence` | Reproducible read-only evidence gate and secret scanner |
| `scripts/localnet.mjs` | Deterministic local chain and deployment |
| `docs/` | Architecture, deployment, threat model, security review, evidence artifacts |

## Recourse kernel coverage

Implemented and covered by tests:

- financing and reserve accounting, EIP-712 pledges, hidden record date, cure window;
- record-date entitlement, 60/40 to 6/4 allocation, reserve amortization;
- receivable settlement that is independent of the recourse payout;
- per-holder settlement, pull-payment credits, fail-closed identity and policy checks;
- a read-only Monad layer that verifies every vault field at a single block;
- the complete journey executed as real transactions against a local chain, covered end to end.

## Cleanverse integration status

Where the Cleanverse integration stands on Monad testnet, as of 28 July 2026:

    AUSDC LIVE TRANSFER: PROVEN
    CONTRACT APASS: PROVEN
    CONTRACT AUSDC CUSTODY ROUND-TRIP: PROVEN
    INVOICE A-TOKEN LAUNCH: ISSUED / READBACK PROVEN
    MINTER ROLE: NOT GRANTED
    MINT/BURN VIA MORDANT ADAPTER: NOT PROVEN
    MORDANT SETTLEMENT: NOT PROVEN

The rail moves real value, and a contract can take custody of it and give it back. What is not
proven is the **settlement** path: no minter role has been granted, no mint or burn has gone through
a Mordant adapter, and no settlement has occurred. None of the lines above should be read as a
working settlement integration. They do not describe Conflicting Pledge Protection, which is
implemented and retained, and whose own limits are listed in
[Current boundary](#current-boundary).

The tier 50 rule on the invoice A-Token is currently validated for exactly three addresses,
`HOLDER_A`, `HOLDER_B` and the M-08 probe. **Every future adapter, vault or holder has to be tested
separately**: an address is admitted by the rule only once its own A-Pass has been issued and read
back.

Evidence, with every claim classified: [`docs/evidence/`](docs/evidence/) and
[`docs/cleanverse-integration.md`](docs/cleanverse-integration.md).

## What Mordant is not

Not a universal duplicate-financing detector, not proof that an invoice is authentic, not a legal
registry of assignment priority, not insurance against debtor default, not a generic platform for
tokenizing every kind of RWA, and not a fully trustless system. It stays centred on receivables and
asset-backed private credit.

## Evidence gate

Re-derives what is true on chain instead of trusting any note in this repository. The default run
replays a recorded fixture and writes nothing:

```bash
pnpm evidence:cleanverse
```

A live run is strictly read-only: it refuses every state-changing JSON-RPC method, aborts unless the
chain is Monad testnet, pins one block for all readings, and writes a Markdown and JSON report whose
every conclusion is classified.

```bash
pnpm evidence:cleanverse -- --live --rpc-url "$MONAD_RPC_URL" \
  --out docs/evidence/cleanverse-monad-$(date +%F)
```

Fixture output is labelled `mode: fixture` and is never presented as a live observation. Reports are
scanned for credential patterns before being written, and a match aborts the write.

## Stack

Next.js 16, React 19, TypeScript, Foundry, Lattigo BGV, Monad testnet, and the Cleanverse
primitives: CVI (A-Pass), CVA (a dedicated invoice A-Token), aUSDC settlement and Validator
Compliance.

## Documentation

| Document | Purpose |
| --- | --- |
| [Conflicting Pledge Protection](docs/conflicting-pledge-protection.md) | MVP execution boundary, governed release, evidence model |
| [Architecture](docs/architecture.md) | Recourse kernel, contracts, policy compatibility |
| [Deployment](docs/deployment.md) | Testnet runbook, contract size limits |
| [Cleanverse integration](docs/cleanverse-integration.md) | What is documented, observed and still blocked |
| [Threat model](docs/threat-model.md) | Attacker classes and mitigations |
| [Security review](docs/security-review.md) | Findings and residual risk |
| [Production gates](docs/production-gates.md) | Hard gates before real funds |
| [Shadow pilot definition](docs/product/shadow-pilot.md) | Scope, processing, outputs, and measurements for a permissioned pilot |
| [Organization role model](docs/product/organization-role-model.md) | Future organization, permission, approval, and wallet boundaries |
| [Customer discovery guide](docs/product/customer-discovery-guide.md) | Twelve questions for the first 5-8 prospects |

Never commit Cleanverse credentials. Configure them in `.env.local`, which is git-ignored.
