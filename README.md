# Mordant

**The programmable recourse layer for tokenized receivables.**

Tokenized platforms automate issuance, ownership and transfers. Mordant automates the remedy when a
funded receivable later breaks its rules.

When a tokenized receivable becomes ineligible after funding, Mordant turns a pre-funded reserve into
protection for the compliant investors carrying the exposure, without cancelling their claim on the
receivable. Cleanverse verifies the asset, participants and transfer policies. Monad executes the
recourse and preserves the audit trail.

> Hackathon prototype for Cleanverse Build: Trusted Assets. Synthetic invoice data and test assets
> only. See [Scope and status](#scope-and-status).

## Quickstart

Run the full recourse journey as real transactions, on a deterministic local chain:

```bash
pnpm install
pnpm localnet       # fresh Anvil + deployment, one command, reproducible from an empty chain
pnpm dev            # then open http://localhost:3000/deal-room
```

Fourteen steps, each one a real transaction: fund the invoice 90/10, split the positions 60/40, sign
and seal the conflicting pledge, reveal it, let the cure window expire, activate the 6/4 entitlement,
claim from the reserve, then settle the receivable 66/44 on its own track. Every step waits for its
receipt and re-reads state from the contracts, and shows wallet, role, network, hash, block, status
and decoded events. Nothing advances on interface state alone.

The chain is local, the settlement and invoice tokens are protocol doubles, and the interface says so
in its header: `LOCAL / PROTOCOL DOUBLE / SYNTHETIC`.

Run the checks:

```bash
pnpm validate       # lint, typecheck, unit, Foundry, evidence gate, secret scan, build
pnpm test:e2e       # browser flows (needs: pnpm exec playwright install chromium)
```

## How it works

A recourse cycle has seven stages. Mordant implements them as one state machine per invoice:

| Stage | What happens |
| --- | --- |
| 1. Attest | An authorized source reports a confirmed incident on a funded receivable |
| 2. Seal | A record date is fixed by a hidden commitment, before disclosure |
| 3. Disclose | The incident is revealed and bound to the commitment |
| 4. Cure | The counterparty gets a window to resolve or dispute it |
| 5. Identify | The compliant holders carrying the exposure at the record date are resolved |
| 6. Assign | The pre-funded reserve becomes their entitlement |
| 7. Preserve | Verifiable proof is retained, and the original receivable claim survives |

### First implemented policy: confirmed conflicting pledge

> When an originator pledges one invoice twice, its holders inherit the bond.

```text
100 financing            ->   90 to the originator, 10 retained as reserve
100 invoice units        ->   holder A 60, holder B 40
confirmed conflict       ->   holder A claims 6, holder B claims 4
receivable settles       ->   holder A 66, holder B 44, units intact throughout
```

The reserve amortizes with outstanding protected principal: if 50 of 100 units remain at the record
date, at most 5 of the initial 10 stays exposed.

Buyer disputes, credit notes and invalid documents are future extensions of the same kernel. They
are not implemented; the conflicting-pledge policy is the only one in this repository.

## Repository

| Path | Contents |
| --- | --- |
| `contracts/` | Solidity vault, factory, Cleanverse boundaries, Foundry tests |
| `src/app`, `src/components` | Next.js interface, deal room and server routes |
| `src/lib/dealroom` | Transactional journey against the local chain |
| `src/lib/contracts` | Read-only chain layer and ABI parity gate |
| `src/lib/cleanverse` | Server-only Cleanverse v5.6 API client |
| `src/lib/evidence` | Reproducible read-only evidence gate and secret scanner |
| `scripts/localnet.mjs` | Deterministic local chain and deployment |
| `docs/` | Architecture, deployment, threat model, security review, evidence artifacts |

## Scope and status

Implemented and covered by tests:

- financing and reserve accounting, EIP-712 pledges, hidden record date, cure window;
- record-date entitlement, 60/40 to 6/4 allocation, reserve amortization;
- receivable settlement that is independent of the recourse payout;
- per-holder settlement, pull-payment credits, fail-closed identity and policy checks;
- a read-only Monad layer that verifies every vault field at a single block;
- the complete journey executed as real transactions against a local chain, covered end to end.

Not proven end to end against the live network:

- issuance of a dedicated invoice A-Token on Monad reaching `ISSUED`;
- gateway delivery of an A-Pass to the adapter and to each vault;
- the complete settlement rail on Monad.

A read-only evidence run pinned to Monad testnet block 48667706 found no backend/factory selector
skew, and an authenticated sandbox check found that several Monad A-Tokens accepted our test wallets
while Monad aUSDC specifically failed with `ComplianceFailed`. That refusal was lifted on 28 July
2026 by a Cleanverse configuration transaction, not by a contract upgrade: aUSDC now returns `true`
for the same tuples, while the historical call still reverts when replayed at the original block.

Passing a compliance precheck is not settling. No aUSDC transfer has been broadcast, so the
settlement rail is still not described as live.

Evidence, with every claim classified: [`docs/evidence/`](docs/evidence/) and
[`docs/cleanverse-integration.md`](docs/cleanverse-integration.md).

### What Mordant is not

Not a universal duplicate-financing detector, not proof that an invoice is authentic, not a legal
registry of assignment priority, not insurance against debtor default, not a generic platform for
tokenizing every kind of RWA, and not a fully trustless system. It stays centred on receivables and
asset-backed private credit. Production deployment is not authorized: real funds require audit,
governance and an operational framework that this prototype does not have.

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

Next.js 16, React 19, TypeScript, Foundry, Monad testnet, and the Cleanverse primitives: CVI
(A-Pass), CVA (a dedicated invoice A-Token), aUSDC settlement and Validator Compliance.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Recourse kernel, contracts, policy compatibility |
| [Deployment](docs/deployment.md) | Testnet runbook, contract size limits |
| [Cleanverse integration](docs/cleanverse-integration.md) | What is documented, observed and still blocked |
| [Threat model](docs/threat-model.md) | Attacker classes and mitigations |
| [Security review](docs/security-review.md) | Findings and residual risk |
| [Production gates](docs/production-gates.md) | Hard gates before real funds |

Never commit Cleanverse credentials. Configure them in `.env.local`, which is git-ignored.
