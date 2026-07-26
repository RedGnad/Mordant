# Mordant

> **When an originator pledges one invoice twice, its holders inherit the bond.**

Mordant is a programmable breach reserve for buyer-accepted, tokenized receivables inside a
participating multi-funder platform. A verified invoice is financed once, part of the existing
originator reserve remains locked, and a confirmed conflicting pledge converts the still-required
reserve into a protection right for the holders at the record date. Their invoice claim remains
intact.

This repository is a Cleanverse Build: Trusted Assets hackathon prototype. It uses synthetic invoice
data and test assets only. The idea and product architecture are frozen; production deployment is
not authorized.

## What the demo proves

```text
100 aUSDC financing
  -> 90 aUSDC to the originator
  -> 10 aUSDC retained reserve

100 invoice units
  -> holder A owns 60
  -> holder B owns 40

confirmed conflicting pledge
  -> holder A can claim 6 aUSDC
  -> holder B can claim 4 aUSDC
  -> both still own their 60 / 40 invoice units
```

The reserve amortizes with outstanding protected principal. If only 50 of the original 100 units
remain before the conflict record date, at most 5 of the initial 10 reserve remains exposed.

## Boundaries

Mordant does **not** claim to detect off-network financing, prove invoice truth, establish legal
assignment priority, insure debtor default, or replace a legal registry. It settles a contractually
defined consequence for a registered conflicting pledge inside a mandatory workflow.

## Stack

- Next.js 16 / React 19 / TypeScript
- Foundry / Solidity
- Monad testnet
- Cleanverse CVI (A-Pass), CVA (custom A-Token), aUSDC and validator/CCP rules

The custom CVA custody path is isolated behind an allowlisted adapter. Mordant does not assume that
an ordinary contract can receive an A-Pass-gated A-Token. The adapter must instead prove a dedicated
invoice A-Token supply and sponsor-approved custody credit attributable to one vault.

## Current build status

- Solidity state machines, EIP-712 pledges, hidden record date and 90/10 accounting are implemented.
- Unit and stateful invariant suites cover both clean amortization and the 60/40 → 6/4 conflict path.
- A server-only Cleanverse v5.6 client implements the documented CVI, CVA and validator endpoints.
- A read-only Monad/viem layer verifies all live vault fields at one block and calls the contract's
  own accounting assertion.
- The interface runs honestly in synthetic mode until a judged vault address is configured.

The remaining P0 is sponsor-specific, not hidden in a mock: Cleanverse must confirm the real custom
A-Token custody/burn/release adapter and the CVI verifier path. See
[`docs/cleanverse-integration.md`](docs/cleanverse-integration.md).

## Local development

```bash
cp .env.example .env.local
pnpm install
pnpm dev
```

Contracts:

```bash
forge test --root contracts -vvv
```

Full local validation:

```bash
pnpm validate
```

Browser flow (desktop and mobile Chromium):

```bash
pnpm exec playwright install chromium
pnpm test:e2e
```

Never put Cleanverse credentials in Git. The sandbox key originally delivered for the event must be
rotated before durable use because it was pasted into a chat transcript.
