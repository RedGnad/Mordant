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
- Cleanverse CVI (A-Pass), CVA (dedicated invoice A-Token), aUSDC and Validator Compliance; the
  exact relationship to the separately named CCP Protocol awaits sponsor confirmation

The dedicated CVA custody path is isolated behind an allowlisted adapter. A no-write Monad fork proves
that a contract with its own A-Pass can pass the deployed aUSDC policy and use role-gated mint/burn.
Both the adapter and every vault must hold a valid A-Pass before activation, funding or aUSDC
settlement; readiness fails closed if either credential or any external policy read is missing,
reverting or negative. A holder must also be able to receive the corresponding amount of underlying
CVA according to `cva.policy().canTransfer(cva, adapter, holder, futurePosition)` when CVA delivery is
possible. Activation rejects duplicate holder addresses and probes each complete allocation. An mINV
transfer probes the recipient's balance after the transfer plus the exact holder-to-holder pair and
delta. Default release probes the caller's complete remaining mINV balance, including after a partial
release. These total-position probes cover monotone caps such as `current CVA balance + amount`; the
adapter still rechecks policy and actual balance deltas for the units it really moves. The adapter and
vault themselves can never be mINV holders.

This is conservative policy compatibility, not universal “policy parity.” A mutable,
history-dependent or non-monotone policy can change between a probe and execution. Conversely, a
max-per-transaction policy may reject a total-position probe even though the immediate delta would
fit. Mordant accepts that safe false negative rather than claiming liveness it cannot prove.

The cash rail stays separate. A funder that receives no mINV allocation needs the holder role and a
valid A-Pass, not an artificial adapter-to-funder CVA probe; the real aUSDC transfer enforces its own
policy on `funder -> vault`. Bond claims and cash redemptions likewise require holder role/A-Pass and
an explicit exact-amount aUSDC policy precheck before the token transfer, but no CVA deliverability
check because no CVA is delivered to the claimant. Every outgoing `_transferExact` performs that
policy precheck before moving aUSDC.

Default settlement is per holder, so CVA delivery for one account does not disable cash redemption
for another. A holder is forced to cash only when escrow covers the face value of its complete mINV
balance, `isRedemptionReady(vault, holderBalance)` confirms that exact burn, and
`settlement.policy().canTransfer(settlement, vault, holder, exactCash)` approves the exact cash
payout. If any condition is false, that holder may receive CVA without affecting the others. Each CVA
payout increases `cvaReleasedFace`; any escrow above the remaining cash liability is credited to the
buyer, while other cash-eligible holders may still redeem. `defaultCvaReleaseStarted` is an observable
history flag, not a mode gate: it blocks neither funding nor redemption. After a CVA payout, the buyer
may fund the exact remaining shortfall
`faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow`, so a prior CVA payout cannot starve
the cash path of later holders.

Buyer refunds and amortized/returned bond for the originator are `settlementCredit` pull-payments,
not inline pushes. An expired buyer or originator therefore cannot block holder redemption,
protection close or default CVA release; only that account's own `claimSettlementCredit` waits for
its A-Pass/aUSDC eligibility to recover. Activation remains atomic: net proceeds are paid to the
originator inline, and a failure reverts the entire activation before funds can be left in the vault.

## Current build status

- Solidity state machines, EIP-712 pledges, hidden record date and 90/10 accounting are implemented.
- Unit and stateful invariant suites cover both clean amortization and the 60/40 → 6/4 conflict path.
- A server-only Cleanverse v5.6 client implements the documented CVI, CVA, validator and sandbox
  provisioning endpoints needed by the integration path.
- Production-shaped Cleanverse boundaries now call live A-Pass validity for both custody contracts,
  gate holders on underlying-CVA deliverability, and implement dedicated A-Token custody, exact
  release and role-gated burn; a full vault integration test exercises them.
- Per-allocation activation checks, mixed per-holder default settlement and accounted
  `settlementCredit` pull-payments close the stale-burn and expired-beneficiary liveness failures.
- A read-only Monad/viem layer verifies all live vault fields at one block and calls the contract's
  own accounting assertion.
- The interface runs honestly in synthetic mode until a judged vault address is configured.

The permissionless redemption-dust P0 is fixed and regression-tested. Contract A-Pass custody,
direct CVI reads and aUSDC burn authority are now proven without changing public state. The remaining
integration gate is narrower and not hidden in a mock: the live spike must prove gateway issuance to
both the adapter and vault and the dedicated invoice A-Token lifecycle. Read-only probes on 27 July
traced the current Monad launcher failure to a Cleanverse backend/factory ABI version skew. Cleanverse
gateway acceptance of contract-address A-Pass issuance has not been observed either. Those two
external dependencies currently block an honest live rail even though contract custody is feasible
on-chain. Validator reads also remain unhealthy but are not required for the direct CVI path. See
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
