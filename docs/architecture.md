# Mordant architecture — current product and verified execution profiles

## Product kernel

Mordant is the recourse layer for tokenized private credit. Its current kernel separates an
authenticated private-credit case state from the policy, operation authorization and evidence that
follow it:

```text
private inputs
  → governed result
  → precommitted Governed Recourse Policy
  → governed action plan
  → durable operation authorization
  → bounded operation
  → verified outcome and operation-bound evidence
```

The governed result does not independently authorize recourse, an operational action, settlement
or legal judgment. The current policy is code/deployment committed before result exposure; it is
not an institution-authored or cryptographically institution-approved policy.

## First implemented workflow: Conflicting Pledge Protection

Conflicting Pledge Protection is the first implemented workflow, not the generic Mordant category.
It evaluates whether two submitted financing-claim windows against one receivable conflict. A fixed
BGV circuit produces a governed conflict/no-conflict result; that result establishes no legal
priority, responsibility, ownership, fraud, default, payout recipient or payout amount.

The current managed V2 path selects
`mordant.managed-demo.facility-protection@1` before result exposure. Conflict selects a 24-hour
local protocol-double cure path; no conflict selects record-and-close. Both branches have settlement
authorization `NOT_AUTHORIZED`. Exact semantics are documented in
[Governed Recourse Policy](governed-recourse-policy.md).

The public deployment uses managed combined intake. Direct participant admission separately proves
two wallet authorizations, but not participant-local encryption. Participant-originated native-CLI
encryption is not integrated in the current `origin/main` and remains roadmap until merged and
requalified.

## Current managed V2 authority layers

| Layer | Authority and boundary |
| --- | --- |
| Private evaluation | Fixed BGV execution. Managed preparation may receive plaintext; the evaluator receives ciphertexts and has no decryption key. |
| Governed result | Signed conflict/no-conflict status only. The designated decryptor is Mordant-controlled. |
| Governed policy | Closed policy selected before result exposure. It consumes conflict status and produces a verified action plan. |
| Operation authorization | Durable authorization derived from the exact selection, plan, result and operation parameters. |
| Evidence | The terminal operation outcome is validated for action compatibility and bound back to the authority chain. |

## Specialised historical settlement architecture

The contracts below are the specialised vault and Adapter V2 architecture used by the separate
hardened on-chain execution. That retained run proves a real 600-second cure, finalization and aUSDC
claims under its historical configuration. It did not use the current managed V2 policy-authority
chain, whose local cure is 24 hours and whose settlement authorization is `NOT_AUTHORIZED`.

In the specialised historical architecture, confirmed conflict status entered a preconfigured demo
policy that selected pre-funded, traceable recourse for the configured compliant holders while
leaving their original receivable claim intact.
Other incident classes (buyer disputes, credit notes, invalid documents) remain unimplemented future
work rather than generic capabilities of these contracts.

## Contracts

- `MordantFactory`: unique root/token/vault registry, facility membership and allowlists for the CVA
  adapter and settlement token.
- `MordantInvoiceVault`: one immutable invoice, beneficial units, reserve, pledge state, checkpoints,
  conflict cure/finalization, protection claims and receivable redemption.
- `CleanverseAPassVerifier`: fail-closed live A-Pass validity plus explicit institutional role
  authorization behind `ICviVerifier`.
- `CleanverseCvaAdapter`: one-token/one-vault custody credit and exact burn/release boundary behind
  `ICvaAdapter`.

The adapters are intentional. A disposable Monad fork proves that a contract with its own A-Pass can
pass the deployed aUSDC policy and that a `MINTER_ROLE` holder can mint to and burn from that contract.
Cleanverse does not yet publish the definitive lifecycle ABI for a newly issued invoice A-Token, and
Monad issuance health is unverified (no backend/factory selector skew was observable at block
48667706, but no application has been run since). The vault therefore does not hard-code the deployed
aUSDC behavior as if it applied to every CVA: the approved adapter must expose an exact custody credit
for that vault. A local mock proves Mordant accounting only.

The production-shaped boundaries themselves are no longer mocks. Their tests execute complete cash
redemption and default-release paths, while using protocol-shaped doubles for the external A-Pass and
A-Token contracts. The Monad sandbox deployment path for a newly issued invoice A-Token was unproven when this was
written; it has since been executed, and MINV01 was issued with readback on Monad testnet.

Each adapter must report a custom A-Token dedicated to one invoice. Activation requires both its
issued supply and its vault credit to equal the initial beneficial units exactly, with the same six
decimal scale as Mordant receipts. Redemption burns the CVA and internal unit together; an
unexpected external mint, custody deficit or asset change stops the flow before value moves.

The invoice CVA, mINV and allowlisted aUSDC rail use one six-decimal base-unit scale. On those raw
values, the vault constructor requires `faceValue >= initialUnits`. For every positive non-final lot,
`floor(faceValue * units / initialUnits)` is therefore at least one aUSDC atomic unit; the final lot
receives the exact remaining face value. No positive receipt lot can be burned or released while its
face discharge rounds to zero. The constructor does not convert token decimals, so deployment must
independently verify the allowlisted settlement token's six-decimal scale.

Holder eligibility is deliberately stronger than a generic A-Pass check. Adapter-to-holder probes use
the holder's complete future mINV position, not merely the current transfer delta:

- activation rejects duplicate holder addresses, then probes each holder's complete allocation;
- an mINV transfer probes `balanceOf(recipient) + amount`;
- default release probes the caller's complete remaining mINV balance, not only the requested release;
  after a partial release, the next probe uses the new residual balance.

This shape covers monotone policies that cap `current CVA balance + amount` and avoids accepting a
receipt position whose underlying CVA could not later be delivered. A missing policy, revert or
negative result rejects the participant. Neither the vault nor its adapter may ever hold mINV,
preventing internal custody addresses from entering checkpoints or protection allocations.

A holder-to-holder mINV transfer has an additional pair check:
`cva.policy().canTransfer(cva, holderA, holderB, amount)`. The sender retains holder role/A-Pass
eligibility; the recipient must pass the adapter-to-recipient future-position probe. This prevents
the receipt wrapper from creating an economically equivalent transfer that the underlying CVA policy
would reject because of the exact counterparty pair or amount.

These probes are not a universal liveness proof or exact policy parity. Policies may be mutable,
history-dependent or non-monotone, so a decision can change before execution. A max-per-transaction
policy can also produce a conservative false negative when the total-position probe is larger than
the immediate transfer delta. On execution, the adapter still rechecks the actual delta and verifies
the real sender decrease and recipient increase; a successful probe never bypasses those checks.

Activation atomically rechecks valid A-Passes for both the adapter and the vault. The adapter's base
`isActivationReady` check verifies binding, identity, role, custody, decimals, supply and policy
presence; it deliberately does not simulate a burn of the full supply, which could falsely reject a
valid max-per-transaction policy. The vault separately calls `isRedemptionReady(vault, allocation)`
for every real initial allocation. A non-allocated funder needs holder-role authorization and a valid
A-Pass only; the real aUSDC transfer itself applies the aUSDC policy to `funder -> vault`. Buyer
funding and every aUSDC settlement boundary recheck their relevant identity/readiness conditions and
rely on the real aUSDC transfer policy. Every outgoing `_transferExact` first calls the settlement
policy for the exact `(settlement, vault, recipient, amount)` tuple and only then invokes the token.

`claimBond` and cash `redeem` require the claimant's holder role and valid A-Pass plus an explicit
exact-amount settlement-policy precheck and the policy enforced by the actual vault-to-holder aUSDC
transfer. They deliberately do not require CVA adapter-to-holder deliverability: those paths deliver
cash, not CVA. The CVA delivery check applies only to initial allocations/mints, mINV transfers and
`releaseDefaultCva`. An expired adapter or vault A-Pass pauses the affected CVA/aUSDC path until the
issuer renews the identity; it is never treated as a soft warning.

## Independent state machines

```text
Protection: Unfunded -> Active -> CommitPending -> ConflictConfirmed -> Entitled
                                  |                  |
                                  +-> Active         +-> Active (dual-auth cure)
                 Active ----------------------------------------------> Released

Receivable: Unissued -> Outstanding -> Redeemed
                                  \--> DefaultOutstanding
```

No protection transition changes the receivable state or burns its units.

Default settlement is mixed and decided independently for each holder. For the caller, Mordant first
computes the cash face value of its complete `holderBalance`. The holder is forced to use cash only
when `redemptionEscrow` covers that complete amount and
`cvaAdapter.isRedemptionReady(vault, holderBalance)` confirms the exact burn, and the settlement
policy approves `(settlement, vault, holder, holderCashAmount)`. If any condition is false, the holder
may receive the requested CVA units. That CVA delivery does not disable cash redemption for anyone
else: a second holder whose exact burn and exact cash transfer are allowed may still redeem against
the existing escrow.

`cvaReleasedFace` records the invoice face value discharged through CVA rather than cash. Remaining
cash liability is always `faceValue - redeemedFace - cvaReleasedFace`. After every cash redemption or
CVA release, escrow above that liability is removed from `redemptionEscrow` and accrued to the buyer
as `settlementCredit`. `defaultCvaReleaseStarted` records that at least one CVA payout occurred but
does not gate `fundRedemption` or `redeem`. After default, the buyer may still fund exactly
`faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow` for the remaining holders. Thus one
holder can take CVA while another takes cash without double-counting face value, trapping pre-existing
escrow or letting a prior CVA payout grief later holders by disabling funding.

Originator bond returns and buyer escrow refunds never push aUSDC inline. `_releaseExcessBond`,
`_returnAllLockedBond` and excess-escrow reconciliation accrue accounted `settlementCredit`; the
beneficiary later pulls it through `claimSettlementCredit`. `settlementCreditTotal` remains part of
the vault's settlement-balance invariant until claimed. Consequently, an expired originator or buyer
A-Pass does not block a holder's `redeem`, `closeProtection` or `releaseDefaultCva`; it blocks only
the expired beneficiary's own credit claim until eligibility is restored. Holder bond claims and cash
redemption payouts remain direct because the eligible holder is the caller.

Activation is intentionally different. Net proceeds are sent to the originator inline in the same
transaction as funder collection, state activation and mINV minting. If the originator cannot receive
aUSDC, the whole transaction reverts atomically, so no advance or reserve is stranded in a partially
activated vault.

## Conflict proof

The hidden commitment binds the pledge digest, the exact originator signature hash, facility,
vault and salt. This fixes the holder checkpoint before the signature can be revealed or acquired
opportunistically. A valid reveal must come from a second registered facility and overlap the first
exclusive pledge. Cure requires both the originator's signed cancellation and the second facility's
transaction; no owner can skip the cure window.

## Reserve amortization

```text
requiredBond(supply) = ceil(initialBond * supply / initialSupply)
```

A clean redemption releases reserve above the required amount. A pending commit, revealed conflict
or cure window freezes the bond at its snapshot requirement. After entitlement, allocated protection
never returns to the originator.

## Demo fixture

```text
invoice face value      110 aUSDC
advance                 100 aUSDC
originator proceeds      90 aUSDC
initial reserve          10 aUSDC
invoice units           100
record-date holders      60 / 40
protection claims         6 / 4
redemption claims        66 / 44
```

## Policy compatibility and settlement rails

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

## Execution scale and future topology

The public deployment intentionally exposes one active BGV slot. That deployment limit is distinct
from the qualified architectural proof in
[`evidence/n2-isolated-execution-proof-2026-08-08.md`](evidence/n2-isolated-execution-proof-2026-08-08.md):
two isolated instances of the existing worker ran opposite real BGV cases concurrently with
separate durable roots and simultaneous evaluator processes. The supported conclusion is only that
multiple isolated execution slots can run concurrently.

Production routing, pooling, load balancing, autoscaling, high availability and N>2 capacity are
not implemented or proven. N=3 Private Conflict Graph is a research direction for multi-funder
conflict semantics; it is not part of the current workflow, capability list or product proof.
