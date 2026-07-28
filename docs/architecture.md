# Mordant v7.1 architecture

## Product kernel

Mordant is a programmable recourse kernel for tokenized receivables. The kernel turns an attested
off-chain incident on a funded receivable into pre-funded, traceable recourse, attributable to the
compliant investors who carry the exposure. Its lifecycle is: receive an incident attested by an
authorized source, seal a record date before full disclosure, open a cure or dispute window,
identify the compliant holders bearing the exposure, assign a pre-funded reserve to their
protection, retain verifiable proof, and leave their original claim on the receivable intact.

## First implemented policy: confirmed conflicting pledge

Exactly one policy is implemented. One buyer-accepted invoice is financed inside a mandatory
multi-funder workflow. Part of an existing originator reserve is locked against an exclusive-pledge
covenant. If another registered facility reveals a confirmed overlapping exclusive pledge, the
still-required reserve becomes an entitlement of the beneficial holders at the hidden-commit record
date. The invoice claim remains intact.

Other incident classes (buyer disputes, credit notes, invalid documents) are future extensions of
the same kernel. They are **not implemented**, and the contracts below are deliberately specialised
on the conflicting-pledge policy rather than generalised into a multi-incident engine.

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
A-Token contracts. What remains unproven is the current Monad sandbox deployment path for a newly
issued invoice A-Token, not Mordant's adapter logic.

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
