# Mordant v7.1 architecture

## Product kernel

One buyer-accepted invoice is financed inside a mandatory multi-funder workflow. Part of an existing
originator reserve is locked against an exclusive-pledge covenant. If another registered facility
reveals a confirmed overlapping exclusive pledge, the still-required reserve becomes an entitlement
of the beneficial holders at the hidden-commit record date. The invoice claim remains intact.

## Contracts

- `MordantFactory`: unique root/token/vault registry, facility membership and allowlists for the CVA
  adapter and settlement token.
- `MordantInvoiceVault`: one immutable invoice, beneficial units, reserve, pledge state, checkpoints,
  conflict cure/finalization, protection claims and receivable redemption.
- `ICviVerifier`: participant eligibility boundary.
- `ICvaAdapter`: sponsor-confirmed custody credit, global issued-supply accounting and burn/release
  boundary.

The adapters are intentional. Cleanverse documents custom A-Token issuance but does not currently
document how an A-Pass-gated token is custodied by an arbitrary contract or publish the definitive
mint/burn ABI. The vault therefore does not pretend to hold the CVA directly: the approved adapter
must expose an exact custody credit for that vault. A local mock proves Mordant accounting only.

Each adapter must report a custom A-Token dedicated to one invoice. Activation requires both its
issued supply and its vault credit to equal the initial beneficial units exactly. Redemption burns
the CVA and internal unit together; an unexpected external mint or asset change stops the flow.

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

After default, the first CVA withdrawal irrevocably selects the CVA-release rail. Cash funding and
cash redemption are then disabled, so one holder cannot retain the CVA while another consumes cash
that economically belongs to the same face value. A cash escrow covering the full remaining face
value blocks selection of the CVA rail and remains redeemable by holders. A partial escrow carried
into default is refunded to the buyer when the first holder selects CVA release; after default the
buyer may only fund the exact shortfall needed to cover the full remaining cash liability. This
prevents either an unrelated account or an adversarial buyer from obstructing the CVA choice with
dust while preserving partial redemptions before default. A production servicer would require an
explicit immutable or buyer-authorized role rather than permissionless funding.

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
