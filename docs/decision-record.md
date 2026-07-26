# Frozen product decision

- Name: **Mordant**
- Track: **RWA — CVI and CVA from issuance**
- One-liner: **When an originator pledges one invoice twice, its holders inherit the bond.**
- Initial client: an operator of a buyer-led or tokenized receivables platform with at least two
  independent funders and a mandatory registration workflow.

## Frozen kernel

Mordant is a funded exclusivity covenant for one buyer-accepted tokenized invoice. The first
financing retains part of an existing originator reserve. A second registered overlapping pledge
turns the still-required reserve into a pro-rata entitlement of holders at the hidden record date,
without consuming their invoice claim.

It is not a universal duplicate-financing detector, legal registry, debtor-default insurance or
proof that an off-network loan occurred.

## Build and kill gates

The hackathon build remains valid only if the real sponsor path demonstrates custom A-Token issuance,
compliant custody credit, CVI-gated roles, 60/40 → 6/4 aUSDC payout and intact 66/44 redemption. If
Cleanverse cannot provide that path, the build stops rather than replacing it cosmetically with a
mock.

The underlying engine records remain in the parent strategy repository:

- `../data/engine/commitments/mordant-architecture-v7-terminal-audit.md`;
- `../data/engine/commitments/mordant-terminal-production-gtm-audit-2026-07-26.md`;
- `../data/engine/commitments/mordant_architecture_model_v7.py`.

The executable model currently passes 24/24 scenarios. That proves consistency of the product model,
not security of this Solidity implementation.
