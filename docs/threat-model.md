# Threat model

## Protected in the prototype

- immutable one-to-one invoice root, CVA and vault binding;
- owner allowlists for the CVA adapter and settlement asset;
- EIP-712 domain separation and pledge replay protection;
- hidden commitment bound to the exact originator signature, facility, vault and salt;
- facility-authenticated second record so the originator cannot self-trigger alone;
- commit/reveal record date before the conflicting pledge is public;
- pro-rata, one-shot protection entitlement with bounded rounding dust;
- reserve amortization after clean partial redemption;
- separate protection and redemption accounting;
- buyer-only redemption funding, preventing third-party dust deposits from blocking the default CVA
  release choice;
- exact full-liability funding after default and automatic return of partial escrow when the CVA rail
  is selected, preventing buyer-controlled dust from deadlocking holder recovery;
- irreversible CVA-rail selection after default, preventing later cash funding or redemption from
  double-allocating the remaining face value;
- balance-delta checks against fee-on-transfer behavior;
- exact CVA custody credit, issued-supply and asset-integrity checks;
- no owner withdrawal of an active reserve.

## Explicitly outside the prototype

- off-network financing;
- buyer/originator collusion or invoice fabrication;
- legal assignment perfection, priority and insolvency treatment;
- confidential partial matching across platforms;
- production KYB, sanctions, UBO and related-party controls;
- abuse prevention for public API proxies and proof that an A-Pass query belongs to the requester;
- recovery when a historical holder loses A-Pass eligibility;
- recovery of a CVA credited to a vault whose financing never activates;
- censorship or griefing by the factory owner or a facility occupying the single pending commit;
- correctness or upgrade safety of sponsor contracts;
- economic calibration of a production reserve.

## Integration kill gate

Cleanverse must confirm a compliant custody account or approved Mordant contract that can credit,
burn and release the invoice A-Token without bypassing A-Pass rules. Local mocks are evidence of
Mordant accounting only, never evidence that this sponsor path exists. Current Monad UAT issuance
and Validator read failures must also be cleared before an end-to-end testnet claim.
