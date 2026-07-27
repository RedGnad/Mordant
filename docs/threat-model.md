# Threat model

## Protected in the prototype

- immutable one-to-one invoice root, CVA and vault binding;
- owner allowlists for the CVA adapter and settlement asset;
- EIP-712 domain separation and pledge replay protection;
- hidden commitment bound to the exact originator signature, facility, vault and salt;
- facility-authenticated second record so the originator cannot self-trigger alone;
- commit/reveal record date before the conflicting pledge is public;
- pro-rata, one-shot protection entitlement with bounded rounding dust;
- constructor enforcement of `faceValue >= initialUnits` on the shared six-decimal scale, preventing
  any positive non-final receipt lot from rounding to zero face discharge while the final lot absorbs
  the exact residual;
- reserve amortization after clean partial redemption;
- separate protection and redemption accounting;
- buyer-only redemption funding, preventing third parties from manipulating the escrow coverage used
  in per-holder default settlement;
- exact residual-liability funding after default using
  `faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow`;
- per-holder default settlement: cash is mandatory only when escrow covers that holder's complete
  face amount, `isRedemptionReady(vault, holderBalance)` confirms the exact burn and the settlement
  policy approves the exact vault-to-holder cash amount; otherwise that holder may receive CVA
  without constraining another holder's cash redemption;
- `cvaReleasedFace` accounting and automatic buyer credit for escrow above remaining cash liability,
  preventing mixed CVA/cash settlement from double-allocating invoice face value;
- an observational `defaultCvaReleaseStarted` flag that gates neither later funding nor existing cash
  redemption, preventing a prior CVA payout from griefing remaining holders;
- balance-delta checks against fee-on-transfer behavior;
- exact CVA custody credit, issued-supply and asset-integrity checks;
- structural activation readiness based on identity, role, custody and policy presence, followed by
  exact burn-readiness checks for each real allocation instead of a misleading full-supply probe;
- duplicate-holder rejection at activation and adapter-to-holder probes over complete future
  positions, including recipient balance after transfer and residual balance after partial release;
- adapter-side policy rechecks and exact observed balance deltas for the units actually moved;
- fail-closed A-Pass checks for both the adapter and vault before activation, funding and aUSDC
  settlement;
- adapter-to-holder future-position checks for initial allocations, transfer recipients and residual
  default claims, plus exact holder-to-holder pair/delta checks through
  `policy().canTransfer(...)`, with the vault and adapter prohibited from holding mINV;
- separate cash-policy enforcement: holder role/A-Pass plus explicit exact-tuple prechecks before
  every outgoing `_transferExact`, followed by the real aUSDC policy, without unrelated CVA
  deliverability probes;
- pull-based `settlementCredit` for originator bond returns and buyer refunds, so beneficiary A-Pass
  expiry cannot censor holder redeem/close/default-release progress;
- atomic activation proceeds: a denied inline originator payment reverts fund collection, mINV mint
  and state changes together;
- no owner withdrawal of an active reserve.

## Explicitly outside the prototype

- off-network financing;
- buyer/originator collusion or invoice fabrication;
- legal assignment perfection, priority and insolvency treatment;
- confidential partial matching across platforms;
- production KYB, sanctions, UBO and related-party controls;
- abuse prevention for public API proxies and proof that an A-Pass query belongs to the requester;
- recovery when a historical holder loses A-Pass eligibility;
- legal-subject-level role separation across multiple A-Passed wallet addresses;
- cryptographic proof that the allowlisted CVA came from the canonical Cleanverse factory and is
  bound to the vault's `invoiceRoot`, rather than relying on operator-reviewed issuance evidence;
- recovery of a CVA credited to a vault whose financing never activates;
- censorship or griefing by the factory owner or a facility occupying the single pending commit;
- correctness or upgrade safety of sponsor contracts;
- universal liveness under mutable, history-dependent or non-monotone policies; total-position probes
  may also conservatively reject deltas that would fit a max-per-transaction policy;
- economic calibration of a production reserve.

## Integration kill gate

A disposable Monad fork proves that a contract with its own A-Pass can pass the deployed policy and
that the current `MINTER_ROLE` can mint and burn. A separate read-only live check proves that
`policy()` is callable and that `canTransfer(token, from, to, amount)` is routable. It does **not**
prove the policy accepts anyone: at block 48667706 the probed tuples were rejected with
`ComplianceFailed(address)`, consistent with an unsatisfied compliance rule, which Mordant reads as
a refusal. The
runtime CVA guard passes the complete position the holder would need to receive: the initial
allocation, the recipient's post-transfer balance, or the caller's full residual balance on default
release. Cash-only flows remain governed by the aUSDC policy. The remaining kill gate is operational:
the sandbox gateway must issue separate A-Passes to the adapter and vault, and the repaired Monad
launcher must
produce a dedicated invoice A-Token matching the tested ABI. Local tests and fork evidence never
replace those final live readbacks. Validator failures block only the optional richer policy path,
not direct CVI through `isValidAPass(address)`.
