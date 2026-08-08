# Internal adversarial review

This is a prebuild engineering review, not an external audit and not a production-safety claim.

> ## Current status, 8 August 2026
>
> Two findings below were written before the Cleanverse write path and the Monad
> settlement were executed, and are now **superseded**. They are annotated in place
> rather than deleted, because the reasoning that produced them is still the record
> of how the boundary was probed.
>
> - `/atoken/launch` **has** since been executed: MINV01 was issued with readback.
> - A **compliant A-Pass profile was identified** (tier 50), and the settlement path
>   completed: recourse claims in aUSDC were paid and reconciled on Monad testnet.
>
> Everything else in this document still stands, including the production gaps:
> no `MINTER_ROLE` grant, address-level rather than legal-subject-level role
> separation, revocable external A-Token administration, and the governance,
> timelock and monitoring controls production would require.

## Findings closed in the prototype

- A buyer-supplied malicious adapter or settlement token is rejected unless the factory owner has
  explicitly allowlisted it.
- A facility cannot choose a record date and acquire an originator signature afterward: the hidden
  commitment includes the exact signature hash.
- The same wallet address cannot overlap buyer, originator, facility and holder roles in a protected
  vault.
- The vault and adapter are categorically rejected as mINV holders, so custody addresses cannot
  enter holder checkpoints or receive protection allocations.
- Activation rejects duplicate holder addresses, so one address cannot split its position across
  individually passing probes.
- Adapter-to-holder admission probes the complete future position: initial allocation, recipient
  balance plus transfer amount, or the caller's complete remaining balance before default release.
- A holder-to-holder mINV transfer retains sender role/A-Pass, probes the recipient's future position
  and checks the exact `canTransfer(cva, holderA, holderB, amount)` pair/delta.
- The adapter rechecks the actual execution delta and verifies real sender/recipient balance changes;
  preflight success never replaces transfer accounting.
- A non-allocated funder is checked for holder role/A-Pass without a false CVA-delivery probe; the
  actual aUSDC transfer enforces the exact funder-to-vault policy.
- Bond claims and cash redemptions check holder role/A-Pass, explicitly precheck the exact
  vault-to-holder aUSDC policy tuple, and then execute the policy-enforcing token transfer. They do not
  require adapter-to-holder CVA deliverability, so CVA policy cannot strand a cash-only entitlement.
- CVA credit, asset identity and dedicated issued supply are checked; an unexpected mint or adapter
  asset change stops state transitions.
- With CVA, mINV and aUSDC recorded on the required six-decimal scale, the constructor rejects
  `faceValue < initialUnits`. Any positive non-final lot therefore maps to at least one atomic aUSDC
  unit, while the final-lot branch pays or discharges the exact residual instead of rounding to zero.
- Redemption funding cannot exceed the unpaid face value.
- Only the immutable buyer/debtor can fund redemption, preventing an unrelated account from
  manipulating the cash coverage used in a holder's default-settlement decision.
- After default, each holder is forced to cash only when escrow covers the face value of its complete
  balance, that complete-balance burn is ready and the settlement policy approves the exact cash
  payout. Otherwise that holder may receive CVA without changing another holder's settlement choice.
- `cvaReleasedFace` reduces remaining cash liability after each CVA payout. Only escrow above that
  liability becomes buyer `settlementCredit`; holders whose burn and exact aUSDC payout both pass can
  continue redeeming from the escrow that remains.
- `defaultCvaReleaseStarted` is an observation flag, not a settlement lock. Following any CVA payout,
  the buyer may fund the exact liability shortfall and cash-eligible holders may redeem, preventing a
  prior CVA payout from griefing later holders.
- Originator bond returns and buyer refunds accrue as accounted pull-payments. An expired beneficiary
  cannot revert holder redemption, protection close or default release; it claims after restoring
  A-Pass/aUSDC eligibility.
- Activation proceeds remain an atomic inline transfer. A denied originator causes the complete
  activation to revert before any funder cash, reserve or receipt state can be stranded.
- A transfer after the hidden commit cannot move the historical 60/40 entitlement.
- Protection claims never burn receipts or CVA and cannot consume receivable escrow.

## Findings still open

- The Cleanverse CVI verifier and CVA adapter now have tested implementations, but the A-Pass and
  standard A-Token ABIs are inferred from current deployed bytecode rather than a published stable
  Solidity interface. They still require a fresh judged testnet deployment and upgrade monitoring.
- Activation, buyer funding and aUSDC settlement require current A-Passes for both adapter and vault,
  but live contract-address issuance through the Cleanverse gateway has not yet been observed.
- Base activation readiness checks identity, role, custody and policy presence without simulating a
  full-supply burn. Every actual initial allocation receives its own exact position check.
- Policy compatibility is conservative, not universal parity. Mutable, history-dependent or
  non-monotone policies can invalidate a prior result, while max-per-transaction rules can reject a
  total-position probe even when the immediate delta would fit. Such false negatives fail closed and
  remain an explicit liveness boundary.
- The external A-Token admin can still revoke `MINTER_ROLE` after cash is escrowed. Per-holder CVA
  settlement remains possible only while default delivery itself is permitted. Production still
  needs a non-revocation covenant, monitoring and an emergency role-restoration procedure for
  simultaneous burn/release loss.
- Both contract A-Passes must expire after the full invoice and recovery horizon. If either expires,
  the affected activation, cash or CVA path pauses until the issuer renews the identity.
- No backend/factory selector skew was observable at block 48667706: the factory implementation
  carries the ten-argument launch selector. This is a read-only bytecode fact. Whether a
  /atoken/launch application now succeeds was NOT PROVEN, WRITE ACTION REQUIRED, when this was
  written. **Superseded 8 August 2026:** the launch was executed and MINV01 reached `ISSUED` with
  readback, so a fresh invoice CVA is live.
- The probed `canTransfer` tuples were rejected with `ComplianceFailed(address)`, consistent with a
  compliance rule that is not satisfied. Mordant fails closed correctly. No settlement path can
  complete for those participants until a compliant A-Pass profile is identified with Cleanverse.
  **Superseded 8 August 2026:** a compliant tier 50 profile was identified, `isAssetTransferAllowed`
  returns true for the adapter to each holder, and the settlement path completed with both aUSDC
  claims paid and reconciled.
- One global pending commitment can be used by an allowlisted facility for bounded griefing or to
  delay another reveal. Production needs quotas, a caution or parallel per-facility commitments.
- Factory ownership can change facility membership and thereby censor future reveals or freeze a
  holder later labelled as a facility. Production needs scoped governance, timelock and operating
  rules.
- Verifier ownership can add or revoke institutional roles. A compromised or unilateral owner can
  block future actions even though it cannot rewrite existing accounting. Production needs the same
  scoped governance, timelock and recovery controls.
- Role separation is address-level, not legal-subject-level. One legal entity using multiple
  A-Passed wallets could occupy economically conflicting roles unless onboarding binds every wallet
  to an authoritative entity registry.
- The adapter proves immutable token/vault/unit consistency, but the current A-Token interface does
  not cryptographically prove Cleanverse factory provenance or bind the token metadata to
  `invoiceRoot`. Factory allowlisting and issuance evidence remain operational trust until a
  canonical on-chain registry or attestation closes that link.
- There is no onchain recovery for an A-Token credited before a financing that never activates.
- A historical holder whose A-Pass or CVA-policy eligibility is revoked keeps its entitlement in
  accounting but cannot claim until a compliant recovery process exists.
- Deterministic invoice roots leak low-entropy commercial facts unless matching moves to a
  confidential environment.
- The contracts fit Monad's 128 KiB limit reported by the local Foundry build, but exceed Ethereum's
  classic 24 KiB runtime limit. A cross-chain version must split or optimize them.
- No external audit, formal verification, legal opinion, production monitoring or incident response
  exists.

Any one of these remains a production `NO-GO` for real invoices or funds.
