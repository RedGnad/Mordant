# Testnet deployment runbook

No address is deployed or claimed during prebuild. The official judged deployment must be fresh and
must use the discovered Cleanverse configuration and a newly issued invoice A-Token.

## Contract size: Ethereum limit versus Monad limit

These are two different limits and must not be conflated.

| | limit | `MordantFactory` 40382 B | `MordantInvoiceVault` 31312 B |
| --- | --- | --- | --- |
| Ethereum, EIP-170 | 24576 B runtime | exceeds by 15806 B | exceeds by 6736 B |
| Monad, documented | 128 KB runtime, 256 KB init code | within | within |

Status:

- `MONAD SIZE LIMIT: WITHIN DOCUMENTED 128 KB LIMIT`
- `MONAD DEPLOYABILITY: NOT PROVEN — RPC PREFLIGHT REQUIRED`
- `STANDARD EVM PORTABILITY: BLOCKED BY EIP-170`

Source: Monad documentation, "Max contract size 128 kb (up from 24.5 kb in Ethereum)", and "the
maximum contract code size limit is 128 KB (up from 24 KB in Ethereum). Consequently, the max init
code size limit is 256 KB (up from 48 KB in Ethereum)."

What follows from that, and only that. A default Anvil enforces the Ethereum limit and therefore
refuses these contracts, which is why `pnpm localnet` configures the local chain to the Monad
figure. Being inside the documented Monad limit is not the same as a successful Monad deployment:
that remains `NOT PROVEN` until an RPC preflight confirms it against the live network, without
broadcasting. Porting these contracts to any standard EVM chain stays blocked by EIP-170 until they
are split or optimised, which is a separate decision and is not attempted here.

## Cleanverse boundaries

Deploy the tested boundary implementations only after the invoice A-Token reaches `ISSUED`:

- `MORDANT_BOUNDARY_OWNER` — judged EOA or multisig controlling institutional role grants and the
  one-time adapter binding;
- `CLEANVERSE_APASS_ADDRESS` — runtime-discovered Monad A-Pass proxy;
- `INVOICE_ATOKEN_ADDRESS` — issued dedicated invoice A-Token;
- `CVI_OPEN_ROLE_MASK` — `16` opens only role 4 (holders) to eligible A-Passes; this never bypasses
  the underlying CVA `canTransfer` check or the adapter/vault holder exclusions;
- `DEPLOYER_PRIVATE_KEY` and `MONAD_RPC_URL` — ephemeral testnet deployment inputs.

```bash
forge script --root contracts \
  script/DeployCleanverseBoundaries.s.sol:DeployCleanverseBoundaries \
  --rpc-url "${MONAD_RPC_URL}"
```

Add `--broadcast` only during the judged window after the simulation and address readbacks pass.

## Factory

Required environment variables:

- `DEPLOYER_PRIVATE_KEY` — ephemeral Monad testnet deployer only;
- `MORDANT_FACTORY_OWNER` — final owner, preferably the judged multisig/test owner;
- `CVI_VERIFIER_ADDRESS` — freshly deployed `CleanverseAPassVerifier`;
- `CVA_ADAPTER_ADDRESS` — freshly deployed `CleanverseCvaAdapter` for the dedicated invoice A-Token;
- `SETTLEMENT_TOKEN_ADDRESS` — discovered aUSDC address;
- `MONAD_RPC_URL` — explicit RPC endpoint.

Simulate before broadcasting:

```bash
forge script --root contracts script/DeployFactory.s.sol:DeployFactory \
  --rpc-url "${MONAD_RPC_URL}"
```

Broadcast only on Monad testnet or local Anvil after the simulation succeeds:

```bash
forge script --root contracts script/DeployFactory.s.sol:DeployFactory \
  --rpc-url "${MONAD_RPC_URL}" \
  --broadcast
```

The script rejects every chain except Monad testnet (`10143`) and local Anvil (`31337`), contains no
fallback address and transfers factory ownership after allowlisting the two asset boundaries.

## Exact judged sequence

1. Discover the live chain configuration and save its response in a new judged deployment record.
   Read back and record that the allowlisted aUSDC settlement token uses six decimals.
2. Launch one standard invoice A-Token through the documented Cleanverse issuance flow and wait for
   `ISSUED`. Accept its address only from the terminal application response; verify the issuance
   transaction, implementation, six-decimal scale, policy, `MINTER_ROLE` and burn selector before
   exporting it.
3. Deploy `CleanverseAPassVerifier` and one fresh `CleanverseCvaAdapter` for the issued CVA.
4. Deploy the factory with those boundary addresses and create the buyer-accepted invoice vault from
   the buyer wallet. Record `faceValue` and `initialUnits` in their shared six-decimal base-unit scale
   and require `faceValue >= initialUnits`; the constructor rejects the vault otherwise. This ensures
   every positive non-final lot maps to at least one atomic aUSDC unit, while the final lot receives
   the exact residual face value.
5. Issue separate A-Passes to the adapter and vault. Set both expiries beyond the complete invoice,
   default and operational-recovery horizon. Read back both credentials before continuing.
6. Grant the adapter only the narrowly required CVA mint/burn role. Grant buyer, originator and
   facility roles in `CleanverseAPassVerifier`, then register both facilities in the factory.
7. Mint exactly the dedicated supply into the adapter, bind it irrevocably to the vault and verify
   supply, balance and credit.
8. Before activation, prove both contract A-Passes are valid and each intended holder passes
   `cva.policy().canTransfer(cva, adapter, holder, allocation)` for its complete future position.
   Reject duplicate holder addresses before activation. If the funder receives no allocation, verify
   only its holder role/A-Pass and let the actual aUSDC transfer enforce `funder -> vault`; do not
   invent an adapter-to-funder CVA probe. Confirm explicitly that neither the adapter nor vault can
   hold mINV. Verify base `isActivationReady` from identity, role, custody and policy presence, then
   call `isRedemptionReady(vault, allocation)` for every real allocation; do not substitute a
   full-supply burn simulation.
9. Execute activation, conflict, 6/4 protection claims and independent 66/44 redemption. Recheck
   fail-closed readiness before funding and every aUSDC settlement. For the judged holder-to-holder
   transfer, record the recipient's adapter probe using `recipientBalance + amount` and
   `cva.policy().canTransfer(cva, holderA, holderB, amount)` for the exact pair/delta; the sender keeps
   holder role/A-Pass eligibility. For bond claims and cash redemption, record holder role/A-Pass plus
   the explicit
   `settlement.policy().canTransfer(settlement, vault, holder, exactCash)` precheck and actual aUSDC
   outcome; no CVA deliverability probe belongs on those cash-only paths.
10. On a separate disposable fixture, escrow enough cash for both holders, make holder A's
    exact burn or exact vault-to-A cash payout unavailable and cross into default. Let A receive CVA,
    verify the matching increase in `cvaReleasedFace`, credit only escrow above the reduced cash
    liability to the buyer, then let holder B—whose burn and exact cash payout both pass—redeem from
    the remaining escrow.
11. Verify `defaultCvaReleaseStarted` is observational only. After A's CVA payout, leave escrow short,
    fund exactly `faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow`, and prove B can
    redeem cash; neither funding nor redemption may be gated by A's earlier release.
12. Exercise pull-payment liveness: accrue an originator bond return or buyer refund while that
    beneficiary cannot receive aUSDC, prove holder redeem/close/default release still completes, then
    restore eligibility and call `claimSettlementCredit`. Record `settlementCreditTotal` before and
    after the claim.
13. Simulate activation with an originator that cannot receive aUSDC and verify the transaction
    reverts atomically with no funder balance loss, vault balance increase, mINV mint or state change.
14. Set `NEXT_PUBLIC_MORDANT_VAULT_ADDRESS`; the UI will then read a single-block snapshot and call
   `assertAccounting()` before displaying a live proof.

On the policy fixture, also prove that a partial default release checks the caller's complete current
mINV balance and that a subsequent release checks the new residual. Record the adapter's before/after
balance deltas for the units actually transferred. Treat a rejection caused only by a total-position
probe exceeding a max-per-transaction limit as a conservative no-go, not as proof the immediate delta
was forbidden.

Save every address, transaction hash and post-transaction readback after each step. Never accept an
arbitrary token address merely because it implements the expected selectors.

Wait for Monad's `Verified` state before treating deployment or asset-state changes as irreversible
business facts; an ordinary transaction receipt is not the final operational checkpoint.

Never reuse the synthetic mocks or prebuild keys for the judged deployment.

This runbook is currently externally blocked. Re-measured on 27 July 2026 at Monad testnet block
48667706 (`pnpm evidence:cleanverse --live`, artifacts in `docs/evidence/`):

- **no backend/factory selector skew was observable at block 48667706**: the Monad proxy resolves to implementation
  `0x21084e6ca8d65d3f1a3d27cac9c1abe06f1582ea`, whose dispatch table contains the ten-argument
  launch selector `0xeff21872`. Issuance health itself remains untested;
- live gateway issuance of an A-Pass to a contract address is still unobserved;
- the deployed aUSDC policy reverted with `ComplianceFailed(address)` for all three probed
  `canTransfer` tuples, including one between two valid A-Pass holders.

**That blocker was lifted on 28 July 2026** by a Cleanverse configuration transaction, with no
contract upgrade (`pnpm revalidate:ausdc`, artifact
`docs/evidence/monad-ausdc-revalidation-2026-07-28.*`). A policy-accepted holder-to-holder pair is
now known, so step 9 has a viable path. It remains untested: no aUSDC transfer has been broadcast,
and the settlement rail stays `NOT PROVEN` until one is.

Read-only calls prove the on-chain contract path, but they do not authorize skipping any live
dependency, and a reverting policy must never be worked around by weakening the precheck.

## Credential handling

Never commit Cleanverse credentials. They are server-only and belong in `.env.local`, which is
git-ignored. Any sandbox key that has been shared outside a secret manager must be rotated before
durable use, and `pnpm secret:scan` runs as part of `pnpm validate` to catch a credential pattern
before it reaches a commit.
