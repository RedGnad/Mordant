# M-05 plan: Monad PROTOCOL DOUBLE deployment

**`CURRENT STATUS: PLAN / DRY-RUN / NO BROADCAST`**

**`TARGET CLASSIFICATION AFTER SUCCESSFUL EXECUTION: MONAD LIVE / PROTOCOL DOUBLE / NOT CLEANVERSE`**

This is a plan and a dry run. **Nothing has been broadcast.** No `--broadcast`, no signature, no
private key in this repository. Execution requires the owner's explicit authorization, and the
target classification applies only once execution has actually succeeded.

What this would prove: the Mordant recourse machinery running on the real Monad testnet, end to end,
with its own protocol doubles. What it would **not** prove: any Cleanverse integration. It uses no
aUSDC, no CCUSD2, no WMON and no Cleanverse write endpoint, and it must never be presented as a
Cleanverse-integrated deployment.

## 1. Contracts to deploy

All five are existing, unmodified contracts from this repository.

| # | Contract | Runtime | Role in the deployment |
| --- | --- | --- | --- |
| 1 | `MockEligibility` | 1 415 B | CVI double: role eligibility and identity, no Cleanverse call |
| 2 | `MockERC20` "Mordant Demo Settlement (double)" `dSETTLE`, 6 decimals | 2 692 B | Settlement double. **Not aUSDC** |
| 3 | `MockERC20` "Mordant Demo Invoice A-Token (double)" `dINV`, 6 decimals | 2 692 B | CVA double. **Not a Cleanverse A-Token** |
| 4 | `MockCvaAdapter` | 2 813 B | Custody double bound to `dINV` |
| 5 | `MordantFactory` | 40 382 B | Real factory, unchanged |

The vault is not deployed directly: `MordantFactory.createInvoiceVault` creates it, installing
31 312 B of runtime.

Token names carry `(double)` and the symbols are `dSETTLE` and `dINV`, so no explorer view or
screenshot can suggest a Cleanverse asset.

## 2. Addresses, roles and keys

**Seven distinct signers. Six of them send transactions and need MON. The originator never sends a
transaction: it only produces EIP-712 pledge signatures, so it needs no MON at all.**

| Role | Sends tx | Needs MON | Purpose |
| --- | --- | --- | --- |
| `deployer` | 21 | yes | Deploys the five contracts, owns the factory and the eligibility double, mints the doubles |
| `buyer` | 3 | yes | `createInvoiceVault`, then approves and funds the 110 redemption |
| `originator` | **0** | **no** | Signs both pledges off chain, EIP-712 only. Receives the 90 proceeds |
| `facilityA` | 1 | yes | `activate` |
| `facilityB` | 3 | yes | `commitConflict`, `revealConflict`, `finalizeConflict` |
| `holderA` | 4 | yes | Funder, 60-unit holder: approve, transfer, claim, redeem |
| `holderB` | 2 | yes | 40-unit holder: claim, redeem |

Key handling for the future runner, which does not exist yet:

- each key is read from its own environment variable at run time, never from a file in this
  repository and never from a shared blob;
- the originator key is the one that may stay out of the runner entirely. Because it only signs,
  it can be held externally: the runner accepts a pre-computed EIP-712 signature for each pledge,
  which lets the originator sign from a hardware wallet or an isolated machine;
- no private key, seed phrase or other secret material is logged or persisted. Public addresses,
  signatures, transaction hashes, blocks and readbacks may be recorded where required;
- `pnpm secret:scan` runs over the artifacts before they are committed.

## 3. Transaction order

**Phase 0, funding (5 transactions).** The deployer sends MON to the five other spending wallets.
The originator is deliberately not funded: it signs and never sends.

1. `deployer -> buyer`, 1.3654 MON
2. `deployer -> facilityA`, 0.1074 MON
3. `deployer -> facilityB`, 0.1032 MON
4. `deployer -> holderA`, 0.1431 MON
5. `deployer -> holderB`, 0.0693 MON

**Phase 0 gate.** Before any Phase 1 transaction, read `eth_getBalance` for all six spending wallets
and confirm each is at least its budgeted figure. A wallet that is short here stops the run: topping
it up mid-sequence is recoverable, but discovering it during `createInvoiceVault` wastes 6.5 M gas.

**Phase 1, deployments (5 transactions).** Order matters: each later constructor takes an address
produced earlier.

6. `MockEligibility`
7. `MockERC20` settlement double
8. `MockERC20` CVA double
9. `MockCvaAdapter(cvaDouble)`
10. `MordantFactory(deployer, eligibility)`

**Phase 2, configuration (17 transactions).**

11-16. `eligibility.setEligible` for buyer (role 1), originator (2), facilityA (3), facilityB (3),
holderA (4), holderB (4)
17-18. `factory.setFacility(facilityA|facilityB, true)`
19. `factory.setCvaAdapter(adapter, true)`
20. `factory.setSettlementToken(settlementDouble, true)`
21. `factory.createInvoiceVault(config)` **from the buyer**
22. `eligibility.setIdentityValid(vault, true)`
23. `cvaDouble.mint(deployer, 100e6)`
24. `cvaDouble.approve(adapter, 100e6)`
25. `adapter.creditVault(vault, 100e6)`
26. `settlementDouble.mint(holderA, 100e6)`
27. `settlementDouble.mint(buyer, 110e6)`

**Phase 3, the journey (12 transactions).** Optional, and the reason the deployment is worth doing.

28. `settlementDouble.approve(vault, 100e6)` from holderA
29. `vault.activate(pledge, signature, holderA, [holderA], [100e6])` from facilityA
30. `vault.transfer(holderB, 40e6)` from holderA
31. `vault.commitConflict(commitment)` from facilityB
32. `vault.revealConflict(pledge, signature, salt)` from facilityB
33. `vault.finalizeConflict()` after the cure window
34-35. `vault.claimBond()` from holderA, then holderB
36. `settlementDouble.approve(vault, 110e6)` from buyer
37. `vault.fundRedemption(110e6)` from buyer
38-39. `vault.redeem(60e6)` from holderA, `vault.redeem(40e6)` from holderB

**Total: 39 transactions.** 5 funding, 5 deployments, 17 configuration, 12 journey.

### Timing on a real network

On Monad there is no `evm_increaseTime`, so any window the demo has to sit through is real elapsed
time. Only one of the two periods is a wait:

| Parameter | Value | Why |
| --- | --- | --- |
| `revealPeriod` | **3 600**, unchanged | A maximum deadline, not a wait. Facility B reveals immediately after committing; the window only bounds how long it may take. Shortening it buys nothing and adds the risk that a legitimate reveal expires |
| `curePeriod` | **60** | `DEMO-ONLY CONFIGURATION`. This one is a genuine wait: `finalizeConflict` is only callable once it has elapsed. 60 seconds keeps a live demo watchable |

`curePeriod = 60` must be labelled `DEMO-ONLY CONFIGURATION` wherever the deployment is presented. A
real cure window is measured in days, and a 60-second one would give a counterparty no realistic
chance to resolve or dispute the incident. It is a vault configuration value, not a contract change,
and the dry run below was re-measured with exactly these two values.

## 4. Gas and MON, per wallet

Phase 1 comes from read-only `eth_estimateGas` against Monad at block 48807664. Phases 2 and 3 need
deployed contracts, so they were measured by executing the exact sequence on a local chain. Local
measurements, not Monad observations. The deployer row below uses the Monad estimate for the five
deployments rather than the local figure, which is 149 429 gas lower.

| Wallet | Tx | Gas | MON at 102 gwei | Funded, 2x margin |
| --- | --- | --- | --- | --- |
| `deployer` | 21 | 12 186 160 | 1.2430 | **2.4860** |
| `buyer` | 3 | 6 693 003 | 0.6827 | **1.3654** |
| `originator` | 0 | 0 | 0 | **0, signs only** |
| `facilityA` | 1 | 526 533 | 0.0537 | **0.1074** |
| `facilityB` | 3 | 505 929 | 0.0516 | **0.1032** |
| `holderA` | 4 | 701 469 | 0.0715 | **0.1431** |
| `holderB` | 2 | 339 868 | 0.0347 | **0.0693** |
| funding transfers, 5 x 21 000 | 5 | 105 000 | 0.0107 | 0.0214 |
| **Total** | **39** | **21 057 962** | **2.1479** | **4.2958** |

Two transactions dominate: `MordantFactory` at 8.8 M gas on the deployer, and `createInvoiceVault`
at 6.5 M on the buyer. The buyer therefore needs **1.37 MON**, not a token amount.

If the deployer distributes MON to the other five spending wallets, fund the deployer with
**4.30 MON** and let it send the five transfers. Otherwise fund each wallet with its own line above.
The originator is funded with nothing in either case.

Phase 3 alone is 2.25 M gas, about 0.23 MON, so the journey can be replayed on a fresh vault for
roughly a quarter of a MON once the contracts are deployed.

## 5. Exact commands

Dry run, no broadcast:

```bash
pnpm m05:dryrun                                   # Monad read-only creation-gas estimate
anvil --port 8547 --code-size-limit 131072 --silent &
node scripts/m05-dryrun-local.mjs                 # configuration and journey gas
```

The broadcasting script does not exist yet and must not be written until this plan is approved. When
it is, it must:

- refuse any chain id other than 10143;
- read each key from its own environment variable at run time, never from a file in the repository,
  and accept a pre-computed EIP-712 signature so the originator key can stay on a separate machine;
- log or persist no private key, seed phrase or other secret material; public addresses,
  signatures, transaction hashes, blocks and readbacks may be recorded where required;
- stop at the first failed readback rather than continuing;
- write an artifact recording every transaction hash, block, gas used and readback.

## 6. Readback after each transaction

No step is considered done on a receipt alone. Each one is confirmed by reading state back.

| After | Readback |
| --- | --- |
| Phase 0 funding | `eth_getBalance` for all six spending wallets, each at or above its budget. This gate must pass before Phase 1 begins |
| every deployment | `eth_getCode` non-empty, and its size equals the compiled runtime |
| `setEligible` | `isEligible(account, role) == true` |
| `setFacility` | `factory.isFacility(address) == true` |
| `setCvaAdapter` / `setSettlementToken` | `approvedCvaAdapter` / `approvedSettlementToken == true` |
| `createInvoiceVault` | `InvoiceVaultCreated` decoded; `vaultForRoot[root]` equals the emitted vault; vault code size 31 312 B; `faceValue`, `initialUnits`, `bondBps` match the config |
| `creditVault` | `adapter.availableBalance(vault) == 100e6` and `issuedSupply() == 100e6` |
| `activate` | `protectionState == Active`, `receivableState == Outstanding`, originator balance +90e6, vault balance 10e6, `bondLocked == 10e6`, `totalSupply == 100e6`, then `assertAccounting()` |
| `transfer` | `balanceOf(holderA) == 60e6`, `balanceOf(holderB) == 40e6` |
| `commitConflict` | `protectionState == CommitPending`, `pendingConflict.commitment` matches |
| `revealConflict` | `protectionState == ConflictConfirmed`, `cureDeadline` set |
| `finalizeConflict` | `protectionState == Entitled`, `entitlementAllocated == 10e6` |
| `claimBond` | claimant settlement balance +6e6 then +4e6, units unchanged at 60/40 |
| `fundRedemption` | `redemptionEscrow == 110e6` |
| `redeem` | `redeemedFace` reaches 110e6, `receivableState == Redeemed`, holders paid 66e6 and 44e6 |

`assertAccounting()` is called after every money-moving transaction. It reverts on any inconsistency,
so a passing call is itself a readback.

## 7. Abort and rollback

There is no rollback. Every transaction is final, so the rule is to stop rather than to repair.

| Failure | Action |
| --- | --- |
| Chain id is not 10143 | Abort before the first transaction |
| A deployment reverts or runs out of gas | Stop. Nothing downstream is usable; record the hash and restart from step 1 with fresh addresses |
| A readback disagrees with the expectation | Stop immediately. Do not send the next transaction. The mismatch is the finding |
| `createInvoiceVault` reverts | Stop. The most likely causes are a role overlap or an unapproved adapter or token, all visible in phase 2 readbacks |
| `activate` reverts | Stop. Usual causes: missing approval, CVA custody not credited, or an ineligible participant |
| The cure window has not elapsed | Wait out the 60 seconds. Do not redeploy with a shorter one |
| A reveal approaches the 3 600 s `revealPeriod` deadline | Reveal now. If it expires, the commitment is dead and the conflict must be re-committed with a fresh salt |
| A wallet runs out of MON mid-sequence | Stop, top it up from the deployer, then resume at the failed step. No state is lost |
| A partially configured deployment | Abandon it and start again with a fresh invoice root. Redeploying is cheaper and cleaner than patching, and the factory refuses a duplicate root |

An abandoned deployment costs at most the MON already spent. No user funds and no Cleanverse asset
are ever at risk, because none are involved.

## 8. What this deployment must never be called

Not a Cleanverse integration, not a live settlement rail, not an aUSDC transaction, not proof that
the Cleanverse CVA lifecycle works. Until execution succeeds the status stays
`PLAN / DRY-RUN / NO BROADCAST`. Once it does, every published reference must carry
`MONAD LIVE / PROTOCOL DOUBLE / NOT CLEANVERSE`, and the interface must keep showing the same label
for a deployment of this kind.

The open Cleanverse question on the Monad settlement token is unaffected by this plan and remains
the blocker for a real rail.
