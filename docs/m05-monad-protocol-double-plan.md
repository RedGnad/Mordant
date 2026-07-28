# M-05 plan: Monad PROTOCOL DOUBLE deployment

**Classification: `MONAD LIVE / PROTOCOL DOUBLE / NOT CLEANVERSE`.**

This is a plan and a dry run. **Nothing has been broadcast.** No `--broadcast`, no signature, no
private key in this repository. Execution requires the owner's explicit authorization.

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

## 2. Addresses and roles

Seven distinct addresses. The deployer is the only one that needs MON.

| Role | Needs MON | Purpose |
| --- | --- | --- |
| `deployer` | yes | Deploys all five contracts, owns the factory and the eligibility double |
| `buyer` | yes, small | Calls `createInvoiceVault`, funds the redemption |
| `originator` | no | Signs pledges off chain, receives the 90 proceeds |
| `facilityA` | yes, small | Activates the vault |
| `facilityB` | yes, small | Commits, reveals, finalizes the conflict |
| `holderA` | yes, small | Funder, then 60-unit holder |
| `holderB` | yes, small | 40-unit holder |

Key management is the owner's decision and is out of scope here. No key is stored in this
repository, and the deployment script must read one from the environment at run time only.

## 3. Transaction order

**Phase 1, deployments (5 transactions).** Order matters: each later constructor takes an address
produced earlier.

1. `MockEligibility`
2. `MockERC20` settlement double
3. `MockERC20` CVA double
4. `MockCvaAdapter(cvaDouble)`
5. `MordantFactory(deployer, eligibility)`

**Phase 2, configuration (17 transactions).**

6-11. `eligibility.setEligible` for buyer (role 1), originator (2), facilityA (3), facilityB (3),
holderA (4), holderB (4)
12-13. `factory.setFacility(facilityA|facilityB, true)`
14. `factory.setCvaAdapter(adapter, true)`
15. `factory.setSettlementToken(settlementDouble, true)`
16. `factory.createInvoiceVault(config)` **from the buyer**
17. `eligibility.setIdentityValid(vault, true)`
18. `cvaDouble.mint(deployer, 100e6)`
19. `cvaDouble.approve(adapter, 100e6)`
20. `adapter.creditVault(vault, 100e6)`
21. `settlementDouble.mint(holderA, 100e6)`
22. `settlementDouble.mint(buyer, 110e6)`

**Phase 3, the journey (12 transactions).** Optional, and the reason the deployment is worth doing.

23. `settlementDouble.approve(vault, 100e6)` from holderA
24. `vault.activate(pledge, signature, holderA, [holderA], [100e6])` from facilityA
25. `vault.transfer(holderB, 40e6)` from holderA
26. `vault.commitConflict(commitment)` from facilityB
27. `vault.revealConflict(pledge, signature, salt)` from facilityB
28. `vault.finalizeConflict()` after the cure window
29-30. `vault.claimBond()` from holderA, then holderB
31. `settlementDouble.approve(vault, 110e6)` from buyer
32. `vault.fundRedemption(110e6)` from buyer
33-34. `vault.redeem(60e6)` from holderA, `vault.redeem(40e6)` from holderB

Phase 3 needs real elapsed time for the cure window. On Monad there is no `evm_increaseTime`, so
`curePeriod` and `revealPeriod` must be set to a value the demo can actually wait out. **Set both to
60 seconds** at vault creation instead of the 3 600 used locally. This is the one parameter that
must change between the local run and Monad, and it is a configuration value, not a contract change.

## 4. Gas and MON

Phase 1 measured against Monad testnet by read-only `eth_estimateGas` at block 48807664. Phases 2
and 3 measured by executing the same sequence on a local chain, because they need deployed
contracts. Local measurements, not Monad observations.

| Phase | Transactions | Gas |
| --- | --- | --- |
| 1, deployments | 5 | 11 356 942 (Monad estimate) |
| 2, configuration | 17 | 7 195 948 (local measurement) |
| 3, journey | 12 | 2 250 655 (local measurement) |
| **Total** | **34** | **20 803 545** |

At the observed Monad testnet gas price of 102 gwei:

- expected cost: **2.12 MON**
- recommended funding with a 2x margin for gas-price movement: **5 MON on the deployer**, plus
  roughly 0.2 MON on each of the five other acting addresses.

`MordantFactory` alone is 8.8 M gas and `createInvoiceVault` 6.5 M, so those two transactions are
about 74% of the total. Both are within Monad's 128 KB code limit and were confirmed acceptable by
the M-04 preflight.

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
- read its key from the environment, never from a file in the repository;
- stop at the first failed readback rather than continuing;
- write an artifact recording every transaction hash, block and readback.

## 6. Readback after each transaction

No step is considered done on a receipt alone. Each one is confirmed by reading state back.

| After | Readback |
| --- | --- |
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
| The cure window has not elapsed | Wait. Do not shorten it by redeploying |
| A partially configured deployment | Abandon it and start again with a fresh invoice root. Redeploying is cheaper and cleaner than patching, and the factory refuses a duplicate root |

An abandoned deployment costs at most the MON already spent. No user funds and no Cleanverse asset
are ever at risk, because none are involved.

## 8. What this deployment must never be called

Not a Cleanverse integration, not a live settlement rail, not an aUSDC transaction, not proof that
the Cleanverse CVA lifecycle works. Every published reference must carry
`MONAD LIVE / PROTOCOL DOUBLE / NOT CLEANVERSE`, and the interface must keep showing the same label
for a deployment of this kind.

The open Cleanverse question on the Monad settlement token is unaffected by this plan and remains
the blocker for a real rail.
