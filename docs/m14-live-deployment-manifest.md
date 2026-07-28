# M-14: live deployment manifest

    MANIFEST STRUCTURE: READY
    EXECUTION INPUTS: INCOMPLETE
    PUBLIC WRITES: NOT AUTHORIZED
    MORDANT SETTLEMENT: NOT PROVEN LIVE

Six of the nine participant addresses have not been supplied. The structure is complete; the inputs
it will act on are not, and those are different claims. Once every address is supplied and verified,
the status becomes `LIVE DEPLOYMENT MANIFEST: READY`.

What a public deployment would consist of, verified as far as it can be without performing any of
it. No runner in this mission accepts a write mode: `--run`, `--broadcast`, `--deploy`, `--execute`
and `--send` all stop the process.

    pnpm m14:manifest --out docs/evidence/monad-m14-manifest-2026-07-29

## The frozen version

    4285f622c238f9663dfcdb3dd0a5e5b01e8c081d

M-13 rehearsed **this** tree. The freeze covers `contracts/src`, `contracts/foundry.toml` and the
structural parameters below; scripts and documents may move without invalidating anything, and a
gate that refused those would be theatre, since writing this manifest changes the tree.

Any change to a contract or a structural parameter after this point requires a **full M-13 replay**
before deployment. The manifest refuses to generate otherwise, naming what moved.

| Parameter | Value |
| --- | --- |
| `initialUnits` | 100000 |
| `advanceAmount` | 100000 |
| `faceValue` | 110000 |
| `bondBps` / bond | 1000 / 10000 |
| net proceeds | 90000 |
| holder allocation / share | 50000 / 55000 |
| `revealPeriod` / `curePeriod` | 3600 / 3600 |
| `protectionDurationSeconds` | **86400** |

`protectionEnd` is **computed at creation** as the vault's creation block timestamp plus 86400. It
is never a date written in advance: one fixed earlier would drift against whenever the deployment
actually happens, and could be stale or already past before the vault exists.

Parameter set hash: `0x0e41517292b37dddeeb7b3e6279ff6b7c2f009a82fae2045efcc0a7b50228c8b`.

### The rehearsal that proved this set

| | |
| --- | --- |
| contracts commit | `4285f622c238f9663dfcdb3dd0a5e5b01e8c081d` |
| rehearsal commit | `3b2454072eee3f98800522d5b8995392d9066b83` |
| artifact | `docs/evidence/monad-m13c-terminal-paths-2026-07-29.json` |
| verdict | `M-13 PINNED MONAD FORK REHEARSAL: PROVEN` |

The two commits are recorded separately on purpose. The contracts are frozen at the first; the
rehearsal proving *these parameters* is the second. Changing the duration invalidated the earlier
rehearsal by our own rule, so it was replayed in full and both branches pass again.

## The live path

    activation -> conflict -> reveal -> finalisation -> default -> MINV01 release

**Cash redemption stays fork-proven.** Deploying a second public vault purely to reproduce a branch
already proven on a fork would spend real deployments to demonstrate nothing new. The recourse path
is the one that shows what Mordant is for.

## Contracts

Runtime hashes are from the frozen artifacts and are what each deployment must be checked against.

| Contract | Phase | Creation | Runtime | Within EIP-170 | Gas cap |
| --- | --- | --- | --- | --- | --- |
| `CleanverseCvaAdapter` | A | 9,621 B | 8,904 B | yes | 2,000,000 |
| `CleanverseAPassVerifier` | C1 | 3,334 B | 2,902 B | yes | 2,000,000 |
| `MordantFactory` | C1 | 40,833 B | 40,382 B | **no** | 8,000,000 |
| `MordantInvoiceVault` | C2 | 35,248 B | 31,312 B | **no** | 8,000,000 |

Two contracts exceed EIP-170 and deploy only because Monad documents a 128 KB limit. That is a
deployment precondition, not a footnote: on a chain enforcing 24,576 bytes neither would deploy.

**On addresses.** `CREATE` addresses are deterministic from the deployer and nonce, but they are not
treated as stable until the deployment is confirmed, the bytecode verified and the readbacks pass.
**No A-Pass is requested on the strength of a computed address alone.** The vault's address is read
from the `InvoiceVaultCreated` event under the same rule.

## Participants

Nine roles. Two facilities are required because the protected one cannot challenge itself, and the
funder is separate from the buyer because the vault rejects an address that is both.

| Role | Mordant role | Signs | Needs aUSDC |
| --- | --- | --- | --- |
| owner/deployer | none | deployments, role config, grants, `bindVault` | 0 |
| holderA, holderB | `ROLE_HOLDER` | `releaseDefaultCva` | 0 |
| buyer | `ROLE_BUYER` | `createInvoiceVault` | 0 |
| funder | `ROLE_HOLDER` | approve, advance at activation | **100000** |
| originator | `ROLE_ORIGINATOR` | two EIP-712 pledges | 0 |
| facilityProtected | `ROLE_FACILITY` | `activate` | 0 |
| facilityChallenger | `ROLE_FACILITY` | commit, reveal | 0 |
| issuanceMinter | none | the single `mint` | 0 |

Only the funder needs aUSDC, and only the advance: the live path stops at the release, so the buyer
never funds redemption. The originator signs but sends nothing.

The generated artifact records each participant's current A-Pass, expiry, Cleanverse eligibility and
MON balance, and marks any address the owner has not supplied as `ADDRESS NOT SUPPLIED` rather than
inventing one.

## Execution DAG

**No phase triggers the next.** Each ends at a stop, and resuming is a separate deliberate command.

**Phase A, adapter.** Deploy, verify the runtime hash against the frozen artifact, verify `owner()`,
`token()`, `apass()` and `boundVault() == 0`. Stop.

**Phase B, adapter credential.** Request the live A-Pass for the adapter. On an ambiguous or
timed-out response, **stop and reconcile by hand; never retry automatically**, because a retry after
an accepted-but-unconfirmed request is how you get two credentials. Verify through the API and on
chain, then verify the MINV01 policy for zero to adapter, adapter to zero, and adapter to each
holder. Stop.

**Phase C1, infrastructure and known participants.** Deploy the verifier and factory, configure
roles then allowlists, request every A-Pass for addresses already known (all of them except the
vault), and verify funding and that each operator can sign what its phase requires. Stop.

Ordering constraint proven in M-13C: `setFacility` asks the verifier, which asks the live A-Pass, so
a credential must exist **before** the allowlist entry.

**Phase C2, just-in-time vault creation.** Create the vault **only when D and E can run immediately
afterwards**, compute `protectionEnd` from that block, request the vault's A-Pass at once, and
verify the nine tuples. Stop.

The split exists so the 24 hour window is not spent waiting on prerequisites that were knowable in
advance. Everything that can be prepared before the clock starts is prepared in C1.

**Phase D, supply ceremony and binding.** Grant `MINTER_ROLE` to the temporary issuance wallet, mint
exactly `initialUnits` to the adapter, revoke immediately, grant to the adapter, reconstruct every
`RoleGranted` and `RoleRevoked` since MINV01 was deployed, and verify the adapter is the **only**
active minter. If it is not, stop **without binding**. Then `bindVault`. Stop.

**Phase E, activation.** The originator signs the pledge, the funder approves and advances, the
protected facility calls `activate`, then verify net proceeds, bond, receipts and
`assertAccounting()`. Stop.

**Phase F, recourse demonstration.** The challenger commits and reveals, wait out the **real** cure
window, `finalizeConflict`, wait out the **real** `protectionEnd`, `markDefault`, then each holder
calls `releaseDefaultCva`. Verify every invariant and balance.

Phase F is the only one with real waiting. On a fork the clock was moved; publicly it is not.

## Target public schedule

| Slot | What runs |
| --- | --- |
| T0, one sitting | C2 creation, vault credential, D binding, E activation |
| T0 + minutes | F commit and reveal, immediately after activation |
| T0 + 1 hour | `finalizeConflict`, once the cure window has really passed |
| T0 + 24 hours | `markDefault`, then `releaseDefaultCva` by each holder |

The first slot is one sitting on purpose: the vault's creation starts the 24 hours, so binding and
activation follow it without a gap.

## Mandatory gates

Every future public command must carry all eight:

1. requires `--run` and `--out`;
2. verifies chain id 10143;
3. verifies the address derived from the signing key;
4. simulates or estimates before sending;
5. applies the gas ceilings;
6. writes the hash as `PENDING` before awaiting the receipt;
7. distinguishes `PENDING`, `STOPPED` and `SUCCESS`;
8. refuses any state that differs from the preceding manifest.

`assertGatesComplete` refuses a command missing any one of them and names it. Ambiguous Cleanverse
operations are never retried automatically.

## Stop and recovery matrix

Nothing recovers by itself. An automatic recovery is how a half-finished deployment becomes two.

| Stopped after | State | What to do |
| --- | --- | --- |
| adapter deployed, no A-Pass | inert: holds nothing, bound to nothing | resume at B with that address. Nothing is at risk while it waits. Redeployable. |
| A-Pass issued, no infrastructure | credentialed adapter, unbound | resume at C. The credential lasts a year; re-verify rather than assume. Redeployable. |
| vault created, no A-Pass | a vault that cannot settle | resume at C step 5. **Do not create a second vault**: the first stays allowlisted and could be bound by mistake. |
| **temporary minter granted, not revoked** | an address other than the adapter can mint | **REVOKE FIRST**, before anything else. The exclusivity check will refuse to bind while it stands. |
| **supply minted, not bound** | adapter holds the whole supply, unclaimed | resume at D step 7. **Do not mint more**: `bindVault` compares exactly, and burning back needs the `MINTER_ROLE` the revoke removed. |
| adapter bound, vault not activated | custody committed to an empty vault | resume at E. `bindVault` is one-shot: a new vault needs a new adapter and a new supply. |
| activated, conflict not started | live receivable inside the protection window | resume at F before `protectionEnd`. If the window closes, `closeProtection` reaches default without the conflict path, demonstrating less. |

The two marked in bold are the ones with real exposure. Everything from `bindVault` onward is
non-redeployable, because binding is the only contractually one-shot step.

## What this mission does not do

No deployment, no A-Pass request, no grant, no mint, no binding, no activation. The manifest is a
plan and a set of checks, and every runner refuses to execute it.
