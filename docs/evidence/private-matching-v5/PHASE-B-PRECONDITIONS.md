# Phase B preconditions: two blockers

Checked at the start of M-RC2-RUN2, before any live broadcast. Both are
resource preconditions the mission mandates, both fail, and both need an owner
action rather than a workaround.

Phase A (runner readiness, no live broadcasts) is unaffected and proceeds.

## Continuation checks that PASSED

| Check | Result |
|---|---|
| Branch | `remediation/private-matching-v4-rc2` |
| HEAD | `99dae19` as expected |
| Ancestor `09a8b24` | yes |
| Ancestor `c709df2` | yes |
| Tracked tree | clean |
| Untracked files | 5, the classified pre-existing set |
| Surviving processes | none |
| Chain | 10143, block ~49979682 |
| Deployer nonce | 128 latest == 128 pending, reconciled |
| Relayer nonce | 0 == 0, reconciled |
| Submitter nonce | 0 == 0, reconciled |
| Frozen RC1 sources | 16/16 match `af5baad` |
| Frozen V5 sources | 12/12 match the freeze |
| V5 EIP-712 types | 4/4 match |

No `AMBIGUOUS` state. Nothing pending on any account.

## Stage classification for the FINAL run

Every stage is `NOT_STARTED`. The provisional deployment is explicitly not
reused, so no stage inherits from it.

| Stage | State |
|---|---|
| 1 INITIALIZED | NOT_STARTED |
| 2 FINAL_STACK_PLANNED | NOT_STARTED |
| 3 FINAL_STACK_DEPLOYED | NOT_STARTED |
| 4 - 23 | NOT_STARTED |

## BLOCKER 1 — insufficient MON for the final run

| | |
|---|---|
| Deployer balance | **2.669 MON** |
| Current base fee | 100 gwei, so `maxFeePerGas` = 202 gwei |
| Provisional stack, measured | 31,565,323 gas over 20 transactions |
| That stack at current fees | **6.376 MON** |
| Plus vault, session, binding (~12M gas) | 2.424 MON |
| **Projected total** | **~8.8 MON** |

The provisional deployment cost about 3.8 MON when base fees were lower; the
current base fee is 100 gwei, which roughly doubles the same work.

This is a floor, not a ceiling: **Monad checks the sender's balance against
`gas_limit * maxFeePerGas`, not against gas actually used**, and the runner sets
`gas_limit = estimate * 1.3`. The instantaneous balance requirement during the
factory deployment is therefore higher than the settled cost.

The relayer and submitter each hold 0.3 MON, which is adequate for their one
transaction each.

**Required: fund `0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0` to at least 12 MON**
to cover the projected 8.8 MON plus the gas-limit headroom and fee variance.

## BLOCKER 2 — insufficient free disk for the live ceremony

| | |
|---|---|
| Free space | **2.1 GiB** |
| Ceremony material, measured | 344 MB (parameters, collective public key, relinearization key, Galois keys, six input ciphertexts) |
| Three operator directories | ~1.0 GB, since process separation means no operator may share another's artifacts |
| Two FullFHE256 envelopes | ~76 MB (measured transport 37.75 MB per side) |
| Evaluator working set, captures, journal, evidence | ~100 MB |
| **Projected peak** | **~1.5 GB** |
| **Mandated margin, 2x peak** | **~3.0 GB** |

2.1 GiB is below the mandated margin and below even a single unsafe pass with
the leak-scan copies. This project has already hit `ENOSPC` twice mid-ceremony
in earlier sessions, each time losing work, so this is a measured recurrence
rather than a theoretical risk.

The streaming secret scanner added for L-02 reads in place and does not
duplicate files, which is the only reason the projection is 1.5 GB rather than
3 GB.

**Required: at least 4 GiB free before the live ceremony**, giving the mandated
2x margin against the 1.5 GB projected peak plus headroom for the evidence
bundle.

## Consequence

Phase B (fresh final deployment, live ceremony, atomic binding) **cannot start**
until both are resolved. Attempting it would either revert mid-deployment on
balance or fail mid-ceremony on disk, in both cases leaving another partially
deployed stack to reconcile.

Phase A proceeds now and is committed independently, exactly as the mission
sequences it.
