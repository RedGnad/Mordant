# Settlement authority proof

A governed Boolean says a conflict exists. It never says who gets paid, how much,
or out of which adapter. This document records the seam that keeps those two
things apart, and states exactly what it does and does not prove.

## The authority chain

```
settlement profile committed BEFORE result exposure
  -> settlementProfileDigest
  -> governed result (contributes the Boolean, nothing else)
  -> verified settlement plan  -> planHash
  -> settlement authorization  -> settlementAuthorizationHash
  -> BridgeExecutor refuses to sign without a matching authorization
```

Every economic term (both holders, both payouts, token, verifier, facility,
attestor, adapter identity, cure window, governing authority) is committed and
digest-bound before any result exists. `deriveSettlementPlan` reads exactly one
field from the governed result, `conflict`, and takes everything else from the
committed profile. A profile altered after commitment produces a different
digest and is refused.

Enforcement sits in `simulate`, the only place in `bridge-executor.ts` that
signs, and fires **before the attestor key is loaded**. Any release with
`payoutA + payoutB > 0` must present an authorization matching that exact
release. A refusing release carries none, because there is nothing to authorize.

## Positive path

`an authorized profile settles exactly what it committed` asserts that a profile
committing `payoutA = 1`, `payoutB = 1` and a 600 second cure window, combined
with a governed conflict from the committed authority, produces a plan carrying
those exact terms, an authorization bound to the committed profile digest, and a
gate that accepts the matching release.

## Negative controls

| Control | Refusal code |
|---|---|
| Governed Boolean with no settlement authority | `SETTLEMENT_NOT_AUTHORIZED` |
| No-conflict result cannot settle | `NO_CONFLICT` |
| Profile tampered with after commitment | `PROFILE_TAMPERED` |
| Result from an uncommitted governing authority | `AUTHORITY_MISMATCH` |
| Changed holder | `HOLDER_MISMATCH` |
| Changed payout | `PAYOUT_MISMATCH` |
| Wrong adapter | `ADAPTER_MISMATCH` |
| Authorization belonging to another plan | `PLAN_MISMATCH` |
| Authorization attached to a no-conflict release | `NO_CONFLICT_RELEASE` |
| Release for a different governed result | `RESULT_MISMATCH` |
| Published managed policy stays unauthorized | `SETTLEMENT_NOT_AUTHORIZED` |

The digest test additionally asserts that changing any one of the ten committed
terms moves `settlementProfileDigest`.

## How to reproduce

```bash
npx tsc -p tsconfig.settlement-authority.json
node --test .settlement-test-dist/src/lib/protection/settlement-authority.test.js
```

Result: **15 pass, 0 fail**. Repository typecheck `npx tsc --noEmit` exits 0.

## Scope

This document covers the authority seam itself: what is committed, what is
derived, and what is refused. It is a code-level proof and carries no
transaction hashes of its own.

The settlement this seam governs, with its full hashes, chronology and exact
reconciliation, is recorded in the
[unified settlement manifest](./unified-settlement-manifest.md). A separate
retained run on Monad testnet is kept in the hardened artifacts alongside it.

The published managed policy `mordant.managed-demo.facility-protection@1` is
untouched and remains `settlementAuthorization = NOT_AUTHORIZED`.
