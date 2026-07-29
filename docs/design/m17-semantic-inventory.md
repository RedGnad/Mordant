# M-17 Part A: Mordant semantic inventory

What the system actually knows, where each fact comes from, who needs it and what it lets them
decide. No metaphors here, and no screen design: this is the substrate any later design has to serve.

Sources: `contracts/src/MordantInvoiceVault.sol` (16 events, 30 public state variables),
`src/lib/contracts/read-vault.ts` (the reader the app already uses),
`src/lib/dealroom/journey.ts` (14 journey steps), and the M-15 engine's 17 sub-actions.

**Users referenced below:** holder, buyer, funder, originator, facility (protected), facility
(challenger), operator (whoever runs the ceremony), auditor.

## Level 1: immediate decision

Everything needed to answer "what is happening, how much is exposed, when can something be done,
and by whom". If a screen shows nothing else, it shows these.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| `protectionState` | vault, enum | all | which actions exist at all | every visit | public | yes |
| `receivableState` | vault, enum | all | whether the receivable is outstanding, redeemed or defaulted | every visit | public | yes |
| `faceValue` | immutable | holder, buyer | total owed at maturity | every visit | public | yes |
| `advanceAmount` | immutable | originator, funder | cash actually advanced | first visits | public | yes |
| `initialBond` / `bondLocked` | immutable / state | holder | protection standing behind the position | every visit | public | yes |
| `pendingConflict.cureDeadline` | `PendingConflict` | all | when finalisation unlocks | continuously while open | public | yes |
| `pendingConflict.revealDeadline` | `PendingConflict` | challenger | when a commit expires unrevealed | continuously while committed | public | yes |
| `protectionEnd` | immutable | holder, buyer | when default becomes markable | daily | public | yes |
| next permitted action | derived: state + deadlines + caller role | all | what to do now | every visit | public | yes |
| caller eligibility | `cviVerifier.isEligible` | all | whether *this* user may act | every visit | public | yes |
| `balanceOf(holder)` | vault receipts | holder | size of own position | every visit | public | yes |

**The derived pair is the important one.** Neither "next permitted action" nor "caller eligibility"
exists as a field; both are computed from state, deadlines and role. They are what the user actually
came for, and they are the two facts no contract returns directly.

## Level 2: operational detail

Needed to work the deal, not to decide in the first ten seconds.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| `totalSupply`, `initialUnits` | vault | holder, operator | how much of the issue remains outstanding | per action | public | secondary |
| holder allocation table | `Activated` event + balances | holder, operator | who carries what | per action | public | secondary |
| `cvaAccounted` | vault | operator | units the vault still counts as backed | per action | technical | secondary |
| `adapter.availableBalance` | adapter | operator | custody the adapter admits owing | per action | technical | secondary |
| `redemptionEscrow` | vault | buyer, holder | cash already parked against the face | per action | public | secondary |
| `redeemedFace`, `cvaReleasedFace` | vault | holder | how much of the liability is discharged, and by which route | per action | public | secondary |
| `entitlementAllocated` / `Claimed` | vault | holder | bond claimable after finalisation | after finalisation | public | secondary |
| `settlementCreditTotal` | vault | holder | value owed but not yet transferable | rare | public | secondary |
| `protectedFacility`, `conflictSigner` | vault | all | who is on each side of the conflict | during conflict | public | secondary |
| `revealPeriod`, `curePeriod`, `bondBps` | immutable | auditor | the terms the deal was struck on | once | public | secondary |

## Level 3: proof

What lets someone verify a claim rather than trust the screen. Always reachable, never competing
with level 1.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| transaction hash per transition | receipts, M-15 artifacts | auditor, holder | independent verification | on dispute | public | on demand |
| block number and hash | receipts | auditor | pinning a claim to a point in the chain | on dispute | public | on demand |
| the 16 vault events | `Activated` … `DefaultMarked` | auditor | reconstructing the whole history | on dispute | public | on demand |
| `protectedPledgeDigest`, `conflictingPledgeDigest` | vault | auditor, facility | which pledge is which | during conflict | public | on demand |
| EIP-712 pledge signature | off-chain, recorded | auditor | who authorised the pledge | on dispute | public | on demand |
| `RoleGranted` / `RoleRevoked` on MINV01 | token events | operator, auditor | that only the adapter can mint | before binding | technical | on demand |
| `assertAccounting()` result | vault view | operator | that the vault's own invariants hold | per action | technical | on demand |
| A-Pass validity and expiry | registry + `/query_apass` | operator | whether a party can still transact | per action | **sensitive** | on demand |

**One sensitivity flag.** A-Pass records carry a `currentKycHash` and a `magickLink`. The hash is a
compliance artefact and the link is a credential; neither belongs on a shared screen. Everything
else in this table is already public on chain.

## Level 4: technical diagnostic

Needed when something is wrong. Not part of the normal product surface.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| adapter runtime fingerprint | `getCode` + artifact, immutables masked | operator | that the deployed contract is the reviewed one | at deployment | technical | no |
| custody cross-links | `token()`, `apass()`, `boundVault()` | operator | that the wiring matches the manifest | at deployment | technical | no |
| the nine policy tuples | `policy.canTransfer` | operator | which transfer would be refused, and in which direction | before each phase | technical | no |
| revert selector | failed call data | operator | why a transaction was refused | on failure | technical | no |
| gas estimate and ceiling | `estimateContractGas` | operator | whether a cost is abnormal | per transaction | technical | no |
| phase artifact status | M-15 artifacts | operator | where a ceremony stopped and what may resume | on interruption | technical | no |
| chain id, fork pinning | RPC | operator | that this is the intended network | always | technical | no |

## Three observations for whoever designs this

**The deadline is the interface.** Almost every level-1 decision is "not yet" rather than "no". The
state alone is not actionable; state plus remaining time is. A design that renders status as a
static badge will be wrong for this product most of the time.

**Two figures mean different things and look identical.** `faceValue` is what is owed; `bondLocked`
is what protects the holder if it is not paid. Both are amounts in the same token at the same
decimals. Nothing but labelling and placement distinguishes them, so the typographic system carries
real risk here.

**Level 4 is not decoration for level 1.** Runtime fingerprints and policy tuples are how an
operator finds out why a ceremony refused to continue. They belong to a different surface, used by a
different person, at a different moment. Merging them into the deal screen for a sense of rigour
would make the daily screen unreadable and the diagnostic screen incomplete.

## What does not exist

Worth stating so no design invents it:

- no price, no yield, no valuation, no market data;
- no counterparty credit score or rating;
- no portfolio aggregate: every screen so far is one deal;
- no notification or message history;
- no human identity beyond an address and an A-Pass tier.
