# M-17 Part A: Mordant semantic inventory

What the system actually knows, where each fact comes from, who needs it and what it lets them
decide. No metaphors here, and no screen design: this is the substrate any later design has to serve.

Sources: `contracts/src/MordantInvoiceVault.sol` (16 events, 30 public state variables),
`src/lib/contracts/read-vault.ts` (the reader the app already uses),
`src/lib/dealroom/journey.ts` (14 journey steps), and the M-15 engine's 17 sub-actions.

## Three surfaces, not one audience

**Correction to an earlier draft.** "Operator" was used for both the person working deals and the
person running M-15 and reading revert selectors. Those are different people with different
sessions, and merging them is what made the earlier single-screen tension look unresolvable.

| Surface | User | What they do | Session shape |
| --- | --- | --- | --- |
| **Deal Workspace** | credit operator, deal manager | works deals daily: monitors deadlines, prepares and takes actions, reads positions and accounting | long, repeated, many deals |
| **Participant Deal Room** | holders, buyer, funder, originator, facilities | checks one deal: exposure, state, what they may do and when | short, occasional, one deal |
| **Protocol Operations** | protocol administrator | runs deployment phases, reads runtime fingerprints, revert selectors and stop matrices | rare, high-stakes, ceremony-shaped |

Product priority:

    OPERATOR-FIRST, PARTICIPANT-READABLE, DIAGNOSTICS-SEPARATE

The Deal Workspace is the surface that earns its keep daily and should be designed first. The
Participant Deal Room shows the same deal with less, and must be readable by someone who has not seen
it before. Protocol Operations is a separate application in everything but deployment: its user, its
frequency and its failure modes have nothing in common with the other two.

**Users referenced in the tables below:** holder, buyer, funder, originator, facility (protected),
facility (challenger), deal manager, protocol administrator, auditor.

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
| action readiness | derived, five independent inputs, see below | all | what to do now, and why not | every visit | public | yes |
| `balanceOf(holder)` | vault receipts | holder | size of own position | every visit | public | yes |

## Action readiness: five independent gates

**Correction to an earlier draft.** `cviVerifier.isEligible` was presented as the answer to "may I
act". It is not. It answers one of five questions, and a screen that renders it as the answer will
tell a user they are eligible while the transaction reverts.

The five gates are independent, and a readiness verdict must name the one that is failing:

| Gate | Answered by | Failure means |
| --- | --- | --- |
| **Identity / policy** | `cviVerifier.isEligible`, `isValidAPass`, `policy.canTransfer` | the credential is missing, expired, or the token policy refuses this transfer |
| **Role / participant** | `buyer`, `originatorTreasury`, `protectedFacility`, `authorizedOriginator`, `factory.isFacility`, plus the vault's exclusions such as funder ≠ buyer | this address is not the party this action belongs to |
| **Temporal** | `cureDeadline`, `revealDeadline`, `protectionEnd`, `block.timestamp` | the window has not opened, or has closed |
| **Economic** | `balanceOf`, `allowance` on the settlement token | the balance or the approval is short |
| **Protocol precondition** | `protectionState`, `receivableState`, `boundVault`, `MINTER_ROLE`, prior artifacts | the state machine is not at a point where this action exists |

### The readiness vocabulary

Eight verdicts, each mapping to a gate and each carrying what would resolve it:

| Verdict | Gate that produced it | What the screen must also say |
| --- | --- | --- |
| `AVAILABLE NOW` | all pass | which address will sign |
| `AVAILABLE AT <timestamp>` | temporal | the timestamp, and the remaining interval |
| `WRONG ROLE` | role | which role may act, and whether the viewer holds another |
| `CREDENTIAL REQUIRED` | identity / policy | which credential, and whether it is missing or expired |
| `FUNDS REQUIRED` | economic | the shortfall, in the token, and whether it is balance or allowance |
| `PREVIOUS ACTION REQUIRED` | protocol precondition | which action, and who owes it |
| `ALREADY COMPLETED` | protocol precondition | when, and the transaction that did it |
| `RECOVERY REQUIRED` | protocol precondition | what is stranded, and that no automatic recovery will run |

`RECOVERY REQUIRED` is not hypothetical: the M-14 stop matrix lists seven interruption points, two of
them with real exposure, an unrevoked temporary minter and a minted-but-unbound supply.

**Why this replaces "almost every decision is not yet".** That earlier phrasing collapsed five
different refusals into one, and only `AVAILABLE AT` was actually about time. A design built on it
would have produced a single greyed button with a countdown, which is wrong for the other six
verdicts and actively misleading for `WRONG ROLE` and `RECOVERY REQUIRED`.

## Level 2: operational detail

Needed to work the deal, not to decide in the first ten seconds.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| `totalSupply`, `initialUnits` | vault | holder, deal manager | how much of the issue remains outstanding | per action | public | secondary |
| holder allocation table | `Activated` event + balances | holder, deal manager | who carries what | per action | public | secondary |
| `cvaAccounted` | vault | deal manager | units the vault still counts as backed | per action | technical | secondary |
| `adapter.availableBalance` | adapter | deal manager | custody the adapter admits owing | per action | technical | secondary |
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
| `RoleGranted` / `RoleRevoked` on MINV01 | token events | protocol administrator, auditor | that only the adapter can mint | before binding | technical | on demand |
| `assertAccounting()` result | vault view | deal manager | that the vault's own invariants hold | per action | technical | on demand |
| A-Pass validity and expiry | registry + `/query_apass` | deal manager | whether a party can still transact | per action | **sensitive** | on demand |

**One sensitivity flag.** A-Pass records carry a `currentKycHash` and a `magickLink`. The hash is a
compliance artefact and the link is a credential; neither belongs on a shared screen. Everything
else in this table is already public on chain.

## Level 4: technical diagnostic

Needed when something is wrong. This is the **Protocol Operations** surface, used by the protocol
administrator. It is not part of the Deal Workspace or the Participant Deal Room.

| Data | Source | Who | Decision it enables | Consulted | Nature | Main screen |
| --- | --- | --- | --- | --- | --- | --- |
| adapter runtime fingerprint | `getCode` + artifact, immutables masked | protocol administrator | that the deployed contract is the reviewed one | at deployment | technical | no |
| custody cross-links | `token()`, `apass()`, `boundVault()` | protocol administrator | that the wiring matches the manifest | at deployment | technical | no |
| the nine policy tuples | `policy.canTransfer` | protocol administrator | which transfer would be refused, and in which direction | before each phase | technical | no |
| revert selector | failed call data | protocol administrator | why a transaction was refused | on failure | technical | no |
| gas estimate and ceiling | `estimateContractGas` | protocol administrator | whether a cost is abnormal | per transaction | technical | no |
| phase artifact status | M-15 artifacts | protocol administrator | where a ceremony stopped and what may resume | on interruption | technical | no |
| chain id, fork pinning | RPC | protocol administrator | that this is the intended network | always | technical | no |

## Three observations for whoever designs this

**Readiness is the interface, and it has eight shapes.** State alone is not actionable, but neither
is state plus time: five independent gates produce eight verdicts, and each needs a different
resolution path shown next to it. A design that renders a single greyed button with a countdown
handles one verdict out of eight.

**Two figures mean different things and look identical.** `faceValue` is what is owed; `bondLocked`
is what protects the holder if it is not paid. Both are amounts in the same token at the same
decimals. Nothing but labelling and placement distinguishes them, so the typographic system carries
real risk here.

**Level 4 belongs to Protocol Operations, not to the deal screens.** Runtime fingerprints and policy
tuples are how a protocol administrator finds out why a ceremony refused to continue. Different user,
different frequency, different failure modes. Merging them into a deal screen for a sense of rigour
would make the daily screen unreadable and the diagnostic screen incomplete.

## What does not exist

Worth stating so no design invents it:

- no price, no yield, no valuation, no market data;
- no counterparty credit score or rating;
- no portfolio aggregate: every screen so far is one deal;
- no notification or message history;
- no human identity beyond an address and an A-Pass tier.
