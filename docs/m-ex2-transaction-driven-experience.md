# M-EX2 — Transaction-driven living experience

Status: implemented candidate for human review. M-EX1 remains the selected experience direction;
this mission connects those principles to the existing protocol-double execution and does not add a
design-lab route.

## Product entry

The mode is explicit and uses the real product routes:

- Workspace: `/?demo=transactions`
- Participant Deal Room: `/participant?demo=transactions`
- Protocol Operations: `/protocol?demo=transactions`

The Context control on every normal product surface exposes the entry. The same navigation changes
perspective without creating or selecting another deal.

Start the controlled environment with `pnpm localnet`, then start the app. The API refuses to execute
in a production process, on a non-local RPC, or on any chain other than Anvil `31337`. A Vercel build
therefore presents an honest source boundary instead of labeling modeled data as executed.

## Canonical execution

The branch is the existing executable recourse path:

1. approve the 100 dSETTLE advance;
2. activate one invoice vault, paying 90 to the originator and retaining the 10 reserve;
3. distribute the same invoice position 60/40;
4. sign, commit, and reveal Facility B's conflicting exclusive pledge;
5. advance controlled chain time beyond the existing cure deadline;
6. finalize the 6/4 protection entitlement and let both holders claim;
7. fund the independent 110 receivable redemption and redeem 66/44.

The protocol protection duration remains exactly 24 hours. M-EX2 does not shorten it. Only the
controlled Anvil clock advances past the existing one-hour cure deadline so the complete path can be
reviewed without waiting in wall-clock time.

One run retains one deal ID, invoice root, vault, settlement token, and participant set. Reset uses an
Anvil snapshot and creates a new clean execution over those same canonical identities.

## Source and observation model

`.dealroom/m-ex2-run.json` is the runtime execution artifact. It is generated from the deployment and
contract reads, never from a UI fixture. Private keys and contract ABIs remain server-side and are not
serialized into the public run.

For a transaction, the server persists:

- the block-pinned `before` read;
- actor, contract method, and action;
- the broadcast hash while the transaction is pending;
- receipt status, transaction hash, block number, block hash, gas and decoded events;
- the block-pinned `after` read;
- the latest confirmed state as the last safe state.

The conclusion on all three surfaces derives from `current`. It changes only after the corresponding
receipt is retained and its block is read. The EIP-712 signature and controlled time transition are
truthfully labeled as non-transaction operations and are never given fabricated receipts.

If simulation fails before broadcast, the run becomes failed and keeps `before` authoritative. If a
request stops after broadcast, its hash remains pending until a later read observes the real receipt.
A reverted receipt is retained as failed proof. The same canonical action is then the retry target.

## Experience behavior

- Workspace turns the shared state into incident, consequence, responsibility, and deadline.
- Participant Deal Room shows the holder's personal consequence and only offers `claimBond` when the
  contract-derived entitlement exists.
- Protocol Operations orders the same facts as current incident, impact, recovery/last safe state,
  then receipt proof.
- Opening proof replaces the decision composition. It does not stack a diagnostic panel below it.
- The receivable remains the fixed economic anchor; abnormal states displace only protection or
  recovery responsibility; full redemption returns the composition to alignment.

## Retained proof

The first complete run is retained at
`docs/evidence/m-ex2-controlled-run-2026-07-29.json`. It records 12 successful transaction receipts,
one EIP-712 signature, one controlled-time transition, and a continuous move from block 22 to block
35. It contains no private keys.

The automated deal-room E2E test resets the chain, executes the same branch through the product UI,
checks a visible pending hash, checks receipt proof, changes all three perspectives without changing
the deal/root/vault, completes both accounting domains, and resets to the same canonical identity.

## Authorization boundary

```text
M-EX1 PRINCIPLES: SELECTED
CANONICAL DEAL EXECUTION: PROVEN
TRANSACTION-DRIVEN EXPERIENCE: READY FOR HUMAN REVIEW
PRODUCTION CLAIMS: NOT AUTHORIZED
REAL FUNDS: NOT AUTHORIZED
COMMERCIAL PILOT: NOT STARTED
```
