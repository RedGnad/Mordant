# M-07: minimal live aUSDC transfer

    CURRENT STATUS:        PLAN / READ-ONLY PREFLIGHT / NO BROADCAST
    TARGET CLASSIFICATION: AUSDC LIVE TRANSFER
    NEVER:                 MORDANT SETTLEMENT

The smallest possible write proof on the Cleanverse rail: one aUSDC transfer of one atomic unit
between two wallets that both hold a valid A-Pass. Nothing else moves. No vault, no adapter, no
pledge, no invoice A-Token.

M-06 established that the aUSDC policy accepts holder-to-holder transfers again. That is a
precheck answering `true`, which is not the same as value moving. This mission closes exactly that
gap and no more. A successful run may be described as `AUSDC LIVE TRANSFER`. It may never be
described as a Mordant settlement, because no Mordant contract is involved.

Runner: `scripts/m07-ausdc-transfer.mjs`. Read-only by default.

## What blocks this today

**We control no Monad wallet.** `DEPLOYER_PRIVATE_KEY`, `MORDANT_BOUNDARY_OWNER`,
`MORDANT_FACTORY_OWNER` and `CLEANVERSE_APASS_ADDRESS` are all present in `.env` but empty. The
only working credentials are the Cleanverse API ones.

So the critical path is not the token rail, which is open. It is the bootstrap below. Every step of
it is a write, and none is authorized yet.

## Measured facts, 28 July 2026

All read-only, at Monad testnet block 48864474 and later.

| Fact | Value | How |
| --- | --- | --- |
| aUSDC | `0xaC0893567D43C3E7e6e35a72803df05416C1f20D` | rediscovered via `query_deposit_atoken_list` |
| decimals | 6 | `decimals()` |
| one atomic unit | 0.000001 aUSDC | derived |
| aUSDC totalSupply | 112.14 | `totalSupply()` |
| USDC held by AccessCore | 112.14 | `balanceOf(AccessCore)` on USDC |
| USDC totalSupply | 9,227,122,145.7 | `totalSupply()` |
| gas, compliance-checked transfer of 1 unit | 319,513 | `eth_estimateGas` from a real A-Pass holder |
| gas price | 102 gwei | `eth_gasPrice` |
| cost of the transfer | ~0.0326 MON | 319,513 x 102 gwei |
| aUSDC Transfer events, last 4,000 blocks | 0 | `eth_getLogs` |
| USDC deposits into AccessCore, last 6,000 blocks | 0 | `eth_getLogs` |

AccessCore holds exactly as much USDC as aUSDC exists, at the observed block:

    AUSDC CURRENT BACKING CONSISTENCY: OBSERVED 1:1
    AUSDC PUBLIC DEPOSIT PATH: NOT PROVEN

That equality establishes backing consistency at one block. It does **not** establish the mechanism
that produced it: no deposit was observed, no deposit selector has been read back, and an equal
balance is equally consistent with an operator minting and funding both sides. Treating it as proof
of a public deposit path would be an inference dressed as an observation.

The rail is currently idle: no aUSDC moved in the scanned window, so this transfer will not be lost
in noise.

`0x7f7098632b0258Af07e527015D65e6bc743f4CF5` holds 0.5 aUSDC and has no other visible role, which
is consistent with **a transfer fee**. That is a prior, not a fact about this token: the address has
not been shown to be a fee receiver, and there could be several or none. So the runner assumes
nothing about it. It discovers every address the transfer actually touched from the `Transfer`
events, reads each one's balance at the parent block and the receipt block, and reconciles the two.
At one atomic unit a percentage fee likely rounds to zero, but that is a prediction, and predictions
are not the basis of a check.

## How to obtain testnet aUSDC

Route A is the only candidate funding route. Route B is investigation only: its selector and
conditions are unknown, and it is neither authorized nor executable.

**Route A, direct faucet.** `POST /faucet` with
`{chain: "monad", symbol: "ausdc", depositAddress: <wallet>, amount: <amount>}`, returning
`{chain, symbol, deposit_address, amount, tx_hash}`. The v5.6 documentation records a test-token
faucet for symbols including `usdc` and `ausdc`.

    FAUCET AMOUNT UNIT: NOT PROVEN

The documentation does not state whether `amount` is human or atomic units, nor any rate limit, and
the protected documentation site serves its content from a password-gated API rather than from the
page bundle, so it could not be re-read here. One authorized call resolves it. Ask for the smallest
plausible amount first and read `tx_hash` back on chain.

**Route B, wrap USDC. Investigation only.** The open question is whether aUSDC can be obtained by
depositing USDC into AccessCore `0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC`.

    AUSDC PUBLIC DEPOSIT PATH: NOT PROVEN

It is neither authorized nor executable. The deposit selector has not been identified, the deposit
conditions are unknown (whether an A-Pass, an allowance, a minimum or a permissioned caller is
required), and no deposit was observed in the scanned window. Cleanverse publishes only the
withdrawal side of this interface (`withdraw(address aToken, uint256 amount, address recipient)`).
Identifying the selector and the conditions is a research task, and its outcome would be a separate
mission, not a step of this one.

**MON for gas** comes from the official Monad testnet faucet at `testnet.monad.xyz`: 0.5 MON for a
new developer wallet, 10 MON with mainnet-balance eligibility, once per 24 hours. Either amount
covers the ~0.0326 MON this transfer costs, with a wide margin.

## Phase 0: bootstrap, all writes, none authorized

1. **The wallet owner generates two wallets.** The developer never generates, receives, requests or
   handles the keys used for a live run, and no key is ever pasted into a chat, a command line or a
   commit. The owner writes them into `.env`, which is git-ignored, as `MORDANT_KEY_HOLDER_A` and
   `MORDANT_KEY_HOLDER_B`, with the matching public `MORDANT_ADDRESS_HOLDER_A` and
   `MORDANT_ADDRESS_HOLDER_B`. Only the addresses are shared. The runner reads the keys from the
   environment at broadcast time and refuses to sign if the key does not derive the configured
   sender.
2. **Fund the sender with MON** from `testnet.monad.xyz`. Only the sender pays gas; the recipient
   needs no MON to receive.
3. **Issue an A-Pass to both wallets** with `POST /generate_apass`. This is the step most likely to
   surprise: the M-01C wallets already had A-Passes, so issuance to a fresh wallet is untested by
   us. Verify with `isValidAPass` on chain and `POST /query_apass`.
4. **Obtain aUSDC through Route A. If Route A fails or its amount unit remains ambiguous, stop. Do
   not attempt Route B.**

The runner's read-only mode reaches step 1 and stops there today, which is the correct behaviour:
it refuses to continue rather than assuming wallets exist.

## Phase 1: preflight, read-only, runnable now

    node --env-file=.env scripts/m07-ausdc-transfer.mjs --check

Eight fail-closed gates, in order. The first four run before any key is read, so a misconfigured
endpoint can never reach the point where secret material is loaded.

1. chain id is 10143;
2. the aUSDC address is **rediscovered** and matches what M-06 recorded;
3. the aUSDC implementation, the policy address and the policy implementation all match M-06,
   and the token is registered and not paused;
4. `decimals()` is still 6, since the amount arithmetic depends on it;
5. sender and recipient are configured and distinct, because a self-transfer proves nothing;
6. both hold a usable A-Pass. `/query_apass` must return a successful envelope **and** a present
   record **and** an active status **and** an expiration that is present, non-zero and strictly in
   the future, **and** `isValidAPass` must be `true` on chain. An absent expiration is not read as
   unlimited, and a truthy non-boolean does not satisfy the on-chain check;
7. `/verify_apass` returns code 4 for both, against this exact token;
8. `policy().canTransfer(aUSDC, sender, recipient, 1)` returns `true` for the exact tuple and the
   exact amount that will be sent.

Then funding: the sender holds at least one atomic unit of aUSDC, gas is estimated against real
state, and the sender holds enough MON.

Gas is **fail-closed**. An estimate that cannot be produced, a price that cannot be read, a
non-`bigint` or zero value on either, or a computed budget of zero all stop the run. Nothing is
broadcast on a guessed or absent cost. The run also stops above 400,000 gas or 200 gwei, so an
abnormal cost halts rather than silently spends.

**Any mismatch stops the run and sends nothing.** A rail that changed since M-06 must be
re-observed, not transacted against.

## Phase 2: broadcast, requires explicit authorization

    node --env-file=.env scripts/m07-ausdc-transfer.mjs --broadcast --out docs/evidence/<prefix>

Requires **all three** of the `--broadcast` flag, `MORDANT_M07_BROADCAST_AUTHORIZED=yes`, and
`--out`, so neither a stray flag nor a stale variable can send a transaction alone, and a run that
can move value always leaves an artifact. The runner re-derives the sender address from its key and
refuses to sign if it is not the configured sender.

Order: all Phase 1 gates, then `simulateContract` against current state, then one `transfer`.

**The hash is checkpointed atomically the moment `writeContract` returns, with status `PENDING`,
before the receipt is awaited.** From that point the transaction exists whether or not the process
survives, so the artifact must say so. The receipt, readbacks and reconciliation are filled in
afterwards. Any stop, at any point, writes a `STOPPED` artifact recording how far the run got: a
stop after broadcast is classified `AUSDC LIVE TRANSFER ATTEMPT — RECEIPT UNCONFIRMED`, never as
nothing having happened. Every write is a temporary file renamed into place, so a reader never
observes a partial artifact.

Recorded: the transaction hash, status, block number and hash; gas used, effective gas price and fee
paid; every aUSDC `Transfer` event decoded, plus the addresses of any other logs; balances before
and after for **every address the events touched**, read at the parent block and the receipt block;
and `canTransfer` read again afterwards, because a rail that stops accepting immediately after a
transfer is a finding rather than a detail.

**Counterparties are discovered from the events.** No address is assumed to be the fee receiver.
`0x7f7098632b0258Af07e527015D65e6bc743f4CF5` holding 0.5 aUSDC is a prior worth noting, not a
constant to reconcile against, and there may be several such addresses or none. Burns are read as
transfers to the zero address, and an unexpected mint fails reconciliation.

The result is `AUSDC LIVE TRANSFER` only when **all** of the following hold:

- the receipt succeeded;
- at least one aUSDC `Transfer` event was emitted;
- the events debit the sender by exactly the intended amount;
- the events credit the recipient by a strictly positive amount;
- the events balance, so no log was missed;
- and the measured balance delta of every touched address equals what the events say happened to it.

Otherwise the result is `AUSDC LIVE TRANSFER ATTEMPT`, with the failing reasons recorded.

## What this will and will not prove

Proven by a successful run: the deployed aUSDC token accepts a real, policy-checked transfer
between two A-Pass holders, and our credentials can produce such a pair.

Not proven, and not to be claimed: any Mordant settlement path, the CVA rail, the invoice A-Token,
A-Pass issuance to a contract address, or that a vault can hold or move aUSDC. Those depend on the
next mission, below.

## Next dependency for Mordant

The token rail being open does not unblock Mordant. Two things stand between this transfer and a
real settlement, and they are independent, so they can be attempted in parallel.

**1. A-Pass issuance to contract addresses.** Every Mordant settlement path moves aUSDC to or from
a contract: the vault, and the CVA adapter. The policy checks both sides of a transfer, so each
contract needs its own A-Pass. M-01C established that validator registration alone does not confer
custody eligibility, and that the contract needed its own A-Pass in the proof. Issuance to a
contract address through the gateway remains **unobserved live**, and it is the single hardest
dependency: it is the one step where a plausible failure mode (the gateway refusing a non-EOA)
would force a design change rather than a retry.

Test it in isolation, before any full integration: deploy one throwaway contract, request an A-Pass
for it, and read `isValidAPass` back. That is a cheap, decisive experiment.

**2. A dedicated invoice A-Token.** `POST /atoken/launch` with a rule Mordant's own participants
satisfy, then wait for `ISSUED`, then grant `MINTER_ROLE` to the adapter. Unlike aUSDC, this rule is
**ours to choose**, so the M-01C class of failure cannot recur here. The known unknowns are launch
latency and whether the ten-argument launch selector behaves as the factory bytecode suggests.

Ordering: dependency 1 gates the settlement rail and should be attempted first, because a negative
result there changes the architecture. Dependency 2 gates issuance and is lower risk. Neither is
authorized yet, and neither should start before this transfer has actually succeeded: proving the
simplest write first keeps the failure surface small.
