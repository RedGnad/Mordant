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

Two readings follow from the supply figures. AccessCore holds exactly as much USDC as aUSDC exists,
so **aUSDC is a 1:1 wrapper minted by depositing USDC into AccessCore**. And the rail is currently
idle: no aUSDC has moved in the scanned window, so this transfer will not be lost in noise.

`0x7f7098632b0258Af07e527015D65e6bc743f4CF5` holds 0.5 aUSDC and has no other visible role, which
is consistent with **a transfer fee**. The runner therefore measures that address across the
transfer rather than assuming the recipient receives exactly what the sender paid. At one atomic
unit a percentage fee likely rounds to zero, but that is a prediction, not a basis for a check.

## How to obtain testnet aUSDC

Two routes. The first is one call and is preferred; the second is the fallback and is the one the
supply figures prove is live.

**Route A, direct faucet.** `POST /faucet` with
`{chain: "monad", symbol: "ausdc", depositAddress: <wallet>, amount: <amount>}`, returning
`{chain, symbol, deposit_address, amount, tx_hash}`. The v5.6 documentation records a test-token
faucet for symbols including `usdc` and `ausdc`.

    FAUCET AMOUNT UNIT: NOT PROVEN

The documentation does not state whether `amount` is human or atomic units, nor any rate limit, and
the protected documentation site serves its content from a password-gated API rather than from the
page bundle, so it could not be re-read here. One authorized call resolves it. Ask for the smallest
plausible amount first and read `tx_hash` back on chain.

**Route B, wrap USDC.** Faucet `usdc` to the wallet, then deposit into AccessCore
`0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC` to mint aUSDC 1:1. The 112.14 / 112.14 correspondence
is direct evidence this path is what produced the existing supply. Cleanverse publishes the
withdrawal side of this interface (`withdraw(address aToken, uint256 amount, address recipient)`);
the deposit selector has not been read back and would need confirming before use.

**MON for gas** comes from the official Monad testnet faucet at `testnet.monad.xyz`: 0.5 MON for a
new developer wallet, 10 MON with mainnet-balance eligibility, once per 24 hours. Either amount
covers the ~0.0326 MON this transfer costs, with a wide margin.

## Phase 0: bootstrap, all writes, none authorized

1. **Generate two wallets locally.** Keys go to `.env` only, which is git-ignored. Never printed,
   never committed, never passed on a command line. Roles `HOLDER_A` (sender) and `HOLDER_B`
   (recipient), set as `MORDANT_KEY_HOLDER_A` / `MORDANT_ADDRESS_HOLDER_A` and the B equivalents.
2. **Fund the sender with MON** from `testnet.monad.xyz`. Only the sender pays gas; the recipient
   needs no MON to receive.
3. **Issue an A-Pass to both wallets** with `POST /generate_apass`. This is the step most likely to
   surprise: the M-01C wallets already had A-Passes, so issuance to a fresh wallet is untested by
   us. Verify with `isValidAPass` on chain and `POST /query_apass`.
4. **Obtain aUSDC for the sender** by route A, falling back to route B.

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
6. both hold a valid, unexpired A-Pass, on chain and per `/query_apass`;
7. `/verify_apass` returns code 4 for both, against this exact token;
8. `policy().canTransfer(aUSDC, sender, recipient, 1)` returns `true` for the exact tuple and the
   exact amount that will be sent.

Then funding: the sender holds at least one atomic unit of aUSDC, gas is estimated against real
state, and the sender holds enough MON. The run stops if the estimate exceeds 400,000 gas or the
price exceeds 200 gwei, so an abnormal cost halts rather than silently spends.

**Any mismatch stops the run and sends nothing.** A rail that changed since M-06 must be
re-observed, not transacted against.

## Phase 2: broadcast, requires explicit authorization

    node --env-file=.env scripts/m07-ausdc-transfer.mjs --broadcast

Requires **both** the `--broadcast` flag and `MORDANT_M07_BROADCAST_AUTHORIZED=yes`, so neither a
stray flag nor a stale variable can send a transaction alone. The runner also re-derives the sender
address from its key and refuses if it is not the configured sender.

Order: all Phase 1 gates, then `simulateContract` against current state, then one `transfer`, then
wait for the receipt.

Recorded: balances before and after for sender, recipient and the fee receiver; the transaction
hash, status, block number and hash; gas used, effective gas price and fee paid; every decoded log
with the `Transfer` event identified; and `canTransfer` read again afterwards, because a rail that
stops accepting immediately after a transfer is a finding rather than a detail.

The result is `AUSDC LIVE TRANSFER` only when the receipt succeeded, the sender paid exactly one
atomic unit, and value is conserved across sender, recipient and fee receiver. Otherwise it is
`AUSDC LIVE TRANSFER ATTEMPT`.

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
