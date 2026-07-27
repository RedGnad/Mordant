# Cleanverse v5.6 integration record

Status: the protected documentation, official public Cleanverse code, the UAT API and the deployed
Monad testnet contracts have been inspected. The REST client covers the confirmed building blocks.
No state-changing sponsor call or judged deployment is claimed yet.

## What is now confirmed

The source of truth is the protected [Cleanverse API v5.6 documentation](https://docs.cleanverse.com/docs/cleanverse),
revised 21 July 2026. The documented UAT base is
`https://uatapi.cleanverse.com/api/cooperate`.

The docs remove three earlier uncertainties:

1. `POST /atoken/launch` issues a new standard A-Token with an admin wallet and an A-Pass rule. Once
   its application reaches `ISSUED`, that admin grants `MINTER_ROLE` to the selected minter.
2. `POST /atoken/register_atoken` can register an existing A-Token after an EIP-191 owner signature
   over lowercase `chain + atoken_address`.
3. A smart-contract address can be registered as an APass Compliance Validator pool. Registration
   uses an EIP-191 signature from the address returned by the pool's on-chain `owner()`.

The API also documents:

- encrypted A-Pass issuance with `POST /generate_apass`;
- A-Pass inspection and A-Token transfer eligibility through `POST /query_apass` and
  `POST /verify_apass`;
- on-chain pool registration and rule mutation through `/validator/*`;
- a test-token faucet for symbols including `usdc` and `ausdc`;
- terminal A-Token application data, including the issued address and transaction hash, through
  `GET /atoken/query_apply_status/{requestId}`.

A read-only UAT call to `POST /query_deposit_atoken_list` with `{"chain":"monad"}` returned business
success (`code = 0000`) and the current standard pair:

- USDC `0x534b2f3A21130d7a60830c2Df862319e593943A3`;
- aUSDC `0xaC0893567D43C3E7e6e35a72803df05416C1f20D`;
- AccessCore `0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC`;
- A-Pass `0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9`.

These are observations, not hard-coded configuration authority. Runtime discovery and explicit
deployment records remain authoritative.

The unauthenticated official `GET /api/skills/query_chain_config` endpoint independently returns the
same Monad chain and contract configuration. Cleanverse's only public GitHub repository also
publishes the AccessCore withdrawal ABI:

```solidity
function withdraw(address aToken, uint256 amount, address recipient) external;
```

That is evidence for the wrapped origin-token/aToken rail (including aUSDC). It is not evidence that
a newly issued, invoice-specific A-Token is backed by AccessCore or should use the same redemption
path.

## Monad UAT health on 27 July 2026

All checks in this section were read-only REST requests or `eth_call` simulations. No A-Pass,
A-Token, faucet transfer, pool registration, role grant or transaction was created.

- The provided API identity has Issue Member access: `GET /atoken/list_my_atokens` succeeds.
- The three most recent visible Monad A-Token launches are `ISSUE_FAILED` with
  `failed to execute launchAToken: execution reverted`; four older Monad applications have remained
  `PENDING` since June.
- A Base A-Token launch visible to the same institution reached `ISSUED` on 27 July. This proves the
  issuance workflow works on Base and makes the current Monad path the leading suspect; sponsor
  confirmation is still required because the requests were not identical controlled experiments.
- `POST /query_apass` fails for multiple existing Monad A-Passes with an ABI length mismatch, while
  `POST /verify_apass` works for the same records.
- `POST /validator/is_register` returns business error `12027` (`returned no data`) for Monad
  addresses, while the same endpoint returns `registered: false` normally on Base.

The launch failure now has a concrete on-chain explanation. The shared factory proxy is
`0xd1ad67ca3b7da5934813f4bd005812ebb3b43ff6`. A successful official Base launch calls selector
`0xeff21872` with ten arguments; the Base implementation
`0x45c365cb6ee32dfc65efc55636273cc329c91fed` contains it. On Monad, the same proxy points to
implementation `0x31759eff15291a5e36bb5625b55c49107dc0ee71`, which lacks that selector and exposes
the older eight-argument `0xef84b94a`. Replaying the successful Base calldata against the Monad
factory with `eth_call` reverts without data. This is strong evidence of a Cleanverse
backend/factory ABI version skew, rather than a Mordant payload error. It still means a fresh
end-to-end Monad issuance cannot honestly be claimed healthy today.

## Contract-custody proof

The earlier assumption that an A-Pass-gated A-Token could not be held by a smart contract was too
conservative. It is not a limitation of the deployed Monad contracts.

Read-only inspection of the current Monad aUSDC deployment established that it is an upgradeable
AccessControl token with `MINTER_ROLE`, `mint(address,uint256)`, `burn(address,uint256)` and a policy
contract. An `eth_call` of A-Pass `issue(...)`, sent from the deployed authorized issuer, completed
successfully when the recipient was AccessCore, a smart-contract address.

The same claim was then tested end to end on a disposable Anvil fork of Monad testnet. No public
state was changed:

1. impersonate the already-authorized public A-Pass issuer;
2. issue an A-Pass to AccessCore on the fork;
3. verify `ownerOf(uint160(AccessCore)) == AccessCore`;
4. verify the aUSDC policy changes from rejecting the recipient to allowing it;
5. mint one unit to AccessCore and burn it again from AccessCore;
6. verify an arbitrary address calling `burn(address,uint256)` reverts with the exact aUSDC
   `MINTER_ROLE` requirement.

This proves that contract A-Pass custody and role-gated mint/burn are technically viable on the
deployed rail. Validator registration alone still does not confer custody eligibility: the contract
needed its own A-Pass in the proof.

A separate live, read-only probe resolved the deployed A-Token's `policy()` and called
`canTransfer(token, adapter, prospectiveHolder, 1)` without submitting a transaction. It confirms
that the policy surface can answer an adapter-to-holder question. The runtime check uses a holder's
complete future mINV position: its allocation at activation, `recipientBalance + amount` on transfer,
and its complete remaining balance before default release. The exact holder-to-holder transfer delta
receives a separate pair check. This observation does not prove stable ABI or universal policy
parity, which must not be claimed.

The model deliberately targets monotone balance caps such as `current CVA balance + amount`. It can
fail conservatively under a max-per-transaction policy because a total-position probe may exceed the
immediate delta. It cannot guarantee future liveness for mutable, history-dependent or non-monotone
policies. The adapter therefore rechecks the actual execution delta and verifies the resulting token
balance changes even after all preflight probes pass.

## Why a dependency remains

The remaining dependency is narrower. We have not performed a live `/generate_apass` write, so the
gateway's willingness to issue an A-Pass to either required contract address (adapter and vault) is
not observed. The documented request accepts a generic wallet address and does not state an EOA-only
restriction, while the deployed contract accepts the operation. This is an operational authorization
blocker for the live rail, not an on-chain feasibility blocker.

The other live blocker is issuance health for the invoice-specific CVA. The current Monad
`/atoken/launch` applications are failing or stale. AccessCore's documented aUSDC withdrawal path
does not replace issuance and lifecycle semantics for a dedicated invoice A-Token. Until Cleanverse
repairs the observed Monad backend/factory version skew and the gateway accepts both contract A-Pass
requests, Mordant must remain synthetic/local and must not describe the CVA/aUSDC rail as live.

The v5.6 docs do not publish:

- the Monad Validator contract address and Solidity ABI that an on-chain `ICviVerifier` should call;
- whether the `/generate_apass` gateway accepts a contract wallet controlled by the verified legal
  entity, despite the deployed A-Pass contract supporting it;
- whether newly issued standard A-Tokens use the same `MINTER_ROLE`-gated burn behavior proven for
  the deployed aUSDC.

Those facts determine the final production adapter. Guessing them would create a demo that looks live while
silently bypassing the sponsor's compliance model.

Validator is no longer a hard dependency for the first Track 1 spine. The deployed A-Pass exposes
`isValidAPass(address)` and returns the expected values for valid and absent records. Mordant now has
a fail-closed `CleanverseAPassVerifier` which combines that live CVI result with explicit
buyer/originator/facility role grants. A prospective holder additionally has to pass the CVA's own
adapter-to-holder `canTransfer` policy check. Holder-to-holder movements also require the underlying
CVA policy to approve that exact sender, recipient and amount, and the vault and adapter are
categorically excluded as holders. Validator/CCP remains an optional richer policy surface until its
Monad address and stable ABI are published.

The only Validator address recoverable from an official documented successful transaction is the
Base Sepolia deployment `0xac7e5179c2c7f03f209136886c172eb34f161792`. It has no code at that
address on Monad. Together with the Monad `12027` API response and its absence from chain config,
this makes Validator/CCP unsafe as an MVP-critical dependency.

The real `CleanverseCvaAdapter` is also implemented against the proven ERC-20 plus
`burn(address,uint256)` surface. It binds the complete supply of one dedicated token irrevocably to
one vault after checking the vault's immutable adapter/token/unit binding, a live adapter A-Pass and
the adapter's `MINTER_ROLE`. It also enforces the same six-decimal unit scale as Mordant receipts and
fails closed if actual custody drops below credited custody. It tracks exact credit, releases CVA
after default and burns CVA on cash redemption. Its unit and full vault integration tests pass
against protocol-shaped doubles. A judged live use remains gated on the launched invoice token
matching that surface.

Base readiness and amount readiness are deliberately separate. `isActivationReady(vault)` verifies
the adapter identity, role, binding, custody, decimals, issued supply and the presence of a policy,
but does not ask whether the complete supply can be burned in one transaction. That would produce a
false negative for a legitimate max-per-transaction rule. During activation, the vault therefore
rejects duplicate holder addresses and calls `isRedemptionReady(vault, allocation)` for each actual
initial allocation. The same exact-position check is used when a holder's cash path must be evaluated.

The vault requires a valid A-Pass for itself as well as the adapter. Activation checks both contract
identities, release/burn readiness and underlying-CVA deliverability for every actual allocation. A
funder without an allocation is checked only for the holder role and A-Pass; the live aUSDC transfer
then applies its own policy to the exact `funder -> vault` movement.

The policy domains remain separate after activation. An mINV transfer retains sender role/A-Pass,
probes adapter-to-recipient delivery for the recipient's complete future position, and checks the
exact holder pair and delta. `releaseDefaultCva` probes the caller's complete remaining mINV balance;
after a partial release, the next call probes the new residual balance. By contrast, `claimBond` and
cash `redeem` check the claimant's holder role/A-Pass and let the actual
aUSDC transfer enforce the settlement policy. Before every outgoing `_transferExact`, Mordant also
queries that policy for the exact token, vault sender, recipient and amount; a false result or revert
fails before the token call. Cash paths do not require CVA deliverability because they do not deliver
CVA. Missing contracts, failed calls, expired credentials and negative applicable policy decisions
all fail closed. This cannot prevent the external token administrator from revoking a role after cash
is accepted, so that sponsor-governance risk remains an explicit production gate.

After default, settlement is evaluated per holder rather than through a shared mode. A caller is
forced to cash only when escrow covers the face value of its complete mINV balance and
`cvaAdapter.isRedemptionReady(vault, holderBalance)` confirms that exact burn, and
`settlement.policy().canTransfer(settlement, vault, holder, holderCashAmount)` approves the exact
payout. Otherwise the caller may receive CVA. This decision affects only that holder: another holder
whose complete-balance burn and exact cash transfer are allowed may still consume existing escrow
through cash `redeem`.

Every CVA payout increments `cvaReleasedFace` by the face value discharged through CVA. The remaining
cash liability is `faceValue - redeemedFace - cvaReleasedFace`; if existing escrow exceeds it, only
the excess becomes buyer `settlementCredit`. `defaultCvaReleaseStarted` is informational and does not
prevent either new redemption funding or cash redemption. After a CVA payout, the buyer can still
fund the exact residual shortfall
`faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow` for the remaining holders. This
preserves mixed CVA/cash settlement without double-paying invoice face value or allowing a prior CVA
payout to disable later funding.

The same pull-credit ledger receives amortized or fully returned bond owed to the originator. Neither
buyer refunds nor originator bond returns are pushed during holder state transitions. An expired
buyer/originator A-Pass can therefore delay only its own `claimSettlementCredit`; it cannot revert a
holder's cash `redeem`, `closeProtection` or `releaseDefaultCva`. The vault includes
`settlementCreditTotal` in its accounting assertion until each beneficiary successfully pulls aUSDC.
Activation net proceeds remain inline and atomic: if the originator cannot receive under the live
aUSDC policy, fund collection, receipt minting and all state changes revert together.

## Selected testnet path

The intended path, subject to one disposable proof, is:

1. after the Monad issuance defect is cleared, launch one standard CVA for one synthetic,
   buyer-accepted invoice and verify its terminal on-chain implementation and policy;
2. deploy the `CleanverseAPassVerifier`, one fresh `CleanverseCvaAdapter`, the factory, and then create
   the invoice vault;
3. issue separate A-Passes to both the adapter and the newly created vault through the documented API;
4. grant only the adapter the token permission required to mint the exact invoice supply and burn
   redeemed units;
5. mint exactly 100 invoice CVAs into adapter custody, bind the adapter irrevocably to that vault,
   and prove the exact supply/credit readback;
6. prove CVI for buyer, originator, both facilities and both unique holders; reject duplicate holder
   entries, prove each complete allocation passes the adapter-to-holder policy, require the funder's
   holder role/A-Pass without a CVA probe, and reject the adapter and vault as holders;
7. pass the complete fail-closed activation readiness check;
8. execute financing, conflicting pledge, 60/40 snapshot, 6/4 reserve claims, and independent 66/44
   invoice redemption; preserve evidence that real aUSDC policy checks, rather than CVA
   deliverability probes, govern funder-to-vault funding and vault-to-holder cash payouts;
9. on an isolated liveness fixture, escrow enough cash for both holders, make holder A's
   complete-balance burn or exact cash payout unavailable, cross into default and let A receive CVA;
   verify `cvaReleasedFace`, credit only the escrow now exceeding remaining cash liability to the
   buyer, then let holder B—whose burn and exact cash payout both pass—redeem from the escrow that
   remains;
10. prove `defaultCvaReleaseStarted` records A's CVA payout without gating either path; if escrow is
    short, let the buyer fund exactly
    `faceValue - redeemedFace - cvaReleasedFace - redemptionEscrow`, then let B redeem cash;
11. prove that expired buyer/originator recipients do not block holder redeem/close/default release,
    then restore eligibility and pull their credits with `claimSettlementCredit`;
12. retain every address, transaction hash and read-back assertion.

The path is accepted only if the live API permits both contract A-Pass issuances in step 3 and the
issued token permission permits step 4. Otherwise the Cleanverse integration gate fails; Mordant will
not replace either step with a mock in the judged build.

A superficially simpler non-custodial fallback is not accepted yet. If holders can transfer the
A-Token independently of Mordant's record-date units, the two ownership ledgers can diverge and the
60/40 protection snapshot is no longer trustworthy. Non-custodial custody becomes viable only if a
sponsor policy/hook makes both movements atomic or the A-Token itself becomes the checkpointed
claim token.

## Remaining questions, if public evidence is exhausted

No outreach is required yet. If the public contracts, API and official repositories cannot answer
these points before the judged integration, the smallest possible support request is:

1. Does the sandbox `/generate_apass` gateway permit separate A-Passes for the adapter and each vault,
   controlled by a verified legal entity? The deployed A-Pass and aUSDC policy accept contract
   addresses in simulation.
2. Can Cleanverse identify or clear the current `launchAToken` execution reverts and Validator
   `12027` responses on Monad UAT?
3. What are the Monad testnet APass Compliance Validator address and ABI/view function for checking
   `(pool, user)` directly on-chain?
4. On a standard A-Token created by `/atoken/launch`, does `MINTER_ROLE` authorize both
   `mint(address,uint256)` and `burn(address,uint256)`, as it does on the deployed aUSDC?
5. Should the factory, each invoice vault, or both be registered through `/validator/register`?
6. Is “CCP Protocol” the umbrella product for pre-transaction rules, Travel Rule data and audit
   reports, with Validator Compliance as one component, or a separate integration surface? The
   public materials do not establish synonymy.

## Implemented API boundary

- encrypted request bodies for documented write endpoints;
- plaintext request bodies for documented read/verification endpoints and the faucet;
- bodyless GET for application status;
- `api-id` and a fresh `X-Request-ID` on every request;
- response-envelope and payload validation;
- server-only credentials and redacted public projections.

AES-CBC with a zero IV exists only because it is Cleanverse's documented wire format. It is not a
general encryption design. The sandbox key delivered by email must be rotated before durable use
because it was pasted into a chat transcript.
