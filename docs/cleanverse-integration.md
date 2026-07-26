# Cleanverse v5.6 integration record

Status: the protected documentation, the UAT API and the deployed Monad testnet contracts have been
inspected. The REST client covers the confirmed building blocks. No state-changing sponsor call or
judged deployment is claimed yet.

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

These are likely UAT deployment/backend defects, not proof of a product limitation. They do mean a
fresh end-to-end Monad issuance cannot honestly be claimed healthy today.

## Why a dependency remains

The dependency is no longer “we do not know whether Cleanverse can issue our asset.” It can. The
remaining dependency is the exact contract binding needed to keep the receivable A-Token inside a
Mordant vault while preserving Cleanverse compliance.

Read-only inspection of the current Monad aUSDC deployment established that it is an upgradeable
AccessControl token with `MINTER_ROLE`, `mint(address,uint256)`, `burn(address,uint256)` and a policy
contract. Read-only simulations established that AccessCore can burn, an arbitrary account cannot,
and both transfers and mints to a destination without A-Pass revert. A transfer between two valid
A-Pass holders succeeds. Therefore Validator registration alone does not make a vault eligible for
custody, and minting the A-Token to it cannot be assumed to work merely because REST launch succeeds.

The v5.6 docs do not publish:

- the Monad Validator contract address and Solidity ABI that an on-chain `ICviVerifier` should call;
- whether `/generate_apass` may bind the verified legal entity to a vault contract address;
- the supported way to exempt or approve a registered Validator pool as A-Token custody;
- whether `burn(address,uint256)` is governed by `MINTER_ROLE` for newly issued standard A-Tokens.

Those four facts determine the real adapter. Guessing them would create a demo that looks live while
silently bypassing the sponsor's compliance model.

## Selected testnet path

The intended path, subject to one disposable proof, is:

1. after the Monad issuance defect is cleared, issue one standard A-Token for one synthetic,
   buyer-accepted invoice;
2. deploy a fresh Mordant factory, vault and minimal sponsor adapter on Monad testnet;
3. register the relevant Ownable Mordant contract as a Validator pool;
4. make the vault an approved A-Token recipient using the sponsor-supported path;
5. grant only the adapter the token permission required to mint the exact invoice supply and burn
   redeemed units;
6. mint exactly 100 invoice A-Tokens into vault-attributable custody;
7. prove CVI for buyer, originator, both facilities and both holders;
8. execute financing, conflicting pledge, 60/40 snapshot, 6/4 reserve claims, and independent 66/44
   invoice redemption;
9. retain every address, transaction hash and read-back assertion.

The path is accepted only if the real policy permits step 4 and the real token permission permits
step 5. Otherwise the Cleanverse integration gate fails; Mordant will not replace either step with a
mock in the judged build.

A superficially simpler non-custodial fallback is not accepted yet. If holders can transfer the
A-Token independently of Mordant's record-date units, the two ownership ledgers can diverge and the
60/40 protection snapshot is no longer trustworthy. Non-custodial custody becomes viable only if a
sponsor policy/hook makes both movements atomic or the A-Token itself becomes the checkpointed
claim token.

## Exact support questions

These questions are sufficient; no broad partnership is required for the hackathon build:

1. On Monad testnet, may an A-Pass be issued to a smart-contract vault controlled by a verified
   legal entity, or should a Validator-registered pool be approved by the A-Token policy another way?
2. Can Cleanverse identify or clear the current `launchAToken` execution reverts and Validator
   `12027` responses on Monad UAT?
3. What are the Monad testnet APass Compliance Validator address and ABI/view function for checking
   `(pool, user)` directly on-chain?
4. On a standard A-Token created by `/atoken/launch`, does `MINTER_ROLE` authorize both
   `mint(address,uint256)` and `burn(address,uint256)`?
5. Should the factory, each invoice vault, or both be registered through `/validator/register`?
6. Is “CCP Protocol” the product name for Validator Compliance, or a separate integration surface?

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
