# M-12: production adapter and minter path

    CURRENT STATUS:  PLAN / READ-ONLY INSPECTION / NO FORK EXECUTION
    NOT AUTHORIZED:  MINTER_ROLE grant, any mint, any adapter deployment
    MORDANT SETTLEMENT: NOT PROVEN

M-11 issued the invoice A-Token. This plans the path from that token to a Mordant adapter that can
actually hold and burn it. Nothing here has been executed on Monad.

## 1. The production adapter exists

The stop condition was: halt if the repository contains only a mock. It does not.

| | |
| --- | --- |
| production | `contracts/src/cleanverse/CleanverseCvaAdapter.sol`, 258 lines |
| mock | `contracts/src/mocks/MockCvaAdapter.sol`, 70 lines, test-only |
| interface | `contracts/src/interfaces/ICvaAdapter.sol` |
| tests | `contracts/test/CleanverseAdapters.t.sol`, 21 tests, passing |

`MockCvaAdapter` is referenced only from tests. The vault's constructor takes an `ICvaAdapter`
address, so the production adapter is what a real deployment binds.

## 2. What the adapter requires, read from its code

`bindVault` is the gate, and it is strict. It refuses unless **all** of the following hold:

- the adapter has not already been bound (`AlreadyBound`), so binding is one-shot;
- the vault has code, and its `cvaAdapter()`, `cvaToken()` and `initialUnits()` already point back at
  this adapter, this token and this exact unit count;
- `token.decimals() == 6`;
- `apass.isValidAPass(adapter) == true`;
- the adapter holds `MINTER_ROLE` on the token;
- `token.totalSupply() == units` **and** `token.balanceOf(adapter) == units`.

That last line is the one that shapes the whole sequence: **the entire supply must already have been
minted to the adapter before binding**, and no more may exist anywhere else.

### Role semantics, stated precisely

Three separate facts, easy to conflate:

- **`MINTER_ROLE` authorises both mint and burn** at the token level;
- **the adapter uses it only to call `burn`**, having no mint function of its own;
- **`DEFAULT_ADMIN_ROLE` grants and revokes roles. It confers no minting.**

    ADAPTER MINTS: NEVER
    ADAPTER BURNS: YES, GATED BY MINTER_ROLE

Our admin wallet holds `DEFAULT_ADMIN_ROLE` and **not** `MINTER_ROLE`. Verified two ways:
`hasRole(MINTER_ROLE, admin)` is `false`, and a read-only simulation of `mint(probe, 1)` from it
reverts with `AccessControlUnauthorizedAccount` (`0xe2517d3f`).

So the admin cannot mint, and issuance needs its own sequence:

    1. grant MINTER_ROLE to the issuance wallet
    2. mint the exact supply to the adapter
    3. revoke MINTER_ROLE from the issuance wallet

Step 3 is not optional. `bindVault` requires the supply to equal the adapter's balance exactly, and
an open minter could break that invariant after binding.

### Accounting invariants

Every state-changing path re-reads balances and supply and reverts on any discrepancy:

- `consumeOnRedemption`: balance and total supply must each fall by exactly `units`, else
  `AccountingMismatch`;
- `releaseOnDefault`: the adapter's balance must fall by exactly `units` and the holder's rise by
  exactly `units`;
- `availableBalance` reverts rather than under-reporting if the held balance has fallen below the
  recorded credit;
- `custodyCredit` is decremented **before** the external call in both paths, and both are
  `nonReentrant`.

The readiness predicates (`isActivationReady`, `isCashRedemptionReady`, `isRedemptionReady`) wrap
every external call in `try/catch` and return `false` on revert, so a failing dependency degrades to
"not ready" rather than propagating.

## 3. Token surface, verified against MINV01

Read-only on Monad testnet, against `0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b`:

| `ICleanverseAToken` requires | MINV01 answers |
| --- | --- |
| `decimals()` | 6, matching `EXPECTED_DECIMALS` |
| `policy()` | `0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd` |
| `MINTER_ROLE()` | `0x9f2df0fe...56a6`, equal to `keccak256("MINTER_ROLE")` |
| `hasRole`, `getRoleAdmin`, `grantRole`, `revokeRole` | selectors present |
| `mint(address,uint256)`, `burn(address,uint256)` | selectors present |
| implementation | `0xce444680...`, carries bytecode |

`totalSupply()` is currently **0**, and the runner treats anything else as fail-closed: units
already existing somewhere would have to be explained and reconciled before a mint is planned, since
`bindVault` demands the whole supply sit in the adapter.

    INVOICE A-TOKEN SURFACE: MATCHES THE ADAPTER INTERFACE
    INVOICE A-TOKEN SUPPLY: ZERO

## 4. Addresses that will need an A-Pass at tier 50

The policy checks **both sides** of every transfer, so this list is derived from the actual transfer
sites rather than from roles on paper. The invoice A-Token's rule is `min_tier: 50`; aUSDC's rule is
Cleanverse's and is separate.

**On the invoice A-Token (MINV01):**

| Address | Why |
| --- | --- |
| the adapter | holds the whole supply, burns it, and transfers it out on default |
| each holder | receives units through `releaseOnDefault` |

**On aUSDC, the settlement token:**

| Address | Why |
| --- | --- |
| the vault | `_requireSettlementIdentity` demands its own valid identity, and it both receives and pays |
| the funder / buyer | sends the advance into the vault |
| the originator treasury | receives net proceeds and returned bond |
| each holder | receives redemption, credit pulls and cash settlement |

The roster is resolved from the environment and **deduplicated by address**, since one wallet may
fill several slots and a single A-Pass should not be counted, or requested, twice.

`HOLDER_A` and `HOLDER_B` already hold an A-Pass from earlier missions and are **not** new
requirements. The adapter, vault, buyer and originator treasury are: each must be issued and read
back individually, and nothing about the existing three generalises to them.

### The exact tuples the policy will be asked about

| Token | From | To |
| --- | --- | --- |
| MINV01 | zero address | adapter (mint) |
| MINV01 | adapter | zero address (burn) |
| MINV01 | adapter | HOLDER_A, HOLDER_B (default release) |
| aUSDC | buyer | vault (advance in) |
| aUSDC | vault | originator treasury (net proceeds) |
| aUSDC | vault | HOLDER_A, HOLDER_B (settlement) |
| aUSDC | vault | buyer (cash redemption) |

Note the ordering trap: the adapter's address is only known after deployment, and its A-Pass must
exist before `bindVault`, which itself must run before any vault activation.

## 5. Prepared runners, none executed

`scripts/m12-adapter-path.mjs`, three read-only modes. Each refuses to write and prints what it
would do.

    pnpm m12:inspect    adapter source, interface conformance, token surface, supply
    pnpm m12:apass      the A-Pass roster, with current status per address
    pnpm m12:grant      the MINTER_ROLE grant, described as calldata, not executed

The grant mode emits target, function signature, arguments and calldata, and never a command line
carrying a key, for the reason established in M-10. **Calldata is withheld entirely** unless the
configured adapter address passes every precondition: code present, `token()` equal to MINV01,
`apass()` equal to the A-Pass registry, the expected `owner()`, and `boundVault()` still the zero
address. Granting mint and burn authority to an unverified or already bound adapter is exactly what
that check exists to prevent.

## 6. The sequence, once authorised

Not authorised yet. Recorded so the ordering constraints are explicit:

1. deploy `CleanverseCvaAdapter(owner, MINV01, apass)`;
2. issue an A-Pass to the adapter address and read it back;
3. grant `MINTER_ROLE` to the adapter from the admin wallet, for its burn path;
4. issue the supply through the grant/mint/revoke sequence above, since the admin cannot mint;
5. deploy the vault configured with this adapter, token and unit count;
6. issue A-Passes to the vault, funder, originator treasury and each holder;
7. `bindVault(vault, units)`;
8. only then, activation.

**Only `bindVault` is contractually one-shot** (`AlreadyBound`). The other steps are not uniformly
irreversible and should not be described as such: a deployment can be replaced by deploying again, a
role can be revoked, and an A-Pass can be reissued. What is genuinely awkward is a mis-minted supply,
since `bindVault` compares it exactly and burning back requires `MINTER_ROLE`, which step 3 removes.
Each step should still be proved on a fork first.

## 7. What stays unproven

    MINTER ROLE: NOT GRANTED
    MINT/BURN VIA MORDANT ADAPTER: NOT PROVEN
    MORDANT SETTLEMENT: NOT PROVEN

Reading that the adapter's code demands `MINTER_ROLE`, and that the admin could grant it, is not the
same as having granted it, minted, burned or settled anything.
