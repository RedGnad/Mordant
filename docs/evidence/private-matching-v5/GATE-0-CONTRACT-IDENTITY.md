# Gate 0: contract identity compatibility

## Classification: CONTRACT IDENTITY SUPPORTED

The Vault V2 rehearsal discovered that every settlement transfer calls
`cviVerifier.hasValidIdentity(address(vault))`, and that `activate` reverts
`SettlementNotReady()` without it. The question was whether the vault, being a
contract, can hold that identity on the real rail or whether the rehearsal had
leaned on behaviour only `MockEligibility` offers.

**It is not mock-only behaviour, and it is not inconclusive.** The question was
settled against the live deployment in an earlier mission.

## The production path, read from source

`CleanverseAPassVerifier` is the real `ICviVerifier` implementation:

```solidity
function _hasValidIdentity(address account) private view returns (bool) {
    if (account == address(0)) return false;
    try apass.isValidAPass(account) returns (bool valid) { return valid; }
    catch { return false; }
}
```

There is **no contract/EOA distinction anywhere in the path**. Validity is a
property of the address in the A-Pass registry, so a vault that holds its own
A-Pass satisfies `hasValidIdentity` by exactly the same route an EOA does.

Corroborating: `CleanverseCvaAdapter._hasValidAPass()` calls
`apass.isValidAPass(address(this))` — a contract checking its **own** A-Pass.
The production design already assumes contracts hold A-Passes.

## Live evidence

`CleanverseAPassProbe` exists solely to answer this, deliberately against a
disposable address rather than a vault. Recorded in
`docs/cleanverse-integration.md` and
`docs/evidence/monad-contract-apass-2026-07-28.json`:

| Claim | Status |
|---|---|
| `CONTRACT APASS` | **PROVEN** |
| `CONTRACT APASS POLICY — RECEIVE` | PASSED |
| `CONTRACT APASS POLICY — SEND` | PASSED |
| `CONTRACT AUSDC CUSTODY ROUND-TRIP` | **PROVEN** |

Monad testnet, chain 10143, pinned block 48889095. Baseline showed 0 of 5 known
contracts held an A-Pass before issuance; the probe
`0x0f8b9a0c064306f938912658c96c681d8655140b` held one after. The custody round
trip closed at blocks 48897630 and 48897632, one `Transfer` per leg, probe ends
empty.

## What `setIdentityValid` stands in for

`MockEligibility.setIdentityValid(vault, true)` in the rehearsal is the local
equivalent of **issuing an A-Pass to the vault address** through the authorized
Cleanverse issuer. That operation is proven on the live rail, so the rehearsal
is exercising a production-compatible path rather than a mock convenience.

## Limits, stated rather than glossed

The integration document is explicit that the proof is **not generalised**, and
that wording is kept here rather than softened:

> The issuance route tested did not reject the address for being a contract.
> That is the whole of the observation... one route, one call shape, one
> address, one moment. It does not establish that every issuance route accepts
> contracts, nor that this one always will.

Three further limits:

1. **Validator registration is not enough.** Registering a contract as an APass
   Compliance Validator pool does not confer custody eligibility. The contract
   needed its **own** A-Pass in the proof.
2. **The A-Pass expires 28 July 2027.** Anything depending on it needs a renewal
   path.
3. **`MINTER ROLE: NOT GRANTED`** and **`MINT/BURN VIA MORDANT ADAPTER: NOT
   PROVEN`** remain open in the integration status. Neither is on the V5
   admission path, but neither is closed.

## Operational dependency this creates for Phase B

The live V5 run creates a **fresh** vault at a CREATE2 address that does not
exist yet. Activation moves the settlement advance, so that address will need an
A-Pass issued to it by the authorized Cleanverse issuer **between vault creation
and activation**.

That is an external operation the runner cannot perform: it has no issuer
authority on the A-Pass contract. Phase B therefore needs either

- an out-of-band issuance step between `VAULT_CREATED` and activation, with the
  runner blocking until `hasValidIdentity(vault)` reads true; or
- a Monad deployment configured with an eligibility contract the deployment
  itself controls, in which case the run proves the V5 protocol but not the
  Cleanverse settlement integration, and must say so.

This is recorded now rather than discovered at activation time on a funded run.

## Verdict

**CONTRACT IDENTITY SUPPORTED.** No owner decision is required to proceed with
Groups 3 and 4. The Phase B issuance dependency above is a sequencing
requirement, not a blocker for local work.
