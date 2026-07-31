# Bounded Monad testnet FHE acceptance

This runner is a test-assets-only acceptance gate for the existing FHE V2 result
schema. It deploys the laboratory verifier, configures the existing policy, produces
a fresh FHE result and accepts it once on Monad testnet. It does not modify a
Mordant vault, settlement, Cleanverse integration, UI, or `main`.

`--check` is read-only. `--run` sends the three laboratory transactions recorded in
the public artifact: verifier deployment, policy configuration, and one result
acceptance. Replay is checked only with `eth_call`.

## Required test-only configuration

Set these values in an untracked local environment file. Do not commit any key.

```text
FHE_MONAD_RPC_URL=
FHE_MONAD_DEPLOYER_PRIVATE_KEY=
FHE_MONAD_DEPLOYER_ADDRESS=
FHE_MONAD_TEST_VAULT=
FHE_MONAD_VALIDATOR_1_PRIVATE_KEY=
FHE_MONAD_VALIDATOR_2_PRIVATE_KEY=
FHE_MONAD_VALIDATOR_3_PRIVATE_KEY=
```

The deployer must be a dedicated funded Monad-testnet account. The three validators
must be distinct from it and from one another. `FHE_MONAD_TEST_VAULT` is only a
public synthetic anchor; it does not need a deployed vault contract.

## Commands

```bash
pnpm fhe:monad:check
pnpm fhe:monad:run
```

The report intentionally retains only public commitments, public addresses,
transaction/block metadata, gas and timing. It rejects output fields that could
contain private inputs, credentials, private keys, threshold shares or certificates.

Success is limited to:

```text
MONAD TESTNET FHE RESULT ACCEPTANCE: PROVEN
FHE POLICY EXECUTION: QUORUM-AUTHENTICATED
CORRECT-COMPUTATION PUBLIC PROOF: NOT PROVIDED
MORDANT VAULT INTEGRATION: NOT STARTED
PRODUCTION FUNDS: NOT AUTHORIZED
```
