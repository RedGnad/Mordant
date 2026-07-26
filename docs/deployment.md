# Testnet deployment runbook

No address is deployed or claimed during prebuild. The official judged deployment must be fresh and
must use sponsor-confirmed CVI/CVA implementations.

## Factory

Required environment variables:

- `DEPLOYER_PRIVATE_KEY` — ephemeral Monad testnet deployer only;
- `MORDANT_FACTORY_OWNER` — final owner, preferably the judged multisig/test owner;
- `CVI_VERIFIER_ADDRESS` — sponsor-confirmed verifier adapter;
- `CVA_ADAPTER_ADDRESS` — sponsor-confirmed custody adapter for the dedicated invoice A-Token;
- `SETTLEMENT_TOKEN_ADDRESS` — discovered aUSDC address;
- `MONAD_RPC_URL` — explicit RPC endpoint.

Simulate before broadcasting:

```bash
forge script --root contracts script/DeployFactory.s.sol:DeployFactory \
  --rpc-url "${MONAD_RPC_URL}"
```

Broadcast only on Monad testnet or local Anvil after the simulation succeeds:

```bash
forge script --root contracts script/DeployFactory.s.sol:DeployFactory \
  --rpc-url "${MONAD_RPC_URL}" \
  --broadcast
```

The script rejects every chain except Monad testnet (`10143`) and local Anvil (`31337`), contains no
fallback address and transfers factory ownership after allowlisting the two asset boundaries.

## After deployment

1. Save addresses and transaction hashes in a new judged deployment record.
2. Register both participating facilities through the final factory owner.
3. Launch one standard invoice A-Token through the documented Cleanverse issuance flow and wait for
   `ISSUED`.
4. Create the buyer-accepted invoice vault from the buyer wallet and register the sponsor-confirmed
   Ownable target as a Validator pool.
5. Prove that the vault is a policy-approved A-Token recipient before granting the adapter its
   narrowly required mint/burn role.
6. Credit exactly the issued CVA supply to that vault through the sponsor adapter.
7. Execute activation, conflict, 6/4 protection claims and independent 66/44 redemption.
8. Set `NEXT_PUBLIC_MORDANT_VAULT_ADDRESS`; the UI will then read a single-block snapshot and call
   `assertAccounting()` before displaying a live proof.

Never reuse the synthetic mocks or prebuild keys for the judged deployment.
