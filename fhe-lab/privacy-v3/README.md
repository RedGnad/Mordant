# V3 privacy-claim laboratory gate

V3 is parallel to the historical V2 verifier and result format. It binds `consumer` into the
result core, commitment, EIP-712 digest, replay identity and decision identity. Its evaluator
output is limited to a Boolean and public commitments; responsibility, deadline and consequence
are derived by `LaboratoryRecourseConsumer` from immutable on-chain configuration.

The consumer is deliberately non-economic: it cannot transfer tokens, reserves, receivables,
redemption amounts, claims or settlement funds.

## What is implemented

```text
fresh FHE result V3
  -> 2-of-3 EIP-712 quorum attestation
  -> consumer-bound verifier acceptance
  -> atomic laboratory recourse record
  -> public commitments and bounded metadata only
```

`V3LaboratoryRecourse.t.sol` covers the atomic transition and rejections for direct verifier
bypass, wrong consumer/vault/policy/version, false results, expiry, result/proof mutation,
one/duplicate validator signatures, replay nonce, reused decision and reused proof.

## Gate deliberately not claimed

This directory does **not** yet demonstrate the final independently launched Client A, Client B,
evaluator and three-node mTLS session in one captured run. Nor can it make the required Monad V3
transaction without the dedicated testnet deployer and validators. Therefore no product privacy
claim is authorized by this code alone.

Run the public-output scanner only against a generated evidence directory:

```bash
node fhe-lab/privacy-v3/leak-scan.mjs path/to/evidence
```
# Process-separated evidence

`process-run.mjs` is the controlled laboratory capture used by the V3 Monad
runner. It launches six application processes: Client A, Client B, evaluator /
coordinator, and three separate mTLS threshold nodes. Only nodes 1 and 2 are
selected; node 3 is authenticated through its status endpoint and records no
threshold session. The parent orchestrates paths and lifecycles only. It never
opens either client-private canary manifest.

After termination, the offline audit scans all public files against the client
canaries and deletes the private manifests. The resulting classification is
`PROCESS-SEPARATED CONTROLLED LAB`, not independent organizational custody.

Run the public testnet preflight with `pnpm fhe:privacy:check`. The write path
is `pnpm fhe:privacy:run`; it deploys only V3 laboratory contracts and opens a
non-economic recourse record when all gates pass.
