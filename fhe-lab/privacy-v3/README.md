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

## Gate status

The gate is met on Monad testnet under controlled laboratory conditions. One fresh six-process
capture (Client A, Client B, evaluator/coordinator, three mTLS threshold nodes) fed one atomic V3
recourse transaction:

```text
transaction  0x038d075412a031591e53d5a8d598563e5a0882b840a665af0b460809347ea023
block        49715282
verifier     0x7F1271D43B0E41e2eeDDD5290f459fDc6196a19a
consumer     0xB23A3C3492B9BA83D80C8abc9A5484d2885f058A
```

Retained evidence is in `fhe-lab/monad-testnet/artifacts/`: the run report, the crash-safe journal
and the process capture's public text evidence. The transaction moved no token or asset.

### What this does not establish

- no public proof of correct FHE execution; the quorum authenticates who endorsed the result;
- no source truth for the underlying commercial facts;
- transaction metadata (addresses, timing, sizes, gas, the Boolean outcome) stays public;
- no private settlement and no anonymity;
- controlled laboratory custody, not independently administered operators;
- no production authorization.

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
