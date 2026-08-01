# Provenance — private matching V4

Where every part of the private-matching feature on `main` came from, and what it
is and is not evidence of.

## Source commits

| Role | Commit | Tag |
|---|---|---|
| Frozen contract set | `af5baad` | `v4-contracts-af5baad` |
| Runner source | `3ca83ed` | — |
| Evidence source | `dfa8fbe` | `m-priv8-evidence-4` |
| Source branch | `fhe-lab` | preserved unchanged |
| Integration branch | `integration/private-matching-v4` from `main` at `37176bc` | — |

`fhe-lab` is preserved as provenance and is not merged wholesale. The classified
inventory of every differing file is in
[`docs/integration/MERGE-INVENTORY.md`](../integration/MERGE-INVENTORY.md).

## Frozen sources

Sixteen paths are frozen at `af5baad`. Their approved git blob hashes are in
[`frozen-sources-af5baad.txt`](frozen-sources-af5baad.txt), and
`scripts/verify-frozen-sources.mjs` compares every working-tree file against
them. CI runs it on every push and pull request; drift fails the build.

```
e224b0d17cd0397e284b37d8716363eda089bffb  contracts/src/identity/MordantNormalization.sol
3c9dcda8cf80eba6c41d11f8711c3043e8a043a4  contracts/src/identity/MordantAssetIdentity.sol
bdb11e86ada7d67187bf6c71502ec970d13143e2  contracts/src/identity/MordantMatchResult.sol
91c3fff1f0eb1591d2b45c94e3a0152ef277fedf  contracts/src/identity/MordantIssuerRegistry.sol
085b0ceacea37e90431156cf9265f7d51c3b90af  contracts/src/identity/MordantSourceAttestation.sol
dff600a71c4fff704b20e2a9051c59d4de9157d1  contracts/src/identity/MordantSourceIdentityRegistry.sol
a64388007ca0d343332e2dd617baa4805b4e5740  contracts/src/identity/IIdentityAnchor.sol
cfc1f619a6257666cd8c796051a540fe8921e900  contracts/src/MordantInvoiceVault.sol
9523dc215ecceafaa5a532aafcf876c46bb053d5  contracts/src/MordantFactory.sol
4eab090727d9dff97b93396eacb94df3d1a831f2  contracts/src/MordantInvoiceVaultV2.sol
2eea903cf4f9746e5b0aad7ea3528d2b9180767f  contracts/src/MordantFactoryV2.sol
d76999d9631a9632858e02305202a521387aee1c  contracts/src/v4/MordantScopeGovernanceRegistry.sol
385ad4679b90fbcb8d0bc9a13837d8bc3d58f6a0  contracts/src/v4/ECDSAQuorumMatchVerifierV4.sol
b6b68a2996c5a3319f9eff7399390f81071aaab7  contracts/src/v4/PrivateMatchBinder.sol
49e88ba465c54d8e3802636217f70dbe787902ff  contracts/src/v4/IAnchoredReceivable.sol
3f9832f804f1b1792eb26524c232704f3add7bfb  contracts/foundry.toml
```

`contracts/src/MordantInvoiceVault.sol` and `contracts/src/MordantFactory.sol`
are V1 and are byte-identical to `main` before this integration as well as to
`af5baad`. V1 was not modified.

## Integrated blob hashes

Every frozen source arrived on the integration branch byte-identical: the
verifier reports **16/16** on `integration/private-matching-v4`. The remaining
imported files are runtime and tests, which are not frozen. One whitespace-only
change was made outside the frozen set: `fhe-lab/lattigo/ceremony.go` was
`gofmt`-aligned after an earlier field rename left a struct misaligned on
`fhe-lab`. `diff -w` against the `fhe-lab` original is empty.

## Monad chain and transactions

Chain 10143, Monad testnet. Test assets only.

| | |
|---|---|
| Session commitment | `0x868bbacda43e4e009fcfba5fec5ad8593f6010e2dbcdba1e7b3af583a86ac161` |
| Commitment transaction | `0x0255f6bb265f79a0ba947260300b95f9395b776cdbb09bea0d198ca0495e0c9d` (block 49833899) |
| Binding transaction | `0xd12c8daecda1963a8fc79b78b8c3012994d26a2eca8ae3f4b2f032e73f0b0007` (block 49834094, gas 1,175,669, value 0) |
| Anchor (Vault V2) | `0x3046a101CC5cFCc3AEF7537F0E35ee39a33759E6` |
| Scope governance registry | `0x3d550619c4c20Bd70D53B7c93fbAa46c0dCE1512` |
| V4 verifier | `0x02D71361A2A27aa4067cc40A778Bf2ABd626C775` |
| V4 binder | `0x1D152f44Ab215F8aFafA8CDB6317ce505a748233` |

Deployed runtime bytecode was compared against the artifacts compiled from the
frozen tree, blanking exactly the spans named by each artifact's own
`immutableReferences`. **10 of 10 match outside their immutable spans; zero
mismatches.** Per-contract hashes and decoded immutables are in
[`docs/evidence/private-matching-v4/code-hashes.json`](../evidence/private-matching-v4/code-hashes.json).

## Public evidence bundle

[`docs/evidence/private-matching-v4/`](../evidence/private-matching-v4/) — seven
files, curated field by field from the run artifacts rather than copied, so
nothing unselected can arrive by accident:

| File | Contents |
|---|---|
| `transactions.json` | Public transaction hashes, blocks, deployment addresses |
| `events-and-receipts.json` | Commitment and binding receipts with decoded logs |
| `readbacks.json` | Recourse record, anchor state, consumed identities, asset movement, replays, metadata audit |
| `code-hashes.json` | Deployed bytecode hashes and decoded immutables |
| `leak-scan.json` | Leak-scan result, positive controls, manifest digests only |
| `performance.json` | Ceremony, quorum, preflight agreement, timeline |
| `provenance.json` | SHA-256 of each bundle file, source commits, redactions |

The full narrative report is
[`fhe-lab/privacy-v4/evidence/M-PRIV8-REPORT.md`](../../fhe-lab/privacy-v4/evidence/M-PRIV8-REPORT.md).

Redactions applied: local filesystem paths were dropped; private canary
manifests were deleted by the leak scan and only their SHA-256 digests retained;
binding calldata is summarised rather than reproduced.

## What this evidence supports

- Private matching between two mutually authorized submissions, on controlled
  Monad testnet evidence.
- Governed recourse opened only after bilateral disclosure consent.
- The evaluator does not receive the submitted receivable identities or
  commercial terms.

## Known limitations

These are carried verbatim from the M-PRIV8 report and are not softened here.

1. **Organizational independence is not established.** Every process in the run
   was a separate OS process, but all ran on one machine under one operator. The
   separation is architectural, not administrative.
2. **FHE execution correctness is not publicly proven.** That the computation was
   performed, performed correctly and performed after the commitment is attested
   by the validator quorum, which verified on-chain that the commitment existed
   before signing. It is not a public proof.
3. **No traffic-analysis privacy is claimed.** One relayer address published every
   commitment in this deployment, and the number of commitments is public and
   countable. The production target is a multi-relayer authorized pool, which the
   governance registry already models: `authorizedRelayer` is a set, and
   `resolveSession` rejects a relayer that turns out to be a session controller.
   That is deployment configuration, not a contract change. No batching or
   traffic-obfuscation cryptography exists in this system.
4. **Two Vault V2 anchors for one receivable remain correlatable** through their
   public economics. This is a permanent property of the Candidate A shape and
   was accepted as such.
5. **Namespace and normalization-profile agreement between platforms is
   source-attested**, not cryptographically enforced.
6. **Not production ready.** Nothing here is a production deployment, and the
   product flow ships disabled by default.

## Prohibited claims

The following must not be stated anywhere in this repository on the strength of
this evidence: fraud detection; open-book screening; market surveillance; market
completeness; absence of undisclosed pledges; zero knowledge; trustlessness;
public proof of correct FHE execution; private transactions; private settlement;
hidden transaction metadata; independent organizational custody; production
readiness.
