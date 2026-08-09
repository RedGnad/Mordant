# N=3 private conflict graph qualification — 2026-08-09

## Qualified evidence

This qualification covers the bounded synthetic N=3 experiment retained in
[`n3-private-conflict-graph-proof-2026-08-09.json`](./n3-private-conflict-graph-proof-2026-08-09.json).
The envelope uses schema `mordant.n3-private-conflict-graph-evidence/1`, was generated at
`2026-08-09T00:11:46.230Z`, and has canonical evidence digest
`sha256:9151ff402a4e103575523bf06c4021b8ee4cac9b62fd628a32c7dc88eb5a9f1d`.

- Repository and branch: `RedGnad/Mordant`, `experiment/n3-private-conflict-graph`
- Starting/base commit: `9ea6652dbf61c6227e3a21183e628a7356b6df18`
- Execution source commit: `c7ddb004a89627beec248c228125d5a42f6a1fe6`
- Execution source tree: `3df3aa8f0cf31d5a53543a9706be20e6583738b3`
- Source condition: clean committed checkout with the source-commit environment pin matched
- Native condition: five executables freshly built during the proof with CGO disabled, readonly modules,
  trim paths, and VCS stamping disabled; no prepopulated binary root was accepted

## Qualified result

Execution was sequential in order A/B, A/C, B/C on the unchanged single-slot worker, with maximum
observed concurrency 1. Every pair stopped at `RELEASED` and was independently inspected by
`mordant-fhe-inspect`.

| Pair | Governed state | Intent digest | Binding digest | Governed-result digest | Evidence-leaf digest | Inspection-report digest |
| --- | --- | --- | --- | --- | --- | --- |
| A/B | `CONFLICT` | `sha256:37efd2acf19ba13f1935a9c033369f9aabd0b167c5e2edd8916095a92a962c83` | `sha256:19569e318129c34b288eaf1d4fcb11820fc0fb9e284b4aead556b00e6e311e6a` | `sha256:70ea8ec908b8f937276d38b4fe60b08d68ab7a3bc95d0ba9830b2446c7d3cb45` | `sha256:408c1773b32e9c66f20f216b3091573e0ccd6c987020c32aa9305e22fbe777fc` | `sha256:5b26048cfab42349cde2875478321577b30396b07ad1e5a3e2de143eb01fe3e6` |
| A/C | `NO_CONFLICT_UNDER_POLICY` | `sha256:1aa9a0752f29895142f7f8c01fa5175cdbe72f938cdebc5588b37d3167f55fe8` | `sha256:3c4dc057c63fa5f9c40e05177b6e67a4ab98dd475afabdb4eec9b445f4f9c282` | `sha256:7eb457d871d65d56a4afd60a5ff8ac349bbcfcb333dae5ffea9f2f9aa8c1651f` | `sha256:b609fbf07fed59c78ed8420162bd971af2b765a0131e5e87db804e9805190f9a` | `sha256:dc962ad0a85ab1757a048e91b88449547927c5560a2db055dd0b35f50448c0da` |
| B/C | `CONFLICT` | `sha256:0506cc290a4112bf1877b0328226d01ad8ee911006a2503c2460b691253f3581` | `sha256:857a951cbb6af3de883cded4e29220cc59ed120fadbe02e85ce437c948af2cf0` | `sha256:2701e25d0d61dbd1a711c865bf38b777ace38ecdb382c9670024e7e389d446ec` | `sha256:2615f33faf4eafae84ba35c53b956ae54f7a90ecbace172803f1a8bd5edc6784` | `sha256:773946571ca4361be81a1a121209230612adad78e14ac363fb4c4f1d018bb342` |

The aggregate is `COMPLETE` and `REVIEW_READY`; `globalAllClear` is `false`. Its aggregate root is
`sha256:e9d01a7267b2c1518baf734166e053fbdd6c536c463a00ab1daabadbe00817a3`.

## Validation

The retained envelope and all 17 retained-evidence tests passed with:

```sh
pnpm proof:n3-private-conflict-graph:validate
```

This command recompiles the product-test projection, independently validates the retained JSON, and
runs the mutation suite covering canonical body and inspection-report digests, sanitation, session and
pin binding, completeness/all-clear refusal, corrupt-pair isolation, claimant scope, side effects,
retention disclosures, and supported-claim narrowing.

## Privacy, retention, and recourse boundary

- Exact intervals and salts were persisted only in temporary operator-private filesystem roots until
  explicit operator cleanup; they are absent from public evidence and projections.
- The authorization private key was not persisted. Its lifetime is caller-managed process memory until
  references are released. Neither zeroization nor garbage-collection timing is claimed.
- All three pair case roots and all registered temporary root classes were removed after evidence capture
  using ordinary unlink/recursive unlink. This is not secure erasure or proof of forensic deletion.
- Each pair remained at `RELEASED` with recourse state `NOT_OPEN`. Scans found no recourse,
  evidence-export, adapter, cure, or settlement operation or artifact. No settlement executed and no
  tokens moved.
- The aggregate requires policy or human review; conflict edges do not automatically create incidents,
  recourse, cure, or settlement outcomes.

## Unsupported boundary

This qualification does not establish an N-party FHE circuit or ciphertext-reuse design, concurrent
pair throughput, production deployment, horizontal scaling, high availability, arbitrary N, or support
for any receivable beyond the bounded synthetic case. It does not establish automatic incident grouping
or recourse decisions, deploy adapters, move tokens, or exercise settlement. It makes no secure-erasure
claim, and the cleaned native binary bytes are not retained for independent post-cleanup re-hashing.

PASS — N=3 PRIVATE CONFLICT GRAPH PROOF READY FOR REVIEW
