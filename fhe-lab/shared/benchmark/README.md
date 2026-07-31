# Benchmark output rules

`benchmark-result.schema.json` remains the provider-neutral, per-case interchange schema. Both
implementations must run every policy case and publish that shape without input values.

`benchmark-summary.schema.json` is the normative aggregate shape for the checked-in Lattigo
measurement at `../../lattigo/benchmark/arm64-2026-07-31.json`. It records setup once, then median
and p95 latency, sizes and sampled Go heap use for both identity modes. It does not replace or relax
the per-case interchange contract.

Record cold key generation separately from warm per-case execution. At least five measured runs
after one warm-up are required; retain median and p95 in an implementation report if the raw samples
would reveal no confidential data.

Required targets are diagnostic rather than automatic pass/fail:

- client encryption under 3 seconds;
- evaluation under 30 seconds;
- result-to-Monad under 60 seconds.

`decryptionMs` means complete result decryption (or the slowest threshold share-to-combine path).
`bandwidthBytes` includes both encrypted inputs, evaluator output, decryption shares, attestation,
and Monad calldata. `peakGpuBytes` is `null` when no GPU path exists. Never use a fabricated zero.

Validate the aggregate artifact directly with:

```bash
node fhe-lab/shared/benchmark/validate-benchmark-summary.mjs
```

The aggregate currently reports local Anvil adapter latency, not Monad latency. Its caveats also
state that `fheEnvelopes` omits threshold transport, attestation and calldata, and that its memory
peak is sampled Go `HeapAlloc`, not process RSS.
