# Lattigo exact-policy kill test

This directory is a reproducible, provider-specific cryptographic spike for Mordant's shared
provider-neutral FHE interface. It proves that the selected policy can be evaluated with exact
integer arithmetic and a real 2-of-3 Lattigo threshold key. It does **not** prove a production
client/evaluator trust boundary, correct real-world facts, legal priority, or production safety.

## Pinned implementation

- Package: `github.com/tuneinsight/lattigo/v6`
- Version: `v6.2.0` (pinned in `go.mod`)
- License: Apache-2.0; upstream `LICENSE`
- Toolchain: Go 1.24 or newer (required by Lattigo v6.2.0)
- Scheme: scale-invariant BGV/BFV exact integer arithmetic
- Parameters: Lattigo's N15 example family (`LogN=15`, twelve Q moduli, three P moduli,
  plaintext modulus 65537)

Primary upstream references:

- <https://github.com/tuneinsight/lattigo/tree/v6.2.0>
- <https://github.com/tuneinsight/lattigo/tree/v6.2.0/examples/multiparty/int_pir>
- <https://github.com/tuneinsight/lattigo/blob/v6.2.0/examples/params.go>
- <https://pkg.go.dev/github.com/tuneinsight/lattigo/v6@v6.2.0/multiparty>

The parameter set is taken from an official example and is suitable for this kill test. It is not
an independently audited Mordant production recommendation.

## Reproduce

From this directory:

```bash
go test ./... -count=1
go run ./cmd/workflow
go run ./cmd/workflow | node ../workflow/run.mjs --stdin
go run ./cmd/bench
```

The third command requires Foundry/Anvil and the adapter artifact described in
`../workflow/README.md`. On Apple Silicon, use a native arm64 Go toolchain; the recorded benchmark
did not use the amd64/Rosetta installation present on the test machine.

`cmd/workflow` emits exactly the strict public provider envelope accepted by the shared workflow.
It never emits a plaintext pledge, ciphertext bytes, secret share, raw key, or private fixture. On
failure stdout stays empty and a stable failure code is written to stderr. `cmd/bench` emits only
aggregate sizes, timings and Go heap measurements.

## Implemented policy

The result is true exactly when:

```text
same receivable
AND same currency
AND a.activeFrom < b.activeUntil
AND b.activeFrom < a.activeUntil
AND a.exclusive
AND b.exclusive
AND ingress grant A is valid
AND ingress grant B is valid
```

The two unsigned 64-bit comparisons are strict and evaluated together in SIMD slots. Adjacent
periods therefore do not overlap. Equality for currency and, in full-FHE mode, receivable identity
is exact over all 256 bits. The final circuit has multiplicative depth 10 for the public-link mode
and 11 for full-FHE identity equality.

Authorization is deliberately **not** a client-supplied encrypted Boolean. The original
`GrantIngress` path remains for circuit fixtures. The integrated path uses an Ed25519 issuer whose
signed enrollment binds the exact external ciphertext, active key, policy, input context,
authorization claim, expiry and nonce. Unknown/revoked/expired issuers and enrollment replay fail
closed. The trust registry is runtime-local; a hosted organization identity and revocation source
remain future work.

## Encrypted layout

Each `CipherPledge` envelope contains four ciphertexts in public-link mode and five in full-FHE
mode. Bits are MSB-first.

| Ciphertext | Slots used | Width | Policy V1 use |
| --- | ---: | ---: | --- |
| `PolicyBits` | `0..63` | uint64 | `activeFrom` |
| `PolicyBits` | `64..127` | uint64 | `activeUntil` |
| `PolicyBits` | `128` | 1 bit | `exclusive` |
| `CurrencyBits` | `0..255` | bytes32 | exact equality |
| `AmountBits` | `0..255` | uint256 | encrypted and transported; not evaluated in V1 |
| `ObligationIDBits` | `0..255` | bytes32 | encrypted and transported; not evaluated in V1 |
| `ReceivableIDBits` | `0..255` | bytes32 | optional exact equality in full-FHE mode |

`Uint256` uses four big-endian uint64 limbs and is tested at `2^256-1`. Currency is a complete
bytes32, not a shortened numeric currency code.

The reported encrypted-pledge size covers the complete canonical provider envelope: key label,
parameter fingerprint, public commitments, and every ciphertext listed above. It does not include
the public policy result, threshold traffic, quorum attestation or Monad calldata.

## Confidentiality classification

| Pledge field | Spike treatment | Public residue |
| --- | --- | --- |
| Invoice identity | full-FHE bytes32 **or** salted public link | zero in full-FHE; pseudonymous link in public mode |
| Originator/facility/private position metadata | client-only material represented by a salted metadata commitment | opaque commitment |
| Obligation ID | encrypted bytes32 | ciphertext only |
| Amount | encrypted uint256 | ciphertext size |
| Currency | encrypted bytes32 | equality result only through final decision |
| `activeFrom`, `activeUntil` | encrypted uint64 | overlap result only through final decision |
| `exclusive` | encrypted bit | final decision only |
| Authorization claim/signature | expected at trusted ingress; raw claim/signature not serialized by this spike | scoped authorization commitment |

The metadata commitment must use high-entropy client salt. Reuse permits linkability. The public
receivable-link mode intentionally reveals that two submissions refer to the same pseudonymous
receivable and permits longitudinal linkability if the salt is reused. Full-FHE mode removes this
public link at the cost measured below.

## Canonical public binding

`CipherPledgeDigest` is only `keccak256(canonical provider envelope)`. It is not the shared input
commitment. `CanonicalInputCommitment` implements the exact Solidity ABI definition from
`../shared/canonical-encoding.md` and binds:

```text
chainId, vault, policyId, policyVersion, keyId, inputSlot,
ciphertextDigest, authorizationCommitment,
receivableLinkCommitment, clientNonce
```

The implementation is checked against a Viem-generated reference vector. `ResultCommitment`
likewise matches the shared Viem vector byte-for-byte. The workflow output binds the FHE result to
chain 31337, the test vault, policy V1, both canonical input commitments, responsibility, deadline,
nonce and expiry before the 2-of-3 ECDSA quorum attests it for the Monad adapter.

## Threshold behavior

Setup uses Lattigo's Shamir thresholdizer and collective public, relinearization and Galois key
protocols. Encryption uses the collective public key. The hardened release has two selected
operators independently derive smudged collective key-switch shares toward the zero key; the
coordinator verifies both signatures, aggregates them, and releases only the Boolean. Tests cover
every 2-of-3 coalition and reject one party.

`cmd/threshold-node` imports exactly one operator bundle and serves bounded binary requests behind
TLS 1.3 mutual authentication. Its bbolt ledger fsyncs `COMMITTED` before crypto, `RELEASED` before
bytes leave the node, and requires coordinator persistence before `ACKED`. There is no fallback
coalition after commit. The replay authority is a domain-separated digest of the active key epoch,
closed protocol kind and canonical `c1` bytes actually consumed by Lattigo; changing `c0`, session
or coalition cannot reopen a release.

The provisioning ceremony is still controlled and co-located. Process separation is implemented;
independent organizational custody, distributed DKG, KMS sealing, rotation/recovery and an
availability model are not.

## Ciphertext-origin boundary

`ExternalClient` imports only public parameters and the collective public key and can encrypt in a
separate process. A strict fixed-width signed enrollment replaces the local issuance registry for
that path and binds the serialized ciphertext digest, active key, canonical input context and
authorization claim. Public input commitments are derived from those signed contexts.

This establishes an authenticated gateway boundary, not a proof of correct encryption. A dishonest
authorized issuer can enroll malformed Boolean slots or false source data. A well-formedness proof,
reviewed issuer policy and durable trust/revocation service remain production gates.

## Native arm64 benchmark

Recorded 31 July 2026 on an Apple M1 with 8 GiB RAM (`darwin/arm64`), Go 1.24.0, 8 logical CPU
cores, no GPU path. Each mode used
one complete unmeasured warm-up followed by five measured runs. Median and p95 use the five
measured samples; nearest-rank p95 is the maximum at `n=5`.

### Setup

| Metric | Value |
| --- | ---: |
| Threshold share creation | 63.9 ms |
| Collective public key | 41.4 ms |
| Collective relinearization key | 294.2 ms |
| Collective Galois keys | 1,403.8 ms |
| Total setup | 2,064.7 ms |
| Public key | 7,864,600 bytes |
| Evaluation keys | 314,584,702 bytes |
| Threshold share | 3,932,296 bytes per party |
| Full-FHE identity evaluation-key delta | 0 bytes |

The full-FHE equality reuses rotations already required for bytes32 currency equality, so it adds a
ciphertext but no evaluation-key material.

### Online work

| Metric | Public salted link median / p95 | Full-FHE identity median / p95 |
| --- | ---: | ---: |
| One complete pledge | 25,168,031 B | 31,459,985 B |
| Two pledges + encrypted decision | 56,628,012 B | 69,211,920 B |
| Client encryption, pledge A end-to-end | 325 / 352 ms | 474 / 537 ms |
| Canonical commitment pair | 145 / 157 ms | 189 / 214 ms |
| Two strict uint64 comparisons, batched | 2,679 / 3,198 ms | 2,844 / 3,266 ms |
| One strict comparison, amortized | 1,339 / 1,599 ms | 1,422 / 1,633 ms |
| Currency bytes32 equality | 1,690 / 1,867 ms | 1,810 / 2,135 ms |
| Receivable bytes32 equality | public comparison | 1,754 / 1,787 ms |
| FHE evaluation end-to-end | 5,277 / 6,014 ms | 7,665 / 8,682 ms |
| Final AND | 288 / 313 ms | 441 / 463 ms |
| Threshold decrypt | 39 / 49 ms | 40 / 58 ms |
| Peak Go heap (not process RSS) | 1,031,276,760 B | 1,121,442,536 B |

“Two pledges + encrypted decision” is an FHE-envelope byte count, **not total bandwidth**. It
excludes threshold-share transport because the shares are co-located, and excludes the quorum
attestation and 868-byte adapter calldata measured by the separate workflow. The first recorded
adapter integration measured 158.5 ms from public result to accepted local Anvil transaction; a
final validation rerun measured 63.8 ms and 13.93 seconds wall-clock for the complete CLI process,
including fresh key setup, FHE execution, adapter deployment, quorum signing, acceptance and replay
check. Using median provider
stages, the demonstrated path is about 6.3 seconds in public-link mode and 8.9 seconds in full-FHE
mode, excluding one-time key setup and real network latency.

Both modes are comfortably under the diagnostic targets of 3 seconds per client encryption and
30 seconds evaluation. The complete controlled-local path is also below 60 seconds, but no Monad
network latency was measured. Payload and evaluation-key sizes—not compute latency—are the clearest
operational cost.

## Tested outcomes

- overlap conflict true;
- separated periods false;
- adjacent periods false under strict `<`;
- different complete currency bytes32 false;
- exclusivity false;
- different public receivable link false;
- uint64 maximum boundary true;
- full-FHE receivable identity true and false;
- malformed/truncated ciphertext rejected;
- every ciphertext shape and level validated;
- wrong request key and wrong embedded key rejected;
- ciphertext from a different runtime rejected, including forged metadata in this harness;
- wrong parameter fingerprint and policy version rejected;
- unregistered, expired and revoked ingress rejected;
- evaluation and decryption replay rejected;
- result commitment tampering rejected;
- max uint256 amount serialized and round-tripped.

## Decision represented by this spike

The exact Mordant policy, exact uint64 overlap comparisons, 2-of-3 threshold decryption, canonical
provider-neutral output, quorum authentication and Monad adapter are technically compatible within
the target latency. The hardening pass additionally proves authenticated external enrollment,
process-deployable share services, durable one-shot state and a threshold-evidence commitment
carried into the EVM attestation. Lattigo is therefore a credible independent FHE candidate for the
controlled vertical slice; the circuit itself is not a kill condition.

Production is still **not authorized**. Mordant still needs independent setup custody, a durable
issuer/revocation system, ciphertext well-formedness assurance, transport/RSS measurements,
equivocation operations, key rotation/recovery, audit and an explicit correct-computation assurance
strategy. FHE protects computation over supplied inputs; it does not establish that the underlying
receivable facts are true.
