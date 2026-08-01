# V5 schema freeze

Frozen after the four release-protocol gates passed. These hashes are what
off-chain producers, the verifier, the binder and every archived signature all
depend on. Changing one silently invalidates evidence that was already produced,
so a change here is a versioned schema change, never an edit.

Verified by `scripts/verify-v5-typehashes.mjs`, which reads the type strings out
of the Solidity sources and rehashes them, so a field added, removed or
reordered fails the gate rather than drifting.

## EIP-712 types

| Type | Source | keccak256 of the type string |
|---|---|---|
| `ConfidentialMatchResultV5Core` | `contracts/src/v5/MordantResultCoreV5.sol` | `0x3428619310f11cb249a9c673fbcee9eeb9cfed9f2c515ff2a8cdfb1fee0a4bf5` |
| `ConfidentialMatchAttestationV5` | `contracts/src/v5/MordantMatchVerifierV5.sol` | `0x8ef0fc17e2de7e62e4ec12daed5f608451fde3bf304eaaa3133354222cb05361` |
| `DisclosureConsentV5` | `contracts/src/v5/PrivateMatchBinderV5.sol` | `0xcf8cd9a622d5692702a48f51306c1681b66caae31a75943b9f2bb681296c70a5` |
| `BilateralSessionIntentV5` | `contracts/src/v5/MordantScopeGovernanceRegistryV5.sol` | `0x46b6113037776856ab1103a6b21ce3fa94d39940bddd0f59b0f3c4ea69cb898d` |

### EIP-712 domains

| Contract | name | version |
|---|---|---|
| `MordantMatchVerifierV5` | `Mordant Confidential Match` | `5` |
| `PrivateMatchBinderV5` | `Mordant Private Match Binder` | `5` |
| `MordantScopeGovernanceRegistryV5` | `Mordant Bilateral Session Intent` | `2` |

The verifier's domain version moved from `4` to `5`, so a V4 attestation hashes
to a different digest and can never verify against V5 even before the schema
check runs.

## Result-core field order

Normative. It is the EIP-712 field order, the commitment preimage order and the
order every off-chain producer must use.

```
schemaVersion, chainId, verifier, binder, policyId, policyVersion,
sessionCommitment, sessionNullifier, governanceContext,
sourceRecordCommitmentA, sourceRecordCommitmentB,
enrollmentDigestA, enrollmentDigestB,
ciphertextDigestA, ciphertextDigestB,
inputCommitmentA, inputCommitmentB,
sameEconomicAsset, policyConflict, outcome,
outputCiphertextCommitment, circuitHash, circuitVersion, releaseLayoutVersion,
parameterFingerprint, evaluationKeyEpoch, evaluationKeyDigest,
runtimeFingerprint, providerProofCommitment,
nonce, expiry
```

The result commitment is `keccak256(abi.encode(COMMITMENT_DOMAIN, structHash))`
with `COMMITMENT_DOMAIN = keccak256("mordant.result-core-commitment/5")`. It is
deliberately a different preimage from the EIP-712 struct hash, so a signature
over one can never be replayed as the other.

## Outcome encoding

| `sameEconomicAsset` | `policyConflict` | `outcome` | enum |
|---|---|---|---|
| false | false | 1 | `DifferentAsset` |
| true | false | 2 | `SameAssetNoPolicyConflict` |
| true | true | 3 | `SameAssetPolicyConflict` |
| false | true | - | invalid, reverts at every boundary |

`0` is `None` and `4` is `NotComparable`. Only `SameAssetPolicyConflict` may open
a recourse record.

## Off-chain transcript schemas (Go)

| Schema | Domain string |
|---|---|
| Session binding | `MordantSessionBinding/v5` |
| Ciphertext enrollment | `MordantCiphertextEnrollment/v5` |
| Release descriptor | `MordantReleaseDescriptor/v5` |
| Release transcript | `mordant.release-transcript/v5` |
| Circuit inputs | `mordant.circuit-v5-input/1` |
| Circuit outputs | `mordant.circuit-v5-output/1` |
| Circuit side digest | `mordant.circuit-v5-side/1` |
| Release slot id | `mordant.release-slot/1` |
| Runtime fingerprint | `MordantRuntimeFingerprint/v5` |
| Evaluation key digest | `mordant.evaluation-key-digest/1` |
| Circuit structure | `mordant.circuit-v5-structure/1` |

Verifier-side identity domains: `mordant.v5-replay-key/1`,
`mordant.v5-decision-key/1`, `mordant.v5-recomputation-context/1`.

## Pinned versions

| Constant | Value | Where |
|---|---|---|
| Result schema | 5 | `MordantResultCoreV5.RESULT_SCHEMA_VERSION` |
| Circuit | 5 | `CircuitV5Version` / `Core.CIRCUIT_VERSION` |
| Release layout | 1 | `ReleaseLayoutVersion` / `Core.RELEASE_LAYOUT_VERSION` |
| Serialization | 1 | `SerializationVersion` |
| Enrollment schema | 5 | `EnrollmentV5Version` |
| Lattigo | `v6.2.0` | `lattigoPinnedVersion`, asserted against `go.mod` |

## Runtime compatibility

The runtime fingerprint covers the Lattigo version, the Go version, GOOS/GOARCH,
the FHE parameters, the circuit build hash, the serialization version, the
evaluation-key digest and epoch, and the release layout.

Each operator derives it **locally** from its own build and its own loaded keys.
A coordinator may not supply executable code, a circuit binary, parameters or a
claimed fingerprint as an authority; the descriptor's claimed fingerprint is
compared against the operator's own and refused on mismatch.

A dependency or runtime upgrade changes the fingerprint and therefore requires a
new approved runtime version or key epoch. Builds are never silently mixed: two
operators on different builds are refused rather than reconciled, because a byte
comparison across builds is not a comparison.
