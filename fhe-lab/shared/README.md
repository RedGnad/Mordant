# Mordant confidential-policy shared contract

This directory is the provider-neutral contract for the FHE decision gate. OpenFHE and Lattigo
must consume the same policy, public result, attestation encoding, negative cases, and benchmark
shape. A provider spike does not pass by substituting its own semantics.

This is research code. It does not modify `MordantInvoiceVault`, authorize production funds, or
claim that off-chain facts are true.

## Privacy invariant

Plaintext pledge values may exist only inside the submitting client's process. They must not be
written to calldata, events, artifacts, reports, logs, errors, screenshots, snapshots, benchmark
output, or test fixtures. Test cases in this directory refer to client-runtime profiles; a provider
harness must construct and encrypt those profiles in memory and discard them after the case.

Only these public objects may cross the client boundary:

- an encrypted-input envelope and its commitment;
- a `ConfidentialPolicyResult`;
- an attestation over that result;
- aggregate benchmark measurements and stable error codes.

## Files

- [`field-classification.md`](./field-classification.md) classifies every current `Pledge` field and
  compares the two receivable-identity strategies.
- [`canonical-encoding.md`](./canonical-encoding.md) fixes ABI types, domain separation, commitments,
  EIP-712 digests, replay scope, and role identifiers.
- [`result-schema/`](./result-schema/) contains JSON Schema representations of the public result and
  quorum-attestation envelope. JSON integers are decimal strings; the ABI remains the signing
  authority.
- [`test-vectors/manifest.json`](./test-vectors/manifest.json) is the mandatory cross-provider test
  matrix. It contains no pledge values.
- [`threat-model/README.md`](./threat-model/README.md) states assets, trust boundaries, attacks, and
  explicit non-goals.
- [`benchmark/benchmark-result.schema.json`](./benchmark/benchmark-result.schema.json) is the common
  shape for measurements from both implementations.
- [`scripts/canonical.mjs`](./scripts/canonical.mjs) is the executable reference encoder.
- [`scripts/validate-spec.mjs`](./scripts/validate-spec.mjs) checks schemas, manifest coverage,
  confidentiality guardrails, and the fixed digest vector.

## Run now

From the repository root:

```bash
node fhe-lab/shared/scripts/validate-spec.mjs
```

The command prints only a case count and conformance status. It never prints input material.

## Provider runner contract

Each provider directory must expose a conformance runner with this logical interface:

```text
conformance --manifest fhe-lab/shared/test-vectors/manifest.json \
            --case <case-id|all> \
            --public-output <ephemeral-path>
```

The runner must:

1. resolve each `client-runtime://` profile inside an isolated client process;
2. construct plaintext values only in that process;
3. encrypt before crossing the process boundary;
4. compute `inputCommitmentA/B` from the serialized ciphertext envelopes;
5. evaluate exactly the policy in the manifest;
6. emit only the public result, attestation, stable error code, and aggregate metrics;
7. delete the ephemeral output after the orchestrator has validated it.

An implementation that logs an input to explain a failure fails the gate.

## Adapter acceptance order

The future Monad adapter/verifier should perform the following checks in order, without changing the
production vault during this spike:

1. strict ABI decoding and result-commitment recomputation;
2. `chainId == block.chainid` and explicit vault binding;
3. active `policyId` and `policyVersion`;
4. `validUntil >= block.timestamp`;
5. unused replay key `keccak256(abi.encode(chainId, vault, policyId, nonce))`;
6. active, non-revoked `validatorSetId`, configured quorum, unique ordered validators;
7. EIP-712 attestation digest and signatures;
8. consume the nonce before any external effect;
9. emit only the accepted public result commitment and policy metadata.

The proposed event is:

```solidity
event ConfidentialPolicyResultAccepted(
    bytes32 indexed resultCommitment,
    bytes32 indexed policyId,
    address indexed vault,
    uint32 policyVersion,
    uint256 nonce,
    bool conflictConfirmed
);
```

The result format supports a future 2-of-3 validator quorum. A single key or single signature is
allowed only in a local cryptographic benchmark and must be labelled as such.
