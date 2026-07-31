# Canonical encoding and domain separation

JSON is a transport and review format only. Hashing and signing use the Solidity ABI and EIP-712
definitions below. Implementations must reject out-of-range integers, odd-length hex, uppercase hex,
unknown fields, duplicate signatures, and non-canonical numeric strings before hashing.

## Public result ABI

```solidity
struct ConfidentialPolicyResult {
    uint256 chainId;
    address vault;
    bytes32 policyId;
    uint32 policyVersion;
    bytes32 inputCommitmentA;
    bytes32 inputCommitmentB;
    bool conflictConfirmed;
    bytes32 responsibleRole;
    uint64 cureDeadline;
    uint256 nonce;
    uint64 validUntil;
    bytes32 providerProofCommitment;
    bytes32 resultCommitment;
}
```

`responsibleRole == bytes32(0)` and `cureDeadline == 0` are mandatory when
`conflictConfirmed == false`. Both must be non-zero when it is true. Role identifiers are hashes of
lowercase, versioned labels:

| Role | bytes32 |
| --- | --- |
| none | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| buyer | `keccak256("mordant.role.buyer.v1")` |
| originator | `keccak256("mordant.role.originator.v1")` |
| facility | `keccak256("mordant.role.facility.v1")` |
| holder | `keccak256("mordant.role.holder.v1")` |

Policy V1 assigns the facility role on a confirmed conflict. This does not disclose which facility.

## Input commitment

Provider-specific ciphertext bytes are serialized using the provider’s documented canonical binary
format. The shared layer hashes those bytes and never parses their confidential contents.

```text
ConfidentialPolicyInput(
  uint256 chainId,
  address vault,
  bytes32 policyId,
  uint32 policyVersion,
  bytes32 keyId,
  uint8 inputSlot,
  bytes32 ciphertextDigest,
  bytes32 authorizationCommitment,
  bytes32 receivableLinkCommitment,
  uint256 clientNonce
)
```

```text
inputCommitment = keccak256(
  abi.encode(INPUT_TYPEHASH, chainId, vault, policyId, policyVersion, keyId,
             inputSlot, ciphertextDigest, authorizationCommitment,
             receivableLinkCommitment, clientNonce)
)
```

`inputSlot` is `0` for A and `1` for B. `keyId` is validated at evaluator ingress and is deliberately
not added to the public result; the accepted result binds the already-validated input commitments.
A wrong or retired key ID must fail before evaluation and produce no result.

`authorizationCommitment` is not a client-supplied Boolean. It is the struct hash of an unexpired
claim signed by an issuer in the policy's authorization registry:

```text
ConfidentialSubmitterAuthorization(
  bytes32 subjectCommitment,
  bytes32 role,
  address vault,
  bytes32 policyId,
  uint32 policyVersion,
  bytes32 keyId,
  uint64 validUntil,
  uint256 nonce
)
```

The evaluator verifies the issuer signature and revocation state before evaluation. The claim and
signature stay in the encrypted/private ingress envelope; only their struct hash is bound into the
input commitment. A provider may replace this issuer scheme with a ZK credential only if it produces
the same authorization commitment semantics and passes the unauthorized-submitter vector.

For public salted linking:

```text
receivableLinkCommitment = keccak256(
  abi.encode(
    keccak256("MordantReceivableLink(address vault,uint32 policyVersion,bytes32 invoiceIdentifier,bytes32 salt)"),
    vault,
    policyVersion,
    invoiceIdentifier,
    salt
  )
)
```

The invoice identifier and salt never leave the clients. For full-FHE equality,
`receivableLinkCommitment` is zero and the encrypted identifier is evaluated in the circuit.

## Result commitment

The mandatory provider-proof commitment is:

```text
ProviderProofCommitment(bytes32 resultCiphertextCommitment,bytes32 thresholdTranscriptCommitment,bytes32 thresholdSessionId,bytes32 thresholdKeyCommitment,bytes32 policyCircuitCommitment)
```

```text
providerProofCommitment = keccak256(
  abi.encode(
    PROVIDER_PROOF_COMMITMENT_TYPEHASH,
    resultCiphertextCommitment,
    thresholdTranscriptCommitment,
    thresholdSessionId,
    thresholdKeyCommitment,
    policyCircuitCommitment
  )
)
```

Every component and the final commitment must be non-zero. This binds evidence endorsed by the
validator quorum; it is not by itself a proof of correct FHE computation.

Exact type string:

```text
ConfidentialPolicyResultCore(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)
```

```text
resultCommitment = keccak256(
  abi.encode(
    RESULT_CORE_TYPEHASH,
    chainId,
    vault,
    policyId,
    policyVersion,
    inputCommitmentA,
    inputCommitmentB,
    conflictConfirmed,
    responsibleRole,
    cureDeadline,
    nonce,
    validUntil,
    providerProofCommitment
  )
)
```

## EIP-712 result digest

Domain:

```text
name              = "Mordant Confidential Policy"
version           = "2"
chainId           = result.chainId
verifyingContract = deployed IConfidentialPolicyVerifier adapter
```

Exact result type string:

```text
ConfidentialPolicyResult(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment,bytes32 resultCommitment)
```

The verifier recomputes `resultCommitment`, then computes the EIP-712 digest. The explicit chain ID
and vault are intentionally duplicated inside the signed message: EIP-712 prevents cross-adapter
replay; the fields prevent cross-chain and cross-vault semantic confusion in every representation.

## Quorum attestation digest

Validators do not sign a generic `conflict=true`. They sign:

```text
ConfidentialPolicyAttestation(bytes32 validatorSetId,bytes32 resultDigest)
```

under the same EIP-712 domain. The attestation envelope carries `validatorSetId`, `resultDigest`, the
derived `attestationDigest`, quorum, and signatures. Signatures are sorted by lowercase validator
address in strictly increasing byte order. Duplicate, revoked, unknown, or out-of-order validators
invalidate the entire envelope.

The JSON envelope is for transport. The future Solidity verifier may ABI-encode
`(bytes32 validatorSetId, bytes[] signatures)` because it recomputes both digests and reads quorum
from its active validator-set registry.

## Replay and expiry

- Replay key: `keccak256(abi.encode(chainId, vault, policyId, nonce))`.
- The adapter consumes the replay key before any external effect.
- `validUntil < block.timestamp` is expired; equality is still valid.
- Policy versions are immutable. An inactive version is rejected even under a valid quorum.
- Validator-set rotation does not change a result; it changes which envelope is accepted. Revocation
  policy must state whether already-issued, not-yet-consumed envelopes remain valid.
