# Provider-neutral confidential policy attestation lab

This directory is an isolated Foundry experiment. It changes no production Mordant contract and is
not wired into `MordantInvoiceVault`.

The experiment answers one narrow question: can a quorum of currently authorized validators attest
to a confidential policy result without exposing either committed input? It does **not** prove how
the result was computed, decrypt ciphertext, verify a confidential-compute proof, establish an
off-network conflict, or authorize real funds.

## Interface

`ConfidentialPolicyResult` schema 2 is provider-neutral and fixes the EIP-712 field order:

```text
chainId · vault · policyId · policyVersion
inputCommitmentA · inputCommitmentB
conflictConfirmed · responsibleRole · cureDeadline
nonce · validUntil · providerProofCommitment · resultCommitment
```

`resultCommitment` must equal the typed hash of
`ConfidentialPolicyResultCore(...)`, which contains every preceding field including the nonzero
`providerProofCommitment`. The result itself is hashed as `ConfidentialPolicyResult(...)`.
Validators do not sign that hash directly: they sign the EIP-712
`ConfidentialPolicyAttestation(bytes32 validatorSetId,bytes32 resultDigest)` wrapper.

The domain is exactly `Mordant Confidential Policy`, version `2`, and binds the live chain ID and
verifier contract. An attestation is encoded exactly as:

```solidity
abi.encode(bytes32 validatorSetId, bytes[] signatures)
```

The provider-neutral evidence commitment is derived offchain with the contract's
`deriveProviderProofCommitment` helper:

```text
ProviderProofCommitment(
  resultCiphertextCommitment,
  thresholdTranscriptCommitment,
  thresholdSessionId,
  thresholdKeyCommitment,
  policyCircuitCommitment
)
```

The exact hash is `keccak256(abi.encode(PROVIDER_PROOF_COMMITMENT_TYPEHASH, ...))`. This binds the
endorsed result to one ciphertext, threshold transcript, session, threshold key and policy circuit.
The verifier rejects zero commitments and consumes each accepted provider-proof commitment once,
so the same evidence bundle cannot be re-attested for another decision.

Schema 2 is intentionally ABI-breaking: adding `providerProofCommitment` changes the tuple and thus
the `verifyResult` and `acceptResult` selectors. Schema-1 encoders, signatures and deployments are
not compatible. This lab has no production deployment to migrate.

- The required interface is
  `verifyResult(ConfidentialPolicyResult,bytes) external view returns (bool)`; it consumes nothing.
- `acceptResult` performs the same verification, consumes
  `keccak256(abi.encode(chainId, vault, policyId, nonce))`, a canonical decision key and the
  provider-proof commitment, then emits the accepted result and evidence commitment.
- Signatures must be 65-byte, low-`s` ECDSA signatures sorted by ascending recovered signer address.
  Sorting makes duplicate rejection deterministic and keeps quorum verification linear.
- Every validator or quorum mutation rotates `validatorSetId` and increments its epoch. Attestations
  from an older set are rejected even when their signers remain active.
- `conflictConfirmed == false` requires a zero role and deadline; `true` requires both to be nonzero.
- Policy versions only increase. Version `0` disables a policy while retaining its latest version,
  so an older signed policy cannot be resurrected after re-enablement.

## Trust model

The validator quorum is the computation trust boundary. `providerProofCommitment` binds evidence
endorsed by that quorum; it does **not** prove that the FHE circuit was evaluated correctly, that the
ciphertext decrypts to the stated result, or that the committed offchain facts are true. A quorum
can attest to a false result or a falsely constructed evidence commitment. The owner can add and
revoke validators, change the quorum, and select the current policy version for each
`(vault, policyId)` pair. Owner compromise therefore compromises future acceptance. Previously
accepted replay keys remain immutable in this contract even after validator or policy changes.

Replay resistance is local to this verifier contract. It combines:

- EIP-712 domain separation by chain and verifier address;
- an explicit chain ID and vault in the signed result;
- a single current version per vault and policy;
- the exact consumed replay key `keccak256(abi.encode(chainId, vault, policyId, nonce))`;
- a consumed decision key over chain, vault, policy, version and the sorted input-commitment pair,
  preventing a competing nonce or output for the same inputs;
- a globally consumed provider-proof commitment, preventing reuse of one endorsed evidence bundle;
- an inclusive `validUntil` timestamp.

`acceptResult` is permissionless to relay. A caller cannot alter a valid result because every field
is signed. Front-running only publishes the same accepted attestation sooner; it grants the relayer
no policy authority.

## Minimal integration without modifying the vault

1. A policy worker commits the two inputs, evaluates the confidential policy, commits its result
   ciphertext and threshold evidence, then derives the provider-proof and result commitments.
2. Independent validators sign the current-set EIP-712 attestation and an aggregator sorts the
   signatures before ABI-encoding the set ID and signature array.
3. Any relayer calls `verifyResult`, then `acceptResult` on this sidecar.
4. A read-only service can index the accepted event and correlate it with the existing vault.

The current vault does not consume this result, so acceptance has no effect on Mordant accounting or
state transitions. A future audited integration could require an accepted digest through a narrow
adapter before a vault transition, but that is deliberately outside this lab.

## Deliberate lab limits

- Validators are ECDSA EOAs; contract validators and EIP-1271 are not supported.
- Owner changes are immediate: there is no timelock, multisig enforcement, or slashing mechanism.
- The verifier binds `cureDeadline`, role, conflict flag, and commitments but does not judge their
  business semantics.
- The verifier cannot inspect the provider-proof preimage. Validators are responsible for checking
  that its five components use the specified domain-separated construction.
- Replay, decision and provider-proof keys are stored. The full result is reconstructed from the
  event and signed payload, and the production vault does not read it.
- Replay state is local to this verifier deployment; cross-deployment safety comes from the EIP-712
  verifying-contract domain.

## Run

```bash
forge fmt --root fhe-lab/monad-adapter --check
forge test --root fhe-lab/monad-adapter
```

The 26 tests cover the exact schema-2 interface, acceptance and its event, replay and decision
equivocation, provider-proof mutation/zero/cross-session/reuse, commitment component binding,
monotonic policy disable/re-enable, expiry, obsolete validator sets, wrong vault/chain, core
commitment and result semantics, input/result tampering, validator revocation, configurable quorum,
duplicate signatures, and verifier-contract domain separation.
