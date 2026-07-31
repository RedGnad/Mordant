# Provider-neutral confidential policy attestation lab

This directory is an isolated Foundry experiment. It changes no production Mordant contract and is
not wired into `MordantInvoiceVault`.

The experiment answers one narrow question: can a quorum of currently authorized validators attest
to a confidential policy result without exposing either committed input? It does **not** prove how
the result was computed, decrypt ciphertext, verify a confidential-compute proof, establish an
off-network conflict, or authorize real funds.

## Interface

`ConfidentialPolicyResult` is provider-neutral and fixes the EIP-712 field order:

```text
chainId · vault · policyId · policyVersion
inputCommitmentA · inputCommitmentB
conflictConfirmed · responsibleRole · cureDeadline
nonce · validUntil · resultCommitment
```

`resultCommitment` must equal the typed hash of
`ConfidentialPolicyResultCore(...)`, which contains every preceding field. The result itself is
hashed as `ConfidentialPolicyResult(...)`. Validators do not sign that hash directly: they sign the
EIP-712 `ConfidentialPolicyAttestation(bytes32 validatorSetId,bytes32 resultDigest)` wrapper.

The domain is exactly `Mordant Confidential Policy`, version `1`, and binds the live chain ID and
verifier contract. An attestation is encoded exactly as:

```solidity
abi.encode(bytes32 validatorSetId, bytes[] signatures)
```

- The required interface is
  `verifyResult(ConfidentialPolicyResult,bytes) external view returns (bool)`; it consumes nothing.
- `acceptResult` performs the same verification, consumes
  `keccak256(abi.encode(chainId, vault, policyId, nonce))` and a canonical decision key, then emits
  the accepted result.
- Signatures must be 65-byte, low-`s` ECDSA signatures sorted by ascending recovered signer address.
  Sorting makes duplicate rejection deterministic and keeps quorum verification linear.
- Every validator or quorum mutation rotates `validatorSetId` and increments its epoch. Attestations
  from an older set are rejected even when their signers remain active.
- `conflictConfirmed == false` requires a zero role and deadline; `true` requires both to be nonzero.
- Policy versions only increase. Version `0` disables a policy while retaining its latest version,
  so an older signed policy cannot be resurrected after re-enablement.

## Trust model

The validator quorum is the computation trust boundary. A quorum can attest to a false result. The
owner can add and revoke validators, change the quorum, and select the current policy version for
each `(vault, policyId)` pair. Owner compromise therefore compromises future acceptance. Previously
accepted replay keys remain immutable in this contract even after validator or policy changes.

Replay resistance is local to this verifier contract. It combines:

- EIP-712 domain separation by chain and verifier address;
- an explicit chain ID and vault in the signed result;
- a single current version per vault and policy;
- the exact consumed replay key `keccak256(abi.encode(chainId, vault, policyId, nonce))`;
- a consumed decision key over chain, vault, policy, version and the sorted input-commitment pair,
  preventing a competing nonce or output for the same inputs;
- an inclusive `validUntil` timestamp.

`acceptResult` is permissionless to relay. A caller cannot alter a valid result because every field
is signed. Front-running only publishes the same accepted attestation sooner; it grants the relayer
no policy authority.

## Minimal integration without modifying the vault

1. A policy worker commits the two inputs, fills the business result, and derives the canonical core
   commitment.
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
  business semantics or check a proof of confidential computation.
- Only the replay key is stored. The full result is reconstructed from the event and signed payload,
  and the production vault does not read it.
- Replay state is local to this verifier deployment; cross-deployment safety comes from the EIP-712
  verifying-contract domain.

## Run

```bash
forge fmt --root fhe-lab/monad-adapter --check
forge test --root fhe-lab/monad-adapter
```

The tests cover the exact interface, acceptance and its event, replay and decision equivocation,
monotonic policy disable/re-enable, expiry, obsolete validator sets, wrong vault/chain, core
commitment and result semantics, input/result tampering, validator revocation, configurable quorum,
duplicate signatures, and verifier-contract domain separation.
