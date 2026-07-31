# Confidential-policy threat model

## Protected assets

- Pledge amounts, exact periods, obligation identifiers, commercial conditions, and unnecessary
  participant identities.
- Integrity and freshness of the policy result accepted on Monad.
- Threshold key shares, validator signing keys, active key/policy/validator-set registries.
- Availability of exception evaluation and the audit trail containing only public commitments.

## Trust boundaries

1. **Client:** sees its own pledge and encrypts it. A compromised client can lie about reality; FHE
   cannot fix that.
2. **Transport/relayer:** sees ciphertext, commitments, sizes, timing, and public results, never
   plaintext.
3. **FHE evaluator:** may be malicious and sees computation metadata. It must not possess enough key
   shares to decrypt inputs.
4. **Threshold decryptors/validators:** jointly reveal and authenticate only the result. A quorum can
   still collude or equivocate.
5. **Monad verifier/adapter:** enforces domain, policy, quorum, expiry, and replay rules; it does not
   verify off-chain facts merely because a result is signed.
6. **Recovery operators:** may reconstruct plaintext only under a separately governed incident
   procedure. This authority is excluded from ordinary evaluation.

## Principal attacks and required controls

| Attack | Control / test |
| --- | --- |
| Ciphertext parsing, malleability, or wrong parameters | Strict provider format/version/parameter/key ID validation before evaluation; malformed and wrong-key vectors must produce no result. |
| Approximate or overflowed date comparison | Exact unsigned integer representation; boundary vector proves adjacent periods are not overlap; provider publishes ranges and parameters. |
| Malicious evaluator returns a chosen Boolean | Evaluator signature alone is not sufficient. Prototype target is threshold-decrypted result plus quorum signatures; future assurance compares TEE, ZK proof, or verifiable coprocessor. |
| Validator collusion or equivocation | Independent operators, 2-of-3 minimum target, set ID binding, unique ordered signatures, equivocation monitoring, revocation and operator accountability. |
| Cross-chain/vault/policy replay | Explicit `chainId`, vault, immutable policy ID/version, EIP-712 verifier domain, result nonce, expiry, and consumed replay key. |
| Old key or policy accepted | Evaluator rejects inactive `keyId`; Monad rejects inactive policy version; mandatory negative vectors cover both. |
| Public commitment dictionary attack | High-entropy secret salt, vault/version scope, no low-entropy derivation, option to use full-FHE equality when linkability is unacceptable. |
| Leakage through logs and benchmark artifacts | Client-only plaintext, stable error codes, aggregate metrics, recursive artifact scan, ephemeral output deletion. No debug dumps in CI. |
| Timing, size, and traffic analysis | Fixed envelope classes/padding should be benchmarked; acknowledge residual timing and submitter-network metadata. |
| Denial of service / evaluator outage | Input size limits, admission control, bounded evaluation, multiple evaluators, and no unsafe automatic state transition on timeout. A failed Lattigo multiparty round is terminal for that cryptographic session: retry means a fresh session with fresh protocol randomness/key material, never reissuing shares for the same public polynomial. |
| Key-share loss | Tested backup/rotation ceremony and recovery policy before production; local single-key mode is never an architecture claim. |

## Authenticity options

- **Single evaluator signature:** useful only to wire the local spike; insufficient because the actor
  choosing the result authenticates itself.
- **Threshold decryptor signatures:** minimum integrated-prototype target. It proves a quorum endorsed
  the bound result, not that the FHE program was executed honestly unless operator procedures or
  verifiable shares supply that assurance.
- **TEE attestation:** can bind a measured evaluator binary and key release, but adds hardware vendor,
  attestation-service, rollback, and side-channel trust.
- **ZK proof:** strongest portable direction for proving computation/transition, but the concrete
  proving system, circuit representation, proof cost, and on-Monad verifier cost remain unproven.
- **Verifiable coprocessor network:** can externalize quorum and availability, but is acceptable only
  with a concrete Monad-compatible network, verification contract, security model, and measured
  costs.

The common envelope deliberately authenticates a provider-neutral result digest. Alternative proof
schemes can be added behind `IConfidentialPolicyVerifier` without changing the result tuple.

## Explicit non-goals

This spike does not prove invoice authenticity, legal priority, absence of undisclosed pledges,
oracle correctness, production safety, or protection of a compromised endpoint. It does not hide
the final conflict Boolean, role, cure deadline, public commitments, transaction timing, gas usage,
or the fact that an evaluation occurred.
