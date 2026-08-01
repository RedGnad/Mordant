# Lattigo v6.2 maintainer questions

Status: questions for upstream clarification; this file does not attribute answers to
Lattigo that are absent from its source or documentation.

Scope: `github.com/tuneinsight/lattigo/v6 v6.2.0`, module checksum
`h1:HZrksD5u87bOr/4hWHI1Jhps14Tafdvb84Fxmi3dou0=`.

## Context already established from v6.2.0

The v6.2.0 `multiparty` package implements local operations and serialization, not a
network ceremony. Its documented MHE construction is passive-secure; proofs for active
security are not implemented. Public-key and Galois-key generation each have one public
share round, while relinearization-key generation has two public share rounds. The
thresholdizer has one private pairwise Shamir re-sharing round.

Most importantly, v6.2.0 `SECURITY.md` says that generating and transmitting more than
one share for the same public polynomial and secret-key share can enable key recovery,
that the published retry countermeasures are not implemented, and that retrying any MHE
protocol must be considered insecure. Mordant therefore proposes no cryptographic-round
resume: a failed attempt discards all key material and restarts with a new CeremonyID,
new CRS, new local secret keys, and new randomness.

## Questions

1. Does v6.2.0 intend `MarshalBinary` output for `rlwe.PublicKey`,
   `rlwe.RelinearizationKey`, and `rlwe.GaloisKey` to be canonical and byte-identical
   across supported OS/architecture combinations for identical mathematical values, or
   is this only an implementation property within one build target?

2. Is aggregating the same authenticated public contributions in different orders
   expected to produce the same concrete key bytes for `PublicKeyGenProtocol`, both
   `RelinearizationKeyGenProtocol` rounds, and `GaloisKeyGenProtocol`? Are there any
   aliasing or level constraints, beyond those enforced by the APIs, that an independent
   aggregator must observe?

3. Does the retry warning distinguish transport retransmission of the exact same
   serialized, content-addressed share from regeneration of a randomized share? Mordant's
   proposed transport deduplicates identical bytes and never calls `GenShare` again.

4. After an operator has generated a randomized share but crashes before knowing whether
   it was delivered, is abandoning every secret and public value from that attempt and
   starting with entirely fresh secret keys, CRS, and CeremonyID the recommended safe
   response?

5. Must a failed attempt also prohibit reuse of the operator's underlying local additive
   secret key, even when every CRP changes? Mordant proposes the stricter rule: no local
   key or Shamir share survives a failed attempt.

6. After successful `Thresholdizer` aggregation, which inputs are cryptographically
   required later: only the final `ShamirSecretShare`, or also the original additive
   secret key, Shamir polynomial, or recipient evaluations? Mordant proposes retaining
   only the final aggregate share.

7. Does v6.2.0 perform any validity, proof-of-possession, or well-formedness validation of
   received public-key, relinearization-key, Galois-key, or Shamir contributions beyond
   structural deserialization and parameter/level checks? Our source review found no
   active-security proof system.

8. For a coordinator-resistant but passive-operator deployment, is it consistent with
   the intended API for every party to receive all public shares, independently aggregate
   them, serialize the concrete public/evaluation keys, and sign those exact digests?

9. Does Lattigo impose security requirements on how a distributed application creates a
   CRS beyond all parties obtaining the same unpredictable value? Is an authenticated
   commit/reveal by all parties followed by a domain-separated hash an appropriate
   orchestration layer for passive-secure use?

10. Are public-key, relinearization-key, and Galois-key shares safe to publish as the
    README's public authenticated channel model suggests, provided the retry constraint
    is enforced? Are there contribution types that should instead remain confidential?

11. For 2-of-3 operation, should evaluation-key generation use the original additive
    shares from setup or additive shares derived by `Combiner` from the retained Shamir
    shares for a selected active set? Which retry and active-set constraints apply during
    key generation versus later threshold release?

12. Is there an upstream recommended domain separation or transcript format for binding
    serialized multiparty messages to a ceremony, roster, parameters, operation, round,
    and Galois element, or is this entirely application-defined?

13. Is best-effort in-process zeroization followed by process termination the strongest
    claim a Go application should make for discarded Shamir polynomials, evaluations,
    ephemeral relinearization secrets, and local secret keys? Mordant will not claim
    secure physical erasure.

14. Are the countermeasures for safe retries or active-security contribution proofs on a
    published v6 roadmap, and if so, which upstream artifact should be treated as the
    normative compatibility target?

## Evidence needed to close these questions

Maintainer answers must identify the exact version and, where applicable, the source
symbol or security argument. A same-machine probe is useful regression evidence but is
not an upstream portability guarantee. Until answered, Mordant must pin exact binaries,
test concrete-byte agreement on all three evidence hosts, treat mismatches as terminal,
and retain the one-shot rule.

## Primary references

- [Lattigo v6.2.0 multiparty README](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/README.md)
- [Lattigo v6.2.0 security guidance](https://github.com/tuneinsight/lattigo/blob/v6.2.0/SECURITY.md)
- [Lattigo v6.2.0 threshold implementation](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/threshold.go)
- [Lattigo v6.2.0 collective public-key implementation](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/keygen_cpk.go)
- [Lattigo v6.2.0 relinearization-key implementation](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/keygen_relin.go)
- [Lattigo v6.2.0 Galois-key implementation](https://github.com/tuneinsight/lattigo/blob/v6.2.0/multiparty/keygen_gal.go)
- [Multiparty Homomorphic Encryption from Ring-Learning-With-Errors, ePrint 2020/304](https://eprint.iacr.org/2020/304)
- [An Efficient Threshold Access-Structure for RLWE-Based Multiparty Homomorphic Encryption, ePrint 2022/780](https://eprint.iacr.org/2022/780)
