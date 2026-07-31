# FHE boundary hardening pass

This pass turns the first co-located feasibility spike into a **process-deployable controlled
prototype**. It remains isolated from Mordant's product contracts and does not authorize production
funds, automated actions, or claims about the truth of real-world receivable data.

## Implemented path

```text
external client (public key only)
  -> signed ciphertext enrollment
  -> exact BGV policy evaluation
  -> selected 2-of-3 threshold release
  -> transcript + key + circuit commitment
  -> provider-proof commitment
  -> 2-of-3 validator attestation
  -> one-time local EVM acceptance
```

### External ingress

- `ExternalClient` imports only canonical BGV parameters and the collective public key. It receives
  no evaluation key, secret share, issuance registry, or result-decryption state.
- An Ed25519 enrollment issuer signs the exact ciphertext envelope digest, active key and parameter
  fingerprints, policy version, identity mode, input slot/context, authorization claim, expiry, and
  nonce.
- The enrollment has one strict fixed-width binary representation. Truncation, trailing data,
  unknown identity modes, unknown/revoked issuers, invalid signatures, expiry, context mismatch,
  ciphertext substitution, and replay fail closed.
- Public input commitments are derived from the signed contexts rather than an unsigned caller
  duplicate.

The issuer attests that it performed its ingress checks. This is **not** a zero-knowledge proof that
every encrypted slot is a bit or that the source fact is true. Issuer trust and revocation are still
runtime-local in this controlled implementation.

### Threshold release

- The setup harness exports three different operator bundles. Each contains one Shamir share and an
  independent Ed25519 accountability key and must be stored as a separate `0600` secret.
- `cmd/threshold-node` runs one bundle per process behind TLS 1.3 mutual authentication. The
  coordinator is checked both by its client certificate key and by a signature over the exact
  binary operation, descriptor, ciphertext, response digest, and request nonce.
- Payloads use bounded binary encodings; Lattigo objects are never wrapped in JSON or base64.
- The coordinator selects exactly two operators before `PREPARE`. `ReleaseSelectedCoalition` has no
  discovery or fallback input after that selection.
- Every operator keeps a bbolt one-shot ledger:

```text
PREPARED -> COMMITTED -> GENERATED -> RELEASED -> ACKED
```

`COMMITTED` is fsynced before share generation. `RELEASED` is fsynced before response bytes leave
the operator. The coordinator must durably persist both response wires before ACK. A restart at or
after `COMMITTED` terminalizes the session; it never grants a retry.

The global replay key is not the whole ciphertext. Lattigo's collective key-switch share consumes
`c1`, so the key is the domain-separated commitment to:

```text
active key epoch + closed protocol kind + canonical c1 bytes
```

Mutating unused `c0`, changing the session ID, or changing/reordering the coalition therefore cannot
create a second release opportunity.

Example process entry point (one independently provisioned instance per operator):

```bash
go run ./cmd/threshold-node \
  --listen 127.0.0.1:9443 \
  --operator-config /run/secrets/operator-1.bin \
  --ledger /var/lib/mordant-threshold/operator-1.db \
  --tls-cert /run/secrets/operator-1.crt \
  --tls-key /run/secrets/operator-1.key \
  --client-ca /run/secrets/coordinator-ca.crt \
  --coordinator-key /run/secrets/coordinator-ed25519.pub
```

The controlled setup still sees all three shares while provisioning. A production custody claim
requires a distributed DKG, sealed/KMS-backed storage, independently administered hosts, rotation,
backup/recovery rules, and operational review.

### Provider proof and EVM binding

Public result schema 2 contains `providerProofCommitment`. Its preimage commits to:

- the evaluated result ciphertext;
- the signed threshold transcript;
- the one-shot threshold session ID;
- the threshold key/operator-set epoch;
- the exact policy circuit and parameter fingerprint.

The result commitment includes that provider-proof commitment. EIP-712 domain version 2 signs the
result, and the verifier rejects a zero proof, a mutated proof, reuse of a proof in another decision,
or a threshold-session substitution. The adapter emits the proof commitment with the accepted
result.

This proves **which evidence the validator quorum endorsed**. It does not prove that the FHE
evaluator ran honestly. A future correctness layer still requires a reviewed TEE attestation, a ZK
proof, or a concrete verifiable coprocessor network.

## What the reproducible workflow proves

`cmd/workflow` now uses the public-only client, strict signed-enrollment wire round trip, the exact
encrypted policy, two distinct imported threshold operators, signed threshold responses, the real
transcript/key/circuit commitments, and provider-proof schema 1. Piping that public result into the
Node workflow yields a one-time accepted local Anvil receipt and a rejected replay.

The mTLS/durable operator path is covered by its own integration suite, including an unselected
third node, wrong coordinator identity, durable ACK state, and c1-bound replay. The CLI runner and
the network suite share the same descriptor, response, transcript and commitment primitives; the
CLI does not pretend its local operator instances are independent organizations.

## Remaining gates

- no distributed DKG or independent setup custody;
- no hosted/durable issuer registry or organization authorization system;
- no proof of well-formed ciphertext bits and no proof of correct FHE execution;
- no Byzantine/malicious-share proof beyond signed accountable responses;
- no process RSS or wide-area transport benchmark for the hardened service;
- no Monad testnet transaction or Execution Events integration;
- no production vault integration, real assets, funds, or automated action.

The next bounded technical test is a read-only Monad testnet preflight followed by one explicitly
authorized test-assets-only adapter transaction. It must preserve the same schema-2 result and may
not be described as an existing Execution Events integration.
