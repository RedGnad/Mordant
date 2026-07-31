# Canonical economic-asset identity, scheme version 1

Normative specification. The Solidity library `MordantAssetIdentity.sol` and the JavaScript
reference `fhe-lab/shared/identity/asset-identity.mjs` are both bound by this document, and the
vectors below are asserted in both.

## Why this exists

Two platforms that never communicate must derive the *same* 256-bit identity for the same invoice,
from facts each already holds, without ever exchanging it. Every rule here exists to make that
convergence exact. A disagreement produces a **false negative**, which is the dangerous direction:
a real double-financing silently goes undetected.

## Identity fields

| Field | Type | Nullable | Normalization |
|---|---|---|---|
| `debtorNamespace` | string | no | lowercase ASCII letters only |
| `debtorId` | string | no | uppercase alphanumeric ASCII only |
| `sellerNamespace` | string | no | lowercase ASCII letters only |
| `sellerId` | string | no | uppercase alphanumeric ASCII only |
| `invoiceNumber` | string | no | uppercase alphanumeric ASCII only |
| `currencyCode` | bytes3 | no | ISO 4217 alpha-3, uppercase |
| `amountMinor` | uint256 | no | integer minor units, never a float |
| `amountExponent` | uint8 | no (may be 0) | minor units per major unit |
| `issueDateDays` | uint32 | no | days since 1970-01-01 UTC |
| `dueDateDays` | uint32 | **yes**, `0` | days since 1970-01-01 UTC |

`dueDateDays` is the only nullable field. Every other zero is rejected, because a silently absent
field would let two different invoices converge.

### Namespaces

A registry, not free text: `lei`, `duns`, `vat`, `gln`, `eth`. The namespace is part of the identity,
so the same digits under `duns` and under `vat` are different parties. Adding a namespace does not
require a scheme bump; removing or re-meaning one does.

### Normalization rationale

`INV-2026/0042`, `inv 2026 0042` and `INV20260042` are the same invoice on three platforms. Dropping
every non-alphanumeric byte and uppercasing makes them converge. The cost is deliberate: two invoices
that differ *only* by punctuation are treated as one asset. That is the correct trade for receivables,
where separator conventions are platform-specific and invoice numbers are not.

Amounts never pass through floating point. `1234.56 USD` is `amountMinor = 123456, amountExponent = 2`.
`1250000 JPY` is `amountMinor = 1250000, amountExponent = 0`.

## Canonical encoding

Dynamic fields are pre-hashed and the whole tuple is `abi.encode`d, exactly as EIP-712 does. No field
boundary is ambiguous, and no two distinct identities can share an encoding through concatenation.

```text
assetId = keccak256(abi.encode(
    keccak256("mordant.canonical-asset-identity/1"),
    uint16 schemeVersion,
    keccak256(normalizedDebtorNamespace),
    keccak256(normalizedDebtorId),
    keccak256(normalizedSellerNamespace),
    keccak256(normalizedSellerId),
    keccak256(normalizedInvoiceNumber),
    bytes3 currencyCode,
    uint256 amountMinor,
    uint8   amountExponent,
    uint32  issueDateDays,
    uint32  dueDateDays
))
```

## Commitment and salt

```text
assetCommitment = keccak256(abi.encode(
    keccak256("mordant.asset-commitment/1"),
    uint16 schemeVersion, uint32 identityEpoch, bytes32 assetId, bytes32 salt))

salt = keccak256(abi.encode(
    keccak256("mordant.asset-salt/1"),
    bytes32 issuerMasterSecret, bytes32 assetId, uint32 identityEpoch, uint256 anchorNonce))
```

The salt is high-entropy, per anchor, and **never published**. It is what makes two anchors of the
same economic asset carry unlinkable public commitments.

**Salt custody and recovery.** The salt is derived, not stored, so there is no per-anchor secret to
back up. An issuer keeps one master secret and recomputes any anchor's salt from public data
(`assetId` it already holds, epoch and anchor nonce from the chain). Losing the master secret is the
single failure mode: the issuer can no longer produce enrollments for its existing anchors and must
rotate to a new epoch and re-anchor. Compromise of the master secret lets an attacker recompute
commitments for assets whose `assetId` it already knows, which is a linkability loss, not a
decryption loss.

## Versioning, epochs, amendment

- **Scheme version** changes when the encoding or normalization changes. Commitments are only
  comparable within one scheme version; the factory rejects a mismatch.
- **Identity epoch** rotates salts without changing the scheme. `MordantIssuerRegistry.advanceEpoch`
  retires older epochs for an issuer without revoking it.
- **Amendment** is supersession, never mutation. `amountMinor` is part of the identity, so an amended
  invoice has a *different* `assetId` and needs its own anchor and its own attestation. The prior
  anchor stays on-chain and keeps its own identity, which is the honest record: two economic facts
  existed at two times.

## Collision analysis

- **Cryptographic**: keccak256, birthday bound `2^128`. Not the practical risk.
- **Semantic collision**: two genuinely different invoices sharing debtor, seller, invoice number,
  currency, amount, issue date and due date. If all seven agree, the two records describe the same
  economic obligation, so convergence is correct behaviour rather than a fault.
- **Near miss (the real risk)**: the same invoice normalizing differently on two platforms, for
  example one using the debtor's VAT number and the other its LEI. The identity then differs and the
  conflict is missed. This is a **data-quality failure, not a cryptographic one**, and it is the
  reason the namespace is part of the identity and why namespace agreement is an onboarding
  requirement rather than a runtime assumption.

## Public-correlation analysis

The identity surface alone does not correlate two anchors: commitments are per-anchor salted, and
`assetCommitment != invoiceRoot` is enforced at both the attestation and the vault.

**However, a Vault V2 still publishes V1's economics**: `buyer`, `faceValue`, `currency`,
`advanceAmount`, `protectionEnd`. Two V2 vaults for the same invoice remain correlatable through a
join on `(buyer, faceValue, currency)`, exactly as the M-PRIV6 Gate 1 audit found for V1. The salted
commitment fixes the *identity* leak and does not fix the *economics* leak.

Therefore:

- **Candidate A (one vault + one non-vault source) is genuinely private**, because the counterparty
  registers only the five opaque identity fields through `MordantSourceIdentityRegistry` and
  publishes no economics at all.
- **Two Mordant V2 vaults for one asset remain publicly correlatable** and must not be presented as
  a private match.

Closing the economics leak would require committing `buyer`, `faceValue` and `currency` as well,
which changes the vault's own accounting and redemption surface. That is a V3 vault question, and it
is recorded here rather than claimed as solved.

## Issuer responsibility and Cleanverse boundary

The issuer asserts one thing: *this anchor represents the economic asset committed as
`assetCommitment`, under this scheme version and epoch*. It is not trusted for the match, the policy
result, the counterparty's submission, or the anchor's receivable state.

`MordantIssuerRegistry` is deliberately separate from the Cleanverse eligibility verifier
(`ICviVerifier`). Eligibility answers *may this address hold this role*; identity issuance answers
*may this key assert what an anchor's economic asset is*. Two different authorities, so a Cleanverse
adapter can be replaced without touching identity, and an identity issuer can be revoked without
affecting role eligibility. Revocation is terminal per key id: a revoked issuer can never be
re-enabled, so a compromised key cannot be quietly restored after it has anchored assets.

## Test vectors

Emitted by `contracts/test/IdentityVectors.t.sol`, asserted by
`fhe-lab/shared/identity/asset-identity.test.mjs`.

| Vector | assetId |
|---|---|
| `baseline` | `0x4116fe1fadbf98f677977e80518500ca631242d26da85c0a5327cbba2a9761d8` |
| `normalization-equivalent` | `0x4116fe1fadbf98f677977e80518500ca631242d26da85c0a5327cbba2a9761d8` |
| `no-due-date` | `0xb819eda4dd7f0bd8f23e5519461ee31aeb987634a891d3dff56d8d6f1b121e0f` |
| `zero-decimal-currency` | `0xcc6ddd8fbf3e06e6bf3beb27b4a0f568848d407e4a50e1e0bdf986c7ae42191b` |

`baseline` and `normalization-equivalent` are the same invoice written the way two different
platforms would write it, and they converge. That single equality is the entire premise of the
product.

Commitment vector, `issuerMasterSecret = keccak256("mordant.test.issuer-master-secret")`, epoch 1,
anchor nonce 1:

```text
assetId         0x4116fe1fadbf98f677977e80518500ca631242d26da85c0a5327cbba2a9761d8
salt            0xfddf47d5eed3490c5c98ebf5b986bfe4b2b604e8e384e3c23aca48cc2064cc35
assetCommitment 0x4d7c1f4128b244638593d73d2eb1284952e869e4f8f0c2c516b4ab53f0467b40
```
