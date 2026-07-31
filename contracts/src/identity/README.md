# Canonical economic-asset identity, scheme version 2

> **Scheme 1 is retired.** It placed currency, amount and due date inside the identity, so an
> amended invoice became a *different asset*. That hid exactly the case Mode B exists to find:
> "same receivable, conflicting terms". Scheme 2 splits identity from terms. The factory refuses
> scheme 1 attestations.


Normative specification. The Solidity library `MordantAssetIdentity.sol` and the JavaScript
reference `fhe-lab/shared/identity/asset-identity.mjs` are both bound by this document, and the
vectors below are asserted in both.

## Why this exists

Two platforms that never communicate must derive the *same* 256-bit identity for the same invoice,
from facts each already holds, without ever exchanging it. Every rule here exists to make that
convergence exact. A disagreement produces a **false negative**, which is the dangerous direction:
a real double-financing silently goes undetected.

## A. StableAssetIdentity

What the receivable *is*. Every field is identity-defining: changing it means a different
receivable, not an amended one.

| Field | Justification for inclusion |
|---|---|
| `sellerNamespace`, `sellerId` | the receivable is an obligation owed *to* this party; changing it is a novation, not an amendment |
| `debtorNamespace`, `debtorId` | owed *by* this party; same reasoning |
| `invoiceNamespace` | invoice numbers are unique only within a numbering scheme; the namespace names that scheme |
| `invoiceId` | the document reference within that namespace |
| `issueDateDays` | re-dating an invoice requires cancellation and re-issue in VAT regimes, so it is identity-defining, and it disambiguates invoice-number reuse across periods |

**Deliberately excluded.** `jurisdiction`: every supported namespace is either globally unique
(LEI, DUNS, GLN, PEPPOL) or self-scoping (a VAT identifier carries its country prefix). A separate
jurisdiction field would give two ways to express one fact, which is a divergence source.
Currency, amount, due date and payment schedule: all mutable by amendment, so all belong to terms.

### Namespace precedence

When a registry document identifier exists (PEPPOL, SDI, IRN), the platform **must** use that
registry namespace rather than the seller's own numbering. Precedence is fixed so two platforms
holding the same invoice cannot pick different forms and diverge.

## B. AssetTermsVersion

What the receivable currently *says*. Amendable, versioned, and bound to the asset it belongs to.

| Field | Purpose |
|---|---|
| `currencyCode`, `faceValueMinor`, `amountExponent` | the amount owed |
| `dueDateDays` | nullable (`0`) when the document states none |
| `paymentScheduleDigest` | `0` for a single bullet payment |
| `termsVersion` | strictly increasing per asset, 1-based |
| `amendmentId` | the amendment's own reference |
| `supersedesTermsCommitment` | makes history a chain, not a set |
| `relation` | Original, Amendment, Cancellation, CreditNote, Replacement, Novation |
| `relatedStableAssetId` | the asset a credit note, replacement or novation points at |
| `effectiveFrom` | when the terms take effect |

### Namespaces

A registry, not free text: `lei`, `duns`, `vat`, `gln`, `eth`. The namespace is part of the identity,
so the same digits under `duns` and under `vat` are different parties. Adding a namespace does not
require a scheme bump; removing or re-meaning one does.

## Normalization profiles

Scheme 1 stripped punctuation from every identifier. That destroyed leading zeros that are
significant in DUNS and GLN, and merged genuinely different strings. Scheme 2 uses versioned,
field-specific profiles whose id is part of the digest, so the same characters under two profiles
never collide.

| Profile | Rule | Collisions |
|---|---|---|
| `ALNUM_UPPER_FIXED` (1) | `[A-Z0-9]` only, uppercased, fixed length. LEI. | none |
| `DIGITS_FIXED` (2) | digits only, fixed length, **leading zeros preserved**. DUNS, GLN. | none |
| `VAT` (3) | uppercased, strips only space, dot, hyphen; requires two leading letters | none in practice |
| `HEX_ADDRESS` (4) | `0x` + 40 hex, lowercased (EIP-55 case is display-only) | none |
| `INVOICE_CASE_SENSITIVE` (5) | preserved byte for byte | **none** |
| `INVOICE_CASE_INSENSITIVE` (6) | uppercased, non-alphanumerics dropped | **yes, lossy** |

Every profile **fails closed** on bytes outside printable ASCII. No Unicode folding: NFKC and
friends map distinct characters onto each other and would manufacture collisions.

**The lossy profile, stated plainly.** Under profile 6, `INV-001` and `IN-V001` normalize to the
same value. That is the price of tolerating formatting differences between platforms, and it is
asserted in the tests so nobody can claim the profile is injective. An issuer whose numbering
carries meaning in punctuation or case must declare profile 5 instead.

Amounts never pass through floating point. `1234.56 USD` is `faceValueMinor = 123456,
amountExponent = 2`. `1250000 JPY` is `faceValueMinor = 1250000, amountExponent = 0`.

## Canonical encoding

Dynamic fields are pre-hashed and the whole tuple is `abi.encode`d, exactly as EIP-712 does. No field
boundary is ambiguous, and no two distinct identities can share an encoding through concatenation.

```text
stableAssetId = keccak256(abi.encode(
    keccak256("mordant.stable-asset-identity/2"), uint16 2,
    sellerNamespace, sellerId, debtorNamespace, debtorId,
    invoiceNamespace, invoiceId, uint32 issueDateDays))

normalizedField = keccak256(abi.encode(
    keccak256("mordant.normalized-field/2"), uint8 profileId, canonicalBytes))
```

## Commitment and salt

```text
assetCommitment = keccak256(abi.encode(
    keccak256("mordant.asset-commitment/2"),
    uint16 schemeVersion, uint32 identityEpoch, bytes32 stableAssetId, bytes32 salt))

termsCommitment = keccak256(abi.encode(
    keccak256("mordant.asset-terms/1"), uint16 termsSchemeVersion,
    bytes32 stableAssetId, uint32 termsVersion, economicsDigest, lineageDigest))

salt = keccak256(abi.encode(
    keccak256("mordant.asset-salt/2"),
    bytes32 issuerMasterSecret, bytes32 stableAssetId, uint32 identityEpoch, uint256 anchorNonce))
```

`termsCommitment` binds `stableAssetId`, so a terms version cannot be detached and re-attached to a
different receivable.

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
### Amendment, cancellation, credit note, replacement, novation

| Event | Stable identity | Terms | Where recorded |
|---|---|---|---|
| **Amendment** (amount or due date corrected) | **unchanged** | new version, supersedes prior | terms registry, append-only |
| **Cancellation** | **unchanged** | new version, relation `Cancellation` | terms registry |
| **Credit note** | **new asset** (own document, own number) | own terms, `relatedStableAssetId` = invoice | its own anchor |
| **Replacement** | **new asset** (new invoice number) | own terms, `relatedStableAssetId` = original | its own anchor |
| **Novation** (a party changes) | **new asset** by construction | own terms, `relatedStableAssetId` = original | its own anchor |

The rule is a single question: *did the receivable become a different obligation, or did the same
obligation change what it says?* A party change or a new document number is the former. An amount
correction on the same document is the latter, and scheme 1 got that backwards.

## Collision analysis

- **Cryptographic**: keccak256, birthday bound `2^128`. Not the practical risk.
- **Semantic collision**: two genuinely different invoices sharing seller, debtor, invoice namespace,
  invoice identifier and issue date. If all five agree, the two records describe the same economic
  obligation, so convergence is correct behaviour rather than a fault.
- **Profile collision**: profile 6 merges strings that differ only in punctuation placement. This is
  a deliberate, tested, documented loss. Profile 5 has none.
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

| Vector | stableAssetId |
|---|---|
| `baseline` | `0x060778b5d9ddb677b48068aee8a3ca13bb64683cc37ff44b012407a2c8fcde53` |
| `normalization-equivalent` | `0x060778b5d9ddb677b48068aee8a3ca13bb64683cc37ff44b012407a2c8fcde53` |
| `other-invoice` | `0x215e176b4eddbf78bcaeb3a1d08a5892a39fa633799d242e6bda19fec045674a` |
| `other-issue-date` | `0x38224eebfcaa6c04c89ab68fd85ee23f6fd5665f13397b1492b7e16d5e2e5823` |

Terms commitments over `baseline`, showing that terms move while identity does not:

| Terms | termsCommitment |
|---|---|
| original, face 110.000000, due 20590 | `0xd833732a67d31774e45d85e39d5fe1149143e032a091bfeb4b0fefa09bdfec1c` |
| amended amount, face 120.000000 | `0xa50db32ab31c3e20c925a0169553be2dc020e00e383c272e4049aa33ad1cb595` |
| amended due date, 20620 | `0x2411f484a4271c989dd07eb461b28ab63d9fdab95d2a78404c8cd532242bf2ca` |

`baseline` and `normalization-equivalent` are the same invoice written the way two different
platforms would write it, and they converge. That single equality is the entire premise of the
product.

Commitment vector, `issuerMasterSecret = keccak256("mordant.test.issuer-master-secret")`, epoch 1,
anchor nonce 1:

```text
stableAssetId   0x060778b5d9ddb677b48068aee8a3ca13bb64683cc37ff44b012407a2c8fcde53
salt            0x7b7a1004e942194ee50f3ae1e53251b239cd7952bea8e13fec02f38ac2534699
assetCommitment 0xdbe34193bdc60e205060888f9bc66457b8bceaa92cc2e2eb16f7ad273ec51bc6
```
