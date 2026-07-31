# V4 anchor binding

## The problem the obvious answer does not solve

The natural binding check is:

```text
anchor.invoiceRoot() == assetId
```

**This cannot be used.** If the anchor's public `invoiceRoot` equalled the canonical economic-asset
identity, then anyone could compute `assetId` from public chain data and the match would be publicly
computable before evaluation. The whole mode would collapse into the PUBLICLY CORRELATABLE class
rejected in Gate 1. The public root and the private identity must be *different values by design*,
which is precisely why binding needs an attestation rather than an equality check.

## Comparison of binding methods

| Method | Binds identity to anchor? | New trust | Verdict |
|---|---|---|---|
| **Commitment opening alone** — reveal `assetId, matchSalt`, check `H(…) == matchCommitment` | No. Proves what was matched, not that this anchor is that asset | none | **Necessary but insufficient** |
| **`anchor.invoiceRoot() == assetId`** | Yes | none | **Rejected**: makes the match publicly computable |
| **Contract-native commitment** — vault stores `assetIdCommitment` at creation | Yes, verifiable on-chain | none | **Rejected for the first vertical**: requires modifying `MordantInvoiceVault`, which is frozen. Correct long-term answer |
| **Verified credential / DID** | Yes | credential issuer + resolver infrastructure | Deferred; same trust as below with more moving parts |
| **Issuer-signed mapping attestation** | Yes | issuer asserts the mapping | **Selected** |

The selected design is **commitment opening plus issuer-signed mapping attestation**: the opening
proves what was matched, and the attestation proves that this anchor is that asset.

## `AnchorMappingAttestation`

Signed off-chain by the anchor-side platform issuer, verified on-chain by the binder.

```solidity
struct AnchorMappingAttestation {
    uint256 chainId;              // no cross-chain replay
    address binder;               // this binder only
    address anchor;               // the receivable vault being bound
    bytes32 issuerKeyId;          // which platform issuer asserts this
    bytes32 scopeCommitment;      // the authorized scope that owns this anchor
    bytes32 assetIdCommitment;    // H(domain ‖ assetId ‖ mappingSalt)
    bytes32 policyId;
    uint32  policyVersion;
    uint64  keyEpoch;             // ceremony key epoch this mapping is valid for
    uint64  validUntil;
    uint256 nonce;                // one-shot per issuer
}
```

EIP-712, domain `Mordant Private Match Binding` version `4`.

### What the issuer is trusted to assert

> **Anchor `V` on chain `C` represents the economic asset whose canonical identity is committed as
> `assetIdCommitment`, for policy `P` version `n` and key epoch `e`, until `validUntil`.**

The issuer is trusted for **that mapping only**. It is not trusted for:

- the match itself, computed homomorphically over both parties' encrypted identities;
- the policy result, attested by the 2-of-3 quorum;
- the counterparty's submission, authorized by a different issuer;
- the anchor's receivable state, read directly from the vault at binding time.

A dishonest issuer can bind a genuine match to the wrong anchor **within its own portfolio**. It
cannot fabricate a match, cannot bind an anchor it has no scope over, and cannot act after
revocation. This is the single new source-truth assumption V4 introduces, and it requires explicit
owner acceptance.

## Binding checks

For anchor A, the binder requires all of:

1. **Quorum** — 2-of-3 EIP-712 signatures over the exact `ConfidentialPolicyResultV4` core, with
   `resultCommitment` recomputed on-chain, never asserted.
2. **Positive result** — `matchConfirmed == true`. A false match can never be bound.
3. **Intended binder** — `result.binder == address(this)`.
4. **Opening** — `H(domain ‖ assetId ‖ matchSalt) == result.matchCommitment`.
5. **Mapping** — attestation signature recovers to a registered, unrevoked issuer key;
   `attestation.assetIdCommitment == H(domain ‖ assetId ‖ mappingSalt)` for the supplied
   `mappingSalt`, i.e. the same `assetId` as the opening.
6. **Authorization** — `attestation.scopeCommitment` equals `result.scopeCommitmentA` or
   `scopeCommitmentB`, so the issuer attesting the anchor is one of the two authorized submitters.
7. **Consent** — a disclosure-consent signature from the *other* scope's issuer over
   `(sessionId, matchCommitment, binder, chainId)`. One party cannot unilaterally publish the match.
8. **Anchor state** — `anchor.code.length != 0`, `receivableState == Outstanding`,
   `protectionState == Active`, read live through the read-only `IReceivableAnchor` interface.
9. **Epochs** — `attestation.keyEpoch` equals the ceremony key epoch the quorum signed for, and
   `policyId`/`policyVersion` match the result and the binder's immutable configuration.
10. **Freshness** — `block.timestamp <= result.validUntil` and `<= attestation.validUntil`.

## Substitution resistance

| Attack | Blocked by |
|---|---|
| Bind a genuine match to an unrelated anchor | check 5: the attestation commits `assetIdCommitment`; a different anchor's attestation commits a different asset |
| Reuse an attestation from another binder or chain | checks 1 and 3, plus `chainId`/`binder` inside the attestation |
| Forge the mapping | issuer signature over EIP-712; issuer registry with revocation |
| Attest an anchor outside the issuer's portfolio | check 6: `scopeCommitment` must be one of the two the quorum signed |
| Publish the counterparty's match without consent | check 7 |
| Bind a false match | check 2 |
| Substitute a different result under a valid attestation | `resultCommitment` recomputed on-chain; quorum signs the exact core |

## Replay resistance

| Replay | Blocked by |
|---|---|
| Same result bound twice | `matchCommitment` is a one-time identity in the verifier |
| Same result, second anchor | as above — one positive match, one binding |
| Same nonce | `replayKey = H(chainId, binder, policyId, nonce)` one-shot |
| Same two inputs re-evaluated | `decisionKey` over sorted input commitments, one-shot |
| Attestation reuse across sessions | attestation `nonce` one-shot per issuer, and `matchCommitment` is salted per session so it never repeats |
| Cross-epoch reuse | `keyEpoch` in the attestation must match the ceremony epoch |

Because `matchCommitment` is salted per session, the same economic asset produces an unlinkable
commitment in every session. Two separate bindings for the same asset cannot be joined by an
observer.

## Two-anchor case (`anchorCount = 2`, reserved)

Both issuers supply mapping attestations, each committing the **same** `assetId` under its own
`mappingSalt`, and both supply consent. The binder records a cross-anchor conflict naming both
vaults. Every check above applies twice. Not implemented in the first vertical, because Gate 1
classified two *Mordant* anchors as publicly correlatable; it becomes meaningful only when the second
anchor is a foreign platform's contract with a different public shape.

## What becomes public at binding

The anchor address, that it is in conflict, `matchConfirmed`/`conflictConfirmed`, both scope
commitments, both input commitments, the match commitment, policy scope, responsible role, cure
deadline, consequence id, and the attesting issuer key id.

**`assetId` itself is opened to the binder contract in calldata.** That is a real disclosure and must
be stated: after a binding, the canonical asset identity of that receivable is public. The privacy
claim is that identity is protected *through discovery and evaluation*, and is disclosed only by an
authorized, bilaterally consented decision to seek recourse — not that it stays private forever.

An alternative that avoids even this — proving the opening in zero knowledge — is the ZK stop
condition and is deliberately not taken.
