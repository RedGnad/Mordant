# Mode compatibility and trust matrix

One canonical identity architecture serves both modes. This document specifies how, and classifies
every property.

## Shared foundation

```text
                    canonical assetId (scheme v1, never transmitted)
                                     │
                   salted per anchor, per issuer, per epoch
                                     │
                            assetCommitment
                    ┌────────────────┴────────────────┐
                    │                                 │
        MordantInvoiceVaultV2                MordantSourceIdentityRegistry
        (tokenized receivable)               (non-vault platform source)
                    └────────────────┬────────────────┘
                                     │
                          IIdentityAnchor: five opaque fields
                    ┌────────────────┴────────────────┐
              Mode A enrollment                 Mode B enrollment
        IdentityPublicCommitment              IdentityFullFHE256
```

Both anchor kinds expose exactly `assetCommitment`, `identitySchemeVersion`, `identityEpoch`,
`issuerKeyId`, `sourceAttestationDigest`. Neither exposes the asset identity or the salt.

## Anchored enrollment binding

Every anchored enrollment in either mode binds the same seven things (owner decision 9):

| Bound value | Source | Prevents |
|---|---|---|
| `assetCommitment` | read from the anchor | attaching a submission to a different asset |
| `sourceAttestationDigest` | read from the anchor | detaching from the pre-commitment |
| ciphertext digest | the submitted envelope | swapping ciphertexts under a valid enrollment |
| input commitment | canonical derivation | context substitution |
| `policyId` / `policyVersion` | policy scope | evaluating under a different circuit |
| key epoch | ceremony epoch | replay across key rotations |
| `issuerKeyId` | the anchor | an unauthorized party submitting for someone's anchor |

Because the anchor's commitment is immutable and was attested before the anchor existed, an
enrollment cannot be pointed at an asset the issuer chose after seeing anything.

## Mode A: anchored confidential recourse

Unchanged and shipping. `IdentityPublicCommitment`, one known public vault, both sides carry the same
public receivable link. Proven end to end in M-PRIV5C with a live Monad transaction.

V2 adds one thing to Mode A: the vault now also carries an asset commitment, so a Mode A vault is
eligible to become a Mode B anchor later without redeployment. A **V1** vault has no identity surface
and can serve Mode A only. That is the migration boundary, and it is deliberate: V2 is a new
admission model, not a retrofit.

## Mode B: bilateral private matching

`IdentityFullFHE256`, no shared public link, the 256-bit equality decided homomorphically. Measured
in M-PRIV6: +60 ms client encryption, +6.29 MB envelope per pledge, +3.43 s evaluation, depth
unchanged at 11.

The binding step now differs materially from the M-PRIV6 sketch, and this is the correction the owner
decision forced:

| | M-PRIV6 sketch (superseded) | V2 architecture |
|---|---|---|
| When the mapping is asserted | at binding, after the match | **before the anchor exists** |
| Can an issuer pick the anchor after seeing a match | yes, the flaw | **no** |
| Where the commitment lives | in a signed attestation only | **immutable in the anchor** |
| What the binder checks | attestation signature | `anchor.assetCommitment() == result.commitment`, plus the attestation digest the anchor already carries |
| Is `assetId` disclosed on-chain | yes, opened in calldata | **no** |

The binder compares two commitments that both already exist. Nothing is opened, so the canonical
identity is never published, which satisfies owner decision 9 without ZK.

## Test vector parity

`contracts/test/MordantIdentityV2.t.sol::testTwoAnchorsOfTheSameAssetAreUnlinkableByCommitment` and
the JavaScript suite both operate on the *same* canonical `assetId`
(`0x4116fe1f…61d8`), one through a vault anchor and one through raw commitments, demonstrating that
a Mode A anchor and a Mode B counterparty derive identity identically.

## Trust matrix

| Property | Classification |
|---|---|
| Canonical identity encoding is deterministic and collision-resistant | CRYPTOGRAPHICALLY ENFORCED |
| Two anchors of one asset carry unlinkable commitments | CRYPTOGRAPHICALLY ENFORCED |
| `assetCommitment` is immutable after deployment | CRYPTOGRAPHICALLY ENFORCED |
| No post-deployment remapping path exists | CRYPTOGRAPHICALLY ENFORCED |
| Attestation is chain, factory, scheme, epoch and nonce scoped | CRYPTOGRAPHICALLY ENFORCED |
| Creation parameters cannot change after signing | CRYPTOGRAPHICALLY ENFORCED |
| Vault address is a pure function of the attestation (CREATE2) | CRYPTOGRAPHICALLY ENFORCED |
| Commercial terms confidential from the evaluator | CRYPTOGRAPHICALLY ENFORCED |
| 256-bit asset equality decided without decryption | CRYPTOGRAPHICALLY ENFORCED |
| 2-of-3 threshold release, dealerless custody | CRYPTOGRAPHICALLY ENFORCED |
| **The anchor represents the committed economic asset** | **SOURCE-ATTESTED** |
| The invoice exists and its facts are true | SOURCE-ATTESTED |
| Namespace agreement between platforms | SOURCE-ATTESTED (onboarding) |
| Issuer authorization and revocation | POLICY-GOVERNED |
| Identity epoch rotation | POLICY-GOVERNED |
| Role eligibility (Cleanverse adapter) | POLICY-GOVERNED |
| Query budgets and bilateral session initiation | POLICY-GOVERNED |
| Anchor address, `invoiceRoot`, `assetCommitment`, issuer key id, attestation digest | PUBLIC |
| Vault economics: `buyer`, `faceValue`, `currency`, `advanceAmount`, `protectionEnd` | PUBLIC |
| Canonical `assetId` and its preimage facts | CONFIDENTIAL |
| Per-anchor salt and issuer master secret | CONFIDENTIAL |
| Counterparty book and portfolio contents | CONFIDENTIAL |
| Match Boolean, before consent | CONFIDENTIAL |
| Conflict against a named anchor, after bilateral consent | SELECTIVELY DISCLOSED |
| Organizationally independent threshold custody | OPERATIONAL PRODUCTION REQUIREMENT |
| Issuer key management, HSM, rotation ceremony | OPERATIONAL PRODUCTION REQUIREMENT |
| Master-secret backup and recovery procedure | OPERATIONAL PRODUCTION REQUIREMENT |

## Independent custody topology (documented, not simulated)

Required for production, deliberately not coded or faked here:

- three operators under three distinct legal entities, separate cloud accounts, separate key custody;
- each generating its own share in its own HSM, no shared administrator;
- a documented DKG ceremony with independent witnesses;
- rotation on operator change, with an epoch bump and re-anchoring;
- an availability agreement, since 2-of-3 liveness is now an operational commitment.

Nothing in this repository simulates organizational independence, and no evidence produced here
should be read as demonstrating it.
