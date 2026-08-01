# V5 deployment reconciliation

## Classification: PROVISIONAL

The Monad testnet deployment at chain 10143 described below is **PROVISIONAL**
and must not be used as final evidence. It is retained only as the record of a
superseded deployment.

**Established, not assumed.** The deployed verifier runtime does not contain the
producer-side view selectors:

| Selector | Function | In frozen artifact | In deployed runtime |
|---|---|---|---|
| `0xf417e039` | `resultCommitmentOf` | yes | **ABSENT** |
| `0xa2538a0c` | `resultStructHash` | yes | **ABSENT** |
| `0x6316be9b` | `acceptMatch` | yes | present |
| `0x514c1bd3` | `recomputationContext` | yes | present |
| `0xbb2bc62f` | `replayKey` | yes | present |
| `0x1ce74e5a` | `decisionKey` | yes | present |

Deployed verifier runtime is 10827 bytes; the frozen artifact is 10961. The
difference is exactly the two producer views added in `f5cf7c3`.

## Inventory

Source commit at deployment: `c191be13` (before the freeze commit `bc5f9d7`).
Deployment journal: `fhe-lab/monad-testnet/artifacts/v5-run/journal.json`.
Machine-readable inventory with runtime code hashes:
`fhe-lab/monad-testnet/artifacts/v5-run/provisional-inventory.json`.

| Contract | Address | Runtime bytes |
|---|---|---|
| `MockEligibility` | `0x1244956B5b75cF3dE6DfF1f42997861D9F1cC90A` | 1415 |
| `MockERC20` (settlement) | `0xac70C0cbFb639985980dE0D82DEc93AaAAb4732f` | 2692 |
| `MockERC20` (CVA token) | `0x881a6dD2D73696D440077094F0368a8a23d47a24` | 2692 |
| `MockCvaAdapter` | `0x2596d5c0583b927f58d9fcfb059cc548c644412a` | 2813 |
| `MordantIssuerRegistry` | `0xf11Ef0bD0676F16BBa977a07e9076Cb4861656cc` | 3162 |
| `MordantFactoryV2` | `0x64874787905db572D9f935e4dF3A3eE247217912` | 46096 |
| `MordantScopeGovernanceRegistryV5` | `0x100a7427Ae2af6377775DA4dc10379330a78838d` | 13388 |
| `MordantSourceCommitmentRegistry` | `0x2ea5480cf5973966c4D9A295C4B04c635f888Fac` | 7498 |
| `MordantMatchVerifierV5` | `0x2f8e22Ce68DC64cAB20cab1b87e6785132aA9992` | 10827 |
| `PrivateMatchBinderV5` | `0x977d4C9C4E8C3EDE4257Be86B41C8A87a3a4f88b` | 15311 |

20 transactions, all successful: 2 funding, 10 deployments, 8 configuration.

## Consumed or unused session identities

**None consumed.** A full event scan of blocks 49967222 to 49967323 across the
governance registry, source registry, verifier and binder found only
configuration events:

| Contract | Logs | Events |
|---|---|---|
| governance | 2 | `RelayerSet`, `BinderSet` |
| sources | 2 | `SubmitterSet`, `RevealerSet` |
| verifier | 1 | `PolicyVersionUpdated` |
| binder | 0 | none |

There is no `SessionCommitted`, no `SourceCommitted`, no
`ConfidentialMatchAcceptedV5` and no `RecourseOpened`. No session commitment,
nullifier, output commitment, provider proof, source record or consent was ever
consumed on this deployment. Abandoning it strands nothing.

## Configuration observed

- `MordantFactoryV2` constructor is `(address initialOwner, ICviVerifier verifier, MordantIssuerRegistry registry)`. The second parameter is named `verifier` but is the eligibility/CVI interface (`isEligible`), so passing `MockEligibility` there is correct, not a misconfiguration.
- `governance.authorizedBinder` and `sources.authorizedRevealer` both point at the provisional binder `0x977d…f88b`.

## What must be redeployed

Because the verifier and binder addresses change:

- **`MordantMatchVerifierV5`** - new instance from frozen source.
- **`PrivateMatchBinderV5`** - its `verifier` is `immutable`, so a new verifier requires a new binder.
- **`MordantScopeGovernanceRegistryV5`** - its `authorizedBinder` points at the old binder. Redeployed rather than re-authorized so no provisional authorization survives in the final evidence.
- **`MordantSourceCommitmentRegistry`** - same reasoning for `authorizedRevealer`.

`MordantFactoryV2`, `MordantIssuerRegistry`, `MockEligibility` and the token
contracts hold no reference to the verifier or binder. They are nonetheless
redeployed in the final run so that one deployment journal, one source commit
and one address set describe the whole surface.

## Call matrix, established so far

Read from the compiled ABI, not assumed.

| Call | Signature | Notes |
|---|---|---|
| `factory.creationDigest` | `creationDigest(tuple config) -> bytes32` | view; config is `InvoiceConfig` |
| `factory.createIdentityAnchoredVault` | `createIdentityAnchoredVault(tuple config, tuple attestation, bytes signature) -> address` | buyer sends |
| `factory.vaultForRoot` | `vaultForRoot(bytes32) -> address` | readback |
| `factory.vaultForAttestation` | `vaultForAttestation(bytes32) -> address` | the binder's provenance check |
| `issuerRegistry.registerIssuer` | `registerIssuer(address signer, uint32 fromEpoch)` | owner only |
| `issuerRegistry.issuerKeyIdFor` | `issuerKeyIdFor(address) -> bytes32` | pure |
| `eligibility.setEligible` | `setEligible(address, uint8 role, bool)` | roles: buyer 1, originator 2, facility 3, holder 4 |
| `verifier.resultCommitmentOf` | `0xf417e039` | **only on the frozen build** |
| `verifier.resultStructHash` | `0xa2538a0c` | **only on the frozen build** |
| `verifier.acceptMatch` | `0x6316be9b` | callable only by `core.binder` |
| `governance.sessionCommitmentOf` | `(intent, signatures, salt) -> bytes32` | view |
| `governance.sessionNullifierOf` | `(intent) -> bytes32` | view; salt-independent |
| `governance.intentDigest` | `(intent) -> bytes32` | view; what the three signers sign |
| `governance.commitSession` | `(bytes32 commitment, bytes32 nullifier)` | authorized relayer sends |
| `governance.authorize` | `(AuthorizationRequest) -> bytes32 recordDigest` | governor only |
| `sources.sourceCommitmentOf` | `(attestation, issuerSignature, salt) -> bytes32` | view; no off-chain derivation needed |
| `sources.commitSource` | `(bytes32)` | authorized submitter sends |
| `binder.consentDigest` | `(sessionCommitment, sessionNullifier, resultCommitment, sourceRecordCommitment, anchor, consent) -> bytes32` | view; **corrected in `c709df2`** |
| `binder.bindRecourse` | `(envelope, attestation, reveal, anchoredSource, counterpartySource, anchor, consentA, consentB) -> bytes32` | the single external transaction |

**Missing API, recorded rather than worked around.** There is no
`attestationDigest` view on `MordantFactoryV2`. `MordantSourceAttestation` is a
library with `internal` functions, so the source-attestation EIP-712 digest is
not readable on chain. The runner must derive it from the exact values in the
frozen source:

```
domain    name    "Mordant Source Attestation"
          version "1"
          chainId, verifyingContract = the factory (or the source registry)
typehash  keccak256(
  "SourceAssetAttestation(uint256 chainId,address factory,bytes32 creationDigest,"
  "bytes32 assetCommitment,bytes32 initialTermsCommitment,uint16 identitySchemeVersion,"
  "uint16 termsSchemeVersion,uint32 identityEpoch,bytes32 issuerKeyId,bytes32 invoiceRoot,"
  "address controller,uint64 validUntil,uint256 nonce)")
```

This derivation is checked by the transaction itself: `createIdentityAnchoredVault`
recovers the signer and calls `issuerRegistry.requireAuthorized`, so a wrong
digest reverts rather than producing bad state. The same applies to
`sources.revealSource`, which additionally exposes `sourceCommitmentOf` as a
view so the commitment side needs no derivation at all.

## Defect found by building the call matrix

Building the call matrix from the compiled ABI, rather than assuming it, exposed
two real defects in the pre-freeze binder. Both are fixed in `c709df2`.

**1. The public `consentDigest` view did not produce the digest the binder
verified.** The view read `recourses[sessionCommitment].anchorCommitment`, which
is zero before binding, while the binding path encoded
`core.session.sourceRecordCommitmentA`. A producer that called the view to learn
what to sign would have signed a value the binder rejects with
`ConsentNotSignedByController`. The view existed precisely to stop producers
re-deriving EIP-712 encodings, and it was the one thing that could not be used
for that.

**2. Both consents bound side A's source record.** Side B therefore consented to
a statement naming a source it never submitted.

Corrected by giving the public view and the binding check a single shared
encoder, `_consentDigest`, taking every input as a parameter so it reads no
state that exists only after binding, and by passing each side its own
`sourceRecordCommitment`. The `DisclosureConsentV5` EIP-712 type string is
unchanged, so the schema freeze hash still holds; only the encoding semantics
and the view's signature changed.

The V5 test suite now obtains every consent from `binder.consentDigest`, so a
future divergence between the view and the check fails every binding test rather
than surfacing on chain. `testAConsentMustBindItsOwnSourceRecord` covers the
second defect directly.

This is why the freeze was regenerated: `docs/provenance/frozen-v5-sources.txt`
now pins the corrected binder.

## Atomicity gate: PASSES

Verified against the source, not assumed.

- `PrivateMatchBinderV5.bindRecourse` is the binder's only external state-changing entry point.
- It calls `verifier.acceptMatch` as an internal contract-to-contract call inside the same transaction.
- `MordantMatchVerifierV5.acceptMatch` begins `if (msg.sender != core.binder) revert InvalidBinder(...)`, so no external account can reach it. An EOA calling it directly reverts; a caller naming their own contract as `core.binder` produces a result this binder rejects at `core.binder != address(this)`.

One externally broadcast transaction opens a recourse record, and no accepted
result can exist independently before binding. No atomicity regression.

## Source-attestation digest: three-way agreement established

The mission gate required agreement between the runner implementation, an
independent reference and pinned Solidity/JavaScript vectors before any vault
creation is broadcast.

**Leg 3 did not exist.** `sourceAttestationDigest` was present in
`fhe-lab/shared/identity/v4-digests.mjs` but had no pinned Solidity vector and
no test coverage. The runner would have been deriving, unverified, the one
digest that cannot be read from any deployed contract.

Now pinned, from the frozen library itself
(`contracts/test/SourceAttestationVectors.t.sol`):

| Value | |
|---|---|
| `ATTESTATION_TYPEHASH` | `0x5c84efcfafc8e9d8293daaf7fbc1b3023887538bb27651c6c46e8af3551b3397` |
| struct hash (vector) | `0xce83de9e69a87c459c4770633f5d47f240404196deae25bf492c9ca695bae497` |
| digest, verifying contract = factory | `0x49b44a18bf3a9641c23c074ce802b681777f472ddbdf4e7bb38d1d39ff880824` |
| digest, verifying contract = source registry | `0x1d5598ee5e3236baff60335fc551898c0a2cf25f3c06994dddd5c2c4ee3e2ede` |
| domain separator (factory) | `0x684163e2fbeb7d80a14c2603076b625a13a8015737f9e51e8a4d17688e12141e` |

The three producers are:

1. **Runner** - `sourceAttestationDigest`, via viem `encodeAbiParameters`.
2. **Independent reference** - `referenceDigest` in
   `fhe-lab/shared/identity/source-attestation-digest.test.mjs`, which builds the
   preimage by explicit 32-byte word concatenation and shares no encoder with (1).
3. **Pinned Solidity** - emitted by `MordantSourceAttestation` itself.

`agreedSourceAttestationDigest(...)` is the gate a runner calls before signing;
it throws `SOURCE_ATTESTATION_DIGEST_DISAGREEMENT` unless (1) and (2) match, and
both are pinned against (3) in CI.

Coverage is asserted rather than assumed: all thirteen fields are individually
mutated and must change the digest, and transposing `assetCommitment` with
`initialTermsCommitment` must change it too, so field ORDER is covered and not
only field values. The factory and source-registry digests are required to
differ, so a signature for anchor creation cannot be replayed at opaque source
admission.

Solidity 268/268, `fhe:test` 83/83.
