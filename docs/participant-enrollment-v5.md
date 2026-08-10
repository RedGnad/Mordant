# Participant enrollment V5

Status: **on both product paths, enforced at release, fail-closed.**

An enrollment is one participant's signed statement that a specific ciphertext is its own
contribution to a specific bilateral session, pairable only with a specific counterparty. Two
enrollments that cross-certify each other are the two halves of one session, and nothing weaker.

This closes external audit finding H-01 on the product path. Before it, two enrollments issued for
two different sessions shared enough public context that whoever assembled a case could pair any A
with any B and both signatures still verified. The pairing was chosen by the assembler and attested
by nobody.

## Who issues

Each participant, with the key the case binding already admitted for its role. There is no
enrollment authority and nothing to configure.

The product has exactly two signing identities: the two participants, and the release authority.
What an enrollment asserts is a fact about one participant's own submission, and both participants
already sign the case binding that names each other's keys. So the release-side trust store is
*derived* from that signed binding: the two keys are registered as issuers, each for its own role,
for exactly the session window.

A participant therefore cannot enroll the counterparty's ciphertext, and a key the binding never
admitted cannot enroll anything.

## What is signed

The enrollment is a pure function of three things: the case facts, the participant's artifact, and
the role. Nothing else, including the clock.

`EnrollmentCaseFacts` is deliberately the intersection of what the two producers hold. The
coordinator reads the signed `FHECaseBinding`; a direct participant only ever receives its ceremony
bundle, which is a strict subset. Both constructors must produce identical facts for one case, and
a test asserts it.

`IssuedAt` is the session's creation time rather than a wall-clock reading, so the two sides derive
the same bytes without agreeing on a clock and no issuance timestamp has to travel. When a
participant actually signed is recorded by the artifact and the import journal, which is where it
belongs.

The session commitment is the case binding digest. The session nullifier is derived from it under
its own domain, because `CaseNonce` is in the binding but not in the bundle. With no salt on the
binding digest the two carry the same information, so **the nullifier adds no independent
double-submission detection beyond the session commitment** and this profile does not claim it does.

## Settlement vault

`AuthorizationClaim.Vault` is `address vault` inside the EIP-712 type string
`ConfidentialSubmitterAuthorization`. It names the deployed case adapter that will consume the
release.

| Asset identity | Case adapter |
|---|---|
| `sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c` | `0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1` |

Read back from Monad testnet (chain `10143`): 10088 runtime bytes, keccak
`0x3fe60ba9ce84d22b752ff1874116b00ddf9b986a2a3534572ef604c7910cb33d`, with immutables
`assetIdentityDigest 0x7613136e…`, `parameterFingerprint 0xd0f85e99…`, `circuitHash 0x2c166039…`.
Those are the same values this package computes, so the contract and the FHE case describe the same
asset, parameters and circuit.

Issuance **refuses** an asset with no deployed adapter rather than putting a value that is not an
address into a signed field that says it is one. Release requires both participants to have named
the same vault.

## Storage

`participant-enrollment-a.json` and `participant-enrollment-b.json` in the public case root.

The record carries the signature plus the facts needed to audit it by eye. It never carries a
re-serialization of the signed structure: that is re-derived from the store on every read and each
stored field is compared against the re-derivation, so an edited record is refused even where the
edit would not have changed the signature.

On the direct-participant path the enrollment is written **before** the manifest, so manifest-last
remains the single durable marker that a complete, releasable participant input exists.

## Where it is enforced

In the decryptor, before recomputation. The release path loads both records, verifies each against
the binding-derived trust store, pairs them, and checks the pair authorizes the ciphertexts this
case actually holds in the participant order the binding fixes. There is no path that releases a
pair the enrollments do not authorize, and no fallback when verification fails.

## What this does not establish

Release is still performed by the single governed decryptor that holds the secret key. Enrollments
authorize **which pair may be released**. They do not distribute **who can release it**. Nothing
here is evidence of threshold release, operator independence, or institutional decentralization.

The deployed adapter's `expectedGovernedReleaseAuthorityId` is a single immutable authority ID. A
threshold coalition cannot satisfy it without a contract change.
