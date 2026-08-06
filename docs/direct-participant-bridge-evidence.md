# Direct-participant bridge evidence

`mordant.direct-participant-bridge-evidence/1` is the bridge authorization
artifact for a qualified direct-participant run. It exists because a
direct-admission journey is a CUSTOM_SUPERVISED run, and such a run cannot
honestly produce `mordant.protection-evidence/4`: that schema cross-checks its
scenario against a `binding.productScenario` a neutral V2 authorization does not
have. Widening V4 to admit it was refused, so this is a separate contract instead.

Nothing about V4 changed. `assertPublicProtectionEvidence`,
`EXPECTED_GOVERNED_FHE_COMMIT`, the custom-supervised V2 binding, the Go pledge
and governed-result schemas, the BGV circuit and the Ed25519 semantics are all
untouched, and the retained V4 bridge path still runs exactly as before.

## What it is

A server-side artifact, never served publicly, written to
`<runRoot>/<runId>/direct-participant-bridge-evidence.json`. It is not a product
receipt: `mordant.custom-supervised-protection-receipt/1` keeps that role
unchanged, and this artifact binds that receipt's digest.

Its trust does not come from its own shape. It carries the COMPLETE
`GovernedSignedResult` exactly as the decryptor published it, signature included,
and the verifier re-derives every terminal value from that signed object after
checking the signature with the existing `verifyGovernedResultSignature`. The
conflict Boolean is returned only from there, so no field of the envelope, no
request parameter and no configuration file can supply one.

## What it binds

Provenance (`sourceCommit`, `runId`, `executionVariant`), the case identity
(`fheCaseId`, `protectionBindingDigest`, `caseBindingDigest`), the fresh FHE case
binding (`caseBinding`: asset, policy, circuit digest, parameter fingerprint,
release mode, authority id and authority public key), this run's artifacts
(`participantArtifactDigestA`/`B`, `evaluatedArtifactDigest`), the two durable
wallet admissions, the complete signed governed result, the custom receipt digest
and its own `evidenceDigest`.

It carries no `activeFrom`, no `activeUntil`, no raw pledge, no participant or
decryptor private material, no key and no local path. Each participant entry
holds a claim COMMITMENT, never the interval. A leak scan enforces this.

## Verification

`assertDirectParticipantBridgeEvidence` checks, in order: exact schema fields;
the execution variant; the evidence digest over every other field; an exact
40-hex source commit equal to the executing checkout; the run id; the Ed25519
signature; that the retained result digest is the digest of that signed object;
the signed object against the case id, case binding, asset identity, release
mode, authority id, authority public key, circuit digest and parameter
fingerprint; against this run's two participant artifacts and evaluated artifact;
then the two durable admissions, which must be role-ordered, on Monad testnet,
equal to the canonical controlled holders, distinct from each other and not an
excluded wallet. The uncontrolled UAT wallet and the negative control can never
hold a role whatever else they satisfy.

## Bridging

`BridgeExecutor.prepareDirect` accepts only this schema. It derives the release
solely from the verified signed result, the holders solely from the reconciled
durable admissions and the payouts solely from the committed deployment
configuration. Nothing is accepted from a browser.

Because the governed authority is minted per case, the adapter for a
direct-participant run is deployed per case. `checkDirectParticipantAdapter`
therefore takes the run-specific pins (asset, authority, circuit, parameters)
from the verified signed result, while still requiring the reviewed runtime code
hash, the committed settlement token, verifier, facility and attestor, zero open
and entitled liabilities, a reserve covering the canonical payouts, live
eligibility for both holders and the facility, a refused negative control,
permitted payout transfers, an unconsumed result, and byte-identical Viem and
Solidity release digests.

## Pruning

The artifact is written under the durable run root, never under `public/`, so the
worker's post-terminal pruning preserves it while still removing `public/`,
`decryptor-private/`, `participant-private/` and the admitted intervals. The raw
`governed-conflict-result.json` is expendable after that precisely because this
artifact carries a complete copy of it.
