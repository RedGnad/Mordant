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
from the verified signed result, while still requiring the committed settlement
token, verifier, facility and attestor, zero open and entitled liabilities, a
reserve covering the canonical payouts, live eligibility for both holders and the
facility, a refused negative control, permitted payout transfers, an unconsumed
result, and byte-identical Viem and Solidity release digests.

Solidity embeds immutables INTO the runtime code, so a case-specific deployment
cannot share the committed deployment's code hash and comparing the two would
always fail. What the executor checks at run time is the exact runtime byte
length plus every immutable above, which is a complete account of how two
deployments of this source may differ. The immutable-masked bytecode equality
against the reviewed artifact needs the compiler's immutable spans, which no RPC
exposes, so it is proved once at deployment and recorded in evidence.

## Pruning

The artifact is written under the durable run root, never under `public/`, so the
worker's post-terminal pruning preserves it while still removing `public/`,
`decryptor-private/`, `participant-private/` and the admitted intervals. The raw
`governed-conflict-result.json` is expendable after that precisely because this
artifact carries a complete copy of it.

## Live qualification, 2026-08-07

Two fresh two-wallet journeys were consumed end to end on Monad testnet. The
authoritative one is the hardened run below, executed at source commit
`5f2156107e61d9d88eb0d1eb82e8676827717dc4`.

| | |
|---|---|
| Run | `e618abc2-0ac7-4d79-b201-44959a54b68c` |
| Governed authority (fresh) | `sha256:a241d6cf105dc55ee2fecacf962fa413fd19e1b7868b0815567c5155884d5c13` |
| Bridge evidence digest | `sha256:a0176d37443e41188e0b3b7e8ca2a1582aa408725d9ce3d00be46068945d1169` |
| Case-specific adapter | `0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1` |
| ReleaseConsumed | `0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651`, block 51573394 |
| Cure deadline | 1786076998, a real 600 s window from `block.timestamp` |
| Finalize (permissionless) | `0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34`, block 51575381 |
| Claim A | `0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819`, 2400 |
| Claim B | `0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50`, 1600 |

The adapter's masked runtime bytecode equals the reviewed artifact
(`0x29b610f1fa6592d70e7171b98dcaaa7ee48a7bf0896efa1f3bbe7a1f773e722e`, 28
immutable spans, 10088 bytes), so only its constructor pins differ. The bridge
evidence was verified again after the worker pruned the run, with the Ed25519
signature checked against the copy it carries.

Three things separate this run from the earlier one. Settlement re-verified each
participant's retained `ParticipantAdmissionV1` payload and signature against the
durable admission ledger, rather than accepting the digest the artifact carries.
The expected source commit came from server configuration, so the artifact no
longer vouches for its own provenance. And the case adapter was bound to a
deployment proof located by its claimed address and run, so a proof retained for
another deployment cannot stand in for it.

The earlier journey, run `76005a0c-2787-4c50-b196-636e45b71781` on adapter
`0x00efE6AAcaC6Aa94A3c66d8F09D310197600D935` at activation commit
`85d1d9f5ac66630b39ce2de3c60c420019223a6a`, is retained under
`docs/evidence/activation-*` as a real settled execution that predates those
three checks.
