# Participant-originated encryption

Status: **supported, security-sensitive qualified native CLI profile; opt-in and disabled by default.**

This is a genuine native-CLI product capability with a deliberately narrow
qualification boundary. It is not wired into the universal managed public demo
or the browser wallet-admission flow, and neither of those paths is relabelled
as participant-originated. The qualification runner does not execute a live
settlement, but it preserves the governed Boolean and existing settlement input
semantics. It does not establish production institutional key management.

## Supported privacy claim

> For the participant-originated profile, the financing claim is encrypted in
> the participant-controlled environment before Mordant coordination
> infrastructure receives it.

In this profile, each participant creates and signs its own governed-FHE pledge
artifact from a plaintext financing-claim fixture held in that participant's
local directory.
The coordinating service accepts only public ceremony material, wallet
authorizations, hiding commitments, signatures and encrypted artifacts. Its
request schemas contain no `activeFrom` or `activeUntil` member.

The existing governed-FHE artifact schema, BGV circuit, parameter profile,
evaluator, governed decryptor, governed-result schema, Adapter V2 and settlement
contracts are not changed by this profile.

## Process and storage topology

```text
participant A process                 participant B process
  local wallet key                      local wallet key
  local Ed25519 artifact key            local Ed25519 artifact key
  local plaintext pledge + salt         local plaintext pledge + salt
  verified public client bundle         verified public client bundle
  local submission-a.{json,bin}         local submission-b.{json,bin}
                |                                  |
                +------ authenticated import -----+
                                   |
                         participant-originated coordinator
                           registrations / intents
                           quarantine / import journal
                           governed public case root
                                   |
                       +-----------+-----------+
                       |                       |
                 evaluator process       decryptor process
                 public case only        public case + decryptor-private
                 no private mount        independent recomputation + release
```

The product qualification uses separate local processes and disjoint
directories. It does not claim separate institutions, different operating-system
users, hardened container mounts, secure erasure, or production-grade isolation.

The coordinator root must never contain:

- a participant plaintext pledge file;
- a participant claim salt or commitment preimage;
- a participant artifact-signing private key;
- an execution-state object containing a raw claim;
- a request or endpoint shape accepting pledge-window bounds.
- a bearer credential, token field or authorization-header value;
- a participant-local filesystem path.

The coordinator's non-secret process configuration is created under a separate
ephemeral control root, never under its durable state root. The runner creates a
fresh one-run bearer value in memory and gives it to the coordinator and upload
child only through an ephemeral process environment. Each child consumes and
removes the environment entry at startup. The value is never placed in config,
argv, journals, receipts or evidence; the retained-state scanner searches for
both its exact bytes and the complete `Bearer …` header bytes.

## Ceremony

### Phase 0 — wallet registration

Each participant generates an Ed25519 artifact-signing key locally. A distinct
wallet EIP-712 authorization registers the public key for exactly one run/case,
role and wallet. The coordinator recomputes the signing-key digest, typed-data
digest, validity interval and nonce before a create-only registration is made.
Only the public Ed25519 key reaches the coordinator.

### Public foundation

After both registrations, key generation receives the two registered public
keys and creates the existing FHE case foundation. It publishes the protection
and case bindings without receiving either Ed25519 private key.

Each participant downloads the bounded public foundation, verifies its case,
asset, policy, circuit, parameter and FHE-key pins, and locally signs both the
existing case binding and protection binding. The coordinator verifies and
imports those four signatures create-only. Existing protection verification and
case finalization then create the standard case manifest.

### Authenticated client bundle

The finalized role-specific bundle contains only public encryption and
verification material. It binds:

- run and FHE case;
- asset and policy identities;
- circuit ID, version and digest;
- parameter profile and fingerprint;
- FHE public-key digest;
- participant role, identities and artifact-signing public keys;
- case- and protection-binding digests;
- release mode, authority identity and public key;
- validity deadline;
- expected participant-client source and executable digests;
- exact public object names, sizes and SHA-256 digests.

The bundle is authenticated by the existing bilateral case/protection
signatures, the governed release-authority signature, exact object digests and
an out-of-band expected client build pin. It contains no FHE secret key or
decryptor signing key and does not distribute evaluation-key bytes to the
participant client.

## Claim commitment and authorization chain

The participant generates a fresh 32-byte random salt locally and computes a
domain-separated SHA-256 commitment over the complete local pledge, case, role
and salt. Reusing the old unsalted low-entropy interval commitment is forbidden.
Neither the salt nor the pledge preimage is submitted.

Phase 1 is a wallet-signed encryption intent binding the run/case, both binding
digests, asset, policy, circuit/profile, FHE public key, role, wallet,
artifact-signing-key digest, hiding claim commitment, client bundle/source/build
pins, nonce and expiry.

The native client verifies the bundle, encrypts through the existing
`IdentityFullFHE256` client, and places the recomputed Phase-1 intent digest and
claim commitment in the existing opaque `AuthorizationCommitment` and
`PrivateMetadataCommitment` fields. The governed artifact format itself is
unchanged.

Phase 2 is a wallet-signed final admission binding the recomputed Phase-1 digest,
claim commitment, canonical encrypted-artifact digest, exact ciphertext-object
digest, role, wallet, submission nonce and expiry. The coordinator recomputes
these values; it does not trust client-declared digests.

## Bounded import protocol

The supported HTTP contract is fixed to:

- `POST /v1/participant-originated/import/begin`;
- `PUT /v1/participant-originated/import/ciphertext`;
- `PUT /v1/participant-originated/import/artifact-manifest`;
- `GET /v1/participant-originated/import/status`.

The small admission request never carries ciphertext. After Phase-2
verification, the coordinator issues a one-use upload reservation. Raw objects
are streamed to server-selected exact role filenames in a pinned quarantine
directory with:

- authentication before the expensive ciphertext validation;
- strict content type, declared length, per-object and aggregate size limits;
- incremental SHA-256 verification;
- no archive handling and no caller-selected filesystem path;
- canonical, exact-member artifact JSON verification;
- case, role, participant key, FHE key, parameter, profile, circuit, expiry,
  artifact signature and ciphertext-component verification;
- comparison of the ciphertext's opaque intent/claim fields to the wallet
  records;
- create-only role occupancy and nonce consumption;
- a fsynced durable import journal;
- quarantine validation before the standard `submission-{a,b}.bin/json` objects
  become evaluator-visible, with the manifest published last as the commit
  marker.

No participant registration, intent, import journal, bundle wrapper or receipt is
placed in the governed public root. That root retains the existing strict
allowlist consumed by the evaluator and governed decryptor.

A crash after the manifest-last commit becomes evaluator-visible but before the
private completion journal is durable can leave the ticket in
`RECONCILIATION_REQUIRED`. Recovery never replays an uncertain create-only
publication. This is fail-closed for integrity and confidentiality, but the
operator may need to abandon and recreate that case; the profile does not claim
production-cluster availability or automatic rollback across that crash window.

## Supported operator surface

The supported boundary is native CLI plus an embeddable coordinator service,
not a browser route:

- `mordant-fhe-keygen` exposes `participant-foundation`,
  `participant-ceremony-request`, `participant-ceremony-import`,
  `participant-finalize` and role-specific `participant-bundle-export` modes;
- `mordant-fhe-client` exposes participant-local `participant-keygen`,
  `participant-ceremony-sign`, `participant-claim` and `participant-prepare`
  modes;
- `mordant-fhe-import` exposes raw-stdin `stage-object`, `verify`, `publish` and
  exact durable `reconcile` modes;
- `createParticipantOriginatedCoordinator` and
  `createParticipantOriginatedCoordinatorServer` provide the stable
  `/v1/participant-originated/import/*` ciphertext-only service boundary.

The historical keygen `create`/`finalize` and client `submit` modes remain the
defaults. The participant-originated service is opt-in and deliberately is not
imported by `mordant-live-worker.mjs`.

## Deliberate correctness gap

The available primitives do **not** prove that the plaintext encrypted in a
participant artifact equals the plaintext preimage of its hiding claim
commitment. The protocol proves wallet authorization and provenance for a
case-/role-/artifact-bound ciphertext, and it binds the commitment into that
ciphertext envelope. It does not provide a semantic equality proof.

The supported profile therefore qualifies only pinned, honest participant
clients. It does not add or imply an unreviewed zero-knowledge proof system.
Closing this gap remains a production correctness requirement.

## Claim boundary

If both real cases and all negative controls pass, the evidence supports the
privacy claim above. Operationally, that means:

> In the demonstrated participant-encrypted CLI path, each participant prepared
> and signed its own case- and role-bound encrypted artifact locally. Mordant's
> coordinating service received authenticated encrypted artifacts and did not
> receive raw pledge-window bounds.

It does not support browser/device BGV, participant-controlled decryption,
privacy from the governed decryptor, threshold decryption, zero trust in all
Mordant infrastructure, semantic equality between commitment and ciphertext,
claim truth or legal validity, secure erasure, independent institutions,
ERC-1271 contract-wallet verification, production institutional key management,
or production-cluster readiness. The qualified wallet verifier is EOA-only.
The retained-state check is an exact scan of all known plaintext and secret
representations, not a general semantic DLP system.

The managed public profile remains available for accessibility. Its plaintext
is processed by managed Mordant infrastructure and it must remain described as
managed, not participant-originated.

## Qualification commands

The harness is deliberately opt-in. A dry run only prints the two planned case
topologies and performs no FHE work:

```bash
node scripts/run-participant-originated-qualification.mjs \
  --dry-run \
  --work-root /private/tmp/mordant-participant-originated-qualification-plan
```

The real qualification refuses a dirty checkout and requires the caller to pin
the exact committed `HEAD` it will execute. It additionally proves that the
executed commit descends from exact post-policy product-promotion base
`8a523d36dbfe6935f27e6a55a8b5fd048a7b4883`. The work root must not already
exist; it is marked, used for the heavy transient artifacts, and removed after
the sanitized evidence has been written:

```bash
node scripts/run-participant-originated-qualification.mjs \
  --run \
  --work-root /private/tmp/mordant-participant-originated-qualification-run \
  --evidence-root "$PWD/docs/evidence" \
  --expected-source-sha "$(git rev-parse HEAD)"
```

The retained create-only result is
`docs/evidence/participant-originated-encryption-product-qualification.json`.
It must be generated from a clean committed product branch; the older PR #40
experimental evidence is not promoted or copied. The product-qualification evidence
contains source, executable and runtime digests; process topology; public bundles;
Phase-0/1/2 signed authorizations; artifact references; full import journals;
evaluator/decryptor provenance; complete governed signed results; coordinator
state scans; the negative-control matrix; and a canonical product-qualification
receipt.
Participant plaintext fixtures, salts, wallet private keys, artifact-signing
private keys, bearer credentials and local absolute paths are not retained.

Focused checks used by the harness are also runnable independently:

```bash
pnpm protection:test
node --test scripts/run-participant-originated-qualification.test.mjs
cd fhe-lab/lattigo
go test -timeout 40m ./...
```
