# Ephemeral one-shot Lattigo ceremony

This package is the authorized Private Matching V5 ceremony implementation. It creates one fresh
2-of-3 Lattigo key for one bilateral privacy session. `keyEpoch` is fixed to `0`, `maximumSessions`
is fixed to `1`, and the signed scope is the exact session commitment. The public bundle is not a
reusable epoch bundle and must never support a second session.

The package is transport-agnostic: one `Participant` is intended to run on each of three separate
hosts under three genuinely distinct administrators. No shared writable filesystem, shared secret
store, supervisor, coordinator, evaluator, or audit process is trusted. A coordinator can move
opaque signed bytes but cannot author a contribution or manifest. The accepted threat model is
honest-but-curious operators, malicious coordinator/evaluator, fewer than two colluding operators,
and fail-closed availability. This is not an active-secure protocol against a malicious operator.

Local tests use three directories on one host. They are functional, test-only material and are
explicitly not three-host acceptance evidence or evidence of independent custody or separate
organizations.

## Terminal protocol

The public witness state sequence is:

```text
NOT_STARTED
  -> RESERVED
  -> RUNNING
  -> CRS_COMMITTED
  -> CRS_REVEALED
  -> PRIVATE_SHARES
  -> PUBLIC_KEY
  -> RELIN_ONE
  -> RELIN_TWO
  -> GALOIS[0..n-1]
  -> MANIFEST
  -> PUBLISHED
  -> COMPLETED
```

`ABORTED` may be reached from any nonterminal phase. `COMPLETED` and `ABORTED` are terminal. Every
accepted non-abort transition has all three operator signatures; a terminal abort has at least two,
so two surviving operators can witness abandonment by the third. A process that has signed one
value for a sequence cannot sign another. There is no checkpoint parser, recovery constructor,
resume API, regenerated randomized action, reusable key epoch, or legacy bundle parser.

Before secrets exist, every operator atomically consumes the bilateral session in a durable registry
separate from its witness files, creates immutable CeremonyID and fixed-scope markers, signs an exact
deep-copied context snapshot with its process/boot reservation, verifies the canonical ordered set of
all three reservations, and stores all three. A conflict or partial persistence poisons the session.
The MVP attempt ordinal is always `1`; changing a nonce, ordinal or CeremonyID cannot authorize a
second key. An abort or poison requires a completely new bilateral application session with a new
session identity and commitment, fresh CRS, RLWE keys, Shamir polynomials and protocol shares.

## Canonical binding and publication

The deterministic length-delimited big-endian encoding binds protocol/context/envelope/manifest
versions, Lattigo module version and checksum, privacy domain, session identity and commitment,
attempt ordinal and nonce, chain/policy/circuit/release values, query budget, exact parameters,
ordered Galois elements, immutable lifecycle, exact source commit, three ordered operator points,
distinct administrator identifiers, signing/encryption/transport identities, runtime binary and
Go/OS/architecture fingerprints. Every envelope additionally binds CeremonyID, context and roster
digests, one-shot scope/epoch, signer derived from Ed25519 verification, recipient where private,
operation/round/Galois element, predecessor transcript, input and payload digest.

All participants independently reconstruct the concrete public, relinearization and ordered Galois
keys from the authenticated transcript. `KeyID` commits to those exact bytes and the full context.
The all-operator manifest attestations sign the digest of the exact canonical unsigned bundle. The
pre-manifest witness head, three private-ready sealed-bundle digests and terminal replicated witness
heads prevent signing one bundle and publishing another. Public and private publication uses
restricted directories, no-replace files, file/directory fsync and exact-byte readback; no cross-host
atomicity claim is made.

Activation occurs only after the all-three manifest and private-ready attestations, exact
publication readback and three matching `COMPLETED` witnesses. Exact executable provenance may be
verified against retained binary bytes, but it does not by itself prove independent hosts or an
acceptance topology. Expiry is immutable in the manifest;
an already expired ceremony is refused. Session termination may shorten operational use but cannot
extend the manifest expiry. There is no RC2 rotation: a retry is a fresh attempt and post-MVP
positive reusable epochs remain absent. Emergency `REVOKED` or `EXPIRED` status is a separate
monotone, terminal statement linked to the initial signed `ACTIVE` status and requires 2-of-3
operator signatures; reactivation is rejected.

## Private artifact readers

| Artifact | Only permitted reader |
| --- | --- |
| Signing private key | That operator's ceremony process while live; later status/release process through its own keystore handle |
| X25519 transport private key | That operator's endpoint/process |
| Additive RLWE key, Shamir polynomial, plaintext evaluations, relinearization ephemeral | That operator's live ceremony process only |
| Pairwise Shamir evaluation | Its sender until sealing and its exact recipient until aggregation/receipt |
| Aggregate threshold share | Its owning operator; retained only inside that operator's sealed bundle |
| Sealed private bundle and sealing key | Owning operator's ceremony/release boundary; never coordinator, evaluator, client, audit runner, or another operator |
| Public/evaluation keys, transcript, manifest, status and witness | Public after canonical verification |

Private shares never appear in command-line arguments, environment configuration, filenames,
errors, logs, snapshots, public witnesses, manifests or coordinator-visible artifacts. This package
has no command-line or logging surface. The private wire is signed inside recipient-bound X25519 +
AES-GCM; the retained operator bundle is AES-GCM sealed and mode `0600` in a mode `0700` directory.

## Cleanup and retention

- Before completion, additive keys, Shamir polynomials, plaintext private wires, relinearization
  ephemerals and generation state are memory-only. Outbound/inbound plaintext wires are released
  after sealed transport and authenticated aggregation receipt.
- On completion, the live participant drops its additive key, polynomial, aggregate in-memory
  share, CRS reveal/seed, relinearization ephemeral, signing-key copy and transport-key handle. The
  aggregate share remains only in the owning operator's sealed private bundle.
- On abort or poison, live secret references are dropped and an authoritative terminal tombstone
  makes any previously staged sealed private bytes unacceptable to every supported consumer. Such
  bytes may remain on storage or backups; they must not enter another session and no physical or
  secure erasure is claimed.
- After terminal revocation/expiry and closure of every authorized release window, the owning
  administrator destroys its bundle-sealing key and deletes its private bundle.
- Reservations, signing decisions, signed witness/status chains, canonical public bundle,
  ciphertext private wires in the public transcript, source/runtime digests and audit evidence are
  retained as immutable non-secret evidence. A sealed operator bundle remains until its authorized
  retention endpoint.

These are logical cleanup rules. Go memory, swap, core/crash collection, snapshots, backups, media
and an administrator may retain remnants. The implementation makes no secure-erasure or physical-
erasure claim.

## Obsolete boundary

The earlier recoverable implementation and its evidence remain in place for history. The five
historical ceremony executables `ceremony-client`, `ceremony-coordinator`, `ceremony-evaluator`,
`ceremony-lab` and `ceremony-operator`, plus their recovery implementation files, are
build-constrained behind the explicit
`obsolete_recoverable_ceremony` tag, have no default production alias, and are not imported by this
package. That tag is for reproducing rejected historical evidence only; it is not a compatibility,
fallback or migration mode for the one-shot protocol. The old `MCR1`, `MCL1`, recovery ledgers and
snapshots are unconditionally unknown to all one-shot parsers.

Run the bounded package validation from `fhe-lab/lattigo`:

```bash
go test ./oneshotceremony -count=1
go vet ./oneshotceremony
go build ./oneshotceremony
```
