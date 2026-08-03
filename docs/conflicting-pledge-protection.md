# Conflicting Pledge Protection — MVP execution boundary

This service is a synthetic hackathon prototype. It does not move real funds, establish legal
priority, provide insurance, or prove production custody.

## Root asset

The product root is the retained Cleanverse M-11 issuance/readback for MINV01 on Monad testnet:

- Cleanverse A-Token `0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b`;
- request `IA20260729032221850604`;
- issuance transaction `0xd26ba9b1624a6e10127a48e2acabdbbf94cae97e0be071e243c7ee5b08211b8c`;
- token deployment block `48901234`, separately retained by the M13A ceremony evidence;
- preflight pinned block `48901220`, which is not represented as a post-launch readback;
- retained M11 launch/readback, Cleanverse documentation/aPass and M13A ceremony sources.

The record does not invent a legal issuer. Its administrator address is observed, the receivable
description and amounts are fixtures, and legal issuer identity remains `UNPROVEN`. Cleanverse
documentation version v5.6 is `DOCUMENTED`, not observed on-chain. The retained timestamp remains
the timezone-neutral `issuedAtRaw`, and the aUSDC decimals are supported by the retained M11
readback. A canonical domain-separated SHA-256 digest of the classified record is the sole
`AssetIdentity` admitted by the protection case. Its current value is
`sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c`. The holder snapshot,
FHE case, participant artifacts, evaluated artifact, governed result, recourse record, public
evidence and frontend all read that same digest.

The exact retained provenance is:

- `docs/evidence/monad-invoice-atoken-launch-2026-07-28.json` —
  SHA-256 `3919f586ba19a901151225e0d9de83d554566db26658fd301a025625ba02a8d9`;
- `docs/evidence/cleanverse-monad-2026-07-28.json` —
  SHA-256 `6e8a7c742a032ba82272b0931503aed85470cf3f8b39915f763e47cc1bbaf0df`;
- `docs/evidence/monad-m13a-ceremony-2026-07-28.json` —
  SHA-256 `cd0bcc8944796a18dda32efa618bb5a0a2311b0755cd16c6a5ef657e34e18bb3`.

## Runtime split

- The local backend runs the accepted fixed N15 BGV path in separate keygen, participant,
  evaluator and governed-decryptor processes.
- The evaluator receives only the public case root. It receives no secret-key path.
- The frontend calls product operations. It cannot choose a ciphertext path, evaluation key,
  output slot, circuit, decryptor path or asset identity.
- Mutation is disabled in production before request-body parsing. Local mutation requires the
  explicit `MORDANT_LOCAL_EXECUTION_ENABLED=1` opt-in and either a loopback request or the external
  administrator capability.
- The deployed web view reads a completed public `MordantProtectionEvidence`; it does not represent
  that import as browser-side or newly executed FHE.
- The recourse adapter and cure clock are `PROTOCOL_DOUBLE`. No live Cleanverse settlement occurs.

## Durable operations and recovery

Each product mutation is recorded before its subprocess or irreversible filesystem action in an
atomically persisted `mordant.protection-operation-journal/1`. An operation binds its run ID,
sequence, phase, immutable parameters and their digest, expected current and target stage, fixed
timestamps, expected artifacts, creation time and terminal reconciliation outcome. The process
lock coordinates only the live process; it is not the durable source of truth.

Every operation and read first reconciles the journal against cryptographically verified terminal
artifacts. Completed preparation, submissions, finalization, evaluation, release, recourse and
evidence publication advance the TypeScript state without repeating the one-shot action. An exact
published release is reconstructed as the accepted `exactRetry`; a different or ambiguous
irreversible result aborts the run. Recourse reuses the timestamp persisted before invocation.
Retained evidence is written by temporary file, file flush, atomic rename, directory flush and
exact readback verification.

Ordinary unlink removes only each Mordant-generated transient plaintext pledge JSON file and
participant signing-key file after the exact signed public submission is verified. This is
operational cleanup, not secure erasure. Decryptor private artifacts and retained signed results
remain in a retained local case directory unless that entire generated case directory is later
removed as an explicit storage-management action.

## Disk preflight and retention

One measured complete case occupies about 393 MB on the August 2026 ARM64 run. The backend
conservatively budgets 550 MiB per new case and requires a further 1.5 GiB free safety margin before
key generation. It checks the filesystem containing the configured run root after creating that
root. A separate 768 MiB bounded check applies to the binary/cache filesystem.

The preflight runs before key generation and fails with a storage-specific error if the margin is
not present. It never automatically deletes evidence, terminal markers, signed results,
user-selected directories, non-Mordant files, or prior case directories. Compiled binaries and Go
build cache live only under ignored `.mordant/` paths and are regenerable.

Both regenerated public product manifests are retained in
`docs/evidence/conflicting-pledge-protection/`. Because the development filesystem could not retain
two complete N15 case directories while regenerating and validating both, the completed conflict
case directory was removed only after its public manifest had passed exact verification. The
complete no-conflict local case remains under `.mordant/protection/`. This is an explicit prototype
retention fact, not a secure-erasure or production-custody claim.

## Exact claim

“Mordant protects a tokenized receivable with a private conflict check and governed recourse. The
parties’ pledge records are evaluated under BGV fully homomorphic encryption. The evaluator cannot
inspect the inputs or dictate the released result. A designated governed decryptor independently
recomputes the fixed circuit, decrypts the final Boolean, and signs it into the recourse workflow.”

Disclosure: “The MVP uses a designated trusted decryptor and local single-host execution. Threshold
output release and production custody isolation remain post-MVP upgrades.”
