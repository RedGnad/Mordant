# Conflicting Pledge Protection — MVP execution boundary

This service is a synthetic hackathon prototype. It does not move real funds, establish legal
priority, provide insurance, or prove production custody.

## Root asset

The product root is the retained Cleanverse M-11 issuance/readback for MINV01 on Monad testnet:

- Cleanverse A-Token `0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b`;
- request `IA20260729032221850604`;
- issuance transaction `0xd26ba9b1624a6e10127a48e2acabdbbf94cae97e0be071e243c7ee5b08211b8c`;
- deployment block `48901234`;
- retained source `docs/evidence/monad-invoice-atoken-launch-2026-07-28.json`.

The record does not invent a legal issuer. Its administrator address is observed, the receivable
description and amounts are fixtures, and legal issuer identity remains `UNPROVEN`. A canonical
domain-separated SHA-256 digest of the classified record is the sole `AssetIdentity` admitted by
the protection case. The holder snapshot, FHE case, participant artifacts, evaluated artifact,
governed result, recourse record, public evidence and frontend all read that same digest.

## Runtime split

- The local backend runs the accepted fixed N15 BGV path in separate keygen, participant,
  evaluator and governed-decryptor processes.
- The evaluator receives only the public case root. It receives no secret-key path.
- The frontend calls product operations. It cannot choose a ciphertext path, evaluation key,
  output slot, circuit, decryptor path or asset identity.
- The deployed web view reads a completed public `MordantProtectionEvidence`; it does not represent
  that import as browser-side or newly executed FHE.
- The recourse adapter and cure clock are `PROTOCOL_DOUBLE`. No live Cleanverse settlement occurs.

Ordinary unlink removes only the two Mordant-generated transient plaintext pledge JSON files and
participant signing-key files after successful encryption. This is operational cleanup, not secure
erasure. The decryptor private artifacts and retained signed result remain in the case directory.

## Disk preflight and retention

One measured complete case occupies about 393 MB (392,680 KiB) on the August 2026 ARM64 run. The
backend conservatively budgets 550 MiB per new case and requires a further 1.5 GiB free safety
margin before key generation. The retained conflict and no-conflict cases measured about 786 MB
combined. Their product evidence manifests are about 26 KiB and 25 KiB respectively.

The preflight runs before key generation and fails with a storage-specific error if the margin is
not present. It never automatically deletes evidence, terminal markers, signed results,
user-selected directories, non-Mordant files, or prior case directories. Compiled binaries and Go
build cache live only under ignored `.mordant/` paths and are regenerable.

## Exact claim

“Mordant protects a tokenized receivable with a private conflict check and governed recourse. The
parties’ pledge records are evaluated under BGV fully homomorphic encryption. The evaluator cannot
inspect the inputs or dictate the released result. A designated governed decryptor independently
recomputes the fixed circuit, decrypts the final Boolean, and signs it into the recourse workflow.”

Disclosure: “The MVP uses a designated trusted decryptor and local single-host execution. Threshold
output release and production custody isolation remain post-MVP upgrades.”
