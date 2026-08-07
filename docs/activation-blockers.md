> # ⚠ SUPERSEDED: HISTORICAL BLOCKER REPORT
>
> **These blockers were resolved. They do NOT describe the current product, and
> this file is not a current qualification.**
>
> Every blocker below was closed by the direct-participant bridge evidence
> correction, and a hardened two-wallet BGV journey has since been **consumed end
> to end on Monad testnet**: `ReleaseConsumed`, a real 600-second cure window,
> permissionless finalization, and both holder claims paid and reconciled exactly.
>
> - Current status: [`README.md` → Current state](../README.md#current-state-verified-live-run-on-monad)
> - The correction: [`direct-participant-bridge-evidence.md`](./direct-participant-bridge-evidence.md)
> - **Authoritative run: `e618abc2-0ac7-4d79-b201-44959a54b68c`** on adapter
>   `0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`
> - Pre-hardening run `76005a0c-2787-4c50-b196-636e45b71781`, tag
>   `mordant-v5-hackathon-live-e2e1`, is also history: it settled for real, but it
>   predates the settlement-time admission proofs, the external source pin and the
>   deployment-proof binding, so it is not the current qualification either.
>
> This file is kept unedited below as the honest record of what was refused and
> why, before the architecture correction was authorized. Read it as history.

---

# Live activation blockers

Status: **stopped before any deployment or broadcast.** Nothing was signed for
submission, no adapter was deployed, and no transaction was sent.

The activation target was one fresh two-wallet direct-admission journey consumed
end to end on Monad testnet. The fresh journey itself ran and completed. Binding
it to an Adapter V2 is blocked by three independent, reproduced facts, each of
which would require weakening an invariant this repository declares
non-negotiable.

Integration checkpoint: `f7bd68d048739987c6abb000bbe44cae97a10035`.
Activation environment: a normal clone, not a linked worktree (see B0).

## Qualification results

- Go/Lattigo, full suite from the normal clone with
  `MORDANT_FHE_EVALUATOR_BIN` and `MORDANT_FHE_DECRYPTOR_BIN` set to absolute
  binaries built from this checkout: **8/8 packages ok, exit 0**, including
  `oneshotceremony` F-09.
- Live Monad readback against the deployed adapter: **32/32 checks** at block
  `51501230`, retained in
  `docs/evidence/activation-preflight-readback-2026-08-07.json`.
- Protection suite (protection, worker, participant authorization/admission,
  bridge/executor, recourse-compatibility route): **276/276**.
- Typecheck, production build and secret scan: clean.

## What did run

One real journey, run `d91d389c-1d86-439a-8444-d2e42b5a3bf6`, case code
`4XP6F7184R847X4G`, retained in
`docs/evidence/activation-fresh-journey-2026-08-07.json`:

- participant A `0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685` signed
  `ParticipantAdmissionV1` with its own key; A-Pass eligibility read live at
  block `51507855`;
- participant B `0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9` signed separately;
  eligibility read live at block `51507874`;
- real BGV evaluation on the fixed circuit, evaluated artifact
  `sha256:e97904ee…`;
- governed Ed25519 release, `conflict = true`, governed result digest
  `sha256:3e2979d5…`, authority `sha256:fa4d9d2e…`;
- terminal state `CONFLICT_CONFIRMED` / `CURE_WINDOW`, original receivable
  `OUTSTANDING_INTACT`.

## B0 — VCS provenance requires a normal clone (resolved)

Go's `buildvcs` identifies a repository by a `.git` **directory**. A linked git
worktree has `.git` as a *file*, so the toolchain walked past it and stamped the
enclosing `Master` repository's revision (`a25000d1…`) instead of the checkpoint.
That wrong revision would have been recorded as the governed-FHE source
provenance of the run. Re-running from a normal clone stamps the activation
commit with `vcs.modified=false`, and `oneshotceremony` F-09 then has the live
revision it requires. This one is fixed, not outstanding.

## B1 — the governed release authority is per-case random, the adapter pin is immutable

- `fhe-lab/lattigo/governedfhe/keygen.go:156` calls
  `ed25519.GenerateKey(rand.Reader)` for every new FHE case.
  `cmd/mordant-fhe-keygen/main.go` exposes no seed, no import and no reuse mode.
- `fhe-lab/lattigo/governedfhe/types.go:235` derives the authority id purely from
  that public key:
  `sha256("MordantReleaseAuthorityIdentity/v1\0" + mode + "\0" + publicKey)`.
- `contracts/src/recourse/MordantRecourseAdapter.sol:97,178,217` declares
  `expectedGovernedReleaseAuthorityId` `immutable`, sets it once in the
  constructor, and reverts `GovernedAuthorityMismatch` on any other value.

Observed: the deployed adapter pins `0xc21276405a…`, the authority of the single
retained run `30ef645f-8047-45ee-8b7c-19952a54555f`. The fresh run produced
`sha256:fa4d9d2e…`. A fresh journey therefore cannot be consumed by an existing
adapter; each run would need its own deployment.

## B2 — a direct-admission journey cannot produce bridgeable evidence

This is the blocker that a new deployment does not solve.

- `participant-admission-service.ts:258` creates a **neutral** case, and
  `governed-fhe-product-server.ts:1146` gives every neutral case
  `executionVariant = CUSTOM_SUPERVISED`. There is no direct-admission path that
  produces a non-custom run. Confirmed empirically: the fresh run's
  `execution.json` records `"executionVariant": "CUSTOM_SUPERVISED"`.
- `governed-fhe-product-server.ts:2072-2082` states it plainly: *"A custom V2 run
  produces its own local receipt. It cannot produce V4 evidence, because that
  schema cross-checks its scenario against a `binding.productScenario` that a
  neutral V2 authorization does not have, and widening or weakening the published
  V1 contract is not acceptable."* It writes
  `mordant.custom-supervised-protection-receipt/1`.
- The bridge's only input is `verifiedReleaseFromEvidence`
  (`bridge-executor.ts:468`), which calls `assertPublicProtectionEvidence`;
  `protection-evidence.ts:1017` hard-requires
  `schemaVersion === "mordant.protection-evidence/4"`.

The custom receipt also carries none of the fields the payload needs: no Ed25519
signature, no `releaseAuthorityId`, no `assetIdentityDigest`, no `circuitDigest`
and no `parameterFingerprint`. So the governed signature could not be verified
before signing even if the schema gate were bypassed.

## B3 — the governed-FHE commit pin is a source constant

`protection-evidence.ts:23` pins
`EXPECTED_GOVERNED_FHE_COMMIT = "3b0247593d022fb18aadd2b554329f85c5a19898"`, and
line 1026 rejects anything else. Evidence produced by a fresh run records the
revision actually running, so even a V4-shaped fresh evidence is refused unless
that constant is edited.

## Why this stopped here

Clearing B2 or B3 means changing the accepted governed-release and evidence
contracts, which is exactly what the activation brief excluded absent a
reproduced regression, and B2's own source comment calls that widening
unacceptable. Faking either one, by re-pinning a commit the code did not run or
by hand-writing digests into a payload, would put an untrue claim into signed
evidence.

The retained V4 run `30ef645f-…` remains consumable by the deployed adapter
`0xbe67DB4F8a1a884C809884eA45c4dD4376B01b18`: its authority matches the pin and
`resultConsumed` is still `false`. That is a real settlement path, but it is a
split demonstration, not the fresh two-wallet journey, and it was not executed.

The deployed adapter and all of its evidence are unchanged and remain valid.
