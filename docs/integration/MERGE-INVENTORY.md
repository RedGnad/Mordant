# M-MAIN1 — Merge inventory

Every file that differs between `main` (`37176bc`) and `fhe-lab` (`dfa8fbe`),
classified before anything is imported. 188 files, zero unclassified.

## Provenance

| | |
|---|---|
| Source branch | `fhe-lab` at `dfa8fbe` |
| Frozen contracts | `af5baad`, tagged `v4-contracts-af5baad` |
| Final runner | `3ca83ed` |
| Final evidence | `dfa8fbe`, tagged `m-priv8-evidence-4` |
| Target | `main` at `37176bc` |
| Integration branch | `integration/private-matching-v4` |

Both tags are pushed. `fhe-lab` is preserved unchanged as provenance, including
one artifact that would otherwise be removed: see GENERATED below.

## Import rule

`PRODUCT CORE`, `RUNTIME` and `TEST` are imported. `PUBLIC EVIDENCE` is imported
selectively, curated rather than copied. `INTERNAL EVIDENCE`, `GENERATED`,
`OBSOLETE EXPERIMENT` and `UNDECIDED` are not imported. No file in the mission's
never-import list is tracked on `fhe-lab` at all.

## Never-import list, verified against the source branch

| Category | Tracked on `fhe-lab`? |
|---|---|
| Keys, threshold shares, private manifests, raw canaries | No. Generated into gitignored run roots outside the repository. |
| Ceremony work directories | No. `fhe-lab/monad-testnet/.gitignore` excludes `/artifacts/*`. |
| Caches, generated keys, local environment files | No. Only `.env.example` and `.env.m15.example` are tracked. |
| Scratchpads | No. |
| `contracts/out` | No. Ignored by the root `.gitignore`. |
| Large binary evidence | One exception, quarantined: see GENERATED. |
| Process captures with private material | V3 stdout/stderr captures are tracked on `fhe-lab` and classified INTERNAL EVIDENCE, not imported. |


### PRODUCT CORE — 19 files

**Vault V2 / Factory V2 identity-anchored admission**

- `contracts/src/MordantFactoryV2.sol`
- `contracts/src/MordantInvoiceVaultV2.sol`

**Canonical identity, terms model, normalization, issuer and source registries**

- `contracts/src/identity/IIdentityAnchor.sol`
- `contracts/src/identity/MordantAssetIdentity.sol`
- `contracts/src/identity/MordantIssuerRegistry.sol`
- `contracts/src/identity/MordantMatchResult.sol`
- `contracts/src/identity/MordantNormalization.sol`
- `contracts/src/identity/MordantSessionPrecommitRegistry.sol`
- `contracts/src/identity/MordantSourceAttestation.sol`
- `contracts/src/identity/MordantSourceIdentityRegistry.sol`
- `contracts/src/identity/MordantTermsRegistry.sol`

**Identity module documentation**

- `contracts/src/identity/README.md`

**Scope governance, opaque session registry, V4 verifier, V4 binder, anchored-receivable interface**

- `contracts/src/v4/ECDSAQuorumMatchVerifierV4.sol`
- `contracts/src/v4/IAnchoredReceivable.sol`
- `contracts/src/v4/MordantScopeGovernanceRegistry.sol`
- `contracts/src/v4/PrivateMatchBinder.sol`

**Cross-language identity and digest reference, pinned to Solidity vectors**

- `fhe-lab/shared/identity/asset-identity.mjs`
- `fhe-lab/shared/identity/session-protocol.mjs`
- `fhe-lab/shared/identity/v4-digests.mjs`


### RUNTIME — 42 files

**FHE library: BGV circuit, FullFHE256 identity path, threshold, enrollment, commitments**

- `fhe-lab/lattigo/ceremony.go`
- `fhe-lab/lattigo/ceremony_aggregator.go`
- `fhe-lab/lattigo/ceremony_evaluation_keys.go`
- `fhe-lab/lattigo/ceremony_manifest.go`
- `fhe-lab/lattigo/ceremony_runtime.go`
- `fhe-lab/lattigo/circuit.go`
- `fhe-lab/lattigo/commitment.go`
- `fhe-lab/lattigo/distributed_threshold.go`
- `fhe-lab/lattigo/enrollment.go`
- `fhe-lab/lattigo/enrollment_transport.go`
- `fhe-lab/lattigo/external_client.go`
- `fhe-lab/lattigo/process_envelope.go`
- `fhe-lab/lattigo/protocol_digest.go`
- `fhe-lab/lattigo/threshold.go`
- `fhe-lab/lattigo/types.go`

**Native performance harness for both identity modes**

- `fhe-lab/lattigo/cmd/bench/main.go`

**Dealerless ceremony: clients, coordinator, evaluator, operators, orchestrator**

- `fhe-lab/lattigo/cmd/ceremony-client/coverage.go`
- `fhe-lab/lattigo/cmd/ceremony-client/helpers.go`
- `fhe-lab/lattigo/cmd/ceremony-client/main.go`
- `fhe-lab/lattigo/cmd/ceremony-coordinator/main.go`
- `fhe-lab/lattigo/cmd/ceremony-evaluator/main.go`
- `fhe-lab/lattigo/cmd/ceremony-lab/evidence.go`
- `fhe-lab/lattigo/cmd/ceremony-lab/main.go`
- `fhe-lab/lattigo/cmd/ceremony-operator/main.go`

**Threshold operator node binary**

- `fhe-lab/lattigo/cmd/threshold-node/main.go`

**Go module definition**

- `fhe-lab/lattigo/go.mod`
- `fhe-lab/lattigo/go.sum`

**Threshold operator service and fixtures**

- `fhe-lab/lattigo/internal/synthetic/fixture.go`
- `fhe-lab/lattigo/internal/thresholdnet/ceremony.go`
- `fhe-lab/lattigo/internal/thresholdnet/service.go`
- `fhe-lab/lattigo/internal/thresholdnet/store.go`

**Keeps run artifacts out of version control**

- `fhe-lab/monad-testnet/.gitignore`

**Controller, issuer, autonomous relayer and V4 validator signer services**

- `fhe-lab/monad-testnet/match-validator-signer.mjs`
- `fhe-lab/monad-testnet/party-signer.mjs`

**M-PRIV8 runner, deployment, journaling, recovery, verification**

- `fhe-lab/monad-testnet/priv8-bytecode.mjs`
- `fhe-lab/monad-testnet/priv8-chain.mjs`
- `fhe-lab/monad-testnet/priv8-deploy.mjs`
- `fhe-lab/monad-testnet/priv8-leakscan.mjs`
- `fhe-lab/monad-testnet/priv8-readback.mjs`
- `fhe-lab/monad-testnet/priv8-reconcile.mjs`
- `fhe-lab/monad-testnet/run-priv8.mjs`

**Multi-representation leak scanner used by the M-PRIV8 gate**

- `fhe-lab/privacy-v4/leak-scan.mjs`


### TEST — 21 files

**Solidity suite including cross-language digest vectors**

- `contracts/test/IdentityVectors.t.sol`
- `contracts/test/MordantIdentityV2.t.sol`
- `contracts/test/PrivateMatchBinderV4.t.sol`
- `contracts/test/V4DigestVectors.t.sol`

**Go suite: ceremony, circuit, threshold, enrollment**

- `fhe-lab/lattigo/ceremony_fullfhe_test.go`
- `fhe-lab/lattigo/ceremony_negative_test.go`
- `fhe-lab/lattigo/ceremony_test.go`
- `fhe-lab/lattigo/circuit_test.go`
- `fhe-lab/lattigo/cmd/threshold-node/main_test.go`
- `fhe-lab/lattigo/commitment_test.go`
- `fhe-lab/lattigo/distributed_threshold_test.go`
- `fhe-lab/lattigo/enrollment_transport_test.go`
- `fhe-lab/lattigo/external_client_test.go`
- `fhe-lab/lattigo/internal/thresholdnet/service_test.go`
- `fhe-lab/lattigo/internal/thresholdnet/store_test.go`
- `fhe-lab/lattigo/protocol_digest_test.go`

**Signer scope and key-boundary tests**

- `fhe-lab/monad-testnet/party-signer.test.mjs`

**Multi-representation scanner tests**

- `fhe-lab/privacy-v4/leak-scan.test.mjs`

**Identity and digest conformance**

- `fhe-lab/shared/identity/asset-identity.test.mjs`
- `fhe-lab/shared/identity/session-protocol.test.mjs`
- `fhe-lab/shared/identity/v4-digests.test.mjs`


### PUBLIC EVIDENCE — 27 files

**FHE lab overview**

- `fhe-lab/README.md`

**FHE library documentation**

- `fhe-lab/lattigo/README.md`

**Native FHE performance measurement**

- `fhe-lab/lattigo/benchmark/arm64-2026-07-31.json`

**Monad tooling documentation**

- `fhe-lab/monad-testnet/README.md`

**V4 developer documentation: schema, threat model, anchor binding, anti-probing, mode compatibility**

- `fhe-lab/privacy-v4/CEREMONY-DESIGN.md`
- `fhe-lab/privacy-v4/PRIVATE-CONFLICT-DISCOVERY.md`
- `fhe-lab/privacy-v4/README.md`
- `fhe-lab/privacy-v4/V4-ANCHOR-BINDING.md`
- `fhe-lab/privacy-v4/V4-ANTI-PROBING.md`
- `fhe-lab/privacy-v4/V4-MODE-COMPATIBILITY.md`
- `fhe-lab/privacy-v4/V4-SCHEMA.md`
- `fhe-lab/privacy-v4/V4-THREAT-MODEL.md`

**Final bounded M-PRIV8 report**

- `fhe-lab/privacy-v4/evidence/M-PRIV8-REPORT.md`

**FullFHE256 performance measurement**

- `fhe-lab/privacy-v4/evidence/fullfhe-measurement.json`

**Canonical encoding and field-classification documentation**

- `fhe-lab/shared/README.md`
- `fhe-lab/shared/canonical-encoding.md`
- `fhe-lab/shared/field-classification.md`

**Result schemas, benchmark schemas, test-vector manifest, threat model**

- `fhe-lab/shared/benchmark/README.md`
- `fhe-lab/shared/benchmark/benchmark-result.schema.json`
- `fhe-lab/shared/benchmark/benchmark-summary.schema.json`
- `fhe-lab/shared/benchmark/validate-benchmark-summary.mjs`
- `fhe-lab/shared/result-schema/attestation-envelope.schema.json`
- `fhe-lab/shared/result-schema/confidential-policy-result.schema.json`
- `fhe-lab/shared/result-schema/provider-proof.schema.json`
- `fhe-lab/shared/test-vectors/README.md`
- `fhe-lab/shared/test-vectors/manifest.json`
- `fhe-lab/shared/threat-model/README.md`


### INTERNAL EVIDENCE — 36 files

**Prior-mission decision and hardening notes**

- `fhe-lab/DECISION.md`
- `fhe-lab/HARDENING.md`
- `fhe-lab/MONAD-FINDINGS.md`

**V3 and M-PRIV5 run journals and evidence, superseded by M-PRIV8**

- `fhe-lab/monad-testnet/artifacts/anchor-journal.json`
- `fhe-lab/monad-testnet/artifacts/anchored-ceremony-evidence/ceremony-evidence.json`
- `fhe-lab/monad-testnet/artifacts/anchored-ceremony-evidence/dealerless-custody-evidence.json`
- `fhe-lab/monad-testnet/artifacts/anchored-ceremony-evidence/evaluator-result.json`
- `fhe-lab/monad-testnet/artifacts/anchored-ceremony-evidence/key-manifest.json`
- `fhe-lab/monad-testnet/artifacts/anchored-ceremony-evidence/roster.json`
- `fhe-lab/monad-testnet/artifacts/anchored-leak-sweep.json`
- `fhe-lab/monad-testnet/artifacts/anchored-recourse-journal.json`
- `fhe-lab/monad-testnet/artifacts/anchored-recourse-latest.json`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-journal.json`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-latest.json`
- `fhe-lab/monad-testnet/artifacts/receivable-anchor.json`

**V3 six-process capture including raw stdout and stderr**

- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/leak-scan-final.json`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/leak-scan.json`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/lifecycle.json`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/client-a.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/client-a.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/client-b.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/client-b.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/evaluator-coordinator.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/evaluator-coordinator.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node1.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node1.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node2.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node2.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node3.stderr`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/logs/node3.stdout`
- `fhe-lab/monad-testnet/artifacts/privacy-v3-process-evidence/provider-result.json`

**Ceremony-study evidence predating the M-PRIV8 run; the M-PRIV8 bundle supersedes it**

- `fhe-lab/privacy-v4/evidence/ceremony-evidence.json`
- `fhe-lab/privacy-v4/evidence/dealerless-custody-evidence.json`
- `fhe-lab/privacy-v4/evidence/evaluator-result.json`
- `fhe-lab/privacy-v4/evidence/key-manifest.json`
- `fhe-lab/privacy-v4/evidence/roster.json`


### GENERATED — 1 file

**Compiled Go binary, 10.6 MB, committed by accident**

- `fhe-lab/lattigo/ceremony-client`


### SECRET OR SENSITIVE — 0 files

None.

### OBSOLETE EXPERIMENT — 39 files

**V3 privacy and workflow commands, superseded by the ceremony commands**

- `fhe-lab/lattigo/cmd/privacy-client/main.go`
- `fhe-lab/lattigo/cmd/privacy-coordinator/main.go`
- `fhe-lab/lattigo/cmd/workflow/main.go`

**V3 verifier and recourse consumer, superseded by the V4 verifier and binder**

- `fhe-lab/monad-adapter/.gitignore`
- `fhe-lab/monad-adapter/README.md`
- `fhe-lab/monad-adapter/foundry.toml`
- `fhe-lab/monad-adapter/src/ECDSAQuorumConfidentialPolicyVerifier.sol`
- `fhe-lab/monad-adapter/src/ECDSAQuorumConfidentialPolicyVerifierV3.sol`
- `fhe-lab/monad-adapter/src/LaboratoryRecourseConsumer.sol`
- `fhe-lab/monad-adapter/src/ReceivableAnchoredRecourseConsumer.sol`
- `fhe-lab/monad-adapter/src/interfaces/IConfidentialPolicyVerifier.sol`
- `fhe-lab/monad-adapter/src/interfaces/IConfidentialPolicyVerifierV3.sol`
- `fhe-lab/monad-adapter/src/interfaces/IReceivableAnchor.sol`
- `fhe-lab/monad-adapter/test/ECDSAQuorumConfidentialPolicyVerifier.t.sol`
- `fhe-lab/monad-adapter/test/ReceivableAnchoredRecourse.t.sol`
- `fhe-lab/monad-adapter/test/V3LaboratoryRecourse.t.sol`

**V3-era runners and V3 validator signer, superseded by run-priv8 and match-validator-signer**

- `fhe-lab/monad-testnet/deploy-anchor.mjs`
- `fhe-lab/monad-testnet/run-v3.mjs`
- `fhe-lab/monad-testnet/run-v4.mjs`
- `fhe-lab/monad-testnet/run.mjs`
- `fhe-lab/monad-testnet/validator-signer.mjs`

**Tests for the superseded V3 runners**

- `fhe-lab/monad-testnet/run-v3.test.mjs`
- `fhe-lab/monad-testnet/run.test.mjs`
- `fhe-lab/monad-testnet/validator-signer.test.mjs`

**OpenFHE provider gate result; Lattigo was selected**

- `fhe-lab/openfhe/README.md`

**V3 privacy gate, superseded by privacy-v4**

- `fhe-lab/privacy-v3/DATA-FLOW.md`
- `fhe-lab/privacy-v3/README.md`
- `fhe-lab/privacy-v3/leak-scan.mjs`
- `fhe-lab/privacy-v3/leak-scan.test.mjs`
- `fhe-lab/privacy-v3/process-run.mjs`

**V3 canonical-encoding scripts, superseded by shared/identity**

- `fhe-lab/shared/scripts/canonical-v3.mjs`
- `fhe-lab/shared/scripts/canonical-v3.test.mjs`
- `fhe-lab/shared/scripts/canonical.mjs`
- `fhe-lab/shared/scripts/validate-spec.mjs`

**Local anvil acceptance harness for the V1 verifier**

- `fhe-lab/workflow/README.md`
- `fhe-lab/workflow/package.json`
- `fhe-lab/workflow/run.mjs`
- `fhe-lab/workflow/workflow.mjs`
- `fhe-lab/workflow/workflow.test.mjs`


### UNDECIDED — 3 files

**Adds fhe:* scripts that reference obsolete V3 runners. Only the V4 script surface is worth taking.**

- `package.json`

**main is AHEAD here: fhe-lab never modified these files and main fixed them in 37176bc. Importing would revert main.**

- `src/app/api/pilot-applications/route.ts`
- `src/components/public-experience.tsx`


## Notes on the difficult classifications

### GENERATED — the 10.6 MB binary

`fhe-lab/lattigo/ceremony-client` is a compiled Go binary committed by accident
in `1e74cee`. It is not gitignored on `fhe-lab`.

It cannot be removed from `fhe-lab` without rewriting history from `1e74cee`
forward, which would change `af5baad`, `3ca83ed` and `dfa8fbe` — the exact
commit hashes the frozen-contract manifest and the M-PRIV8 evidence are bound
to. Preserving provenance and deleting the blob are mutually exclusive, and
provenance wins. The blob stays on `fhe-lab`, is excluded from the integration
branch, and `fhe-lab/lattigo/ceremony-client` is added to `.gitignore` on the
integration branch so it can never be re-introduced.

### UNDECIDED — `main` is ahead, not behind

`src/app/api/pilot-applications/route.ts` and `src/components/public-experience.tsx`
appear in `git diff main fhe-lab` only because `main` moved forward in `37176bc`
("Fix validation blockers"). `git diff $(git merge-base main fhe-lab) fhe-lab`
for those two paths is **empty** — `fhe-lab` never touched them. Importing the
`fhe-lab` side would silently revert `main`'s fixes. Not imported.

`package.json` genuinely adds `fhe:*` scripts on `fhe-lab`, but every one of them
points at a superseded V3 runner (`run.mjs`, `run-v3.mjs`) or a superseded test
set. The file is not imported; PR 2 adds a V4-only script surface instead.

### OBSOLETE EXPERIMENT — the V3 generation

`fhe-lab/monad-adapter`, `fhe-lab/privacy-v3`, `fhe-lab/workflow`,
`fhe-lab/openfhe`, the V3 runners and the V3 validator signer are the previous
protocol generation. The V4 verifier and binder supersede them, and no V4 runtime
file imports any of them: the dependency closure of `run-priv8.mjs`,
`priv8-leakscan.mjs`, `party-signer.mjs` and `match-validator-signer.mjs` is
exactly `priv8-chain.mjs`, `priv8-deploy.mjs`, `shared/identity/asset-identity.mjs`,
`shared/identity/v4-digests.mjs` and `privacy-v4/leak-scan.mjs`.

They remain on `fhe-lab` as provenance for the V3 evidence that is still
referenced by the M-PRIV8 report.

### INTERNAL EVIDENCE — why the V4 ceremony JSONs are excluded

`fhe-lab/privacy-v4/evidence/*.json` are from an earlier ceremony study, not
from the M-PRIV8 run. PR 3 imports a curated bundle from the actual evidence run
instead, so main carries one coherent evidence set rather than two that disagree.

The M-PRIV8 evidence bundle itself is gitignored on `fhe-lab` and therefore
absent from this diff. PR 3 curates it from the run artifacts on disk, importing
only public fields and redacting local filesystem paths.
