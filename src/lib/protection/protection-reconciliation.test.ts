import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createProtectionOrchestrator, type ProtectionRuntimeOptions } from "./governed-fhe-product-server";
import type { Sha256Digest } from "./cleanverse-asset";

function digest(byte: string): Sha256Digest {
  return `sha256:${byte.repeat(64)}`;
}

type FakeInspection = {
  foundation?: { bindingDigest: Sha256Digest; report: Record<string, unknown> };
  submissionA?: { artifactDigest: Sha256Digest; ciphertextBytes: number; artifactBytes: number };
  submissionB?: { artifactDigest: Sha256Digest; ciphertextBytes: number; artifactBytes: number };
  finalized: boolean;
  evaluationAdmission: boolean;
  evaluation?: { artifactDigest: Sha256Digest; resultBytes: number; artifactBytes: number };
  releaseAdmission: boolean;
  release?: {
    resultDigest: Sha256Digest;
    conflict: boolean;
    releaseMode: "governed-decryptor-v1";
    resultBytes: number;
    exactRetry: true;
    trustedRecoursePins: Record<string, unknown>;
  };
  recourse?: Record<string, unknown>;
  ambiguous: boolean;
};

function argument(args: readonly string[], flag: string): string {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1);
  return String(args[index + 1]);
}

async function fakeRuntimeRoot(scenario: "conflict" | "no-conflict" = "no-conflict") {
  const root = await mkdtemp(join(tmpdir(), "mordant-product-reconcile-"));
  const inspections = new Map<string, FakeInspection>();
  const calls = new Map<string, number>();
  const failAfterAdmission = new Set<string>();
  const runner: NonNullable<ProtectionRuntimeOptions["binaryRunner"]> = async <T>(binary: string, args: readonly string[]) => {
    calls.set(binary, (calls.get(binary) ?? 0) + 1);
    const publicRoot = argument(args, "-public-root");
    const inspection = inspections.get(publicRoot) ?? {
      finalized: false, evaluationAdmission: false, releaseAdmission: false, ambiguous: false,
    };
    inspections.set(publicRoot, inspection);
    if (binary === "inspect") return structuredClone(inspection) as T;
    mkdirSync(publicRoot, { recursive: true });
    if (binary === "keygen" && argument(args, "-mode") === "create") {
      const spec = JSON.parse(readFileSync(argument(args, "-spec"), "utf8")) as Record<string, unknown>;
      const binding = {
        caseId: spec.caseId,
        assetIdentity: spec.assetIdentity,
        policyId: spec.policyId,
        releaseMode: "governed-decryptor-v1",
        parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
        circuitId: "mordant.identity-full-fhe-256",
      };
      writeFileSync(join(publicRoot, "case-binding.json"), `${JSON.stringify(binding)}\n`);
      inspection.foundation = { bindingDigest: digest("1"), report: { duration: 1 } };
      return { bindingDigest: digest("1"), durationNanos: 1, report: { duration: 1 } } as T;
    }
    if (binary === "keygen") {
      inspection.finalized = true;
      return { manifestDigest: digest("2") } as T;
    }
    if (binary === "client") {
      const role = argument(args, "-role");
      const output = { artifactDigest: role === "PARTICIPANT_A" ? digest("3") : digest("4"), durationNanos: 1, ciphertextBytes: 2, artifactBytes: 3 };
      if (role === "PARTICIPANT_A") inspection.submissionA = output;
      else inspection.submissionB = output;
      writeFileSync(join(publicRoot, role === "PARTICIPANT_A" ? "submission-a.json" : "submission-b.json"), `${JSON.stringify({
        caseId: (JSON.parse(readFileSync(join(publicRoot, "case-binding.json"), "utf8")) as { caseId: string }).caseId,
        assetIdentity: (JSON.parse(readFileSync(join(publicRoot, "case-binding.json"), "utf8")) as { assetIdentity: string }).assetIdentity,
      })}\n`);
      return output as T;
    }
    if (binary === "evaluator") {
      inspection.evaluationAdmission = true;
      if (failAfterAdmission.has("evaluator")) throw new Error("EVALUATOR_INTERRUPTED_AFTER_ADMISSION");
      inspection.evaluation = { artifactDigest: digest("5"), resultBytes: 6, artifactBytes: 7 };
      const binding = JSON.parse(readFileSync(join(publicRoot, "case-binding.json"), "utf8")) as Record<string, unknown>;
      writeFileSync(join(publicRoot, "evaluated-conflict.json"), `${JSON.stringify({ caseId: binding.caseId, assetIdentity: binding.assetIdentity })}\n`);
      return { ...inspection.evaluation, durationNanos: 1 } as T;
    }
    if (binary === "decryptor") {
      inspection.releaseAdmission = true;
      if (failAfterAdmission.has("decryptor")) throw new Error("RELEASE_INTERRUPTED_AFTER_ADMISSION");
      inspection.release = {
        resultDigest: digest("6"), conflict: scenario === "conflict", releaseMode: "governed-decryptor-v1",
        resultBytes: 8, exactRetry: true,
        trustedRecoursePins: {
          participantArtifactDigestA: digest("3"), participantArtifactDigestB: digest("4"),
          evaluatedArtifactDigest: digest("5"), recomputedResultCiphertextDigest: digest("7"),
          resultCiphertextCommitment: digest("8"), decryptorProvenance: digest("9"),
          releaseMode: "governed-decryptor-v1", releaseAuthorityId: digest("a"),
        },
      };
      return { ...inspection.release, durationNanos: 1 } as T;
    }
    if (binary === "recourse") {
      return (scenario === "conflict"
        ? { opened: true, record: inspection.recourse }
        : { opened: false, reason: "SIGNED_RESULT_FALSE" }) as T;
    }
    throw new Error(`Unexpected fake binary ${binary}`);
  };
  const base: ProtectionRuntimeOptions = {
    runRoot: join(root, "runs"), binRoot: join(root, "bin"), importedEvidenceRoot: join(root, "retained"),
    binaryRunner: runner, skipBinaryBuild: true, statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
  };
  return { base, calls, failAfterAdmission };
}

function crashing(base: ProtectionRuntimeOptions, target: string) {
  let armed = true;
  return createProtectionOrchestrator({
    ...base,
    failpoint: (name) => {
      if (armed && name === target) {
        armed = false;
        throw new Error(`INJECTED_CRASH:${name}`);
      }
    },
  });
}

async function prepared(base: ProtectionRuntimeOptions) {
  const orchestrator = createProtectionOrchestrator(base);
  let view = await orchestrator.createProtectionCase("no-conflict");
  view = await orchestrator.preparePrivateMatch(view.runId);
  return { orchestrator, view };
}

for (const failpoint of ["after-participant-key-a", "after-both-participant-keys", "after-keygen-before-state-save"] as const) {
  test(`fresh orchestrator reconciles ${failpoint}`, async () => {
    const { base, calls } = await fakeRuntimeRoot();
    const first = crashing(base, failpoint);
    const created = await first.createProtectionCase("no-conflict");
    await assert.rejects(first.preparePrivateMatch(created.runId), /INJECTED_CRASH/);
    const restarted = createProtectionOrchestrator(base);
    const recovered = await restarted.preparePrivateMatch(created.runId);
    assert.equal(recovered.stage, "MATCH_PREPARED");
    assert.equal(calls.get("keygen"), 1);
  });
}

for (const failpoint of ["after-submission-publication-before-unlink", "after-submission-unlink-before-state-save"] as const) {
  test(`published participant artifact reconciles after ${failpoint}`, async () => {
    const { base, calls } = await fakeRuntimeRoot();
    const { view } = await prepared(base);
    const first = crashing(base, failpoint);
    await assert.rejects(first.submitParticipantPledge(view.runId, "PARTICIPANT_A"), /INJECTED_CRASH/);
    const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
    assert.equal(recovered.stage, "PARTICIPANT_A_SUBMITTED");
    assert.equal(calls.get("client"), 1);
  });
}

test("participant B finalization reconciles without a second finalization", async () => {
  const { base, calls } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  const first = crashing(base, "after-participant-b-finalize-before-state-save");
  await assert.rejects(first.submitParticipantPledge(view.runId, "PARTICIPANT_B"), /INJECTED_CRASH/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "PARTICIPANT_B_SUBMITTED");
  assert.equal(calls.get("keygen"), 2);
});

test("completed evaluation reconciles and is never evaluated twice", async () => {
  const { base, calls } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_B");
  const first = crashing(base, "after-evaluation-completion-before-state-save");
  await assert.rejects(first.evaluatePrivateConflict(view.runId), /INJECTED_CRASH/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "EVALUATED");
  assert.equal(calls.get("evaluator"), 1);
});

test("irreversible evaluation admission without a terminal artifact becomes ABORTED", async () => {
  const { base, calls, failAfterAdmission } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_B");
  failAfterAdmission.add("evaluator");
  await assert.rejects(orchestrator.evaluatePrivateConflict(view.runId), /EVALUATOR_INTERRUPTED/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "ABORTED");
  assert.equal(calls.get("evaluator"), 1);
});

test("published governed release reconciles as exact retry without a second signature", async () => {
  const { base, calls } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_B");
  await orchestrator.evaluatePrivateConflict(view.runId);
  const first = crashing(base, "after-release-publication-before-state-save");
  await assert.rejects(first.releaseGovernedResult(view.runId), /INJECTED_CRASH/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "RELEASED");
  assert.equal(recovered.governedResult?.digest, digest("6"));
  assert.equal(calls.get("decryptor"), 1);
});

test("fixed false-recourse request reconciles from its durable outcome", async () => {
  const { base, calls } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_B");
  await orchestrator.evaluatePrivateConflict(view.runId);
  const release = crashing(base, "after-release-publication-before-state-save");
  await assert.rejects(release.releaseGovernedResult(view.runId), /INJECTED_CRASH/);
  const first = crashing(base, "after-recourse-publication-before-state-save");
  await assert.rejects(first.openRecourseCase(view.runId), /INJECTED_CRASH/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "RECOURSE_OPENED");
  assert.equal(recovered.protectionCase.recourseState, "REFUSED");
  assert.equal(calls.get("recourse"), 1);
});

test("case-space preflight uses RUN_ROOT and separately refuses an undersized binary filesystem", async () => {
  const { base, calls } = await fakeRuntimeRoot();
  assert.notEqual(base.runRoot, base.binRoot);
  const orchestrator = createProtectionOrchestrator({
    ...base,
    statfsAvailableBytes: (root) => root === base.runRoot ? Number.MAX_SAFE_INTEGER : 1,
  });
  const created = await orchestrator.createProtectionCase("no-conflict");
  await assert.rejects(orchestrator.preparePrivateMatch(created.runId), (error: unknown) => (
    error instanceof Error && /binaries and bounded Go cache/.test(error.message)
  ));
  assert.equal(calls.get("keygen"), undefined);
});
