import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createProtectionOrchestrator, type ProtectionRuntimeOptions } from "./governed-fhe-product-server";
import type { Sha256Digest } from "./cleanverse-asset";
import { protectionBindingDigest, type MordantProtectionEvidence } from "./protection-evidence";
import type { MordantProtectionBinding } from "./protection-case";
import { readOperationJournal } from "./protection-operation-journal";

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
  foundationPrivateComplete: boolean;
  releasePrivateComplete: boolean;
  release?: {
    resultDigest: Sha256Digest;
    conflict: boolean;
    releaseMode: "governed-decryptor-v1";
    resultBytes: number;
    exactRetry: true;
    trustedRecoursePins: Record<string, unknown>;
  };
  recourse?: Record<string, unknown>;
  protectionBindingDigest?: Sha256Digest;
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
  const inspectArgs: string[][] = [];
  const failAfterAdmission = new Set<string>();
  const runner: NonNullable<ProtectionRuntimeOptions["binaryRunner"]> = async <T>(binary: string, args: readonly string[]) => {
    calls.set(binary, (calls.get(binary) ?? 0) + 1);
    const publicRoot = argument(args, "-public-root");
    const inspection = inspections.get(publicRoot) ?? {
      finalized: false, evaluationAdmission: false, releaseAdmission: false,
      foundationPrivateComplete: false, releasePrivateComplete: false, ambiguous: false,
    };
    inspections.set(publicRoot, inspection);
    if (binary === "inspect") {
      inspectArgs.push([...args]);
      if (argument(args, "-mode") === "pending-private") {
        return {
          finalized: false, evaluationAdmission: false,
          foundationPrivateComplete: inspection.foundation !== undefined,
          releaseAdmission: inspection.releaseAdmission,
          releasePrivateComplete: inspection.release !== undefined,
          ambiguous: false,
        } as T;
      }
      return structuredClone(inspection) as T;
    }
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
      const productDigest = protectionBindingDigest(spec.protectionBinding as MordantProtectionBinding);
      inspection.foundation = { bindingDigest: digest("1"), report: { duration: 1 } };
      inspection.protectionBindingDigest = productDigest;
      return { bindingDigest: digest("1"), protectionBindingDigest: productDigest, durationNanos: 1, report: { duration: 1 } } as T;
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
      if (argument(args, "-mode") === "recourse") {
        const request = JSON.parse(readFileSync(argument(args, "-request"), "utf8")) as Record<string, unknown>;
        assert.deepEqual(Object.keys(request).sort(), ["assetIdentity", "caseId", "expectedPins"]);
        assert.equal(Object.hasOwn(request, "recordDateUnix"), false);
        assert.equal(Object.hasOwn(request, "nowUnix"), false);
      }
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
  return { base, calls, failAfterAdmission, inspectArgs };
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
  await assert.rejects(orchestrator.evaluatePrivateConflict(view.runId), /Governed FHE evaluator operation failed/);
  const recovered = await createProtectionOrchestrator(base).readProtectionCase(view.runId);
  assert.equal(recovered.stage, "ABORTED");
  assert.equal(calls.get("evaluator"), 1);
});

test("published governed release reconciles as exact retry without a second signature", async () => {
  const { base, calls, inspectArgs } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_A");
  await orchestrator.submitParticipantPledge(view.runId, "PARTICIPANT_B");
  await orchestrator.evaluatePrivateConflict(view.runId);
  const first = crashing(base, "after-release-publication-before-state-save");
  await assert.rejects(first.releaseGovernedResult(view.runId), /INJECTED_CRASH/);
  inspectArgs.length = 0;
  const restarted = createProtectionOrchestrator(base);
  const publicOnly = await restarted.readProtectionCase(view.runId);
  assert.equal(publicOnly.stage, "EVALUATED");
  assert.ok(inspectArgs.every((args) => argument(args, "-mode") === "public" && !args.includes("-private-root")));
  const recovered = await restarted.releaseGovernedResult(view.runId);
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

test("public GET/read reconciliation never supplies a private root to the inspector", async () => {
  const { base, inspectArgs } = await fakeRuntimeRoot();
  const { orchestrator, view } = await prepared(base);
  inspectArgs.length = 0;
  await orchestrator.readProtectionCase(view.runId);
  assert.ok(inspectArgs.length >= 1);
  for (const args of inspectArgs) {
    assert.equal(argument(args, "-mode"), "public");
    assert.equal(args.includes("-private-root"), false);
  }
});

test("a truncated pre-foundation participant key is durably recovered", async () => {
  const { base } = await fakeRuntimeRoot();
  const orchestrator = createProtectionOrchestrator(base);
  const created = await orchestrator.createProtectionCase("no-conflict");
  const participantRoot = join(String(base.runRoot), created.runId, "participant-private");
  mkdirSync(participantRoot, { recursive: true });
  const keyPath = join(participantRoot, "participant_a.ed25519");
  writeFileSync(keyPath, Buffer.alloc(7), { mode: 0o600 });
  const preparedView = await orchestrator.preparePrivateMatch(created.runId);
  assert.equal(preparedView.stage, "MATCH_PREPARED");
  assert.equal(readFileSync(keyPath).length, 64);
});

function retainedNoConflict(): MordantProtectionEvidence {
  return JSON.parse(readFileSync(join(
    process.cwd(), "docs", "evidence", "conflicting-pledge-protection", "no-conflict.json",
  ), "utf8")) as MordantProtectionEvidence;
}

const retainedArtifactPath = join(
  process.cwd(), "docs", "evidence", "conflicting-pledge-protection", "no-conflict.json",
);
const artifactTest = existsSync(retainedArtifactPath) ? test : test.skip;

function writeCompleteExecution(root: string, evidence: MordantProtectionEvidence): void {
  const caseRoot = join(root, evidence.runId);
  mkdirSync(caseRoot, { recursive: true });
  writeFileSync(join(caseRoot, "execution.json"), `${JSON.stringify({
    schemaVersion: "mordant.protection-execution/2",
    runId: evidence.runId,
    stage: "COMPLETE",
    protectionCase: evidence.protectionCase,
    paths: {
      root: caseRoot,
      publicRoot: join(caseRoot, "public"),
      decryptorPrivateRoot: join(caseRoot, "decryptor-private"),
      participantPrivateRoot: join(caseRoot, "participant-private"),
    },
    evidence,
    startedAtUnix: evidence.caseAuthorization.binding.createdAtUnix,
  }, null, 2)}\n`);
  writeFileSync(join(caseRoot, "protection-evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
}

artifactTest("interrupted retention resumes through a fresh orchestrator and exact readback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-retention-reconcile-"));
  const evidence = retainedNoConflict();
  const runRoot = join(root, "runs");
  const destinationRoot = join(root, "retained");
  const destination = join(destinationRoot, "no-conflict.json");
  writeCompleteExecution(runRoot, evidence);
  mkdirSync(destinationRoot, { recursive: true });
  const base: ProtectionRuntimeOptions = {
    runRoot,
    binRoot: join(root, "bin"),
    importedEvidenceRoot: destinationRoot,
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    binaryRunner: async <T>(binary: string, args: readonly string[]) => {
      if (binary === "inspect") return { finalized: true, evaluationAdmission: true, releaseAdmission: true, ambiguous: false } as T;
      assert.equal(binary, "retain");
      const target = join(argument(args, "-retention-root"), `${argument(args, "-scenario")}.json`);
      const source = readFileSync(argument(args, "-source"));
      if (existsSync(target)) {
        assert.deepEqual(readFileSync(target), source);
        return { reconciled: true } as T;
      }
      writeFileSync(target, source);
      return { reconciled: false } as T;
    },
  };
  const first = crashing(base, "after-capability-retention-before-readback");
  await assert.rejects(first.retainProtectionEvidence(evidence.runId, destination), /INJECTED_CRASH/);
  assert.equal(existsSync(destination), true);
  const restarted = createProtectionOrchestrator(base);
  await restarted.retainProtectionEvidence(evidence.runId, destination);
  assert.equal((JSON.parse(readFileSync(destination, "utf8")) as MordantProtectionEvidence).manifestDigest, evidence.manifestDigest);
  assert.equal(readOperationJournal(runRoot, evidence.runId).records.at(-1)?.outcome, "RECONCILED");
});

artifactTest("retention rejects a symlink destination without reading or replacing its target", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-retention-symlink-"));
  const evidence = retainedNoConflict();
  const runRoot = join(root, "runs");
  const destinationRoot = join(root, "retained");
  const destination = join(destinationRoot, "no-conflict.json");
  const target = join(root, "outside.json");
  writeCompleteExecution(runRoot, evidence);
  mkdirSync(destinationRoot, { recursive: true });
  writeFileSync(target, "outside\n");
  symlinkSync(target, destination);
  const orchestrator = createProtectionOrchestrator({
    runRoot,
    binRoot: join(root, "bin"),
    importedEvidenceRoot: destinationRoot,
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    binaryRunner: async <T>(binary: string, args: readonly string[]) => {
      if (binary === "inspect") {
        assert.equal(argument(args, "-mode"), "public");
        return {
          finalized: true, evaluationAdmission: true, releaseAdmission: false,
          foundationPrivateComplete: false, releasePrivateComplete: false, ambiguous: false,
        } as T;
      }
      assert.equal(binary, "retain");
      throw new Error("symlink destination rejected");
    },
  });
  await assert.rejects(orchestrator.retainProtectionEvidence(evidence.runId, destination), /retain operation failed/);
  assert.equal(readFileSync(target, "utf8"), "outside\n");
});

artifactTest("published evidence reconciles after crash without a second create-only export", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-evidence-reconcile-"));
  const evidence = retainedNoConflict();
  const runRoot = join(root, "runs");
  const caseRoot = join(runRoot, evidence.runId);
  const publicRoot = join(caseRoot, "public");
  const privateRoot = join(caseRoot, "decryptor-private");
  const participantRoot = join(caseRoot, "participant-private");
  mkdirSync(publicRoot, { recursive: true });
  mkdirSync(privateRoot, { recursive: true });
  mkdirSync(participantRoot, { recursive: true });
  const signedResult = structuredClone(evidence.governedResult) as unknown as Record<string, unknown>;
  delete signedResult.digest;
  for (const [name, value] of [
    ["case-binding.json", evidence.caseAuthorization.binding],
    ["binding-signature-a.json", evidence.caseAuthorization.participantSignatures[0]],
    ["binding-signature-b.json", evidence.caseAuthorization.participantSignatures[1]],
    ["protection-binding.json", evidence.protectionAuthorization.binding],
    ["protection-binding-signature-a.json", evidence.protectionAuthorization.participantSignatures[0]],
    ["protection-binding-signature-b.json", evidence.protectionAuthorization.participantSignatures[1]],
    ["case-crypto.json", { publicKey: evidence.fhe.publicKey }],
    ["evaluated-conflict.json", {
      resultCiphertext: evidence.fhe.resultCiphertext,
      resultCiphertextCommitment: evidence.fhe.resultCiphertextCommitment,
      evaluatorProvenance: evidence.fhe.evaluatorProvenance,
    }],
    ["governed-conflict-result.json", signedResult],
  ] as const) writeFileSync(join(publicRoot, name), `${JSON.stringify(value)}\n`);
  const pins = evidence.governedFheEvidence.measurements.release.trustedRecoursePins;
  const execution = {
    schemaVersion: "mordant.protection-execution/2",
    runId: evidence.runId,
    stage: "RECOURSE_OPENED",
    protectionCase: evidence.protectionCase,
    paths: { root: caseRoot, publicRoot, decryptorPrivateRoot: privateRoot, participantPrivateRoot: participantRoot },
    keygen: {
      bindingDigest: evidence.fhe.caseBindingDigest,
      protectionBindingDigest: evidence.protectionAuthorization.bindingDigest,
      durationNanos: 0,
      report: evidence.governedFheEvidence.measurements.keyGeneration,
    },
    submissions: {
      PARTICIPANT_A: { artifactDigest: evidence.fhe.participantArtifactDigests[0], durationNanos: 0, ciphertextBytes: 1, artifactBytes: 1 },
      PARTICIPANT_B: { artifactDigest: evidence.fhe.participantArtifactDigests[1], durationNanos: 0, ciphertextBytes: 1, artifactBytes: 1 },
    },
    evaluation: { artifactDigest: evidence.fhe.evaluatedArtifactDigest, durationNanos: 0, resultBytes: 1, artifactBytes: 1 },
    release: {
      resultDigest: evidence.governedResult.digest, conflict: false, releaseMode: "governed-decryptor-v1",
      durationNanos: 0, resultBytes: 1, exactRetry: false, trustedRecoursePins: pins,
    },
    recourse: { opened: false, reason: "SIGNED_RESULT_FALSE" },
    startedAtUnix: evidence.caseAuthorization.binding.createdAtUnix,
  };
  writeFileSync(join(caseRoot, "execution.json"), `${JSON.stringify(execution, null, 2)}\n`);
  let attestationExists = false;
  let publicEvidenceExists = false;
  let exports = 0;
  const inspection = {
    foundation: { bindingDigest: evidence.fhe.caseBindingDigest, report: {} },
    submissionA: { artifactDigest: evidence.fhe.participantArtifactDigests[0], ciphertextBytes: 1, artifactBytes: 1 },
    submissionB: { artifactDigest: evidence.fhe.participantArtifactDigests[1], ciphertextBytes: 1, artifactBytes: 1 },
    finalized: true,
    evaluationAdmission: true,
    evaluation: { artifactDigest: evidence.fhe.evaluatedArtifactDigest, resultBytes: 1, artifactBytes: 1 },
    releaseAdmission: true,
    release: {
      resultDigest: evidence.governedResult.digest, conflict: false, releaseMode: "governed-decryptor-v1",
      resultBytes: 1, exactRetry: true, trustedRecoursePins: pins,
    },
    foundationPrivateComplete: false,
    releasePrivateComplete: false,
    protectionBindingDigest: evidence.protectionAuthorization.bindingDigest,
    ambiguous: false,
  };
  const base: ProtectionRuntimeOptions = {
    runRoot,
    binRoot: join(root, "bin"),
    importedEvidenceRoot: join(root, "retained"),
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    binaryRunner: async <T>(binary: string, args: readonly string[]) => {
      if (binary === "inspect") return {
        ...inspection,
        ...(attestationExists ? { recourseAttestationDigest: evidence.recourseAttestation.digest } : {}),
        ...(publicEvidenceExists ? { evidence: evidence.governedFheEvidence } : {}),
      } as T;
      assert.equal(binary, "recourse");
      const mode = argument(args, "-mode");
      if (mode === "attest") {
        attestationExists = true;
        writeFileSync(
          join(publicRoot, "product-recourse-attestation.json"),
          `${JSON.stringify(evidence.recourseAttestation.attestation)}\n`,
        );
        return {
          digest: evidence.recourseAttestation.digest,
          attestation: evidence.recourseAttestation.attestation,
        } as T;
      }
      assert.equal(mode, "evidence");
      assert.equal(attestationExists, true);
      exports += 1;
      publicEvidenceExists = true;
      return evidence.governedFheEvidence as T;
    },
  };
  const previousSource = process.env.MORDANT_PROTECTION_SOURCE_COMMIT;
  process.env.MORDANT_PROTECTION_SOURCE_COMMIT = evidence.sourceCommit;
  try {
    const first = crashing(base, "after-evidence-publication-before-state-save");
    await assert.rejects(first.exportProtectionEvidence(evidence.runId), /INJECTED_CRASH/);
    const recovered = await createProtectionOrchestrator(base).readProtectionCase(evidence.runId);
    assert.equal(recovered.stage, "COMPLETE");
    assert.equal(recovered.evidence?.runId, evidence.runId);
    assert.equal(exports, 1);
  } finally {
    if (previousSource === undefined) delete process.env.MORDANT_PROTECTION_SOURCE_COMMIT;
    else process.env.MORDANT_PROTECTION_SOURCE_COMMIT = previousSource;
  }
});
