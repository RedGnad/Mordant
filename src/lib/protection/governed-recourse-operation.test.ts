import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import type { Sha256Digest } from "./cleanverse-asset";
import { createProtectionOrchestrator, type ProtectionRuntimeOptions } from "./governed-fhe-product-server";
import {
  evaluateManagedDemoGovernedRecoursePolicy,
  selectManagedDemoGovernedRecoursePolicy,
} from "./governed-recourse-policy";
import { governedResultDigest, type GovernedSignedResult, type MordantProtectionEvidence } from "./protection-evidence";
import { readOperationJournal } from "./protection-operation-journal";

type Scenario = "conflict" | "no-conflict";

function retained(scenario: Scenario): MordantProtectionEvidence {
  return JSON.parse(readFileSync(join(
    process.cwd(),
    "docs",
    "evidence",
    "conflicting-pledge-protection",
    `${scenario}.json`,
  ), "utf8")) as MordantProtectionEvidence;
}

function argument(args: readonly string[], flag: string): string {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1);
  return String(args[index + 1]);
}

async function releasedPolicyHarness(input: Readonly<{
  scenario: Scenario;
  cureWindowSeconds?: number;
  mutateState?: (state: Record<string, unknown>) => void;
}>) {
  const evidence = retained(input.scenario);
  const result = evidence.governedResult as GovernedSignedResult;
  const root = await mkdtemp(join(tmpdir(), "mordant-governed-operation-"));
  const runRoot = join(root, "runs");
  const caseRoot = join(runRoot, evidence.runId);
  const publicRoot = join(caseRoot, "public");
  mkdirSync(publicRoot, { recursive: true });

  const selection = selectManagedDemoGovernedRecoursePolicy({
    caseId: result.caseId,
    resultPolicyId: result.policyId,
    resultPolicyVersion: result.policyVersion,
    selectedAtUnix: result.releasedAtUnix - 1,
  });
  const plan = evaluateManagedDemoGovernedRecoursePolicy({ selection, governedResult: result });
  const createdAt = new Date(evidence.caseAuthorization.binding.createdAtUnix * 1_000).toISOString();
  const state: Record<string, unknown> = {
    schemaVersion: "mordant.protection-execution/2",
    runId: evidence.runId,
    stage: "RELEASED",
    protectionCase: {
      ...evidence.protectionCase,
      timeline: [],
      incidentState: result.conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      cureDeadline: null,
      recourseState: "NOT_OPEN",
      createdAt,
    },
    paths: {
      root: caseRoot,
      publicRoot,
      decryptorPrivateRoot: join(caseRoot, "decryptor-private"),
      participantPrivateRoot: join(caseRoot, "participant-private"),
    },
    release: {
      resultDigest: governedResultDigest(result),
      conflict: result.conflict,
      releaseMode: "governed-decryptor-v1",
      durationNanos: 0,
      resultBytes: 1,
      exactRetry: false,
      trustedRecoursePins: evidence.governedFheEvidence.measurements.release.trustedRecoursePins,
    },
    executionVariant: "CUSTOM_SUPERVISED",
    governedRecoursePolicySelection: selection,
    governedActionPlan: plan,
    startedAtUnix: evidence.caseAuthorization.binding.createdAtUnix,
  };
  input.mutateState?.(state);
  writeFileSync(join(caseRoot, "execution.json"), `${JSON.stringify(state, null, 2)}\n`);

  let recourseCalls = 0;
  const boundAtUnix = result.releasedAtUnix + 1;
  const recourse = result.conflict
    ? {
      opened: true,
      record: {
        caseId: result.caseId,
        resultDigest: governedResultDigest(result),
        boundAtUnix,
        cureDeadlineUnix: boundAtUnix + (input.cureWindowSeconds ?? 86_400),
        open: true,
      },
    } as const
    : { opened: false, reason: "SIGNED_RESULT_FALSE" } as const;
  const options: ProtectionRuntimeOptions = {
    runRoot,
    binRoot: join(root, "bin"),
    importedEvidenceRoot: join(root, "retained"),
    retentionRoot: join(root, "retained"),
    expectedSourceCommit: evidence.sourceCommit,
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    now: () => new Date((result.releasedAtUnix + 2) * 1_000),
    binaryRunner: async <T>(binary: string, args: readonly string[]) => {
      if (binary === "inspect") {
        return {
          finalized: false,
          evaluationAdmission: false,
          releaseAdmission: false,
          foundationPrivateComplete: false,
          releasePrivateComplete: false,
          ambiguous: false,
        } as T;
      }
      assert.equal(binary, "recourse");
      assert.equal(argument(args, "-mode"), "recourse");
      recourseCalls += 1;
      return structuredClone(recourse) as T;
    },
  };
  return {
    caseRoot,
    orchestrator: createProtectionOrchestrator(options),
    plan,
    recourseCalls: () => recourseCalls,
    runId: evidence.runId,
    runRoot,
    selection,
  };
}

for (const scenario of ["conflict", "no-conflict"] as const) {
  test(`managed ${scenario} operation is authorized from the committed action plan`, async () => {
    const harness = await releasedPolicyHarness({ scenario });
    const view = await harness.orchestrator.openRecourseCase(harness.runId);
    assert.equal(view.stage, "RECOURSE_OPENED");
    assert.equal(harness.recourseCalls(), 1);

    const operation = readOperationJournal(harness.runRoot, harness.runId).records.at(-1);
    assert.equal(operation?.operation, "openRecourseCase");
    assert.equal(operation?.outcome, "COMPLETED");
    const authorization = operation?.immutableParameters.governedActionAuthorization as Record<string, unknown>;
    assert.equal(authorization.policySelectionHash, harness.selection.selectionHash);
    assert.equal(authorization.planHash, harness.plan.planHash);
    assert.equal(authorization.selectedGovernedAction, harness.plan.selectedGovernedAction);

    const retainedState = JSON.parse(readFileSync(join(harness.caseRoot, "execution.json"), "utf8")) as Record<string, unknown>;
    const retainedOperation = retainedState.governedRecourseOperation as Record<string, unknown>;
    assert.equal(retainedOperation.operationParametersDigest, operation?.immutableParametersDigest);
    assert.equal(retainedOperation.policySelectionHash, harness.selection.selectionHash);
    assert.equal(retainedOperation.planHash, harness.plan.planHash);
    assert.equal(retainedOperation.selectedGovernedAction, harness.plan.selectedGovernedAction);
    assert.equal(
      retainedOperation.operationOutcome,
      scenario === "conflict" ? "LOCAL_CURE_PATH_OPENED" : "NO_CONFLICT_RECORDED_AND_CLOSED",
    );
    assert.equal(retainedOperation.settlementAuthorization, "NOT_AUTHORIZED");
  });
}

test("missing or altered governed action plans cannot admit the managed operation", async () => {
  const mutations: readonly Readonly<{
    label: string;
    mutate: (state: Record<string, unknown>) => void;
  }>[] = [
    {
      label: "missing plan",
      mutate: (state) => { delete state.governedActionPlan; },
    },
    {
      label: "altered planHash",
      mutate: (state) => {
        state.governedActionPlan = {
          ...(state.governedActionPlan as Record<string, unknown>),
          planHash: `sha256:${"a".repeat(64)}` as Sha256Digest,
        };
      },
    },
    {
      label: "altered policySelectionHash",
      mutate: (state) => {
        state.governedActionPlan = {
          ...(state.governedActionPlan as Record<string, unknown>),
          policySelectionHash: `sha256:${"b".repeat(64)}` as Sha256Digest,
        };
      },
    },
    {
      label: "inconsistent selectedGovernedAction",
      mutate: (state) => {
        state.governedActionPlan = {
          ...(state.governedActionPlan as Record<string, unknown>),
          selectedGovernedAction: "RECORD_AND_CLOSE",
        };
      },
    },
  ];

  for (const mutation of mutations) {
    const harness = await releasedPolicyHarness({ scenario: "conflict", mutateState: mutation.mutate });
    await assert.rejects(harness.orchestrator.openRecourseCase(harness.runId));
    assert.equal(harness.recourseCalls(), 0, mutation.label);
    const state = JSON.parse(readFileSync(join(harness.caseRoot, "execution.json"), "utf8")) as Record<string, unknown>;
    assert.equal(state.governedRecourseOperation, undefined, mutation.label);
    assert.equal(readOperationJournal(harness.runRoot, harness.runId).records.length, 0, mutation.label);
  }
});

test("a cure-window outcome that disagrees with policy cannot be retained or represented", async () => {
  const harness = await releasedPolicyHarness({ scenario: "conflict", cureWindowSeconds: 600 });
  await assert.rejects(
    harness.orchestrator.openRecourseCase(harness.runId),
    /Local cure deadline disagrees with the committed policy/,
  );
  assert.equal(harness.recourseCalls(), 1);
  const state = JSON.parse(readFileSync(join(harness.caseRoot, "execution.json"), "utf8")) as Record<string, unknown>;
  assert.equal(state.stage, "RELEASED");
  assert.equal(state.recourse, undefined);
  assert.equal(state.governedRecourseOperation, undefined);
  await assert.rejects(
    harness.orchestrator.readCustomSupervisedCase(harness.runId),
    /Local cure deadline disagrees with the committed policy/,
  );
});
