import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";

import { createProtectionOrchestrator, type ProtectionRuntimeOptions } from "./governed-fhe-product-server";
import { isPublicProtectionCaseProjection } from "./protection-presentation";
import {
  COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA,
  CUSTOM_SUPERVISED_VIEW_SCHEMA,
  GOVERNED_POLICY_CUSTOM_SUPERVISED_VIEW_SCHEMA,
  parseCustomSupervisedProtectionView,
} from "./custom-supervised-view";

const WINDOWS = {
  participantA: { activeFrom: 120, activeUntil: 420 },
  participantB: { activeFrom: 220, activeUntil: 520 },
} as const;

const CUSTOM_RUN = "77777777-7777-4777-8777-777777777777";
const FIXED_RUN = "88888888-8888-4888-8888-888888888888";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "mordant-custom-view-"));
  const base: ProtectionRuntimeOptions = {
    runRoot: join(root, "runs"),
    binRoot: join(root, "bin"),
    retentionRoot: join(root, "retained"),
    importedEvidenceRoot: join(root, "imported"),
    expectedSourceCommit: "b5587f6489933c6dc462da7fda56e57bd5f9e31b",
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    binaryRunner: async <T>(binary: string) => {
      if (binary !== "inspect") throw new Error(`unexpected binary ${binary}`);
      return {
        finalized: false, evaluationAdmission: false, releaseAdmission: false,
        foundationPrivateComplete: false, releasePrivateComplete: false, ambiguous: false,
      } as T;
    },
  };
  return base;
}

function preReleaseView(runId: string) {
  return {
    schemaVersion: CUSTOM_SUPERVISED_VIEW_SCHEMA,
    runId,
    executionVariant: "CUSTOM_SUPERVISED",
    stage: "CASE_CREATED",
    nextOperation: "preparePrivateMatch",
    terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: `sha256:${"a".repeat(64)}`,
      fheCaseId: `sha256:${"b".repeat(64)}`,
      incidentState: "AUTHORIZED",
      recourseState: "NOT_OPEN",
      cureDeadline: null,
    },
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null,
    governedResult: null,
    recourse: null,
    receipt: null,
  };
}

function releasedView(runId: string, conflict: boolean) {
  return {
    ...preReleaseView(runId),
    stage: "RELEASED",
    nextOperation: "openRecourseCase",
    terminalScenario: conflict ? "conflict" : "no-conflict",
    governedResult: {
      conflict,
      digest: `sha256:${"c".repeat(64)}`,
      releaseMode: "governed-decryptor-v1",
    },
  };
}

test("a custom pre-release view parses and carries no scenario", () => {
  const parsed = parseCustomSupervisedProtectionView(preReleaseView(CUSTOM_RUN));
  assert.notEqual(parsed, null);
  assert.equal(parsed!.terminalScenario, null);
  assert.equal(parsed!.governedResult, null);
  assert.equal(JSON.stringify(parsed).includes("productScenario"), false);
});

test("the V1 guard stays V1-only and never admits a custom execution variant", async () => {
  const base = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  const fixed = await orchestrator.createProtectionCase("conflict", FIXED_RUN);
  const extra = ["incidentState", "cureDeadline", "recourseState"];
  assert.equal(isPublicProtectionCaseProjection(fixed.protectionCase, extra), true);
  // The V1 guard must never be widened to accept the neutral variant. This is
  // what forces a custom run onto its own schema instead of being cast into V1.
  assert.equal(
    isPublicProtectionCaseProjection({ ...fixed.protectionCase, productScenario: "CUSTOM_SUPERVISED" }, extra),
    false,
  );
});

test("a custom run is readable under its own schema", async () => {
  const base = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createProtectionCase("conflict", CUSTOM_RUN, structuredClone(WINDOWS));
  const view = await orchestrator.readCustomSupervisedCase(CUSTOM_RUN);
  const parsed = parseCustomSupervisedProtectionView(view);
  assert.notEqual(parsed, null, "the server view must satisfy its own strict parser");
  assert.equal(parsed!.executionVariant, "CUSTOM_SUPERVISED");
  assert.equal(parsed!.terminalScenario, null);
  assert.equal(parsed!.governedResult, null);
});

test("the managed product commits its policy before result exposure without changing legacy custom creation", async () => {
  const base = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createManagedGovernedPolicyCase(CUSTOM_RUN, structuredClone(WINDOWS));
  const view = await orchestrator.readCustomSupervisedCase(CUSTOM_RUN);
  assert.equal(view.schemaVersion, GOVERNED_POLICY_CUSTOM_SUPERVISED_VIEW_SCHEMA);
  assert.equal(view.governedResult, null);
  if (view.schemaVersion !== GOVERNED_POLICY_CUSTOM_SUPERVISED_VIEW_SCHEMA) assert.fail("expected V2 view");
  assert.equal(view.governedPolicy.selection.caseId, view.protectionCase.fheCaseId);
  assert.equal(view.governedPolicy.selection.policyId, "mordant.managed-demo.facility-protection");
  assert.equal(view.governedPolicy.actionPlan, null);
  assert.equal(view.governedPolicy.actionEvidence, null);
  assert.notEqual(parseCustomSupervisedProtectionView(view), null);
});

test("a fixed run is refused by the custom readback", async () => {
  const base = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createProtectionCase("conflict", FIXED_RUN);
  await assert.rejects(
    () => orchestrator.readCustomSupervisedCase(FIXED_RUN),
    /not a supervised custom case/,
  );
});

test("terminalScenario must follow the governed Boolean, in both directions", () => {
  const trueView = parseCustomSupervisedProtectionView(releasedView(CUSTOM_RUN, true));
  assert.equal(trueView!.terminalScenario, "conflict");
  const falseView = parseCustomSupervisedProtectionView(releasedView(CUSTOM_RUN, false));
  assert.equal(falseView!.terminalScenario, "no-conflict");
});

test("every dishonest custom view is refused", () => {
  const cases: Record<string, unknown> = {
    "pre-release claiming a scenario": { ...preReleaseView(CUSTOM_RUN), terminalScenario: "conflict" },
    "terminal scenario disagreeing with the Boolean": { ...releasedView(CUSTOM_RUN, true), terminalScenario: "no-conflict" },
    "carrying a product scenario": {
      ...preReleaseView(CUSTOM_RUN),
      protectionCase: { ...preReleaseView(CUSTOM_RUN).protectionCase, productScenario: "conflict" },
    },
    "carrying raw windows": { ...preReleaseView(CUSTOM_RUN), pledges: WINDOWS },
    "wrong schema": { ...preReleaseView(CUSTOM_RUN), schemaVersion: "mordant.protection-product-view/1" },
    "wrong execution variant": { ...preReleaseView(CUSTOM_RUN), executionVariant: "OTHER" },
    "unknown member": { ...preReleaseView(CUSTOM_RUN), extra: 1 },
    "receipt disagreeing with the Boolean": {
      ...releasedView(CUSTOM_RUN, true),
      receipt: { governedResult: { conflict: false } },
    },
  };
  for (const [name, value] of Object.entries(cases)) {
    assert.equal(parseCustomSupervisedProtectionView(value), null, `${name} must be refused`);
  }
});

function coalitionReleasedView(runId: string, policyConflict: boolean) {
  const base = preReleaseView(runId);
  return {
    ...base,
    schemaVersion: COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA,
    stage: "RELEASED",
    nextOperation: null,
    terminalScenario: policyConflict ? "conflict" : "no-conflict",
    protectionCase: { ...base.protectionCase, incidentState: policyConflict ? "CONFLICT_CONFIRMED" : "CLEARED" },
    governedResult: {
      digest: `sha256:${"c".repeat(64)}`,
      releaseMode: "coalition-v5",
      sameEconomicAsset: true,
      policyConflict,
      threshold: 2,
      coalition: [1, 3],
      operatorTopology: "colocated-single-process",
    },
    settlement: policyConflict
      ? {
        status: "EXECUTION_READY",
        settlementProfileDigest: `0x${"d".repeat(64)}`,
        planHash: `0x${"e".repeat(64)}`,
        authorizationHash: `0x${"f".repeat(64)}`,
      }
      : {
        status: "NO_CONFLICT_NO_SETTLEMENT",
        settlementProfileDigest: `0x${"d".repeat(64)}`,
        planHash: null,
        authorizationHash: null,
      },
  };
}

test("a coalition case is created under its own view schema, with nothing released", async () => {
  const base = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createManagedCoalitionCase(CUSTOM_RUN, structuredClone(WINDOWS));
  const view = await orchestrator.readCustomSupervisedCase(CUSTOM_RUN);
  assert.equal(view.schemaVersion, COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA);
  assert.equal(view.governedResult, null);
  if (view.schemaVersion !== COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA) assert.fail("expected the coalition view");
  assert.equal(view.settlement, null);
  assert.equal(view.terminalScenario, null);
  assert.notEqual(parseCustomSupervisedProtectionView(view), null);
});

test("a released coalition view carries both bits separately and its settlement projection", () => {
  const confirmed = parseCustomSupervisedProtectionView(coalitionReleasedView(CUSTOM_RUN, true));
  assert.notEqual(confirmed, null);
  if (confirmed?.schemaVersion !== COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA) assert.fail("expected the coalition view");
  assert.equal(confirmed.governedResult?.sameEconomicAsset, true);
  assert.equal(confirmed.governedResult?.policyConflict, true);
  assert.equal(confirmed.settlement?.status, "EXECUTION_READY");
  assert.equal(confirmed.terminalScenario, "conflict");

  const cleared = parseCustomSupervisedProtectionView(coalitionReleasedView(CUSTOM_RUN, false));
  assert.notEqual(cleared, null);
  if (cleared?.schemaVersion !== COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA) assert.fail("expected the coalition view");
  assert.equal(cleared.governedResult?.sameEconomicAsset, true);
  assert.equal(cleared.governedResult?.policyConflict, false);
  assert.equal(cleared.settlement?.status, "NO_CONFLICT_NO_SETTLEMENT");
  assert.equal(cleared.settlement?.planHash, null);
  assert.equal(cleared.terminalScenario, "no-conflict");
});

test("every dishonest coalition view is refused", () => {
  const conflict = coalitionReleasedView(CUSTOM_RUN, true);
  const cleared = coalitionReleasedView(CUSTOM_RUN, false);
  const cases: Record<string, unknown> = {
    "the bit combination the circuit cannot produce": {
      ...conflict,
      governedResult: { ...conflict.governedResult, sameEconomicAsset: false },
      terminalScenario: "conflict",
    },
    "the two bits recompressed into one canonical Boolean": {
      ...conflict,
      governedResult: { ...conflict.governedResult, conflict: true },
    },
    "a released view without its settlement projection": { ...conflict, settlement: null },
    "an execution-ready settlement on a cleared run": { ...cleared, settlement: conflict.settlement },
    "a cleared settlement on a confirmed run": { ...conflict, settlement: cleared.settlement },
    "a governed release mode inside the coalition view": {
      ...conflict,
      governedResult: { ...conflict.governedResult, releaseMode: "governed-decryptor-v1" },
    },
    "a serving coalition smaller than its quorum": {
      ...conflict,
      governedResult: { ...conflict.governedResult, coalition: [1] },
    },
    "a recourse decision in the coalition milestone": {
      ...conflict,
      recourse: { opened: true, reason: null },
    },
    "a terminal scenario disagreeing with the policy bit": { ...conflict, terminalScenario: "no-conflict" },
    "a settlement before any release": { ...preReleaseView(CUSTOM_RUN), schemaVersion: COALITION_CUSTOM_SUPERVISED_VIEW_SCHEMA, settlement: cleared.settlement },
  };
  for (const [name, value] of Object.entries(cases)) {
    assert.equal(parseCustomSupervisedProtectionView(value), null, `${name} must be refused`);
  }
});
