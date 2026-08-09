import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  GOVERNED_RESULT_EXCLUSIONS,
  GOVERNED_RECOURSE_POLICY_ID,
  MANAGED_DEMO_GOVERNED_RECOURSE_POLICY,
  GovernedRecoursePolicyError,
  evaluateManagedDemoGovernedRecoursePolicy,
  governedRecoursePolicyHash,
  referenceGovernedActionEvidence,
  selectManagedDemoGovernedRecoursePolicy,
  verifyManagedDemoGovernedRecoursePolicySelection,
} from "./governed-recourse-policy";
import { type GovernedSignedResult } from "./protection-evidence";

function retainedResult(scenario: "conflict" | "no-conflict"): GovernedSignedResult {
  const retained = JSON.parse(readFileSync(join(
    process.cwd(),
    "docs",
    "evidence",
    "conflicting-pledge-protection",
    `${scenario}.json`,
  ), "utf8")) as Readonly<{ governedResult: GovernedSignedResult }>;
  return structuredClone(retained.governedResult);
}

function selectionFor(result: GovernedSignedResult, selectedAtUnix = result.releasedAtUnix - 60) {
  return selectManagedDemoGovernedRecoursePolicy({
    caseId: result.caseId,
    resultPolicyId: result.policyId,
    resultPolicyVersion: result.policyVersion,
    selectedAtUnix,
  });
}

test("the promoted policy is one bounded, versioned first workflow", () => {
  const policy = MANAGED_DEMO_GOVERNED_RECOURSE_POLICY;
  assert.equal(policy.policyId, GOVERNED_RECOURSE_POLICY_ID);
  assert.equal(policy.policyVersion, 1);
  assert.equal(policy.workflow.label, "Conflicting Pledge Protection");
  assert.equal(policy.workflow.productPosition, "FIRST_IMPLEMENTED_WORKFLOW");
  assert.deepEqual(policy.governedResultContract.establishesOnly, ["CONFLICT", "NO_CONFLICT"]);
  assert.deepEqual(policy.governedResultContract.doesNotEstablish, GOVERNED_RESULT_EXCLUSIONS);
  assert.equal(policy.conflict.settlementAuthorization, "NOT_AUTHORIZED");
  assert.equal(policy.noConflict.settlementAuthorization, "NOT_AUTHORIZED");
  assert.equal(governedRecoursePolicyHash(), policy.policyHash);
  assert.equal(policy.policyHash, "sha256:33a5455061a346bd9fe4b5353c5f292d8015dc8f73c63cdf405b5f7f3d14fa09");
});

test("policy selection is committed and verifiable before governed-result exposure", () => {
  const result = retainedResult("conflict");
  const selection = selectionFor(result);
  assert.doesNotThrow(() => verifyManagedDemoGovernedRecoursePolicySelection(selection));
  assert.equal(selection.policyHash, MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.policyHash);
  assert.equal(selection.caseId, result.caseId);

  const tampered = { ...selection, selectedAtUnix: selection.selectedAtUnix - 1 };
  assert.throws(
    () => verifyManagedDemoGovernedRecoursePolicySelection(tampered),
    (error) => error instanceof GovernedRecoursePolicyError && error.code === "SELECTION",
  );
  assert.throws(() => verifyManagedDemoGovernedRecoursePolicySelection({
    ...selection,
    legalPriority: "FIRST",
  } as unknown as typeof selection));
  assert.throws(
    () => evaluateManagedDemoGovernedRecoursePolicy({
      selection: selectionFor(result, result.releasedAtUnix),
      governedResult: result,
    }),
    (error) => error instanceof GovernedRecoursePolicyError && error.code === "POLICY_SHOPPING",
  );
});

test("conflict selects only the configured local cure path", () => {
  const result = retainedResult("conflict");
  const plan = evaluateManagedDemoGovernedRecoursePolicy({
    selection: selectionFor(result),
    governedResult: result,
  });
  assert.equal(plan.resultOutcome, "CONFLICT");
  assert.equal(plan.resultSemantic, "CONFLICT_STATUS_ONLY");
  assert.equal(plan.selectedGovernedAction, "OPEN_LOCAL_CURE_PATH");
  assert.equal(plan.actionOwner, "MORDANT_MANAGED_EXECUTION");
  assert.equal(plan.cureWindowSeconds, 600);
  assert.equal(plan.deadlineRule, "STARTS_WHEN_LOCAL_CURE_PATH_OPENS");
  assert.equal(plan.escalation, "MANUAL_REVIEW_OUTSIDE_MANAGED_RUN");
  assert.equal(plan.requiredApproval, "NONE_FOR_LOCAL_PROTOCOL_DOUBLE");
  assert.equal(plan.actionClass, "LOCAL_PROTOCOL_DOUBLE");
  assert.equal(plan.settlementAuthorization, "NOT_AUTHORIZED");
});

test("no conflict selects evidence-only close and no cure deadline", () => {
  const result = retainedResult("no-conflict");
  const plan = evaluateManagedDemoGovernedRecoursePolicy({
    selection: selectionFor(result),
    governedResult: result,
  });
  assert.equal(plan.resultOutcome, "NO_CONFLICT");
  assert.equal(plan.selectedGovernedAction, "RECORD_AND_CLOSE");
  assert.equal(plan.cureWindowSeconds, null);
  assert.equal(plan.deadlineRule, "NOT_APPLICABLE");
  assert.equal(plan.escalation, "NONE");
  assert.equal(plan.actionClass, "EVIDENCE_ONLY");
  assert.equal(plan.settlementAuthorization, "NOT_AUTHORIZED");
});

test("the policy refuses another case and any altered signed result", () => {
  const conflict = retainedResult("conflict");
  const noConflict = retainedResult("no-conflict");
  assert.throws(
    () => evaluateManagedDemoGovernedRecoursePolicy({
      selection: selectionFor(conflict),
      governedResult: noConflict,
    }),
  );
  const altered = { ...conflict, conflict: false } as GovernedSignedResult;
  assert.throws(() => evaluateManagedDemoGovernedRecoursePolicy({
    selection: selectionFor(conflict),
    governedResult: altered,
  }));
});

test("action evidence references existing receipt bytes without authorizing settlement", () => {
  const result = retainedResult("conflict");
  const plan = evaluateManagedDemoGovernedRecoursePolicy({
    selection: selectionFor(result),
    governedResult: result,
  });
  const evidenceDigest = `sha256:${"a".repeat(64)}` as const;
  const reference = referenceGovernedActionEvidence({ plan, evidenceDigest });
  assert.equal(reference.actionPlanHash, plan.planHash);
  assert.equal(reference.resultDigest, plan.resultDigest);
  assert.equal(reference.evidenceDigest, evidenceDigest);
  assert.equal(reference.evidenceClass, "CUSTOM_SUPERVISED_RECEIPT");
  assert.equal(reference.settlementAuthorization, "NOT_AUTHORIZED");
  assert.throws(() => referenceGovernedActionEvidence({
    plan: { ...plan, actionOwner: "LEGAL_COUNSEL" } as unknown as typeof plan,
    evidenceDigest,
  }));
});

test("the policy module has no settlement, wallet, contract or workflow-engine capability", () => {
  const source = readFileSync(join(
    process.cwd(),
    "src",
    "lib",
    "protection",
    "governed-recourse-policy.ts",
  ), "utf8");
  for (const forbiddenImport of ["viem", "wagmi", "child_process", "node:http", "node:fs", "contracts/"]) {
    assert.equal(source.includes(`from \"${forbiddenImport}`), false, `policy imported ${forbiddenImport}`);
  }
  for (const forbiddenPrimitive of ["eval(", "new Function", "arbitraryRule", "workflowDsl", "legalPriorityRule"]) {
    assert.equal(source.includes(forbiddenPrimitive), false, `policy exposed ${forbiddenPrimitive}`);
  }
});
