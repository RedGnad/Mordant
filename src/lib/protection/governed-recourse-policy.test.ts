import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  GOVERNED_RESULT_EXCLUSIONS,
  GOVERNED_RECOURSE_POLICY_ID,
  MANAGED_DEMO_GOVERNED_RECOURSE_POLICY,
  GovernedRecoursePolicyError,
  authorizeManagedDemoGovernedRecourseOperation,
  evaluateManagedDemoGovernedRecoursePolicy,
  governedRecoursePolicyHash,
  recordManagedDemoGovernedRecourseOperation,
  referenceGovernedActionEvidence,
  selectManagedDemoGovernedRecoursePolicy,
  verifyManagedDemoGovernedRecourseOperationAuthorization,
  verifyManagedDemoGovernedRecourseOperationRecord,
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
  assert.equal(policy.policyHash, "sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e");
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
  assert.equal(plan.cureWindowSeconds, 86_400);
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

test("the selected action authorizes and binds the exact local operation outcome", () => {
  const result = retainedResult("conflict");
  const selection = selectionFor(result);
  const plan = evaluateManagedDemoGovernedRecoursePolicy({
    selection,
    governedResult: result,
  });
  const authorization = authorizeManagedDemoGovernedRecourseOperation({ selection, plan });
  assert.equal(authorization.policySelectionHash, selection.selectionHash);
  assert.equal(authorization.planHash, plan.planHash);
  assert.equal(authorization.selectedGovernedAction, "OPEN_LOCAL_CURE_PATH");
  assert.doesNotThrow(() => verifyManagedDemoGovernedRecourseOperationAuthorization(
    authorization,
    selection,
    plan,
  ));
  const operation = recordManagedDemoGovernedRecourseOperation({
    authorization,
    operationId: "99999999-9999-4999-8999-999999999999",
    operationParametersDigest: `sha256:${"b".repeat(64)}`,
    recourse: {
      opened: true,
      record: {
        caseId: selection.caseId,
        resultDigest: plan.resultDigest,
        boundAtUnix: result.releasedAtUnix + 1,
        cureDeadlineUnix: result.releasedAtUnix + 1 + 86_400,
        open: true,
      },
    },
  });
  assert.equal(operation.operationAuthorizationHash, authorization.authorizationHash);
  assert.equal(operation.cureWindowSeconds, 86_400);
  assert.doesNotThrow(() => verifyManagedDemoGovernedRecourseOperationRecord(operation));

  const evidenceDigest = `sha256:${"a".repeat(64)}` as const;
  const reference = referenceGovernedActionEvidence({ plan, operation, evidenceDigest });
  assert.equal(reference.actionPlanHash, plan.planHash);
  assert.equal(reference.resultDigest, plan.resultDigest);
  assert.equal(reference.operationAuthorizationHash, authorization.authorizationHash);
  assert.equal(reference.operationParametersDigest, operation.operationParametersDigest);
  assert.equal(reference.operationOutcomeDigest, operation.recourseOutcomeDigest);
  assert.equal(reference.operationRecordHash, operation.operationRecordHash);
  assert.equal(reference.evidenceDigest, evidenceDigest);
  assert.equal(reference.evidenceClass, "CUSTOM_SUPERVISED_RECEIPT");
  assert.equal(reference.settlementAuthorization, "NOT_AUTHORIZED");
  assert.throws(() => referenceGovernedActionEvidence({
    plan: { ...plan, actionOwner: "LEGAL_COUNSEL" } as unknown as typeof plan,
    operation,
    evidenceDigest,
  }));
});

test("operation authorization fails closed on altered bindings and cure-window disagreement", () => {
  const result = retainedResult("conflict");
  const selection = selectionFor(result);
  const plan = evaluateManagedDemoGovernedRecoursePolicy({ selection, governedResult: result });
  const authorization = authorizeManagedDemoGovernedRecourseOperation({ selection, plan });
  assert.throws(() => verifyManagedDemoGovernedRecourseOperationAuthorization(
    { ...authorization, planHash: `sha256:${"f".repeat(64)}` },
    selection,
    plan,
  ));
  assert.throws(() => verifyManagedDemoGovernedRecourseOperationAuthorization(
    { ...authorization, policySelectionHash: `sha256:${"e".repeat(64)}` },
    selection,
    plan,
  ));
  assert.throws(() => recordManagedDemoGovernedRecourseOperation({
    authorization,
    operationId: "99999999-9999-4999-8999-999999999999",
    operationParametersDigest: `sha256:${"b".repeat(64)}`,
    recourse: {
      opened: true,
      record: {
        caseId: selection.caseId,
        resultDigest: plan.resultDigest,
        boundAtUnix: result.releasedAtUnix + 1,
        cureDeadlineUnix: result.releasedAtUnix + 1 + 600,
        open: true,
      },
    },
  }), (error) => error instanceof GovernedRecoursePolicyError && error.code === "CURE_WINDOW");
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
