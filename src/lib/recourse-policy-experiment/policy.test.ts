import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import test from "node:test";

import {
  approveProposedAction,
  authorizeAction,
  bindPolicy,
  completeGovernedActionPath,
  createExperimentalCase,
  evaluatePolicy,
  expireReview,
  exposeGovernedResult,
  recordAuthorizedAction,
  type ExperimentalCase,
} from "./engine";
import {
  EXPERIMENTAL_POLICIES,
  FACILITY_PROTECTION_POLICY,
  MANUAL_ESCALATION_POLICY,
  PROTOTYPE_SIGNERS,
  RETAINED_CONFLICT_RESULT_PATH,
  RETAINED_GOVERNED_RESULTS,
  RETAINED_NO_CONFLICT_RESULT_PATH,
} from "./fixtures";
import {
  EXPERIMENT_PROGRAM_ID,
  RecoursePolicyError,
  createGovernanceApprovalEvent,
  digestValue,
  signPolicyManifest,
  verifyGovernanceApprovalEvent,
  verifyGovernedActionReceipt,
  verifyPolicyManifest,
  verifyPolicySelectionEvent,
  type GovernedActionReceipt,
  type GovernedRecoursePolicy,
  type UnsignedGovernedRecoursePolicy,
} from "./policy";

const BASE = Date.parse("2026-08-09T10:00:00.000Z") / 1000;

function clone<T>(value: T): T {
  return structuredClone(value);
}

function expectCode(code: string, action: () => unknown): void {
  assert.throws(action, (error: unknown) => error instanceof RecoursePolicyError && error.code === code);
}

function unsigned(policy: GovernedRecoursePolicy): UnsignedGovernedRecoursePolicy {
  const draft = clone(policy) as unknown as Record<string, unknown>;
  delete draft.policyAuthority;
  delete draft.digest;
  delete draft.signature;
  return draft as unknown as UnsignedGovernedRecoursePolicy;
}

function resign(
  policy: GovernedRecoursePolicy,
  mutate: (draft: Record<string, unknown>) => void,
): GovernedRecoursePolicy {
  const draft = unsigned(policy) as unknown as Record<string, unknown>;
  mutate(draft);
  return signPolicyManifest(draft as unknown as UnsignedGovernedRecoursePolicy, PROTOTYPE_SIGNERS.policyAuthority);
}

function reviewed(policy = FACILITY_PROTECTION_POLICY): ExperimentalCase {
  const result = RETAINED_GOVERNED_RESULTS.conflict;
  let state = createExperimentalCase({
    caseId: result.caseId,
    assetIdentity: result.assetIdentity,
    runId: `reviewed-${policy.policyId}`,
    authorizedAtUnix: BASE,
  });
  state = bindPolicy({
    state,
    policy,
    selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1,
    applicabilityAtUnix: BASE + 1,
    nonce: `selection-${policy.policyId}`,
  });
  state = exposeGovernedResult({
    state,
    governedResult: result,
    sourcePath: RETAINED_CONFLICT_RESULT_PATH,
    exposedAtUnix: BASE + 2,
  });
  return evaluatePolicy(state, BASE + 3);
}

function completed(
  policy = FACILITY_PROTECTION_POLICY,
  runId = `completed-${policy.policyId}`,
) {
  const facility = policy.policyId === FACILITY_PROTECTION_POLICY.policyId;
  return completeGovernedActionPath({
    policy,
    governedResult: RETAINED_GOVERNED_RESULTS.conflict,
    sourcePath: RETAINED_CONFLICT_RESULT_PATH,
    selector: PROTOTYPE_SIGNERS.selector,
    approver: facility ? PROTOTYPE_SIGNERS.creditOpsApprover : PROTOTYPE_SIGNERS.institutionalReviewer,
    approverRole: facility ? "CREDIT_OPS_APPROVER" : "INSTITUTIONAL_REVIEWER",
    recorder: PROTOTYPE_SIGNERS.actionRecorder,
    runId,
    authorizedAtUnix: BASE,
    selectedAtUnix: BASE + 1,
    resultExposedAtUnix: BASE + 2,
    evaluatedAtUnix: BASE + 3,
    approvalIssuedAtUnix: BASE + 4,
    approvalExpiresAtUnix: BASE + 600,
    actionAuthorizedAtUnix: BASE + 5,
    actionRecordedAtUnix: BASE + 6,
  });
}

test("the experiment admits exactly two deeply immutable policies with separate identities", () => {
  assert.equal(EXPERIMENTAL_POLICIES.length, 2);
  assert.deepEqual(EXPERIMENTAL_POLICIES.map((policy) => policy.policyId), [
    "mordant.experimental.facility-protection",
    "mordant.experimental.manual-escalation",
  ]);
  assert.ok(EXPERIMENTAL_POLICIES.every((policy) => !policy.policyId.startsWith("sha256:")));
  assert.ok(EXPERIMENTAL_POLICIES.every((policy) => Object.isFrozen(policy) && Object.isFrozen(policy.conflictBranch)));
  assert.ok(EXPERIMENTAL_POLICIES.every((policy) => policy.settlement.permission === "PROHIBITED"));
  EXPERIMENTAL_POLICIES.forEach(verifyPolicyManifest);
});

test("changing any policy body member changes the signed policy digest", () => {
  const changed = resign(FACILITY_PROTECTION_POLICY, (draft) => {
    draft.effectiveUntilUnix = Number(draft.effectiveUntilUnix) - 1;
  });
  assert.notEqual(changed.digest, FACILITY_PROTECTION_POLICY.digest);
});

test("closed policy schema rejects arbitrary calldata or conditions", () => {
  const policy = clone(FACILITY_PROTECTION_POLICY) as unknown as Record<string, unknown>;
  policy.calldata = "0xdeadbeef";
  expectCode("POLICY_FIELDS", () => verifyPolicyManifest(policy));

  const branchPolicy = clone(FACILITY_PROTECTION_POLICY) as unknown as Record<string, unknown>;
  (branchPolicy.conflictBranch as Record<string, unknown>).condition = "amount > 0";
  expectCode("POLICY_BRANCH_FIELDS", () => verifyPolicyManifest(branchPolicy));
});

test("policy is selected before exposure and cannot be replaced afterward", () => {
  const result = RETAINED_GOVERNED_RESULTS.conflict;
  let state = createExperimentalCase({ caseId: result.caseId, assetIdentity: result.assetIdentity, authorizedAtUnix: BASE, runId: "no-shopping" });
  state = bindPolicy({
    state,
    policy: FACILITY_PROTECTION_POLICY,
    selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1,
    applicabilityAtUnix: BASE + 1,
    nonce: "no-shopping-selection",
  });
  state = exposeGovernedResult({ state, governedResult: result, sourcePath: RETAINED_CONFLICT_RESULT_PATH, exposedAtUnix: BASE + 2 });
  expectCode("ACTION_STATE", () => bindPolicy({
    state,
    policy: MANUAL_ESCALATION_POLICY,
    selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 3,
    applicabilityAtUnix: BASE + 3,
    nonce: "late-replacement",
  }));
  expectCode("POST_RESULT_POLICY_SELECTION", () => verifyPolicySelectionEvent(
    state.selection,
    state.policy!,
    BASE + 1,
  ));
});

test("expired and not-yet-effective policies fail closed", () => {
  const result = RETAINED_GOVERNED_RESULTS.conflict;
  const baseCase = () => createExperimentalCase({ caseId: result.caseId, assetIdentity: result.assetIdentity, authorizedAtUnix: BASE, runId: `effective-${Math.random()}` });
  const expired = resign(FACILITY_PROTECTION_POLICY, (draft) => {
    draft.effectiveFromUnix = BASE - 200;
    draft.effectiveUntilUnix = BASE - 100;
  });
  const future = resign(FACILITY_PROTECTION_POLICY, (draft) => {
    draft.effectiveFromUnix = BASE + 100;
    draft.effectiveUntilUnix = BASE + 200;
  });
  expectCode("POLICY_EXPIRED", () => bindPolicy({
    state: baseCase(), policy: expired, selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1, applicabilityAtUnix: BASE + 1, nonce: "expired",
  }));
  expectCode("POLICY_NOT_YET_EFFECTIVE", () => bindPolicy({
    state: baseCase(), policy: future, selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1, applicabilityAtUnix: BASE + 1, nonce: "future",
  }));
});

test("wrong asset and program scopes fail closed", () => {
  const wrongAsset = resign(FACILITY_PROTECTION_POLICY, (draft) => {
    (draft.scope as Record<string, unknown>).assetIdentity = digestValue({ asset: "wrong" });
  });
  const result = RETAINED_GOVERNED_RESULTS.conflict;
  const state = createExperimentalCase({ caseId: result.caseId, assetIdentity: result.assetIdentity, authorizedAtUnix: BASE, runId: "scope" });
  expectCode("POLICY_SCOPE_MISMATCH", () => bindPolicy({
    state, policy: wrongAsset, selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1, applicabilityAtUnix: BASE + 1, nonce: "wrong-asset",
  }));

  const wrongProgram = unsigned(FACILITY_PROTECTION_POLICY) as unknown as Record<string, unknown>;
  (wrongProgram.scope as Record<string, unknown>).programId = "another-program";
  expectCode("POLICY_SCOPE", () => signPolicyManifest(
    wrongProgram as unknown as UnsignedGovernedRecoursePolicy,
    PROTOTYPE_SIGNERS.policyAuthority,
  ));
});

test("governed-result semantic or schema mismatch fails", () => {
  const wrongSemantic = unsigned(FACILITY_PROTECTION_POLICY) as unknown as Record<string, unknown>;
  (wrongSemantic.acceptedGovernedResult as Record<string, unknown>).semantic = "LEGAL_DEFAULT";
  expectCode("POLICY_RESULT_SEMANTIC", () => signPolicyManifest(
    wrongSemantic as unknown as UnsignedGovernedRecoursePolicy,
    PROTOTYPE_SIGNERS.policyAuthority,
  ));
});

test("the retained result remains immutable and is verified without changing its bytes", () => {
  const original = JSON.stringify(RETAINED_GOVERNED_RESULTS.conflict);
  reviewed();
  assert.equal(JSON.stringify(RETAINED_GOVERNED_RESULTS.conflict), original);
});

test("unauthorized approver and approval for another action digest fail", () => {
  const state = reviewed();
  expectCode("UNAUTHORIZED_APPROVER", () => approveProposedAction({
    state,
    approverRole: "INSTITUTIONAL_REVIEWER",
    approver: PROTOTYPE_SIGNERS.institutionalReviewer,
    nonce: "unauthorized",
    issuedAtUnix: BASE + 4,
    expiresAtUnix: BASE + 100,
  }));

  const approved = approveProposedAction({
    state,
    approverRole: "CREDIT_OPS_APPROVER",
    approver: PROTOTYPE_SIGNERS.creditOpsApprover,
    nonce: "exact-action",
    issuedAtUnix: BASE + 4,
    expiresAtUnix: BASE + 100,
  });
  const approval = clone(approved.approval!) as unknown as Record<string, unknown>;
  approval.proposedActionDigest = digestValue({ another: "action" });
  expectCode("APPROVAL_ACTION_BINDING", () => verifyGovernanceApprovalEvent({
    event: approval,
    proposedAction: approved.proposedAction!,
    expectedPreviousEventDigest: approved.approval!.previousEventDigest,
    atUnix: BASE + 5,
  }));
});

test("expired approvals and replayed approval nonces fail", () => {
  let state = reviewed();
  state = approveProposedAction({
    state,
    approverRole: "CREDIT_OPS_APPROVER",
    approver: PROTOTYPE_SIGNERS.creditOpsApprover,
    nonce: "bounded-approval",
    issuedAtUnix: BASE + 4,
    expiresAtUnix: BASE + 10,
  });
  expectCode("APPROVAL_EXPIRED", () => authorizeAction(state, BASE + 11));
  expectCode("APPROVAL_REPLAY", () => verifyGovernanceApprovalEvent({
    event: state.approval,
    proposedAction: state.proposedAction!,
    expectedPreviousEventDigest: state.approval!.previousEventDigest,
    atUnix: BASE + 5,
    consumedNonces: new Set(["bounded-approval"]),
  }));
});

test("human-required actions cannot authorize without approval and review expiry escalates", () => {
  const state = reviewed();
  expectCode("ACTION_STATE", () => authorizeAction(state, BASE + 4));
  const expired = expireReview(state, state.proposedAction!.approvalExpiresAtUnix! + 1);
  assert.equal(expired.currentState, "ESCALATION_REQUIRED");
  assert.deepEqual(expired.history.slice(-2).map((event) => event.toState), ["REVIEW_EXPIRED", "ESCALATION_REQUIRED"]);
});

test("automatic no-conflict branch needs no approval and refuses a fake approval", () => {
  const result = RETAINED_GOVERNED_RESULTS.noConflict;
  let state = createExperimentalCase({ caseId: result.caseId, assetIdentity: result.assetIdentity, authorizedAtUnix: BASE, runId: "automatic" });
  state = bindPolicy({
    state,
    policy: FACILITY_PROTECTION_POLICY,
    selector: PROTOTYPE_SIGNERS.selector,
    selectedAtUnix: BASE + 1,
    applicabilityAtUnix: BASE + 1,
    nonce: "automatic-selection",
  });
  state = exposeGovernedResult({ state, governedResult: result, sourcePath: RETAINED_NO_CONFLICT_RESULT_PATH, exposedAtUnix: BASE + 2 });
  state = evaluatePolicy(state, BASE + 3);
  assert.equal(state.currentState, "POLICY_EVALUATED");
  assert.equal(state.proposedAction?.actionType, "RECORD_AND_CLOSE");
  assert.equal(state.approval, null);
  expectCode("APPROVAL_NOT_REQUIRED", () => createGovernanceApprovalEvent({
    proposedAction: state.proposedAction!,
    approverRole: "CREDIT_OPS_APPROVER",
    nonce: "fake-approval",
    issuedAtUnix: BASE + 4,
    expiresAtUnix: BASE + 5,
    previousEventDigest: state.history.at(-1)!.digest,
  }, PROTOTYPE_SIGNERS.creditOpsApprover));
  state = authorizeAction(state, BASE + 4);
  const path = recordAuthorizedAction({ state, recorder: PROTOTYPE_SIGNERS.actionRecorder, recordedAtUnix: BASE + 5 });
  assert.equal(path.state.receipt?.approvalEventDigest, null);
  assert.equal(path.state.currentState, "ACTION_RECORDED");
});

test("same governed conflict fact produces two distinct policy-governed action paths", () => {
  const facility = completed(FACILITY_PROTECTION_POLICY, "same-fact-facility");
  const manual = completed(MANUAL_ESCALATION_POLICY, "same-fact-manual");
  assert.equal(facility.state.receipt?.governedResult.digest, manual.state.receipt?.governedResult.digest);
  assert.equal(facility.state.receipt?.resultingAction.actionType, "OPEN_CURE_PATH");
  assert.equal(manual.state.receipt?.resultingAction.actionType, "MANUAL_ESCALATION");
  assert.notEqual(facility.state.receipt?.policy.digest, manual.state.receipt?.policy.digest);
});

test("tampering action, deadline, or configuration reference invalidates receipt verification", () => {
  const path = completed();
  const context = {
    policy: path.state.policy!,
    selection: path.state.selection!,
    approval: path.state.approval,
    proposedAction: path.state.proposedAction!,
    authorizationEvent: path.authorizationEvent,
  };
  const mutations: Array<(receipt: Record<string, unknown>) => void> = [
    (receipt) => { (receipt.resultingAction as Record<string, unknown>).actionType = "MANUAL_ESCALATION"; },
    (receipt) => { (receipt.resultingAction as Record<string, unknown>).operationalDeadlineUnix = BASE + 999; },
    (receipt) => { (receipt.resultingAction as Record<string, unknown>).actionConfigurationDigest = digestValue({ tampered: true }); },
  ];
  for (const mutate of mutations) {
    const receipt = clone(path.state.receipt!) as unknown as Record<string, unknown>;
    mutate(receipt);
    assert.throws(() => verifyGovernedActionReceipt({ receipt, ...context }));
  }
});

test("tampering any referenced policy, selection, approval, or transition invalidates the evidence chain", () => {
  const path = completed();
  const base = {
    receipt: path.state.receipt!,
    policy: path.state.policy!,
    selection: path.state.selection!,
    approval: path.state.approval,
    proposedAction: path.state.proposedAction!,
    authorizationEvent: path.authorizationEvent,
  };
  const policy = clone(base.policy) as unknown as Record<string, unknown>;
  policy.policyVersion = 2;
  assert.throws(() => verifyGovernedActionReceipt({ ...base, policy: policy as unknown as GovernedRecoursePolicy }));
  const selection = clone(base.selection) as unknown as Record<string, unknown>;
  selection.nonce = "changed";
  assert.throws(() => verifyGovernedActionReceipt({ ...base, selection: selection as never }));
  const approval = clone(base.approval!) as unknown as Record<string, unknown>;
  approval.nonce = "changed";
  assert.throws(() => verifyGovernedActionReceipt({ ...base, approval: approval as never }));
  const receipt = clone(base.receipt) as unknown as GovernedActionReceipt;
  const authorizationEvent = clone(base.authorizationEvent) as unknown as Record<string, unknown>;
  authorizationEvent.digest = digestValue({ wrong: "head" });
  assert.throws(() => verifyGovernedActionReceipt({ ...base, receipt, authorizationEvent: authorizationEvent as never }));
});

test("settlement-permitted policy without an exact configuration digest fails", () => {
  const draft = unsigned(FACILITY_PROTECTION_POLICY) as unknown as Record<string, unknown>;
  (draft.settlement as Record<string, unknown>).permission = "PERMITTED";
  (draft.settlement as Record<string, unknown>).configurationDigest = null;
  expectCode("POLICY_SETTLEMENT_CONFIG", () => signPolicyManifest(
    draft as unknown as UnsignedGovernedRecoursePolicy,
    PROTOTYPE_SIGNERS.policyAuthority,
  ));
});

function resolveImport(from: string, specifier: string): string | null {
  const base = specifier.startsWith("@/")
    ? resolve(process.cwd(), "src", specifier.slice(2))
    : specifier.startsWith(".")
      ? resolve(dirname(from), specifier)
      : "";
  if (base.length === 0) return null;
  for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, "index.ts"), join(base, "index.tsx")]) {
    if (existsSync(candidate) && extname(candidate).match(/^\.tsx?$/u)) return candidate;
  }
  return null;
}

test("experimental API dependency graph has no settlement, wallet, RPC, or broadcast capability", () => {
  const entry = resolve(process.cwd(), "src/app/api/design-lab/governed-recourse-policy/route.ts");
  const queue = [entry];
  const visited = new Set<string>();
  const forbiddenPath = /(?:bridge-executor|controlled-live-settlement|governed-recourse-bridge|dealroom-server)/u;
  const forbiddenCode = /(?:sendTransaction|writeContract|broadcastTransaction|createWalletClient|waitForTransactionReceipt|from\s+["'](?:viem|wagmi)["'])/u;
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (visited.has(file)) continue;
    visited.add(file);
    assert.doesNotMatch(file, forbiddenPath);
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, forbiddenCode, `forbidden execution capability in ${file}`);
    for (const match of source.matchAll(/from\s+["']([^"']+)["']/gu)) {
      const dependency = resolveImport(file, match[1]!);
      if (dependency !== null) queue.push(dependency);
    }
  }
  assert.ok(visited.size >= 5);
});

test("experiment program remains a single closed evidence-only namespace", () => {
  assert.equal(FACILITY_PROTECTION_POLICY.scope.programId, EXPERIMENT_PROGRAM_ID);
  assert.equal(MANUAL_ESCALATION_POLICY.scope.programId, EXPERIMENT_PROGRAM_ID);
  assert.equal(FACILITY_PROTECTION_POLICY.conflictBranch.evaluationActionType, "REVIEW_REQUIRED");
  assert.equal(MANUAL_ESCALATION_POLICY.conflictBranch.evaluationActionType, "REVIEW_REQUIRED");
});

test("retained experimental evidence independently verifies and stays separated", () => {
  const root = resolve(process.cwd(), "docs/evidence/governed-recourse-policy-experiment");
  const policyA = JSON.parse(readFileSync(join(root, "policy-a-facility-protection.json"), "utf8")) as GovernedRecoursePolicy;
  const policyB = JSON.parse(readFileSync(join(root, "policy-b-manual-escalation.json"), "utf8")) as GovernedRecoursePolicy;
  verifyPolicyManifest(policyA);
  verifyPolicyManifest(policyB);
  assert.equal(policyA.digest, FACILITY_PROTECTION_POLICY.digest);
  assert.equal(policyB.digest, MANUAL_ESCALATION_POLICY.digest);
  const evidence = JSON.parse(readFileSync(join(root, "same-conflict-two-policy-paths.json"), "utf8")) as {
    readonly governedResultSource: { readonly digest: string; readonly originalObjectModified: boolean };
    readonly paths: ReadonlyArray<{
      readonly policyReference: { readonly policyId: string };
      readonly selectionEvent: Parameters<typeof verifyGovernedActionReceipt>[0]["selection"];
      readonly proposedAction: Parameters<typeof verifyGovernedActionReceipt>[0]["proposedAction"];
      readonly governanceApprovalEvent: Parameters<typeof verifyGovernedActionReceipt>[0]["approval"];
      readonly governedActionReceipt: Parameters<typeof verifyGovernedActionReceipt>[0]["receipt"];
      readonly authorizationEvent: Parameters<typeof verifyGovernedActionReceipt>[0]["authorizationEvent"];
    }>;
  };
  assert.equal(evidence.governedResultSource.digest, RETAINED_GOVERNED_RESULTS.conflict.digest);
  assert.equal(evidence.governedResultSource.originalObjectModified, false);
  assert.equal(evidence.paths.length, 2);
  for (const path of evidence.paths) {
    const policy = path.policyReference.policyId === policyA.policyId ? policyA : policyB;
    verifyGovernedActionReceipt({
      receipt: path.governedActionReceipt,
      policy,
      selection: path.selectionEvent,
      approval: path.governanceApprovalEvent,
      proposedAction: path.proposedAction,
      authorizationEvent: path.authorizationEvent,
    });
  }
});
