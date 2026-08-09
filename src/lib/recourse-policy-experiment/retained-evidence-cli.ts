import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { completeGovernedActionPath } from "./engine";
import {
  FACILITY_PROTECTION_POLICY,
  MANUAL_ESCALATION_POLICY,
  PROTOTYPE_SIGNERS,
  RETAINED_CONFLICT_RESULT_PATH,
  RETAINED_GOVERNED_RESULTS,
} from "./fixtures";
import { canonicalJson, verifyGovernedActionReceipt } from "./policy";

const BASE = Date.parse("2026-08-09T10:00:00.000Z") / 1000;
const outputRoot = join(process.cwd(), "docs", "evidence", "governed-recourse-policy-experiment");

function path(
  policy: typeof FACILITY_PROTECTION_POLICY | typeof MANUAL_ESCALATION_POLICY,
  runId: string,
) {
  const facility = policy.policyId === FACILITY_PROTECTION_POLICY.policyId;
  const completed = completeGovernedActionPath({
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
  const state = completed.state;
  verifyGovernedActionReceipt({
    receipt: state.receipt,
    policy: state.policy!,
    selection: state.selection!,
    approval: state.approval,
    proposedAction: state.proposedAction!,
    authorizationEvent: completed.authorizationEvent,
  });
  return {
    runId: state.runId,
    policyReference: {
      policyId: state.policy!.policyId,
      policyVersion: state.policy!.policyVersion,
      digest: state.policy!.digest,
    },
    selectionEvent: state.selection,
    governedResultExposure: state.governedResult,
    proposedAction: state.proposedAction,
    governanceApprovalEvent: state.approval,
    governedActionReceipt: state.receipt,
    actionHistory: state.history,
    authorizationEvent: completed.authorizationEvent,
  };
}

const facility = path(FACILITY_PROTECTION_POLICY, "mordant-experiment-facility-protection-conflict-001");
const manual = path(MANUAL_ESCALATION_POLICY, "mordant-experiment-manual-escalation-conflict-001");

const evidence = {
  schemaVersion: "mordant.governed-recourse-policy-experiment-evidence/1",
  classification: "EXPERIMENTAL_OFF_CHAIN_EVIDENCE_ONLY",
  retainedAtUnix: BASE + 7,
  governedResultSource: {
    path: RETAINED_CONFLICT_RESULT_PATH,
    digest: RETAINED_GOVERNED_RESULTS.conflict.digest,
    schemaVersion: RETAINED_GOVERNED_RESULTS.conflict.schemaVersion,
    semantic: "CONFLICT_OR_NO_CONFLICT_ONLY",
    outcome: "CONFLICT",
    originalObjectModified: false,
    existingSignatureVerifierReused: "verifyGovernedResultSignature",
  },
  capabilities: {
    executionMode: "EVIDENCE_ONLY",
    rpcWrites: false,
    transactionBroadcast: false,
    settlement: false,
    tokenMovement: false,
  },
  paths: [facility, manual],
  comparison: {
    sameGovernedResultDigest: facility.governedResultExposure!.digest === manual.governedResultExposure!.digest,
    facilityProtectionAction: facility.governedActionReceipt!.resultingAction.actionType,
    manualEscalationAction: manual.governedActionReceipt!.resultingAction.actionType,
    policyDigestsDiffer: facility.policyReference.digest !== manual.policyReference.digest,
  },
  verification: {
    policySignaturesVerified: true,
    selectionSignaturesVerified: true,
    approvalSignaturesVerified: true,
    receiptSignaturesVerified: true,
    hashLinkedStateTransitionsVerified: true,
    prototypeAuthoritiesOnly: true,
    productionAuthorizationClaimed: false,
    legalCorrectnessClaimed: false,
  },
};

if (!evidence.comparison.sameGovernedResultDigest || !evidence.comparison.policyDigestsDiffer) {
  throw new Error("Retained experiment does not prove one governed fact under two policy digests");
}

mkdirSync(outputRoot, { recursive: true });
writeFileSync(join(outputRoot, "policy-a-facility-protection.json"), `${JSON.stringify(FACILITY_PROTECTION_POLICY, null, 2)}\n`);
writeFileSync(join(outputRoot, "policy-b-manual-escalation.json"), `${JSON.stringify(MANUAL_ESCALATION_POLICY, null, 2)}\n`);
writeFileSync(join(outputRoot, "same-conflict-two-policy-paths.json"), `${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`${canonicalJson({
  outputRoot,
  policies: [FACILITY_PROTECTION_POLICY.digest, MANUAL_ESCALATION_POLICY.digest],
  receipts: [facility.governedActionReceipt!.digest, manual.governedActionReceipt!.digest],
})}\n`);
