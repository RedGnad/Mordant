import conflictEvidence from "../../../docs/evidence/conflicting-pledge-protection/conflict.json";
import noConflictEvidence from "../../../docs/evidence/conflicting-pledge-protection/no-conflict.json";

import {
  governedResultDigest,
  verifyGovernedResultSignature,
  type GovernedSignedResult,
} from "../protection/protection-evidence";
import type { Sha256Digest } from "../protection/cleanverse-asset";
import {
  EXPERIMENT_PROGRAM_ID,
  GOVERNED_RESULT_SEMANTIC,
  createPrototypeSigner,
  deepFreeze,
  digestValue,
  signPolicyManifest,
  verifyPolicyManifest,
  type GovernedRecoursePolicy,
  type PrototypeSigner,
  type UnsignedGovernedRecoursePolicy,
} from "./policy";

export const RETAINED_CONFLICT_RESULT_PATH = "docs/evidence/conflicting-pledge-protection/conflict.json" as const;
export const RETAINED_NO_CONFLICT_RESULT_PATH = "docs/evidence/conflicting-pledge-protection/no-conflict.json" as const;

export const PROTOTYPE_SIGNERS = deepFreeze({
  policyAuthority: createPrototypeSigner("POLICY_AUTHORITY", "Mordant design lab policy authority — prototype only"),
  selector: createPrototypeSigner("POLICY_SELECTOR", "Mordant design lab policy selector — prototype only"),
  creditOpsApprover: createPrototypeSigner("CREDIT_OPS_APPROVER", "Credit Ops approver — prototype only"),
  institutionalReviewer: createPrototypeSigner("INSTITUTIONAL_REVIEWER", "Institutional reviewer — prototype only"),
  actionRecorder: createPrototypeSigner("ACTION_RECORDER", "Mordant action evidence recorder — prototype only"),
}) satisfies Readonly<Record<string, PrototypeSigner>>;

type RetainedGovernedResult = GovernedSignedResult & Readonly<{ digest: Sha256Digest }>;

const retainedConflict = (conflictEvidence as unknown as { readonly governedResult: RetainedGovernedResult }).governedResult;
const retainedNoConflict = (noConflictEvidence as unknown as { readonly governedResult: RetainedGovernedResult }).governedResult;

function verifiedRetainedResult(result: RetainedGovernedResult, expectedConflict: boolean): RetainedGovernedResult {
  verifyGovernedResultSignature(result);
  if (governedResultDigest(result) !== result.digest) throw new Error("Retained governed-result digest mismatch");
  if (result.conflict !== expectedConflict) throw new Error("Retained governed-result outcome mismatch");
  return deepFreeze(result);
}

export const RETAINED_GOVERNED_RESULTS = deepFreeze({
  conflict: verifiedRetainedResult(retainedConflict, true),
  noConflict: verifiedRetainedResult(retainedNoConflict, false),
});

const EFFECTIVE_FROM_UNIX = Date.parse("2026-08-01T00:00:00.000Z") / 1000;
const EFFECTIVE_UNTIL_UNIX = Date.parse("2027-08-01T00:00:00.000Z") / 1000;
const EXPERIMENT_ASSET_IDENTITY = RETAINED_GOVERNED_RESULTS.conflict.assetIdentity;

const commonPolicy = {
  schemaVersion: "mordant.governed-recourse-policy/1" as const,
  policyVersion: 1,
  scope: {
    programId: EXPERIMENT_PROGRAM_ID,
    assetClass: "TOKENIZED_PRIVATE_CREDIT" as const,
    assetIdentity: EXPERIMENT_ASSET_IDENTITY,
  },
  acceptedGovernedResult: {
    semantic: GOVERNED_RESULT_SEMANTIC,
    schemaVersion: "mordant.governed-conflict-result/1" as const,
    serviceId: "mordant.private-pledge-matching" as const,
    serviceVersion: 1 as const,
    releaseMode: "governed-decryptor-v1" as const,
  },
  effectiveFromUnix: EFFECTIVE_FROM_UNIX,
  effectiveUntilUnix: EFFECTIVE_UNTIL_UNIX,
  noConflictBranch: {
    governedOutcome: "NO_CONFLICT" as const,
    evaluationActionType: "RECORD_AND_CLOSE" as const,
    authorizedActionType: "RECORD_AND_CLOSE" as const,
    accountableInstitutionalRole: "RECORDS_OPERATIONS" as const,
    authorizationMode: "AUTOMATIC_PERMITTED" as const,
    allowedApproverRoles: [] as const,
    approvalWindowSeconds: null,
    deadlineRule: null,
    escalationRule: null,
    actionConfigurationDigest: digestValue({
      schemaVersion: "mordant.experimental-action-configuration/1",
      actionType: "RECORD_AND_CLOSE",
      effect: "EVIDENCE_RECORD_ONLY",
      settlement: "PROHIBITED",
    }),
  },
  settlement: {
    permission: "PROHIBITED" as const,
    configurationDigest: null,
  },
} as const;

const facilityProtectionInput: UnsignedGovernedRecoursePolicy = {
  ...commonPolicy,
  policyId: "mordant.experimental.facility-protection",
  conflictBranch: {
    governedOutcome: "CONFLICT",
    evaluationActionType: "REVIEW_REQUIRED",
    authorizedActionType: "OPEN_CURE_PATH",
    accountableInstitutionalRole: "CREDIT_OPERATIONS",
    authorizationMode: "HUMAN_APPROVAL_REQUIRED",
    allowedApproverRoles: ["CREDIT_OPS_APPROVER"],
    approvalWindowSeconds: 86_400,
    deadlineRule: {
      kind: "RELATIVE_TO_RESULT_EXPOSURE",
      seconds: 604_800,
    },
    escalationRule: {
      trigger: "DEADLINE_UNRESOLVED",
      actionType: "MANUAL_ESCALATION",
    },
    actionConfigurationDigest: digestValue({
      schemaVersion: "mordant.experimental-action-configuration/1",
      actionType: "OPEN_CURE_PATH",
      deadlineSeconds: 604_800,
      unresolvedEscalation: "MANUAL_ESCALATION",
      settlement: "PROHIBITED",
    }),
  },
};

const manualEscalationInput: UnsignedGovernedRecoursePolicy = {
  ...commonPolicy,
  policyId: "mordant.experimental.manual-escalation",
  conflictBranch: {
    governedOutcome: "CONFLICT",
    evaluationActionType: "REVIEW_REQUIRED",
    authorizedActionType: "MANUAL_ESCALATION",
    accountableInstitutionalRole: "RISK_OPERATIONS",
    authorizationMode: "HUMAN_APPROVAL_REQUIRED",
    allowedApproverRoles: ["INSTITUTIONAL_REVIEWER"],
    approvalWindowSeconds: 86_400,
    deadlineRule: null,
    escalationRule: null,
    actionConfigurationDigest: digestValue({
      schemaVersion: "mordant.experimental-action-configuration/1",
      actionType: "MANUAL_ESCALATION",
      destination: "INSTITUTIONAL_MANUAL_REVIEW",
      settlement: "PROHIBITED",
    }),
  },
};

export const FACILITY_PROTECTION_POLICY = signPolicyManifest(
  facilityProtectionInput,
  PROTOTYPE_SIGNERS.policyAuthority,
);

export const MANUAL_ESCALATION_POLICY = signPolicyManifest(
  manualEscalationInput,
  PROTOTYPE_SIGNERS.policyAuthority,
);

/** Exactly two immutable policy fixtures are admitted by the experiment. */
export const EXPERIMENTAL_POLICIES = deepFreeze([
  FACILITY_PROTECTION_POLICY,
  MANUAL_ESCALATION_POLICY,
] as const);

export type ExperimentalPolicyId = typeof EXPERIMENTAL_POLICIES[number]["policyId"];

export function policyById(policyId: string): GovernedRecoursePolicy {
  const policy = EXPERIMENTAL_POLICIES.find((candidate) => candidate.policyId === policyId);
  if (policy === undefined) throw new Error("Unknown experimental policy fixture");
  verifyPolicyManifest(policy);
  return policy;
}
