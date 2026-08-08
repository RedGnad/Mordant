import {
  approveProposedAction,
  authorizeAction,
  bindPolicy,
  createExperimentalCase,
  evaluatePolicy,
  exposeGovernedResult,
  recordAuthorizedAction,
  type ExperimentalCase,
} from "./engine";
import {
  EXPERIMENTAL_POLICIES,
  PROTOTYPE_SIGNERS,
  RETAINED_CONFLICT_RESULT_PATH,
  RETAINED_GOVERNED_RESULTS,
  policyById,
} from "./fixtures";
import { RecoursePolicyError, type ApproverRole } from "./policy";

export const EXPERIMENT_CAPABILITIES = Object.freeze({
  executionMode: "EVIDENCE_ONLY",
  rpcWrites: false,
  transactionBroadcast: false,
  settlement: false,
  tokenMovement: false,
} as const);

export type ExperimentCommand =
  | Readonly<{ action: "reset" }>
  | Readonly<{ action: "bind-policy"; policyId: string }>
  | Readonly<{ action: "expose-result" }>
  | Readonly<{ action: "evaluate-policy" }>
  | Readonly<{ action: "approve-action" }>
  | Readonly<{ action: "authorize-action" }>
  | Readonly<{ action: "record-action" }>;

export type ExperimentView = Readonly<{
  experimental: true;
  productionAuthority: false;
  legalDetermination: false;
  capabilities: typeof EXPERIMENT_CAPABILITIES;
  availablePolicies: readonly Readonly<{
    policyId: string;
    policyVersion: number;
    digest: string;
    conflictAction: string;
  }>[];
  case: ExperimentalCase;
}>;

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

function freshCase(atUnix = nowUnix()): ExperimentalCase {
  return createExperimentalCase({
    caseId: RETAINED_GOVERNED_RESULTS.conflict.caseId,
    assetIdentity: RETAINED_GOVERNED_RESULTS.conflict.assetIdentity,
    authorizedAtUnix: atUnix,
  });
}

let current = freshCase();

export function readExperimentView(): ExperimentView {
  return {
    experimental: true,
    productionAuthority: false,
    legalDetermination: false,
    capabilities: EXPERIMENT_CAPABILITIES,
    availablePolicies: EXPERIMENTAL_POLICIES.map((policy) => ({
      policyId: policy.policyId,
      policyVersion: policy.policyVersion,
      digest: policy.digest,
      conflictAction: policy.conflictBranch.authorizedActionType,
    })),
    case: current,
  };
}

function approvalSigner(role: ApproverRole) {
  return role === "CREDIT_OPS_APPROVER"
    ? PROTOTYPE_SIGNERS.creditOpsApprover
    : PROTOTYPE_SIGNERS.institutionalReviewer;
}

export function applyExperimentCommand(command: ExperimentCommand, atUnix = nowUnix()): ExperimentView {
  switch (command.action) {
    case "reset":
      current = freshCase(atUnix);
      break;
    case "bind-policy": {
      const policy = policyById(command.policyId);
      current = bindPolicy({
        state: current,
        policy,
        selector: PROTOTYPE_SIGNERS.selector,
        selectedAtUnix: Math.max(atUnix, current.history.at(-1)?.atUnix ?? atUnix),
        applicabilityAtUnix: atUnix,
      });
      break;
    }
    case "expose-result": {
      if (current.selection === null) throw new RecoursePolicyError("POLICY_NOT_BOUND", "Bind a policy before exposing the result");
      current = exposeGovernedResult({
        state: current,
        governedResult: RETAINED_GOVERNED_RESULTS.conflict,
        sourcePath: RETAINED_CONFLICT_RESULT_PATH,
        exposedAtUnix: Math.max(atUnix, current.selection.selectedAtUnix + 1),
      });
      break;
    }
    case "evaluate-policy":
      current = evaluatePolicy(current, Math.max(atUnix, current.history.at(-1)?.atUnix ?? atUnix));
      break;
    case "approve-action": {
      const action = current.proposedAction;
      const role = action?.allowedApproverRoles[0];
      if (action === null || action === undefined || role === undefined || action.approvalExpiresAtUnix === null) {
        throw new RecoursePolicyError("APPROVAL_NOT_REQUIRED", "Current action has no human approval control");
      }
      const issuedAtUnix = Math.max(atUnix, current.history.at(-1)?.atUnix ?? atUnix);
      current = approveProposedAction({
        state: current,
        approverRole: role,
        approver: approvalSigner(role),
        issuedAtUnix,
        expiresAtUnix: Math.min(action.approvalExpiresAtUnix, issuedAtUnix + 3_600),
      });
      break;
    }
    case "authorize-action":
      current = authorizeAction(current, Math.max(atUnix, current.history.at(-1)?.atUnix ?? atUnix));
      break;
    case "record-action":
      current = recordAuthorizedAction({
        state: current,
        recorder: PROTOTYPE_SIGNERS.actionRecorder,
        recordedAtUnix: Math.max(atUnix, current.history.at(-1)?.atUnix ?? atUnix),
      }).state;
      break;
  }
  return readExperimentView();
}

export function parseExperimentCommand(value: unknown): ExperimentCommand {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RecoursePolicyError("COMMAND_FIELDS", "Experiment command must be an object");
  }
  const command = value as Record<string, unknown>;
  const keys = Object.keys(command).sort();
  if (command.action === "bind-policy") {
    if (keys.join(",") !== "action,policyId" || typeof command.policyId !== "string") {
      throw new RecoursePolicyError("COMMAND_FIELDS", "Bind-policy accepts only action and policyId");
    }
    return { action: "bind-policy", policyId: command.policyId };
  }
  if (keys.join(",") !== "action" || ![
    "reset", "expose-result", "evaluate-policy", "approve-action", "authorize-action", "record-action",
  ].includes(String(command.action))) {
    throw new RecoursePolicyError("COMMAND_FIELDS", "Unknown or non-closed experiment command");
  }
  return { action: command.action } as ExperimentCommand;
}
