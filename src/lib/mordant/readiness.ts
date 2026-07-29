import {
  assessAction,
  type DealAction,
  type DealDiagnostic,
  type GateCheck,
  type GateKind,
  type IsoTimestamp,
  type ParticipantRole,
  type SyntheticDeal,
} from "./product-model";

export const READINESS_VERDICT_CODES = [
  "AVAILABLE_NOW",
  "AVAILABLE_AT",
  "WRONG_ROLE",
  "CREDENTIAL_REQUIRED",
  "FUNDS_REQUIRED",
  "PREVIOUS_ACTION_REQUIRED",
  "ALREADY_COMPLETED",
  "RECOVERY_REQUIRED",
] as const;

export type ReadinessVerdictCode = (typeof READINESS_VERDICT_CODES)[number];

export interface ReadinessVerdict {
  readonly code: ReadinessVerdictCode;
  readonly conclusion: string;
  readonly cause: string;
  readonly blockingGate: GateCheck | null;
  readonly responsible: string;
  readonly unlock: string;
  readonly recheckAt: IsoTimestamp | null;
  readonly economicConsequence: string;
  readonly nextAction: string;
}

const ROLE_LABELS: Readonly<Record<ParticipantRole, string>> = {
  originator: "Originator",
  buyer: "Buyer",
  facility_a: "Facility A",
  facility_b: "Facility B",
  holder: "Holder",
  protocol_operator: "Protocol Operations",
  observer: "Observer",
};

const GATE_PRIORITY: readonly GateKind[] = ["identity", "role", "time", "economic", "protocol"];

function unresolvedGate(dealAction: DealAction, kind: GateKind): GateCheck | undefined {
  return dealAction.gates.find(
    (gate) => gate.kind === kind && gate.status !== "satisfied" && gate.status !== "not_applicable",
  );
}

function recoveryDiagnostic(deal: SyntheticDeal, action: DealAction): DealDiagnostic | undefined {
  return deal.diagnostics.find(
    (diagnostic) =>
      diagnostic.category === "recovery" &&
      diagnostic.severity === "error" &&
      (diagnostic.recoveryActionId === undefined || diagnostic.recoveryActionId === action.id),
  );
}

function observationDiagnostic(deal: SyntheticDeal): DealDiagnostic | undefined {
  return deal.diagnostics.find((diagnostic) => diagnostic.category === "observation");
}

function roleLabel(deal: SyntheticDeal, role: ParticipantRole): string {
  if (deal.nextResponsibility.actorRole === role) {
    return deal.nextResponsibility.actorLabel;
  }

  if (deal.viewer.role === role) {
    return deal.viewer.label;
  }

  return ROLE_LABELS[role];
}

function responsibleForGate(deal: SyntheticDeal, gate: GateCheck, action: DealAction): string {
  return roleLabel(deal, gate.responsibleRole ?? action.actorRole);
}

function economicConsequence(deal: SyntheticDeal, action: DealAction): string {
  return deal.nextResponsibility.consequenceIfMissed ?? action.consequence.summary;
}

function gateUnlock(gate: GateCheck): string {
  return gate.remediation ?? `Resolve the ${gate.label.toLowerCase()} gate, then reassess the action.`;
}

function gateVerdict(deal: SyntheticDeal, action: DealAction, gate: GateCheck): ReadinessVerdict {
  const shared = {
    cause: gate.detail,
    blockingGate: gate,
    responsible: responsibleForGate(deal, gate, action),
    unlock: gateUnlock(gate),
    economicConsequence: economicConsequence(deal, action),
  } as const;

  switch (gate.kind) {
    case "identity":
      return {
        code: "CREDENTIAL_REQUIRED",
        conclusion: "A viewer-specific credential is required",
        ...shared,
        recheckAt: null,
        nextAction: `Resolve the identity requirement before reviewing ${action.label}.`,
      };
    case "role":
      return {
        code: "WRONG_ROLE",
        conclusion: "This action belongs to another participant role",
        ...shared,
        recheckAt: deal.nextResponsibility.dueAt ?? null,
        nextAction: `Do not submit this action from ${deal.viewer.label}; wait for ${shared.responsible}.`,
      };
    case "time": {
      const recheckAt = deal.nextResponsibility.dueAt ?? null;
      return {
        code: "AVAILABLE_AT",
        conclusion:
          recheckAt === null ? "Available when the execution window opens" : `Available at ${recheckAt}`,
        ...shared,
        recheckAt,
        nextAction:
          recheckAt === null
            ? `Recheck ${action.label} when the time gate changes.`
            : `Recheck ${action.label} at ${recheckAt}.`,
      };
    }
    case "economic":
      return {
        code: "FUNDS_REQUIRED",
        conclusion: "Funds or allowance are required",
        ...shared,
        recheckAt: null,
        nextAction: `Resolve the economic requirement before reviewing ${action.label}.`,
      };
    case "protocol":
      return {
        code: "PREVIOUS_ACTION_REQUIRED",
        conclusion: "A protocol prerequisite must complete first",
        ...shared,
        recheckAt: null,
        nextAction: `Complete the protocol prerequisite, then reassess ${action.label}.`,
      };
  }
}

function unknownGateVerdict(
  deal: SyntheticDeal,
  action: DealAction,
  gate: GateCheck,
): ReadinessVerdict {
  const responsible = responsibleForGate(deal, gate, action);
  const unlock = gateUnlock(gate);

  return {
    code: "PREVIOUS_ACTION_REQUIRED",
    conclusion: "Readiness cannot be established yet",
    cause: `${gate.label} is unknown. ${gate.detail}`,
    blockingGate: null,
    responsible,
    unlock,
    recheckAt: null,
    economicConsequence: economicConsequence(deal, action),
    nextAction: `${unlock} Then reassess ${action.label}; do not infer that the gate failed.`,
  };
}

function pendingGateVerdict(
  deal: SyntheticDeal,
  action: DealAction,
  gate: GateCheck,
): ReadinessVerdict {
  const responsible = responsibleForGate(deal, gate, action);
  const unlock = gateUnlock(gate);
  const recheckAt = gate.kind === "time" ? (deal.nextResponsibility.dueAt ?? null) : null;

  return {
    code: "AVAILABLE_AT",
    conclusion:
      recheckAt === null
        ? `Available when the ${gate.label.toLowerCase()} check resolves`
        : `Available at ${recheckAt}`,
    cause: `${gate.label} is pending. ${gate.detail}`,
    blockingGate: null,
    responsible,
    unlock,
    recheckAt,
    economicConsequence: economicConsequence(deal, action),
    nextAction: `Wait for the ${gate.label.toLowerCase()} check to resolve, then reassess ${action.label}.`,
  };
}

/**
 * Derives the single M-21 verdict for an action without mutating the deal or
 * consulting time, network, wallet, or UI state outside the supplied model.
 */
export function deriveReadinessVerdict(deal: SyntheticDeal, action: DealAction): ReadinessVerdict {
  const assessment = assessAction(action, deal.observation);
  const recovery = recoveryDiagnostic(deal, action);

  if (recovery !== undefined) {
    return {
      code: "RECOVERY_REQUIRED",
      conclusion: "Protocol recovery is required",
      cause: recovery.detail,
      blockingGate: null,
      responsible: roleLabel(deal, recovery.ownerRole ?? "protocol_operator"),
      unlock: deal.nextResponsibility.task,
      recheckAt: deal.nextResponsibility.dueAt ?? null,
      economicConsequence: economicConsequence(deal, action),
      nextAction: deal.nextResponsibility.task,
    };
  }

  if (assessment.availability === "completed" || assessment.availability === "superseded") {
    const superseded = assessment.availability === "superseded";
    return {
      code: "ALREADY_COMPLETED",
      conclusion: superseded ? "This action has been superseded" : "This action is already completed",
      cause: superseded
        ? "A later action has replaced this terminal action."
        : action.proofId === undefined
          ? "The action lifecycle is recorded as completed."
          : `The action lifecycle is completed and linked to proof ${action.proofId}.`,
      blockingGate: null,
      responsible: deal.nextResponsibility.status === "none" ? deal.nextResponsibility.actorLabel : roleLabel(deal, action.actorRole),
      unlock: "No unlock is required; this action is terminal.",
      recheckAt: null,
      economicConsequence: action.consequence.summary,
      nextAction:
        action.proofId === undefined
          ? "Review the current deal state before selecting another action."
          : "Open the recorded proof for this completed action.",
    };
  }

  if (
    deal.observation.freshness.status === "stale" ||
    deal.observation.freshness.status === "unknown" ||
    deal.observation.finality.status === "unknown"
  ) {
    const diagnostic = observationDiagnostic(deal);
    const unknown =
      deal.observation.freshness.status === "unknown" || deal.observation.finality.status === "unknown";
    const refresh = deal.nextResponsibility.task;

    return {
      code: "PREVIOUS_ACTION_REQUIRED",
      conclusion: unknown ? "A trustworthy observation is required" : "The deal observation must be refreshed",
      cause:
        diagnostic?.detail ??
        (unknown
          ? "The current observation or its finality is unknown, so readiness cannot be established."
          : "The current observation is stale, so readiness cannot be trusted."),
      blockingGate: null,
      responsible: deal.nextResponsibility.actorLabel,
      unlock: refresh,
      recheckAt: null,
      economicConsequence: economicConsequence(deal, action),
      nextAction: `${refresh} Then reassess ${action.label}.`,
    };
  }

  for (const kind of GATE_PRIORITY) {
    const gate = unresolvedGate(action, kind);
    if (gate !== undefined) {
      if (gate.status === "blocked") {
        return gateVerdict(deal, action, gate);
      }

      if (gate.status === "unknown") {
        return unknownGateVerdict(deal, action, gate);
      }

      return pendingGateVerdict(deal, action, gate);
    }
  }

  if (assessment.availability === "pending") {
    return {
      code: "AVAILABLE_AT",
      conclusion: "Available after the required observation finality",
      cause: `The current observation is ${deal.observation.finality.status}; ${action.label} requires ${action.requiredFinality} finality.`,
      blockingGate: null,
      responsible: deal.nextResponsibility.actorLabel,
      unlock: deal.nextResponsibility.task,
      recheckAt: deal.nextResponsibility.dueAt ?? null,
      economicConsequence: economicConsequence(deal, action),
      nextAction: `Wait for the required finality, re-read state, then reassess ${action.label}.`,
    };
  }

  return {
    code: "AVAILABLE_NOW",
    conclusion: "Available now",
    cause: "All five readiness gates are satisfied and the required observation finality is present.",
    blockingGate: null,
    responsible: roleLabel(deal, action.actorRole),
    unlock: "No readiness blocker remains.",
    recheckAt: null,
    economicConsequence: economicConsequence(deal, action),
    nextAction: `Review the consequence and simulate ${action.label} before signing.`,
  };
}
