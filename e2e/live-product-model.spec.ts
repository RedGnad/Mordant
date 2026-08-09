import { expect, test } from "@playwright/test";

import {
  adaptManagedIntake,
  managedProductState,
  parseManagedWorkerView,
  type ManagedWorkerView,
} from "../src/components/live-product/managed-intake-adapter";
import {
  conflictView,
  noConflictView,
  RUNNING_VIEW,
} from "../src/components/live-product/live-product-fixtures";
import {
  ausdcFromAtomic,
  assertNoPrematureOutcome,
  capabilities,
  intakeMode,
  INTAKE_DISCLOSURE,
  NO_CAPABILITIES,
  stageOrderFor,
  type EligibilityView,
} from "../src/components/live-product/live-product-view-model";
import {
  CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  currentCustomReceiptDisclosures,
} from "../src/lib/custom-supervised-receipt-disclosures";

const IDLE: EligibilityView = {
  state: "IDLE", holderAddress: null, chainId: null, gateAddress: null, observedBlock: null, problem: null,
};
const VERIFIED: EligibilityView = {
  state: "VERIFIED",
  holderAddress: "0x911F99f424D47F08a15fcC771e94dcc2f7252B02",
  chainId: 10_143,
  gateAddress: "0x3ffb28a13fd6dc372ae952f15b55263285d5a280",
  observedBlock: 51_248_337,
  problem: null,
};

const MANAGED = capabilities("MANAGED_COMBINED_INTAKE");

function adapt(view: ManagedWorkerView | null, eligibility = VERIFIED) {
  return adaptManagedIntake({
    view,
    capabilitySet: MANAGED,
    eligibility,
    wallet: null,
    claimsAuthored: view !== null,
    elapsedSeconds: view === null ? null : 12,
    notice: null,
    noticeState: null,
  });
}

function withReceiptDisclosures(
  view: ManagedWorkerView,
  disclosures: readonly string[],
): unknown {
  const clone = structuredClone(view) as unknown as Record<string, unknown>;
  // `ManagedWorkerView` normalizes legacy wire V1 with `governedPolicy: null`;
  // the exact V1 wire schema itself predates that normalized client member.
  if (clone.schemaVersion === "mordant.custom-supervised-protection-view/1") delete clone.governedPolicy;
  // Presentation fixtures deliberately use memorable non-hex digest seeds.
  // This helper exercises the network parser, so normalize those seeds while
  // preserving every equality/cross-reference the parser checks.
  const replacements: Readonly<Record<string, string>> = {
    g: "1", p: "2", r: "3", v: "4", x: "5", z: "6",
  };
  const normalize = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        const entry = value[index];
        if (typeof entry === "string" && /^sha256:([gprvxz])\1{63}$/u.test(entry)) {
          value[index] = `sha256:${replacements[entry[7]].repeat(64)}`;
        } else normalize(entry);
      }
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, entry] of Object.entries(value)) {
      if (typeof entry === "string" && /^sha256:([gprvxz])\1{63}$/u.test(entry)) {
        (value as Record<string, unknown>)[key] = `sha256:${replacements[entry[7]].repeat(64)}`;
      } else normalize(entry);
    }
  };
  normalize(clone);
  const receipt = clone.receipt as Record<string, unknown>;
  receipt.disclosures = [...disclosures];
  return clone;
}

function legacyDisclosures(): readonly string[] {
  return [
    ...currentCustomReceiptDisclosures("OPERATOR").slice(0, 3),
    LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
  ];
}

function prePolicyDisclosures(): readonly string[] {
  return [
    ...currentCustomReceiptDisclosures("OPERATOR").slice(0, 3),
    PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
    PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  ];
}

function governedPolicyTerminalView(): unknown {
  const value = withReceiptDisclosures(
    conflictView(),
    currentCustomReceiptDisclosures("OPERATOR"),
  ) as Record<string, unknown>;
  const protectionCase = value.protectionCase as Record<string, unknown>;
  const governedResult = value.governedResult as Record<string, unknown>;
  const receipt = value.receipt as Record<string, unknown>;
  const policyHash = "sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e";
  const selectionHash = `sha256:${"9".repeat(64)}`;
  const planHash = `sha256:${"a".repeat(64)}`;
  value.schemaVersion = "mordant.custom-supervised-protection-view/2";
  value.governedPolicy = {
    selection: {
      schemaVersion: "mordant.governed-recourse-policy-selection/1",
      policyId: "mordant.managed-demo.facility-protection",
      policyVersion: 1,
      policyHash,
      caseId: protectionCase.fheCaseId,
      resultPolicyId: "sha256:a9e039b95a56043532bcc1d7a8c1bb0086fc64d50adcb35ff54f54ee59fb6e65",
      resultPolicyVersion: 1,
      selectedAtUnix: 1_699_999_999,
      selectionHash,
    },
    actionPlan: {
      schemaVersion: "mordant.governed-action-plan/1",
      policyId: "mordant.managed-demo.facility-protection",
      policyVersion: 1,
      policyHash,
      policySelectionHash: selectionHash,
      resultDigest: governedResult.digest,
      resultOutcome: "CONFLICT",
      resultSemantic: "CONFLICT_STATUS_ONLY",
      selectedGovernedAction: "OPEN_LOCAL_CURE_PATH",
      actionOwner: "MORDANT_MANAGED_EXECUTION",
      cureWindowSeconds: 86_400,
      deadlineRule: "STARTS_WHEN_LOCAL_CURE_PATH_OPENS",
      escalation: "MANUAL_REVIEW_OUTSIDE_MANAGED_RUN",
      requiredApproval: "NONE_FOR_LOCAL_PROTOCOL_DOUBLE",
      actionClass: "LOCAL_PROTOCOL_DOUBLE",
      settlementAuthorization: "NOT_AUTHORIZED",
      planHash,
    },
    actionEvidence: {
      schemaVersion: "mordant.governed-action-evidence-reference/1",
      policySelectionHash: selectionHash,
      resultDigest: governedResult.digest,
      actionPlanHash: planHash,
      selectedGovernedAction: "OPEN_LOCAL_CURE_PATH",
      actionOwner: "MORDANT_MANAGED_EXECUTION",
      operationId: "99999999-9999-4999-8999-999999999999",
      operationAuthorizationHash: `sha256:${"c".repeat(64)}`,
      operationParametersDigest: `sha256:${"d".repeat(64)}`,
      operationOutcomeDigest: `sha256:${"e".repeat(64)}`,
      operationRecordHash: `sha256:${"f".repeat(64)}`,
      evidenceDigest: receipt.receiptDigest,
      evidenceClass: "CUSTOM_SUPERVISED_RECEIPT",
      settlementAuthorization: "NOT_AUTHORIZED",
      referenceHash: `sha256:${"b".repeat(64)}`,
    },
  };
  return value;
}

test.describe("live product presentation model", () => {
  test("nothing is enabled unless a caller turns it on", () => {
    expect(intakeMode(NO_CAPABILITIES)).toBe("NONE");
    for (const value of Object.values(NO_CAPABILITIES)) expect(value).toBe(false);
    // The target capabilities are off under the production capability set.
    expect(MANAGED.DIRECT_PARTICIPANT_ADMISSION).toBe(false);
    expect(MANAGED.SEPARATE_WALLET_STAGING).toBe(false);
    expect(MANAGED.ONCHAIN_RECOURSE_CONNECTED).toBe(false);
    expect(MANAGED.WALLETCONNECT_AVAILABLE).toBe(false);
  });

  test("the managed intake prints only its own disclosure", () => {
    const model = adapt(RUNNING_VIEW);
    expect(model.intake).toBe("MANAGED_COMBINED");
    expect(model.intakeDisclosure).toBe(INTAKE_DISCLOSURE.MANAGED_COMBINED);
    expect(model.intakeDisclosure).toContain("managed service");
    // The two-wallet sentence may never appear under the managed capability.
    expect(model.intakeDisclosure).not.toContain("independently authorize");
  });

  test("no outcome exists before a governed release", () => {
    const model = adapt(RUNNING_VIEW);
    expect(model.release).toBeNull();
    expect(model.decisionRail).toBeNull();
    expect(model.state).toBe("ENCRYPTED_EVALUATION");
    expect(model.expectation).toContain("thirty seconds");
    assertNoPrematureOutcome(model);
  });

  test("an unstarted run never leaves the eligibility states", () => {
    expect(managedProductState(null, { eligibility: "IDLE", claimsAuthored: false, notice: null }))
      .toBe("ELIGIBILITY_REQUIRED");
    expect(managedProductState(null, { eligibility: "CHECKING", claimsAuthored: false, notice: null }))
      .toBe("ELIGIBILITY_CHECKING");
    expect(managedProductState(null, { eligibility: "REFUSED", claimsAuthored: false, notice: null }))
      .toBe("ELIGIBILITY_REFUSED");
    expect(adapt(null, IDLE).stages).toHaveLength(0);
  });

  test("conflict opens a decision rail with a dynamic deadline", () => {
    const model = adapt(conflictView());
    expect(model.state).toBe("RECEIPT_SEALED");
    expect(model.release?.conflict).toBe(true);
    expect(model.decisionRail?.nextDecision).toBe("Apply approved cure policy after conflict review");
    expect(model.decisionRail?.responsibleNow).toBe("Policy / human review required");

    const deadline = model.decisionRail?.deadlineIso;
    expect(typeof deadline).toBe("string");
    // The deadline must be in the future relative to the moment it is produced,
    // which is what a hard-coded historical date could never satisfy.
    expect(new Date(deadline!).getTime()).toBeGreaterThan(Date.now());
  });

  test("no conflict refuses recourse and never claims approval", () => {
    const model = adapt(noConflictView());
    expect(model.release?.conflict).toBe(false);
    expect(model.decisionRail?.nextDecision).toBe("No recourse action is available");
    expect(model.decisionRail?.deadlineIso).toBeNull();
    expect(model.decisionRail?.consequence).toContain("established no conflict between the submitted windows");
    const railText = JSON.stringify(model.decisionRail);
    for (const forbidden of ["approved", "approval", "creditworthy"]) {
      expect(railText.toLowerCase()).not.toContain(forbidden);
    }
  });

  test("conflict and no conflict are structurally different", () => {
    const conflict = adapt(conflictView());
    const cleared = adapt(noConflictView());
    expect(conflict.decisionRail?.deadlineIso).not.toBe(cleared.decisionRail?.deadlineIso);
    expect(conflict.decisionRail?.responsibleNow).not.toBe(cleared.decisionRail?.responsibleNow);
    expect(conflict.decisionRail?.consequence).not.toBe(cleared.decisionRail?.consequence);
    expect(conflict.receipt?.summary[0].value).toBe("Conflict confirmed");
    expect(cleared.receipt?.summary[0].value).toBe("No conflict");
  });

  test("on-chain recourse stays disconnected under the production capability", () => {
    const model = adapt(conflictView());
    expect(model.onchain.phase).toBe("NOT_CONNECTED");
    expect(model.onchain.entitlement).toBeNull();
    expect(model.onchain.evidence.contractAddress).toBeNull();
    expect(model.onchain.disabledReason)
      .toBe("This managed run ends after its policy-authorized local operation and sealed evidence.");
  });

  test("the receipt is layered and keeps raw evidence last", () => {
    const model = adapt(conflictView());
    expect(model.receipt?.summary.length).toBeGreaterThan(0);
    expect(model.receipt?.technical.length).toBeGreaterThan(0);
    expect(model.receipt?.raw).not.toBeNull();
    // Level one is for a person: it carries no digest.
    for (const row of model.receipt!.summary) expect(row.value).not.toMatch(/^sha256:/u);
  });

  test("the browser receipt parser accepts exact current and immutable historical disclosures", () => {
    const current = currentCustomReceiptDisclosures("OPERATOR");
    expect(parseManagedWorkerView(withReceiptDisclosures(conflictView(), current))).not.toBeNull();
    expect(parseManagedWorkerView(withReceiptDisclosures(conflictView(), prePolicyDisclosures()))).not.toBeNull();
    expect(parseManagedWorkerView(withReceiptDisclosures(conflictView(), legacyDisclosures()))).not.toBeNull();

    const malformed = [
      [...current.slice(0, 3), "The Boolean decides the terminal outcome."],
      current.slice(0, 4),
      [...legacyDisclosures(), CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE],
      [...current.slice(0, 3), LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE, CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE],
      [...current, "extra"],
    ];
    for (const disclosures of malformed) {
      expect(parseManagedWorkerView(withReceiptDisclosures(conflictView(), disclosures))).toBeNull();
    }
  });

  test("legacy raw evidence is preserved but presented under the current authority boundary", () => {
    const parsed = parseManagedWorkerView(withReceiptDisclosures(conflictView(), legacyDisclosures()));
    expect(parsed).not.toBeNull();
    const model = adapt(parsed);
    expect(model.receipt?.summary.find((row) => row.label === "Result authority")?.value)
      .toContain("conflict/no-conflict between the submitted windows only");
    expect(model.receipt?.summary.find((row) => row.label === "Recourse authority")?.value)
      .toContain("precommitted policy selects the bounded branch");
    expect(model.receipt?.rawContext).toContain("Immutable historical receipt");
    expect(model.receipt?.rawContext).toContain("not the current product boundary");
    expect(model.receipt?.rawContext).not.toContain(LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE);
    expect(JSON.stringify(model.receipt?.raw)).toContain(LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE);
  });

  test("a terminal governed-policy view binds its selected action through the authorized operation to evidence", () => {
    const parsed = parseManagedWorkerView(governedPolicyTerminalView());
    expect(parsed).not.toBeNull();
    const model = adapt(parsed);
    expect(model.governedPolicy?.policyId).toBe("mordant.managed-demo.facility-protection");
    expect(model.governedPolicy?.actionPlan?.selectedGovernedAction).toBe("OPEN_LOCAL_CURE_PATH");
    expect(model.governedPolicy?.actionPlan?.settlementAuthorization).toBe("NOT_AUTHORIZED");
    expect(model.governedPolicy?.actionEvidenceDigest).toBe(model.receipt?.raw?.receiptDigest);
    expect(parsed?.governedPolicy?.actionEvidence?.operationAuthorizationHash).toMatch(/^sha256:/);
    expect(parsed?.governedPolicy?.actionEvidence?.operationParametersDigest).toMatch(/^sha256:/);
    expect(parsed?.governedPolicy?.actionEvidence?.operationOutcomeDigest).toMatch(/^sha256:/);
    expect(model.decisionRail?.responsibleNow).toContain("local protocol double");
    expect(model.decisionRail?.consequence).toContain("Settlement is not authorized");

    const tampered = governedPolicyTerminalView() as Record<string, unknown>;
    const policy = tampered.governedPolicy as Record<string, unknown>;
    const evidence = policy.actionEvidence as Record<string, unknown>;
    evidence.evidenceDigest = `sha256:${"f".repeat(64)}`;
    expect(parseManagedWorkerView(tampered)).toBeNull();
  });

  test("aUSDC renders with its real decimals and keeps atomic units separate", () => {
    const amount = ausdcFromAtomic("9999");
    expect(amount.formatted).toBe("0.00");
    expect(amount.atomic).toBe("9999");
    expect(amount.decimals).toBe(6);
    expect(ausdcFromAtomic("100000000").formatted).toBe("100.00");
    expect(ausdcFromAtomic("1234567890123").formatted).toBe("1,234,567.89");
  });

  test("separate admission adds one real stage and managed intake does not", () => {
    expect(stageOrderFor("MANAGED_COMBINED")).toHaveLength(8);
    expect(stageOrderFor("DIRECT_ADMISSION")).toHaveLength(9);
    expect(stageOrderFor("DIRECT_ADMISSION")).toContain("CLAIM_INPUTS_ADMITTED");
    expect(stageOrderFor("MANAGED_COMBINED")).not.toContain("CLAIM_INPUTS_ADMITTED");
  });

  test("EVALUATED means BGV complete with governed release still pending", () => {
    const model = adapt(RUNNING_VIEW);
    const active = model.stages.filter((stage) => stage.progress === "active");
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe("GOVERNED_VERIFICATION");
    expect(active[0].label).toBe("Governed result pending");
    expect(active[0].detail).toContain("Encrypted evaluation is complete");
    expect(model.stages.map((stage) => String(stage.id))).not.toContain("EVALUATION_RUNNING");
    expect(model.stages.find((stage) => stage.id === "EVALUATION_COMPLETE")).toMatchObject({
      label: "Encrypted evaluation complete",
      progress: "done",
    });
    expect(model.stages.filter((stage) => stage.progress === "done")).toHaveLength(5);
    // Only the active stage carries a sentence.
    expect(model.stages.filter((stage) => stage.detail !== null)).toHaveLength(1);
  });

  test("the public projection rejects private claim windows", () => {
    expect(parseManagedWorkerView({ ...RUNNING_VIEW, activeFrom: 120 })).toBeNull();
    expect(parseManagedWorkerView({
      ...RUNNING_VIEW,
      claim: { participantA: { activeFrom: 120, activeUntil: 420 } },
    })).toBeNull();
  });
});
