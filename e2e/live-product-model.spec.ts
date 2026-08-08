import { expect, test } from "@playwright/test";

import {
  adaptManagedIntake,
  managedProductState,
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
    expect(model.intakeDisclosure).toContain("managed execution service");
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
    expect(model.onchain.disabledReason).toContain("not connected");
  });

  test("the receipt is layered and keeps raw evidence last", () => {
    const model = adapt(conflictView());
    expect(model.receipt?.summary.length).toBeGreaterThan(0);
    expect(model.receipt?.technical.length).toBeGreaterThan(0);
    expect(model.receipt?.raw).not.toBeNull();
    // Level one is for a person: it carries no digest.
    for (const row of model.receipt!.summary) expect(row.value).not.toMatch(/^sha256:/u);
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

  test("stage progress is derived, never invented", () => {
    const model = adapt(RUNNING_VIEW);
    const active = model.stages.filter((stage) => stage.progress === "active");
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe("EVALUATION_RUNNING");
    expect(model.stages.filter((stage) => stage.progress === "done")).toHaveLength(4);
    // Only the active stage carries a sentence.
    expect(model.stages.filter((stage) => stage.detail !== null)).toHaveLength(1);
  });
});
