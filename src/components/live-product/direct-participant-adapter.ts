/**
 * Maps the public participant-case projection onto the five-chapter UI without
 * ever rebuilding a combined claim model. The worker projection deliberately
 * exposes only admission status and wallets, and this adapter preserves that
 * boundary all the way to the component tree.
 */

import { adaptManagedIntake, type ManagedWorkerView } from "./managed-intake-adapter";
import type { ParticipantAdmissionProjection } from "./participant-admission-client";
import {
  type CapabilitySet,
  type DirectAdmissionView,
  type DirectClaimDraft,
  type EligibilityView,
  type LiveProductState,
  type LiveProductViewModel,
  type ParticipantRole,
  type WalletView,
} from "./live-product-view-model";

const IDLE_ELIGIBILITY: EligibilityView = Object.freeze({
  state: "IDLE", holderAddress: null, chainId: null, gateAddress: null, observedBlock: null, problem: null,
});

const DIRECT_PRIVACY_NOTE =
  "Only this role's interval is sent with its signed admission. The other participant's interval is not displayed here.";

function projectionFor(admission: ParticipantAdmissionProjection | null, role: ParticipantRole) {
  return role === "A" ? admission?.participantA ?? { admitted: false, wallet: null }
    : admission?.participantB ?? { admitted: false, wallet: null };
}

function otherRoleFor(activeRole: ParticipantRole | null, admission: ParticipantAdmissionProjection | null): ParticipantRole {
  if (activeRole === "A") return "B";
  if (activeRole === "B") return "A";
  return admission?.participantA.admitted === true ? "A" : "B";
}

function stateFor(input: Readonly<{
  view: ManagedWorkerView | null;
  admission: ParticipantAdmissionProjection | null;
  activeRole: ParticipantRole | null;
  eligibility: EligibilityView;
  authorizing: boolean;
  noticeState: LiveProductState | null;
}>): LiveProductState {
  if (input.noticeState !== null) return input.noticeState;
  if (input.view?.stage === "ABORTED" || input.admission?.abandoned === true) return "EXECUTION_FAILED";
  if (input.admission === null || !input.admission.bothAdmitted) {
    if (input.activeRole !== null) {
      if (input.eligibility.state === "CHECKING") return "ELIGIBILITY_CHECKING";
      if (input.eligibility.state === "REFUSED") return "ELIGIBILITY_REFUSED";
      if (input.eligibility.state !== "VERIFIED") return "ELIGIBILITY_REQUIRED";
      if (input.activeRole === "A") return input.authorizing ? "CLAIM_A_AUTHORIZING" : "CLAIM_A_REQUIRED";
      return input.authorizing ? "CLAIM_B_AUTHORIZING" : "CLAIM_B_REQUIRED";
    }
    return "WAITING_FOR_OTHER_PARTICIPANT";
  }
  // Once the worker reports both roles admitted, only its authenticated custom
  // view determines progress and any release wording.
  return adaptManagedIntake({
    view: input.view,
    capabilitySet: Object.freeze({
      MANAGED_COMBINED_INTAKE: false,
      SEPARATE_WALLET_STAGING: false,
      DIRECT_PARTICIPANT_ADMISSION: true,
      ONCHAIN_RECOURSE_CONNECTED: false,
      WALLETCONNECT_AVAILABLE: false,
    }),
    eligibility: IDLE_ELIGIBILITY,
    wallet: null,
    claimsAuthored: input.view !== null,
    elapsedSeconds: null,
    notice: null,
    noticeState: null,
  }).state;
}

export function adaptDirectParticipantIntake(input: Readonly<{
  view: ManagedWorkerView | null;
  admission: ParticipantAdmissionProjection | null;
  capabilitySet: CapabilitySet;
  activeRole: ParticipantRole | null;
  eligibility: EligibilityView;
  ownDraft: DirectClaimDraft;
  wallet: WalletView | null;
  authorizing: boolean;
  retryReady: boolean;
  elapsedSeconds: number | null;
  notice: LiveProductViewModel["notice"];
  noticeState: LiveProductState | null;
}>): LiveProductViewModel {
  const base = adaptManagedIntake({
    view: input.view,
    capabilitySet: input.capabilitySet,
    eligibility: input.eligibility,
    wallet: input.wallet,
    claimsAuthored: input.view !== null,
    elapsedSeconds: input.elapsedSeconds,
    notice: input.notice,
    noticeState: input.noticeState,
  });
  const activeRole = input.activeRole;
  const otherRole = otherRoleFor(activeRole, input.admission);
  const other = projectionFor(input.admission, otherRole);
  const own = activeRole === null ? null : projectionFor(input.admission, activeRole);
  const directAdmission: DirectAdmissionView = Object.freeze({
    current: activeRole === null ? null : Object.freeze({
      role: activeRole,
      label: activeRole === "A" ? "Participant A" : "Participant B",
      draft: Object.freeze({ ...input.ownDraft }),
      admission: input.authorizing ? "AUTHORIZING" : own?.admitted ? "ADMITTED" : "REQUIRED",
      wallet: input.wallet,
      eligibility: input.eligibility,
      eligibilityVerified: input.eligibility.state === "VERIFIED",
      privacyNote: DIRECT_PRIVACY_NOTE,
    }),
    other: Object.freeze({
      role: otherRole,
      label: otherRole === "A" ? "Participant A" : "Participant B",
      admitted: other.admitted,
      wallet: other.wallet,
    }),
    handoffRequired: input.admission?.participantA.admitted === true
      && input.admission.participantB.admitted === false
      && activeRole === null,
    retryReady: input.retryReady,
  });

  const claimA = projectionFor(input.admission, "A");
  const claimB = projectionFor(input.admission, "B");
  const state = stateFor({
    view: input.view,
    admission: input.admission,
    activeRole,
    eligibility: input.eligibility,
    authorizing: input.authorizing,
    noticeState: input.noticeState,
  });
  const abandonedNotice: LiveProductViewModel["notice"] = input.admission?.abandoned !== true
    ? null
    : {
      title: "This participant case is no longer accepting admissions.",
      body: "No result was released. Start a new case only after both participants are ready to authorize their own claims.",
      retryable: false,
    };

  return Object.freeze({
    ...base,
    state,
    wallet: input.wallet,
    claimA: Object.freeze({ ...base.claimA, admission: claimA.admitted ? "ADMITTED" : "REQUIRED", wallet: claimA.wallet, eligibilityVerified: claimA.admitted }),
    claimB: Object.freeze({ ...base.claimB, admission: claimB.admitted ? "ADMITTED" : "REQUIRED", wallet: claimB.wallet, eligibilityVerified: claimB.admitted }),
    directAdmission,
    activeRole,
    handoffRequired: directAdmission.handoffRequired,
    notice: input.notice ?? base.notice ?? abandonedNotice,
  });
}
