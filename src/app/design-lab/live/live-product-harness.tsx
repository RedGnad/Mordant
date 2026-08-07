"use client";

import { useState } from "react";

import { PublicShell } from "@/components/public-shell";
import { adaptDirectParticipantIntake } from "@/components/live-product/direct-participant-adapter";
import { LiveProduct, type ClaimDraft } from "@/components/live-product/live-product";
import { adaptManagedIntake } from "@/components/live-product/managed-intake-adapter";
import type { ParticipantAdmissionProjection } from "@/components/live-product/participant-admission-client";
import {
  conflictView,
  noConflictView,
  onchainFixture,
  RUNNING_VIEW,
} from "@/components/live-product/live-product-fixtures";
import {
  capabilities,
  type EligibilityView,
  type LiveProductViewModel,
  type OnchainPhase,
} from "@/components/live-product/live-product-view-model";

const VERIFIED: EligibilityView = {
  state: "VERIFIED",
  holderAddress: "0x911F99f424D47F08a15fcC771e94dcc2f7252B02",
  chainId: 10_143,
  gateAddress: "0x3ffb28a13fd6dc372ae952f15b55263285d5a280",
  observedBlock: 51_248_337,
  problem: null,
};
const IDLE: EligibilityView = {
  state: "IDLE", holderAddress: null, chainId: null, gateAddress: null, observedBlock: null, problem: null,
};

const DRAFT: ClaimDraft = { aFrom: "120", aUntil: "420", bFrom: "220", bUntil: "520" };
const DISJOINT: ClaimDraft = { aFrom: "120", aUntil: "300", bFrom: "420", bUntil: "620" };

const MANAGED = capabilities("MANAGED_COMBINED_INTAKE");
/**
 * Never reachable in production. The runtime branch has not published a
 * qualified capability flag, so direct admission exists only here.
 */
const WITH_ADMISSION = capabilities("DIRECT_PARTICIPANT_ADMISSION");
const WALLET_A = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const WALLET_B = "0x1111111111111111111111111111111111111111";
/** Never reachable in production: the harness is the only place this is on. */
const WITH_ONCHAIN = capabilities("MANAGED_COMBINED_INTAKE", "ONCHAIN_RECOURSE_CONNECTED");

function build(scenario: string): { model: LiveProductViewModel; draft: ClaimDraft | null } {
  const base = {
    capabilitySet: MANAGED,
    eligibility: VERIFIED,
    wallet: null,
    claimsAuthored: true,
    elapsedSeconds: 14,
    notice: null,
    noticeState: null,
  } as const;

  if (scenario === "eligibility") {
    return {
      model: adaptManagedIntake({ ...base, view: null, eligibility: IDLE, claimsAuthored: false, elapsedSeconds: null }),
      draft: DRAFT,
    };
  }
  if (scenario === "authorize") {
    return {
      model: adaptManagedIntake({ ...base, view: null, claimsAuthored: false, elapsedSeconds: null }),
      draft: DRAFT,
    };
  }
  if (scenario === "running") {
    return { model: adaptManagedIntake({ ...base, view: RUNNING_VIEW }), draft: DRAFT };
  }
  if (scenario === "no-conflict") {
    return { model: adaptManagedIntake({ ...base, view: noConflictView(), elapsedSeconds: null }), draft: DISJOINT };
  }
  if (scenario === "busy") {
    return {
      model: adaptManagedIntake({
        ...base,
        view: null,
        claimsAuthored: false,
        elapsedSeconds: null,
        noticeState: "BUSY",
        notice: {
          title: "A private check is already running.",
          body: "One execution slot is available, so this check waits rather than running in parallel.",
          retryable: true,
        },
      }),
      draft: DRAFT,
    };
  }
  if (scenario === "unavailable") {
    return {
      model: adaptManagedIntake({
        ...base,
        view: null,
        claimsAuthored: false,
        elapsedSeconds: null,
        noticeState: "SERVICE_UNAVAILABLE",
        notice: {
          title: "The execution service did not answer.",
          body: "The run is still recorded and this page can resume it.",
          retryable: true,
        },
      }),
      draft: DRAFT,
    };
  }
  if (scenario.startsWith("admission")) {
    const wallet = {
      state: "CONNECTED" as const,
      address: scenario === "admission-b" || scenario === "admission-same" ? WALLET_B : WALLET_A,
      connectorName: "Alpha Wallet",
      connectorUid: "fixture",
      chainId: 10_143,
      expectedChainId: 10_143,
      problem: null,
    };
    const eligibilityFor = (holderAddress: string, state: EligibilityView["state"] = "VERIFIED"): EligibilityView => state === "VERIFIED"
      ? { ...VERIFIED, holderAddress }
      : { ...IDLE, state, holderAddress: state === "IDLE" ? null : holderAddress };
    const admittedA: ParticipantAdmissionProjection = Object.freeze({
      schemaVersion: "mordant.participant-case/1",
      caseCode: "0123456789ABCDEF",
      runId: "00000000-0000-4000-8000-000000000004",
      lifecycle: "PARTICIPANT_A_ADMITTED",
      participantA: Object.freeze({ admitted: true, wallet: WALLET_A }),
      participantB: Object.freeze({ admitted: false, wallet: null }),
      bothAdmitted: false,
      abandoned: false,
    });
    const direct = (input: Readonly<{
      activeRole: "A" | "B" | null;
      admission: ParticipantAdmissionProjection | null;
      ownDraft: Readonly<{ activeFrom: string; activeUntil: string }>;
      walletAddress: string;
      eligibility: EligibilityView;
    }>) => adaptDirectParticipantIntake({
      view: null,
      admission: input.admission,
      capabilitySet: WITH_ADMISSION,
      activeRole: input.activeRole,
      eligibility: input.eligibility,
      ownDraft: input.ownDraft,
      wallet: { ...wallet, address: input.walletAddress },
      authorizing: false,
      retryReady: false,
      elapsedSeconds: null,
      notice: null,
      noticeState: null,
    });

    if (scenario === "admission-handoff") {
      return {
        model: direct({ activeRole: null, admission: admittedA, ownDraft: { activeFrom: "", activeUntil: "" }, walletAddress: WALLET_A, eligibility: eligibilityFor(WALLET_A) }),
        draft: null,
      };
    }
    if (scenario === "admission-same") {
      return {
        model: direct({ activeRole: "B", admission: admittedA, ownDraft: { activeFrom: "220", activeUntil: "520" }, walletAddress: WALLET_A, eligibility: eligibilityFor(WALLET_A) }),
        draft: null,
      };
    }
    if (scenario === "admission-b") {
      return {
        model: direct({ activeRole: "B", admission: admittedA, ownDraft: { activeFrom: "220", activeUntil: "520" }, walletAddress: WALLET_B, eligibility: eligibilityFor(WALLET_B) }),
        draft: null,
      };
    }
    return {
      model: direct({
        activeRole: "A",
        admission: null,
        ownDraft: { activeFrom: "120", activeUntil: "420" },
        walletAddress: WALLET_A,
        eligibility: eligibilityFor(WALLET_A, scenario === "admission-verify" ? "IDLE" : "VERIFIED"),
      }),
      draft: null,
    };
  }

  if (scenario.startsWith("onchain-")) {
    const phase = scenario.slice("onchain-".length).toUpperCase().replace(/-/gu, "_") as OnchainPhase;
    const model = adaptManagedIntake({ ...base, capabilitySet: WITH_ONCHAIN, view: conflictView(), elapsedSeconds: null });
    return {
      // The adapter never fabricates an on-chain view, so the harness supplies
      // the typed fixture in its place.
      model: Object.freeze({ ...model, onchain: onchainFixture(phase) }),
      draft: DRAFT,
    };
  }
  return { model: adaptManagedIntake({ ...base, view: conflictView(), elapsedSeconds: null }), draft: DRAFT };
}

export function LiveProductHarness({ scenario }: { readonly scenario: string }) {
  const [{ model, draft }] = useState(() => build(scenario));

  return (
    <PublicShell surface="live">
      <p
        data-testid="harness-banner"
        style={{
          margin: 0,
          padding: "10px var(--shell-gutter)",
          background: "#fff7db",
          borderBottom: "1px solid var(--rule)",
          font: "11px var(--font-proof), monospace",
          letterSpacing: "0.07em",
          textTransform: "uppercase",
        }}
      >
        Design fixture · not a real execution · scenario {scenario}
      </p>
      <LiveProduct
        model={model}
        draft={draft}
        invalidFields={[]}
        formError={null}
        holderDraft={model.eligibility.holderAddress ?? ""}
        publicTestHolder="0x911F99f424D47F08a15fcC771e94dcc2f7252B02"
        actions={{}}
      />
    </PublicShell>
  );
}
