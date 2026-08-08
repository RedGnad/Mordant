import type { Metadata } from "next";

import { PublicExperience } from "@/components/public-experience";
import { PROTECTION_STATES } from "@/lib/dealroom/living-demo";
import { getLivingDemoReviewRun } from "@/lib/dealroom/living-demo-review-server";
import { CCP_PUBLIC_TEST_HOLDER } from "@/lib/protection/ccp-eligibility";
import { readLiveTokenConfiguration } from "@/lib/protection/live-launch-token";

export const metadata: Metadata = {
  title: "Recourse for tokenized receivables",
  description: "Mordant turns confirmed receivables exceptions into governed action and verifiable evidence.",
};

/**
 * The landing renders its live check only when the worker is actually reachable.
 *
 * Reading the configuration here, server side, means the page never offers a run
 * it cannot start, and no environment value reaches the client. A missing worker
 * is a quiet absence rather than a button that fails.
 */
function liveCheckAvailable(): boolean {
  try {
    return readLiveTokenConfiguration().workerOrigin !== "";
  } catch {
    return false;
  }
}

export default function Home() {
  const run = getLivingDemoReviewRun();
  const action = run.actions.find((candidate) => candidate.id === "reveal");

  if (action === undefined || action.after == null || action.receipt === undefined) {
    throw new Error("The public proof checkpoint is missing from the retained run.");
  }

  return (
    <PublicExperience
      liveCheckHolder={liveCheckAvailable() ? CCP_PUBLIC_TEST_HOLDER : null}
      proof={{
      actor: action.actorLabel,
      action: action.title,
      before: PROTECTION_STATES[action.before.protectionState],
      after: PROTECTION_STATES[action.after.protectionState],
      block: action.receipt.blockNumber,
      // The receipt is labelled with the chain that produced it. It comes from
      // the recorded lifecycle run, not from the live encrypted check, and the
      // landing must not let one stand in for the other.
      chain: `${run.source.network} · chain ${run.source.chainId}`,
    }}
    />
  );
}
