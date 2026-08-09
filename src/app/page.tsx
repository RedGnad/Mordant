import type { Metadata } from "next";

import { PublicExperience } from "@/components/public-experience";
import { CCP_PUBLIC_TEST_HOLDER } from "@/lib/protection/ccp-eligibility";
import { readLiveTokenConfiguration } from "@/lib/protection/live-launch-token";

export const metadata: Metadata = {
  title: "The recourse layer for tokenized private credit",
  description: "Run Mordant's first workflow from private conflict status through precommitted policy, bounded action and evidence.",
};

/**
 * The landing renders its live proof only when the worker is actually reachable.
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
  return (
    <PublicExperience
      liveCheckHolder={liveCheckAvailable() ? CCP_PUBLIC_TEST_HOLDER : null}
    />
  );
}
