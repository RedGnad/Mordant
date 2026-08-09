import type { Metadata } from "next";

import { PublicShell } from "@/components/public-shell";
import { VerifiedLiveRun } from "@/components/live-product/verified-live-run";
import { loadVerifiedLiveRunReceipt } from "@/lib/protection/verified-live-run";

export const metadata: Metadata = {
  title: "Verified on-chain execution",
  description: "A separate hardened historical Adapter V2 execution, with its Monad testnet aUSDC transactions linked.",
};

/**
 * The completed real journey.
 *
 * The receipt is built from committed evidence by a loader that refuses any
 * inconsistent set, so this page either renders a genuine run or fails. There is
 * deliberately no fallback: a page that quietly degraded to sample data would be
 * the one thing this surface must never do.
 */
export default function VerifiedRunPage() {
  const receipt = loadVerifiedLiveRunReceipt();
  return (
    <PublicShell surface="evidence">
      <VerifiedLiveRun receipt={receipt} />
    </PublicShell>
  );
}
