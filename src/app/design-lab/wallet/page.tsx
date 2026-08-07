import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { WalletHarness } from "./wallet-harness";

/**
 * Development-only harness for the wallet modal.
 *
 * The modal belongs to a capability that is disabled in production, so it has no
 * production route yet. This page exists so the focused suite can drive it with
 * a mock EIP-1193 provider and prove the request discipline. It returns 404 in a
 * production build.
 */

export const metadata: Metadata = {
  title: "Wallet modal harness",
  robots: { index: false, follow: false, nocache: true },
};

export default function WalletHarnessPage() {
  if (process.env.NODE_ENV === "production") notFound();
  // Never a real project ID here: the harness proves the unconfigured path by
  // default and the configured path through an explicit query flag.
  return <WalletHarness />;
}
