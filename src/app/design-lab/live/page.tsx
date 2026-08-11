import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { LiveProductHarness } from "./live-product-harness";

/**
 * Development-only harness for the live product states.
 *
 * The terminal states, the on-chain phases and the target two-wallet flow cannot
 * be reached in production without spending the single execution slot, and the
 * last two are behind disabled capabilities. This page renders them from
 * deterministic fixtures so the focused suite can assert them. It 404s in a
 * production build.
 */

export const metadata: Metadata = {
  title: "Live product harness",
  robots: { index: false, follow: false, nocache: true },
};

export default async function LiveProductHarnessPage({ searchParams }: {
  readonly searchParams: Promise<Readonly<Record<string, string | string[] | undefined>>>;
}) {
  if (process.env.NODE_ENV === "production") notFound();
  const query = await searchParams;
  const scenario = typeof query.scenario === "string" ? query.scenario : "conflict";
  const nowIso = typeof query.now === "string" && !Number.isNaN(Date.parse(query.now))
    ? query.now
    : undefined;
  return <LiveProductHarness scenario={scenario} nowIso={nowIso} />;
}
