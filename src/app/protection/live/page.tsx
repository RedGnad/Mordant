import type { Metadata } from "next";

import { LiveExecution } from "@/components/live-execution";
import { LiveUnavailable } from "@/components/live-unavailable";
import { PublicShell } from "@/components/public-shell";
import { CCP_PUBLIC_TEST_HOLDER } from "@/lib/protection/ccp-eligibility";
import { readLiveTokenConfiguration } from "@/lib/protection/live-launch-token";

export const metadata: Metadata = {
  title: "Live encrypted execution",
  description: "Start a real BGV conflict check on a verified Cleanverse receivable.",
};

export const dynamic = "force-dynamic";

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export default async function LiveProtectionPage({ searchParams }: {
  readonly searchParams: Promise<Readonly<Record<string, string | string[] | undefined>>>;
}) {
  const query = await searchParams;
  // Exact URL shape: only an optional runId is accepted here.
  const unknownKey = Object.keys(query).find((key) => key !== "runId");
  const rawRunId = typeof query.runId === "string" ? query.runId : null;
  const runId = unknownKey === undefined && rawRunId !== null && RUN_ID.test(rawRunId) ? rawRunId : null;

  let workerOrigin: string | null = null;
  try {
    workerOrigin = readLiveTokenConfiguration().workerOrigin;
  } catch {
    workerOrigin = null;
  }

  if (workerOrigin === null) {
    return (
      <PublicShell surface="live">
        <LiveUnavailable />
      </PublicShell>
    );
  }

  return (
    <PublicShell surface="live">
      <LiveExecution workerOrigin={workerOrigin} initialRunId={runId} publicTestHolder={CCP_PUBLIC_TEST_HOLDER} />
    </PublicShell>
  );
}
