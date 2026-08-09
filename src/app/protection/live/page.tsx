import type { Metadata } from "next";

import { LiveExecution } from "@/components/live-execution";
import { LiveUnavailable } from "@/components/live-unavailable";
import { capabilities } from "@/components/live-product/live-product-view-model";
import { PublicShell } from "@/components/public-shell";
import { MONAD_TESTNET_CHAIN_ID, loadCanonicalRecourseBridgeArtifacts } from "@/lib/protection/adapter-compatibility";
import { CCP_PUBLIC_TEST_HOLDER } from "@/lib/protection/ccp-eligibility";
import { readLiveTokenConfiguration } from "@/lib/protection/live-launch-token";

export const metadata: Metadata = {
  title: "Live encrypted execution",
  description: "Run Mordant's first workflow from governed private result through precommitted policy and verified bounded action.",
};

export const dynamic = "force-dynamic";

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CASE_CODE = /^[0-9A-HJKMNP-TV-Z]{16}$/u;

/**
 * The dormant two-wallet rail is server-gated on both explicit acknowledgements
 * and the byte-pinned canonical V2 artifacts. Nothing from this decision (and
 * none of the environment values) is serialized into the client.
 */
function directParticipantAdmissionEnabled(): boolean {
  if (process.env.MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION !== "enabled"
    || process.env.MORDANT_WORKER_DIRECT_PARTICIPANT_ADMISSION_ACK !== "MORDANT_PARTICIPANT_ADMISSION_V1") return false;
  const workerChainId = process.env.MORDANT_WORKER_CHAIN_ID;
  const workerMaxActiveCases = process.env.MORDANT_WORKER_MAX_ACTIVE_CASES;
  if ((workerChainId !== undefined && workerChainId !== "10143")
    || (workerMaxActiveCases !== undefined && workerMaxActiveCases !== "1")) return false;
  try {
    const canonical = loadCanonicalRecourseBridgeArtifacts();
    return canonical.configuration.adapter.chainId === MONAD_TESTNET_CHAIN_ID
      && canonical.adapter.chainId === MONAD_TESTNET_CHAIN_ID;
  } catch {
    return false;
  }
}

export default async function LiveProtectionPage({ searchParams }: {
  readonly searchParams: Promise<Readonly<Record<string, string | string[] | undefined>>>;
}) {
  const query = await searchParams;
  // Exact URL shape: no identifier, or one identifier for its matching rail.
  const keys = Object.keys(query);
  const unknownKey = keys.find((key) => key !== "runId" && key !== "caseCode");
  const rawRunId = typeof query.runId === "string" ? query.runId : null;
  const rawCaseCode = typeof query.caseCode === "string" ? query.caseCode : null;
  const runId = unknownKey === undefined && keys.length === 1 && rawRunId !== null && RUN_ID.test(rawRunId) ? rawRunId : null;
  const caseCode = unknownKey === undefined && keys.length === 1 && rawCaseCode !== null && CASE_CODE.test(rawCaseCode) ? rawCaseCode : null;

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

  const directAdmission = directParticipantAdmissionEnabled();
  const capabilitySet = directAdmission
    ? capabilities("DIRECT_PARTICIPANT_ADMISSION")
    : capabilities("MANAGED_COMBINED_INTAKE");

  return (
    <PublicShell surface="live">
      <LiveExecution
        workerOrigin={workerOrigin}
        initialRunId={directAdmission ? null : runId}
        initialCaseCode={directAdmission ? caseCode : null}
        publicTestHolder={CCP_PUBLIC_TEST_HOLDER}
        capabilitySet={capabilitySet}
      />
    </PublicShell>
  );
}
