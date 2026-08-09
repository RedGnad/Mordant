import type { Metadata } from "next";

import { ProtectionExperience } from "@/components/protection-experience";
import { loadImportedProtectionEvidence } from "@/lib/protection/governed-fhe-product-server";
import type { ProductScenario } from "@/lib/protection/protection-case";

export const metadata: Metadata = {
  title: "Retained case evidence",
  description: "Inspect the governed result, chronology and public evidence for a retained Mordant protection case.",
};

type ProtectionSearchParams = Readonly<Record<string, string | string[] | undefined>>;

function single(value: string | string[] | undefined): string | null {
  return typeof value === "string" ? value : value === undefined ? null : "INVALID";
}

function localAdapterOrigin(): string | null {
  if (process.env.NODE_ENV !== "development" || process.env.MORDANT_LOCAL_EXECUTION_ENABLED !== "1") return null;
  const sourceCommit = process.env.MORDANT_PROTECTION_SOURCE_COMMIT;
  if (sourceCommit === undefined || !/^(?!0{40}$)[0-9a-f]{40}$/u.test(sourceCommit)) return null;
  const configured = process.env.MORDANT_LOCAL_ADAPTER_ORIGIN;
  if (configured === undefined) return null;
  try {
    const url = new URL(configured);
    if (
      url.protocol !== "http:"
      || url.hostname !== "127.0.0.1"
      || url.port === ""
      || url.pathname !== "/protection"
      || url.username !== ""
      || url.password !== ""
      || url.search !== ""
      || url.hash !== ""
    ) return null;
    return url.toString().replace(/\/$/u, "");
  } catch {
    return null;
  }
}

export default async function ProtectionPage({ searchParams }: {
  readonly searchParams: Promise<ProtectionSearchParams>;
}) {
  const query = await searchParams;
  const unknownQueryKey = Object.keys(query).find((key) => key !== "scenario" && key !== "runId");
  const rawScenario = single(query.scenario);
  const rawRunId = single(query.runId);
  const scenario: ProductScenario = rawScenario === "no-conflict" ? "no-conflict" : "conflict";
  const scenarioValid = rawScenario === null || rawScenario === "conflict" || rawScenario === "no-conflict";
  const runIdValid = rawRunId === null || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(rawRunId);
  const runHasScenario = rawRunId === null || rawScenario === "conflict" || rawScenario === "no-conflict";
  let initialUrlError = unknownQueryKey !== undefined || !scenarioValid
    ? "The protection scenario URL is invalid. Choose Conflict or No conflict."
    : !runIdValid || !runHasScenario
      ? "The durable local run URL is invalid. A run requires its validated scenario and run identifier."
      : null;
  const initialRunId = initialUrlError === null ? rawRunId : null;
  let evidence: ReturnType<typeof loadImportedProtectionEvidence> | null = null;
  if (initialUrlError === null && initialRunId === null) {
    try {
      evidence = loadImportedProtectionEvidence(scenario);
    } catch {
      // A rejected retained manifest is never serialized into SSR, RSC or the
      // hydration payload. The public surface receives one bounded message.
      initialUrlError = "Verified protection evidence is unavailable.";
    }
  }
  return (
    <ProtectionExperience
      initialEvidence={evidence}
      initialScenario={scenario}
      initialRunId={initialRunId}
      initialUrlError={initialUrlError}
      localAdapterOrigin={localAdapterOrigin()}
    />
  );
}
