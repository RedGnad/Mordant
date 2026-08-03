import { NextResponse } from "next/server";

import {
  ProtectionProductError,
  loadImportedProtectionEvidence,
  readProtectionCreation,
  readRetainedProtectionEvidenceInConfiguredRoot,
  readProtectionCase,
} from "../../../../lib/protection/governed-fhe-product-server";
import { createProtectionPostHandler } from "../../../../lib/protection/protection-api-route";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function response(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "cache-control": "no-store, max-age=0" },
  });
}

function failure(error: unknown) {
  if (error instanceof ProtectionProductError && error.status < 500) return response({ error: error.message }, error.status);
  if (error instanceof ProtectionProductError && error.status === 507) return response({ error: error.message }, error.status);
  return response({ error: "Protection operation failed" }, 500);
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const runId = url.searchParams.get("runId");
    if (runId !== null) {
      if (
        url.searchParams.getAll("runId").length !== 1
        || [...url.searchParams.keys()].some((key) => key !== "runId")
      ) {
        return response({ error: "Only an exact protection runId may be read." }, 400);
      }
      const view = await readProtectionCase(runId);
      if (view.stage !== "COMPLETE") return response(view);
      try {
        const retained = readRetainedProtectionEvidenceInConfiguredRoot(runId);
        return response({ ...view, evidence: retained.evidence });
      } catch (error) {
        if (!(error instanceof ProtectionProductError) || error.status !== 423) throw error;
        return response({
          schemaVersion: "mordant.protection-retention-required/1",
          status: "RETENTION_REQUIRED",
          runId: view.runId,
          scenario: view.protectionCase.productScenario,
          recoveryOperation: "retainProtectionEvidence",
        });
      }
    }
    const creationRequestId = url.searchParams.get("creationRequestId");
    if (creationRequestId !== null) {
      if (
        url.searchParams.getAll("creationRequestId").length !== 1
        || [...url.searchParams.keys()].some((key) => key !== "creationRequestId")
      ) {
        return response({ error: "Only an exact creationRequestId may be read." }, 400);
      }
      return response(await readProtectionCreation(creationRequestId));
    }
    const requestedScenario = url.searchParams.get("scenario") ?? "conflict";
    if (
      (requestedScenario !== "conflict" && requestedScenario !== "no-conflict")
      || url.searchParams.getAll("scenario").length > 1
      || [...url.searchParams.keys()].some((key) => key !== "scenario")
    ) return response({ error: "Unsupported protection evidence scenario." }, 400);
    const scenario = requestedScenario;
    return response({
      schemaVersion: "mordant.protection-imported-view/1",
      presentation: "IMPORTED_COMPLETED_EVIDENCE",
      evidence: loadImportedProtectionEvidence(scenario),
    });
  } catch (error) {
    return failure(error);
  }
}

export const POST = createProtectionPostHandler();
