import { NextResponse } from "next/server";

import {
  ProtectionProductError,
  completeCureChronology,
  createProtectionCase,
  evaluatePrivateConflict,
  exportProtectionEvidence,
  loadImportedProtectionEvidence,
  openRecourseCase,
  preparePrivateMatch,
  readProtectionCase,
  releaseGovernedResult,
  submitParticipantPledge,
} from "@/lib/protection/governed-fhe-product-server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function response(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "cache-control": "no-store, max-age=0" },
  });
}

function failure(error: unknown) {
  if (error instanceof ProtectionProductError) return response({ error: error.message }, error.status);
  return response({ error: error instanceof Error ? error.message : "Protection operation failed" }, 500);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const runId = url.searchParams.get("runId");
    if (runId !== null) return response(readProtectionCase(runId));
    const scenario = url.searchParams.get("scenario") === "no-conflict" ? "no-conflict" : "conflict";
    return response({
      schemaVersion: "mordant.protection-imported-view/1",
      presentation: "IMPORTED_COMPLETED_EVIDENCE",
      evidence: loadImportedProtectionEvidence(scenario),
    });
  } catch (error) {
    return failure(error);
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as Record<string, unknown>;
    if (
      body.intent === "create"
      && exactKeys(body, ["intent", "scenario"])
      && (body.scenario === "conflict" || body.scenario === "no-conflict")
    ) {
      return response(await createProtectionCase(body.scenario));
    }
    if (
      body.intent !== "execute"
      || !exactKeys(body, ["intent", "runId", "operation"])
      || typeof body.runId !== "string"
      || typeof body.operation !== "string"
    ) {
      return response({ error: "Expected an exact product-level protection operation." }, 400);
    }
    switch (body.operation) {
      case "preparePrivateMatch": return response(await preparePrivateMatch(body.runId));
      case "submitParticipantA": return response(await submitParticipantPledge(body.runId, "PARTICIPANT_A"));
      case "submitParticipantB": return response(await submitParticipantPledge(body.runId, "PARTICIPANT_B"));
      case "evaluatePrivateConflict": return response(await evaluatePrivateConflict(body.runId));
      case "releaseGovernedResult": return response(await releaseGovernedResult(body.runId));
      case "openRecourseCase": return response(await openRecourseCase(body.runId));
      case "completeCureChronology": return response(await completeCureChronology(body.runId));
      case "exportProtectionEvidence": return response(await exportProtectionEvidence(body.runId));
      default: return response({ error: "Unsupported product-level protection operation." }, 400);
    }
  } catch (error) {
    return failure(error);
  }
}
