import "server-only";

import { NextResponse } from "next/server";

import {
  ProtectionProductError,
  completeCureChronology,
  createProtectionCase,
  evaluatePrivateConflict,
  exportProtectionEvidence,
  openRecourseCase,
  preparePrivateMatch,
  releaseGovernedResult,
  retainProtectionEvidenceInConfiguredRoot,
  submitParticipantPledge,
} from "./governed-fhe-product-server";
import { protectionMutationGate } from "./protection-api-gate";
import {
  SupervisedPledgeWindowsError,
  assertSupervisedPledgeWindows,
} from "./supervised-pledge-windows";

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

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function createProtectionPostHandler(environment: NodeJS.ProcessEnv = process.env) {
  return async function post(request: Request) {
    const gate = protectionMutationGate(request, environment);
    if (!gate.allowed) return response({ error: "Protection mutation endpoint unavailable" }, gate.status ?? 404);
    try {
      if (new URL(request.url).search !== "") {
        return response({ error: "Protection mutation query parameters are not accepted." }, 400);
      }
      const parsed: unknown = await request.json();
      if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
        return response({ error: "Expected an exact product-level protection operation." }, 400);
      }
      const body = parsed as Record<string, unknown>;
      if (
        body.intent === "create"
        && exactKeys(body, ["intent", "scenario", "creationRequestId"])
        && (body.scenario === "conflict" || body.scenario === "no-conflict")
        && typeof body.creationRequestId === "string"
      ) {
        return response(await createProtectionCase(body.scenario, body.creationRequestId));
      }
      // Supervised custom create. The scenario stays a routing value only: the
      // scenario that enters the signed binding is derived from the operator's
      // own windows, so this field cannot predict or constrain the result.
      if (
        body.intent === "create"
        && exactKeys(body, ["intent", "scenario", "creationRequestId", "pledges"])
        && (body.scenario === "conflict" || body.scenario === "no-conflict")
        && typeof body.creationRequestId === "string"
      ) {
        let windows;
        try {
          windows = assertSupervisedPledgeWindows(body.pledges);
        } catch (error) {
          // The message names the offending field, never the entered values.
          return response({
            error: error instanceof SupervisedPledgeWindowsError
              ? error.message
              : "Supervised pledge windows rejected.",
          }, 400);
        }
        return response(await createProtectionCase(body.scenario, body.creationRequestId, windows));
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
        case "retainProtectionEvidence": return response(await retainProtectionEvidenceInConfiguredRoot(body.runId));
        default: return response({ error: "Unsupported product-level protection operation." }, 400);
      }
    } catch (error) {
      return failure(error);
    }
  };
}
