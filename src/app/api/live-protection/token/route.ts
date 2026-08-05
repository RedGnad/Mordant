import { NextResponse } from "next/server";

import {
  CcpEligibilityError,
  createCcpReader,
  verifyCcpEligibility,
} from "@/lib/protection/ccp-eligibility";
import {
  LiveLaunchTokenError,
  issuanceAllowed,
  issueLiveLaunchToken,
  readLiveTokenConfiguration,
  type IssuanceWindow,
} from "@/lib/protection/live-launch-token";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Coarse per-instance issuance bound for a public demo. The worker enforces the
// authoritative limits; this only stops trivial bulk minting.
const ISSUANCE: IssuanceWindow = { issued: [] };
const ISSUANCE_LIMIT = 30;
const ISSUANCE_WINDOW_MS = 60_000;
const MAX_BODY_BYTES = 512;

function response(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { "cache-control": "no-store, max-age=0" } });
}

/** Exact request shape: a holder address and nothing else. */
function readHolderAddress(raw: unknown): unknown {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CcpEligibilityError("ADDRESS", 400, "Enter a valid 0x wallet address.");
  }
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "holderAddress") {
    throw new CcpEligibilityError("ADDRESS", 400, "Only a holder address is accepted.");
  }
  return (raw as Record<string, unknown>).holderAddress;
}

export async function POST(request: Request) {
  try {
    if (new URL(request.url).search !== "") {
      return response({ error: "Query parameters are not accepted." }, 400);
    }
    const configuration = readLiveTokenConfiguration();
    if (!issuanceAllowed(ISSUANCE, Date.now(), ISSUANCE_LIMIT, ISSUANCE_WINDOW_MS)) {
      return response({ error: "Too many launch requests. Try again shortly." }, 429);
    }

    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return response({ error: "The request is too large." }, 400);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return response({ error: "The request body must be JSON." }, 400);
    }

    // Eligibility is decided before anything is minted: a holder the active Monad
    // policy rejects never receives a launch token.
    const eligibility = await verifyCcpEligibility(readHolderAddress(parsed), createCcpReader());
    if (!eligibility.eligible) {
      return response({ schemaVersion: "mordant.live-launch-token/1", eligibility, token: null }, 403);
    }

    // The token carries no pledge values and no holder identity: the browser sends
    // the windows directly to the worker, so this route never sees or stores them.
    const issued = issueLiveLaunchToken(configuration, Date.now());
    return response({
      schemaVersion: "mordant.live-launch-token/1",
      token: issued.token,
      expiresAt: issued.expiresAt,
      workerOrigin: issued.workerOrigin,
      eligibility,
    });
  } catch (error) {
    if (error instanceof CcpEligibilityError) return response({ error: error.message, code: error.code }, error.status);
    if (error instanceof LiveLaunchTokenError) return response({ error: error.message }, error.status);
    return response({ error: "Launch token issuance failed." }, 500);
  }
}

export function GET() {
  return response({ error: "Method not allowed." }, 405);
}
