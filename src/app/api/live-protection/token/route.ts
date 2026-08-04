import { NextResponse } from "next/server";

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

function response(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { "cache-control": "no-store, max-age=0" } });
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
    // The token carries no pledge values: the browser sends those directly to
    // the worker, so this route never sees or stores a visitor's windows.
    const issued = issueLiveLaunchToken(configuration, Date.now());
    return response({
      schemaVersion: "mordant.live-launch-token/1",
      token: issued.token,
      expiresAt: issued.expiresAt,
      workerOrigin: issued.workerOrigin,
    });
  } catch (error) {
    if (error instanceof LiveLaunchTokenError) return response({ error: error.message }, error.status);
    return response({ error: "Launch token issuance failed." }, 500);
  }
}

export function GET() {
  return response({ error: "Method not allowed." }, 405);
}
