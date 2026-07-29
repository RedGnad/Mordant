import { NextResponse } from "next/server";

import {
  LivingDemoError,
  executeLivingDemoAction,
  getLivingDemoRun,
  resetLivingDemoRun,
} from "@/lib/dealroom/living-demo-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function response(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "cache-control": "no-store, max-age=0" },
  });
}

function failure(error: unknown) {
  if (error instanceof LivingDemoError) {
    return response({ error: error.message }, error.status);
  }
  const message = error instanceof Error ? error.message : "Unknown controlled execution error";
  return response({ error: message }, 500);
}

export async function GET() {
  try {
    return response(await getLivingDemoRun());
  } catch (error) {
    return failure(error);
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as { intent?: unknown; actionId?: unknown };
    if (body.intent === "reset") {
      return response(await resetLivingDemoRun());
    }
    if (body.intent === "execute" && typeof body.actionId === "string") {
      return response(await executeLivingDemoAction(body.actionId));
    }
    return response({ error: "Expected reset or an executable action id." }, 400);
  } catch (error) {
    return failure(error);
  }
}
