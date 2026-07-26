import "server-only";

import { NextResponse } from "next/server";
import { ZodError } from "zod";

import { CleanverseApiError } from "./client";
import { CleanverseConfigError } from "./config";
import { CleanverseKeyError } from "./crypto";

export function invalidInputResponse(): NextResponse {
  return NextResponse.json({ error: "Invalid request input" }, { status: 400 });
}

export function cleanverseRouteError(error: unknown): NextResponse {
  if (error instanceof ZodError) {
    return invalidInputResponse();
  }

  if (error instanceof CleanverseApiError) {
    return NextResponse.json(
      {
        error: "Cleanverse request failed",
        ...(error.upstreamCode ? { code: error.upstreamCode } : {}),
      },
      { status: 502 },
    );
  }

  if (error instanceof CleanverseConfigError || error instanceof CleanverseKeyError) {
    return NextResponse.json({ error: "Cleanverse integration is unavailable" }, { status: 503 });
  }

  return NextResponse.json({ error: "Unexpected server error" }, { status: 500 });
}
