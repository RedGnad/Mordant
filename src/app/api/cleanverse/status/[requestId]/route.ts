import { NextResponse } from "next/server";

import { getCleanverseClient } from "@/lib/cleanverse/client";
import { toPublicApplyStatus } from "@/lib/cleanverse/public-view";
import { cleanverseRouteError, invalidInputResponse } from "@/lib/cleanverse/route-response";
import { requestIdSchema } from "@/lib/cleanverse/schemas";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ requestId: string }>;
};

export async function GET(_request: Request, context: RouteContext): Promise<NextResponse> {
  const parsed = requestIdSchema.safeParse((await context.params).requestId);
  if (!parsed.success) {
    return invalidInputResponse();
  }

  try {
    const result = await getCleanverseClient().queryApplyStatus(parsed.data);
    const data = toPublicApplyStatus(result);

    return NextResponse.json({ data }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return cleanverseRouteError(error);
  }
}
