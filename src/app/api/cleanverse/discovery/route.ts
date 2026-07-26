import { NextResponse } from "next/server";

import { getCleanverseClient } from "@/lib/cleanverse/client";
import { toPublicDiscovery } from "@/lib/cleanverse/public-view";
import { cleanverseRouteError, invalidInputResponse } from "@/lib/cleanverse/route-response";
import { querySupportedATokensRequestSchema } from "@/lib/cleanverse/schemas";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<NextResponse> {
  const searchParams = new URL(request.url).searchParams;
  const parsed = querySupportedATokensRequestSchema.safeParse({
    chain: searchParams.get("chain"),
    symbol: searchParams.get("symbol") ?? undefined,
    address: searchParams.get("address") ?? undefined,
  });

  if (!parsed.success) {
    return invalidInputResponse();
  }

  try {
    const result = await getCleanverseClient().querySupportedATokens(parsed.data);
    const data = toPublicDiscovery(result);
    return NextResponse.json({ data }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return cleanverseRouteError(error);
  }
}
