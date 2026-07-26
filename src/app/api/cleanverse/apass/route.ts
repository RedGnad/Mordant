import { NextResponse } from "next/server";

import { getCleanverseClient } from "@/lib/cleanverse/client";
import { toPublicAPass } from "@/lib/cleanverse/public-view";
import { cleanverseRouteError, invalidInputResponse } from "@/lib/cleanverse/route-response";
import { queryAPassRequestSchema } from "@/lib/cleanverse/schemas";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<NextResponse> {
  const searchParams = new URL(request.url).searchParams;
  const parsed = queryAPassRequestSchema.safeParse({
    chain: searchParams.get("chain"),
    address: searchParams.get("address"),
  });

  if (!parsed.success) {
    return invalidInputResponse();
  }

  try {
    const result = await getCleanverseClient().queryAPass(parsed.data);
    const data = toPublicAPass(result);

    return NextResponse.json({ data }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return cleanverseRouteError(error);
  }
}
