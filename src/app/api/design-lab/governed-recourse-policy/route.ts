import {
  applyExperimentCommand,
  parseExperimentCommand,
  readExperimentView,
} from "@/lib/recourse-policy-experiment/experiment-store";
import { RecoursePolicyError } from "@/lib/recourse-policy-experiment/policy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function unavailable(): Response {
  return Response.json({ error: "EXPERIMENT_DISABLED", message: "This design-lab route is unavailable in production." }, { status: 404 });
}

export async function GET(): Promise<Response> {
  if (process.env.NODE_ENV === "production") return unavailable();
  return Response.json(readExperimentView(), { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: Request): Promise<Response> {
  if (process.env.NODE_ENV === "production") return unavailable();
  try {
    const command = parseExperimentCommand(await request.json());
    return Response.json(applyExperimentCommand(command), { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof RecoursePolicyError) {
      return Response.json({ error: error.code, message: error.message }, { status: 409 });
    }
    if (error instanceof SyntaxError) {
      return Response.json({ error: "INVALID_JSON", message: "Request body must be JSON." }, { status: 400 });
    }
    throw error;
  }
}
