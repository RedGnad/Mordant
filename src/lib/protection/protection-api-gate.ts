import { timingSafeEqual } from "node:crypto";

export type MutationGateDecision = Readonly<{
  allowed: boolean;
  status: 404 | 405 | null;
  reason: "PRODUCTION_READ_ONLY" | "LOCAL_EXECUTION_DISABLED" | "MUTATION_ORIGIN_REJECTED" | null;
}>;

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function protectionMutationGate(request: Request, environment: NodeJS.ProcessEnv = process.env): MutationGateDecision {
  if (environment.NODE_ENV === "production") {
    return { allowed: false, status: 405, reason: "PRODUCTION_READ_ONLY" };
  }
  if (environment.MORDANT_LOCAL_EXECUTION_ENABLED !== "1") {
    return { allowed: false, status: 404, reason: "LOCAL_EXECUTION_DISABLED" };
  }
  const configured = environment.MORDANT_LOCAL_ADMIN_CAPABILITY;
  const supplied = request.headers.get("x-mordant-admin-capability");
  const capability = configured !== undefined && configured.length >= 32 && supplied !== null
    && constantTimeEqual(configured, supplied);
  return capability
    ? { allowed: true, status: null, reason: null }
    : { allowed: false, status: 404, reason: "MUTATION_ORIGIN_REJECTED" };
}
