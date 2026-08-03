import type { ProductScenario } from "./protection-case";

export const PROTECTION_RECOVERY_STORAGE_KEY = "mordant.protection.browser-recovery.v1";
export const PROTECTION_RECOVERY_TTL_MS = 24 * 60 * 60 * 1_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MUTATIONS = new Set([
  "preparePrivateMatch",
  "submitParticipantA",
  "submitParticipantB",
  "evaluatePrivateConflict",
  "releaseGovernedResult",
  "openRecourseCase",
  "completeCureChronology",
  "exportProtectionEvidence",
]);

type RecoveryBase = Readonly<{
  schemaVersion: "mordant.protection-browser-recovery/1";
  scenario: ProductScenario;
  createdAtUnix: number;
  expiresAtUnix: number;
}>;

export type ProtectionBrowserRecovery =
  | (RecoveryBase & Readonly<{
    kind: "CREATION_PENDING";
    creationRequestId: string;
  }>)
  | (RecoveryBase & Readonly<{
    kind: "MUTATION_PENDING";
    runId: string;
    operation: string;
  }>)
  | (RecoveryBase & Readonly<{
    kind: "RETENTION_REQUIRED";
    runId: string;
    operation: "retainProtectionEvidence";
  }>);

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function validBase(value: Record<string, unknown>, nowUnix: number): boolean {
  return value.schemaVersion === "mordant.protection-browser-recovery/1"
    && (value.scenario === "conflict" || value.scenario === "no-conflict")
    && typeof value.createdAtUnix === "number"
    && Number.isSafeInteger(value.createdAtUnix)
    && typeof value.expiresAtUnix === "number"
    && Number.isSafeInteger(value.expiresAtUnix)
    && value.expiresAtUnix === value.createdAtUnix + PROTECTION_RECOVERY_TTL_MS
    && value.createdAtUnix <= nowUnix + 60_000
    && value.createdAtUnix >= nowUnix - PROTECTION_RECOVERY_TTL_MS
    && value.expiresAtUnix > nowUnix;
}

export function parseProtectionBrowserRecovery(
  raw: string,
  nowUnix = Date.now(),
): ProtectionBrowserRecovery | null {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (!record(value) || !validBase(value, nowUnix)) return null;
  if (
    value.kind === "CREATION_PENDING"
    && exactKeys(value, ["schemaVersion", "kind", "scenario", "creationRequestId", "createdAtUnix", "expiresAtUnix"])
    && typeof value.creationRequestId === "string"
    && UUID.test(value.creationRequestId)
  ) return structuredClone(value) as ProtectionBrowserRecovery;
  if (
    value.kind === "MUTATION_PENDING"
    && exactKeys(value, ["schemaVersion", "kind", "scenario", "runId", "operation", "createdAtUnix", "expiresAtUnix"])
    && typeof value.runId === "string"
    && UUID.test(value.runId)
    && typeof value.operation === "string"
    && MUTATIONS.has(value.operation)
  ) return structuredClone(value) as ProtectionBrowserRecovery;
  if (
    value.kind === "RETENTION_REQUIRED"
    && exactKeys(value, ["schemaVersion", "kind", "scenario", "runId", "operation", "createdAtUnix", "expiresAtUnix"])
    && typeof value.runId === "string"
    && UUID.test(value.runId)
    && value.operation === "retainProtectionEvidence"
  ) return structuredClone(value) as ProtectionBrowserRecovery;
  return null;
}

function base(scenario: ProductScenario, nowUnix: number): RecoveryBase {
  return {
    schemaVersion: "mordant.protection-browser-recovery/1",
    scenario,
    createdAtUnix: nowUnix,
    expiresAtUnix: nowUnix + PROTECTION_RECOVERY_TTL_MS,
  };
}

export function pendingCreationRecovery(
  scenario: ProductScenario,
  creationRequestId: string,
  nowUnix = Date.now(),
): ProtectionBrowserRecovery {
  if (!UUID.test(creationRequestId)) throw new Error("Invalid creation recovery identifier");
  return { ...base(scenario, nowUnix), kind: "CREATION_PENDING", creationRequestId };
}

export function pendingMutationRecovery(
  scenario: ProductScenario,
  runId: string,
  operation: string,
  nowUnix = Date.now(),
): ProtectionBrowserRecovery {
  if (!UUID.test(runId) || !MUTATIONS.has(operation)) throw new Error("Invalid mutation recovery authority");
  return { ...base(scenario, nowUnix), kind: "MUTATION_PENDING", runId, operation };
}

export function retentionRequiredRecovery(
  scenario: ProductScenario,
  runId: string,
  nowUnix = Date.now(),
): ProtectionBrowserRecovery {
  if (!UUID.test(runId)) throw new Error("Invalid retention recovery authority");
  return { ...base(scenario, nowUnix), kind: "RETENTION_REQUIRED", runId, operation: "retainProtectionEvidence" };
}
