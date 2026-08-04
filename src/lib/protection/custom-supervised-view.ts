/**
 * Distinct product view for a supervised custom V2 run.
 *
 * The V1 view `mordant.protection-product-view/1` is untouched: it keeps its
 * exact shape, its `productScenario`, and its V1-only guard. A custom run
 * cannot honestly be squeezed into it, because before governed release it has
 * no scenario at all, and pretending otherwise is what forced the earlier
 * `as unknown as ProductScenario` cast.
 *
 * So a custom run gets its own schema. Before release it exposes
 * `terminalScenario: null` and `governedResult: null`; after a verified
 * governed release the terminal scenario derives from the signed Boolean and
 * from nothing else.
 */

import type { Sha256Digest } from "./cleanverse-asset";
import type { ProductScenario } from "./protection-case";
import { CUSTOM_SUPERVISED_EXECUTION_VARIANT } from "./custom-supervised-v2";
import type { CustomSupervisedProtectionReceipt } from "./custom-supervised-receipt";

export const CUSTOM_SUPERVISED_VIEW_SCHEMA = "mordant.custom-supervised-protection-view/1" as const;

export const CUSTOM_INCIDENT_STATES = Object.freeze([
  "AUTHORIZED", "PRIVATE_MATCH_OPEN", "EVALUATED", "CONFLICT_CONFIRMED", "CLEARED",
] as const);

export const CUSTOM_RECOURSE_STATES = Object.freeze([
  "NOT_OPEN", "CURE_WINDOW", "AVAILABLE", "SIMULATED_AVAILABLE", "REFUSED",
] as const);

export type CustomSupervisedProtectionView = Readonly<{
  schemaVersion: typeof CUSTOM_SUPERVISED_VIEW_SCHEMA;
  runId: string;
  executionVariant: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
  stage: string;
  nextOperation: string | null;
  /** Null until a verified governed release exists. Never predicted. */
  terminalScenario: ProductScenario | null;
  protectionCase: Readonly<{
    cleanverseAssetDigest: Sha256Digest;
    fheCaseId: Sha256Digest;
    incidentState: (typeof CUSTOM_INCIDENT_STATES)[number];
    recourseState: (typeof CUSTOM_RECOURSE_STATES)[number];
    cureDeadline: string | null;
  }>;
  participantArtifactDigests: Readonly<{
    participantA: Sha256Digest | null;
    participantB: Sha256Digest | null;
  }>;
  evaluatedArtifactDigest: Sha256Digest | null;
  governedResult: null | Readonly<{
    conflict: boolean;
    digest: Sha256Digest;
    releaseMode: "governed-decryptor-v1";
  }>;
  recourse: null | Readonly<{ opened: boolean; reason: "SIGNED_RESULT_FALSE" | null }>;
  receipt: CustomSupervisedProtectionReceipt | null;
}>;

function record(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value: unknown, keys: readonly string[]): value is Readonly<Record<string, unknown>> {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function digest(value: unknown): value is Sha256Digest {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

/**
 * Field names that must never appear anywhere in a custom browser-visible view.
 */
const FORBIDDEN_VIEW_KEYS = Object.freeze([
  "productScenario", "activeFrom", "activeUntil", "supervisedPledgeWindows", "pledges",
]);

/**
 * Strict exact parser. Returns null rather than throwing so the browser can
 * treat a mismatched view as an ordinary refusal.
 */
export function parseCustomSupervisedProtectionView(value: unknown): CustomSupervisedProtectionView | null {
  if (!exactRecord(value, [
    "schemaVersion", "runId", "executionVariant", "stage", "nextOperation", "terminalScenario",
    "protectionCase", "participantArtifactDigests", "evaluatedArtifactDigest", "governedResult",
    "recourse", "receipt",
  ])) return null;
  if (value.schemaVersion !== CUSTOM_SUPERVISED_VIEW_SCHEMA) return null;
  if (value.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) return null;
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) return null;
  if (typeof value.stage !== "string") return null;
  if (value.nextOperation !== null && typeof value.nextOperation !== "string") return null;

  const protectionCase = value.protectionCase;
  if (!exactRecord(protectionCase, [
    "cleanverseAssetDigest", "fheCaseId", "incidentState", "recourseState", "cureDeadline",
  ])) return null;
  if (!digest(protectionCase.cleanverseAssetDigest) || !digest(protectionCase.fheCaseId)) return null;
  if (!CUSTOM_INCIDENT_STATES.includes(protectionCase.incidentState as never)) return null;
  if (!CUSTOM_RECOURSE_STATES.includes(protectionCase.recourseState as never)) return null;
  if (protectionCase.cureDeadline !== null && typeof protectionCase.cureDeadline !== "string") return null;

  const digests = value.participantArtifactDigests;
  if (!exactRecord(digests, ["participantA", "participantB"])) return null;
  for (const entry of [digests.participantA, digests.participantB]) {
    if (entry !== null && !digest(entry)) return null;
  }
  if (value.evaluatedArtifactDigest !== null && !digest(value.evaluatedArtifactDigest)) return null;

  const governedResult = value.governedResult;
  if (governedResult !== null) {
    if (!exactRecord(governedResult, ["conflict", "digest", "releaseMode"])) return null;
    if (typeof governedResult.conflict !== "boolean") return null;
    if (!digest(governedResult.digest)) return null;
    if (governedResult.releaseMode !== "governed-decryptor-v1") return null;
  }

  const recourse = value.recourse;
  if (recourse !== null) {
    if (!exactRecord(recourse, ["opened", "reason"])) return null;
    if (typeof recourse.opened !== "boolean") return null;
    if (recourse.reason !== null && recourse.reason !== "SIGNED_RESULT_FALSE") return null;
  }

  // The terminal scenario exists only after a governed release, and must agree
  // with the signed Boolean. A pre-release view claiming one is refused.
  const terminalScenario = value.terminalScenario;
  if (governedResult === null) {
    if (terminalScenario !== null) return null;
  } else {
    const expected = (governedResult.conflict as boolean) ? "conflict" : "no-conflict";
    if (terminalScenario !== expected) return null;
  }

  if (value.receipt !== null && !record(value.receipt)) return null;
  // A receipt must agree with the governed Boolean it accompanies.
  if (record(value.receipt) && governedResult !== null) {
    const receiptResult = value.receipt.governedResult;
    if (!record(receiptResult) || receiptResult.conflict !== governedResult.conflict) return null;
  }

  const encoded = JSON.stringify(value);
  for (const forbidden of FORBIDDEN_VIEW_KEYS) {
    if (encoded.includes(`"${forbidden}"`)) return null;
  }
  return value as unknown as CustomSupervisedProtectionView;
}

export function isCustomSupervisedProtectionView(value: unknown): boolean {
  return record(value) && value.schemaVersion === CUSTOM_SUPERVISED_VIEW_SCHEMA;
}
