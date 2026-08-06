/**
 * Local-only receipt for a supervised custom V2 run.
 *
 * A custom run cannot honestly produce `mordant.protection-evidence/4`: that
 * schema cross-checks its `scenario` against `binding.productScenario`, and a
 * neutral V2 authorization has no product scenario at all. Rather than widen or
 * weaken the published V1 evidence contract, a custom run produces this
 * separate receipt.
 *
 * The receipt is retained only under the run-specific custom directory. It is
 * never served publicly and never enters the imported-evidence parser.
 */

import { createHash } from "node:crypto";

import { canonicalJson, type Sha256Digest } from "./cleanverse-asset";
import { CUSTOM_SUPERVISED_EXECUTION_VARIANT } from "./custom-supervised-v2";

export const CUSTOM_SUPERVISED_RECEIPT_SCHEMA = "mordant.custom-supervised-protection-receipt/1" as const;

export type CustomSupervisedProtectionReceipt = Readonly<{
  schemaVersion: typeof CUSTOM_SUPERVISED_RECEIPT_SCHEMA;
  receiptDigest: Sha256Digest;
  runId: string;
  sourceCommit: string;
  governedFheCommit: string;
  executionVariant: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
  authorization: Readonly<{
    protectionBindingSchema: string;
    protectionBindingDigest: Sha256Digest;
    fheCaseId: Sha256Digest;
    caseBindingDigest: Sha256Digest;
  }>;
  execution: Readonly<{
    participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
    evaluatedArtifactDigest: Sha256Digest;
    evaluatorProvenance: Sha256Digest;
    decryptorProvenance: Sha256Digest;
    circuitId: string;
    parameterProfile: string;
  }>;
  governedResult: Readonly<{
    conflict: boolean;
    digest: Sha256Digest;
    releaseMode: string;
    releaseOrdinal: number;
    resultCiphertextDigest: Sha256Digest;
    independentlyRecomputedResultDigest: Sha256Digest;
  }>;
  terminal: Readonly<{
    incidentState: string;
    recourseState: string;
    recourseOpened: boolean;
    recourseRefusal: string | null;
    recourseRecordDigest: Sha256Digest | null;
    originalReceivableState: string;
  }>;
  chronology: Readonly<{
    clockClass: string;
    signedAtUnix: number;
    events: readonly Readonly<{ ordinal: number; kind: string; atUnix: number | null }>[];
  }>;
  disclosures: readonly string[];
}>;

/**
 * Field names that must never appear anywhere in a receipt. The raw operator
 * windows, private identifiers, key material and local paths are all private
 * execution input or private artifacts.
 */
const FORBIDDEN_RECEIPT_KEYS = Object.freeze([
  "activeFrom", "activeUntil", "supervisedPledgeWindows", "pledges", "participantA", "participantB",
  "receivableId", "obligationId", "authorizationCommitment", "privateMetadataCommitment",
  "privateKey", "signingKey", "decryptorPrivate", "participantPrivate", "path", "root",
]);

export function customSupervisedReceiptDigest(
  receipt: Omit<CustomSupervisedProtectionReceipt, "receiptDigest">,
): Sha256Digest {
  const encoded = `MordantCustomSupervisedReceipt/v1\0${canonicalJson(receipt)}`;
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

export class CustomSupervisedReceiptError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "CustomSupervisedReceiptError";
  }
}

/**
 * Verifies a receipt is internally consistent and free of private material.
 * This is the custom-path counterpart of the V1 evidence verifier; it does not
 * touch, widen or reuse the V1 verifier.
 */
export function assertCustomSupervisedReceipt(receipt: CustomSupervisedProtectionReceipt): void {
  if (receipt.schemaVersion !== CUSTOM_SUPERVISED_RECEIPT_SCHEMA) {
    throw new CustomSupervisedReceiptError("SCHEMA", "Unsupported custom receipt schema");
  }
  if (receipt.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
    throw new CustomSupervisedReceiptError("EXECUTION_VARIANT", "A custom receipt must declare CUSTOM_SUPERVISED");
  }
  const { receiptDigest, ...body } = receipt;
  if (receiptDigest !== customSupervisedReceiptDigest(body)) {
    throw new CustomSupervisedReceiptError("RECEIPT_DIGEST", "Custom receipt digest mismatch");
  }
  // The terminal state must follow the governed Boolean, never the reverse.
  const conflict = receipt.governedResult.conflict;
  if (receipt.terminal.incidentState !== (conflict ? "CONFLICT_CONFIRMED" : "CLEARED")) {
    throw new CustomSupervisedReceiptError("TERMINAL_INCIDENT", "Terminal incident state does not follow the governed Boolean");
  }
  if (receipt.terminal.recourseOpened !== conflict) {
    throw new CustomSupervisedReceiptError("TERMINAL_RECOURSE", "Recourse outcome does not follow the governed Boolean");
  }
  if (!conflict && receipt.terminal.recourseRefusal !== "SIGNED_RESULT_FALSE") {
    throw new CustomSupervisedReceiptError("TERMINAL_REFUSAL", "A false governed Boolean must record a signed refusal");
  }
  if (conflict && receipt.terminal.recourseRecordDigest === null) {
    throw new CustomSupervisedReceiptError("TERMINAL_RECORD", "A true governed Boolean must bind a recourse record");
  }
  if (receipt.governedResult.resultCiphertextDigest !== receipt.governedResult.independentlyRecomputedResultDigest) {
    throw new CustomSupervisedReceiptError("RECOMPUTATION", "Governed recomputation digest mismatch");
  }
  if (receipt.terminal.originalReceivableState !== "OUTSTANDING_INTACT") {
    throw new CustomSupervisedReceiptError("RECEIVABLE", "The original receivable must remain intact");
  }
  const encoded = canonicalJson(receipt);
  for (const forbidden of FORBIDDEN_RECEIPT_KEYS) {
    if (encoded.includes(`"${forbidden}"`)) {
      throw new CustomSupervisedReceiptError("PRIVATE_LEAK", `A custom receipt must not expose ${forbidden}`);
    }
  }
}
