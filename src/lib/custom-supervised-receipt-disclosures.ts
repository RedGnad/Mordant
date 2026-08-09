/**
 * Exact managed-receipt disclosure contract shared by the producer and the
 * browser parser. Keep this module data-only so importing it cannot pull any
 * server or cryptographic implementation into the client bundle.
 */

export const CUSTOM_RECEIPT_EXECUTION_DISCLOSURE =
  "Supervised local single-host execution; not production authorized.";
export const CUSTOM_RECEIPT_PARTICIPANT_DISCLOSURE =
  "Participant-admitted pledge windows under verified durable wallet authorizations; synthetic lender fixtures and no real funds.";
export const CUSTOM_RECEIPT_OPERATOR_DISCLOSURE =
  "Operator-entered pledge windows; synthetic lender fixtures and no real funds.";
export const CUSTOM_RECEIPT_DECRYPTOR_DISCLOSURE =
  "Designated trusted decryptor; no threshold release and no native Monad FHE.";
export const CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE =
  "The governed Boolean establishes conflict status. It is an authenticated input to the precommitted policy, not an authorization for recourse or settlement by itself.";
export const CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE =
  "The precommitted policy selects a bounded managed action branch; it establishes no legal truth and does not authorize settlement.";

/** Exact pre-policy wording retained so already-digested five-line receipts remain readable. */
export const PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE =
  "The governed signed Boolean is the sole authority for the conflict/no-conflict result.";
export const PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE =
  "Configured demo policy determines the recourse path; the Boolean does not assign legal responsibility, action ownership, deadline or payout amount.";

/** Exact historical wording retained only so already-digested receipts remain readable. */
export const LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE =
  "The governed signed Boolean is the sole authority for the terminal outcome.";

export type CustomReceiptDisclosureVersion = "CURRENT" | "PRE_POLICY" | "LEGACY";
export type CustomReceiptIntake = "PARTICIPANT" | "OPERATOR";

function isIntakeDisclosure(value: unknown): boolean {
  return value === CUSTOM_RECEIPT_PARTICIPANT_DISCLOSURE
    || value === CUSTOM_RECEIPT_OPERATOR_DISCLOSURE;
}

export function currentCustomReceiptDisclosures(
  intake: CustomReceiptIntake,
): readonly string[] {
  return Object.freeze([
    CUSTOM_RECEIPT_EXECUTION_DISCLOSURE,
    intake === "PARTICIPANT"
      ? CUSTOM_RECEIPT_PARTICIPANT_DISCLOSURE
      : CUSTOM_RECEIPT_OPERATOR_DISCLOSURE,
    CUSTOM_RECEIPT_DECRYPTOR_DISCLOSURE,
    CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE,
    CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE,
  ]);
}

/**
 * Narrow compatibility gate. It accepts the complete current layout or the
 * complete historical layout and no mixed, partial or user-defined variant.
 */
export function classifyCustomReceiptDisclosures(
  value: unknown,
): CustomReceiptDisclosureVersion | null {
  if (!Array.isArray(value)
    || value[0] !== CUSTOM_RECEIPT_EXECUTION_DISCLOSURE
    || !isIntakeDisclosure(value[1])
    || value[2] !== CUSTOM_RECEIPT_DECRYPTOR_DISCLOSURE) return null;

  if (value.length === 5
    && value[3] === CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE
    && value[4] === CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE) return "CURRENT";

  if (value.length === 5
    && value[3] === PRE_POLICY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE
    && value[4] === PRE_POLICY_CUSTOM_RECEIPT_RECOURSE_BOUNDARY_DISCLOSURE) return "PRE_POLICY";

  if (value.length === 4
    && value[3] === LEGACY_CUSTOM_RECEIPT_BOOLEAN_AUTHORITY_DISCLOSURE) return "LEGACY";

  return null;
}
