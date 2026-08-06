/**
 * Presentation model for the live product.
 *
 * UI-owned on purpose. It is deliberately NOT placed in `src/lib/protection`,
 * which the runtime agent owns: nothing here may be imported by the runtime, and
 * nothing from the runtime schemas is imported here. The only coupling to the
 * backend is the narrow `ManagedWorkerView` shape below, which mirrors the
 * fields the deployed worker already returns and is re-validated at the edge.
 *
 * The model exists so the components can be built once and connected later. A
 * capability that has not been qualified is not rendered, and the adapter is the
 * only place allowed to decide what the current backend can honestly claim.
 */

// ---------------------------------------------------------------- capabilities

export const LIVE_PRODUCT_CAPABILITIES = [
  "MANAGED_COMBINED_INTAKE",
  "SEPARATE_WALLET_STAGING",
  "DIRECT_PARTICIPANT_ADMISSION",
  "ONCHAIN_RECOURSE_CONNECTED",
  "WALLETCONNECT_AVAILABLE",
] as const;

export type LiveProductCapability = (typeof LIVE_PRODUCT_CAPABILITIES)[number];

export type CapabilitySet = Readonly<Record<LiveProductCapability, boolean>>;

/** Nothing is enabled unless a caller explicitly turns it on. */
export const NO_CAPABILITIES: CapabilitySet = Object.freeze({
  MANAGED_COMBINED_INTAKE: false,
  SEPARATE_WALLET_STAGING: false,
  DIRECT_PARTICIPANT_ADMISSION: false,
  ONCHAIN_RECOURSE_CONNECTED: false,
  WALLETCONNECT_AVAILABLE: false,
});

export function capabilities(...enabled: readonly LiveProductCapability[]): CapabilitySet {
  const next: Record<LiveProductCapability, boolean> = { ...NO_CAPABILITIES };
  for (const capability of enabled) next[capability] = true;
  return Object.freeze(next);
}

/**
 * The only intake a visitor may reach. Exactly one of the three intake
 * capabilities is authoritative, and a build that somehow enables two resolves
 * to the least advanced one rather than the most flattering.
 */
export type IntakeMode = "MANAGED_COMBINED" | "SEPARATE_WALLET_STAGING" | "DIRECT_ADMISSION" | "NONE";

export function intakeMode(set: CapabilitySet): IntakeMode {
  if (set.MANAGED_COMBINED_INTAKE) return "MANAGED_COMBINED";
  if (set.SEPARATE_WALLET_STAGING) return "SEPARATE_WALLET_STAGING";
  if (set.DIRECT_PARTICIPANT_ADMISSION) return "DIRECT_ADMISSION";
  return "NONE";
}

/**
 * The exact sentence each intake is allowed to print. Nothing else may describe
 * how the inputs reach the evaluator.
 */
export const INTAKE_DISCLOSURE: Readonly<Record<IntakeMode, string>> = Object.freeze({
  MANAGED_COMBINED:
    "This supervised test submits both demo claims to Mordant's managed execution service. "
    + "The service prepares their encryption before the FHE evaluator processes them.",
  SEPARATE_WALLET_STAGING:
    "Each eligible wallet authorizes only its own claim. Mordant's managed execution service "
    + "prepares the encryption for both claims once each has been separately authorized.",
  DIRECT_ADMISSION:
    "Two distinct A-Pass-eligible wallets independently authorize role-bound participant "
    + "admissions into the same neutral case. Each admission invokes the participant FHE client separately.",
  NONE: "No execution service is configured on this deployment.",
});

// ---------------------------------------------------------------- product states

export type LiveProductState =
  | "INTRODUCTION"
  | "ELIGIBILITY_REQUIRED"
  | "ELIGIBILITY_CHECKING"
  | "ELIGIBILITY_ACCEPTED"
  | "ELIGIBILITY_REFUSED"
  | "CASE_READY"
  | "CLAIM_A_REQUIRED"
  | "CLAIM_A_AUTHORIZING"
  | "CLAIM_A_ADMITTED"
  | "CLAIM_B_REQUIRED"
  | "CLAIM_B_AUTHORIZING"
  | "CLAIM_B_ADMITTED"
  | "WAITING_FOR_OTHER_PARTICIPANT"
  | "PREPARING_ENCRYPTION"
  | "PARTICIPANT_A_ENCRYPTED"
  | "PARTICIPANT_B_ENCRYPTED"
  | "ENCRYPTED_EVALUATION"
  | "GOVERNED_VERIFICATION"
  | "RELEASE_AVAILABLE"
  | "CONFLICT_REVEALED"
  | "NO_CONFLICT_REVEALED"
  | "ONCHAIN_SUBMISSION"
  | "CURE_OPEN"
  | "CURED"
  | "ENTITLED"
  | "CLAIM_A_AVAILABLE"
  | "CLAIM_B_AVAILABLE"
  | "CLAIMED"
  | "RECOURSE_REFUSED"
  | "RECEIPT_SEALED"
  | "BUSY"
  | "SERVICE_UNAVAILABLE"
  | "RECOVERY_AVAILABLE"
  | "EXECUTION_FAILED";

/** States that must never render outcome wording. */
export const PRE_RELEASE_STATES: ReadonlySet<LiveProductState> = new Set<LiveProductState>([
  "INTRODUCTION",
  "ELIGIBILITY_REQUIRED",
  "ELIGIBILITY_CHECKING",
  "ELIGIBILITY_ACCEPTED",
  "ELIGIBILITY_REFUSED",
  "CASE_READY",
  "CLAIM_A_REQUIRED",
  "CLAIM_A_AUTHORIZING",
  "CLAIM_A_ADMITTED",
  "CLAIM_B_REQUIRED",
  "CLAIM_B_AUTHORIZING",
  "CLAIM_B_ADMITTED",
  "WAITING_FOR_OTHER_PARTICIPANT",
  "PREPARING_ENCRYPTION",
  "PARTICIPANT_A_ENCRYPTED",
  "PARTICIPANT_B_ENCRYPTED",
  "ENCRYPTED_EVALUATION",
  "GOVERNED_VERIFICATION",
]);

// ---------------------------------------------------------------- money

/** aUSDC carries six decimals. Raw atomic units are never shown as an amount. */
export const AUSDC_DECIMALS = 6;

export type TokenAmount = Readonly<{
  /** Exact atomic units, as a decimal string. Never formatted, never rounded. */
  atomic: string;
  /** Human amount, grouped, with the token symbol handled by the component. */
  formatted: string;
  decimals: number;
  symbol: "aUSDC";
}>;

export function ausdcFromAtomic(atomic: string): TokenAmount {
  if (!/^\d+$/u.test(atomic)) throw new Error("An atomic amount must be whole and non-negative");
  const units = BigInt(atomic);
  const scale = 10n ** BigInt(AUSDC_DECIMALS);
  const whole = units / scale;
  const fraction = (units % scale).toString().padStart(AUSDC_DECIMALS, "0").slice(0, 2);
  const grouped = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/gu, ",");
  return Object.freeze({ atomic, formatted: `${grouped}.${fraction}`, decimals: AUSDC_DECIMALS, symbol: "aUSDC" as const });
}

// ---------------------------------------------------------------- wallet and eligibility

export type ParticipantRole = "A" | "B";

export type WalletConnectionState =
  | "DISCONNECTED"
  | "CONNECTING"
  | "CONNECTED"
  | "WRONG_NETWORK"
  | "SWITCHING_NETWORK"
  | "REJECTED"
  | "UNAVAILABLE";

export type WalletView = Readonly<{
  state: WalletConnectionState;
  address: string | null;
  /** Wallet-supplied, untrusted, presentation only. */
  connectorName: string | null;
  connectorUid: string | null;
  chainId: number | null;
  expectedChainId: number;
  /** A message already written for a person, never a raw provider payload. */
  problem: string | null;
}>;

export type EligibilityState = "IDLE" | "CHECKING" | "VERIFIED" | "REFUSED" | "ERROR";

export type EligibilityView = Readonly<{
  state: EligibilityState;
  holderAddress: string | null;
  chainId: number | null;
  gateAddress: string | null;
  observedBlock: number | null;
  /** Set only when the check could not be completed. */
  problem: string | null;
}>;

// ---------------------------------------------------------------- claims

export type ClaimWindow = Readonly<{ activeFrom: number; activeUntil: number }>;

export type ClaimAdmission =
  | "NOT_REQUIRED"
  | "REQUIRED"
  | "AUTHORIZING"
  | "ADMITTED";

export type ParticipantClaimView = Readonly<{
  role: ParticipantRole;
  label: string;
  /** Present only while the visitor is still authoring it. */
  window: ClaimWindow | null;
  admission: ClaimAdmission;
  /** Wallet bound to this role, when the capability provides one. */
  wallet: string | null;
  eligibilityVerified: boolean;
  /** Digest of the admitted claim, once the backend has produced one. */
  artifactDigest: string | null;
  privacyNote: string;
}>;

// ---------------------------------------------------------------- execution

export type ExecutionStageId =
  | "CASE_AUTHORIZED"
  | "CLAIM_INPUTS_ADMITTED"
  | "ENCRYPTION_PREPARED"
  | "PARTICIPANT_A_ENCRYPTED"
  | "PARTICIPANT_B_ENCRYPTED"
  | "EVALUATION_RUNNING"
  | "GOVERNED_VERIFICATION"
  | "RECOURSE_APPLICATION"
  | "RECEIPT_SEALED";

export type StageProgress = "done" | "active" | "pending";

export type ExecutionStageView = Readonly<{
  id: ExecutionStageId;
  label: string;
  progress: StageProgress;
  /** One sentence, shown only for the active stage. */
  detail: string | null;
}>;

const STAGE_LABEL: Readonly<Record<ExecutionStageId, string>> = Object.freeze({
  CASE_AUTHORIZED: "Case authorized",
  CLAIM_INPUTS_ADMITTED: "Claim inputs admitted",
  ENCRYPTION_PREPARED: "Private encryption prepared",
  PARTICIPANT_A_ENCRYPTED: "Participant A encrypted",
  PARTICIPANT_B_ENCRYPTED: "Participant B encrypted",
  EVALUATION_RUNNING: "Encrypted evaluation running",
  GOVERNED_VERIFICATION: "Governed result verification",
  RECOURSE_APPLICATION: "Recourse application",
  RECEIPT_SEALED: "Receipt sealed",
});

const STAGE_DETAIL: Readonly<Partial<Record<ExecutionStageId, string>>> = Object.freeze({
  ENCRYPTION_PREPARED: "Mordant's managed execution service is preparing the encryption for this case.",
  EVALUATION_RUNNING: "The evaluator is running the fixed circuit. It receives ciphertexts and holds no decryption key.",
  GOVERNED_VERIFICATION: "The designated decryptor is recomputing the circuit and signing one Boolean.",
  RECOURSE_APPLICATION: "The signed result is being applied to the protection case.",
});

export const MANAGED_STAGE_ORDER: readonly ExecutionStageId[] = Object.freeze([
  "CASE_AUTHORIZED",
  "ENCRYPTION_PREPARED",
  "PARTICIPANT_A_ENCRYPTED",
  "PARTICIPANT_B_ENCRYPTED",
  "EVALUATION_RUNNING",
  "GOVERNED_VERIFICATION",
  "RECOURSE_APPLICATION",
  "RECEIPT_SEALED",
]);

/** Separate admission adds one real stage the managed intake does not have. */
export const ADMISSION_STAGE_ORDER: readonly ExecutionStageId[] = Object.freeze([
  "CASE_AUTHORIZED",
  "CLAIM_INPUTS_ADMITTED",
  "ENCRYPTION_PREPARED",
  "PARTICIPANT_A_ENCRYPTED",
  "PARTICIPANT_B_ENCRYPTED",
  "EVALUATION_RUNNING",
  "GOVERNED_VERIFICATION",
  "RECOURSE_APPLICATION",
  "RECEIPT_SEALED",
]);

export function stageOrderFor(mode: IntakeMode): readonly ExecutionStageId[] {
  return mode === "MANAGED_COMBINED" || mode === "NONE" ? MANAGED_STAGE_ORDER : ADMISSION_STAGE_ORDER;
}

export function buildStages(order: readonly ExecutionStageId[], reachedIndex: number): readonly ExecutionStageView[] {
  return order.map((id, index) => Object.freeze({
    id,
    label: STAGE_LABEL[id],
    progress: (index < reachedIndex ? "done" : index === reachedIndex ? "active" : "pending") as StageProgress,
    detail: index === reachedIndex ? STAGE_DETAIL[id] ?? null : null,
  }));
}

// ---------------------------------------------------------------- result and recourse

export type GovernedRelease = Readonly<{
  conflict: boolean;
  digest: string;
  releaseMode: string;
}>;

export type RecourseDecision = Readonly<{
  opened: boolean;
  /** Only ever the backend's own reason, never an invented one. */
  reason: string | null;
  responsible: string | null;
  /** Absolute instant carried by the signed recourse record. Never hard-coded. */
  cureDeadlineIso: string | null;
  consequence: string | null;
}>;

export type DecisionRail = Readonly<{
  nextDecision: string;
  responsibleNow: string | null;
  deadlineIso: string | null;
  deadlineNote: string | null;
  consequence: string;
  receiptAvailable: boolean;
}>;

// ---------------------------------------------------------------- on-chain

export type OnchainPhase =
  | "NOT_CONNECTED"
  | "BRIDGE_ATTESTATION_READY"
  | "SUBMITTING_RELEASE"
  | "TRANSACTION_PENDING"
  | "RELEASE_CONSUMED"
  | "CURE_OPEN"
  | "CURE_SUBMITTED"
  | "CURE_CONFIRMED"
  | "AWAITING_CURE_DEADLINE"
  | "FINALIZATION_AVAILABLE"
  | "FINALIZATION_PENDING"
  | "ENTITLEMENT_OPENED"
  | "CLAIM_PENDING"
  | "CLAIM_CONFIRMED";

export type OnchainEvidence = Readonly<{
  /** No address, ABI, amount or event is hard-coded here. All of it arrives typed. */
  transactionHash: string | null;
  blockNumber: number | null;
  contractAddress: string | null;
  explorerBase: string | null;
}>;

export type EntitlementView = Readonly<{
  holderA: TokenAmount | null;
  holderB: TokenAmount | null;
  claimedByA: boolean;
  claimedByB: boolean;
}>;

export type OnchainView = Readonly<{
  phase: OnchainPhase;
  evidence: OnchainEvidence;
  entitlement: EntitlementView | null;
  /** Set when the adapter is present but the capability is off. */
  disabledReason: string | null;
}>;

export const ONCHAIN_NOT_CONNECTED: OnchainView = Object.freeze({
  phase: "NOT_CONNECTED" as const,
  evidence: Object.freeze({ transactionHash: null, blockNumber: null, contractAddress: null, explorerBase: null }),
  entitlement: null,
  disabledReason: "On-chain recourse is not connected on this deployment.",
});

// ---------------------------------------------------------------- receipt

export type ReceiptRow = Readonly<{ label: string; value: string }>;

export type LayeredReceipt = Readonly<{
  /** Level one: what was decided, for a person. */
  summary: readonly ReceiptRow[];
  /** Level two: the identifiers a reviewer checks. */
  technical: readonly ReceiptRow[];
  /** Level three: the raw verified projection. */
  raw: Readonly<Record<string, unknown>> | null;
}>;

// ---------------------------------------------------------------- the view model

export type LiveProductViewModel = Readonly<{
  state: LiveProductState;
  capabilities: CapabilitySet;
  intake: IntakeMode;
  intakeDisclosure: string;

  runId: string | null;
  caseId: string | null;
  assetDigest: string | null;
  assetLabel: string;
  protectedAmount: TokenAmount | null;
  reserveAmount: TokenAmount | null;

  wallet: WalletView | null;
  eligibility: EligibilityView;

  claimA: ParticipantClaimView;
  claimB: ParticipantClaimView;
  activeRole: ParticipantRole | null;
  handoffRequired: boolean;

  stages: readonly ExecutionStageView[];
  elapsedSeconds: number | null;
  expectation: string | null;

  release: GovernedRelease | null;
  recourse: RecourseDecision | null;
  decisionRail: DecisionRail | null;

  onchain: OnchainView;
  receipt: LayeredReceipt | null;

  /** Present only for BUSY, SERVICE_UNAVAILABLE, RECOVERY_AVAILABLE, EXECUTION_FAILED. */
  notice: Readonly<{ title: string; body: string; retryable: boolean }> | null;
}>;

/** Outcome wording may exist only once a signed release does. */
export function assertNoPrematureOutcome(model: LiveProductViewModel): void {
  if (PRE_RELEASE_STATES.has(model.state) && model.release !== null) {
    throw new Error(`A pre-release state (${model.state}) must not carry a governed release`);
  }
  if (PRE_RELEASE_STATES.has(model.state) && model.decisionRail !== null) {
    throw new Error(`A pre-release state (${model.state}) must not carry a decision rail`);
  }
}
