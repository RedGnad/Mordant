/**
 * Front-end product model for Mordant's synthetic hackathon prototype.
 *
 * Nothing in this module represents real funds, custody, legal assignment,
 * insurance, or a production eligibility decision. Fixtures use synthetic test
 * assets and synthetic references only.
 */

import { syntheticInvoiceRootForScenario } from "./identity";

export const PRODUCT_MODEL_SCHEMA_VERSION = "mordant.product-model.v1" as const;

export const SYNTHETIC_MODEL_NOTICE =
  "Synthetic demo data only. No real funds, custody, legal assignment, insurance, or production-safety claim." as const;

export const FIXTURE_NOW = "2026-07-29T08:00:00.000Z" as const;

export const SYNTHETIC_ASSET = {
  id: "synthetic-ausdc",
  symbol: "aUSDC",
  label: "Synthetic aUSDC",
  decimals: 6,
  kind: "synthetic-test-asset",
} as const;

export type IsoTimestamp = string;
export type IntegerString = `${bigint}`;
export type SyntheticReference = `synthetic:${string}`;
export type SyntheticInvoiceRoot = `synroot:${string}`;

export type ParticipantRole =
  | "originator"
  | "buyer"
  | "facility_a"
  | "facility_b"
  | "holder"
  | "protocol_operator"
  | "observer";

export type ReceivableState =
  | "accepted"
  | "issued"
  | "outstanding"
  | "partially_redeemed"
  | "redeemed"
  | "cancelled";

export type ProtectionState =
  | "unfunded"
  | "funding_pending"
  | "active"
  | "conflict_registered"
  | "cure_period"
  | "claimable"
  | "settled"
  | "released"
  | "recovery";

export type MonetaryDomain = "receivable" | "protection";

export interface DomainAmount<D extends MonetaryDomain = MonetaryDomain> {
  readonly domain: D;
  readonly asset: typeof SYNTHETIC_ASSET;
  readonly minorUnits: IntegerString;
}

/**
 * Deterministic synthetic allocation used to derive the connected holder's
 * personal exposure. It is a unit ratio, not a claim about legal ownership.
 */
export interface ParticipantPosition {
  readonly invoiceUnits: IntegerString;
  readonly totalUnits: IntegerString;
}

export interface ReceivableLedger {
  readonly domain: "receivable";
  readonly faceValue: DomainAmount<"receivable">;
  readonly outstanding: DomainAmount<"receivable">;
  readonly redeemed: DomainAmount<"receivable">;
  readonly issuedUnits: IntegerString;
  readonly outstandingUnits: IntegerString;
}

export interface ProtectionLedger {
  readonly domain: "protection";
  readonly demoReserveParameterBps: 1000;
  readonly initialReserve: DomainAmount<"protection">;
  readonly requiredReserve: DomainAmount<"protection">;
  readonly lockedReserve: DomainAmount<"protection">;
  readonly protectionPaid: DomainAmount<"protection">;
}

export interface MachineTransition<S extends string> {
  readonly at: IsoTimestamp;
  readonly from: S;
  readonly action: string;
  readonly to: S;
  readonly proofId?: string;
}

export interface ReceivableMachine {
  readonly domain: "receivable";
  readonly state: ReceivableState;
  readonly immutableInvoiceRoot: SyntheticInvoiceRoot;
  readonly history: readonly MachineTransition<ReceivableState>[];
}

export interface ProtectionMachine {
  readonly domain: "protection";
  readonly state: ProtectionState;
  readonly immutablePolicyId: SyntheticReference;
  readonly history: readonly MachineTransition<ProtectionState>[];
}

export const GATE_KINDS = ["identity", "role", "time", "economic", "protocol"] as const;

export type GateKind = (typeof GATE_KINDS)[number];
export type GateStatus = "satisfied" | "blocked" | "pending" | "unknown" | "not_applicable";
export type GateVisibility = "shared" | "viewer_only" | "operations_only";

export interface GateCheck<K extends GateKind = GateKind> {
  readonly kind: K;
  readonly status: GateStatus;
  readonly code: string;
  readonly label: string;
  readonly detail: string;
  readonly remediation?: string;
  readonly responsibleRole?: ParticipantRole;
  readonly visibility: GateVisibility;
}

export type GateVector = readonly [
  identity: GateCheck<"identity">,
  role: GateCheck<"role">,
  time: GateCheck<"time">,
  economic: GateCheck<"economic">,
  protocol: GateCheck<"protocol">,
];

export type GateOverrides = {
  readonly [K in GateKind]?: Partial<Omit<GateCheck<K>, "kind">>;
};

export type FreshnessStatus = "fresh" | "aging" | "stale" | "unknown";
export type FinalityStatus = "unconfirmed" | "pending" | "safe" | "finalized" | "unknown";

export interface Freshness {
  readonly status: FreshnessStatus;
  readonly observedAt?: IsoTimestamp;
  readonly staleAfterSeconds: number;
}

export interface Finality {
  readonly status: FinalityStatus;
  readonly syntheticBlock?: IntegerString;
  readonly confirmations?: number;
}

export interface Observation {
  readonly source: "synthetic-fixture";
  readonly freshness: Freshness;
  readonly finality: Finality;
}

export type ResponsibilityStatus = "due_now" | "upcoming" | "waiting_external" | "recovery" | "none";

export interface Responsibility {
  readonly status: ResponsibilityStatus;
  readonly actorRole?: ParticipantRole;
  readonly actorLabel: string;
  readonly task: string;
  readonly dueAt?: IsoTimestamp;
  readonly consequenceIfMissed?: string;
  readonly visibility: GateVisibility;
}

export type ActionLifecycle = "proposed" | "submitted" | "completed" | "superseded";
export type RequiredFinality = "none" | "safe" | "finalized";

export type MonetaryEffect =
  | {
      readonly domain: "receivable";
      readonly direction: "into_vault" | "to_holder";
      readonly amount: DomainAmount<"receivable">;
      readonly label: string;
    }
  | {
      readonly domain: "protection";
      readonly direction: "into_reserve" | "to_protected_party" | "released";
      readonly amount: DomainAmount<"protection">;
      readonly label: string;
    };

export interface MachineEffect<S extends ReceivableState | ProtectionState> {
  readonly from: S;
  readonly to: S;
}

export interface ActionConsequence {
  readonly summary: string;
  readonly receivableTransition?: MachineEffect<ReceivableState>;
  readonly protectionTransition?: MachineEffect<ProtectionState>;
  readonly monetaryEffects: readonly MonetaryEffect[];
  readonly receivableUnitsEffect: "none" | "burn_redeemed_units";
  readonly irreversible: boolean;
}

export interface DealAction {
  readonly id: string;
  readonly machine: MonetaryDomain | "system";
  readonly label: string;
  readonly contractAction: string;
  readonly actorRole: ParticipantRole;
  readonly lifecycle: ActionLifecycle;
  readonly requiredFinality: RequiredFinality;
  readonly gates: GateVector;
  readonly consequence: ActionConsequence;
  readonly proofId?: string;
}

export type EvidenceClassification =
  | "observed_onchain"
  | "attested"
  | "derived_by_mordant"
  | "external_unverified";

export interface ProofEvidenceItem {
  readonly classification: EvidenceClassification;
  readonly label: string;
  readonly value: string;
  readonly source: string;
}

export interface ProofDiagnostic {
  readonly severity: "info" | "warning" | "error";
  readonly code: string;
  readonly message: string;
  readonly recovery?: string;
}

export interface MachineSnapshot<S extends ReceivableState | ProtectionState> {
  readonly state: S;
  readonly observedAt: IsoTimestamp;
}

export interface ProofAction {
  readonly name: string;
  readonly actorRole: ParticipantRole;
  readonly reference: SyntheticReference;
  readonly submittedAt: IsoTimestamp;
}

interface TransitionProofBase {
  readonly id: string;
  readonly finality: Finality;
  readonly evidence: readonly ProofEvidenceItem[];
  readonly diagnostics: readonly ProofDiagnostic[];
}

export interface ReceivableTransitionProof extends TransitionProofBase {
  readonly machine: "receivable";
  readonly before: MachineSnapshot<ReceivableState>;
  readonly action: ProofAction;
  readonly after: MachineSnapshot<ReceivableState>;
}

export interface ProtectionTransitionProof extends TransitionProofBase {
  readonly machine: "protection";
  readonly before: MachineSnapshot<ProtectionState>;
  readonly action: ProofAction;
  readonly after: MachineSnapshot<ProtectionState>;
}

export type TransitionProof = ReceivableTransitionProof | ProtectionTransitionProof;

export interface DealDiagnostic {
  readonly severity: "info" | "warning" | "error";
  readonly category: "observation" | "gate" | "protocol" | "data" | "recovery";
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly visibility: GateVisibility;
  readonly ownerRole?: ParticipantRole;
  readonly recoveryActionId?: string;
}

export type DealScenarioId =
  | "healthy"
  | "cure-expiring"
  | "pending-finality"
  | "funds-missing"
  | "allowance-missing"
  | "wrong-role"
  | "credential-required"
  | "prerequisite-missing"
  | "completed"
  | "recovery-required"
  | "stale-observation"
  | "unknown-observation"
  | "partial-redemption"
  | "protection-settled";

export interface SyntheticDeal {
  readonly schemaVersion: typeof PRODUCT_MODEL_SCHEMA_VERSION;
  readonly environment: "synthetic-demo";
  readonly notice: typeof SYNTHETIC_MODEL_NOTICE;
  readonly scenario: DealScenarioId;
  readonly id: SyntheticReference;
  readonly label: string;
  readonly viewer: {
    readonly participantId: SyntheticReference;
    readonly role: ParticipantRole;
    readonly label: string;
    readonly position?: ParticipantPosition;
  };
  readonly machines: {
    readonly receivable: ReceivableMachine;
    readonly protection: ProtectionMachine;
  };
  readonly economics: {
    readonly receivable: ReceivableLedger;
    readonly protection: ProtectionLedger;
  };
  readonly observation: Observation;
  readonly nextResponsibility: Responsibility;
  readonly actions: readonly DealAction[];
  readonly proofs: readonly TransitionProof[];
  readonly diagnostics: readonly DealDiagnostic[];
}

export type ActionAvailability = "available" | "blocked" | "pending" | "completed" | "superseded" | "unknown";

export interface ActionAssessment {
  readonly actionId: string;
  readonly availability: ActionAvailability;
  /** The complete, ordered gate vector is intentionally retained. */
  readonly gates: GateVector;
  readonly blockingGates: readonly GateCheck[];
  readonly pendingGates: readonly GateCheck[];
  readonly unknownGates: readonly GateCheck[];
  readonly observation: Observation;
  readonly observationReason?: "refresh_required" | "finality_required" | "observation_unknown";
}

export type DealPosture = "stable" | "attention" | "critical" | "complete" | "recovery" | "unknown";

export interface DealSummary {
  readonly dealId: SyntheticReference;
  readonly posture: DealPosture;
  readonly receivableState: ReceivableState;
  readonly protectionState: ProtectionState;
  readonly nextResponsibility: Responsibility;
  readonly primaryAction?: ActionAssessment;
  readonly observation: Observation;
}

const DEFAULT_GATE_COPY: Readonly<Record<GateKind, { label: string; detail: string }>> = {
  identity: { label: "Identity", detail: "The viewer-specific synthetic identity check is satisfied." },
  role: { label: "Role", detail: "The connected synthetic participant has the required role." },
  time: { label: "Time", detail: "The action is inside its synthetic execution window." },
  economic: { label: "Economic", detail: "The synthetic balance and allowance checks are satisfied." },
  protocol: { label: "Protocol", detail: "The synthetic protocol prerequisites are satisfied." },
};

function makeGate<K extends GateKind>(kind: K, override?: GateOverrides[K]): GateCheck<K> {
  const defaults = DEFAULT_GATE_COPY[kind];
  return {
    kind,
    status: override?.status ?? "satisfied",
    code: override?.code ?? `${kind}_satisfied`,
    label: override?.label ?? defaults.label,
    detail: override?.detail ?? defaults.detail,
    ...(override?.remediation === undefined ? {} : { remediation: override.remediation }),
    ...(override?.responsibleRole === undefined ? {} : { responsibleRole: override.responsibleRole }),
    visibility: override?.visibility ?? "shared",
  };
}

export function makeGateVector(overrides: GateOverrides = {}): GateVector {
  return [
    makeGate("identity", overrides.identity),
    makeGate("role", overrides.role),
    makeGate("time", overrides.time),
    makeGate("economic", overrides.economic),
    makeGate("protocol", overrides.protocol),
  ];
}

export function amount<D extends MonetaryDomain>(domain: D, minorUnits: IntegerString): DomainAmount<D> {
  if (!/^(0|[1-9]\d*)$/.test(minorUnits)) {
    throw new RangeError("minorUnits must be a non-negative base-10 integer string");
  }

  return { domain, asset: SYNTHETIC_ASSET, minorUnits };
}

/**
 * Returns a participant's exact share of a domain amount without converting
 * through Number. A non-integral minor-unit result is rejected rather than
 * rounded, so the UI cannot silently overstate or understate an exposure.
 */
export function proRateAmount<D extends MonetaryDomain>(
  source: DomainAmount<D>,
  position: ParticipantPosition,
): DomainAmount<D> {
  const invoiceUnits = BigInt(position.invoiceUnits);
  const totalUnits = BigInt(position.totalUnits);

  if (invoiceUnits < 0n || totalUnits <= 0n || invoiceUnits > totalUnits) {
    throw new RangeError("position must satisfy 0 <= invoiceUnits <= totalUnits and totalUnits > 0");
  }

  const weightedMinorUnits = BigInt(source.minorUnits) * invoiceUnits;
  if (weightedMinorUnits % totalUnits !== 0n) {
    throw new RangeError("participant exposure is not exactly representable in asset minor units");
  }

  return amount(source.domain, (weightedMinorUnits / totalUnits).toString() as IntegerString);
}

function finalityRank(status: FinalityStatus): number {
  switch (status) {
    case "unconfirmed":
      return 0;
    case "pending":
      return 1;
    case "safe":
      return 2;
    case "finalized":
      return 3;
    case "unknown":
      return -1;
  }
}

function requiredFinalityRank(required: RequiredFinality): number {
  switch (required) {
    case "none":
      return 0;
    case "safe":
      return 2;
    case "finalized":
      return 3;
  }
}

export function assessAction(action: DealAction, observation: Observation): ActionAssessment {
  const blockingGates = action.gates.filter((gate) => gate.status === "blocked");
  const pendingGates = action.gates.filter((gate) => gate.status === "pending");
  const unknownGates = action.gates.filter((gate) => gate.status === "unknown");
  let availability: ActionAvailability;
  let observationReason: ActionAssessment["observationReason"];

  if (action.lifecycle === "completed") {
    availability = "completed";
  } else if (action.lifecycle === "superseded") {
    availability = "superseded";
  } else if (observation.freshness.status === "unknown" || observation.finality.status === "unknown") {
    availability = "unknown";
    observationReason = "observation_unknown";
  } else if (observation.freshness.status === "stale") {
    availability = "unknown";
    observationReason = "refresh_required";
  } else if (unknownGates.length > 0) {
    availability = "unknown";
  } else if (blockingGates.length > 0) {
    availability = "blocked";
  } else if (pendingGates.length > 0) {
    availability = "pending";
  } else if (finalityRank(observation.finality.status) < requiredFinalityRank(action.requiredFinality)) {
    availability = "pending";
    observationReason = "finality_required";
  } else {
    availability = "available";
  }

  return {
    actionId: action.id,
    availability,
    gates: action.gates,
    blockingGates,
    pendingGates,
    unknownGates,
    observation,
    ...(observationReason === undefined ? {} : { observationReason }),
  };
}

export function deriveDealSummary(deal: SyntheticDeal): DealSummary {
  const primary = deal.actions[0];
  const primaryAction = primary === undefined ? undefined : assessAction(primary, deal.observation);
  let posture: DealPosture;

  if (deal.observation.freshness.status === "stale" || deal.observation.freshness.status === "unknown") {
    posture = "unknown";
  } else if (deal.diagnostics.some((diagnostic) => diagnostic.category === "recovery" && diagnostic.severity === "error")) {
    posture = "recovery";
  } else if (deal.machines.receivable.state === "redeemed" && ["released", "settled"].includes(deal.machines.protection.state)) {
    posture = "complete";
  } else if (deal.machines.protection.state === "claimable") {
    posture = "critical";
  } else if (
    ["conflict_registered", "cure_period"].includes(deal.machines.protection.state) ||
    deal.nextResponsibility.status === "due_now"
  ) {
    posture = "attention";
  } else {
    posture = "stable";
  }

  return {
    dealId: deal.id,
    posture,
    receivableState: deal.machines.receivable.state,
    protectionState: deal.machines.protection.state,
    nextResponsibility: deal.nextResponsibility,
    ...(primaryAction === undefined ? {} : { primaryAction }),
    observation: deal.observation,
  };
}

const RECEIVABLE_FACE = amount("receivable", "2480000000000");
const RECEIVABLE_ZERO = amount("receivable", "0");
const PROTECTION_RESERVE = amount("protection", "248000000000");
const PROTECTION_ZERO = amount("protection", "0");

const BASE_OBSERVATION: Observation = {
  source: "synthetic-fixture",
  freshness: { status: "fresh", observedAt: FIXTURE_NOW, staleAfterSeconds: 120 },
  finality: { status: "finalized", syntheticBlock: "1402", confirmations: 32 },
};

const BASE_RECEIVABLE: ReceivableMachine = {
  domain: "receivable",
  state: "outstanding",
  immutableInvoiceRoot: "synroot:mordant-demo-invoice-001",
  history: [
    {
      at: "2026-07-21T09:00:00.000Z",
      from: "accepted",
      action: "issueSyntheticUnits()",
      to: "issued",
    },
    {
      at: "2026-07-21T09:01:00.000Z",
      from: "issued",
      action: "activateSyntheticReceivable()",
      to: "outstanding",
    },
  ],
};

const BASE_PROTECTION: ProtectionMachine = {
  domain: "protection",
  state: "active",
  immutablePolicyId: "synthetic:policy:demo-001",
  history: [
    {
      at: "2026-07-21T09:02:00.000Z",
      from: "unfunded",
      action: "fundSyntheticProtection()",
      to: "active",
    },
  ],
};

const BASE_RECEIVABLE_LEDGER: ReceivableLedger = {
  domain: "receivable",
  faceValue: RECEIVABLE_FACE,
  outstanding: RECEIVABLE_FACE,
  redeemed: RECEIVABLE_ZERO,
  issuedUnits: "100",
  outstandingUnits: "100",
};

const BASE_PROTECTION_LEDGER: ProtectionLedger = {
  domain: "protection",
  demoReserveParameterBps: 1000,
  initialReserve: PROTECTION_RESERVE,
  requiredReserve: PROTECTION_RESERVE,
  lockedReserve: PROTECTION_RESERVE,
  protectionPaid: PROTECTION_ZERO,
};

const NO_RESPONSIBILITY: Responsibility = {
  status: "none",
  actorLabel: "No participant",
  task: "No intervention is due in this synthetic scenario.",
  visibility: "shared",
};

interface FixtureOverrides {
  readonly label: string;
  readonly viewer?: SyntheticDeal["viewer"];
  readonly receivable?: ReceivableMachine;
  readonly protection?: ProtectionMachine;
  readonly receivableLedger?: ReceivableLedger;
  readonly protectionLedger?: ProtectionLedger;
  readonly observation?: Observation;
  readonly nextResponsibility?: Responsibility;
  readonly actions?: readonly DealAction[];
  readonly proofs?: readonly TransitionProof[];
  readonly diagnostics?: readonly DealDiagnostic[];
}

function fixture(scenario: DealScenarioId, overrides: FixtureOverrides): SyntheticDeal {
  const receivable = overrides.receivable ?? BASE_RECEIVABLE;

  return {
    schemaVersion: PRODUCT_MODEL_SCHEMA_VERSION,
    environment: "synthetic-demo",
    notice: SYNTHETIC_MODEL_NOTICE,
    scenario,
    id: `synthetic:deal:${scenario}`,
    label: overrides.label,
    viewer:
      overrides.viewer ??
      ({
        participantId: "synthetic:participant:holder-a",
        role: "holder",
        label: "Holder A (synthetic)",
        position: { invoiceUnits: "60", totalUnits: "100" },
      } as const),
    machines: {
      receivable: {
        ...receivable,
        immutableInvoiceRoot: syntheticInvoiceRootForScenario(scenario),
      },
      protection: overrides.protection ?? BASE_PROTECTION,
    },
    economics: {
      receivable: overrides.receivableLedger ?? BASE_RECEIVABLE_LEDGER,
      protection: overrides.protectionLedger ?? BASE_PROTECTION_LEDGER,
    },
    observation: overrides.observation ?? BASE_OBSERVATION,
    nextResponsibility: overrides.nextResponsibility ?? NO_RESPONSIBILITY,
    actions: overrides.actions ?? [],
    proofs: overrides.proofs ?? [],
    diagnostics: overrides.diagnostics ?? [],
  };
}

const REDEEM_AT_MATURITY: DealAction = {
  id: "redeem-at-maturity",
  machine: "receivable",
  label: "Redeem receivable at maturity",
  contractAction: "redeemSyntheticReceivable()",
  actorRole: "holder",
  lifecycle: "proposed",
  requiredFinality: "finalized",
  gates: makeGateVector({
    time: {
      status: "blocked",
      code: "maturity_not_reached",
      detail: "Synthetic maturity is 31 July 2026 at 14:00 UTC.",
      remediation: "Wait until the displayed maturity time.",
      responsibleRole: "buyer",
    },
  }),
  consequence: {
    summary: "Pays synthetic receivable redemption money and burns only the redeemed invoice units.",
    receivableTransition: { from: "outstanding", to: "redeemed" },
    monetaryEffects: [
      {
        domain: "receivable",
        direction: "to_holder",
        amount: RECEIVABLE_FACE,
        label: "Synthetic receivable redemption",
      },
    ],
    receivableUnitsEffect: "burn_redeemed_units",
    irreversible: true,
  },
};

const CURE_CONFLICT: DealAction = {
  id: "cure-conflict",
  machine: "protection",
  label: "Cure registered conflict",
  contractAction: "cureSyntheticConflict()",
  actorRole: "originator",
  lifecycle: "proposed",
  requiredFinality: "safe",
  gates: makeGateVector(),
  consequence: {
    summary: "Resolves the synthetic protection conflict without burning or transferring receivable units.",
    protectionTransition: { from: "cure_period", to: "active" },
    monetaryEffects: [],
    receivableUnitsEffect: "none",
    irreversible: false,
  },
};

const PROTECTION_SETTLEMENT_PROOF: ProtectionTransitionProof = {
  id: "proof-protection-settlement",
  machine: "protection",
  before: { state: "claimable", observedAt: "2026-07-29T07:40:00.000Z" },
  action: {
    name: "settleSyntheticProtection()",
    actorRole: "facility_a",
    reference: "synthetic:tx:protection-settlement",
    submittedAt: "2026-07-29T07:41:00.000Z",
  },
  after: { state: "settled", observedAt: "2026-07-29T07:42:00.000Z" },
  finality: { status: "finalized", syntheticBlock: "1396", confirmations: 38 },
  evidence: [
    {
      classification: "observed_onchain",
      label: "Synthetic contract event",
      value: "ProtectionSettled",
      source: "Synthetic fixture event stream",
    },
    {
      classification: "derived_by_mordant",
      label: "Receivable-unit effect",
      value: "None",
      source: "Mordant action model",
    },
  ],
  diagnostics: [],
};

export const SYNTHETIC_DEALS = [
  fixture("healthy", {
    label: "Healthy outstanding receivable",
    nextResponsibility: {
      status: "upcoming",
      actorRole: "buyer",
      actorLabel: "Buyer (synthetic)",
      task: "Provide receivable redemption money at synthetic maturity.",
      dueAt: "2026-07-31T14:00:00.000Z",
      consequenceIfMissed: "The receivable remains outstanding and the protocol can expose the next configured step.",
      visibility: "shared",
    },
    actions: [REDEEM_AT_MATURITY],
  }),
  fixture("cure-expiring", {
    label: "Cure period expiring",
    protection: {
      ...BASE_PROTECTION,
      state: "cure_period",
      history: [
        ...BASE_PROTECTION.history,
        {
          at: "2026-07-29T07:00:00.000Z",
          from: "active",
          action: "registerSyntheticConflict()",
          to: "conflict_registered",
        },
        {
          at: "2026-07-29T07:01:00.000Z",
          from: "conflict_registered",
          action: "openSyntheticCurePeriod()",
          to: "cure_period",
        },
      ],
    },
    viewer: {
      participantId: "synthetic:participant:originator",
      role: "originator",
      label: "Originator (synthetic)",
    },
    nextResponsibility: {
      status: "due_now",
      actorRole: "originator",
      actorLabel: "Originator or Facility B",
      task: "Cure the registered synthetic conflict.",
      dueAt: "2026-07-29T10:00:00.000Z",
      consequenceIfMissed: "The protection state can become claimable; receivable units remain untouched.",
      visibility: "shared",
    },
    actions: [CURE_CONFLICT],
    diagnostics: [
      {
        severity: "warning",
        category: "protocol",
        code: "cure_window_expiring",
        title: "Cure window closes soon",
        detail: "The synthetic cure window closes at 10:00 UTC.",
        visibility: "shared",
        ownerRole: "originator",
      },
    ],
  }),
  fixture("pending-finality", {
    label: "Conflict reveal pending finality",
    protection: { ...BASE_PROTECTION, state: "conflict_registered" },
    observation: {
      source: "synthetic-fixture",
      freshness: { status: "fresh", observedAt: FIXTURE_NOW, staleAfterSeconds: 120 },
      finality: { status: "pending", syntheticBlock: "1402", confirmations: 1 },
    },
    nextResponsibility: {
      status: "waiting_external",
      actorLabel: "Synthetic network",
      task: "Wait for the submitted conflict reveal to reach finalized observation.",
      visibility: "shared",
    },
    actions: [
      {
        ...CURE_CONFLICT,
        id: "reveal-conflict-pending",
        label: "Reveal conflict",
        contractAction: "revealSyntheticConflict()",
        actorRole: "facility_b",
        lifecycle: "submitted",
        requiredFinality: "finalized",
        consequence: {
          summary: "Registers the synthetic conflict after finality without changing receivable ownership or units.",
          protectionTransition: { from: "active", to: "conflict_registered" },
          monetaryEffects: [],
          receivableUnitsEffect: "none",
          irreversible: true,
        },
        proofId: "proof-pending-reveal",
      },
    ],
    proofs: [
      {
        id: "proof-pending-reveal",
        machine: "protection",
        before: { state: "active", observedAt: "2026-07-29T07:58:00.000Z" },
        action: {
          name: "revealSyntheticConflict()",
          actorRole: "facility_b",
          reference: "synthetic:tx:pending-reveal",
          submittedAt: "2026-07-29T07:59:00.000Z",
        },
        after: { state: "conflict_registered", observedAt: FIXTURE_NOW },
        finality: { status: "pending", syntheticBlock: "1402", confirmations: 1 },
        evidence: [
          {
            classification: "observed_onchain",
            label: "Synthetic event",
            value: "ConflictRegistered",
            source: "Synthetic fixture event stream",
          },
        ],
        diagnostics: [
          {
            severity: "info",
            code: "finality_pending",
            message: "The synthetic event is observed but not finalized.",
          },
        ],
      },
    ],
  }),
  fixture("funds-missing", {
    label: "Protection funding blocked by synthetic balance",
    protection: { ...BASE_PROTECTION, state: "unfunded", history: [] },
    protectionLedger: { ...BASE_PROTECTION_LEDGER, lockedReserve: PROTECTION_ZERO },
    viewer: {
      participantId: "synthetic:participant:originator",
      role: "originator",
      label: "Originator (synthetic)",
    },
    nextResponsibility: {
      status: "due_now",
      actorRole: "originator",
      actorLabel: "Originator (synthetic)",
      task: "Provide enough synthetic test balance to fund protection.",
      visibility: "viewer_only",
    },
    actions: [
      {
        id: "fund-protection-funds-missing",
        machine: "protection",
        label: "Fund synthetic protection",
        contractAction: "fundSyntheticProtection()",
        actorRole: "originator",
        lifecycle: "proposed",
        requiredFinality: "safe",
        gates: makeGateVector({
          economic: {
            status: "blocked",
            code: "synthetic_balance_insufficient",
            detail: "Your synthetic test balance is below the 248,000.00 aUSDC demo reserve.",
            remediation: "Add synthetic test assets to this demo participant.",
            responsibleRole: "originator",
            visibility: "viewer_only",
          },
        }),
        consequence: {
          summary: "Locks only synthetic protection reserve money; receivable units are unchanged.",
          protectionTransition: { from: "unfunded", to: "active" },
          monetaryEffects: [
            {
              domain: "protection",
              direction: "into_reserve",
              amount: PROTECTION_RESERVE,
              label: "Synthetic protection reserve",
            },
          ],
          receivableUnitsEffect: "none",
          irreversible: false,
        },
      },
    ],
  }),
  fixture("allowance-missing", {
    label: "Protection funding blocked by synthetic allowance",
    protection: { ...BASE_PROTECTION, state: "unfunded", history: [] },
    protectionLedger: { ...BASE_PROTECTION_LEDGER, lockedReserve: PROTECTION_ZERO },
    viewer: {
      participantId: "synthetic:participant:originator",
      role: "originator",
      label: "Originator (synthetic)",
    },
    nextResponsibility: {
      status: "due_now",
      actorRole: "originator",
      actorLabel: "Originator (synthetic)",
      task: "Set the synthetic protection allowance.",
      visibility: "viewer_only",
    },
    actions: [
      {
        id: "fund-protection-allowance-missing",
        machine: "protection",
        label: "Fund synthetic protection",
        contractAction: "fundSyntheticProtection()",
        actorRole: "originator",
        lifecycle: "proposed",
        requiredFinality: "safe",
        gates: makeGateVector({
          economic: {
            status: "blocked",
            code: "synthetic_allowance_insufficient",
            detail: "Your synthetic protection allowance is 0.00 aUSDC.",
            remediation: "Set a 248,000.00 aUSDC synthetic test allowance.",
            responsibleRole: "originator",
            visibility: "viewer_only",
          },
        }),
        consequence: {
          summary: "Locks only synthetic protection reserve money; receivable units are unchanged.",
          protectionTransition: { from: "unfunded", to: "active" },
          monetaryEffects: [
            {
              domain: "protection",
              direction: "into_reserve",
              amount: PROTECTION_RESERVE,
              label: "Synthetic protection reserve",
            },
          ],
          receivableUnitsEffect: "none",
          irreversible: false,
        },
      },
    ],
  }),
  fixture("wrong-role", {
    label: "Action reserved to another participant role",
    protection: { ...BASE_PROTECTION, state: "cure_period" },
    nextResponsibility: {
      status: "due_now",
      actorRole: "facility_b",
      actorLabel: "Facility B (synthetic)",
      task: "Reveal or cure the registered synthetic conflict.",
      dueAt: "2026-07-29T12:00:00.000Z",
      visibility: "shared",
    },
    actions: [
      {
        ...CURE_CONFLICT,
        id: "cure-conflict-wrong-role",
        actorRole: "facility_b",
        gates: makeGateVector({
          role: {
            status: "blocked",
            code: "role_reserved_for_facility_b",
            detail: "This action is reserved to Facility B. You are connected as Holder.",
            remediation: "Wait for Facility B; no action is available to your role.",
            responsibleRole: "facility_b",
          },
        }),
      },
    ],
  }),
  fixture("credential-required", {
    label: "Viewer-specific synthetic credential required",
    protection: { ...BASE_PROTECTION, state: "unfunded", history: [] },
    protectionLedger: { ...BASE_PROTECTION_LEDGER, lockedReserve: PROTECTION_ZERO },
    viewer: {
      participantId: "synthetic:participant:originator",
      role: "originator",
      label: "Originator (synthetic)",
    },
    nextResponsibility: {
      status: "due_now",
      actorRole: "originator",
      actorLabel: "You",
      task: "Resolve your viewer-specific synthetic eligibility check.",
      visibility: "viewer_only",
    },
    actions: [
      {
        id: "fund-protection-credential-required",
        machine: "protection",
        label: "Fund synthetic protection",
        contractAction: "fundSyntheticProtection()",
        actorRole: "originator",
        lifecycle: "proposed",
        requiredFinality: "safe",
        gates: makeGateVector({
          identity: {
            status: "blocked",
            code: "viewer_synthetic_credential_missing",
            detail: "Your viewer-specific synthetic eligibility credential is not present.",
            remediation: "Complete the synthetic demo eligibility step for your participant.",
            responsibleRole: "originator",
            visibility: "viewer_only",
          },
        }),
        consequence: {
          summary: "Locks synthetic protection reserve money; no receivable units are burned or transferred.",
          protectionTransition: { from: "unfunded", to: "active" },
          monetaryEffects: [
            {
              domain: "protection",
              direction: "into_reserve",
              amount: PROTECTION_RESERVE,
              label: "Synthetic protection reserve",
            },
          ],
          receivableUnitsEffect: "none",
          irreversible: false,
        },
      },
    ],
  }),
  fixture("prerequisite-missing", {
    label: "Protocol prerequisite missing",
    viewer: {
      participantId: "synthetic:participant:facility-b",
      role: "facility_b",
      label: "Facility B (synthetic)",
    },
    nextResponsibility: {
      status: "due_now",
      actorRole: "facility_b",
      actorLabel: "Facility B (synthetic)",
      task: "Submit the synthetic conflict commitment before reveal.",
      visibility: "shared",
    },
    actions: [
      {
        id: "reveal-conflict-prerequisite-missing",
        machine: "protection",
        label: "Reveal conflict",
        contractAction: "revealSyntheticConflict()",
        actorRole: "facility_b",
        lifecycle: "proposed",
        requiredFinality: "safe",
        gates: makeGateVector({
          protocol: {
            status: "blocked",
            code: "commitment_not_observed",
            detail: "No finalized synthetic commitment is linked to this reveal.",
            remediation: "Submit and finalize the synthetic commitment first.",
            responsibleRole: "facility_b",
          },
        }),
        consequence: {
          summary: "Registers a synthetic protection conflict without altering the receivable state or units.",
          protectionTransition: { from: "active", to: "conflict_registered" },
          monetaryEffects: [],
          receivableUnitsEffect: "none",
          irreversible: true,
        },
      },
    ],
  }),
  fixture("completed", {
    label: "Receivable and protection lifecycle completed",
    receivable: {
      ...BASE_RECEIVABLE,
      state: "redeemed",
      history: [
        ...BASE_RECEIVABLE.history,
        {
          at: "2026-07-28T14:00:00.000Z",
          from: "outstanding",
          action: "redeemSyntheticReceivable()",
          to: "redeemed",
          proofId: "proof-completed-redemption",
        },
      ],
    },
    protection: { ...BASE_PROTECTION, state: "released" },
    receivableLedger: {
      ...BASE_RECEIVABLE_LEDGER,
      outstanding: RECEIVABLE_ZERO,
      redeemed: RECEIVABLE_FACE,
      outstandingUnits: "0",
    },
    protectionLedger: {
      ...BASE_PROTECTION_LEDGER,
      requiredReserve: PROTECTION_ZERO,
      lockedReserve: PROTECTION_ZERO,
    },
    actions: [
      {
        ...REDEEM_AT_MATURITY,
        id: "redeem-completed",
        lifecycle: "completed",
        gates: makeGateVector(),
        proofId: "proof-completed-redemption",
      },
    ],
    proofs: [
      {
        id: "proof-completed-redemption",
        machine: "receivable",
        before: { state: "outstanding", observedAt: "2026-07-28T13:59:00.000Z" },
        action: {
          name: "redeemSyntheticReceivable()",
          actorRole: "holder",
          reference: "synthetic:tx:completed-redemption",
          submittedAt: "2026-07-28T14:00:00.000Z",
        },
        after: { state: "redeemed", observedAt: "2026-07-28T14:01:00.000Z" },
        finality: { status: "finalized", syntheticBlock: "1320", confirmations: 114 },
        evidence: [
          {
            classification: "observed_onchain",
            label: "Synthetic event",
            value: "ReceivableRedeemed",
            source: "Synthetic fixture event stream",
          },
        ],
        diagnostics: [],
      },
    ],
  }),
  fixture("recovery-required", {
    label: "Protection transition requires recovery",
    protection: { ...BASE_PROTECTION, state: "recovery" },
    viewer: {
      participantId: "synthetic:participant:operator",
      role: "protocol_operator",
      label: "Protocol operator (synthetic)",
    },
    nextResponsibility: {
      status: "recovery",
      actorRole: "protocol_operator",
      actorLabel: "Protocol Operations",
      task: "Inspect the failed synthetic transition and resume from its last finalized state.",
      visibility: "operations_only",
    },
    actions: [
      {
        id: "resume-protection-transition",
        machine: "system",
        label: "Resume protection transition",
        contractAction: "resumeSyntheticTransition()",
        actorRole: "protocol_operator",
        lifecycle: "proposed",
        requiredFinality: "finalized",
        gates: makeGateVector({
          protocol: {
            status: "blocked",
            code: "synthetic_transition_incomplete",
            detail: "The last synthetic protection transition has no valid after-state observation.",
            remediation: "Inspect diagnostics, reconcile the synthetic state, then retry explicitly.",
            responsibleRole: "protocol_operator",
            visibility: "operations_only",
          },
        }),
        consequence: {
          summary: "Attempts recovery of the protection state only; receivable ownership and units remain unchanged.",
          monetaryEffects: [],
          receivableUnitsEffect: "none",
          irreversible: false,
        },
      },
    ],
    diagnostics: [
      {
        severity: "error",
        category: "recovery",
        code: "after_state_unavailable",
        title: "After-state unavailable",
        detail: "The synthetic event was submitted but its expected after-state could not be reconstructed.",
        visibility: "operations_only",
        ownerRole: "protocol_operator",
        recoveryActionId: "resume-protection-transition",
      },
    ],
  }),
  fixture("stale-observation", {
    label: "Observation is stale",
    observation: {
      source: "synthetic-fixture",
      freshness: { status: "stale", observedAt: "2026-07-29T07:50:00.000Z", staleAfterSeconds: 120 },
      finality: { status: "finalized", syntheticBlock: "1388", confirmations: 46 },
    },
    nextResponsibility: {
      status: "waiting_external",
      actorLabel: "Observation service",
      task: "Refresh synthetic state before presenting any action as executable.",
      visibility: "shared",
    },
    actions: [{ ...CURE_CONFLICT, id: "cure-after-refresh" }],
    diagnostics: [
      {
        severity: "warning",
        category: "observation",
        code: "observation_stale",
        title: "State refresh required",
        detail: "The last synthetic observation is older than its 120-second freshness window.",
        visibility: "shared",
      },
    ],
  }),
  fixture("unknown-observation", {
    label: "Observation state is unknown",
    observation: {
      source: "synthetic-fixture",
      freshness: { status: "unknown", staleAfterSeconds: 120 },
      finality: { status: "unknown" },
    },
    nextResponsibility: {
      status: "waiting_external",
      actorLabel: "Observation service",
      task: "Restore a trustworthy synthetic observation before evaluating actions.",
      visibility: "shared",
    },
    actions: [{ ...CURE_CONFLICT, id: "cure-after-observation-restored" }],
    diagnostics: [
      {
        severity: "error",
        category: "observation",
        code: "observation_unknown",
        title: "Current state unknown",
        detail: "No current synthetic block or freshness timestamp is available.",
        visibility: "shared",
      },
    ],
  }),
  fixture("partial-redemption", {
    label: "Partially redeemed receivable with amortized reserve",
    receivable: { ...BASE_RECEIVABLE, state: "partially_redeemed" },
    receivableLedger: {
      ...BASE_RECEIVABLE_LEDGER,
      outstanding: amount("receivable", "1240000000000"),
      redeemed: amount("receivable", "1240000000000"),
      outstandingUnits: "50",
    },
    protectionLedger: {
      ...BASE_PROTECTION_LEDGER,
      requiredReserve: amount("protection", "124000000000"),
      lockedReserve: amount("protection", "124000000000"),
    },
    nextResponsibility: {
      status: "upcoming",
      actorRole: "buyer",
      actorLabel: "Buyer (synthetic)",
      task: "Provide the remaining synthetic receivable redemption amount at maturity.",
      dueAt: "2026-07-31T14:00:00.000Z",
      visibility: "shared",
    },
    actions: [
      {
        ...REDEEM_AT_MATURITY,
        id: "redeem-remaining-units",
        gates: makeGateVector(),
        consequence: {
          summary: "Pays the remaining synthetic receivable amount and burns only the redeemed units.",
          receivableTransition: { from: "partially_redeemed", to: "redeemed" },
          monetaryEffects: [
            {
              domain: "receivable",
              direction: "to_holder",
              amount: amount("receivable", "1240000000000"),
              label: "Remaining synthetic receivable redemption",
            },
          ],
          receivableUnitsEffect: "burn_redeemed_units",
          irreversible: true,
        },
      },
    ],
  }),
  fixture("protection-settled", {
    label: "Protection settled while receivable remains outstanding",
    protection: {
      ...BASE_PROTECTION,
      state: "settled",
      history: [
        ...BASE_PROTECTION.history,
        {
          at: "2026-07-29T07:42:00.000Z",
          from: "claimable",
          action: "settleSyntheticProtection()",
          to: "settled",
          proofId: "proof-protection-settlement",
        },
      ],
    },
    protectionLedger: {
      ...BASE_PROTECTION_LEDGER,
      requiredReserve: PROTECTION_ZERO,
      lockedReserve: PROTECTION_ZERO,
      protectionPaid: PROTECTION_RESERVE,
    },
    nextResponsibility: {
      status: "upcoming",
      actorRole: "buyer",
      actorLabel: "Buyer (synthetic)",
      task: "Provide receivable redemption money at synthetic maturity; protection settlement did not redeem it.",
      dueAt: "2026-07-31T14:00:00.000Z",
      visibility: "shared",
    },
    actions: [
      {
        id: "settle-protection-completed",
        machine: "protection",
        label: "Settle synthetic protection",
        contractAction: "settleSyntheticProtection()",
        actorRole: "facility_a",
        lifecycle: "completed",
        requiredFinality: "finalized",
        gates: makeGateVector(),
        consequence: {
          summary: "Pays synthetic protection money without burning or transferring the underlying invoice units.",
          protectionTransition: { from: "claimable", to: "settled" },
          monetaryEffects: [
            {
              domain: "protection",
              direction: "to_protected_party",
              amount: PROTECTION_RESERVE,
              label: "Synthetic protection settlement",
            },
          ],
          receivableUnitsEffect: "none",
          irreversible: true,
        },
        proofId: "proof-protection-settlement",
      },
      REDEEM_AT_MATURITY,
    ],
    proofs: [PROTECTION_SETTLEMENT_PROOF],
  }),
] as const satisfies readonly SyntheticDeal[];

export const SYNTHETIC_DEALS_BY_ID: Readonly<Record<DealScenarioId, SyntheticDeal>> = Object.fromEntries(
  SYNTHETIC_DEALS.map((deal) => [deal.scenario, deal]),
) as Record<DealScenarioId, SyntheticDeal>;

export function getSyntheticDeal(scenario: DealScenarioId): SyntheticDeal {
  return SYNTHETIC_DEALS_BY_ID[scenario];
}
