import type { Address, Hex } from "viem";

import type { DealRoomState, Role, StepKind } from "@/lib/dealroom/journey";

export const TRANSACTION_DEMO_QUERY = "transactions" as const;
export const CONTROLLED_CHAIN_SOURCE = "Executed on controlled demo chain" as const;

export type LivingSurface = "workspace" | "participant" | "protocol";
export type LivingActionStatus = "pending" | "confirmed" | "failed";

export type LivingReceipt = Readonly<{
  transactionHash: Hex;
  blockNumber: string;
  blockHash: Hex;
  status: "success" | "reverted";
  gasUsed: string;
  events: readonly string[];
}>;

export type LivingActionRecord = Readonly<{
  id: string;
  title: string;
  detail: string;
  actor: Role;
  actorLabel: string;
  kind: StepKind;
  contract: "vault" | "settlement" | null;
  method: string | null;
  status: LivingActionStatus;
  transactionHash?: Hex;
  receipt?: LivingReceipt;
  before: DealRoomState;
  after?: DealRoomState;
  error?: string;
  startedAt: string;
  completedAt?: string;
}>;

export type LivingNextAction = Readonly<{
  id: string;
  title: string;
  detail: string;
  actor: Role;
  actorLabel: string;
  kind: StepKind;
  contract: "vault" | "settlement" | null;
  method: string | null;
}>;

export type LivingDeal = Readonly<{
  id: string;
  invoiceRoot: Hex;
  vault: Address;
  settlementToken: Address;
  settlementSymbol: "dSETTLE";
  initialUnits: string;
  advanceAmount: string;
  faceValue: string;
  protectionAmount: string;
  participants: Readonly<Record<Role, Address>>;
}>;

export type LivingRunArtifact = Readonly<{
  schemaVersion: 1;
  runId: string;
  revision: number;
  source: Readonly<{
    kind: "controlled-demo-chain";
    label: typeof CONTROLLED_CHAIN_SOURCE;
    network: "Anvil";
    chainId: number;
    protocolAssets: "doubles";
    executionDiscipline: "M-15 checkpoint semantics";
  }>;
  deal: LivingDeal;
  status: "ready" | "running" | "failed" | "complete";
  current: DealRoomState;
  lastSafeState: DealRoomState;
  actions: readonly LivingActionRecord[];
  nextAction: LivingNextAction | null;
  updatedAt: string;
}>;

export type LivingView = Readonly<{
  eyebrow: string;
  title: string;
  support: string;
  consequence: string;
  responsible: string;
  deadline: string | null;
  safeAction: string;
  abnormal: boolean;
  resolved: boolean;
}>;

export const RECORDED_CHECKPOINTS = [
  { id: "funding", label: "Funding", actionId: "approve-funding" },
  { id: "activation", label: "Activation", actionId: "activate" },
  { id: "positions", label: "Position allocation", actionId: "positions" },
  { id: "commitment", label: "Conflict commitment", actionId: "commit" },
  { id: "reveal", label: "Conflict reveal", actionId: "reveal" },
  { id: "deadline", label: "Deadline", actionId: "cure-window" },
  { id: "entitlement", label: "Protection entitlement", actionId: "finalize" },
  { id: "claims", label: "Claims", actionId: "claim-b" },
  { id: "redemption", label: "Receivable redemption", actionId: "redeem-b" },
] as const;

export type RecordedCheckpointId = (typeof RECORDED_CHECKPOINTS)[number]["id"];
export type RecordedCheckpoint = (typeof RECORDED_CHECKPOINTS)[number];
export type RecordedCheckpointSelection = Readonly<{
  checkpoint: RecordedCheckpoint;
  action: LivingActionRecord;
  run: LivingRunArtifact;
}>;

export const DEFAULT_RECORDED_CHECKPOINT_ID: RecordedCheckpointId = "reveal";

export function isRecordedCheckpointId(value: string | null): value is RecordedCheckpointId {
  return RECORDED_CHECKPOINTS.some((checkpoint) => checkpoint.id === value);
}

function nextActionFromRecord(action: LivingActionRecord | undefined): LivingNextAction | null {
  if (action === undefined) return null;
  return {
    id: action.id,
    title: action.title,
    detail: action.detail,
    actor: action.actor,
    actorLabel: action.actorLabel,
    kind: action.kind,
    contract: action.contract,
    method: action.method,
  };
}

export function selectRecordedCheckpoint(
  run: LivingRunArtifact,
  requestedId: string | null,
): RecordedCheckpointSelection {
  const available = RECORDED_CHECKPOINTS.filter((checkpoint) => (
    run.actions.some((action) => action.id === checkpoint.actionId && action.status === "confirmed")
  ));
  const fallback = available.find((checkpoint) => checkpoint.id === DEFAULT_RECORDED_CHECKPOINT_ID)
    ?? available.at(-1);
  if (fallback === undefined) {
    throw new Error("The recorded run has no confirmed public checkpoint.");
  }
  const checkpoint = isRecordedCheckpointId(requestedId)
    ? available.find((candidate) => candidate.id === requestedId) ?? fallback
    : fallback;
  const actionIndex = run.actions.findIndex((action) => action.id === checkpoint.actionId);
  const action = run.actions[actionIndex];
  if (action === undefined || action.status !== "confirmed") {
    throw new Error(`The recorded checkpoint ${checkpoint.id} is not confirmed.`);
  }
  const current = action.after ?? action.before;
  const projected: LivingRunArtifact = {
    ...run,
    status: actionIndex === run.actions.length - 1 ? run.status : "ready",
    current,
    lastSafeState: current,
    actions: run.actions.slice(0, actionIndex + 1),
    nextAction: nextActionFromRecord(run.actions[actionIndex + 1]),
  };
  return { checkpoint, action, run: projected };
}

export const PROTECTION_STATES = [
  "Unfunded", "Active", "Commit pending", "Conflict confirmed", "Entitled", "Released",
] as const;

export const RECEIVABLE_STATES = [
  "Unissued", "Outstanding", "Redeemed", "Default outstanding",
] as const;

const ROLE_LABELS: Readonly<Record<Role, string>> = {
  deployer: "Demo chain controller",
  buyer: "Buyer",
  originator: "Originator",
  facilityA: "Facility A",
  facilityB: "Facility B",
  holderA: "Holder A",
  holderB: "Holder B",
};

export function roleLabel(role: Role): string {
  return ROLE_LABELS[role];
}

export function formatDemoAmount(minorUnits: string): string {
  const unit = 1_000_000n;
  const raw = BigInt(minorUnits);
  const whole = raw / unit;
  const fractional = ((raw % unit) / 10_000n).toString().padStart(2, "0");
  return `${whole.toLocaleString("en-US")}.${fractional}`;
}

export function compactTechnicalValue(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function deadlineLabel(timestamp: string): string | null {
  if (timestamp === "0") return null;
  const milliseconds = Number(timestamp) * 1_000;
  if (!Number.isFinite(milliseconds)) return null;
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(milliseconds));
}

export function latestReceiptAction(run: LivingRunArtifact): LivingActionRecord | null {
  return [...run.actions].reverse().find((action) => action.receipt !== undefined) ?? null;
}

export function deriveLivingView(run: LivingRunArtifact, surface: LivingSurface): LivingView {
  const state = run.current;
  const selectedAction = run.actions.at(-1);
  const failed = [...run.actions].reverse().find((action) => action.status === "failed");
  const pending = [...run.actions].reverse().find((action) => action.status === "pending");
  const deadline = deadlineLabel(state.pendingConflict.cureDeadline);
  const facility = state.pendingConflict.facility.toLowerCase()
    === run.deal.participants.facilityB.toLowerCase() ? "Facility B" : "The challenging facility";
  const receivable = RECEIVABLE_STATES[state.receivableState] ?? "Unknown";
  const protection = PROTECTION_STATES[state.protectionState] ?? "Unknown";
  const resolved = state.receivableState === 2 || run.status === "complete";
  const abnormal = state.protectionState >= 2 && state.protectionState <= 4 && !resolved;

  if (surface === "workspace") {
    if (resolved) {
      return {
        eyebrow: "Receipt-derived resolution",
        title: "The receivable has been paid in full.",
        support: "Protection and receivable accounting remain separate in the retained receipts.",
        consequence: `${formatDemoAmount(state.redeemedFace)} dSETTLE face value redeemed.`,
        responsible: "No open responsibility",
        deadline: null,
        safeAction: "Open receipt proof",
        abnormal: false,
        resolved: true,
      };
    }
    if (state.protectionState === 4) {
      if (selectedAction?.id === "claim-b") {
        return {
          eyebrow: "Protection claims confirmed",
          title: "Protection claims are complete.",
          support: `The receivable remains ${receivable.toLowerCase()}.`,
          consequence: `${formatDemoAmount(state.entitlementClaimed)} dSETTLE paid without consuming invoice units.`,
          responsible: run.nextAction?.actorLabel ?? "Buyer",
          deadline: null,
          safeAction: run.nextAction?.title ?? "Open receipt proof",
          abnormal: false,
          resolved: false,
        };
      }
      return {
        eyebrow: "Current contract truth",
        title: "Protection is available to record-date holders.",
        support: `The receivable remains ${receivable.toLowerCase()}.`,
        consequence: `${formatDemoAmount(state.entitlementAllocated)} dSETTLE allocated without consuming invoice units.`,
        responsible: run.nextAction?.actorLabel ?? "No open responsibility",
        deadline: null,
        safeAction: run.nextAction?.title ?? "Open receipt proof",
        abnormal: true,
        resolved: false,
      };
    }
    if (state.protectionState === 3) {
      if (selectedAction?.id === "cure-window") {
        return {
          eyebrow: "Deadline checkpoint",
          title: "The cure deadline passed unresolved.",
          support: `The receivable remains ${receivable.toLowerCase()}.`,
          consequence: "Protection can now be allocated to the record-date holders.",
          responsible: run.nextAction?.actorLabel ?? facility,
          deadline,
          safeAction: run.nextAction?.title ?? "Open checkpoint proof",
          abnormal: true,
          resolved: false,
        };
      }
      return {
        eyebrow: "Exception isolated",
        title: `${facility} revealed a conflicting pledge.`,
        support: `The receivable remains ${receivable.toLowerCase()}.`,
        consequence: "If the cure window closes unresolved, protection becomes claimable.",
        responsible: facility,
        deadline,
        safeAction: "Wait for the responsible facility or the deadline",
        abnormal: true,
        resolved: false,
      };
    }
    if (state.protectionState === 2) {
      return {
        eyebrow: "Exception detected",
        title: "A conflict commitment is now on-chain.",
        support: `The receivable remains ${receivable.toLowerCase()}.`,
        consequence: "The hidden commitment must be revealed before it can affect protection.",
        responsible: "Facility B",
        deadline: deadlineLabel(state.pendingConflict.revealDeadline),
        safeAction: run.nextAction?.title ?? "Read the retained receipt",
        abnormal: true,
        resolved: false,
      };
    }
    if (selectedAction?.id === "approve-funding") {
      return {
        eyebrow: "Funding checkpoint",
        title: "Funding approval is confirmed.",
        support: "The receivable has not been activated yet.",
        consequence: "Facility A can now activate the funded receivable and reserve.",
        responsible: run.nextAction?.actorLabel ?? "Facility A",
        deadline: null,
        safeAction: run.nextAction?.title ?? "Open receipt proof",
        abnormal: false,
        resolved: false,
      };
    }
    if (selectedAction?.id === "activate") {
      return {
        eyebrow: "Activation checkpoint",
        title: "The receivable is active.",
        support: "Funding and the protection reserve were recorded separately.",
        consequence: "The invoice positions can now be allocated.",
        responsible: run.nextAction?.actorLabel ?? "Holder A",
        deadline: null,
        safeAction: run.nextAction?.title ?? "Open receipt proof",
        abnormal: false,
        resolved: false,
      };
    }
    if (selectedAction?.id === "positions") {
      return {
        eyebrow: "Allocation checkpoint",
        title: "The receivable positions are allocated.",
        support: `${formatDemoAmount(state.holderAUnits)} units belong to Holder A; ${formatDemoAmount(state.holderBUnits)} to Holder B.`,
        consequence: "The receivable remains outstanding with no open protection event.",
        responsible: run.nextAction?.actorLabel ?? "Originator",
        deadline: null,
        safeAction: run.nextAction?.title ?? "Open receipt proof",
        abnormal: false,
        resolved: false,
      };
    }
    return {
      eyebrow: "Current contract truth",
      title: state.protectionState === 1 ? "No exception is open." : "This receivable is ready for funding.",
      support: state.protectionState === 1
        ? "One financed receivable. Protection is active."
        : "The controlled chain has one vault and no funded position yet.",
      consequence: "No intervention is due.",
      responsible: run.nextAction?.actorLabel ?? "No open responsibility",
      deadline: null,
      safeAction: run.nextAction?.title ?? "Open receipt proof",
      abnormal: false,
      resolved: false,
    };
  }

  if (surface === "participant") {
    if (state.receivableState === 2) {
      return {
        eyebrow: "Your position",
        title: "Your invoice position has been paid.",
        support: "The earlier protection claim did not reduce the invoice redemption.",
        consequence: `${formatDemoAmount(state.holderASettlement)} dSETTLE received across both domains.`,
        responsible: "No open responsibility",
        deadline: null,
        safeAction: "Open receipt proof",
        abnormal: false,
        resolved: true,
      };
    }
    if (state.protectionState === 4 && !state.holderABondClaimed) {
      const claim = BigInt(run.deal.protectionAmount) * BigInt(state.holderAUnits)
        / BigInt(state.totalSupply || "1");
      return {
        eyebrow: "Your position",
        title: `${formatDemoAmount(claim.toString())} dSETTLE is ready for you to claim.`,
        support: "Your invoice units remain yours.",
        consequence: "The claim pays from the reserve and does not consume the receivable.",
        responsible: "You",
        deadline: null,
        safeAction: "Claim your protection",
        abnormal: true,
        resolved: false,
      };
    }
    if (state.holderABondClaimed) {
      return {
        eyebrow: "Your position",
        title: "Your protection was paid.",
        support: "Your invoice units are unchanged and remain redeemable.",
        consequence: `${formatDemoAmount(state.holderASettlement)} dSETTLE protection received.`,
        responsible: run.nextAction?.actorLabel ?? "Buyer",
        deadline: null,
        safeAction: "Wait for invoice payment",
        abnormal: false,
        resolved: false,
      };
    }
    if (state.protectionState === 3) {
      if (selectedAction?.id === "cure-window") {
        return {
          eyebrow: "Your position",
          title: "You are still waiting.",
          support: "Your invoice units are unchanged.",
          consequence: "The deadline passed; protection entitlement is the next protocol step.",
          responsible: run.nextAction?.actorLabel ?? facility,
          deadline,
          safeAction: "Wait",
          abnormal: true,
          resolved: false,
        };
      }
      return {
        eyebrow: "Your position",
        title: "Nothing you need to do.",
        support: "Your invoice units are unchanged.",
        consequence: "Protection may become claimable if the conflict remains unresolved.",
        responsible: facility,
        deadline,
        safeAction: "Wait",
        abnormal: true,
        resolved: false,
      };
    }
    if (selectedAction?.id === "approve-funding") {
      return {
        eyebrow: "Your position",
        title: "Your funding approval is recorded.",
        support: "No invoice units have been issued yet.",
        consequence: "Facility A must activate the receivable before your position exists.",
        responsible: run.nextAction?.actorLabel ?? "Facility A",
        deadline: null,
        safeAction: "Wait",
        abnormal: false,
        resolved: false,
      };
    }
    if (selectedAction?.id === "activate") {
      return {
        eyebrow: "Your position",
        title: "Your invoice position is active.",
        support: `${formatDemoAmount(state.holderAUnits)} invoice units are recorded for you.`,
        consequence: "The protection reserve is separate from your receivable.",
        responsible: run.nextAction?.actorLabel ?? "Holder A",
        deadline: null,
        safeAction: "Wait",
        abnormal: false,
        resolved: false,
      };
    }
    if (selectedAction?.id === "positions") {
      return {
        eyebrow: "Your position",
        title: `You hold ${formatDemoAmount(state.holderAUnits)} invoice units.`,
        support: "The allocation is confirmed on the recorded run.",
        consequence: "Your receivable remains outstanding and protected by the separate reserve.",
        responsible: run.nextAction?.actorLabel ?? "Originator",
        deadline: null,
        safeAction: "Wait",
        abnormal: false,
        resolved: false,
      };
    }
    return {
      eyebrow: "Your position",
      title: state.protectionState === 2 ? "A potential conflict is being checked." : "Your position is unchanged.",
      support: `${formatDemoAmount(state.holderAUnits)} invoice units read from the vault.`,
      consequence: state.protectionState === 2
        ? "No protection consequence exists until the commitment is revealed."
        : "No participant action is due.",
      responsible: run.nextAction?.actorLabel ?? "No open responsibility",
      deadline: null,
      safeAction: "Wait",
      abnormal: state.protectionState === 2,
      resolved: false,
    };
  }

  if (failed !== undefined) {
    return {
      eyebrow: "Execution stopped",
      title: `${failed.title} did not complete.`,
      support: "The last safe contract read remains authoritative.",
      consequence: failed.error ?? "No after-state was established.",
      responsible: failed.actorLabel,
      deadline: null,
      safeAction: `Retry ${failed.title}`,
      abnormal: true,
      resolved: false,
    };
  }
  if (pending !== undefined) {
    return {
      eyebrow: "Transaction pending",
      title: `${pending.actorLabel} submitted ${pending.title.toLowerCase()}.`,
      support: "The interface is waiting for the receipt before changing its conclusion.",
      consequence: pending.transactionHash === undefined
        ? "Broadcast is being prepared."
        : `Transaction ${compactTechnicalValue(pending.transactionHash)} is not confirmed yet.`,
      responsible: pending.actorLabel,
      deadline,
      safeAction: "Wait for the receipt",
      abnormal: true,
      resolved: false,
    };
  }
  const latest = latestReceiptAction(run);
  const protocolTitles: Readonly<Record<string, string>> = {
    "approve-funding": "Funding approval confirmed.",
    activate: "Receivable activation confirmed.",
    positions: "Position allocation confirmed.",
    commit: "Facility B sealed a conflict commitment.",
    reveal: `${facility} revealed a conflicting pledge.`,
    "cure-window": "The cure deadline passed unresolved.",
    finalize: "Protection entitlement was allocated.",
    "claim-b": "Protection claims completed.",
    "redeem-b": "Receivable redemption completed.",
  };
  const protocolTitle = resolved
    ? protocolTitles[selectedAction?.id ?? ""] ?? "Receivable redemption completed."
    : protocolTitles[selectedAction?.id ?? ""]
      ?? (state.protectionState === 2
        ? "Facility B sealed a conflict commitment."
      : state.protectionState === 3
        ? `${facility} revealed a conflicting pledge.`
        : state.protectionState === 4 && latest?.id === "finalize"
          ? "The unresolved conflict activated protection."
          : latest === null
              ? "The canonical deal is ready to execute."
              : `${latest.title} confirmed.`);
  const protocolConsequence = resolved
    ? `${formatDemoAmount(state.redeemedFace)} dSETTLE face value redeemed independently of protection.`
    : state.protectionState === 2
      ? "No protection consequence exists until the retained commitment is revealed."
    : state.protectionState === 3
      ? "No invoice units moved; protection remains reserved through cure or deadline."
      : state.protectionState === 4
        ? `${formatDemoAmount(state.entitlementClaimed)} of ${formatDemoAmount(state.entitlementAllocated)} dSETTLE protection claimed; invoice accounting is unchanged.`
        : selectedAction?.id === "approve-funding"
          ? "The funding allowance changed; no invoice units were issued."
          : selectedAction?.id === "activate"
            ? "The receivable became outstanding and the protection reserve became active."
            : selectedAction?.id === "positions"
              ? "Ownership moved 40 units to Holder B; total receivable supply stayed unchanged."
              : "No business transaction has been submitted by this run yet.";
  return {
    eyebrow: latest === null ? "Controlled run ready" : "Last confirmed transition",
    title: protocolTitle,
    support: `Protection is ${protection.toLowerCase()}; receivable is ${receivable.toLowerCase()}.`,
    consequence: protocolConsequence,
    responsible: run.nextAction?.kind === "local-chain"
      ? "Protocol operations"
      : run.nextAction?.actorLabel ?? "No open responsibility",
    deadline,
    safeAction: run.nextAction?.title ?? "Open receipt proof",
    abnormal,
    resolved,
  };
}
