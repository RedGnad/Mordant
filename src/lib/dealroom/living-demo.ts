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
  const protocolTitle = resolved
    ? "Receivable redemption completed."
    : state.protectionState === 2
      ? "Facility B sealed a conflict commitment."
    : state.protectionState === 3
      ? `${facility} revealed a conflicting pledge.`
      : state.protectionState === 4 && latest?.id === "finalize"
        ? "The unresolved conflict activated protection."
        : latest === null
            ? "The canonical deal is ready to execute."
            : `${latest.title} confirmed.`;
  const protocolConsequence = resolved
    ? `${formatDemoAmount(state.redeemedFace)} dSETTLE face value redeemed independently of protection.`
    : state.protectionState === 2
      ? "No protection consequence exists until the retained commitment is revealed."
    : state.protectionState === 3
      ? "No invoice units moved; protection remains reserved through cure or deadline."
      : state.protectionState === 4
        ? `${formatDemoAmount(state.entitlementClaimed)} of ${formatDemoAmount(state.entitlementAllocated)} dSETTLE protection claimed; invoice accounting is unchanged.`
        : "No business transaction has been submitted by this run yet.";
  return {
    eyebrow: latest === null ? "Controlled run ready" : "Last confirmed transition",
    title: protocolTitle,
    support: `Protection is ${protection.toLowerCase()}; receivable is ${receivable.toLowerCase()}.`,
    consequence: protocolConsequence,
    responsible: run.nextAction?.actorLabel ?? "No open responsibility",
    deadline,
    safeAction: run.nextAction?.title ?? "Open receipt proof",
    abnormal,
    resolved,
  };
}
