/**
 * The canonical screen's data: one deal, mid-recourse, taken from the M-13 fork rehearsal.
 *
 * The same object feeds all three variants, so a comparison shows only the design changing. These
 * are rehearsal figures, not a deployment: nothing here has happened on the public chain, and the
 * screen says so rather than leaving it to be inferred.
 */

export type EvidenceKind = "transaction" | "readback" | "signature";

export type EvidenceEntry = Readonly<{
  id: string;
  kind: EvidenceKind;
  label: string;
  /** Full value, shown in the evidence panel. */
  value: string;
  /** Shortened for inline display, so a hash never breaks a line. */
  short: string;
  block?: string;
  at: string;
  confirmed: boolean;
}>;

export type HolderPosition = Readonly<{
  id: string;
  label: string;
  address: string;
  short: string;
  units: number;
  /** Share of the face value this holder is owed, in atomic units. */
  claim: number;
  apass: "active" | "expired" | "missing";
}>;

export type LifecycleStep = Readonly<{
  id: string;
  label: string;
  state: "done" | "current" | "blocked" | "upcoming";
  detail: string;
}>;

/** Atomic units at six decimals throughout, matching MINV01 and aUSDC. */
export const DECIMALS = 6;

export const DEAL = Object.freeze({
  reference: "MINV01-0001",
  counterparty: "Clearwave Logistics BV",
  instrument: "Mordant Invoice Note",
  symbol: "MINV01",
  currency: "aUSDC",
  faceValue: 110_000,
  advance: 100_000,
  bond: 10_000,
  netProceeds: 90_000,
  custodyUnits: 100_000,
  /** Where the invoice units actually sit right now. */
  custodian: "CleanverseCvaAdapter",
  custodianAddress: "0xc0bf43a4ca27e0976195e6661b099742f10507e5",
  vaultAddress: "0x3df1E2e6F757E302dbf8b643880483938826968F",
  state: "conflict-revealed",
  stateLabel: "Conflict revealed",
  stateDetail: "A second facility has revealed a conflicting pledge over the same receivable.",
  /** Seconds left in the cure window when the study loads. */
  cureSecondsRemaining: 2_147,
  cureTotalSeconds: 3_600,
  protectionEndsInHours: 24,
  nextAction: "Finalize conflict",
  nextActionDetail:
    "Available once the cure deadline passes. Finalising snapshots holder entitlement to the bond.",
  nextActionRole: "Any participant",
  viewerRole: "Holder A",
  viewerCanAct: false,
  viewerBlockedReason:
    "Finalising is open to anyone, but only after the cure deadline. The window is still open.",
  source: "M-13 fork rehearsal, Monad testnet fork pinned at block 48901500",
});

export const HOLDERS: readonly HolderPosition[] = Object.freeze([
  {
    id: "holder-a",
    label: "Holder A",
    address: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45",
    short: "0x79C5…1e45",
    units: 50_000,
    claim: 55_000,
    apass: "active",
  },
  {
    id: "holder-b",
    label: "Holder B",
    address: "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6",
    short: "0x3444…97E6",
    units: 50_000,
    claim: 55_000,
    apass: "active",
  },
]);

export const LIFECYCLE: readonly LifecycleStep[] = Object.freeze([
  { id: "activated", label: "Activated", state: "done",
    detail: "Advance funded, bond retained, receipts allocated." },
  { id: "committed", label: "Conflict committed", state: "done",
    detail: "The challenger sealed a commitment without revealing its pledge." },
  { id: "revealed", label: "Conflict revealed", state: "current",
    detail: "The pledge is now readable on chain. The cure window opened at reveal." },
  { id: "finalized", label: "Finalise", state: "blocked",
    detail: "Blocked until the cure deadline passes." },
  { id: "default", label: "Default", state: "upcoming",
    detail: "Reachable only after protection ends, 24 hours from activation." },
  { id: "release", label: "Release to holders", state: "upcoming",
    detail: "Each holder claims its MINV01 units directly from custody." },
]);

export const EVIDENCE: readonly EvidenceEntry[] = Object.freeze([
  {
    id: "reveal-tx",
    kind: "transaction",
    label: "Conflict reveal",
    value: "0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6",
    short: "0x9f2d…56a6",
    block: "48901512",
    at: "2026-07-29 03:41:08 UTC",
    confirmed: true,
  },
  {
    id: "pledge-sig",
    kind: "signature",
    label: "Conflicting pledge, EIP-712",
    value: "0x7aac96bed820c7df570df0573a60a945dbce527fe9bbf9691d6fea130a0f9c97",
    short: "0x7aac…9c97",
    at: "2026-07-29 03:41:02 UTC",
    confirmed: true,
  },
  {
    id: "custody",
    kind: "readback",
    label: "Adapter custody, availableBalance",
    value: "100000 MINV01 held for 0x3df1E2e6…968F",
    short: "100 000 units",
    block: "48901518",
    at: "2026-07-29 03:42:16 UTC",
    confirmed: true,
  },
  {
    id: "bond",
    kind: "readback",
    label: "Bond locked, bondLocked",
    value: "10000 aUSDC retained by the vault",
    short: "10 000 aUSDC",
    block: "48901518",
    at: "2026-07-29 03:42:16 UTC",
    confirmed: true,
  },
]);

/**
 * The primary figure is the atomic unit count, grouped.
 *
 * These are the rehearsal's real amounts, and at six decimals 110 000 atomic units is 0.11 aUSDC.
 * Leading with "0.11" would make the screen unreadable and would misrepresent what was moved, so
 * the integer leads and the decimal equivalent sits underneath for anyone converting.
 */
export function formatAtomic(atomic: number): string {
  return atomic.toLocaleString("en-US");
}

/** The decimal equivalent, for the secondary line only. */
export function formatDecimal(atomic: number, decimals = DECIMALS): string {
  return (atomic / 10 ** decimals).toLocaleString("en-US", {
    minimumFractionDigits: 2, maximumFractionDigits: 6,
  });
}

export function formatCountdown(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const minutes = Math.floor(clamped / 60);
  const seconds = clamped % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}
