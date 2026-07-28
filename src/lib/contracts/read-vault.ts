import {
  zeroHash,
  type Address,
  type Hex,
} from "viem";

import type { MonadTestnetReadClient, MonadTestnetPublicConfig } from "./config";
import { mordantInvoiceVaultReadAbi } from "./mordant-invoice-vault-abi";

export const MORDANT_UNIT_DECIMALS = 6 as const;
const UNIT_SCALE = 10n ** BigInt(MORDANT_UNIT_DECIMALS);

export const PROTECTION_STATES = [
  "Unfunded",
  "Active",
  "CommitPending",
  "ConflictConfirmed",
  "Entitled",
  "Released",
] as const;

export const RECEIVABLE_STATES = [
  "Unissued",
  "Outstanding",
  "Redeemed",
  "DefaultOutstanding",
] as const;

export type ProtectionState = (typeof PROTECTION_STATES)[number];
export type ReceivableState = (typeof RECEIVABLE_STATES)[number];

export type RawPendingConflict = Readonly<{
  commitment: Hex;
  facility: Address;
  snapshotSequence: number;
  snapshotSupply: bigint;
  snapshotBond: bigint;
  committedAt: bigint;
  revealDeadline: bigint;
  cureDeadline: bigint;
  conflictingPledgeDigest: Hex;
  conflictSigner: Address;
}>;

export type RawMordantInvoiceVaultSnapshot = Readonly<{
  chainId: number;
  blockNumber: bigint;
  vaultAddress: Address;
  invoiceRoot: Hex;
  decimals: typeof MORDANT_UNIT_DECIMALS;
  protectionState: Readonly<{ code: number; label: ProtectionState }>;
  receivableState: Readonly<{ code: number; label: ReceivableState }>;
  sequence: number;
  totalSupply: bigint;
  initialUnits: bigint;
  cvaAccounted: bigint;
  cvaBurned: bigint;
  faceValue: bigint;
  initialBond: bigint;
  bondLocked: bigint;
  bondReturned: bigint;
  entitlementAllocated: bigint;
  entitlementClaimed: bigint;
  entitlementClaimedUnits: bigint;
  entitlementSnapshotSequence: number;
  entitlementSnapshotSupply: bigint;
  redemptionEscrow: bigint;
  redeemedFace: bigint;
  cvaReleasedFace: bigint;
  settlementCreditTotal: bigint;
  defaultCvaReleaseStarted: boolean;
  accountedSettlementBalance: bigint;
  pendingConflict: RawPendingConflict | null;
}>;

export type SixDecimalAmount = Readonly<{
  atomics: string;
  formatted: string;
  decimals: typeof MORDANT_UNIT_DECIMALS;
}>;

export type HumanTimestamp = Readonly<{
  unixSeconds: string;
  iso: string | null;
}>;

export type MordantInvoiceVaultSnapshot = Readonly<{
  chain: Readonly<{
    id: number;
    blockNumber: string;
  }>;
  contract: Readonly<{
    address: Address;
    invoiceRoot: Hex;
  }>;
  stateMachines: Readonly<{
    protection: Readonly<{ code: number; label: ProtectionState }>;
    receivable: Readonly<{ code: number; label: ReceivableState }>;
    sequence: number;
  }>;
  supply: Readonly<{
    initial: SixDecimalAmount;
    outstanding: SixDecimalAmount;
    cvaAccounted: SixDecimalAmount;
    cvaBurned: SixDecimalAmount;
  }>;
  bond: Readonly<{
    initial: SixDecimalAmount;
    locked: SixDecimalAmount;
    returned: SixDecimalAmount;
  }>;
  entitlement: Readonly<{
    allocated: SixDecimalAmount;
    claimed: SixDecimalAmount;
    unclaimed: SixDecimalAmount;
    claimedUnits: SixDecimalAmount;
    snapshotSequence: number;
    snapshotSupply: SixDecimalAmount;
  }>;
  redemption: Readonly<{
    faceValue: SixDecimalAmount;
    escrow: SixDecimalAmount;
    redeemed: SixDecimalAmount;
    /** Face value discharged through CVA release after default. */
    cvaReleased: SixDecimalAmount;
    /** Face value still owed in cash: faceValue - redeemedFace - cvaReleasedFace. */
    remainingFace: SixDecimalAmount;
    /** Cash the buyer must still escrow: remainingFace - redemptionEscrow. */
    unfundedLiability: SixDecimalAmount;
    defaultCvaReleaseStarted: boolean;
  }>;
  accounting: Readonly<{
    settlementAccounted: SixDecimalAmount;
    /** Accrued pull-payment credit still owed to buyer/originator beneficiaries. */
    settlementCreditTotal: SixDecimalAmount;
    bondLifecycleTotal: SixDecimalAmount;
    contractAssertionPassed: true;
    supplyMatchesCva: boolean;
    bondMatchesInitial: boolean;
    settlementAccountedMatchesComponents: boolean;
  }>;
  pendingConflict: Readonly<{
    commitment: Hex;
    facility: Address;
    snapshotSequence: number;
    snapshotSupply: SixDecimalAmount;
    snapshotBond: SixDecimalAmount;
    committedAt: HumanTimestamp;
    revealDeadline: HumanTimestamp;
    cureDeadline: HumanTimestamp | null;
    conflictingPledgeDigest: Hex | null;
    conflictSigner: Address | null;
  }> | null;
}>;

export class MordantVaultReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MordantVaultReadError";
  }
}

function decodeState<const TStates extends readonly string[]>(
  states: TStates,
  code: number,
  machine: string,
): TStates[number] {
  const label = states[code];
  if (label === undefined) {
    throw new MordantVaultReadError(`Unknown ${machine} state code`);
  }
  return label;
}

function checkedDifference(total: bigint, consumed: bigint, field: string): bigint {
  if (consumed > total) {
    throw new MordantVaultReadError(`${field} accounting is inconsistent`);
  }
  return total - consumed;
}

export function formatSixDecimalAmount(atomics: bigint): SixDecimalAmount {
  if (atomics < 0n) {
    throw new MordantVaultReadError("Unsigned Mordant amount cannot be negative");
  }
  const whole = atomics / UNIT_SCALE;
  const fraction = (atomics % UNIT_SCALE).toString().padStart(MORDANT_UNIT_DECIMALS, "0");
  return Object.freeze({
    atomics: atomics.toString(),
    formatted: `${whole}.${fraction}`,
    decimals: MORDANT_UNIT_DECIMALS,
  });
}

function humanTimestamp(unixSeconds: bigint): HumanTimestamp {
  const milliseconds = unixSeconds * 1_000n;
  const maximumDateMilliseconds = 8_640_000_000_000_000n;
  const iso = milliseconds <= maximumDateMilliseconds
    ? new Date(Number(milliseconds)).toISOString()
    : null;
  return Object.freeze({ unixSeconds: unixSeconds.toString(), iso });
}

/** Reads every field at the same block while issuing the independent RPC calls in parallel. */
export async function readRawMordantInvoiceVaultSnapshot(
  client: MonadTestnetReadClient,
  config: MonadTestnetPublicConfig,
): Promise<RawMordantInvoiceVaultSnapshot> {
  const blockNumber = await client.getBlockNumber();
  const contract = {
    address: config.vaultAddress,
    abi: mordantInvoiceVaultReadAbi,
    blockNumber,
  } as const;

  const [
    invoiceRoot,
    decimals,
    protectionStateCode,
    receivableStateCode,
    sequence,
    totalSupply,
    initialUnits,
    cvaAccounted,
    cvaBurned,
    faceValue,
    initialBond,
    bondLocked,
    bondReturned,
    entitlementAllocated,
    entitlementClaimed,
    entitlementClaimedUnits,
    entitlementSnapshotSequence,
    entitlementSnapshotSupply,
    redemptionEscrow,
    redeemedFace,
    cvaReleasedFace,
    settlementCreditTotal,
    defaultCvaReleaseStarted,
    accountedSettlementBalance,
    pending,
    accountingAssertion,
  ] = await Promise.all([
    client.readContract({ ...contract, functionName: "invoiceRoot" }),
    client.readContract({ ...contract, functionName: "decimals" }),
    client.readContract({ ...contract, functionName: "protectionState" }),
    client.readContract({ ...contract, functionName: "receivableState" }),
    client.readContract({ ...contract, functionName: "sequence" }),
    client.readContract({ ...contract, functionName: "totalSupply" }),
    client.readContract({ ...contract, functionName: "initialUnits" }),
    client.readContract({ ...contract, functionName: "cvaAccounted" }),
    client.readContract({ ...contract, functionName: "cvaBurned" }),
    client.readContract({ ...contract, functionName: "faceValue" }),
    client.readContract({ ...contract, functionName: "initialBond" }),
    client.readContract({ ...contract, functionName: "bondLocked" }),
    client.readContract({ ...contract, functionName: "bondReturned" }),
    client.readContract({ ...contract, functionName: "entitlementAllocated" }),
    client.readContract({ ...contract, functionName: "entitlementClaimed" }),
    client.readContract({ ...contract, functionName: "entitlementClaimedUnits" }),
    client.readContract({ ...contract, functionName: "entitlementSnapshotSequence" }),
    client.readContract({ ...contract, functionName: "entitlementSnapshotSupply" }),
    client.readContract({ ...contract, functionName: "redemptionEscrow" }),
    client.readContract({ ...contract, functionName: "redeemedFace" }),
    client.readContract({ ...contract, functionName: "cvaReleasedFace" }),
    client.readContract({ ...contract, functionName: "settlementCreditTotal" }),
    client.readContract({ ...contract, functionName: "defaultCvaReleaseStarted" }),
    client.readContract({ ...contract, functionName: "accountedSettlementBalance" }),
    client.readContract({ ...contract, functionName: "pendingConflict" }),
    client.readContract({ ...contract, functionName: "assertAccounting" }),
  ] as const);

  if (accountingAssertion !== undefined) {
    throw new MordantVaultReadError("Unexpected accounting assertion result");
  }

  if (decimals !== MORDANT_UNIT_DECIMALS) {
    throw new MordantVaultReadError("Configured contract is not a six-decimal Mordant vault");
  }

  const pendingConflict = pending[0] === zeroHash
    ? null
    : Object.freeze({
        commitment: pending[0],
        facility: pending[1],
        snapshotSequence: pending[2],
        snapshotSupply: pending[3],
        snapshotBond: pending[4],
        committedAt: pending[5],
        revealDeadline: pending[6],
        cureDeadline: pending[7],
        conflictingPledgeDigest: pending[8],
        conflictSigner: pending[9],
      });

  return Object.freeze({
    chainId: config.chainId,
    blockNumber,
    vaultAddress: config.vaultAddress,
    invoiceRoot,
    decimals,
    protectionState: Object.freeze({
      code: protectionStateCode,
      label: decodeState(PROTECTION_STATES, protectionStateCode, "protection"),
    }),
    receivableState: Object.freeze({
      code: receivableStateCode,
      label: decodeState(RECEIVABLE_STATES, receivableStateCode, "receivable"),
    }),
    sequence,
    totalSupply,
    initialUnits,
    cvaAccounted,
    cvaBurned,
    faceValue,
    initialBond,
    bondLocked,
    bondReturned,
    entitlementAllocated,
    entitlementClaimed,
    entitlementClaimedUnits,
    entitlementSnapshotSequence,
    entitlementSnapshotSupply,
    redemptionEscrow,
    redeemedFace,
    cvaReleasedFace,
    settlementCreditTotal,
    defaultCvaReleaseStarted,
    accountedSettlementBalance,
    pendingConflict,
  });
}

export function toHumanMordantInvoiceVaultSnapshot(
  raw: RawMordantInvoiceVaultSnapshot,
): MordantInvoiceVaultSnapshot {
  const unclaimedEntitlement = checkedDifference(
    raw.entitlementAllocated,
    raw.entitlementClaimed,
    "entitlement",
  );
  // The contract discharges face value through two independent paths, so cash liability has to
  // net both. See MordantInvoiceVault._refundExcessRedemptionEscrow / _faceAmount.
  const remainingFace = checkedDifference(
    raw.faceValue,
    raw.redeemedFace + raw.cvaReleasedFace,
    "redemption",
  );
  // The vault refunds any escrow above the remaining cash liability, so escrow can never exceed it.
  const unfundedLiability = checkedDifference(remainingFace, raw.redemptionEscrow, "escrow");
  const bondLifecycleTotal = raw.bondLocked + raw.bondReturned + raw.entitlementAllocated;
  const settlementComponents =
    raw.bondLocked + unclaimedEntitlement + raw.redemptionEscrow + raw.settlementCreditTotal;

  return Object.freeze({
    chain: Object.freeze({
      id: raw.chainId,
      blockNumber: raw.blockNumber.toString(),
    }),
    contract: Object.freeze({
      address: raw.vaultAddress,
      invoiceRoot: raw.invoiceRoot,
    }),
    stateMachines: Object.freeze({
      protection: raw.protectionState,
      receivable: raw.receivableState,
      sequence: raw.sequence,
    }),
    supply: Object.freeze({
      initial: formatSixDecimalAmount(raw.initialUnits),
      outstanding: formatSixDecimalAmount(raw.totalSupply),
      cvaAccounted: formatSixDecimalAmount(raw.cvaAccounted),
      cvaBurned: formatSixDecimalAmount(raw.cvaBurned),
    }),
    bond: Object.freeze({
      initial: formatSixDecimalAmount(raw.initialBond),
      locked: formatSixDecimalAmount(raw.bondLocked),
      returned: formatSixDecimalAmount(raw.bondReturned),
    }),
    entitlement: Object.freeze({
      allocated: formatSixDecimalAmount(raw.entitlementAllocated),
      claimed: formatSixDecimalAmount(raw.entitlementClaimed),
      unclaimed: formatSixDecimalAmount(unclaimedEntitlement),
      claimedUnits: formatSixDecimalAmount(raw.entitlementClaimedUnits),
      snapshotSequence: raw.entitlementSnapshotSequence,
      snapshotSupply: formatSixDecimalAmount(raw.entitlementSnapshotSupply),
    }),
    redemption: Object.freeze({
      faceValue: formatSixDecimalAmount(raw.faceValue),
      escrow: formatSixDecimalAmount(raw.redemptionEscrow),
      redeemed: formatSixDecimalAmount(raw.redeemedFace),
      cvaReleased: formatSixDecimalAmount(raw.cvaReleasedFace),
      remainingFace: formatSixDecimalAmount(remainingFace),
      unfundedLiability: formatSixDecimalAmount(unfundedLiability),
      defaultCvaReleaseStarted: raw.defaultCvaReleaseStarted,
    }),
    accounting: Object.freeze({
      settlementAccounted: formatSixDecimalAmount(raw.accountedSettlementBalance),
      settlementCreditTotal: formatSixDecimalAmount(raw.settlementCreditTotal),
      bondLifecycleTotal: formatSixDecimalAmount(bondLifecycleTotal),
      contractAssertionPassed: true,
      supplyMatchesCva: raw.totalSupply === raw.cvaAccounted,
      bondMatchesInitial: bondLifecycleTotal === raw.initialBond,
      settlementAccountedMatchesComponents:
        raw.accountedSettlementBalance === settlementComponents,
    }),
    pendingConflict: raw.pendingConflict === null
      ? null
      : Object.freeze({
          commitment: raw.pendingConflict.commitment,
          facility: raw.pendingConflict.facility,
          snapshotSequence: raw.pendingConflict.snapshotSequence,
          snapshotSupply: formatSixDecimalAmount(raw.pendingConflict.snapshotSupply),
          snapshotBond: formatSixDecimalAmount(raw.pendingConflict.snapshotBond),
          committedAt: humanTimestamp(raw.pendingConflict.committedAt),
          revealDeadline: humanTimestamp(raw.pendingConflict.revealDeadline),
          cureDeadline: raw.pendingConflict.cureDeadline === 0n
            ? null
            : humanTimestamp(raw.pendingConflict.cureDeadline),
          conflictingPledgeDigest: raw.pendingConflict.conflictingPledgeDigest === zeroHash
            ? null
            : raw.pendingConflict.conflictingPledgeDigest,
          conflictSigner: raw.pendingConflict.conflictSigner === "0x0000000000000000000000000000000000000000"
            ? null
            : raw.pendingConflict.conflictSigner,
        }),
  });
}

export async function readMordantInvoiceVaultSnapshot(
  client: MonadTestnetReadClient,
  config: MonadTestnetPublicConfig,
): Promise<MordantInvoiceVaultSnapshot> {
  return toHumanMordantInvoiceVaultSnapshot(
    await readRawMordantInvoiceVaultSnapshot(client, config),
  );
}
