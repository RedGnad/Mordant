import assert from "node:assert/strict";
import { test } from "node:test";

import type { Address, Hex } from "viem";

import type { DealRoomState, Role } from "./journey";
import {
  CONTROLLED_CHAIN_SOURCE,
  deriveLivingView,
  selectRecordedCheckpoint,
  type LivingActionRecord,
  type LivingRunArtifact,
} from "./living-demo";

const ZERO_ADDRESS = `0x${"00".repeat(20)}` as Address;
const FACILITY_B = `0x${"15".repeat(20)}` as Address;
const HASH = `0x${"ab".repeat(32)}` as Hex;

function state(overrides: Partial<DealRoomState> = {}): DealRoomState {
  return {
    blockNumber: "27",
    blockHash: HASH,
    blockTimestamp: "1800000000",
    protectionState: 3,
    receivableState: 1,
    totalSupply: "100000000",
    bondLocked: "10000000",
    entitlementAllocated: "0",
    entitlementClaimed: "0",
    redeemedFace: "0",
    holderAUnits: "60000000",
    holderBUnits: "40000000",
    holderASettlement: "0",
    holderBSettlement: "0",
    originatorSettlement: "90000000",
    vaultSettlement: "10000000",
    holderABondClaimed: false,
    holderBBondClaimed: false,
    pendingConflict: {
      facility: FACILITY_B,
      committedAt: "1799999000",
      revealDeadline: "1800000900",
      cureDeadline: "1800003600",
      conflictingPledgeDigest: HASH,
    },
    ...overrides,
  };
}

function participants(): Record<Role, Address> {
  return {
    deployer: `0x${"01".repeat(20)}`,
    buyer: `0x${"02".repeat(20)}`,
    originator: `0x${"03".repeat(20)}`,
    facilityA: `0x${"04".repeat(20)}`,
    facilityB: FACILITY_B,
    holderA: `0x${"06".repeat(20)}`,
    holderB: `0x${"07".repeat(20)}`,
  };
}

function confirmedReveal(current: DealRoomState): LivingActionRecord {
  return {
    id: "reveal",
    title: "Reveal the conflict",
    detail: "Facility B discloses the retained pledge.",
    actor: "facilityB",
    actorLabel: "Facility B",
    kind: "transaction",
    contract: "vault",
    method: "revealConflict",
    status: "confirmed",
    transactionHash: HASH,
    receipt: {
      transactionHash: HASH,
      blockNumber: "27",
      blockHash: HASH,
      status: "success",
      gasUsed: "72000",
      events: ["ConflictRevealed(facility=Facility B)"],
    },
    before: state({ blockNumber: "26", protectionState: 2 }),
    after: current,
    startedAt: "2026-07-29T20:00:00.000Z",
    completedAt: "2026-07-29T20:00:01.000Z",
  };
}

function run(current = state(), actions: readonly LivingActionRecord[] = [confirmedReveal(current)]): LivingRunArtifact {
  return {
    schemaVersion: 1,
    runId: "m-ex2:test-run",
    revision: actions.length,
    source: {
      kind: "controlled-demo-chain",
      label: CONTROLLED_CHAIN_SOURCE,
      network: "Anvil",
      chainId: 31_337,
      protocolAssets: "doubles",
      executionDiscipline: "M-15 checkpoint semantics",
    },
    deal: {
      id: "deal:canonical",
      invoiceRoot: HASH,
      vault: `0x${"08".repeat(20)}`,
      settlementToken: `0x${"09".repeat(20)}`,
      settlementSymbol: "dSETTLE",
      initialUnits: "100000000",
      advanceAmount: "100000000",
      faceValue: "110000000",
      protectionAmount: "10000000",
      participants: participants(),
    },
    status: "ready",
    current,
    lastSafeState: current,
    actions,
    nextAction: {
      id: "cure-window",
      title: "Let the cure window expire",
      detail: "Controlled local time progression.",
      actor: "deployer",
      actorLabel: "Demo chain controller",
      kind: "local-chain",
      contract: null,
      method: "evm_increaseTime",
    },
    updatedAt: "2026-07-29T20:00:01.000Z",
  };
}

test("all product perspectives derive different conclusions from one retained deal state", () => {
  const artifact = run();
  const workspace = deriveLivingView(artifact, "workspace");
  const participant = deriveLivingView(artifact, "participant");
  const protocol = deriveLivingView(artifact, "protocol");

  assert.equal(workspace.title, "Facility B revealed a conflicting pledge.");
  assert.equal(workspace.support, "The receivable remains outstanding.");
  assert.equal(participant.title, "Nothing you need to do.");
  assert.equal(participant.support, "Your invoice units are unchanged.");
  assert.equal(protocol.title, "Facility B revealed a conflicting pledge.");
  assert.equal(
    protocol.consequence,
    "No invoice units moved; protection remains reserved through cure or deadline.",
  );
  assert.equal(workspace.abnormal, true);
  assert.equal(participant.abnormal, true);
  assert.equal(protocol.abnormal, true);
});

test("a failed action keeps the last safe read authoritative and exposes a retry", () => {
  const current = state();
  const failed: LivingActionRecord = {
    id: "finalize",
    title: "Activate recourse",
    detail: "Finalize the unresolved conflict.",
    actor: "facilityB",
    actorLabel: "Facility B",
    kind: "transaction",
    contract: "vault",
    method: "finalizeConflict",
    status: "failed",
    before: current,
    error: "Transaction reverted before an after-state was established.",
    startedAt: "2026-07-29T20:01:00.000Z",
    completedAt: "2026-07-29T20:01:01.000Z",
  };
  const artifact = { ...run(current, [failed]), status: "failed" as const };
  const protocol = deriveLivingView(artifact, "protocol");

  assert.equal(protocol.eyebrow, "Execution stopped");
  assert.equal(protocol.support, "The last safe contract read remains authoritative.");
  assert.equal(protocol.safeAction, "Retry Activate recourse");
  assert.match(protocol.consequence, /after-state/);
});

test("resolution preserves protection and receivable outcomes as separate amounts", () => {
  const resolved = state({
    blockNumber: "35",
    protectionState: 4,
    receivableState: 2,
    totalSupply: "0",
    bondLocked: "0",
    entitlementAllocated: "10000000",
    entitlementClaimed: "10000000",
    redeemedFace: "110000000",
    holderAUnits: "0",
    holderBUnits: "0",
    holderASettlement: "72000000",
    holderBSettlement: "48000000",
    holderABondClaimed: true,
    holderBBondClaimed: true,
    pendingConflict: {
      facility: ZERO_ADDRESS,
      committedAt: "0",
      revealDeadline: "0",
      cureDeadline: "0",
      conflictingPledgeDigest: `0x${"00".repeat(32)}`,
    },
  });
  const artifact = { ...run(resolved), status: "complete" as const, nextAction: null };
  const participant = deriveLivingView(artifact, "participant");
  const workspace = deriveLivingView(artifact, "workspace");

  assert.equal(participant.title, "Your invoice position has been paid.");
  assert.equal(participant.consequence, "72.00 dSETTLE received across both domains.");
  assert.equal(workspace.consequence, "110.00 dSETTLE face value redeemed.");
});

test("a recorded checkpoint projects one continuous run without changing its deal", () => {
  const fundingAfter = state({
    blockNumber: "23",
    protectionState: 0,
    receivableState: 0,
    totalSupply: "0",
    bondLocked: "0",
    holderAUnits: "0",
    holderBUnits: "0",
  });
  const activationAfter = state({ blockNumber: "24", protectionState: 1 });
  const funding: LivingActionRecord = {
    ...confirmedReveal(fundingAfter),
    id: "approve-funding",
    title: "Approve the funding transfer",
    before: state({ blockNumber: "22", protectionState: 0, receivableState: 0 }),
    after: fundingAfter,
  };
  const activation: LivingActionRecord = {
    ...confirmedReveal(activationAfter),
    id: "activate",
    title: "Finance the invoice",
    before: fundingAfter,
    after: activationAfter,
  };
  const complete = {
    ...run(activationAfter, [funding, activation]),
    status: "complete" as const,
    nextAction: null,
  };

  const selected = selectRecordedCheckpoint(complete, "funding");

  assert.equal(selected.checkpoint.id, "funding");
  assert.equal(selected.action.id, "approve-funding");
  assert.equal(selected.run.deal.id, complete.deal.id);
  assert.equal(selected.run.current.blockNumber, "23");
  assert.equal(selected.run.actions.length, 1);
  assert.equal(selected.run.nextAction?.id, "activate");
  assert.equal(deriveLivingView(selected.run, "workspace").title, "Funding approval is confirmed.");
});
