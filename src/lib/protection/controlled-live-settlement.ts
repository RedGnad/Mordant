import "server-only";

/**
 * Whether a fresh direct-participant run may be settled on Monad right now.
 *
 * This module decides nothing about HOW to settle. The settlement path is the
 * one already qualified by the live activation run: verify the direct-participant
 * bridge evidence, reconcile the case-specific adapter, simulate, release exactly
 * one signature from a fresh simulation permit. There is deliberately no second
 * implementation here, because a second implementation is a second thing to get
 * wrong.
 *
 * What this module owns is the gate. It is fail-closed in the strict sense: the
 * qualification starts as a list of refusals and a condition can only remove its
 * own refusal. An unknown, unreadable or partially configured deployment stays
 * refused rather than defaulting to permitted.
 *
 * Nothing here is reachable from a browser. The report it produces carries no
 * key, no environment value and no secret, only whether each named condition
 * currently holds.
 */

import { CANONICAL_CLEANVERSE_ASSET_DIGEST } from "./cleanverse-asset";
import {
  MONAD_TESTNET_CHAIN_ID,
  loadCanonicalRecourseConfiguration,
  type CanonicalRecourseConfiguration,
} from "./adapter-compatibility";
import {
  assertDirectParticipantBridgeEvidence,
  type VerifiedDirectParticipantBridgeEvidence,
} from "./direct-participant-bridge-evidence";
import type { EnvironmentLike } from "./ccp-eligibility";

/**
 * The single server-side arm. Two names, both exact, so a stray truthy value in
 * one variable can never arm live settlement on its own.
 */
export const LIVE_SETTLEMENT_ENVIRONMENT = Object.freeze({
  enable: "MORDANT_LIVE_SETTLEMENT",
  acknowledgement: "MORDANT_LIVE_SETTLEMENT_ACK",
});

export const LIVE_SETTLEMENT_ENABLED_VALUE = "enabled" as const;
export const LIVE_SETTLEMENT_ACK_VALUE = "MORDANT_CONTROLLED_LIVE_SETTLEMENT_V1" as const;

/** Every condition that must hold. A qualification lists the ones that do not. */
export const LIVE_SETTLEMENT_CONDITIONS = [
  "SERVER_CAPABILITY_ENABLED",
  "MONAD_CHAIN",
  "CANONICAL_CONFIGURATION_LOADED",
  "BRIDGE_EVIDENCE_VERIFIED",
  "GOVERNED_SIGNATURE_VERIFIED",
  "CANONICAL_PARTICIPANT_A",
  "CANONICAL_PARTICIPANT_B",
  "PARTICIPANTS_DISTINCT",
  "PARTICIPANT_ELIGIBILITY_OBSERVED",
  "SIGNED_CONFLICT_PRESENT",
] as const;

export type LiveSettlementCondition = (typeof LIVE_SETTLEMENT_CONDITIONS)[number];

export type LiveSettlementQualification = Readonly<{
  schemaVersion: "mordant.controlled-live-settlement/1";
  /** True only when every condition holds. */
  permitted: boolean;
  /** The conditions that currently hold, in declaration order. */
  satisfied: readonly LiveSettlementCondition[];
  /** The conditions that do not, in declaration order. Empty exactly when permitted. */
  refused: readonly LiveSettlementCondition[];
  /** One sentence a person can act on. Never an environment value. */
  reason: string;
}>;

const REFUSAL_REASON: Readonly<Record<LiveSettlementCondition, string>> = Object.freeze({
  SERVER_CAPABILITY_ENABLED: "Controlled live settlement is not armed on this deployment.",
  MONAD_CHAIN: "The canonical configuration is not pinned to Monad testnet.",
  CANONICAL_CONFIGURATION_LOADED: "The canonical deployment configuration could not be loaded.",
  BRIDGE_EVIDENCE_VERIFIED: "The direct-participant bridge evidence did not verify.",
  GOVERNED_SIGNATURE_VERIFIED: "The governed Ed25519 result did not verify.",
  CANONICAL_PARTICIPANT_A: "Participant A is not the canonical controlled wallet.",
  CANONICAL_PARTICIPANT_B: "Participant B is not the canonical controlled wallet.",
  PARTICIPANTS_DISTINCT: "The two participants are not distinct wallets.",
  PARTICIPANT_ELIGIBILITY_OBSERVED: "An A-Pass eligibility observation is missing for a participant.",
  SIGNED_CONFLICT_PRESENT: "The governed result carries no signed conflict to settle.",
});

/**
 * Reads the arm.
 *
 * Both names must carry their exact value. Anything else, including absence, a
 * different string, or only one of the two, leaves settlement disarmed.
 */
export function liveSettlementArmed(environment: EnvironmentLike = process.env): boolean {
  return environment[LIVE_SETTLEMENT_ENVIRONMENT.enable] === LIVE_SETTLEMENT_ENABLED_VALUE
    && environment[LIVE_SETTLEMENT_ENVIRONMENT.acknowledgement] === LIVE_SETTLEMENT_ACK_VALUE;
}

export type LiveSettlementInput = Readonly<{
  /** The `mordant.direct-participant-bridge-evidence/1` artifact for the fresh run. */
  evidence: unknown;
  /** The source commit of the checkout that executed the run. */
  sourceCommit: string;
  runId: string;
}>;

/**
 * Qualifies a fresh run for controlled live settlement.
 *
 * Note what this function does NOT accept: no holder, no payout, no Boolean, no
 * adapter, no digest and no pin. Its only inputs are the run's own evidence and
 * its provenance. Everything economic is derived from that verified evidence and
 * from committed configuration, which is why a browser has nothing it could
 * usefully supply.
 */
export function qualifyLiveSettlement(
  input: LiveSettlementInput,
  environment: EnvironmentLike = process.env,
): LiveSettlementQualification {
  // Start refused. A condition may only remove its own refusal.
  const refused = new Set<LiveSettlementCondition>(LIVE_SETTLEMENT_CONDITIONS);
  const clear = (condition: LiveSettlementCondition) => refused.delete(condition);

  if (liveSettlementArmed(environment)) clear("SERVER_CAPABILITY_ENABLED");

  let configuration: CanonicalRecourseConfiguration | null = null;
  try {
    configuration = loadCanonicalRecourseConfiguration();
    clear("CANONICAL_CONFIGURATION_LOADED");
    if (configuration.adapter.chainId === MONAD_TESTNET_CHAIN_ID) clear("MONAD_CHAIN");
  } catch {
    configuration = null;
  }

  let verified: VerifiedDirectParticipantBridgeEvidence | null = null;
  if (configuration !== null) {
    try {
      verified = assertDirectParticipantBridgeEvidence(input.evidence, {
        sourceCommit: input.sourceCommit,
        assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
        holderA: configuration.participants.holderA,
        holderB: configuration.participants.holderB,
        excludedWallets: Object.values(configuration.participants.excluded),
        runId: input.runId,
      });
      // The verifier checks the Ed25519 signature and every cross-reference, so
      // reaching here is the proof for both of these.
      clear("BRIDGE_EVIDENCE_VERIFIED");
      clear("GOVERNED_SIGNATURE_VERIFIED");
    } catch {
      verified = null;
    }
  }

  if (verified !== null && configuration !== null) {
    const [a, b] = verified.evidence.participants;
    if (verified.holderA.toLowerCase() === configuration.participants.holderA.toLowerCase()) {
      clear("CANONICAL_PARTICIPANT_A");
    }
    if (verified.holderB.toLowerCase() === configuration.participants.holderB.toLowerCase()) {
      clear("CANONICAL_PARTICIPANT_B");
    }
    if (verified.holderA.toLowerCase() !== verified.holderB.toLowerCase()) clear("PARTICIPANTS_DISTINCT");
    if (a.eligibilityBlock > 0 && b.eligibilityBlock > 0) clear("PARTICIPANT_ELIGIBILITY_OBSERVED");
    // Only a signed true Boolean has anything to settle. A signed false is a
    // complete, correct outcome that opens no recourse and needs no transaction.
    if (verified.conflict === true) clear("SIGNED_CONFLICT_PRESENT");
  }

  const ordered = LIVE_SETTLEMENT_CONDITIONS.filter((condition) => refused.has(condition));
  const permitted = ordered.length === 0;
  return Object.freeze({
    schemaVersion: "mordant.controlled-live-settlement/1" as const,
    permitted,
    satisfied: Object.freeze(LIVE_SETTLEMENT_CONDITIONS.filter((condition) => !refused.has(condition))),
    refused: Object.freeze(ordered),
    reason: permitted
      ? "Every controlled live settlement condition holds for this run."
      : REFUSAL_REASON[ordered[0]!],
  });
}

/**
 * The remaining conditions the gate cannot answer offline.
 *
 * These are all read from chain by the already-qualified bridge path immediately
 * before signing: adapter reconciliation against the fresh signed pins, bridge
 * attestor equality, Cleanverse eligibility and transfer policy, bounded reserve,
 * `resultConsumed == false`, and a successful `consumeGovernedRelease`
 * simulation. They are listed here so the full set is documented in one place,
 * and enforced there so they are checked against live state rather than a cache.
 */
export const LIVE_SETTLEMENT_ONCHAIN_CONDITIONS = Object.freeze([
  "ADAPTER_RECONCILED_TO_SIGNED_PINS",
  "BRIDGE_ATTESTOR_EQUALS_ADAPTER_IMMUTABLE",
  "CLEANVERSE_ELIGIBILITY_AND_TRANSFER_POLICY",
  "BOUNDED_RESERVE_COVERS_PAYOUTS",
  "RESULT_NOT_ALREADY_CONSUMED",
  "SIMULATION_SUCCEEDS_IMMEDIATELY_BEFORE_BROADCAST",
]);
