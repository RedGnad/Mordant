import { createHash } from "node:crypto";

import type { Hex } from "viem";

/**
 * Settlement authority.
 *
 * A governed Boolean says a conflict exists. It never says who gets paid, how
 * much, or out of which adapter. Those are economics, and economics decided
 * after a result is visible are not governed, they are chosen. This module is
 * the seam that keeps the two apart:
 *
 *   1. a settlement PROFILE is committed BEFORE any governed result is exposed;
 *   2. a governed result is then produced and verified;
 *   3. a PLAN is derived, taking its Boolean from the result and every economic
 *      term from the pre-committed profile, never from the result;
 *   4. an AUTHORIZATION is derived from the plan, and only that authorization
 *      lets the bridge sign an Adapter V2 release.
 *
 * The existing managed policy carries `settlementAuthorization: NOT_AUTHORIZED`
 * and therefore cannot reach step 3 at all. That is the point: publishing a
 * governed protection product does not silently grant it the power to move
 * money.
 */

export const SETTLEMENT_PROFILE_SCHEMA = "mordant.settlement-profile/1" as const;
export const SETTLEMENT_PLAN_SCHEMA = "mordant.settlement-plan/1" as const;
export const SETTLEMENT_AUTHORIZATION_SCHEMA = "mordant.settlement-authorization/1" as const;

/** Only a profile that says this word can ever produce a plan. */
export const SETTLEMENT_AUTHORIZED = "AUTHORIZED" as const;
export const SETTLEMENT_NOT_AUTHORIZED = "NOT_AUTHORIZED" as const;

export type SettlementAuthorizationMode =
  | typeof SETTLEMENT_AUTHORIZED
  | typeof SETTLEMENT_NOT_AUTHORIZED;

type Address = `0x${string}`;

export class SettlementAuthorityError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "SettlementAuthorityError";
  }
}

function fail(code: string, message: string): never {
  throw new SettlementAuthorityError(code, message);
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/u;

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function sameDigest(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

/**
 * The economic terms of one settlement, fixed before anybody can see the
 * outcome they will be applied to.
 *
 * Every field here is an independent commitment. A profile that changes a
 * holder, a payout, the token, the verifier, the facility, the attestor, the
 * adapter or the cure window after the fact produces a different digest, and a
 * different digest cannot authorize a plan built against the original.
 */
export type SettlementProfile = Readonly<{
  schemaVersion: typeof SETTLEMENT_PROFILE_SCHEMA;
  profileId: string;
  profileVersion: number;
  /** Wall-clock commitment time. Evidence, not a gate: the digest is the gate. */
  committedAtUnix: number;
  chainId: number;
  /** The case-specific Adapter V2 this profile may settle through, and no other. */
  adapter: Address;
  settlementToken: Address;
  cviVerifier: Address;
  facility: Address;
  attestor: Address;
  holderA: Address;
  holderB: Address;
  /** Atomic units, decimal strings so the commitment survives JSON exactly. */
  payoutA: string;
  payoutB: string;
  cureWindowSeconds: number;
  /** The governed authority whose results this profile is willing to act on. */
  releaseAuthorityId: string;
  settlementAuthorization: SettlementAuthorizationMode;
}>;

function canonicalProfile(profile: SettlementProfile): string {
  // Key order is fixed here rather than inherited from the object so that a
  // re-serialized profile digests identically regardless of how it was built.
  return JSON.stringify({
    schemaVersion: profile.schemaVersion,
    profileId: profile.profileId,
    profileVersion: profile.profileVersion,
    committedAtUnix: profile.committedAtUnix,
    chainId: profile.chainId,
    adapter: profile.adapter.toLowerCase(),
    settlementToken: profile.settlementToken.toLowerCase(),
    cviVerifier: profile.cviVerifier.toLowerCase(),
    facility: profile.facility.toLowerCase(),
    attestor: profile.attestor.toLowerCase(),
    holderA: profile.holderA.toLowerCase(),
    holderB: profile.holderB.toLowerCase(),
    payoutA: profile.payoutA,
    payoutB: profile.payoutB,
    cureWindowSeconds: profile.cureWindowSeconds,
    releaseAuthorityId: profile.releaseAuthorityId.toLowerCase(),
    settlementAuthorization: profile.settlementAuthorization,
  });
}

export function settlementProfileDigest(profile: SettlementProfile): Hex {
  return `0x${createHash("sha256").update(`MordantSettlementProfile/v1\0${canonicalProfile(profile)}`).digest("hex")}`;
}

function atomic(value: string, label: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) fail("PROFILE_PAYOUT_FORMAT", `${label} must be a decimal atomic amount`);
  return BigInt(value);
}

/**
 * Rejects a profile that could not honestly bind a settlement, before it is
 * ever committed. Shape only: authorization is checked when a plan is derived,
 * so a deliberately NOT_AUTHORIZED profile is still a valid, committable
 * document.
 */
export function assertWellFormedSettlementProfile(profile: SettlementProfile): void {
  if (profile.schemaVersion !== SETTLEMENT_PROFILE_SCHEMA) {
    fail("PROFILE_SCHEMA", "Unrecognised settlement profile schema");
  }
  for (const [label, value] of [
    ["adapter", profile.adapter], ["settlementToken", profile.settlementToken],
    ["cviVerifier", profile.cviVerifier], ["facility", profile.facility],
    ["attestor", profile.attestor], ["holderA", profile.holderA], ["holderB", profile.holderB],
  ] as const) {
    if (!ADDRESS.test(value)) fail("PROFILE_ADDRESS", `${label} must be a 20-byte address`);
  }
  const payoutA = atomic(profile.payoutA, "payoutA");
  const payoutB = atomic(profile.payoutB, "payoutB");
  // Adapter V2 refuses a conflict release whose total is zero, and refuses to
  // pay a holder nothing. Committing such a profile would only fail later.
  if (payoutA + payoutB === 0n) fail("PROFILE_ZERO_TOTAL", "A settlement profile must commit a positive total payout");
  if (payoutA === 0n || payoutB === 0n) fail("PROFILE_ZERO_HOLDER", "Each committed holder payout must be positive");
  if (sameAddress(profile.holderA, profile.holderB)) {
    fail("PROFILE_HOLDER_COLLISION", "The two committed holders must be distinct");
  }
  if (!Number.isSafeInteger(profile.cureWindowSeconds) || profile.cureWindowSeconds <= 0) {
    fail("PROFILE_CURE_WINDOW", "The committed cure window must be a positive number of seconds");
  }
  if (!BYTES32.test(profile.releaseAuthorityId)) {
    fail("PROFILE_AUTHORITY", "The committed release authority must be a 32-byte identifier");
  }
  if (profile.settlementAuthorization !== SETTLEMENT_AUTHORIZED
    && profile.settlementAuthorization !== SETTLEMENT_NOT_AUTHORIZED) {
    fail("PROFILE_AUTHORIZATION_MODE", "The settlement authorization mode is not recognised");
  }
}

/**
 * The published managed protection product, expressed in settlement terms.
 *
 * It is deliberately and permanently NOT_AUTHORIZED. The managed demo produces
 * governed Booleans for a facility; it has never been an instruction to pay
 * anyone, and adding a settlement seam to the repository must not retroactively
 * turn it into one. The zero addresses and zero payouts are not placeholders
 * waiting to be filled: `deriveSettlementPlan` refuses on authorization before
 * it ever inspects them.
 */
export const MANAGED_DEMO_SETTLEMENT_AUTHORIZATION = Object.freeze({
  policyId: "mordant.managed-demo.facility-protection",
  policyVersion: 1,
  settlementAuthorization: SETTLEMENT_NOT_AUTHORIZED,
  reason: "The managed demo governs a Boolean only. No holder, payout or adapter is committed for it.",
} as const);

/** The governed facts a plan is allowed to read. Economics are absent on purpose. */
export type GovernedResultFacts = Readonly<{
  governedResultDigest: Hex;
  runId: Hex;
  releaseAuthorityId: string;
  /** The terminal governed Boolean, and the only thing the result contributes. */
  conflict: boolean;
}>;

export type SettlementPlan = Readonly<{
  schemaVersion: typeof SETTLEMENT_PLAN_SCHEMA;
  settlementProfileDigest: Hex;
  governedResultDigest: Hex;
  runId: Hex;
  releaseAuthorityId: string;
  conflict: true;
  adapter: Address;
  chainId: number;
  holderA: Address;
  holderB: Address;
  payoutA: string;
  payoutB: string;
  cureWindowSeconds: number;
}>;

function canonicalPlan(plan: SettlementPlan): string {
  return JSON.stringify({
    schemaVersion: plan.schemaVersion,
    settlementProfileDigest: plan.settlementProfileDigest.toLowerCase(),
    governedResultDigest: plan.governedResultDigest.toLowerCase(),
    runId: plan.runId.toLowerCase(),
    releaseAuthorityId: plan.releaseAuthorityId.toLowerCase(),
    conflict: plan.conflict,
    adapter: plan.adapter.toLowerCase(),
    chainId: plan.chainId,
    holderA: plan.holderA.toLowerCase(),
    holderB: plan.holderB.toLowerCase(),
    payoutA: plan.payoutA,
    payoutB: plan.payoutB,
    cureWindowSeconds: plan.cureWindowSeconds,
  });
}

export function settlementPlanHash(plan: SettlementPlan): Hex {
  return `0x${createHash("sha256").update(`MordantSettlementPlan/v1\0${canonicalPlan(plan)}`).digest("hex")}`;
}

/**
 * Derives the plan. This is the only place where a governed result meets
 * committed economics, and it reads exactly one field from the result.
 *
 * @param committedDigest the digest recorded when the profile was committed,
 *   before the result existed. Passing the profile alone would let a tampered
 *   profile authorize itself; the independently retained digest is what makes
 *   the commitment binding.
 */
export function deriveSettlementPlan(
  profile: SettlementProfile,
  committedDigest: Hex,
  result: GovernedResultFacts,
): SettlementPlan {
  assertWellFormedSettlementProfile(profile);
  if (!sameDigest(settlementProfileDigest(profile), committedDigest)) {
    fail("PROFILE_TAMPERED", "The settlement profile does not match the digest committed before result exposure");
  }
  if (profile.settlementAuthorization !== SETTLEMENT_AUTHORIZED) {
    fail("SETTLEMENT_NOT_AUTHORIZED", "This profile is published without settlement authority and can never settle");
  }
  if (!sameDigest(profile.releaseAuthorityId, result.releaseAuthorityId)) {
    fail("AUTHORITY_MISMATCH", "The governed result comes from an authority this profile did not commit to");
  }
  // The Boolean alone is never enough, but a false Boolean is always enough to stop.
  if (result.conflict !== true) {
    fail("NO_CONFLICT", "A governed result without a conflict cannot authorize any settlement");
  }
  if (!BYTES32.test(result.governedResultDigest)) fail("RESULT_DIGEST", "The governed result digest is malformed");
  if (!BYTES32.test(result.runId)) fail("RUN_ID", "The governed run identifier is malformed");

  return Object.freeze({
    schemaVersion: SETTLEMENT_PLAN_SCHEMA,
    settlementProfileDigest: committedDigest,
    governedResultDigest: result.governedResultDigest,
    runId: result.runId,
    releaseAuthorityId: profile.releaseAuthorityId,
    conflict: true,
    adapter: profile.adapter,
    chainId: profile.chainId,
    holderA: profile.holderA,
    holderB: profile.holderB,
    payoutA: profile.payoutA,
    payoutB: profile.payoutB,
    cureWindowSeconds: profile.cureWindowSeconds,
  });
}

export type SettlementAuthorization = Readonly<{
  schemaVersion: typeof SETTLEMENT_AUTHORIZATION_SCHEMA;
  planHash: Hex;
  settlementProfileDigest: Hex;
  governedResultDigest: Hex;
  runId: Hex;
  adapter: Address;
  chainId: number;
  holderA: Address;
  holderB: Address;
  payoutA: string;
  payoutB: string;
  cureWindowSeconds: number;
}>;

export function settlementAuthorizationHash(authorization: SettlementAuthorization): Hex {
  const canonical = JSON.stringify({
    schemaVersion: authorization.schemaVersion,
    planHash: authorization.planHash.toLowerCase(),
    settlementProfileDigest: authorization.settlementProfileDigest.toLowerCase(),
    governedResultDigest: authorization.governedResultDigest.toLowerCase(),
    runId: authorization.runId.toLowerCase(),
    adapter: authorization.adapter.toLowerCase(),
    chainId: authorization.chainId,
    holderA: authorization.holderA.toLowerCase(),
    holderB: authorization.holderB.toLowerCase(),
    payoutA: authorization.payoutA,
    payoutB: authorization.payoutB,
    cureWindowSeconds: authorization.cureWindowSeconds,
  });
  return `0x${createHash("sha256").update(`MordantSettlementAuthorization/v1\0${canonical}`).digest("hex")}`;
}

export function deriveSettlementAuthorization(plan: SettlementPlan): SettlementAuthorization {
  return Object.freeze({
    schemaVersion: SETTLEMENT_AUTHORIZATION_SCHEMA,
    planHash: settlementPlanHash(plan),
    settlementProfileDigest: plan.settlementProfileDigest,
    governedResultDigest: plan.governedResultDigest,
    runId: plan.runId,
    adapter: plan.adapter,
    chainId: plan.chainId,
    holderA: plan.holderA,
    holderB: plan.holderB,
    payoutA: plan.payoutA,
    payoutB: plan.payoutB,
    cureWindowSeconds: plan.cureWindowSeconds,
  });
}

/** The release fields an authorization is allowed to speak about. */
export type AuthorizedReleaseFacts = Readonly<{
  adapter: Address;
  chainId: number;
  governedResultDigest: Hex;
  runId: Hex;
  holderA: Address;
  holderB: Address;
  payoutA: bigint;
  payoutB: bigint;
  conflict: boolean;
}>;

/**
 * The gate the bridge calls before it will sign anything that moves money.
 *
 * Every mismatch is fatal and named, because the failure modes here are the
 * product: a swapped holder, an inflated payout or a substituted adapter must
 * be refusals, not diffs that a reviewer has to notice.
 */
export function assertSettlementAuthorization(
  authorization: SettlementAuthorization,
  plan: SettlementPlan,
  release: AuthorizedReleaseFacts,
): void {
  if (authorization.schemaVersion !== SETTLEMENT_AUTHORIZATION_SCHEMA) {
    fail("AUTHORIZATION_SCHEMA", "Unrecognised settlement authorization schema");
  }
  // An authorization that does not hash to its own plan is not evidence of anything.
  if (!sameDigest(authorization.planHash, settlementPlanHash(plan))) {
    fail("PLAN_MISMATCH", "The settlement authorization was not derived from this verified plan");
  }
  if (!sameDigest(authorization.settlementProfileDigest, plan.settlementProfileDigest)) {
    fail("PROFILE_DIGEST_MISMATCH", "The authorization and the plan disagree about the committed profile");
  }
  if (release.conflict !== true) {
    fail("NO_CONFLICT_RELEASE", "A release without a conflict must never carry a settlement authorization");
  }
  if (!sameDigest(authorization.governedResultDigest, release.governedResultDigest)) {
    fail("RESULT_MISMATCH", "The authorization was issued for a different governed result");
  }
  if (!sameDigest(authorization.runId, release.runId)) {
    fail("RUN_MISMATCH", "The authorization was issued for a different governed run");
  }
  if (!sameAddress(authorization.adapter, release.adapter)) {
    fail("ADAPTER_MISMATCH", "The authorization does not cover this Adapter V2");
  }
  if (authorization.chainId !== release.chainId) {
    fail("CHAIN_MISMATCH", "The authorization was issued for a different chain");
  }
  if (!sameAddress(authorization.holderA, release.holderA) || !sameAddress(authorization.holderB, release.holderB)) {
    fail("HOLDER_MISMATCH", "The release pays a holder the committed profile did not name");
  }
  if (BigInt(authorization.payoutA) !== release.payoutA || BigInt(authorization.payoutB) !== release.payoutB) {
    fail("PAYOUT_MISMATCH", "The release pays an amount the committed profile did not fix");
  }
}
