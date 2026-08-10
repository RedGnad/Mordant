import { existsSync, mkdirSync, openSync, closeSync, writeSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { Hex } from "viem";

import { DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE } from "./bridge-executor";
import {
  assertWellFormedSettlementProfile,
  deriveSettlementAuthorization,
  deriveSettlementPlan,
  settlementProfileDigest,
  type GovernedResultFacts,
  type SettlementAuthorization,
  type SettlementPlan,
  type SettlementProfile,
} from "./settlement-authority";

/**
 * Durable commitment of a settlement profile, and the only way the runtime path
 * is allowed to obtain settlement authority.
 *
 * Two properties make the commitment mean something, and both are enforced here
 * rather than asserted in prose:
 *
 *   1. ORDER. Committing is refused once the governed result artifact exists in
 *      the run. A profile can therefore never be written by someone who has
 *      already seen the outcome it will be applied to.
 *   2. IMMUTABILITY. The write is create-only, and the digest is retained beside
 *      the profile. A later edit changes the recomputed digest, the retained one
 *      no longer matches, and every read refuses.
 *
 * What this does not give you is a trusted clock. The ordering guarantee is
 * relative to the run's own artifacts, not to wall time, and a party who
 * controls the run root could stage both files. It is the same trust boundary
 * the durable bridge record already lives inside.
 */

export const SETTLEMENT_PROFILE_FILE = "settlement-profile.json" as const;
export const SETTLEMENT_PROFILE_COMMITMENT_SCHEMA = "mordant.settlement-profile-commitment/1" as const;

export class SettlementProfileStoreError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "SettlementProfileStoreError";
  }
}

function fail(code: string, message: string): never {
  throw new SettlementProfileStoreError(code, message);
}

export type CommittedSettlementProfile = Readonly<{
  schemaVersion: typeof SETTLEMENT_PROFILE_COMMITMENT_SCHEMA;
  profile: SettlementProfile;
  committedDigest: Hex;
}>;

export function settlementProfilePath(runRoot: string, runId: string): string {
  return join(runRoot, runId, SETTLEMENT_PROFILE_FILE);
}

function governedResultPath(runRoot: string, runId: string): string {
  return join(runRoot, runId, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE);
}

/**
 * Writes the commitment, once, before any governed result exists for the run.
 *
 * @throws if the run already holds a governed result, or a profile was already
 *   committed. Neither is recoverable by retrying: a settlement profile that
 *   could be rewritten is not a commitment.
 */
export function commitSettlementProfile(
  runRoot: string,
  runId: string,
  profile: SettlementProfile,
): CommittedSettlementProfile {
  assertWellFormedSettlementProfile(profile);
  if (existsSync(governedResultPath(runRoot, runId))) {
    fail(
      "RESULT_ALREADY_EXPOSED",
      "A governed result already exists for this run, so no settlement profile can still be committed for it",
    );
  }
  const committedDigest = settlementProfileDigest(profile);
  const record: CommittedSettlementProfile = {
    schemaVersion: SETTLEMENT_PROFILE_COMMITMENT_SCHEMA,
    profile,
    committedDigest,
  };
  const path = settlementProfilePath(runRoot, runId);
  mkdirSync(dirname(path), { recursive: true });
  let handle: number;
  try {
    // Create-only: an existing commitment is never silently replaced.
    handle = openSync(path, "wx");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      fail("ALREADY_COMMITTED", "This run already has a committed settlement profile");
    }
    throw error;
  }
  try {
    writeSync(handle, `${JSON.stringify(record, null, 2)}\n`);
  } finally {
    closeSync(handle);
  }
  return Object.freeze(record);
}

/** Reads the commitment and refuses any profile that no longer hashes to its retained digest. */
export function readCommittedSettlementProfile(runRoot: string, runId: string): CommittedSettlementProfile {
  const path = settlementProfilePath(runRoot, runId);
  if (!existsSync(path)) fail("NOT_COMMITTED", "This run has no committed settlement profile");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch {
    fail("UNREADABLE", "The committed settlement profile is not valid JSON");
  }
  const record = raw as Partial<CommittedSettlementProfile>;
  if (record.schemaVersion !== SETTLEMENT_PROFILE_COMMITMENT_SCHEMA) {
    fail("SCHEMA", "Unrecognised settlement profile commitment schema");
  }
  if (record.profile === undefined || typeof record.committedDigest !== "string") {
    fail("SHAPE", "The settlement profile commitment is missing its profile or digest");
  }
  assertWellFormedSettlementProfile(record.profile);
  if (settlementProfileDigest(record.profile).toLowerCase() !== record.committedDigest.toLowerCase()) {
    fail("TAMPERED", "The retained settlement profile no longer matches the digest committed for it");
  }
  return Object.freeze({
    schemaVersion: SETTLEMENT_PROFILE_COMMITMENT_SCHEMA,
    profile: record.profile,
    committedDigest: record.committedDigest as Hex,
  });
}

/**
 * The runtime path's only source of settlement authority.
 *
 * Economics come from the commitment. The authenticated governed result
 * contributes its Boolean and its identity, nothing else. Nothing here reads
 * the release the executor is about to sign, which is what keeps this a
 * derivation rather than a rubber stamp.
 */
export function settlementAuthorityForRun(
  runRoot: string,
  runId: string,
  result: GovernedResultFacts,
): Readonly<{ plan: SettlementPlan; authorization: SettlementAuthorization; committedDigest: Hex }> {
  const committed = readCommittedSettlementProfile(runRoot, runId);
  const plan = deriveSettlementPlan(committed.profile, committed.committedDigest, result);
  return Object.freeze({
    plan,
    authorization: deriveSettlementAuthorization(plan),
    committedDigest: committed.committedDigest,
  });
}
