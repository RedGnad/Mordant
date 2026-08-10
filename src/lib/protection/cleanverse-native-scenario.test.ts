import { ok, strictEqual, throws } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  verifyCoalitionEvidence,
  type CoalitionConflictResult,
  type CoalitionThresholdManifest,
} from "./coalition-evidence";
import {
  assertAdmissionBindsEnrollmentKey,
  assertCoalitionCaseKeysAreAdmitted,
  participantSigningKeyDigest,
  ParticipantAdmissionV2Error,
  type BoundParticipantIdentity,
  type ParticipantAdmissionV2Message,
} from "./participant-admission-v2";
import {
  deriveSettlementPlan,
  settlementProfileDigest,
  SettlementAuthorityError,
  type SettlementProfile,
} from "./settlement-authority";

/**
 * One case, end to end, on the Cleanverse-native path.
 *
 * This is deliberately a single scenario rather than a suite of independent
 * checks. The milestone's question is not whether each part works; it is whether
 * one case carries a participant's Cleanverse identity, without a break, all the
 * way to a value movement, and whether an eligibility that lapses in between
 * still stops it.
 *
 * The FHE half is real: the evidence and the case identities below were produced
 * by a 2-of-3 coalition release of the Go spine, not written here. The on-chain
 * half is proven in `contracts/test/MordantCoalitionAdapter.t.sol`, which runs
 * the same released digests through the adapter to a payout, and through the two
 * fail-closed refusals.
 */

const fixture = JSON.parse(
  readFileSync(join(process.cwd(), "contracts/test/fixtures/coalition-settlement.json"), "utf8"),
) as {
  participantA: BoundParticipantIdentity;
  participantB: BoundParticipantIdentity;
  fheCaseId: string;
  assetIdentityDigest: string;
};

const evidence = JSON.parse(
  readFileSync(join(process.cwd(), "contracts/test/fixtures/coalition-evidence.json"), "utf8"),
) as { thresholdManifest: CoalitionThresholdManifest; coalitionResult: CoalitionConflictResult };

const NOW = 1_786_000_000;
const WALLET_A = "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685" as const;
const WALLET_B = "0x0f8b9a0c064306f938912658c96c681d8655140b" as const;
const RESULT_DIGEST = `0x${"11".repeat(32)}` as const;
const RUN_ID = `0x${"22".repeat(32)}` as const;

/**
 * The admission a CVI-eligible wallet signs. It names the exact Ed25519 key the
 * case publishes for that role, which is the join this milestone exists for.
 */
function admissionFor(
  identity: BoundParticipantIdentity,
  wallet: `0x${string}`,
  overrides: Partial<ParticipantAdmissionV2Message> = {},
): ParticipantAdmissionV2Message {
  return {
    verifyingService: "mordant.participant-admission",
    runId: "canonical-run",
    fheCaseId: fixture.fheCaseId as `0x${string}`,
    protectionBindingDigest: `0x${"b1".repeat(32)}`,
    assetIdentityDigest: fixture.assetIdentityDigest as `0x${string}`,
    role: identity.role as "PARTICIPANT_A" | "PARTICIPANT_B",
    activeFrom: 100,
    activeUntil: 400,
    participantWallet: wallet,
    authorizationNonce: `0x${"b2".repeat(32)}`,
    issuedAt: NOW - 60,
    expiresAt: NOW + 120,
    participantSigningKeyDigest: participantSigningKeyDigest(identity.signingPublicKey),
    ...overrides,
  };
}

function committedProfile(releaseAuthorityId: string): SettlementProfile {
  return Object.freeze({
    schemaVersion: "mordant.settlement-profile/2",
    profileId: "mordant.cleanverse-native.canonical",
    profileVersion: 1,
    caseBinding: Object.freeze({
      runId: RUN_ID,
      caseId: evidence.coalitionResult.caseId,
      caseBindingDigest: evidence.coalitionResult.caseBindingDigest,
      protectionBindingDigest: `sha256:${"ee".repeat(32)}`,
      releaseMode: evidence.coalitionResult.releaseMode,
    }),
    participantConfig: Object.freeze({ path: "docs/evidence/coalition.json", sha256: `sha256:${"dd".repeat(32)}` }),
    committedAtUnix: 1_786_000_000,
    chainId: 10143,
    adapter: "0x9cd93089e02d301bddfc86eaabb39242272cafa1",
    settlementToken: "0xac0893567d43c3e7e6e35a72803df05416c1f20d",
    cviVerifier: "0xcffa4cbf5117718eb7fc0de2e13e07ce75b840ab",
    facility: "0x344412229b3b581c19572f9bf1f5d08d4ae897e6",
    attestor: "0xee3260ba47d097de5a8601107e1b83454593617c",
    holderA: WALLET_A.toLowerCase() as `0x${string}`,
    holderB: WALLET_B,
    payoutA: "2400",
    payoutB: "1600",
    cureWindowSeconds: 600,
    releaseAuthorityId,
    settlementAuthorization: "AUTHORIZED",
  }) as SettlementProfile;
}

test("one case carries a Cleanverse identity from admission to a settlement plan", () => {
  // 1. Two eligible wallets each admit the exact key the case publishes for them.
  const admittedA = assertAdmissionBindsEnrollmentKey(
    admissionFor(fixture.participantA, WALLET_A),
    fixture.participantA,
    `0x${"c1".repeat(32)}`,
    NOW,
  );
  const admittedB = assertAdmissionBindsEnrollmentKey(
    admissionFor(fixture.participantB, WALLET_B),
    fixture.participantB,
    `0x${"c2".repeat(32)}`,
    NOW,
  );

  // 2. Both sides of the coalition case are covered, by distinct wallets.
  assertCoalitionCaseKeysAreAdmitted([admittedA, admittedB], fixture.participantA, fixture.participantB);
  strictEqual(admittedA.signingKeyDigest, participantSigningKeyDigest(fixture.participantA.signingPublicKey));
  strictEqual(admittedB.signingKeyDigest, participantSigningKeyDigest(fixture.participantB.signingPublicKey));

  // 3. Those same keys signed the enrollments the coalition released against.
  //    The evidence and the identities come from the same real run.
  const verified = verifyCoalitionEvidence(
    evidence.coalitionResult,
    evidence.thresholdManifest,
    RESULT_DIGEST,
    RUN_ID,
  );
  strictEqual(verified.servingQuorum, 2);
  ok(verified.policyConflict, "the canonical scenario is the conflicting branch");

  // 4. The economics come from the profile committed before the result existed.
  const profile = committedProfile(verified.coalitionAuthorityId);
  const plan = deriveSettlementPlan(profile, settlementProfileDigest(profile), verified.facts);
  strictEqual(plan.releaseAuthorityId, verified.coalitionAuthorityId, "the coalition is the release identity");
  strictEqual(plan.payoutA, "2400");
  strictEqual(plan.adapter, profile.adapter);

  // 5. The value movement itself, and its live identity and policy checks, are
  //    exercised on chain in MordantCoalitionAdapterTest. The plan is the last
  //    thing produced off chain.
});

test("a key the admitted wallet never named breaks the chain at the first join", () => {
  // The case publishes B's key for role A: no admission covers it.
  throws(
    () =>
      assertAdmissionBindsEnrollmentKey(
        admissionFor(fixture.participantA, WALLET_A),
        { ...fixture.participantA, signingPublicKey: fixture.participantB.signingPublicKey },
        `0x${"c1".repeat(32)}`,
        NOW,
      ),
    (error: unknown) =>
      error instanceof ParticipantAdmissionV2Error && error.code === "SIGNING_KEY_NOT_ADMITTED",
  );
});

test("an admission that has lapsed no longer authorizes its key", () => {
  throws(
    () =>
      assertAdmissionBindsEnrollmentKey(
        admissionFor(fixture.participantA, WALLET_A),
        fixture.participantA,
        `0x${"c1".repeat(32)}`,
        NOW + 100_000,
      ),
    (error: unknown) => error instanceof ParticipantAdmissionV2Error && error.code === "ADMISSION_EXPIRED",
  );
});

test("a profile committed to another coalition cannot borrow this case's result", () => {
  const verified = verifyCoalitionEvidence(
    evidence.coalitionResult,
    evidence.thresholdManifest,
    RESULT_DIGEST,
    RUN_ID,
  );
  const profile = committedProfile(`sha256:${"99".repeat(32)}`);
  throws(
    () => deriveSettlementPlan(profile, settlementProfileDigest(profile), verified.facts),
    (error: unknown) => error instanceof SettlementAuthorityError && error.code === "AUTHORITY_MISMATCH",
  );
});
