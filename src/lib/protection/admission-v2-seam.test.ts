import { ok, strictEqual } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  PARTICIPANT_ADMISSION_DOMAIN_SALT,
  PARTICIPANT_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_TYPES,
  PARTICIPANT_CHALLENGE_SCHEMA,
  LIVE_WORKER_SCHEMA,
  parseParticipantChallengeResponse,
} from "../../components/live-product/participant-admission-client";
import { SUBMISSION_MEASUREMENT_FIELDS } from "./protection-evidence";
import {
  PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_V2_SALT,
  PARTICIPANT_ADMISSION_V2_TYPES,
  participantAdmissionV2TypedData,
  participantSigningKeyDigest,
} from "./participant-admission-v2";

/**
 * The seam between the worker that issues an admission challenge and the browser
 * that must parse it.
 *
 * Two suites, one per side, cannot see a disagreement between them: that is
 * exactly how the live journey broke when the server moved to V2 while the
 * browser still parsed V1 strictly, with both sides green. This test builds the
 * challenge with the server's own typed-data function and feeds it to the
 * browser's own parser, so a divergence fails here rather than in a wallet.
 */

const CHAIN_ID = 10143;
const SERVICE = "mordant.participant-admission";
// The browser requires a UUID, which is what the worker issues.
const RUN_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const NOW = 1_786_000_000;
const SIGNING_KEY = Buffer.alloc(32, 5).toString("base64");

function serverChallengeBody() {
  const typed = participantAdmissionV2TypedData({
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: `0x${"a1".repeat(32)}`,
    protectionBindingDigest: `0x${"a2".repeat(32)}`,
    assetIdentityDigest: `0x${"a3".repeat(32)}`,
    role: "PARTICIPANT_A",
    activeFrom: 100,
    activeUntil: 400,
    participantWallet: "0x3883cbe36be79bd8d1b73ff160b8e7c3cb983685",
    authorizationNonce: `0x${"a4".repeat(32)}`,
    issuedAt: NOW - 60,
    expiresAt: NOW + 120,
    participantSigningKeyDigest: participantSigningKeyDigest(SIGNING_KEY),
  }, CHAIN_ID);
  // Exactly the body the worker route returns: the challenge inside the live
  // worker envelope, which is what the browser is handed.
  return {
    schemaVersion: LIVE_WORKER_SCHEMA,
    challenge: {
      schemaVersion: PARTICIPANT_CHALLENGE_SCHEMA,
      domain: typed.domain,
      primaryType: typed.primaryType,
      types: typed.types,
      message: typed.message,
    },
  };
}

const EXPECTED = {
  runId: RUN_ID,
  role: "PARTICIPANT_A",
  participantWallet: "0x3883cbe36be79bd8d1b73ff160b8e7c3cb983685",
  claim: { activeFrom: 100, activeUntil: 400 },
  fheCaseId: `0x${"a1".repeat(32)}`,
  assetIdentityDigest: `0x${"a3".repeat(32)}`,
  expectedChainId: CHAIN_ID,
  expectedService: SERVICE,
  nowUnixSeconds: NOW,
} as const;

test("the browser parses the challenge the server actually issues", () => {
  const parsed = parseParticipantChallengeResponse(serverChallengeBody(), EXPECTED);
  ok(parsed !== null, "the browser refused a challenge the worker issues");
  strictEqual(parsed.primaryType, "ParticipantAdmissionV2");
  strictEqual(
    parsed.message.participantSigningKeyDigest,
    participantSigningKeyDigest(SIGNING_KEY),
    "the key the wallet authorizes must survive parsing",
  );
});

test("both sides pin the same type, salt and field order", () => {
  strictEqual(PARTICIPANT_ADMISSION_PRIMARY_TYPE, PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE);
  strictEqual(PARTICIPANT_ADMISSION_DOMAIN_SALT, PARTICIPANT_ADMISSION_V2_SALT);
  const browser = PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV2.map((f) => `${f.name}:${f.type}`);
  const server = PARTICIPANT_ADMISSION_V2_TYPES.ParticipantAdmissionV2.map((f) => `${f.name}:${f.type}`);
  strictEqual(browser.join(","), server.join(","), "the signed struct must be identical on both sides");
});

test("a V1 challenge is refused rather than silently signed", () => {
  const body = serverChallengeBody();
  const legacy = {
    ...body,
    challenge: {
      ...body.challenge,
      primaryType: "ParticipantAdmissionV1",
      domain: { ...body.challenge.domain, version: "1" },
    },
  };
  strictEqual(
    parseParticipantChallengeResponse(legacy, EXPECTED),
    null,
    "a V1 challenge means the worker and the UI disagree; signing it would produce a refused admission",
  );
});

test("a challenge missing the signing key is refused", () => {
  const body = serverChallengeBody();
  const { participantSigningKeyDigest: _dropped, ...withoutKey } = body.challenge.message;
  strictEqual(
    parseParticipantChallengeResponse({ ...body, challenge: { ...body.challenge, message: withoutKey } }, EXPECTED),
    null,
    "an admission that names no key cannot bind one",
  );
});

// -------------------------------------------------- Go to TypeScript evidence

/**
 * The public evidence seam.
 *
 * Go writes the submission measurements; this verifier reads them with an exact
 * key set, so a field added on one side and not the other makes every real
 * bundle unverifiable. That is what happened when `enrollmentBytes` was added to
 * the Go report: both sides' own tests stayed green while nothing Go produced
 * could be verified here.
 *
 * The fixture is a real `SubmissionReport`, emitted by the same Go run that
 * produces the coalition fixtures, so this compares against what Go actually
 * writes rather than a copy of it kept in step by hand.
 */
test("the TypeScript verifier accepts the submission report Go actually emits", () => {
  const report = JSON.parse(
    readFileSync(join(process.cwd(), "contracts/test/fixtures/submission-report.json"), "utf8"),
  ) as Record<string, unknown>;
  strictEqual(
    Object.keys(report).sort().join(","),
    [...SUBMISSION_MEASUREMENT_FIELDS].sort().join(","),
    "the Go submission report and the field set this verifier enforces have diverged",
  );
  for (const field of ["ciphertextBytes", "artifactBytes", "enrollmentBytes"] as const) {
    const value = report[field];
    ok(typeof value === "number" && Number.isInteger(value) && value > 0, `${field} must be a positive integer`);
  }
});
