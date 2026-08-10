import { ok, rejects, strictEqual } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { verifyTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  PARTICIPANT_ADMISSION_DOMAIN_SALT,
  PARTICIPANT_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_TYPES,
  PARTICIPANT_CHALLENGE_SCHEMA,
  LIVE_WORKER_SCHEMA,
  parseParticipantChallengeResponse,
} from "../../components/live-product/participant-admission-client";
import { admissionFailure } from "./participant-admission-service";
import { SUBMISSION_MEASUREMENT_FIELDS } from "./protection-evidence";
import {
  ParticipantAdmissionV2Error,
  PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_V2_SALT,
  PARTICIPANT_ADMISSION_V2_TYPES,
  participantAdmissionV2TypedData,
  participantSigningKeyDigest,
  verifyParticipantAdmissionV2,
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

function serverChallengeBody(wallet: `0x${string}` = "0x3883cbe36be79bd8d1b73ff160b8e7c3cb983685") {
  const typed = participantAdmissionV2TypedData({
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: `0x${"a1".repeat(32)}`,
    protectionBindingDigest: `0x${"a2".repeat(32)}`,
    assetIdentityDigest: `0x${"a3".repeat(32)}`,
    role: "PARTICIPANT_A",
    activeFrom: 100,
    activeUntil: 400,
    participantWallet: wallet,
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

// -------------------------------------------------- diagnostics at the edge

/**
 * A refusal a participant can act on.
 *
 * The worker's top-level handler forwards a typed admission refusal and collapses
 * everything else to a generic message, deliberately, so an internal error can
 * never reach a visitor. A V2 refusal was landing in the "everything else" branch,
 * so someone whose admission named the wrong signing key was told only that the
 * service refused the request.
 */
test("a V2 refusal reaches the edge with its own code and status", () => {
  for (const [reason, thrown] of [
    ["a key the case does not publish", new ParticipantAdmissionV2Error("SIGNING_KEY_NOT_ADMITTED", 409, "wrong key")],
    ["an admission outside its window", new ParticipantAdmissionV2Error("ADMISSION_EXPIRED", 409, "expired")],
    ["a malformed field", new ParticipantAdmissionV2Error("ADMISSION_FIELD", 400, "bad field")],
  ] as const) {
    const surfaced = admissionFailure(thrown);
    strictEqual(surfaced.code, thrown.code, `${reason} must keep its code`);
    strictEqual(surfaced.status, thrown.status, `${reason} must keep its status`);
    // The worker discards anything coded ADMISSION, so a generic mapping would
    // be indistinguishable from an internal failure.
    ok(surfaced.code !== "ADMISSION", `${reason} must not collapse to the generic refusal`);
  }
});

test("an unrecognised failure still collapses, so internals never reach a visitor", () => {
  const surfaced = admissionFailure(new Error("ENOENT: /srv/mordant/private/participant_a.ed25519"));
  strictEqual(surfaced.code, "ADMISSION");
  strictEqual(surfaced.status, 500);
  ok(!surfaced.message.includes("participant_a.ed25519"), "an internal path must never be surfaced");
});

/**
 * The other half of the seam: what the browser parsed is what a wallet signs,
 * and what the server then verifies.
 *
 * The parse test above stops one step short. The server does not verify against
 * the domain and types it was handed; it re-derives them from the message, on
 * purpose, so a request can never choose its own typed data. That makes the
 * re-derivation a second place the two sides can silently disagree: the browser
 * could sign a structure the server never reconstructs, and both suites would
 * stay green while every real signature failed. So this signs the exact object
 * the browser produced and hands it to the real verifier.
 */

const WALLET_KEY = `0x${"7".repeat(64)}` as const;
const WALLET = privateKeyToAccount(WALLET_KEY);

/** The expectation the server holds independently of anything the request says. */
function serverExpectation() {
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: `0x${"a1".repeat(32)}`,
    protectionBindingDigest: `0x${"a2".repeat(32)}`,
    assetIdentityDigest: `0x${"a3".repeat(32)}`,
    role: "PARTICIPANT_A",
    participantSigningKeyBase64: SIGNING_KEY,
    activeFrom: 100,
    activeUntil: 400,
    chainId: CHAIN_ID,
    now: NOW,
  } as const;
}

/** viem takes the typed data flattened; the verifier passes it nested. */
const verifyWithViem = (input: Readonly<{
  address: `0x${string}`;
  typedData: ReturnType<typeof participantAdmissionV2TypedData>;
  signature: `0x${string}`;
}>) => verifyTypedData({
  address: input.address,
  domain: input.typedData.domain,
  types: input.typedData.types,
  primaryType: input.typedData.primaryType,
  message: input.typedData.message,
  signature: input.signature,
} as Parameters<typeof verifyTypedData>[0]);

/** Signs exactly what the browser handed the wallet, nothing reconstructed. */
async function signParsedChallenge(
  parsed: NonNullable<ReturnType<typeof parseParticipantChallengeResponse>>,
  account = WALLET,
) {
  return account.signTypedData({
    domain: parsed.domain,
    types: parsed.types,
    primaryType: parsed.primaryType,
    message: parsed.message,
  } as Parameters<typeof account.signTypedData>[0]);
}

test("a signature over the parsed challenge verifies against the server's own re-derivation", async () => {
  const parsed = parseParticipantChallengeResponse(serverChallengeBody(WALLET.address), {
    ...EXPECTED,
    participantWallet: WALLET.address.toLowerCase(),
  });
  ok(parsed !== null, "the browser refused a challenge the worker issues");
  const signature = await signParsedChallenge(parsed);
  const verified = await verifyParticipantAdmissionV2(
    parsed.message,
    signature,
    serverExpectation(),
    verifyWithViem,
  );
  strictEqual(verified.signingKeyDigest, participantSigningKeyDigest(SIGNING_KEY));
  strictEqual(verified.message.participantWallet.toLowerCase(), WALLET.address.toLowerCase());
});

test("another wallet's signature over the same challenge is refused", async () => {
  const parsed = parseParticipantChallengeResponse(serverChallengeBody(WALLET.address), {
    ...EXPECTED,
    participantWallet: WALLET.address.toLowerCase(),
  });
  ok(parsed !== null);
  const impostor = privateKeyToAccount(`0x${"8".repeat(64)}`);
  const signature = await signParsedChallenge(parsed, impostor);
  await rejects(
    () => verifyParticipantAdmissionV2(parsed.message, signature, serverExpectation(), verifyWithViem),
    (error: unknown) => error instanceof ParticipantAdmissionV2Error && error.code === "SIGNATURE_INVALID",
  );
});

test("a key digest swapped after parsing does not survive to admission", async () => {
  // The attack the join exists to stop: a genuine wallet signs, but for a key
  // this case will never publish. The server derives the digest from its own
  // key, so the substitution has nowhere to hide.
  const parsed = parseParticipantChallengeResponse(serverChallengeBody(WALLET.address), {
    ...EXPECTED,
    participantWallet: WALLET.address.toLowerCase(),
  });
  ok(parsed !== null);
  const tampered = {
    ...parsed,
    message: {
      ...parsed.message,
      participantSigningKeyDigest: participantSigningKeyDigest(Buffer.alloc(32, 9).toString("base64")),
    },
  };
  const signature = await signParsedChallenge(tampered);
  await rejects(
    () => verifyParticipantAdmissionV2(tampered.message, signature, serverExpectation(), verifyWithViem),
    (error: unknown) => error instanceof ParticipantAdmissionV2Error && error.code === "SIGNING_KEY_NOT_ADMITTED",
  );
});
