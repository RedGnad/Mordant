import assert from "node:assert/strict";
import test from "node:test";

import {
  PARTICIPANT_ADMISSION_DOMAIN_NAME,
  PARTICIPANT_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS,
  ParticipantAuthorizationError,
  assertParticipantAdmissionMessage,
  digestToBytes32,
  isParticipantRole,
  participantAdmissionDigest,
  participantAdmissionDomain,
  participantAdmissionTypedData,
  participantClaimCommitment,
  verifyParticipantAuthorization,
  type Bytes32,
  type ParticipantAdmissionMessage,
  type TypedDataVerifier,
} from "./participant-authorization";

/**
 * What a participant authorization has to be worth.
 *
 * The wallet signature is the only thing standing between "someone claims to be
 * participant B" and the engine accepting a window under that role. So the properties
 * under test are the substitutions an attacker would actually attempt: a different role,
 * a different case, a different asset, a different wallet, or the same authorization used
 * twice.
 */

const WALLET = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02" as const;
const OTHER_WALLET = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0" as const;
const RUN_ID = "693a1cfc-a8c0-4024-a3de-3e17e38eb99c";
const SERVICE = "https://worker.example";

const FHE_CASE = `sha256:${"1".repeat(64)}` as const;
const BINDING = `sha256:${"2".repeat(64)}` as const;
const ASSET = `sha256:${"3".repeat(64)}` as const;
const NONCE = `0x${"4".repeat(64)}` as Bytes32;

function message(overrides: Partial<ParticipantAdmissionMessage> = {}): ParticipantAdmissionMessage {
  const issuedAt = 1_785_000_000;
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: digestToBytes32(FHE_CASE),
    protectionBindingDigest: digestToBytes32(BINDING),
    assetIdentityDigest: digestToBytes32(ASSET),
    role: "PARTICIPANT_A",
    activeFrom: 120,
    activeUntil: 420,
    participantWallet: WALLET,
    authorizationNonce: NONCE,
    issuedAt,
    expiresAt: issuedAt + 300,
    ...overrides,
  };
}

function expected(overrides: Record<string, unknown> = {}) {
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: FHE_CASE,
    protectionBindingDigest: BINDING,
    assetIdentityDigest: ASSET,
    role: "PARTICIPANT_A" as const,
    claim: { activeFrom: 120, activeUntil: 420 },
    now: 1_785_000_060,
    ...overrides,
  };
}

/** Accepts only the exact digest it was armed with, which is what a real wallet does. */
function walletVerifier(accepted: readonly Bytes32[], address = WALLET): TypedDataVerifier {
  return async (input) => (
    input.address.toLowerCase() === address.toLowerCase() && accepted.includes(input.digest)
  );
}

const SIGNATURE = `0x${"ab".repeat(65)}`;

async function refusal(promise: Promise<unknown>): Promise<ParticipantAuthorizationError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ParticipantAuthorizationError, `expected a typed refusal, got ${String(error)}`);
    return error;
  }
  throw new Error("expected a refusal");
}

test("the typed data binds the chain, the service and the signing wallet", () => {
  const domain = participantAdmissionDomain(10_143);
  assert.equal(domain.name, PARTICIPANT_ADMISSION_DOMAIN_NAME);
  assert.equal(Number(domain.chainId), 10_143);

  const typed = participantAdmissionTypedData(message());
  assert.equal(typed.primaryType, PARTICIPANT_ADMISSION_PRIMARY_TYPE);
  assert.equal(typed.message.participantWallet, WALLET);
  assert.equal(typed.message.role, "PARTICIPANT_A");

  // A different chain is a different signature domain.
  assert.notEqual(
    participantAdmissionDigest(message(), 10_143),
    participantAdmissionDigest(message(), 1),
  );
});

test("every signed field changes the digest", () => {
  const base = participantAdmissionDigest(message());
  const mutations: ReadonlyArray<Partial<ParticipantAdmissionMessage>> = [
    { role: "PARTICIPANT_B" },
    { runId: "5fac6616-1a89-4234-a1fa-1e1046782fb4" },
    { participantWallet: OTHER_WALLET },
    { activeFrom: 121 },
    { activeUntil: 421 },
    { fheCaseId: digestToBytes32(`sha256:${"9".repeat(64)}`) },
    { protectionBindingDigest: digestToBytes32(`sha256:${"8".repeat(64)}`) },
    { assetIdentityDigest: digestToBytes32(`sha256:${"7".repeat(64)}`) },
    { authorizationNonce: `0x${"5".repeat(64)}` as Bytes32 },
    { expiresAt: 1_785_000_301 },
    { verifyingService: "https://other.example" },
  ];
  for (const mutation of mutations) {
    assert.notEqual(
      participantAdmissionDigest(message(mutation)),
      base,
      `${Object.keys(mutation)[0]} must be inside the signature`,
    );
  }
});

test("the claim commitment separates roles and windows", () => {
  const a = participantClaimCommitment({ runId: RUN_ID, role: "PARTICIPANT_A", claim: { activeFrom: 120, activeUntil: 420 } });
  const sameForB = participantClaimCommitment({ runId: RUN_ID, role: "PARTICIPANT_B", claim: { activeFrom: 120, activeUntil: 420 } });
  const otherWindow = participantClaimCommitment({ runId: RUN_ID, role: "PARTICIPANT_A", claim: { activeFrom: 121, activeUntil: 420 } });
  assert.notEqual(a, sameForB);
  assert.notEqual(a, otherWindow);
  assert.match(a, /^0x[0-9a-f]{64}$/u);
});

test("only the two declared roles exist", () => {
  assert.ok(isParticipantRole("PARTICIPANT_A"));
  assert.ok(isParticipantRole("PARTICIPANT_B"));
  for (const candidate of ["participant_a", "PARTICIPANT_C", "", null, 3, {}]) {
    assert.equal(isParticipantRole(candidate), false);
  }
});

test("the message shape is exact", () => {
  assert.deepEqual(assertParticipantAdmissionMessage(message()), message());
  const rejected: readonly unknown[] = [
    null,
    "a string",
    [message()],
    { ...message(), extra: 1 },
    { ...message(), role: "PARTICIPANT_C" },
    { ...message(), participantWallet: "not-an-address" },
    { ...message(), activeFrom: -1 },
    { ...message(), activeFrom: 420, activeUntil: 120 },
    { ...message(), authorizationNonce: "0x1234" },
    { ...message(), issuedAt: 1_785_000_000, expiresAt: 1_785_000_000 },
  ];
  for (const candidate of rejected) {
    assert.throws(
      () => assertParticipantAdmissionMessage(candidate),
      ParticipantAuthorizationError,
      `expected a refusal for ${JSON.stringify(candidate)?.slice(0, 60)}`,
    );
  }
});

test("an authorization longer than the bounded lifetime is refused", () => {
  const issuedAt = 1_785_000_000;
  assert.throws(
    () => assertParticipantAdmissionMessage(message({
      issuedAt,
      expiresAt: issuedAt + PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS + 1,
    })),
    ParticipantAuthorizationError,
  );
});

test("a wallet signature over the exact digest is admitted", async () => {
  const authorized = message();
  const digest = participantAdmissionDigest(authorized);
  const verified = await verifyParticipantAuthorization(
    authorized,
    SIGNATURE,
    expected(),
    walletVerifier([digest]),
  );
  assert.equal(verified.message.role, "PARTICIPANT_A");
  assert.equal(verified.message.participantWallet.toLowerCase(), WALLET.toLowerCase());
  assert.equal(verified.authorizationDigest, digest);
});

test("a signature the wallet does not own is refused", async () => {
  const authorized = message();
  const error = await refusal(verifyParticipantAuthorization(
    authorized,
    SIGNATURE,
    expected(),
    // The wallet rejects every digest, which is what a forged signature looks like.
    walletVerifier([]),
  ));
  assert.equal(error.status >= 400, true);
});

test("role, case, asset and service substitutions are refused", async () => {
  const cases: ReadonlyArray<readonly [string, ParticipantAdmissionMessage, Record<string, unknown>]> = [
    ["role", message({ role: "PARTICIPANT_B" }), {}],
    ["case", message({ runId: "5fac6616-1a89-4234-a1fa-1e1046782fb4" }), {}],
    ["fhe case", message({ fheCaseId: digestToBytes32(`sha256:${"9".repeat(64)}`) }), {}],
    ["binding", message({ protectionBindingDigest: digestToBytes32(`sha256:${"9".repeat(64)}`) }), {}],
    ["asset", message({ assetIdentityDigest: digestToBytes32(`sha256:${"9".repeat(64)}`) }), {}],
    ["service", message({ verifyingService: "https://other.example" }), {}],
  ];
  for (const [label, candidate, overrides] of cases) {
    const digest = participantAdmissionDigest(candidate);
    const error = await refusal(verifyParticipantAuthorization(
      candidate,
      SIGNATURE,
      expected(overrides),
      // Even a perfectly valid wallet signature must not rescue a substituted field.
      walletVerifier([digest]),
    ));
    assert.ok(error.status >= 400, `${label} substitution must be refused`);
  }
});

test("an expired authorization is refused even with a valid signature", async () => {
  const authorized = message();
  const digest = participantAdmissionDigest(authorized);
  const error = await refusal(verifyParticipantAuthorization(
    authorized,
    SIGNATURE,
    expected({ now: authorized.expiresAt + 1 }),
    walletVerifier([digest]),
  ));
  assert.ok(error.status >= 400);
});

test("a malformed signature never reaches the wallet", async () => {
  let consulted = false;
  const spy = async () => {
    consulted = true;
    return true;
  };
  for (const signature of ["", "0x", "not-hex", "0xabc", 42, null, `0x${"ab".repeat(4_000)}`]) {
    await refusal(verifyParticipantAuthorization(message(), signature, expected(), spy));
  }
  assert.equal(consulted, false, "a malformed signature must be refused before any wallet call");
});
