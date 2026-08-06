import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { recoverAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import type { CustomSupervisedProtectionView } from "./custom-supervised-view";
import {
  CASE_CODE_PATTERN,
  admissionAbandoned,
  admissionProgress,
  admitParticipantRole,
  bindCaseCode,
  generateCaseCode,
  readAdmission,
  resolveCaseCode,
  type ParticipantAdmissionRecord,
} from "./participant-admission-store";
import {
  admitParticipant,
  assertAdmissionRequest,
  participantAdmissionChallenge,
  participantLifecycle,
  readParticipantCase,
  type AdmissionDependencies,
  type AdmissionOrchestrator,
  type ApassVerdict,
} from "./participant-admission-service";
import {
  participantAdmissionTypedData,
  type ParticipantAdmissionMessage,
  type ParticipantRole,
  type TypedDataVerifier,
} from "./participant-authorization";

const CHAIN_ID = 10_143;
const RUN_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const SERVICE = "https://mordant.example";
const FHE_CASE_ID = `sha256:${"a".repeat(64)}` as const;
const BINDING_DIGEST = `sha256:${"b".repeat(64)}` as const;
const ASSET_DIGEST = `sha256:${"c".repeat(64)}` as const;
const NOW = 1_800_000_000;

const accountA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const accountB = privateKeyToAccount(`0x${"22".repeat(32)}`);
const accountC = privateKeyToAccount(`0x${"33".repeat(32)}`);

function temporaryRoot(): string {
  return mkdtempSync(join(tmpdir(), "mordant-admission-"));
}

function record(overrides: Partial<Omit<ParticipantAdmissionRecord, "schemaVersion">> = {}) {
  return {
    runId: RUN_ID,
    role: "PARTICIPANT_A" as ParticipantRole,
    participantWallet: accountA.address,
    authorizationDigest: `0x${"1".repeat(64)}` as const,
    claimCommitment: `0x${"2".repeat(64)}` as const,
    authorizationNonce: `0x${"3".repeat(64)}` as const,
    issuedAt: NOW - 10,
    expiresAt: NOW + 600,
    eligibilityBlock: 12_345,
    admittedAtUnix: NOW,
    ...overrides,
  };
}

function throwsCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (error: unknown) => {
    assert.equal((error as { code?: string }).code, code);
    return true;
  });
}

async function rejectsCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.equal((error as { code?: string }).code, code);
    return true;
  });
}

// ------------------------------------------------------------------ case codes

test("a case code is unambiguous and resolves to exactly one run", () => {
  const root = temporaryRoot();
  try {
    const code = generateCaseCode();
    assert.match(code, CASE_CODE_PATTERN);
    // No I, L, O or U, so a transcribed code cannot land on a different case.
    assert.equal(/[ILOU]/u.test(code), false);
    bindCaseCode(root, code, RUN_ID);
    assert.equal(resolveCaseCode(root, code), RUN_ID);
    assert.equal(resolveCaseCode(root, generateCaseCode()), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rebinding a code to the same run is idempotent, to another run is refused", () => {
  const root = temporaryRoot();
  try {
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    assert.doesNotThrow(() => bindCaseCode(root, code, RUN_ID));
    throwsCode(() => bindCaseCode(root, code, "3f2504e0-4f89-11d3-9a0c-0305e82c3302"), "CASE_CODE_TAKEN");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ ledger

test("a role is admitted create-only and an exact retry is idempotent", () => {
  const root = temporaryRoot();
  try {
    const first = admitParticipantRole(root, record());
    assert.equal(first.admitted, true);
    const retry = admitParticipantRole(root, record());
    assert.equal(retry.admitted, false);
    assert.deepEqual(retry.record, first.record);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a different authorization cannot overwrite an admitted role", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record());
    throwsCode(
      () => admitParticipantRole(root, record({ authorizationDigest: `0x${"9".repeat(64)}` })),
      "ROLE_OCCUPIED",
    );
    throwsCode(
      () => admitParticipantRole(root, record({ claimCommitment: `0x${"9".repeat(64)}` })),
      "ROLE_OCCUPIED",
    );
    // The original survives untouched.
    assert.equal(readAdmission(root, RUN_ID, "PARTICIPANT_A")?.authorizationDigest, `0x${"1".repeat(64)}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A cannot overwrite B and B cannot overwrite A", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record({ role: "PARTICIPANT_A", participantWallet: accountA.address }));
    admitParticipantRole(root, record({
      role: "PARTICIPANT_B",
      participantWallet: accountB.address,
      authorizationNonce: `0x${"4".repeat(64)}`,
      authorizationDigest: `0x${"5".repeat(64)}`,
    }));
    assert.equal(readAdmission(root, RUN_ID, "PARTICIPANT_A")?.participantWallet, accountA.address);
    assert.equal(readAdmission(root, RUN_ID, "PARTICIPANT_B")?.participantWallet, accountB.address);
    assert.equal(admissionProgress(root, RUN_ID).bothAdmitted, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the same wallet cannot occupy both roles", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record({ role: "PARTICIPANT_A" }));
    throwsCode(
      () => admitParticipantRole(root, record({
        role: "PARTICIPANT_B",
        authorizationNonce: `0x${"4".repeat(64)}`,
        authorizationDigest: `0x${"5".repeat(64)}`,
      })),
      "DUPLICATE_SIGNER",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a nonce cannot be replayed into the other role", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record({ role: "PARTICIPANT_A" }));
    throwsCode(
      () => admitParticipantRole(root, record({
        role: "PARTICIPANT_B",
        participantWallet: accountB.address,
        authorizationDigest: `0x${"5".repeat(64)}`,
      })),
      "NONCE_REPLAY",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("admission and nonce consumption are one durable object", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record());
    const files = readdirSync(join(root, RUN_ID, "admissions"));
    // One write, one file: there is no interval where a nonce is spent but no
    // role admitted, or a role admitted under an unclaimed nonce.
    assert.deepEqual(files, ["participant_a.json"]);
    const stored = JSON.parse(readFileSync(join(root, RUN_ID, "admissions", "participant_a.json"), "utf8"));
    assert.equal(stored.authorizationNonce, `0x${"3".repeat(64)}`);
    assert.equal(stored.eligibilityBlock, 12_345);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the ledger never stores a claim interval", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record());
    const raw = readFileSync(join(root, RUN_ID, "admissions", "participant_a.json"), "utf8");
    for (const forbidden of ["activeFrom", "activeUntil", "claim\"", "pledge"]) {
      assert.equal(raw.includes(forbidden), false, `${forbidden} must not reach the ledger`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("abandonment is reported, never enacted", () => {
  const root = temporaryRoot();
  try {
    admitParticipantRole(root, record({ role: "PARTICIPANT_A" }));
    assert.equal(admissionAbandoned(root, RUN_ID, NOW, NOW + 10, 1_800), false);
    assert.equal(admissionAbandoned(root, RUN_ID, NOW, NOW + 3_600, 1_800), true);
    // Nothing was deleted by asking.
    assert.notEqual(readAdmission(root, RUN_ID, "PARTICIPANT_A"), null);
    // A complete pair never abandons.
    admitParticipantRole(root, record({
      role: "PARTICIPANT_B",
      participantWallet: accountB.address,
      authorizationNonce: `0x${"4".repeat(64)}`,
      authorizationDigest: `0x${"5".repeat(64)}`,
    }));
    assert.equal(admissionAbandoned(root, RUN_ID, NOW, NOW + 3_600, 1_800), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ lifecycle

test("the lifecycle projects the engine stage plus the ledger", () => {
  const none = { participantA: false, participantB: false, bothAdmitted: false, wallets: { participantA: null, participantB: null } };
  const onlyA = { ...none, participantA: true };
  const both = { participantA: true, participantB: true, bothAdmitted: true, wallets: { participantA: null, participantB: null } };
  assert.equal(participantLifecycle("CASE_CREATED", none, false), "CASE_CREATED_NEUTRAL");
  assert.equal(participantLifecycle("MATCH_PREPARED", none, false), "MATCH_PREPARED");
  assert.equal(participantLifecycle("MATCH_PREPARED", onlyA, false), "PARTICIPANT_A_ADMITTED");
  assert.equal(participantLifecycle("PARTICIPANT_A_SUBMITTED", onlyA, false), "PARTICIPANT_A_ADMITTED");
  assert.equal(participantLifecycle("PARTICIPANT_A_SUBMITTED", both, false), "PARTICIPANT_B_ADMITTED");
  assert.equal(participantLifecycle("PARTICIPANT_B_SUBMITTED", both, false), "SUBMISSIONS_FINALIZED");
  assert.equal(participantLifecycle("EVALUATED", both, false), "EVALUATED");
  assert.equal(participantLifecycle("RELEASED", both, false), "RELEASED");
  assert.equal(participantLifecycle("MATCH_PREPARED", onlyA, true), "ABANDONED");
});

// ------------------------------------------------------------------ service

type Calls = { admitted: string[]; submitted: string[]; apass: string[] };

function view(stage: string): CustomSupervisedProtectionView {
  return {
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: RUN_ID,
    executionVariant: "CUSTOM_SUPERVISED",
    stage,
    nextOperation: null,
    terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: ASSET_DIGEST,
      fheCaseId: FHE_CASE_ID,
      incidentState: "PRIVATE_MATCH_OPEN",
      recourseState: "NOT_OPEN",
      cureDeadline: null,
    },
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null,
    governedResult: null,
    recourse: null,
    receipt: null,
  } as CustomSupervisedProtectionView;
}

/**
 * EOA-only test double for the injected verifier. Production uses
 * `publicClient.verifyHash`, which also answers for deployed ERC-1271 accounts;
 * nothing here exercises that, and nothing claims it does.
 */
const eoaVerifier: TypedDataVerifier = async ({ address, digest, signature }) => {
  const recovered = await recoverAddress({ hash: digest, signature });
  return recovered.toLowerCase() === address.toLowerCase();
};

function harness(root: string, options: Partial<{ apass: (wallet: string) => Promise<ApassVerdict> }> = {}) {
  const calls: Calls = { admitted: [], submitted: [], apass: [] };
  const stage = { value: "MATCH_PREPARED" };
  const orchestrator: AdmissionOrchestrator = {
    createNeutralParticipantCase: async () => ({ runId: RUN_ID }),
    readCustomSupervisedCase: async () => view(stage.value),
    readParticipantAdmissionContext: async () => ({
      runId: RUN_ID,
      stage: stage.value as never,
      fheCaseId: FHE_CASE_ID,
      assetIdentityDigest: ASSET_DIGEST,
      protectionBindingDigest: BINDING_DIGEST,
    }),
    preparePrivateMatch: async () => undefined,
    admitParticipantClaim: async (_runId, role) => { calls.admitted.push(role); return undefined; },
    submitParticipantPledge: async (_runId, role) => {
      calls.submitted.push(role);
      stage.value = role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_SUBMITTED";
      return undefined;
    },
  };
  const dependencies: AdmissionDependencies = {
    orchestrator,
    runRoot: root,
    verifyingService: SERVICE,
    chainId: CHAIN_ID,
    verifyApass: options.apass ?? (async (wallet) => {
      calls.apass.push(wallet);
      return { eligible: true, holderAddress: wallet, observedBlock: 9_001 };
    }),
    verifyTypedData: eoaVerifier,
    now: () => NOW,
  };
  return { dependencies, calls, stage };
}

async function signedRequest(
  caseCode: string,
  role: ParticipantRole,
  account: typeof accountA,
  claim: { activeFrom: number; activeUntil: number },
  overrides: Partial<ParticipantAdmissionMessage> = {},
) {
  const authorization: ParticipantAdmissionMessage = {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: `0x${"a".repeat(64)}`,
    protectionBindingDigest: `0x${"b".repeat(64)}`,
    assetIdentityDigest: `0x${"c".repeat(64)}`,
    role,
    activeFrom: claim.activeFrom,
    activeUntil: claim.activeUntil,
    participantWallet: account.address,
    authorizationNonce: `0x${role === "PARTICIPANT_A" ? "3" : "4"}${"0".repeat(63)}`,
    issuedAt: NOW - 10,
    expiresAt: NOW + 600,
    ...overrides,
  } as ParticipantAdmissionMessage;
  const typedData = participantAdmissionTypedData(authorization, CHAIN_ID);
  const signature = await account.signTypedData({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
  });
  return { caseCode, role, authorization, signature, claim };
}

test("two distinct wallets each admit and submit only their own role", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies, calls } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);

    const a = await admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW);
    assert.equal(a.newlyAdmitted, true);
    assert.equal(a.participantWallet, accountA.address);
    assert.equal(a.eligibilityBlock, 9_001);
    assert.deepEqual(calls.submitted, ["PARTICIPANT_A"]);
    assert.equal(a.admission.lifecycle, "PARTICIPANT_A_ADMITTED");
    assert.equal(a.admission.bothAdmitted, false);

    const b = await admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_B", accountB, { activeFrom: 200, activeUntil: 500 }), NOW);
    assert.equal(b.newlyAdmitted, true);
    assert.deepEqual(calls.submitted, ["PARTICIPANT_A", "PARTICIPANT_B"]);
    assert.equal(b.admission.bothAdmitted, true);
    assert.equal(b.admission.participantA.wallet, accountA.address);
    assert.equal(b.admission.participantB.wallet, accountB.address);
    // The compliance policy was asked about each wallet independently.
    assert.deepEqual(calls.apass, [accountA.address, accountB.address]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("no outcome is exposed before governed release", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    const a = await admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW);
    assert.equal(a.view.governedResult, null);
    assert.equal(a.view.terminalScenario, null);
    const encoded = JSON.stringify(a);
    for (const forbidden of ["activeFrom", "activeUntil", "conflict\":", "no-conflict"]) {
      assert.equal(encoded.includes(forbidden), false, `${forbidden} must not appear in an admission result`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a wallet the policy refuses is never admitted", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies, calls } = harness(root, {
      apass: async (wallet) => ({ eligible: false, holderAddress: wallet, observedBlock: 9_001 }),
    });
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    await rejectsCode(
      admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW),
      "APASS_DENIED",
    );
    assert.deepEqual(calls.submitted, []);
    assert.equal(readAdmission(root, RUN_ID, "PARTICIPANT_A"), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a lost response is recovered by an exact retry without a second admission", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies, calls } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    const request = await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 });
    const first = await admitParticipant(dependencies, request, NOW);
    const retry = await admitParticipant(dependencies, request, NOW);
    assert.equal(first.newlyAdmitted, true);
    assert.equal(retry.newlyAdmitted, false);
    assert.equal(retry.participantWallet, first.participantWallet);
    // The role was admitted once; the engine's own submission stays idempotent.
    assert.deepEqual(calls.admitted, ["PARTICIPANT_A", "PARTICIPANT_A"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a changed claim under a fresh signature cannot take an occupied role", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    await admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW);
    await rejectsCode(
      admitParticipant(
        dependencies,
        await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 900 }, {
          authorizationNonce: `0x${"7".repeat(64)}`,
        }),
        NOW,
      ),
      "ROLE_OCCUPIED",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the same wallet is refused the second role through the service", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    await admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW);
    await rejectsCode(
      admitParticipant(dependencies, await signedRequest(code, "PARTICIPANT_B", accountA, { activeFrom: 200, activeUntil: 500 }), NOW),
      "DUPLICATE_SIGNER",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an abandoned case admits nobody", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    await rejectsCode(
      admitParticipant(
        dependencies,
        await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }),
        NOW - 100_000,
      ),
      "CASE_ABANDONED",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an unknown case code admits nobody", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    await rejectsCode(
      admitParticipant(dependencies, await signedRequest(generateCaseCode(), "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 }), NOW),
      "UNKNOWN_CASE",
    );
    await rejectsCode(readParticipantCase(dependencies, generateCaseCode()), "UNKNOWN_CASE");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the admission body is exact", () => {
  const base = { caseCode: "X", role: "PARTICIPANT_A", authorization: {}, signature: "0x", claim: {} };
  assert.doesNotThrow(() => assertAdmissionRequest(base));
  throwsCode(() => assertAdmissionRequest({ ...base, extra: 1 }), "BODY_MEMBERS");
  throwsCode(() => assertAdmissionRequest({ ...base, role: "PARTICIPANT_C" }), "ROLE");
  throwsCode(() => assertAdmissionRequest([base]), "BODY_SHAPE");
});

test("the challenge is server-issued and carries no operator input", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    const challenge = await participantAdmissionChallenge(
      dependencies, code, "PARTICIPANT_A", accountC.address, { activeFrom: 100, activeUntil: 400 },
    );
    assert.equal(challenge.primaryType, "ParticipantAdmissionV1");
    assert.equal(challenge.domain.chainId, CHAIN_ID);
    assert.equal(challenge.message.runId, RUN_ID);
    assert.equal(challenge.message.participantWallet, accountC.address);
    assert.match(challenge.message.authorizationNonce as string, /^0x[0-9a-f]{64}$/u);
    assert.equal(challenge.message.expiresAt, (challenge.message.issuedAt as number) + 600);
    // Two challenges never share a nonce.
    const second = await participantAdmissionChallenge(
      dependencies, code, "PARTICIPANT_A", accountC.address, { activeFrom: 100, activeUntil: 400 },
    );
    assert.notEqual(challenge.message.authorizationNonce, second.message.authorizationNonce);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a malformed claim is refused before any signature work", async () => {
  const root = temporaryRoot();
  try {
    const { dependencies } = harness(root);
    const code = generateCaseCode();
    bindCaseCode(root, code, RUN_ID);
    const request = await signedRequest(code, "PARTICIPANT_A", accountA, { activeFrom: 100, activeUntil: 400 });
    await rejectsCode(
      admitParticipant(dependencies, { ...request, claim: { activeFrom: 400, activeUntil: 100 } }, NOW),
      "PLEDGE_WINDOW_ORDER",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
