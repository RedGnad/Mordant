import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import type { Sha256Digest } from "./cleanverse-asset";
import {
  createProtectionOrchestrator,
  type ProtectionRuntimeOptions,
} from "./governed-fhe-product-server";
import { admitParticipantRole } from "./participant-admission-store";
import { participantClaimCommitment } from "./participant-authorization";
import { loadCanonicalRecourseConfiguration } from "./adapter-compatibility";
import { customSupervisedBindingDigestV2, type MordantCustomSupervisedBindingV2 } from "./custom-supervised-v2";

/**
 * What the two-wallet path has to be worth at the engine boundary.
 *
 * The unit tests prove the ledger and the signature refuse the wrong things. This
 * file proves the thing that actually matters to a participant: the interval THIS
 * wallet authorized, and no other, is the interval that reaches THIS role's private
 * pledge file and therefore the FHE client. Everything else is bookkeeping.
 */

function digest(byte: string): Sha256Digest {
  return `sha256:${byte.repeat(64)}`;
}

function argument(args: readonly string[], flag: string): string {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `expected ${flag}`);
  return String(args[index + 1]);
}

type Pledge = Readonly<{
  activeFrom: number;
  activeUntil: number;
  authorizationCommitment: string;
  privateMetadataCommitment: string;
}>;

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "mordant-admission-engine-"));
  /** Every pledge file the engine handed to the Go client, by role. */
  const pledges = new Map<string, Pledge>();
  const state = { finalized: false, submissionA: false, submissionB: false };

  const runner: NonNullable<ProtectionRuntimeOptions["binaryRunner"]> = async <T>(
    binary: string,
    args: readonly string[],
  ) => {
    if (binary === "inspect") {
      return {
        finalized: state.finalized,
        evaluationAdmission: false,
        releaseAdmission: false,
        foundationPrivateComplete: false,
        releasePrivateComplete: false,
        ambiguous: false,
        ...(state.submissionA ? { submissionA: { artifactDigest: digest("3"), ciphertextBytes: 2, artifactBytes: 3 } } : {}),
        ...(state.submissionB ? { submissionB: { artifactDigest: digest("4"), ciphertextBytes: 2, artifactBytes: 3 } } : {}),
      } as T;
    }
    const publicRoot = argument(args, "-public-root");
    mkdirSync(publicRoot, { recursive: true });
    if (binary === "keygen" && argument(args, "-mode") === "create") {
      const spec = JSON.parse(readFileSync(argument(args, "-spec"), "utf8")) as Record<string, unknown>;
      // The case spec is written before any participant exists. Nothing about a
      // private interval may appear in it.
      const encoded = JSON.stringify(spec);
      for (const forbidden of ["activeFrom", "activeUntil"]) {
        assert.equal(encoded.includes(forbidden), false, `${forbidden} must not reach the case spec`);
      }
      writeFileSync(join(publicRoot, "case-binding.json"), `${JSON.stringify({
        caseId: spec.caseId,
        assetIdentity: spec.assetIdentity,
        policyId: spec.policyId,
        releaseMode: "governed-decryptor-v1",
        parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
        circuitId: "mordant.identity-full-fhe-256",
      })}\n`);
      return {
        bindingDigest: digest("1"),
        protectionBindingDigest: customSupervisedBindingDigestV2(spec.protectionBinding as MordantCustomSupervisedBindingV2),
        durationNanos: 1,
        report: {},
      } as T;
    }
    if (binary === "keygen") {
      state.finalized = true;
      return { manifestDigest: digest("2") } as T;
    }
    if (binary === "client") {
      const role = argument(args, "-role");
      // Captured while the transient file still exists: this is exactly the
      // plaintext the Go participant client is about to read. Only the two
      // bounds are kept, because they are the only part a participant authors;
      // every other pledge field stays derived exactly as the fixture derives it.
      const written = JSON.parse(readFileSync(argument(args, "-pledge"), "utf8")) as Pledge;
      pledges.set(role, {
        activeFrom: written.activeFrom,
        activeUntil: written.activeUntil,
        authorizationCommitment: written.authorizationCommitment,
        privateMetadataCommitment: written.privateMetadataCommitment,
      });
      const binding = JSON.parse(readFileSync(join(publicRoot, "case-binding.json"), "utf8")) as Record<string, unknown>;
      writeFileSync(
        join(publicRoot, role === "PARTICIPANT_A" ? "submission-a.json" : "submission-b.json"),
        `${JSON.stringify({ caseId: binding.caseId, assetIdentity: binding.assetIdentity })}\n`,
      );
      if (role === "PARTICIPANT_A") state.submissionA = true; else state.submissionB = true;
      return { artifactDigest: role === "PARTICIPANT_A" ? digest("3") : digest("4"), durationNanos: 1, ciphertextBytes: 2, artifactBytes: 3 } as T;
    }
    throw new Error(`Unexpected fake binary ${binary}`);
  };

  const base: ProtectionRuntimeOptions = {
    runRoot: join(root, "runs"),
    binRoot: join(root, "bin"),
    importedEvidenceRoot: join(root, "retained"),
    binaryRunner: runner,
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    directParticipantAdmissionEnabled: true,
  };
  return { base, pledges, root };
}

const RUN_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const CANONICAL_PARTICIPANTS = loadCanonicalRecourseConfiguration().participants;

function admission(overrides: Record<string, unknown> = {}) {
  return {
    participantWallet: "0x911F99f424D47F08a15fcC771e94dcc2f7252B02",
    authorizationDigest: `0x${"1".repeat(64)}`,
    claimCommitment: `0x${"2".repeat(64)}`,
    authorizationNonce: `0x${"3".repeat(64)}`,
    chainId: 10_143,
    issuedAt: 1_785_000_000,
    expiresAt: 1_785_000_300,
    claim: { activeFrom: 120, activeUntil: 420 },
    ...overrides,
  };
}

function verifiedAdmission(
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  input = admission(),
) {
  return {
    ...input,
    participantWallet: role === "PARTICIPANT_A"
      ? CANONICAL_PARTICIPANTS.holderA
      : CANONICAL_PARTICIPANTS.holderB,
    claimCommitment: participantClaimCommitment({ runId: RUN_ID, role, claim: input.claim }),
  };
}

function writeVerifiedDurableAdmission(
  base: ProtectionRuntimeOptions,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  input = admission(),
) {
  const verified = verifiedAdmission(role, input);
  const { claim, ...durable } = verified;
  admitParticipantRole(base.runRoot!, {
    runId: RUN_ID,
    role,
    ...durable,
    participantWallet: durable.participantWallet as `0x${string}`,
    authorizationDigest: durable.authorizationDigest as `0x${string}`,
    claimCommitment: durable.claimCommitment as `0x${string}`,
    authorizationNonce: durable.authorizationNonce as `0x${string}`,
    eligibilityBlock: 1,
    admittedAtUnix: durable.issuedAt,
  });
  return verified;
}

async function admitVerified(
  orchestrator: ReturnType<typeof createProtectionOrchestrator>,
  base: ProtectionRuntimeOptions,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  input = admission(),
) {
  const verified = writeVerifiedDurableAdmission(base, role, input);
  return orchestrator.admitParticipantClaim(RUN_ID, role, verified);
}

test("a neutral case is created with no private input from anyone", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  const created = await orchestrator.createNeutralParticipantCase(RUN_ID);
  assert.equal(created.runId, RUN_ID);
  assert.equal(created.stage, "CASE_CREATED");
  const stored = readFileSync(join(base.runRoot!, RUN_ID, "execution.json"), "utf8");
  for (const forbidden of ["activeFrom", "activeUntil", "supervisedPledgeWindows", "admittedClaims"]) {
    assert.equal(stored.includes(forbidden), false, `${forbidden} must not exist at neutral creation`);
  }
});

test("direct participant admission is disabled unless the runtime explicitly enables it", async () => {
  const { base } = await harness();
  const disabled = createProtectionOrchestrator({ ...base, directParticipantAdmissionEnabled: false });
  await assert.rejects(disabled.createNeutralParticipantCase(RUN_ID), /disabled/u);
});

test("a neutral participant pledge fails closed without its verified durable admission", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await assert.rejects(
    orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A"),
    /verified durable admission/u,
  );
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", admission()),
    /verified durable admission/u,
  );
});

test("each role's own authorized interval reaches its own pledge file", async () => {
  const { base, pledges } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);

  await admitVerified(orchestrator, base, "PARTICIPANT_A", admission({
    claim: { activeFrom: 120, activeUntil: 420 },
  }));
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");

  await admitVerified(orchestrator, base, "PARTICIPANT_B", admission({
    participantWallet: "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0",
    authorizationDigest: `0x${"5".repeat(64)}`,
    authorizationNonce: `0x${"6".repeat(64)}`,
    claim: { activeFrom: 300, activeUntil: 900 },
  }));
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_B");

  // The whole point of the two-wallet path.
  assert.equal(pledges.get("PARTICIPANT_A")?.activeFrom, 120);
  assert.equal(pledges.get("PARTICIPANT_A")?.activeUntil, 420);
  assert.equal(pledges.get("PARTICIPANT_B")?.activeFrom, 300);
  assert.equal(pledges.get("PARTICIPANT_B")?.activeUntil, 900);
});

test("the fixed fixture defaults are never substituted for an admitted interval", async () => {
  const { base, pledges } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await admitVerified(orchestrator, base, "PARTICIPANT_A", admission({
    claim: { activeFrom: 7, activeUntil: 9 },
  }));
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  const written = pledges.get("PARTICIPANT_A");
  // 100/400 are the fixture values a non-admitted run would have used.
  assert.notEqual(written?.activeFrom, 100);
  assert.notEqual(written?.activeUntil, 400);
  assert.deepEqual({ activeFrom: written?.activeFrom, activeUntil: written?.activeUntil }, { activeFrom: 7, activeUntil: 9 });
});

test("the existing Go commitment fields carry the verified authorization and claim digests", async () => {
  const { base, pledges } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  const requested = admission({
    authorizationDigest: `0x${"a".repeat(64)}`,
  });
  const verified = verifiedAdmission("PARTICIPANT_A", requested);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await admitVerified(orchestrator, base, "PARTICIPANT_A", requested);
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  const pledge = pledges.get("PARTICIPANT_A");
  assert.equal(pledge?.authorizationCommitment, verified.authorizationDigest.slice(2));
  assert.equal(pledge?.privateMetadataCommitment, verified.claimCommitment.slice(2));
});

test("the engine rejects plaintext that no longer matches the verified durable claim commitment", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  const verified = writeVerifiedDurableAdmission(base, "PARTICIPANT_A", admission({
    claim: { activeFrom: 120, activeUntil: 420 },
  }));
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", {
      ...verified,
      claim: { activeFrom: 121, activeUntil: 420 },
    }),
    /durable admission does not match/u,
  );
});

test("the engine rejects a durable record that assigns the canonical role to another wallet", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  const wrong = {
    ...verifiedAdmission("PARTICIPANT_A", admission()),
    participantWallet: "0x911F99f424D47F08a15fcC771e94dcc2f7252B02",
  };
  const { claim, ...durable } = wrong;
  admitParticipantRole(base.runRoot!, {
    runId: RUN_ID,
    role: "PARTICIPANT_A",
    ...durable,
    participantWallet: durable.participantWallet as `0x${string}`,
    authorizationDigest: durable.authorizationDigest as `0x${string}`,
    claimCommitment: durable.claimCommitment as `0x${string}`,
    authorizationNonce: durable.authorizationNonce as `0x${string}`,
    eligibilityBlock: 1,
    admittedAtUnix: durable.issuedAt,
  });
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", wrong),
    /durable admission does not match/u,
  );
});

test("B cannot be admitted before A", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_B", admission()),
    /out of order/u,
  );
});

test("no role can be admitted before the case is prepared", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", admission()),
    /out of order/u,
  );
});

test("evaluation is refused while only one participant has submitted", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await admitVerified(orchestrator, base, "PARTICIPANT_A", admission());
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  await assert.rejects(
    orchestrator.evaluatePrivateConflict(RUN_ID),
    /Both encrypted submissions are required/u,
  );
});

test("an exact re-admission is idempotent and a different one is refused", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createNeutralParticipantCase(RUN_ID);
  await orchestrator.preparePrivateMatch(RUN_ID);
  await admitVerified(orchestrator, base, "PARTICIPANT_A", admission());
  // The lost-response retry.
  await orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", verifiedAdmission("PARTICIPANT_A", admission()));
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_A", admission({
      authorizationDigest: `0x${"9".repeat(64)}`,
      claim: { activeFrom: 1, activeUntil: 2 },
    })),
    /already been admitted/u,
  );
});

test("a restart after A carries A's interval and still accepts B", async () => {
  const { base, pledges } = await harness();
  await (async () => {
    const first = createProtectionOrchestrator(base);
    await first.createNeutralParticipantCase(RUN_ID);
    await first.preparePrivateMatch(RUN_ID);
    await admitVerified(first, base, "PARTICIPANT_A", admission({ claim: { activeFrom: 11, activeUntil: 22 } }));
    await first.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  })();
  // A fresh orchestrator, as after a container replacement.
  const restarted = createProtectionOrchestrator(base);
  const view = await restarted.readCustomSupervisedCase(RUN_ID);
  assert.equal(view.stage, "PARTICIPANT_A_SUBMITTED");
  await admitVerified(restarted, base, "PARTICIPANT_B", admission({
    participantWallet: "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0",
    authorizationDigest: `0x${"5".repeat(64)}`,
    authorizationNonce: `0x${"6".repeat(64)}`,
    claim: { activeFrom: 33, activeUntil: 44 },
  }));
  await restarted.submitParticipantPledge(RUN_ID, "PARTICIPANT_B");
  assert.deepEqual(
    { activeFrom: pledges.get("PARTICIPANT_A")?.activeFrom, activeUntil: pledges.get("PARTICIPANT_A")?.activeUntil },
    { activeFrom: 11, activeUntil: 22 },
  );
  assert.deepEqual(
    { activeFrom: pledges.get("PARTICIPANT_B")?.activeFrom, activeUntil: pledges.get("PARTICIPANT_B")?.activeUntil },
    { activeFrom: 33, activeUntil: 44 },
  );
});

test("a crash between admission and submission is completed by the retry", async () => {
  const { base, pledges } = await harness();
  const crashing = createProtectionOrchestrator({
    ...base,
    failpoint: (name) => {
      if (name === "after-submission-publication-before-unlink") throw new Error("INJECTED_CRASH");
    },
  });
  await crashing.createNeutralParticipantCase(RUN_ID);
  await crashing.preparePrivateMatch(RUN_ID);
  await admitVerified(crashing, base, "PARTICIPANT_A", admission({ claim: { activeFrom: 55, activeUntil: 66 } }));
  await assert.rejects(crashing.submitParticipantPledge(RUN_ID, "PARTICIPANT_A"), /INJECTED_CRASH/u);

  // The admission survived the crash, so the retry uses the same interval and
  // never asks the participant to sign again.
  const recovered = createProtectionOrchestrator(base);
  await recovered.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  assert.deepEqual(
    { activeFrom: pledges.get("PARTICIPANT_A")?.activeFrom, activeUntil: pledges.get("PARTICIPANT_A")?.activeUntil },
    { activeFrom: 55, activeUntil: 66 },
  );
});

test("an operator-window case is untouched by the admission path", async () => {
  const { base, pledges } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  await orchestrator.createProtectionCase("conflict", RUN_ID, {
    participantA: { activeFrom: 200, activeUntil: 500 },
    participantB: { activeFrom: 300, activeUntil: 700 },
  });
  await orchestrator.preparePrivateMatch(RUN_ID);
  await orchestrator.submitParticipantPledge(RUN_ID, "PARTICIPANT_A");
  assert.deepEqual(
    { activeFrom: pledges.get("PARTICIPANT_A")?.activeFrom, activeUntil: pledges.get("PARTICIPANT_A")?.activeUntil },
    { activeFrom: 200, activeUntil: 500 },
  );
  // And it refuses to be turned into a participant case midway.
  await assert.rejects(
    orchestrator.admitParticipantClaim(RUN_ID, "PARTICIPANT_B", admission()),
    /created with operator windows/u,
  );
});

test("the two creation paths stay separate on the public surface", async () => {
  const { base } = await harness();
  const orchestrator = createProtectionOrchestrator(base);
  // A neutral participant case is reached by its own entry point, which takes no
  // window argument at all. There is no way to ask for both at once.
  assert.equal(orchestrator.createNeutralParticipantCase.length, 0);
  const created = await orchestrator.createNeutralParticipantCase(RUN_ID);
  assert.equal(created.stage, "CASE_CREATED");
  // Replaying the same creation request is the lost-response retry, not a second case.
  assert.equal((await orchestrator.createNeutralParticipantCase(RUN_ID)).runId, created.runId);
});
