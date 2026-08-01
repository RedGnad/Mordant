// RC2 Run6 local rehearsal and recovery assertions.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toHex, keccak256, toBytes } from "viem";

import { Journal, JournalError, STATES } from "./v5-journal.mjs";
import { startLocalChain } from "./v5-local-chain.mjs";
import { artifact, deployStack, CHAIN_ID, localRunCapabilities } from "./v5-rehearsal-support.mjs";
import { RelayerRefused } from "./v5-relayer-process.mjs";
import { runAdmissionPipeline } from "./v5-journalized-runner.mjs";

const SOURCE_COMMIT = "4299d2c197289ab9e12902846ffb3b2b73a20bca";

async function newRun(t, label = "run6") {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const runRoot = await mkdtemp(join(tmpdir(), "mordant-run6-"));
  const journal = await Journal.open(join(runRoot, "journal.json"), {
    sourceCommit: SOURCE_COMMIT,
    chainId: CHAIN_ID,
  });
  const capabilities = localRunCapabilities(chain, stack);
  const context = {
    chainId: CHAIN_ID,
    chain,
    client: chain.client,
    journal,
    capabilities,
    label,
    privateRoot: join(runRoot, "private"),
    topology: {
      at: stack.at,
      roles: stack.roles,
      config: stack.config,
      issuerKeyId: stack.issuerKeyId,
    },
    participants: {
      controllerA: stack.accounts.controllerA.address,
      controllerB: stack.accounts.controllerB.address,
    },
  };
  return { chain, stack, runRoot, context };
}

async function issueExternalVaultAPass({ chain, stack, context }) {
  const eligibility = await artifact("eligibility");
  const vault = context.journal.stage("VAULT_CREATED").predictedVault;
  const hash = await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.eligibility,
    abi: eligibility.abi,
    functionName: "setIdentityValid",
    args: [vault, true],
  });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success", "separate authorized A-Pass issuer action");
}

async function completeToSession(t, label = "run6") {
  const run = await newRun(t, label);
  const paused = await runAdmissionPipeline(run.context);
  assert.equal(paused.at(-1).stage, "AWAITING_VAULT_APASS");
  assert.equal(paused.at(-1).awaitingExternal, true);
  assert.equal(run.context.journal.state("AWAITING_VAULT_APASS"), STATES.AWAITING_EXTERNAL);
  assert.deepEqual(
    Object.keys(run.context.journal.stage("AWAITING_VAULT_APASS").externalActionRequest).sort(),
    ["chainId", "minimumValidity", "requiredIdentityStatus", "vaultAddress"],
  );
  await issueExternalVaultAPass(run);
  await runAdmissionPipeline(run.context);
  assert.equal(run.context.journal.state("SESSION_COMMITTED"), STATES.CONFIRMED);
  return run;
}

test("journalized Run6 rehearsal pauses for A-Pass, resumes, and reaches SESSION_COMMITTED", async (t) => {
  const { context } = await completeToSession(t, "rehearsal");
  const sourceA = context.journal.stage("SOURCE_A_COMMITTED");
  const sourceB = context.journal.stage("SOURCE_B_COMMITTED");
  const session = context.journal.stage("SESSION_COMMITTED");

  assert.equal(sourceA.verified, true);
  assert.equal(sourceB.verified, true);
  assert.equal(session.verified, true);
  assert.ok(sourceA.receipt.blockNumber < session.verification.committedInBlock);
  assert.ok(sourceB.receipt.blockNumber < session.verification.committedInBlock);
});

test("the frozen nullifier survives salt variation, restart, and excludes a second publication", async (t) => {
  const { chain, context, runRoot } = await completeToSession(t, "restart");
  const prepared = context.journal.stage("SESSION_PREPARED");
  const governance = await artifact("governance");
  const intent = {
    ...prepared.canonicalIntent,
    chainId: BigInt(prepared.canonicalIntent.chainId),
    policyVersion: Number(prepared.canonicalIntent.policyVersion),
    controllerEpochA: Number(prepared.canonicalIntent.controllerEpochA),
    controllerEpochB: Number(prepared.canonicalIntent.controllerEpochB),
    scopeAuthorizationVersionA: Number(prepared.canonicalIntent.scopeAuthorizationVersionA),
    scopeAuthorizationVersionB: Number(prepared.canonicalIntent.scopeAuthorizationVersionB),
    identityEpoch: Number(prepared.canonicalIntent.identityEpoch),
    exactBudget: Number(prepared.canonicalIntent.exactBudget),
    candidateBudget: Number(prepared.canonicalIntent.candidateBudget),
    sessionNonce: BigInt(prepared.canonicalIntent.sessionNonce),
    expiry: BigInt(prepared.canonicalIntent.expiry),
    disclosureVersion: Number(prepared.canonicalIntent.disclosureVersion),
  };
  const changedSalt = toHex(new Uint8Array(32).fill(7));
  const [nullifier, changedCommitment] = await Promise.all([
    chain.client.readContract({
      address: context.topology.at.governance, abi: governance.abi, functionName: "sessionNullifierOf", args: [intent],
    }),
    chain.client.readContract({
      address: context.topology.at.governance, abi: governance.abi,
      functionName: "sessionCommitmentOf", args: [intent, prepared.signatures, changedSalt],
    }),
  ]);
  assert.equal(nullifier, prepared.sessionNullifier, "nullifier is independent of session salt");
  assert.notEqual(changedCommitment, prepared.sessionCommitment, "salt changes only the commitment");

  const relayer = await context.capabilities.relayer.handle();
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: changedCommitment, sessionNullifier: prepared.sessionNullifier,
    }),
    (error) => error instanceof RelayerRefused && error.code === "RELAYER_REFUSED_NULLIFIER_CONSUMED",
  );
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: prepared.sessionCommitment, sessionNullifier: prepared.sessionNullifier,
    }),
    (error) => error instanceof RelayerRefused && error.code === "RELAYER_REFUSED_ALREADY_PUBLISHED",
  );
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: prepared.sessionCommitment,
      sessionNullifier: keccak256(toBytes("substituted-nullifier")),
    }),
    (error) => error instanceof RelayerRefused && error.code === "RELAYER_REFUSED_ALREADY_PUBLISHED",
    "a commitment with a substituted nullifier must be rejected",
  );
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: prepared.sessionCommitment,
      sessionNullifier: prepared.sessionNullifier, intent: { forbidden: true },
    }),
    (error) => error instanceof RelayerRefused && error.code === "RELAYER_REFUSED_FORBIDDEN_FIELD",
  );
  const [record, consumed] = await Promise.all([
    chain.client.readContract({
      address: context.topology.at.governance, abi: governance.abi,
      functionName: "commitment", args: [prepared.sessionCommitment],
    }),
    chain.client.readContract({
      address: context.topology.at.governance, abi: governance.abi,
      functionName: "consumedNullifier", args: [prepared.sessionNullifier],
    }),
  ]);
  assert.equal(record.sessionNullifier, prepared.sessionNullifier);
  assert.equal(consumed, true);

  const reopened = await Journal.open(join(runRoot, "journal.json"), {
    sourceCommit: SOURCE_COMMIT,
    chainId: CHAIN_ID,
  });
  assert.equal(reopened.stage("SESSION_PREPARED").sessionCommitment, prepared.sessionCommitment);
  assert.equal(reopened.stage("SESSION_PREPARED").sessionNullifier, prepared.sessionNullifier);
  assert.equal(reopened.stage("SESSION_COMMITTED").sessionNullifier, prepared.sessionNullifier);
});

test("every completed Run6 handler boundary reopens from disk without changing prepared values", async (t) => {
  const run = await newRun(t, "boundaries");
  await runAdmissionPipeline(run.context);
  assert.equal(run.context.journal.state("AWAITING_VAULT_APASS"), STATES.AWAITING_EXTERNAL);

  // External issuance occurs after the request was durably persisted but before
  // the runner learns about it. Reopening is the only acknowledgement path.
  await issueExternalVaultAPass(run);
  run.context.journal = await Journal.open(join(run.runRoot, "journal.json"), {
    sourceCommit: SOURCE_COMMIT, chainId: CHAIN_ID,
  });

  const boundaries = [
    "VAULT_ACTIVATED", "SOURCE_A_COMMITTED", "SOURCE_B_COMMITTED", "GOVERNANCE_A_CREATED",
    "GOVERNANCE_B_CREATED", "SESSION_PREPARED", "SESSION_NULLIFIER_RESERVED", "SESSION_COMMITTED",
  ];
  const immutableSnapshots = new Map();
  for (const boundary of boundaries) {
    run.context.stopAfter = boundary;
    await runAdmissionPipeline(run.context);
    assert.equal(run.context.journal.state(boundary), STATES.CONFIRMED, boundary);
    const before = run.context.journal.stage(boundary);
    immutableSnapshots.set(boundary, {
      calldata: before.calldata,
      sourceSalt: before.sourceSalt,
      sessionNonce: before.sessionNonce,
      sessionNullifier: before.sessionNullifier,
      sessionSalt: before.sessionSalt,
      sessionCommitment: before.sessionCommitment,
      transactionHash: before.transactionHash,
    });
    run.context.journal = await Journal.open(join(run.runRoot, "journal.json"), {
      sourceCommit: SOURCE_COMMIT, chainId: CHAIN_ID,
    });
    // Re-executing the already-completed prefix must not request a signer,
    // reuse a relayer endpoint, or change a broadcast hash.
    await runAdmissionPipeline(run.context);
    const after = run.context.journal.stage(boundary);
    assert.deepEqual(
      {
        calldata: after.calldata,
        sourceSalt: after.sourceSalt,
        sessionNonce: after.sessionNonce,
        sessionNullifier: after.sessionNullifier,
        sessionSalt: after.sessionSalt,
        sessionCommitment: after.sessionCommitment,
        transactionHash: after.transactionHash,
      },
      immutableSnapshots.get(boundary),
      `${boundary} changed after restart`,
    );
  }
});

test("prepared session mutation and unknown nonce consumption fail closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-run6-journal-"));
  const path = join(root, "journal.json");
  const journal = await Journal.open(path, { sourceCommit: SOURCE_COMMIT, chainId: CHAIN_ID });
  const prefix = [
    "INITIALIZED", "FINAL_STACK_PLANNED", "FINAL_STACK_DEPLOYED", "BYTECODE_VERIFIED", "VAULT_CREATED",
    "AWAITING_VAULT_APASS", "VAULT_ACTIVATED", "SOURCE_A_COMMITTED", "SOURCE_B_COMMITTED",
    "GOVERNANCE_A_CREATED", "GOVERNANCE_B_CREATED",
  ];
  for (const stage of prefix) await journal.recordOffChain(stage, { synthetic: stage });
  const prepared = {
    canonicalIntentHash: keccak256(toBytes("intent")), sessionNonce: "8",
    sessionNullifier: keccak256(toBytes("nullifier")), sessionSalt: keccak256(toBytes("salt")),
    signatureBundleDigest: keccak256(toBytes("bundle")), sessionCommitment: keccak256(toBytes("commitment")),
    relayerRequestDigest: keccak256(toBytes("request")),
  };
  await journal.prepare("SESSION_PREPARED", prepared);
  await assert.rejects(
    () => journal.prepare("SESSION_PREPARED", { ...prepared, sessionNullifier: keccak256(toBytes("substituted")) }),
    (error) => error instanceof JournalError && error.code === "PREPARED_INPUT_DRIFT",
  );
  await journal.recordOffChain("SESSION_PREPARED", {});
  await journal.recordOffChain("SESSION_NULLIFIER_RESERVED", {});
  await journal.prepare("SESSION_COMMITTED", {
    sender: "0x1111111111111111111111111111111111111111", nonce: 2,
    sessionCommitment: prepared.sessionCommitment, sessionNullifier: prepared.sessionNullifier,
  });
  await journal.markBroadcast("SESSION_COMMITTED", "0xdeadbeef");
  await journal.reconcile({
    getTransactionReceipt: async () => null,
    getTransactionCount: async () => 3,
  });
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.AMBIGUOUS);
  assert.throws(() => journal.nextStage(), (error) => error.code === "AMBIGUOUS_STAGE");
});
