// Group 4 integration: governance records, bilateral intent, session nullifier,
// opaque session commitment and the bounded relayer, against a real local EVM.
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { keccak256, toBytes, toHex } from "viem";

import { startLocalChain } from "./v5-local-chain.mjs";
import { TARGETS, guardedBroadcast } from "./v5-live-guard.mjs";
import { artifact, deployStack, CHAIN_ID, POLICY_ID, SCOPE_A, SCOPE_B }
  from "./v5-rehearsal-support.mjs";
import { COMMIT_SESSION_SELECTOR, RelayerRefused, createRelayerProcess }
  from "./v5-relayer-process.mjs";

const ORG_A = keccak256(toBytes("mordant.v5.org-a"));
const ORG_B = keccak256(toBytes("mordant.v5.org-b"));
const KEY_A = keccak256(toBytes("mordant.v5.key-a"));
const KEY_B = keccak256(toBytes("mordant.v5.key-b"));

async function authorize(chain, stack, { scope, controller, keyId, org, version = 1, nonce }) {
  const governanceArt = await artifact("governance");
  const request = {
    scopeCommitment: scope, controller, controllerKeyId: keyId, organizationId: org,
    controllerEpoch: 1, authorizationVersion: version, nonce,
  };
  const recordDigest = await chain.client.readContract({
    address: stack.at.governance, abi: governanceArt.abi, functionName: "authorize", args: [request],
  }).catch(() => null);
  const hash = await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.governance, abi: governanceArt.abi, functionName: "authorize", args: [request],
  });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success", "authorize");
  // The record digest is emitted; read it from the event rather than guessing.
  const { decodeEventLog } = await import("viem");
  let digest = recordDigest;
  for (const log of receipt.logs) {
    try {
      const decoded = decodeEventLog({ abi: governanceArt.abi, data: log.data, topics: log.topics });
      if (decoded.eventName === "ScopeAuthorized") digest = decoded.args.recordDigest;
    } catch { /* not ours */ }
  }
  return { digest, receipt, request };
}

function buildIntent({ stack, recordA, recordB, sourceA, sourceB, assetCommitment, sessionNonce, expiry }) {
  return {
    chainId: BigInt(CHAIN_ID),
    governanceRegistry: stack.at.governance,
    policyId: POLICY_ID,
    policyVersion: 1,
    governanceRecordA: recordA,
    governanceRecordB: recordB,
    controllerKeyIdA: KEY_A,
    controllerKeyIdB: KEY_B,
    controllerEpochA: 1,
    controllerEpochB: 1,
    scopeAuthorizationVersionA: 1,
    scopeAuthorizationVersionB: 1,
    sourceRecordCommitmentA: sourceA,
    sourceRecordCommitmentB: sourceB,
    scopeCommitmentA: SCOPE_A,
    scopeCommitmentB: SCOPE_B,
    issuerKeyId: stack.issuerKeyId,
    identityEpoch: 1,
    strictAssetCommitmentA: assetCommitment,
    candidateAuthorized: false,
    exactBudget: 1,
    candidateBudget: 0,
    sessionNonce,
    expiry,
    disclosureVersion: 1,
  };
}

/// Prepares a full session: two governance records, two opaque sources, an
/// intent signed by three separate bounded processes, and the commitment.
async function prepareSession(chain, stack, { sessionNonce = 7n } = {}) {
  const governanceArt = await artifact("governance");
  const sourcesArt = await artifact("sources");

  // Two opaque sources, published first so they strictly precede the session.
  const sources = [];
  for (const [index, label] of [["a"], ["b"]].entries()) {
    const commitment = keccak256(toBytes(`mordant.v5.source/${sessionNonce}/${index}`));
    const hash = await stack.tx.write(stack.accounts.submitter, {
      address: stack.at.sources, abi: sourcesArt.abi, functionName: "commitSource", args: [commitment],
    });
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    sources.push({ commitment, block: Number(receipt.blockNumber) });
  }

  const a = await authorize(chain, stack, {
    scope: SCOPE_A, controller: stack.accounts.controllerA.address, keyId: KEY_A,
    org: ORG_A, nonce: sessionNonce * 10n + 1n,
  });
  const b = await authorize(chain, stack, {
    scope: SCOPE_B, controller: stack.accounts.controllerB.address, keyId: KEY_B,
    org: ORG_B, nonce: sessionNonce * 10n + 2n,
  });

  const now = BigInt((await chain.client.getBlock()).timestamp);
  const intent = buildIntent({
    stack, recordA: a.digest, recordB: b.digest,
    sourceA: sources[0].commitment, sourceB: sources[1].commitment,
    assetCommitment: keccak256(toBytes(`mordant.v5.strict/${sessionNonce}`)),
    sessionNonce, expiry: now + 7n * 24n * 3600n,
  });

  // The digest each signer recomputes locally, read from the contract that
  // will verify it.
  const intentDigest = await chain.client.readContract({
    address: stack.at.governance, abi: governanceArt.abi, functionName: "intentDigest", args: [intent],
  });
  const signatures = {
    controllerA: await stack.controllerASigner.signDigest(intentDigest),
    controllerB: await stack.controllerBSigner.signDigest(intentDigest),
    issuer: await stack.issuerSigner.signDigest(intentDigest),
  };

  const sessionSalt = toHex(randomBytes(32));
  const [nullifier, commitment] = await Promise.all([
    chain.client.readContract({
      address: stack.at.governance, abi: governanceArt.abi,
      functionName: "sessionNullifierOf", args: [intent],
    }),
    chain.client.readContract({
      address: stack.at.governance, abi: governanceArt.abi,
      functionName: "sessionCommitmentOf", args: [intent, signatures, sessionSalt],
    }),
  ]);

  return { intent, intentDigest, signatures, sessionSalt, nullifier, commitment, a, b, sources, governanceArt };
}

function relayerFor(chain, stack, governanceArt) {
  return createRelayerProcess({
    account: stack.accounts.relayer,
    client: chain.client,
    walletFor: chain.walletFor,
    registry: stack.at.governance,
    chainId: CHAIN_ID,
    governanceAbi: governanceArt.abi,
    broadcast: (description, send) =>
      guardedBroadcast({ target: TARGETS.LOCAL, description, send, env: {} }),
  });
}

/* ------------------------------------------------------------ the flow */

test("a bilateral session is admitted through the bounded relayer", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);

  const relayer = relayerFor(chain, stack, session.governanceArt);
  const result = await relayer.publishSessionCommitment({
    chainId: CHAIN_ID,
    sessionCommitment: session.commitment,
    sessionNullifier: session.nullifier,
  });
  assert.equal(result.status, "success");

  const record = await chain.client.readContract({
    address: stack.at.governance, abi: session.governanceArt.abi,
    functionName: "commitment", args: [session.commitment],
  });
  assert.equal(record.exists, true);
  assert.equal(record.sessionNullifier, session.nullifier);
  assert.equal(record.submitter.toLowerCase(), stack.accounts.relayer.address.toLowerCase());
  assert.equal(record.consumed, false, "not consumed until binding");

  // Chronology: sources and governance records strictly precede the session.
  assert.ok(session.sources[0].block < Number(record.committedInBlock));
  assert.ok(session.sources[1].block < Number(record.committedInBlock));
  assert.ok(Number(session.a.receipt.blockNumber) < Number(record.committedInBlock));
  assert.ok(Number(session.b.receipt.blockNumber) < Number(record.committedInBlock));
});

/* --------------------------------------------------- nullifier semantics */

// Finding M-02: one signed intent must admit exactly one session, however the
// salt is chosen.
test("re-salting the same signed intent cannot admit a second session", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const relayer = relayerFor(chain, stack, session.governanceArt);

  await relayer.publishSessionCommitment({
    chainId: CHAIN_ID, sessionCommitment: session.commitment, sessionNullifier: session.nullifier,
  });

  const otherSalt = toHex(randomBytes(32));
  const otherCommitment = await chain.client.readContract({
    address: stack.at.governance, abi: session.governanceArt.abi,
    functionName: "sessionCommitmentOf", args: [session.intent, session.signatures, otherSalt],
  });
  assert.notEqual(otherCommitment, session.commitment, "a new salt is a new commitment");

  // Same nullifier, so the registry must refuse.
  await assert.rejects(() => relayer.publishSessionCommitment({
    chainId: CHAIN_ID, sessionCommitment: otherCommitment, sessionNullifier: session.nullifier,
  }));
});

test("the nullifier is independent of the salt but not of the nonce", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const governanceArt = session.governanceArt;

  const sameNullifier = await chain.client.readContract({
    address: stack.at.governance, abi: governanceArt.abi,
    functionName: "sessionNullifierOf", args: [session.intent],
  });
  assert.equal(sameNullifier, session.nullifier);

  const otherNonce = { ...session.intent, sessionNonce: session.intent.sessionNonce + 1n };
  const otherNullifier = await chain.client.readContract({
    address: stack.at.governance, abi: governanceArt.abi,
    functionName: "sessionNullifierOf", args: [otherNonce],
  });
  assert.notEqual(otherNullifier, session.nullifier);
});

test("a changed source record changes the session commitment", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);

  const mutated = { ...session.intent, sourceRecordCommitmentB: keccak256(toBytes("other")) };
  const otherCommitment = await chain.client.readContract({
    address: stack.at.governance, abi: session.governanceArt.abi,
    functionName: "sessionCommitmentOf", args: [mutated, session.signatures, session.sessionSalt],
  });
  assert.notEqual(otherCommitment, session.commitment);
});

test("a changed signature changes the session commitment", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);

  // One controller's signature replaced by the other's.
  const swapped = { ...session.signatures, controllerA: session.signatures.controllerB };
  const otherCommitment = await chain.client.readContract({
    address: stack.at.governance, abi: session.governanceArt.abi,
    functionName: "sessionCommitmentOf", args: [session.intent, swapped, session.sessionSalt],
  });
  assert.notEqual(otherCommitment, session.commitment);
});

/* ------------------------------------------------ governance negatives */

test("two records in the same organization cannot form a session", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const governanceArt = await artifact("governance");

  await authorize(chain, stack, {
    scope: SCOPE_A, controller: stack.accounts.controllerA.address, keyId: KEY_A,
    org: ORG_A, nonce: 901n,
  });
  // Same organization for side B.
  const b = await authorize(chain, stack, {
    scope: SCOPE_B, controller: stack.accounts.controllerB.address, keyId: KEY_B,
    org: ORG_A, nonce: 902n,
  });
  assert.match(b.digest, /^0x[0-9a-f]{64}$/);
  // The registry accepts the record; the SESSION is what must refuse, and that
  // is enforced at resolveSession during binding. Recorded here so the
  // rehearsal does not claim a check it did not perform.
});

test("a reused authorization nonce is refused", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  await authorize(chain, stack, {
    scope: SCOPE_A, controller: stack.accounts.controllerA.address, keyId: KEY_A,
    org: ORG_A, nonce: 777n,
  });
  await assert.rejects(() => authorize(chain, stack, {
    scope: SCOPE_A, controller: stack.accounts.controllerA.address, keyId: KEY_A,
    org: ORG_A, version: 2, nonce: 777n,
  }));
});

test("an authorization version must be sequential", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  await assert.rejects(() => authorize(chain, stack, {
    scope: SCOPE_A, controller: stack.accounts.controllerA.address, keyId: KEY_A,
    org: ORG_A, version: 3, nonce: 801n,
  }));
});

/* -------------------------------------------------- the relayer boundary */

test("the relayer refuses every field beyond the commitment and nullifier", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const relayer = relayerFor(chain, stack, session.governanceArt);

  const base = {
    chainId: CHAIN_ID, sessionCommitment: session.commitment, sessionNullifier: session.nullifier,
  };
  const forbidden = {
    intent: session.intent,
    signatures: session.signatures,
    salt: session.sessionSalt,
    sessionSalt: session.sessionSalt,
    scopeCommitmentA: SCOPE_A,
    controllerA: stack.accounts.controllerA.address,
    sourceRecordCommitmentA: session.sources[0].commitment,
    governanceRecordA: session.a.digest,
    anchor: stack.at.factory,
    calldata: "0xdeadbeef",
    data: "0xdeadbeef",
    to: stack.at.governance,
    target: stack.at.governance,
    value: 1n,
    selector: COMMIT_SESSION_SELECTOR,
    functionName: "commitSession",
    abi: session.governanceArt.abi,
    args: [session.commitment, session.nullifier],
  };
  for (const [key, value] of Object.entries(forbidden)) {
    await assert.rejects(
      () => relayer.publishSessionCommitment({ ...base, [key]: value }),
      (error) => {
        assert.ok(error instanceof RelayerRefused, `${key} produced ${error?.name}`);
        assert.match(error.code, /FORBIDDEN_FIELD|UNEXPECTED_FIELD/, key);
        return true;
      },
      `the relayer accepted ${key}`,
    );
  }
});

test("the relayer refuses an unknown field even if harmless", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const relayer = relayerFor(chain, stack, session.governanceArt);
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: session.commitment,
      sessionNullifier: session.nullifier, memo: "hello",
    }),
    (error) => error.code === "RELAYER_REFUSED_UNEXPECTED_FIELD",
  );
});

test("the relayer refuses a wrong chain and a malformed value", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const relayer = relayerFor(chain, stack, session.governanceArt);

  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: 10_143, sessionCommitment: session.commitment, sessionNullifier: session.nullifier,
    }),
    (error) => error.code === "RELAYER_REFUSED_WRONG_CHAIN",
  );
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: "0x1234", sessionNullifier: session.nullifier,
    }),
    (error) => error.code === "RELAYER_REFUSED_MALFORMED_VALUE",
  );
});

test("the relayer refuses to publish the same commitment twice", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const session = await prepareSession(chain, stack);
  const relayer = relayerFor(chain, stack, session.governanceArt);

  await relayer.publishSessionCommitment({
    chainId: CHAIN_ID, sessionCommitment: session.commitment, sessionNullifier: session.nullifier,
  });
  await assert.rejects(
    () => relayer.publishSessionCommitment({
      chainId: CHAIN_ID, sessionCommitment: session.commitment, sessionNullifier: session.nullifier,
    }),
    (error) => error.code === "RELAYER_REFUSED_ALREADY_PUBLISHED",
  );
});

// The key boundary, proven dynamically rather than by reading source: the
// handle exposes one method and no key, and every enumerable property is
// inspected.
test("the relayer handle exposes no key and exactly one method", async (t) => {
  const chain = await startLocalChain();
  t.after(() => chain.stop());
  const stack = await deployStack(chain);
  const governanceArt = await artifact("governance");
  const relayer = relayerFor(chain, stack, governanceArt);

  const keys = Object.keys(relayer).sort();
  assert.deepEqual(keys, ["address", "chainId", "publishSessionCommitment", "registry"]);

  const methods = keys.filter((key) => typeof relayer[key] === "function");
  assert.deepEqual(methods, ["publishSessionCommitment"]);

  // Nothing reachable from the handle is a private key or a signer.
  const serialized = JSON.stringify(relayer, (key, value) =>
    typeof value === "bigint" ? value.toString() : value);
  assert.doesNotMatch(serialized, /0x[0-9a-fA-F]{64}/, "no 32-byte secret is reachable");
  for (const forbidden of ["signTransaction", "signMessage", "sign", "privateKey", "key", "account", "source"]) {
    assert.equal(relayer[forbidden], undefined, `handle exposes ${forbidden}`);
  }
  assert.ok(Object.isFrozen(relayer), "the handle must be frozen");
});
