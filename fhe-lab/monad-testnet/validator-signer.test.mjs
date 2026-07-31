import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { getAddress, recoverTypedDataAddress } from "viem";
import {
  generateIdentity, serve, review, digestsFor, resultCoreCommitment,
  authenticate, ATTESTATION_TYPES, EIP712_NAME, EIP712_VERSION,
} from "./validator-signer.mjs";

const CHAIN = 10143;
const VERIFIER = "0x7F1271D43B0E41e2eeDDD5290f459fDc6196a19a";
const CONSUMER = "0xB23A3C3492B9BA83D80C8abc9A5484d2885f058A";
const VAULT = "0x317689100AcBE3b86B0869D522D0D8579Cfed7F1";
const POLICY = "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540";
const SET_ID = "0xe0f67ba07afcbe0bcb66bc0bf947160a9f84598f7497a33bbbca283ded7a1e2b";

function baseResult(overrides = {}) {
  const result = {
    chainId: CHAIN, consumer: CONSUMER, vault: VAULT, policyId: POLICY, policyVersion: 1,
    inputCommitmentA: `0x${"11".repeat(32)}`,
    inputCommitmentB: `0x${"22".repeat(32)}`,
    conflictConfirmed: true, nonce: "4281141463025089708", validUntil: 1785515992,
    providerProofCommitment: `0x${"33".repeat(32)}`,
    resultCommitment: "0x",
    ...overrides,
  };
  result.resultCommitment = resultCoreCommitment(result);
  return result;
}

async function startSigner(extra = {}) {
  const storage = await mkdtemp(join(tmpdir(), "mordant-signer-"));
  const { address } = await generateIdentity(storage);
  const options = { storage, port: 0, chainId: CHAIN, verifier: VERIFIER, policyId: POLICY, consumer: CONSUMER, vault: VAULT, ...extra };
  const { server, port } = await serve(options);
  const token = (await readFile(join(storage, "runner.token"), "utf8")).trim();
  return { storage, address, server, port, token, options };
}

async function call(port, token, payload) {
  const body = JSON.stringify(payload);
  const response = await fetch(`http://127.0.0.1:${port}/v1/sign`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-signer-auth": createHmac("sha256", token).update(body).digest("hex"),
    },
    body,
  });
  return { status: response.status, body: await response.json() };
}

test("resultCoreCommitment matches the verifier's on-chain recomputation", async () => {
  // These are the exact field values of the retained V3 atomic transaction, and
  // the commitment the deployed verifier recomputed for them.
  const result = {
    chainId: 10143,
    consumer: "0xB23A3C3492B9BA83D80C8abc9A5484d2885f058A",
    vault: "0x7531d467F19d1055AcCF6B0D22286184f87adBd8",
    policyId: "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540",
    policyVersion: 1,
    inputCommitmentA: "0x9e29fbc7cc0c6d520317cbec7d78a3f2bac41688e9a3a1437beed3f9dc466ade",
    inputCommitmentB: "0xa90f6dbbb0a17a09a3c0affa85b60f9cfc698cba3cefdbb9ecdab3c06ad7ed48",
    conflictConfirmed: true,
    nonce: "4281141463025089708",
    validUntil: 1785515992,
    providerProofCommitment: "0x4c8f515cde12d64722110813a59a7d5ee0e43f9ff91d740f5206fe0d74d475f1",
  };
  assert.equal(
    resultCoreCommitment(result).toLowerCase(),
    "0xed0331636a42748e4b1889c4bf69788bd641b6243f0f1e2cace8daa3dbf1ca0b",
  );
});

test("attestation digest matches the verifier's on-chain attestationDigest", async () => {
  const result = {
    chainId: 10143,
    consumer: "0xB23A3C3492B9BA83D80C8abc9A5484d2885f058A",
    vault: "0x7531d467F19d1055AcCF6B0D22286184f87adBd8",
    policyId: "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540",
    policyVersion: 1,
    inputCommitmentA: "0x9e29fbc7cc0c6d520317cbec7d78a3f2bac41688e9a3a1437beed3f9dc466ade",
    inputCommitmentB: "0xa90f6dbbb0a17a09a3c0affa85b60f9cfc698cba3cefdbb9ecdab3c06ad7ed48",
    conflictConfirmed: true,
    nonce: "4281141463025089708",
    validUntil: 1785515992,
    providerProofCommitment: "0x4c8f515cde12d64722110813a59a7d5ee0e43f9ff91d740f5206fe0d74d475f1",
    resultCommitment: "0xed0331636a42748e4b1889c4bf69788bd641b6243f0f1e2cace8daa3dbf1ca0b",
  };
  const { resultDigest, attestationDigest } = digestsFor({
    chainId: 10143, verifier: "0x7F1271D43B0E41e2eeDDD5290f459fDc6196a19a",
    validatorSetId: SET_ID, result,
  });
  // Both values were read from the deployed verifier by eth_call.
  assert.equal(resultDigest.toLowerCase(), "0xd879a2580d1ef2992a2e79e7190d66307988eca13c8b94a5049cd3da0e096828");
  assert.equal(attestationDigest.toLowerCase(), "0xbe3db3290f9de6eed3f1bf9cfd37c7928ec5b2fa38c16df54d8ca05709c6605d");
});

test("a signer signs its own recomputed digest and the signature recovers to its address", async (t) => {
  const signer = await startSigner();
  t.after(() => signer.server.close());
  const result = baseResult();
  const { status, body } = await call(signer.port, signer.token, {
    chainId: CHAIN, verifier: VERIFIER, validatorSetId: SET_ID, result,
  });
  assert.equal(status, 200);
  assert.equal(getAddress(body.address), getAddress(signer.address));
  const recovered = await recoverTypedDataAddress({
    domain: { name: EIP712_NAME, version: EIP712_VERSION, chainId: CHAIN, verifyingContract: getAddress(VERIFIER) },
    types: ATTESTATION_TYPES,
    primaryType: "ConfidentialPolicyAttestation",
    message: { validatorSetId: SET_ID, resultDigest: body.resultDigest },
    signature: body.signature,
  });
  assert.equal(getAddress(recovered), getAddress(signer.address));
});

test("a signer refuses a result whose commitment does not match its fields", async (t) => {
  const signer = await startSigner();
  t.after(() => signer.server.close());
  const result = baseResult();
  result.resultCommitment = `0x${"ff".repeat(32)}`;
  const { status, body } = await call(signer.port, signer.token, {
    chainId: CHAIN, verifier: VERIFIER, validatorSetId: SET_ID, result,
  });
  assert.equal(status, 422);
  assert.match(body.error, /result commitment/);
});

test("a signer refuses everything outside its declared scope", async (t) => {
  const signer = await startSigner();
  t.after(() => signer.server.close());
  const cases = [
    ["chain", { chainId: 1 }],
    ["verifier", { verifier: "0x0000000000000000000000000000000000000009" }],
  ];
  for (const [label, override] of cases) {
    const { status } = await call(signer.port, signer.token, {
      chainId: CHAIN, verifier: VERIFIER, validatorSetId: SET_ID, result: baseResult(), ...override,
    });
    assert.equal(status, 403, `${label} should be out of scope`);
  }
  for (const [label, override] of [
    ["non-conflict", { conflictConfirmed: false }],
    ["other consumer", { consumer: "0x0000000000000000000000000000000000000004" }],
    ["other anchor", { vault: "0x0000000000000000000000000000000000000005" }],
  ]) {
    const { status } = await call(signer.port, signer.token, {
      chainId: CHAIN, verifier: VERIFIER, validatorSetId: SET_ID, result: baseResult(override),
    });
    assert.equal(status, 403, `${label} should be refused`);
  }
});

test("an unauthenticated or tampered request is refused", async (t) => {
  const signer = await startSigner();
  t.after(() => signer.server.close());
  const body = JSON.stringify({ chainId: CHAIN, verifier: VERIFIER, validatorSetId: SET_ID, result: baseResult() });
  const unauthenticated = await fetch(`http://127.0.0.1:${signer.port}/v1/sign`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  assert.equal(unauthenticated.status, 401);

  const wrongToken = await fetch(`http://127.0.0.1:${signer.port}/v1/sign`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-signer-auth": createHmac("sha256", "wrong").update(body).digest("hex") },
    body,
  });
  assert.equal(wrongToken.status, 401);
  assert.equal(authenticate("t", Buffer.from("a"), "00"), false);
});

test("each signer process exposes only its own address", async (t) => {
  const first = await startSigner();
  const second = await startSigner();
  t.after(() => { first.server.close(); second.server.close(); });
  assert.notEqual(first.address, second.address);
  for (const signer of [first, second]) {
    const response = await fetch(`http://127.0.0.1:${signer.port}/v1/status`);
    const status = await response.json();
    assert.equal(getAddress(status.address), getAddress(signer.address));
    assert.equal(status.holdsOwnKeyOnly, true);
    // A signer's storage holds exactly one validator key.
    const key = await readFile(join(signer.storage, "validator.key"), "utf8");
    assert.match(key.trim(), /^0x[0-9a-f]{64}$/);
  }
});

test("review rejects a malformed validator set id", () => {
  const verdict = review(
    { chainId: CHAIN, verifier: VERIFIER, validatorSetId: "0xabc", result: baseResult() },
    { chainId: CHAIN, verifier: VERIFIER },
  );
  assert.match(verdict, /validator set/);
});
