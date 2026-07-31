#!/usr/bin/env node

// One validator signer process holding exactly one EIP-712 key.
//
// The Monad runner holds no validator key. It sends each signer the V3 result
// fields, and the signer recomputes the EIP-712 result digest and the
// attestation digest itself before signing. A signer never signs an opaque hash
// handed to it, and it refuses anything outside the chain, verifier and policy
// scope it was started with.
//
// Requests are authenticated with an HMAC over the exact body using a per-signer
// token the orchestrator provisions, and the listener is bound to loopback. That
// is lab-grade authentication, not an organizational trust boundary.

import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress, hashTypedData, keccak256, encodeAbiParameters, isAddress } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";

const HERE = dirname(fileURLToPath(import.meta.url));

export const EIP712_NAME = "Mordant Confidential Policy";
export const EIP712_VERSION = "3";

// The V3 result and attestation types, mirrored from the deployed verifier.
export const RESULT_TYPES = {
  ConfidentialPolicyResultV3: [
    { name: "chainId", type: "uint256" },
    { name: "consumer", type: "address" },
    { name: "vault", type: "address" },
    { name: "policyId", type: "bytes32" },
    { name: "policyVersion", type: "uint32" },
    { name: "inputCommitmentA", type: "bytes32" },
    { name: "inputCommitmentB", type: "bytes32" },
    { name: "conflictConfirmed", type: "bool" },
    { name: "nonce", type: "uint256" },
    { name: "validUntil", type: "uint64" },
    { name: "providerProofCommitment", type: "bytes32" },
    { name: "resultCommitment", type: "bytes32" },
  ],
};

export const ATTESTATION_TYPES = {
  ConfidentialPolicyAttestation: [
    { name: "validatorSetId", type: "bytes32" },
    { name: "resultDigest", type: "bytes32" },
  ],
};

export const RESULT_CORE_TYPEHASH = keccak256(
  new TextEncoder().encode(
    "ConfidentialPolicyResultV3Core(uint256 chainId,address consumer,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)",
  ),
);

// resultCoreCommitment recomputes what the verifier recomputes on-chain, so a
// signer can confirm the supplied resultCommitment is the honest one for these
// fields rather than trusting the runner.
export function resultCoreCommitment(result) {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" },
        { type: "bytes32" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" },
        { type: "bool" }, { type: "uint256" }, { type: "uint64" }, { type: "bytes32" },
      ],
      [
        RESULT_CORE_TYPEHASH, BigInt(result.chainId), getAddress(result.consumer), getAddress(result.vault),
        result.policyId, Number(result.policyVersion), result.inputCommitmentA, result.inputCommitmentB,
        Boolean(result.conflictConfirmed), BigInt(result.nonce), BigInt(result.validUntil),
        result.providerProofCommitment,
      ],
    ),
  );
}

export function digestsFor({ chainId, verifier, validatorSetId, result }) {
  const domain = { name: EIP712_NAME, version: EIP712_VERSION, chainId: Number(chainId), verifyingContract: getAddress(verifier) };
  const message = {
    chainId: BigInt(result.chainId),
    consumer: getAddress(result.consumer),
    vault: getAddress(result.vault),
    policyId: result.policyId,
    policyVersion: Number(result.policyVersion),
    inputCommitmentA: result.inputCommitmentA,
    inputCommitmentB: result.inputCommitmentB,
    conflictConfirmed: Boolean(result.conflictConfirmed),
    nonce: BigInt(result.nonce),
    validUntil: BigInt(result.validUntil),
    providerProofCommitment: result.providerProofCommitment,
    resultCommitment: result.resultCommitment,
  };
  const resultDigest = hashTypedData({ domain, types: RESULT_TYPES, primaryType: "ConfidentialPolicyResultV3", message });
  const attestationDigest = hashTypedData({
    domain, types: ATTESTATION_TYPES, primaryType: "ConfidentialPolicyAttestation",
    message: { validatorSetId, resultDigest },
  });
  return { resultDigest, attestationDigest };
}

/* ------------------------------------------------------------------ identity */

export async function generateIdentity(storage) {
  await mkdir(storage, { recursive: true, mode: 0o700 });
  const key = generatePrivateKey();
  const account = privateKeyToAccount(key);
  const keyPath = resolve(storage, "validator.key");
  await writeFile(keyPath, key, { mode: 0o600, flag: "wx" });
  await chmod(keyPath, 0o600);
  await writeFile(resolve(storage, "validator.address"), `${account.address}\n`, { mode: 0o644, flag: "wx" });
  const token = randomBytes(32).toString("hex");
  const tokenPath = resolve(storage, "runner.token");
  await writeFile(tokenPath, token, { mode: 0o600, flag: "wx" });
  await chmod(tokenPath, 0o600);
  return { address: account.address, tokenPath };
}

/* --------------------------------------------------------------------- serve */

export function authenticate(token, body, presented) {
  const expected = createHmac("sha256", token).update(body).digest();
  let supplied;
  try { supplied = Buffer.from(String(presented ?? ""), "hex"); } catch { return false; }
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export async function serve(options) {
  const key = (await readFile(resolve(options.storage, "validator.key"), "utf8")).trim();
  const token = (await readFile(resolve(options.storage, "runner.token"), "utf8")).trim();
  const account = privateKeyToAccount(key);

  const server = createServer((request, response) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 256 * 1024) { request.destroy(); return; }
      chunks.push(chunk);
    });
    request.on("end", async () => {
      const body = Buffer.concat(chunks);
      const reply = (status, value) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(`${JSON.stringify(value)}\n`);
      };
      if (request.url === "/v1/status" && request.method === "GET") {
        return reply(200, { address: account.address, holdsOwnKeyOnly: true, scope: { chainId: options.chainId, verifier: options.verifier } });
      }
      if (request.url !== "/v1/sign" || request.method !== "POST") return reply(404, { error: "not found" });
      if (!authenticate(token, body, request.headers["x-signer-auth"])) {
        return reply(401, { error: "unauthenticated" });
      }
      let payload;
      try { payload = JSON.parse(body.toString("utf8")); } catch { return reply(400, { error: "invalid body" }); }
      const verdict = review(payload, options);
      if (verdict) return reply(403, { error: verdict });
      const { resultDigest, attestationDigest } = digestsFor(payload);
      // The signer confirms the runner's resultCommitment is the honest
      // recomputation for these fields before it attests to anything.
      const recomputed = resultCoreCommitment(payload.result);
      if (recomputed.toLowerCase() !== String(payload.result.resultCommitment).toLowerCase()) {
        return reply(422, { error: "result commitment does not match the supplied fields" });
      }
      const signature = await account.signTypedData({
        domain: { name: EIP712_NAME, version: EIP712_VERSION, chainId: Number(payload.chainId), verifyingContract: getAddress(payload.verifier) },
        types: ATTESTATION_TYPES,
        primaryType: "ConfidentialPolicyAttestation",
        message: { validatorSetId: payload.validatorSetId, resultDigest },
      });
      return reply(200, { address: account.address, resultDigest, attestationDigest, signature });
    });
  });
  await new Promise((done) => server.listen(options.port, "127.0.0.1", done));
  return { server, address: account.address, port: server.address().port };
}

// review enforces the scope this signer was started with. A signer will not
// attest outside its chain, its verifier, or for a non-conflict result.
export function review(payload, options) {
  if (!payload || typeof payload !== "object") return "malformed request";
  if (Number(payload.chainId) !== Number(options.chainId)) return "chain out of scope";
  if (!isAddress(String(payload.verifier)) || getAddress(payload.verifier) !== getAddress(options.verifier)) {
    return "verifier out of scope";
  }
  const result = payload.result;
  if (!result || typeof result !== "object") return "missing result";
  if (Number(result.chainId) !== Number(options.chainId)) return "result chain out of scope";
  if (!result.conflictConfirmed) return "refusing to attest a non-conflict result";
  if (options.policyId && String(result.policyId).toLowerCase() !== String(options.policyId).toLowerCase()) {
    return "policy out of scope";
  }
  if (options.consumer && getAddress(result.consumer) !== getAddress(options.consumer)) {
    return "consumer out of scope";
  }
  if (options.vault && getAddress(result.vault) !== getAddress(options.vault)) {
    return "receivable anchor out of scope";
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(payload.validatorSetId ?? ""))) return "invalid validator set";
  return null;
}

function parseArgs(argv) {
  const options = { mode: "serve", storage: null, port: 0, chainId: 0, verifier: null, policyId: null, consumer: null, vault: null };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const next = argv[index + 1];
    if (flag === "--mode" && next) { options.mode = argv[++index]; continue; }
    if (flag === "--storage" && next) { options.storage = resolve(argv[++index]); continue; }
    if (flag === "--port" && next) { options.port = Number(argv[++index]); continue; }
    if (flag === "--chain-id" && next) { options.chainId = Number(argv[++index]); continue; }
    if (flag === "--verifier" && next) { options.verifier = argv[++index]; continue; }
    if (flag === "--policy-id" && next) { options.policyId = argv[++index]; continue; }
    if (flag === "--consumer" && next) { options.consumer = argv[++index]; continue; }
    if (flag === "--vault" && next) { options.vault = argv[++index]; continue; }
  }
  if (!options.storage) throw new Error("SIGNER_STORAGE_REQUIRED");
  return options;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const options = parseArgs(process.argv.slice(2));
  if (options.mode === "identity") {
    const { address } = await generateIdentity(options.storage);
    process.stdout.write(`${address}\n`);
  } else {
    if (!options.chainId || !options.verifier) throw new Error("SIGNER_SCOPE_REQUIRED");
    const { address, port } = await serve(options);
    process.stdout.write(`${JSON.stringify({ ready: true, address, port })}\n`);
  }
}
