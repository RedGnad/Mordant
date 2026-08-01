#!/usr/bin/env node

// One V4 validator signer process holding exactly one EIP-712 key.
//
// Separate from the V3 validator signer, which stays untouched: the V4 verifier
// has its own domain, its own result core and an opaque session commitment the
// V3 schema knows nothing about.
//
// The runner holds no validator key. It sends each signer the V4 envelope
// fields, and the signer independently recomputes the result core commitment,
// the result digest and the attestation digest before signing. A signer never
// signs an opaque hash handed to it.
//
// It also verifies, against the chain, that the session commitment it is being
// asked to attest already existed on-chain. That is the ordering guarantee the
// quorum is responsible for: the commitment demonstrably came first.

import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, defineChain, http, getAddress, isAddress, encodeFunctionData, hexToBigInt } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { resultCoreCommitment, resultDigest, attestationDigest, assertCanonicalSignature } from "../shared/identity/v4-digests.mjs";

const bytes32 = (value) => typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);

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
  return { address: account.address };
}

export function authenticate(token, body, presented) {
  const expected = createHmac("sha256", token).update(body).digest();
  let supplied;
  try { supplied = Buffer.from(String(presented ?? ""), "hex"); } catch { return false; }
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

// review enforces the scope this signer was started with. It refuses anything
// that is not a coherent, bindable exact match inside its chain, verifier,
// binder and policy.
export function review(payload, options) {
  if (!payload || typeof payload !== "object") return "malformed request";
  if (Number(payload.chainId) !== Number(options.chainId)) return "chain out of scope";
  if (!isAddress(String(payload.verifier)) || getAddress(payload.verifier) !== getAddress(options.verifier)) {
    return "verifier out of scope";
  }
  const envelope = payload.envelope;
  if (!envelope || typeof envelope !== "object") return "missing envelope";
  if (Number(envelope.chainId) !== Number(options.chainId)) return "envelope chain out of scope";
  if (getAddress(envelope.binder) !== getAddress(options.binder)) return "binder out of scope";
  if (String(envelope.policyId).toLowerCase() !== String(options.policyId).toLowerCase()) {
    return "policy out of scope";
  }
  if (!bytes32(envelope.sessionCommitment)) return "invalid session commitment";
  const result = envelope.result;
  if (!result || typeof result !== "object") return "missing result";
  // The session IS its commitment. A result naming anything else is refused.
  if (String(result.sessionId).toLowerCase() !== String(envelope.sessionCommitment).toLowerCase()) {
    return "result is not bound to its session commitment";
  }
  if (Number(result.outcome) !== 1) return "refusing to attest a non exact-match outcome";
  if (result.exactMatchConfirmed !== true) return "refusing to attest an unconfirmed match";
  if (result.candidateMatchSuggested === true) return "refusing to attest a candidate result";
  if (result.conflictConfirmed !== true) return "refusing to attest a non-conflict result";
  if (Number(result.anchorCount) !== 2) return "refusing an anchor count other than two";
  if (!bytes32(result.providerProofCommitment) || hexToBigInt(result.providerProofCommitment) === 0n) {
    return "missing provider proof commitment";
  }
  if (!bytes32(result.matchCommitment) || hexToBigInt(result.matchCommitment) === 0n) {
    return "missing match commitment";
  }
  if (String(result.inputCommitmentA).toLowerCase() === String(result.inputCommitmentB).toLowerCase()) {
    return "refusing a self match";
  }
  if (!bytes32(payload.validatorSetId)) return "invalid validator set";
  if (Number(envelope.validUntil) <= Math.floor(Date.now() / 1000)) return "result already expired";
  return null;
}

export async function serve(options) {
  const key = (await readFile(resolve(options.storage, "validator.key"), "utf8")).trim();
  const token = (await readFile(resolve(options.storage, "runner.token"), "utf8")).trim();
  const account = privateKeyToAccount(key);
  const chain = defineChain({
    id: options.chainId, name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [options.rpc] } },
  });
  const client = createPublicClient({ chain, transport: http(options.rpc) });

  // committedAt(bytes32) on the governance registry. Reading it directly keeps
  // the ordering check inside the signer rather than in the runner's report.
  const committedAt = async (sessionCommitment) => {
    const data = encodeFunctionData({
      abi: [{
        type: "function", name: "committedAt", stateMutability: "view",
        inputs: [{ type: "bytes32" }], outputs: [{ type: "uint64" }],
      }],
      args: [sessionCommitment],
    });
    const { data: raw } = await client.call({ to: getAddress(options.governance), data });
    return hexToBigInt(raw ?? "0x0");
  };

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
        return reply(200, {
          address: account.address, holdsOwnKeyOnly: true,
          scope: { chainId: options.chainId, verifier: options.verifier, binder: options.binder },
        });
      }
      if (request.url !== "/v1/sign" || request.method !== "POST") return reply(404, { error: "not found" });
      if (!authenticate(token, body, request.headers["x-signer-auth"])) {
        return reply(401, { error: "unauthenticated" });
      }
      let payload;
      try { payload = JSON.parse(body.toString("utf8")); } catch { return reply(400, { error: "invalid body" }); }
      const verdict = review(payload, options);
      if (verdict) return reply(403, { error: verdict });
      try {
        // The commitment must already be on-chain. Without this the quorum would
        // be attesting an ordering it never checked.
        const at = await committedAt(payload.envelope.sessionCommitment);
        if (at === 0n) return reply(422, { error: "session commitment is not published on-chain" });

        const core = resultCoreCommitment(payload.envelope);
        if (core.toLowerCase() !== String(payload.envelope.resultCommitment).toLowerCase()) {
          return reply(422, { error: "result commitment does not match the supplied fields" });
        }
        const digest = resultDigest(payload.envelope, payload.chainId, payload.verifier);
        const attestation = attestationDigest({
          validatorSetId: payload.validatorSetId, resultHash: digest,
          chainId: payload.chainId, verifier: payload.verifier,
        });
        const signature = await account.sign({ hash: attestation });
        assertCanonicalSignature(signature, "validator");
        return reply(200, {
          address: account.address, resultCoreCommitment: core, resultDigest: digest,
          attestationDigest: attestation, sessionCommittedAt: String(at), signature,
        });
      } catch (error) {
        return reply(500, { error: String(error?.message ?? error) });
      }
    });
  });
  await new Promise((done) => server.listen(options.port, "127.0.0.1", done));
  return { server, address: account.address, port: server.address().port };
}

export function parseArgs(argv) {
  const options = {
    mode: "serve", storage: null, port: 0, chainId: 0,
    verifier: null, binder: null, policyId: null, governance: null, rpc: null,
  };
  const flags = {
    "--mode": "mode", "--storage": "storage", "--port": "port", "--chain-id": "chainId",
    "--verifier": "verifier", "--binder": "binder", "--policy-id": "policyId",
    "--governance": "governance", "--rpc": "rpc",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const field = flags[argv[index]];
    if (field && argv[index + 1] !== undefined) {
      const value = argv[++index];
      options[field] = field === "port" || field === "chainId" ? Number(value) : value;
    }
  }
  if (!options.storage) throw new Error("VALIDATOR_STORAGE_REQUIRED");
  options.storage = resolve(options.storage);
  return options;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const options = parseArgs(process.argv.slice(2));
  if (options.mode === "identity") {
    const { address } = await generateIdentity(options.storage);
    process.stdout.write(`${address}\n`);
  } else {
    if (!options.chainId || !options.verifier || !options.governance || !options.rpc) {
      throw new Error("VALIDATOR_SCOPE_REQUIRED");
    }
    const { address, port } = await serve(options);
    process.stdout.write(`${JSON.stringify({ ready: true, address, port })}\n`);
  }
}
