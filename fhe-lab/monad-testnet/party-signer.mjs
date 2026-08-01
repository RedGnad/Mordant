#!/usr/bin/env node

// One party process holding exactly one secp256k1 key.
//
// Four roles run this program, each in its own OS process and its own storage
// directory: controller A, controller B, the issuer, and the policy-authorized
// non-controller relayer. The runner holds none of their keys and can only ask
// them to act.
//
// Every signer RECOMPUTES the digest it is about to sign from structured fields.
// None of them will sign an opaque hash handed over by the runner, and each
// refuses anything outside the chain, registry and role scope it was started
// with. A controller additionally refuses to sign a disclosure consent whose
// governance record is not the one it was told it holds, which is what stops the
// runner from silently swapping the authority a consent is made under.
//
// Requests are authenticated with an HMAC over the exact body using a per-signer
// token, and the listener is bound to loopback. That is lab-grade process
// separation, not an organizational trust boundary.

import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress, isAddress, isHex } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import {
  intentDigest, consentDigest, sessionCommitment, signatureBundleDigest,
  sourceAttestationDigest, assertCanonicalSignature,
} from "../shared/identity/v4-digests.mjs";

export const ROLES = Object.freeze(["controller-a", "controller-b", "issuer", "relayer"]);

const bytes32 = (value) => typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);

/* ------------------------------------------------------------------ identity */

export async function generateIdentity(storage, role) {
  await mkdir(storage, { recursive: true, mode: 0o700 });
  const key = generatePrivateKey();
  const account = privateKeyToAccount(key);
  const keyPath = resolve(storage, "party.key");
  await writeFile(keyPath, key, { mode: 0o600, flag: "wx" });
  await chmod(keyPath, 0o600);
  await writeFile(resolve(storage, "party.address"), `${account.address}\n`, { mode: 0o644, flag: "wx" });
  await writeFile(resolve(storage, "party.role"), `${role}\n`, { mode: 0o644, flag: "wx" });
  const token = randomBytes(32).toString("hex");
  const tokenPath = resolve(storage, "runner.token");
  await writeFile(tokenPath, token, { mode: 0o600, flag: "wx" });
  await chmod(tokenPath, 0o600);
  return { address: account.address, role };
}

export function authenticate(token, body, presented) {
  const expected = createHmac("sha256", token).update(body).digest();
  let supplied;
  try { supplied = Buffer.from(String(presented ?? ""), "hex"); } catch { return false; }
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

/* -------------------------------------------------------------------- review */

/// Scope rules every request must satisfy, whatever the role.
export function reviewCommon(payload, options) {
  if (!payload || typeof payload !== "object") return "malformed request";
  if (Number(payload.chainId) !== Number(options.chainId)) return "chain out of scope";
  return null;
}

/// A controller or the issuer signing the bilateral session intent.
export function reviewIntent(payload, options) {
  const common = reviewCommon(payload, options);
  if (common) return common;
  const intent = payload.intent;
  if (!intent || typeof intent !== "object") return "missing intent";
  if (!isAddress(String(payload.governance)) || getAddress(payload.governance) !== getAddress(options.governance)) {
    return "governance registry out of scope";
  }
  if (getAddress(intent.governanceRegistry) !== getAddress(options.governance)) {
    return "intent names another registry";
  }
  if (Number(intent.chainId) !== Number(options.chainId)) return "intent chain out of scope";
  if (options.policyId && String(intent.policyId).toLowerCase() !== String(options.policyId).toLowerCase()) {
    return "policy out of scope";
  }
  // The tolerant path is never authorized in this deployment, and a controller
  // will not be talked into authorizing it by a runner that sets the flag.
  if (intent.candidateAuthorized) return "refusing to authorize the tolerant candidate path";
  if (Number(intent.disclosureVersion) !== 1) return "unsupported disclosure version";
  if (Number(intent.expiry) <= Math.floor(Date.now() / 1000)) return "intent already expired";
  // A controller only signs an intent that names the record it actually holds.
  if (options.role === "controller-a" && String(intent.governanceRecordA).toLowerCase() !== String(options.governanceRecord).toLowerCase()) {
    return "intent names another governance record for this side";
  }
  if (options.role === "controller-b" && String(intent.governanceRecordB).toLowerCase() !== String(options.governanceRecord).toLowerCase()) {
    return "intent names another governance record for this side";
  }
  return null;
}

/// A controller consenting to disclose one confirmed result.
export function reviewConsent(payload, options) {
  const common = reviewCommon(payload, options);
  if (common) return common;
  if (!isAddress(String(payload.binder)) || getAddress(payload.binder) !== getAddress(options.binder)) {
    return "binder out of scope";
  }
  if (options.policyId && String(payload.policyId).toLowerCase() !== String(options.policyId).toLowerCase()) {
    return "policy out of scope";
  }
  const consent = payload.consent;
  if (!consent || typeof consent !== "object") return "missing consent";
  if (String(consent.scopeCommitment).toLowerCase() !== String(options.scope).toLowerCase()) {
    return "scope out of scope";
  }
  // The historical authority is fixed at session initiation. A consent made
  // under any other record is refused here, not merely on-chain.
  if (String(consent.governanceRecord).toLowerCase() !== String(options.governanceRecord).toLowerCase()) {
    return "consent names another governance record";
  }
  if (Number(consent.disclosureVersion) !== 1) return "unsupported disclosure version";
  if (!bytes32(payload.sessionCommitment)) return "invalid session commitment";
  if (!bytes32(payload.resultCommitment)) return "invalid result commitment";
  if (!bytes32(payload.matchCommitment)) return "invalid match commitment";
  if (!isAddress(String(payload.anchor))) return "invalid anchor";
  if (Number(consent.validUntil) <= Math.floor(Date.now() / 1000)) return "consent already expired";
  if (!(BigInt(consent.nonce ?? 0) > 0n)) return "consent nonce required";
  // Disclosure is only meaningful for a confirmed exact match, so a controller
  // refuses to consent to publishing anything else.
  if (payload.outcome !== 1 || payload.exactMatchConfirmed !== true) {
    return "refusing to consent to a non exact-match result";
  }
  if (payload.candidateMatchSuggested === true) return "refusing to consent to a candidate result";
  const authorization = payload.authorization;
  if (!authorization || typeof authorization !== "object") return "missing authorization";
  if (String(authorization.controllerKeyId).toLowerCase() !== String(options.controllerKeyId).toLowerCase()) {
    return "authorization names another controller key";
  }
  return null;
}

/// The issuer attesting a source asset identity before an anchor exists.
export function reviewSourceAttestation(payload, options) {
  const common = reviewCommon(payload, options);
  if (common) return common;
  const attestation = payload.attestation;
  if (!attestation || typeof attestation !== "object") return "missing attestation";
  if (Number(attestation.chainId) !== Number(options.chainId)) return "attestation chain out of scope";
  if (!isAddress(String(payload.verifyingContract))) return "invalid verifying contract";
  if (getAddress(attestation.factory) !== getAddress(payload.verifyingContract)) {
    return "attestation names another admission contract";
  }
  if (String(attestation.issuerKeyId).toLowerCase() !== String(options.issuerKeyId).toLowerCase()) {
    return "attestation names another issuer key";
  }
  if (Number(attestation.identitySchemeVersion) !== 3 || Number(attestation.termsSchemeVersion) !== 1) {
    return "unsupported identity or terms scheme";
  }
  if (Number(attestation.validUntil) <= Math.floor(Date.now() / 1000)) return "attestation already expired";
  return null;
}

/* --------------------------------------------------------------------- serve */

export async function serve(options) {
  const key = (await readFile(resolve(options.storage, "party.key"), "utf8")).trim();
  const token = (await readFile(resolve(options.storage, "runner.token"), "utf8")).trim();
  const account = privateKeyToAccount(key);
  const isController = options.role === "controller-a" || options.role === "controller-b";

  const handlers = {
    // Both controllers and the issuer sign the identical intent. Each recomputes
    // the digest from the 24 fields rather than signing what it is handed.
    "/v1/sign-intent": async (payload) => {
      if (!isController && options.role !== "issuer") return { status: 403, body: { error: "role may not initiate" } };
      const verdict = reviewIntent(payload, options);
      if (verdict) return { status: 403, body: { error: verdict } };
      const digest = intentDigest(payload.intent, payload.chainId, payload.governance);
      if (payload.expectedDigest && String(payload.expectedDigest).toLowerCase() !== digest.toLowerCase()) {
        return { status: 422, body: { error: "supplied intent digest does not match the fields" } };
      }
      const signature = await account.sign({ hash: digest });
      assertCanonicalSignature(signature, options.role);
      return { status: 200, body: { role: options.role, address: account.address, digest, signature } };
    },
    // A controller consents to publish one specific confirmed result.
    "/v1/sign-consent": async (payload) => {
      if (!isController) return { status: 403, body: { error: "role may not consent" } };
      const verdict = reviewConsent(payload, options);
      if (verdict) return { status: 403, body: { error: verdict } };
      const digest = consentDigest({
        chainId: payload.chainId,
        binder: payload.binder,
        policyId: payload.policyId,
        policyVersion: payload.policyVersion,
        sessionCommitment: payload.sessionCommitment,
        resultCommitment: payload.resultCommitment,
        matchCommitment: payload.matchCommitment,
        anchor: payload.anchor,
        consent: payload.consent,
        authorization: payload.authorization,
      });
      if (payload.expectedDigest && String(payload.expectedDigest).toLowerCase() !== digest.toLowerCase()) {
        return { status: 422, body: { error: "supplied consent digest does not match the fields" } };
      }
      const signature = await account.sign({ hash: digest });
      assertCanonicalSignature(signature, `${options.role}-consent`);
      return { status: 200, body: { role: options.role, address: account.address, digest, signature } };
    },
    // The issuer pre-authorizes an anchor before it exists.
    "/v1/sign-source-attestation": async (payload) => {
      if (options.role !== "issuer") return { status: 403, body: { error: "role may not attest sources" } };
      const verdict = reviewSourceAttestation(payload, options);
      if (verdict) return { status: 403, body: { error: verdict } };
      const digest = sourceAttestationDigest(payload.attestation, payload.chainId, payload.verifyingContract);
      const signature = await account.sign({ hash: digest });
      assertCanonicalSignature(signature, "issuer-source");
      return { status: 200, body: { role: options.role, address: account.address, digest, signature } };
    },
    // The relayer is handed ONLY the final 32-byte commitment. It is given no
    // intent, no salt and no signatures, so relaying carries no knowledge of the
    // session it publishes.
    "/v1/relay-commitment": async (payload) => {
      if (options.role !== "relayer") return { status: 403, body: { error: "role may not relay" } };
      if (!bytes32(payload.sessionCommitment)) return { status: 400, body: { error: "invalid session commitment" } };
      const extra = Object.keys(payload).filter((name) => !["chainId", "sessionCommitment"].includes(name));
      if (extra.length > 0) {
        return { status: 400, body: { error: `relayer refuses session detail: ${extra.join(",")}` } };
      }
      return { status: 200, body: { role: options.role, address: account.address, accepted: payload.sessionCommitment } };
    },
  };

  const server = createServer((request, response) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) { request.destroy(); return; }
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
          role: options.role, address: account.address, holdsOwnKeyOnly: true,
          scope: { chainId: options.chainId, governance: options.governance, binder: options.binder },
        });
      }
      const handler = handlers[request.url ?? ""];
      if (!handler || request.method !== "POST") return reply(404, { error: "not found" });
      if (!authenticate(token, body, request.headers["x-signer-auth"])) {
        return reply(401, { error: "unauthenticated" });
      }
      let payload;
      try { payload = JSON.parse(body.toString("utf8")); } catch { return reply(400, { error: "invalid body" }); }
      try {
        const { status, body: value } = await handler(payload);
        return reply(status, value);
      } catch (error) {
        return reply(500, { error: String(error?.message ?? error) });
      }
    });
  });
  await new Promise((done) => server.listen(options.port, "127.0.0.1", done));
  return { server, address: account.address, role: options.role, port: server.address().port };
}

/* ---------------------------------------------------------------------- main */

export function parseArgs(argv) {
  const options = {
    mode: "serve", storage: null, role: null, port: 0, chainId: 0,
    governance: null, binder: null, policyId: null, scope: null,
    governanceRecord: null, controllerKeyId: null, issuerKeyId: null,
  };
  const flags = {
    "--mode": "mode", "--storage": "storage", "--role": "role", "--port": "port",
    "--chain-id": "chainId", "--governance": "governance", "--binder": "binder",
    "--policy-id": "policyId", "--scope": "scope", "--governance-record": "governanceRecord",
    "--controller-key-id": "controllerKeyId", "--issuer-key-id": "issuerKeyId",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const field = flags[argv[index]];
    if (field && argv[index + 1] !== undefined) {
      const value = argv[++index];
      options[field] = field === "port" || field === "chainId" ? Number(value) : value;
    }
  }
  if (!options.storage) throw new Error("PARTY_STORAGE_REQUIRED");
  options.storage = resolve(options.storage);
  if (!ROLES.includes(options.role)) throw new Error("PARTY_ROLE_REQUIRED");
  return options;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const options = parseArgs(process.argv.slice(2));
  if (options.mode === "identity") {
    const { address } = await generateIdentity(options.storage, options.role);
    process.stdout.write(`${address}\n`);
  } else {
    if (!options.chainId) throw new Error("PARTY_SCOPE_REQUIRED");
    const { address, port, role } = await serve(options);
    process.stdout.write(`${JSON.stringify({ ready: true, role, address, port })}\n`);
  }
}

// Re-exported so the runner can verify what a signer produced without holding
// its key.
export { intentDigest, consentDigest, sessionCommitment, signatureBundleDigest, isHex };
