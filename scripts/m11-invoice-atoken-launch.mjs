#!/usr/bin/env node
/**
 * M-11: launch the dedicated invoice A-Token.
 *
 * The last dependency M-07 identified. Unlike aUSDC, whose compliance rule belongs to Cleanverse
 * and blocked us for two missions, this token's rule is ours to choose, so the M-01C class of
 * failure cannot recur here.
 *
 *   node --env-file=.env scripts/m11-invoice-atoken-launch.mjs --check    read-only, the default
 *   node --env-file=.env scripts/m11-invoice-atoken-launch.mjs --run --out <prefix>
 *
 * Exactly ONE /atoken/launch call is permitted, and this runner makes at most one. It never retries
 * after a timeout or an ambiguous response: a launch that may have been accepted must never be
 * re-sent, because the failure mode is two tokens rather than none. An ambiguous result is recorded
 * as SUBMITTED / PENDING and left for a human.
 *
 * Not in scope and not performed: MINTER_ROLE, minting, any Mordant deployment, any settlement.
 *
 * No private key, seed phrase or other secret material is logged or persisted. This runner signs
 * nothing on chain: the launch is an authenticated API call and Cleanverse deploys the token.
 */
import { createCipheriv, createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, http, keccak256, toBytes } from "viem";

import {
  ControlError, assertChainId, assertWriteAllowed, scrub, writeArtifact,
} from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE_DIR = join(ROOT, "docs/evidence");
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

/** The token M-11 issued, used by the read-only authority mode. */
const ISSUED_INVOICE_ATOKEN = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";

/** Rediscovered at run time and compared against these, never trusted from here. */
const EXPECTED = Object.freeze({
  aUsdc: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
  policy: "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd",
  policyImplementation: "0xc644e79e4c8ee94c4dee49b76f8591e994e58101",
  apass: "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9",
  accessCore: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
  aTokenFactory: "0xd1ad67ca3b7da5934813f4bd005812ebb3b43ff6",
});

const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** The token this mission launches. Decimals match aUSDC so settlement arithmetic stays trivial. */
const TOKEN = Object.freeze({
  chain: "monad",
  token_name: "Mordant Invoice Note",
  token_symbol: "MINV01",
  decimals: 6,
  /**
   * A real, resolving URL under the project owner's own GitHub account. Cosmetic only, and chosen
   * so nothing impersonates another organisation; it should be replaced once the project hosts its
   * own asset.
   */
  icon: "https://avatars.githubusercontent.com/RedGnad",
});

/**
 * The A-Pass profiles the demo will actually use, read back on 28 July 2026. Every one of them is
 * tier 50, subTier 0, with no group, no subgroup and no country list.
 */
const DEMO_PROFILES = Object.freeze([
  { label: "HOLDER_A", address: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45" },
  { label: "HOLDER_B", address: "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6" },
  { label: "probe", address: "0x0f8b9a0c064306f938912658c96c681d8655140b" },
]);

/** Bounded wait. A launch that has not settled inside this stays PENDING rather than being retried. */
const POLL_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 6_000;

const TERMINAL_STATUSES = new Set(["ISSUED", "REJECTED", "ISSUE_FAILED"]);

const POLICY_ABI = [
  { type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] },
  { type: "function", name: "isTokenRegistered", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "isPaused", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const ACCESS_CONTROL_ABI = [
  { type: "function", name: "getRoleAdmin", stateMutability: "view",
    inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "hasRole", stateMutability: "view",
    inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
];

const ERC20_ABI = [
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
  { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "name", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "policy", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
];

export { ControlError as StopError } from "./runner-controls.mjs";

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * Picks the least permissive rule that still admits every profile the demo will use.
 *
 * "Least permissive" is bounded by what the profiles actually carry. Our A-Passes have no group,
 * no subgroup and no country, so a rule constraining any of those would admit nobody: the only
 * dimensions that can be tightened are the tiers, and they are raised to the minimum any planned
 * profile holds.
 */
export function resolveRule(profiles) {
  if (!Array.isArray(profiles) || profiles.length === 0) {
    stop("no A-Pass profile was supplied, so no rule can be justified.");
  }
  // Absent values are refused rather than coerced: Number(null) is 0, which would silently become
  // a tier-0 profile and drag the whole rule down to admitting anyone.
  const readTier = (value, label, field) => {
    if (value === null || value === undefined || value === "") {
      stop(`profile ${label} has no ${field}. An absent tier is not read as zero.`);
    }
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 0) {
      stop(`profile ${label} has no readable ${field} (${value}).`);
    }
    return parsed;
  };
  for (const profile of profiles) {
    readTier(profile.tier, profile.label, "tier");
    readTier(profile.subTier, profile.label, "subTier");
  }
  const minTier = Math.min(...profiles.map((profile) => Number(profile.tier)));
  const minSubTier = Math.min(...profiles.map((profile) => Number(profile.subTier)));

  const groups = new Set(profiles.map((profile) => String(profile.group ?? "")));
  const subGroups = new Set(profiles.map((profile) => String(profile.subGroup ?? "")));
  // A single shared, non-empty group could be required without excluding anyone. Anything else,
  // including a mix, means the constraint has to stay open or the rule would admit nobody.
  const allowedGroup = groups.size === 1 && [...groups][0] !== "" ? [...groups][0] : "";
  const allowedSubGroup = subGroups.size === 1 && [...subGroups][0] !== "" ? [...subGroups][0] : "";

  return {
    allowed_group: allowedGroup,
    allowed_sub_group: allowedSubGroup,
    min_tier: minTier,
    min_sub_tier: minSubTier,
  };
}

/** Confirms every planned profile satisfies the rule that will actually be submitted. */
export function profilesSatisfying(rule, profiles) {
  return profiles.map((profile) => {
    const reasons = [];
    if (Number(profile.tier) < rule.min_tier) reasons.push(`tier ${profile.tier} < ${rule.min_tier}`);
    if (Number(profile.subTier) < rule.min_sub_tier) {
      reasons.push(`subTier ${profile.subTier} < ${rule.min_sub_tier}`);
    }
    if (rule.allowed_group !== "" && String(profile.group ?? "") !== rule.allowed_group) {
      reasons.push(`group "${profile.group}" is not "${rule.allowed_group}"`);
    }
    if (rule.allowed_sub_group !== "" && String(profile.subGroup ?? "") !== rule.allowed_sub_group) {
      reasons.push(`subGroup "${profile.subGroup}" is not "${rule.allowed_sub_group}"`);
    }
    return { label: profile.label, address: profile.address, tier: profile.tier,
      subTier: profile.subTier, satisfies: reasons.length === 0, reasons };
  });
}

/**
 * A deterministic key over the exact request.
 *
 * The launch endpoint accepts no idempotency field, so this cannot make the API deduplicate. What
 * it does is make a repeat submission detectable: the same intent always produces the same key, so
 * a prior artifact carrying it proves a launch was already sent and the runner refuses rather than
 * creating a second token.
 */
export function launchKey(request) {
  const canonical = JSON.stringify({
    chain: request.chain, token_name: request.token_name, token_symbol: request.token_symbol,
    decimals: request.decimals, admin_address: String(request.admin_address).toLowerCase(),
    rule: {
      allowed_group: request.rule.allowed_group, allowed_sub_group: request.rule.allowed_sub_group,
      min_tier: request.rule.min_tier, min_sub_tier: request.rule.min_sub_tier,
    },
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Makes the launch key actually binding.
 *
 * The key alone only makes a repeat detectable; this is what refuses it. Any prior artifact
 * carrying the same key together with a `launchAttemptedAt` proves a launch was already sent, and
 * the run stops regardless of how that attempt ended. A PENDING one may still be issuing, an
 * ambiguous failure may have been accepted anyway, and an ISSUED one already exists: in all three
 * cases sending again risks a second token, which is the outcome this mission must never produce.
 *
 * @param artifacts parsed evidence artifacts, [{ path, report }]
 */
export function assertLaunchKeyUnused(key, artifacts) {
  const priors = artifacts.filter(
    (entry) => entry.report?.launchKey === key && entry.report?.launchAttemptedAt);
  if (priors.length > 0) {
    const detail = priors
      .map((entry) => `${entry.path} at ${entry.report.launchAttemptedAt}`
        + ` (${entry.report.classification ?? entry.report.status ?? "unknown outcome"})`)
      .join("; ");
    stop(`launch key ${key} was already submitted: ${detail}.`
      + " Sending it again risks a second token. Reconcile with /atoken/list_my_atokens instead.");
  }
  return true;
}

/**
 * Uniqueness, against every A-Token already launched under this identity. A name or symbol
 * collision is refused outright: two tokens differing only by address is exactly the ambiguity this
 * mission must not create.
 */
export function assertNameAndSymbolFree(existing, tokenName, tokenSymbol) {
  const nameHits = existing.filter(
    (token) => String(token.tokenName ?? "").toLowerCase() === tokenName.toLowerCase());
  const symbolHits = existing.filter(
    (token) => String(token.tokenSymbol ?? "").toLowerCase() === tokenSymbol.toLowerCase());
  if (nameHits.length > 0) {
    stop(`an A-Token named "${tokenName}" already exists`
      + ` (${nameHits.map((hit) => `${hit.requestId}:${hit.applyStatus}`).join(", ")}).`);
  }
  if (symbolHits.length > 0) {
    stop(`an A-Token with symbol "${tokenSymbol}" already exists`
      + ` (${symbolHits.map((hit) => `${hit.requestId}:${hit.applyStatus}`).join(", ")}).`);
  }
  return true;
}

/**
 * The verdict.
 *
 * A launch that was accepted but has not reached a terminal status is SUBMITTED / PENDING, never
 * FAILED: the request is in flight and calling it failed would invite a second submission.
 */
export function classifyLaunch({ submitted, applyStatus, readback }) {
  if (!submitted) return "INVOICE A-TOKEN LAUNCH: FAILED";
  if (applyStatus === "REJECTED" || applyStatus === "ISSUE_FAILED") {
    return "INVOICE A-TOKEN LAUNCH: FAILED";
  }
  if (applyStatus !== "ISSUED") return "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING";
  // Issued is what Cleanverse says. The readback is what the chain says, and both must agree.
  if (!readback?.ok) return "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING";
  return "INVOICE A-TOKEN LAUNCH: ISSUED / READBACK PROVEN";
}

/**
 * Whether the admin wallet could grant MINTER_ROLE later, established without writing anything.
 *
 * Knowing that a grant is possible before planning around it is the point: discovering the admin
 * cannot grant would change M-12's design, and finding that out from a reverted transaction would
 * be the expensive way.
 */
export function classifyMinterAuthority({ minterRole, roleAdmin, adminHoldsRoleAdmin }) {
  if (!minterRole || !roleAdmin) return "MINTER ROLE AUTHORITY: NOT READABLE";
  if (adminHoldsRoleAdmin !== true) return "MINTER ROLE AUTHORITY: ADMIN CANNOT GRANT";
  return "MINTER ROLE AUTHORITY: ADMIN CAN GRANT";
}

/** Every evidence artifact on disk, so a prior launch attempt cannot be missed. */
function readEvidenceArtifacts() {
  let names;
  try {
    names = readdirSync(EVIDENCE_DIR).filter((name) => name.endsWith(".json"));
  } catch (error) {
    stop(`the evidence directory could not be read (${error.message}), so a prior launch attempt`
      + " cannot be ruled out.");
  }
  return names.map((name) => {
    const path = join(EVIDENCE_DIR, name);
    try {
      return { path: `docs/evidence/${name}`, report: JSON.parse(readFileSync(path, "utf8")) };
    } catch (error) {
      // A corrupt artifact might be the very record of a prior attempt, so it is never skipped.
      stop(`the evidence artifact ${name} could not be parsed (${error.message}).`);
    }
    return null;
  });
}

const base = () => process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");
const headers = () => ({ "api-id": process.env.CLEANVERSE_API_ID, "X-Request-ID": crypto.randomUUID() });

async function apiGet(path) {
  const response = await fetch(`${base()}${path}`, { headers: headers(), signal: AbortSignal.timeout(30_000) });
  return response.json();
}

async function apiPost(path, body, timeoutMs = 60_000) {
  const response = await fetch(`${base()}${path}`, {
    method: "POST", headers: { "content-type": "application/json", ...headers() },
    body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs),
  });
  return response.json();
}

/** Encrypts the launch payload per the Cleanverse protocol. The key is never printed or stored. */
function encryptBody(payload) {
  const key = Buffer.from(String(process.env.CLEANVERSE_API_KEY).trim(), "base64");
  const cipher = createCipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(true);
  return { data: Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), "utf8")), cipher.final()]).toString("base64") };
}

const MAX_LIST_PAGES = 25;

/**
 * Enumerates every A-Token under this identity, fail-closed.
 *
 * A partial listing would silently weaken the uniqueness check into "no collision among the pages
 * we happened to read", so falling short of the declared total stops the run rather than
 * proceeding on an incomplete view.
 */
async function listMyATokens() {
  const all = [];
  let total = null;
  for (let page = 1; page <= MAX_LIST_PAGES; page += 1) {
    const response = await apiGet(`/atoken/list_my_atokens?page=${page}&pageSize=20`);
    if (response?.code !== "0000") {
      stop(`list_my_atokens failed with ${response?.code}: ${String(response?.message).slice(0, 120)}.`
        + " Uniqueness could not be established, so no launch is attempted.");
    }
    total = Number(response.data?.total ?? Number.NaN);
    const items = response.data?.items ?? [];
    all.push(...items);
    if (items.length === 0 || all.length >= total) break;
  }
  if (!Number.isInteger(total) || total < 0) {
    stop("list_my_atokens did not report a usable total, so uniqueness cannot be established.");
  }
  if (all.length < total) {
    stop(`list_my_atokens reported ${total} A-Tokens but only ${all.length} were retrieved within`
      + ` ${MAX_LIST_PAGES} pages. Uniqueness cannot be established from a partial listing.`);
  }
  return all;
}

/**
 * Read-only: proves whether the admin wallet holds the role that administers MINTER_ROLE.
 *
 * Writes its own artifact and never touches the launch one, which stays exactly as produced.
 */
async function runAuthorityMode(out) {
  const client = createPublicClient({ transport: http(MONAD_RPC) });
  const chainId = await assertChainId(client);
  const blockNumber = await client.getBlockNumber();
  const adminRole = process.env.MORDANT_M11_ADMIN_ROLE ?? "HOLDER_A";
  const adminAddress = process.env[`MORDANT_ADDRESS_${adminRole}`];
  if (!adminAddress) stop(`MORDANT_ADDRESS_${adminRole} must be set.`);
  const token = process.env.MORDANT_INVOICE_ATOKEN ?? ISSUED_INVOICE_ATOKEN;

  const minterRole = keccak256(toBytes("MINTER_ROLE"));
  const read = (functionName, args) => client.readContract({
    address: token, abi: ACCESS_CONTROL_ABI, functionName, args }).catch(() => null);
  const roleAdmin = await read("getRoleAdmin", [minterRole]);
  const adminHoldsRoleAdmin = roleAdmin ? await read("hasRole", [roleAdmin, adminAddress]) : null;
  const adminHoldsMinter = await read("hasRole", [minterRole, adminAddress]);

  const classification = classifyMinterAuthority({ minterRole, roleAdmin, adminHoldsRoleAdmin });
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode: "authority",
    classification,
    scope: "Read-only. No role was granted, nothing was minted and no transaction was sent."
      + " This establishes only whether a future grant is possible.",
    network: { name: "monad-testnet", chainId, blockNumber: blockNumber.toString() },
    token,
    adminRole,
    adminAddress,
    minterRole,
    roleAdmin,
    adminHoldsRoleAdmin,
    adminHoldsMinterRole: adminHoldsMinter,
    statuses: {
      "MINTER ROLE": adminHoldsMinter === true ? "HELD BY ADMIN" : "NOT GRANTED",
      "MINT/BURN VIA MORDANT ADAPTER": "NOT PROVEN",
      "MORDANT SETTLEMENT": "NOT PROVEN",
    },
  };
  process.stdout.write(`M-11 minter authority, read-only\n\n`);
  process.stdout.write(`  token           ${token}\n`);
  process.stdout.write(`  MINTER_ROLE     ${minterRole}\n`);
  process.stdout.write(`  getRoleAdmin    ${roleAdmin}\n`);
  process.stdout.write(`  admin holds it  ${adminHoldsRoleAdmin}\n`);
  process.stdout.write(`  admin is minter ${adminHoldsMinter}\n`);
  process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${classification}\n`);
  if (out) {
    writeArtifact(out, report, process.env);
    process.stdout.write(`\nWrote ${out}.json\n`);
  }
  if (adminHoldsRoleAdmin !== true) {
    stop("the admin wallet does not hold the role that administers MINTER_ROLE."
      + " A future grant would revert, so M-12 must be designed around that.");
  }
}

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const mode = argv.includes("--run") ? "run" : argv.includes("--authority") ? "authority" : "check";
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const steps = [];
  const note = (label, detail) => {
    steps.push({ label, detail });
    process.stdout.write(`  ${label.padEnd(30)} ${detail}\n`);
  };

  const report = {
    schemaVersion: 1,
    runStartedAt: new Date().toISOString(),
    generatedAt: null,
    mode,
    status: "RUNNING",
    classification: mode === "check" ? "READ-ONLY PREFLIGHT — NO LAUNCH SENT" : "PENDING",
    scope:
      "One /atoken/launch call for the dedicated invoice A-Token. No MINTER_ROLE, no mint, no"
      + " Mordant deployment and no settlement. Nothing here is a Mordant settlement.",
    steps,
  };
  const checkpoint = () => {
    if (!out) return;
    report.generatedAt = new Date().toISOString();
    writeArtifact(out, report, process.env);
  };
  main.checkpointOnFailure = (message) => {
    if (!out) return;
    report.status = "STOPPED";
    report.stopReason = message;
    checkpoint();
  };

  if (mode === "authority") {
    await runAuthorityMode(out);
    return;
  }

  process.stdout.write(`M-11 invoice A-Token launch, mode=${mode}\n\n`);
  const client = createPublicClient({ transport: http(MONAD_RPC) });

  const chainId = await assertChainId(client);
  assertWriteAllowed(mode, "run", out);
  note("network", `chain ${chainId}`);
  const blockNumber = await client.getBlockNumber();
  const block = await client.getBlock({ blockNumber });
  note("pinned block", `${blockNumber} ${block.hash}`);

  // --- rediscover the factory and dependencies before any write ---
  const readImplementation = async (address) => {
    const word = await client.getStorageAt({ address, slot: EIP1967_IMPLEMENTATION_SLOT });
    return word && !/^0x0+$/.test(word) ? `0x${word.slice(-40)}` : null;
  };
  const dependencies = {};
  for (const [name, address] of Object.entries(EXPECTED)) {
    const code = await client.getCode({ address });
    if (!code || code === "0x") stop(`${name} at ${address} has no code on chain.`);
    dependencies[name] = { address, codeBytes: (code.length - 2) / 2,
      implementation: await readImplementation(address) };
  }
  if (dependencies.policy.implementation?.toLowerCase() !== EXPECTED.policyImplementation.toLowerCase()) {
    stop(`the policy implementation changed: ${dependencies.policy.implementation}.`);
  }
  const discovery = await apiPost("/query_deposit_atoken_list", { chain: "monad" });
  const discoveredAUsdc = Array.isArray(discovery?.data?.tokens)
    ? discovery.data.tokens.find((pair) => String(pair.atoken?.symbol).toLowerCase() === "ausdc")?.atoken?.address
    : null;
  if (String(discoveredAUsdc).toLowerCase() !== EXPECTED.aUsdc.toLowerCase()) {
    stop(`the discovered aUSDC address ${discoveredAUsdc} does not match the expected ${EXPECTED.aUsdc}.`);
  }
  note("dependencies", `factory, policy, A-Pass, AccessCore and aUSDC all present and unchanged`);
  report.dependencies = dependencies;

  // --- uniqueness, before anything is submitted ---
  const existing = await listMyATokens();
  assertNameAndSymbolFree(existing, TOKEN.token_name, TOKEN.token_symbol);
  note("uniqueness", `${existing.length} existing A-Tokens, no name or symbol collision`);
  report.existingATokenCount = existing.length;

  // --- the rule, derived from the profiles the demo will actually use ---
  const profiles = [];
  for (const { label, address } of DEMO_PROFILES) {
    const record = scrub(await apiPost("/query_apass", { chain: "monad", address }));
    if (record?.code !== "0000" || !record.data) {
      stop(`query_apass failed for ${label} ${address}; the rule cannot be justified without it.`);
    }
    const data = record.data;
    if (Number(data.status) !== 1) stop(`${label} has A-Pass status ${data.status}, expected 1.`);
    profiles.push({ label, address, tier: Number(data.tier), subTier: Number(data.subTier),
      group: data.group ?? "", subGroup: data.subGroup ?? "",
      countries: data.countries ?? [], expirationTime: data.expirationTime ?? null });
  }
  const rule = resolveRule(profiles);
  const satisfaction = profilesSatisfying(rule, profiles);
  const unsatisfied = satisfaction.filter((entry) => !entry.satisfies);
  if (unsatisfied.length > 0) {
    stop(`the resolved rule would exclude ${unsatisfied.map((entry) => entry.label).join(", ")}.`);
  }
  note("resolved rule", `min_tier ${rule.min_tier}, min_sub_tier ${rule.min_sub_tier},`
    + ` group "${rule.allowed_group}", subGroup "${rule.allowed_sub_group}"`);
  note("profiles admitted", satisfaction.map((entry) => `${entry.label}(t${entry.tier})`).join(", "));

  const adminRole = process.env.MORDANT_M11_ADMIN_ROLE ?? "HOLDER_A";
  const adminAddress = process.env[`MORDANT_ADDRESS_${adminRole}`];
  if (!adminAddress) stop(`MORDANT_ADDRESS_${adminRole} must be set to supply admin_address.`);

  const request = { ...TOKEN, admin_address: adminAddress, rule };
  const key = launchKey(request);
  note("admin", `${adminRole} ${adminAddress}`);
  note("launch key", key);

  // Binding, and checked in every mode: a prior artifact recording an attempt with this key means
  // a launch already went out, whatever it returned, so a second one must not follow.
  assertLaunchKeyUnused(key, readEvidenceArtifacts());
  note("launch key check", "no prior artifact records an attempt with this key");

  report.network = { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(),
    blockHash: block.hash };
  report.plannedRequest = request;
  report.launchKey = key;
  report.profiles = profiles;
  report.ruleSatisfaction = satisfaction;
  checkpoint();

  if (mode !== "run") {
    report.status = "COMPLETE";
    process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
    process.stdout.write(`${"LAUNCH".padEnd(30)} check mode sends nothing; pass --run --out\n`);
    if (out) { checkpoint(); process.stdout.write(`\nWrote ${out}.json\n`); }
    return;
  }

  // --- the single launch call ---
  report.launchAttemptedAt = new Date().toISOString();
  report.classification = "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING";
  checkpoint();

  let response;
  let transportError = null;
  try {
    response = scrub(await apiPost("/atoken/launch", encryptBody(request)));
  } catch (error) {
    transportError = String(error.message).slice(0, 300);
    response = null;
  }
  // Recorded before anything is interpreted: from here a token may exist regardless of what this
  // process sees, and the artifact must say so.
  report.launchResponse = { envelopeCode: response?.code ?? null,
    message: String(response?.message ?? "").slice(0, 300), data: response?.data ?? null,
    transportError };
  checkpoint();

  if (transportError || !response) {
    report.status = "STOPPED";
    report.ambiguous = {
      note: "The launch call did not return a usable response. It may still have been accepted."
        + " This runner does not retry: a second call risks creating a second token. Reconcile"
        + " with /atoken/list_my_atokens before any further action.",
    };
    checkpoint();
    stop(`the launch call did not return: ${transportError}. NOT retried. See report.ambiguous.`);
  }
  if (response.code !== "0000" || !response.data?.requestId) {
    report.classification = "INVOICE A-TOKEN LAUNCH: FAILED";
    report.status = "COMPLETE";
    checkpoint();
    stop(`the launch was rejected: ${response.code} ${String(response.message).slice(0, 160)}`);
  }
  const requestId = response.data.requestId;
  note("launch accepted", `requestId ${requestId}, issueAssetId ${response.data.issueAssetId}`);

  // --- bounded polling, no retry of the launch itself ---
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let statusRecord = null;
  let applyStatus = null;
  const polls = [];
  while (Date.now() < deadline) {
    const statusResponse = await apiGet(`/atoken/query_apply_status/${encodeURIComponent(requestId)}`);
    statusRecord = statusResponse?.code === "0000" ? statusResponse.data : null;
    applyStatus = statusRecord?.applyStatus ?? null;
    polls.push({ at: new Date().toISOString(), envelopeCode: statusResponse?.code ?? null, applyStatus });
    note("status", `${applyStatus ?? statusResponse?.code}`);
    if (applyStatus && TERMINAL_STATUSES.has(applyStatus)) break;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  report.polling = { timeoutMs: POLL_TIMEOUT_MS, intervalMs: POLL_INTERVAL_MS, polls,
    reachedTerminal: Boolean(applyStatus && TERMINAL_STATUSES.has(applyStatus)) };
  report.applyStatus = applyStatus;
  report.statusRecord = statusRecord;
  checkpoint();

  // --- readback, on chain, for what Cleanverse says it issued ---
  let readback = null;
  const atokenAddress = statusRecord?.atokenAddress ?? null;
  if (applyStatus === "ISSUED" && atokenAddress) {
    const reasons = [];
    const code = await client.getCode({ address: atokenAddress });
    if (!code || code === "0x") reasons.push("the issued address has no code");

    // A proxy pointing at nothing, or at an address with no code, is not a working token.
    const implementation = await readImplementation(atokenAddress);
    let implementationCodeBytes = null;
    if (!implementation) {
      reasons.push("no implementation is set behind the token proxy");
    } else {
      const implementationCode = await client.getCode({ address: implementation });
      implementationCodeBytes = implementationCode ? (implementationCode.length - 2) / 2 : 0;
      if (implementationCodeBytes === 0) reasons.push(`implementation ${implementation} has no code`);
    }

    // The issuing transaction is what Cleanverse says created this token. If it cannot be fetched
    // or did not succeed, the issued state is unverified whatever the API reports.
    let issuingReceipt = null;
    const issuingTxHash = statusRecord?.txHash ?? null;
    if (!issuingTxHash) {
      reasons.push("no issuing transaction hash was reported");
    } else {
      issuingReceipt = await client.getTransactionReceipt({ hash: issuingTxHash }).catch(() => null);
      if (!issuingReceipt) reasons.push(`the issuing receipt for ${issuingTxHash} could not be fetched`);
      else if (issuingReceipt.status !== "success") {
        reasons.push(`the issuing transaction ${issuingTxHash} has status ${issuingReceipt.status}`);
      }
    }

    const read = async (functionName) => client.readContract({
      address: atokenAddress, abi: ERC20_ABI, functionName }).catch(() => null);
    const [onchainName, onchainSymbol, onchainDecimals, tokenPolicy] =
      await Promise.all([read("name"), read("symbol"), read("decimals"), read("policy")]);
    // The chain must agree it is the token we asked for, not merely a token.
    if (onchainName !== TOKEN.token_name) {
      reasons.push(`name "${onchainName}", expected "${TOKEN.token_name}"`);
    }
    if (onchainSymbol !== TOKEN.token_symbol) {
      reasons.push(`symbol "${onchainSymbol}", expected "${TOKEN.token_symbol}"`);
    }
    if (Number(onchainDecimals) !== TOKEN.decimals) {
      reasons.push(`decimals ${onchainDecimals}, expected ${TOKEN.decimals}`);
    }
    if (String(tokenPolicy ?? "").toLowerCase() !== EXPECTED.policy.toLowerCase()) {
      reasons.push(`policy ${tokenPolicy}, expected ${EXPECTED.policy}`);
    }
    const registered = tokenPolicy ? await client.readContract({
      address: tokenPolicy, abi: POLICY_ABI, functionName: "isTokenRegistered",
      args: [atokenAddress] }).catch(() => null) : null;
    const paused = tokenPolicy ? await client.readContract({
      address: tokenPolicy, abi: POLICY_ABI, functionName: "isPaused",
      args: [atokenAddress] }).catch(() => null) : null;
    if (registered !== true) reasons.push(`isTokenRegistered ${registered}`);
    if (paused !== false) reasons.push(`isPaused ${paused}`);

    // Control tuples: every demo profile must be able to receive and send the token its rule admits.
    const control = [];
    for (const from of profiles) {
      for (const to of profiles) {
        if (from.address === to.address) continue;
        const answer = tokenPolicy ? await client.readContract({
          address: tokenPolicy, abi: POLICY_ABI, functionName: "canTransfer",
          args: [atokenAddress, from.address, to.address, 1n] })
          .catch((error) => `reverted: ${(error.shortMessage ?? error.message).slice(0, 60)}`) : null;
        control.push({ from: from.label, to: to.label, answer: String(answer) });
        if (answer !== true) reasons.push(`canTransfer ${from.label} -> ${to.label} is ${answer}`);
      }
    }
    readback = { atokenAddress, implementation, implementationCodeBytes,
      codeBytes: code ? (code.length - 2) / 2 : 0,
      issuingTxHash, issuingReceiptStatus: issuingReceipt?.status ?? null,
      issuingBlockNumber: issuingReceipt?.blockNumber?.toString() ?? null,
      name: onchainName, symbol: onchainSymbol, decimals: onchainDecimals === null ? null : Number(onchainDecimals),
      policy: tokenPolicy, isTokenRegistered: registered, isPaused: paused,
      controlTuples: control, ok: reasons.length === 0, reasons };
    note("readback", readback.ok
      ? `${atokenAddress}, decimals ${onchainDecimals}, registered, ${control.length} control tuples true`
      : `incomplete: ${reasons.join("; ")}`);
  }
  report.readback = readback;

  report.classification = classifyLaunch({ submitted: true, applyStatus, readback });
  report.status = "COMPLETE";
  if (report.classification.includes("SUBMITTED / PENDING")) {
    report.pending = {
      requestId,
      note: "The launch was accepted and has not reached a proven issued state. It is NOT retried:"
        + " a second call would risk a second token. Re-poll"
        + ` /atoken/query_apply_status/${requestId} before any further action.`,
    };
  }

  process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
  checkpoint();
  process.stdout.write(`\nWrote ${out}.json\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m11-invoice-atoken-launch.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    const message = error instanceof ControlError ? error.message : `STOP — ${error.message}`;
    try {
      main.checkpointOnFailure?.(message);
    } catch (writeError) {
      process.stderr.write(`\nartifact could not be written: ${writeError.message}\n`);
    }
    process.stderr.write(`\n${message}\n`);
    process.exitCode = 1;
  });
}
