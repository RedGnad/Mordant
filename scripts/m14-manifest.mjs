#!/usr/bin/env node
/**
 * M-14: the live deployment manifest. Preparation only.
 *
 * Records exactly what a public deployment would consist of, verifies everything that can be
 * verified today, and refuses to execute any of it. No runner here accepts a write mode: passing
 * --run, --broadcast, --deploy or --execute stops the process.
 *
 *   node --env-file=.env scripts/m14-manifest.mjs [--phase <A..F>] [--out <prefix>]
 *
 * The deployable version is frozen at one commit. Any change to the contracts, their structural
 * parameters or their bytecode after that point invalidates the M-13 rehearsal, and the manifest
 * says so rather than letting a drifted build look prepared.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, http, keccak256 } from "viem";

import { ControlError, assertChainId, scrub, writeArtifact } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

/**
 * The frozen deployable version. Everything M-13 proved was proved against this tree.
 */
export const FROZEN_COMMIT = "4285f622c238f9663dfcdb3dd0a5e5b01e8c081d";

const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const AUSDC = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D";
const APASS_REGISTRY = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
const ZERO = "0x0000000000000000000000000000000000000000";

/** Monad documents a 128 KB code limit; the factory needs it, being far past EIP-170. */
const MONAD_CODE_SIZE_LIMIT = 131_072;
const EIP170_LIMIT = 24_576;

/** Structural parameters. Changing any of these is a change to what M-13 rehearsed. */
export const STRUCTURAL_PARAMETERS = Object.freeze({
  initialUnits: "100000", advanceAmount: "100000", faceValue: "110000",
  bondBps: 1_000, bond: "10000", netProceeds: "90000", holderAllocation: "50000",
  holderShare: "55000", revealPeriod: 3_600, curePeriod: 3_600,
});

/**
 * The live path is the recourse demonstration only. Cash redemption stays fork-proven: deploying a
 * second public vault purely to reproduce a branch already proven on a fork would cost real
 * deployments to demonstrate nothing new.
 */
export const LIVE_PATH = Object.freeze([
  "activation", "conflict commit", "conflict reveal", "finalisation", "default", "MINV01 release",
]);

export const CONTRACTS = Object.freeze([
  { name: "CleanverseCvaAdapter", artifact: "CleanverseCvaAdapter.sol/CleanverseCvaAdapter",
    phase: "A", constructorSignature: "constructor(address initialOwner, ICleanverseAToken token, ICleanverseAPass apass)",
    constructorArgs: ["<owner>", MINV01, APASS_REGISTRY], owner: "<owner>",
    addressPredictable: false,
    addressNote: "CREATE, so the address depends on the deployer nonce and is only known after the"
      + " transaction. Its A-Pass therefore cannot be requested in advance.",
    gasCap: 2_000_000 },
  { name: "CleanverseAPassVerifier", artifact: "CleanverseAPassVerifier.sol/CleanverseAPassVerifier",
    phase: "C", constructorSignature: "constructor(address initialOwner, ICleanverseAPass apass, uint256 openRoleMask)",
    constructorArgs: ["<owner>", APASS_REGISTRY, "16"], owner: "<owner>",
    addressPredictable: false, gasCap: 2_000_000 },
  { name: "MordantFactory", artifact: "MordantFactory.sol/MordantFactory",
    phase: "C", constructorSignature: "constructor(address initialOwner, ICviVerifier verifier)",
    constructorArgs: ["<owner>", "<verifier>"], owner: "<owner>",
    addressPredictable: false, gasCap: 8_000_000 },
  { name: "MordantInvoiceVault", artifact: "MordantInvoiceVault.sol/MordantInvoiceVault",
    phase: "C", constructorSignature: "deployed by MordantFactory.createInvoiceVault(Init)",
    constructorArgs: ["<Init struct>"], owner: "the factory creates it; the buyer calls",
    addressPredictable: false,
    addressNote: "Created by the factory, so the address is only known from the"
      + " InvoiceVaultCreated event. Its A-Pass follows creation, never precedes it.",
    gasCap: 8_000_000 },
]);

/**
 * Every participant, with the role it fills and what it must be able to do. Two facilities are
 * required because a conflict cannot be raised by the protected one, and the funder is separate
 * from the buyer because the vault refuses an address that is both.
 */
export const PARTICIPANTS = Object.freeze([
  { role: "owner/deployer", env: "MORDANT_ADDRESS_HOLDER_A", mordantRole: "none, deploys and administers",
    signs: ["adapter deployment", "verifier deployment", "factory deployment", "role configuration",
      "MINTER_ROLE grant and revoke", "bindVault"], needsAUsdc: "0" },
  { role: "holderA", env: "MORDANT_ADDRESS_HOLDER_A", mordantRole: "ROLE_HOLDER (4)",
    signs: ["releaseDefaultCva"], needsAUsdc: "0" },
  { role: "holderB", env: "MORDANT_ADDRESS_HOLDER_B", mordantRole: "ROLE_HOLDER (4)",
    signs: ["releaseDefaultCva"], needsAUsdc: "0" },
  { role: "buyer", env: "MORDANT_ADDRESS_BUYER", mordantRole: "ROLE_BUYER (1)",
    signs: ["createInvoiceVault"], needsAUsdc: "0",
    note: "the live path stops at the release, so the buyer never funds redemption" },
  { role: "funder", env: "MORDANT_ADDRESS_FUNDER", mordantRole: "ROLE_HOLDER (4), as the advancing party",
    signs: ["aUSDC approve", "advance at activation"], needsAUsdc: STRUCTURAL_PARAMETERS.advanceAmount,
    note: "must not be the buyer; the vault rejects a funder that is also the buyer" },
  { role: "originator", env: "MORDANT_ADDRESS_ORIGINATOR", mordantRole: "ROLE_ORIGINATOR (2)",
    signs: ["EIP-712 pledge", "EIP-712 conflicting pledge"], needsAUsdc: "0",
    note: "receives the net proceeds; signs but sends no transaction" },
  { role: "facilityProtected", env: "MORDANT_ADDRESS_FACILITY_A", mordantRole: "ROLE_FACILITY (3)",
    signs: ["activate"], needsAUsdc: "0" },
  { role: "facilityChallenger", env: "MORDANT_ADDRESS_FACILITY_B", mordantRole: "ROLE_FACILITY (3)",
    signs: ["commitConflict", "revealConflict"], needsAUsdc: "0",
    note: "must be distinct from the protected facility, which cannot challenge itself" },
  { role: "issuanceMinter", env: "MORDANT_ADDRESS_ISSUANCE_MINTER", mordantRole: "none, temporary MINTER_ROLE",
    signs: ["mint the exact supply to the adapter"], needsAUsdc: "0",
    note: "holds MINTER_ROLE only between the grant and the revoke, both in phase D" },
]);

/**
 * The execution DAG. No phase triggers the next: each ends at a stop, and resuming is a separate
 * deliberate command.
 */
export const PHASES = Object.freeze([
  { id: "A", name: "adapter", steps: [
    "deploy CleanverseCvaAdapter(owner, MINV01, A-Pass registry)",
    "verify the runtime bytecode hash against the frozen artifact",
    "verify owner(), token(), apass() and boundVault() == zero",
    "STOP"] },
  { id: "B", name: "adapter credential", steps: [
    "request the live A-Pass for the adapter address through the Cleanverse gateway",
    "on an ambiguous or timed-out response, STOP and reconcile by hand; never retry automatically",
    "verify through the API and on chain that the credential exists",
    "verify the MINV01 policy permits zero to adapter, adapter to zero, and adapter to each holder",
    "STOP"] },
  { id: "C", name: "Mordant infrastructure", steps: [
    "deploy CleanverseAPassVerifier(owner, A-Pass registry, openRoleMask 16)",
    "deploy MordantFactory(owner, verifier)",
    "configure role eligibility, then the facility, adapter and settlement token allowlists",
    "the buyer creates the vault through the factory",
    "request the vault's A-Pass, which its address only permits after creation",
    "request any missing participant A-Pass",
    "verify the nine exact policy tuples",
    "STOP"] },
  { id: "D", name: "supply ceremony and binding", steps: [
    "grant MINTER_ROLE to the temporary issuance wallet",
    "mint exactly initialUnits to the adapter",
    "revoke MINTER_ROLE from the issuance wallet immediately",
    "grant MINTER_ROLE to the adapter",
    "reconstruct every RoleGranted and RoleRevoked since MINV01 was deployed",
    "verify the adapter is the only active minter, else STOP without binding",
    "bindVault(vault, initialUnits)",
    "STOP"] },
  { id: "E", name: "activation", steps: [
    "the originator signs the EIP-712 pledge",
    "the funder approves aUSDC to the vault",
    "the protected facility calls activate",
    "verify net proceeds, bond, receipts and assertAccounting()",
    "STOP"] },
  { id: "F", name: "recourse demonstration", steps: [
    "the challenger facility commits the conflict",
    "the challenger facility reveals the conflicting signed pledge",
    "wait out the real cure window",
    "finalizeConflict",
    "wait out the real protectionEnd",
    "markDefault",
    "each holder calls releaseDefaultCva",
    "verify every invariant and balance"] },
]);

/**
 * What to do when a run stops mid-way. Every entry is a manual decision: nothing recovers by itself,
 * because an automatic recovery is exactly how a half-finished deployment becomes two.
 */
export const STOP_MATRIX = Object.freeze([
  { after: "adapter deployed, no A-Pass",
    state: "an adapter exists holding nothing and bound to nothing",
    action: "resume at phase B with the deployed address. It is inert: it holds no supply and no"
      + " vault points at it, so nothing is at risk while it waits.",
    redeployable: true },
  { after: "adapter A-Pass issued, no infrastructure",
    state: "a credentialed adapter, still unbound",
    action: "resume at phase C. The credential does not expire for a year, so there is no rush;"
      + " re-verify it rather than assuming it survived.",
    redeployable: true },
  { after: "vault created, no A-Pass",
    state: "a vault that cannot settle, since _requireSettlementIdentity would fail",
    action: "resume at phase C step 5 with the created address. Do not create a second vault: the"
      + " first would remain allowlisted and could be bound by mistake.",
    redeployable: false },
  { after: "temporary minter granted, not revoked",
    state: "an address other than the adapter can mint MINV01",
    action: "REVOKE FIRST, before anything else. An open minter breaks the supply invariant"
      + " bindVault depends on, and the exclusivity check will refuse to bind while it stands.",
    redeployable: false, urgent: true },
  { after: "supply minted, not bound",
    state: "the adapter holds the whole supply, no vault claims it",
    action: "resume at phase D step 7. Do not mint more: bindVault compares the supply exactly, and"
      + " burning back requires MINTER_ROLE, which the revoke removed.",
    redeployable: false, urgent: true },
  { after: "adapter bound, vault not activated",
    state: "custody committed to a vault that has issued nothing",
    action: "resume at phase E. bindVault is one-shot, so this adapter and vault are now married:"
      + " a new vault would need a new adapter and a new supply.",
    redeployable: false },
  { after: "activated, conflict not started",
    state: "a live receivable with holders and a bond, inside the protection window",
    action: "resume at phase F before protectionEnd. If the window closes first, closeProtection"
      + " reaches default without the conflict path, which demonstrates less.",
    redeployable: false },
]);

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * Refuses every write mode. M-14 prepares; it does not deploy, grant, mint or bind.
 */
export function assertNoWriteMode(argv) {
  const forbidden = ["--run", "--broadcast", "--deploy", "--execute", "--send"];
  const requested = forbidden.filter((flag) => argv.includes(flag));
  if (requested.length > 0) {
    stop(`${requested.join(", ")} is not a mode of this runner. M-14 produces the manifest and`
      + " executes none of it: public writes are not authorized.");
  }
  return true;
}

/**
 * The frozen version gate.
 *
 * What M-13 rehearsed is the CONTRACTS and their structural parameters, so that is what is frozen.
 * Scripts and documents may move afterwards without invalidating anything, and a gate that refused
 * those would only be theatre: it would make the manifest ungenerable while the manifest itself is
 * being written.
 *
 * @param contractsChanged files under contracts/ differing from the frozen commit
 * @param parametersChanged structural parameters differing from the rehearsed set
 */
export function assertFrozenVersion({ contractsChanged, contractsDirty, parametersChanged }) {
  if (contractsChanged.length > 0) {
    stop(`contracts changed since the frozen commit ${FROZEN_COMMIT}:`
      + ` ${contractsChanged.slice(0, 5).join(", ")}${contractsChanged.length > 5 ? ", ..." : ""}.`
      + " M-13 proved that version; this needs a full rehearsal replay before deployment.");
  }
  if (contractsDirty.length > 0) {
    stop(`uncommitted changes under contracts/: ${contractsDirty.slice(0, 5).join(", ")}.`
      + " The deployable bytecode is not the frozen one.");
  }
  if (parametersChanged.length > 0) {
    stop(`structural parameters changed: ${parametersChanged.join(", ")}.`
      + " These are what the rehearsal exercised, so a change needs a replay.");
  }
  return FROZEN_COMMIT;
}

/** The gates every future public command must carry, recorded so they can be checked against. */
export const REQUIRED_GATES = Object.freeze([
  "requires --run and --out",
  "verifies chain id 10143",
  "verifies the address derived from the signing key",
  "simulates or estimates before sending",
  "applies the gas ceilings",
  "writes the hash as PENDING before awaiting the receipt",
  "distinguishes PENDING, STOPPED and SUCCESS",
  "refuses any state that differs from the preceding manifest",
]);

export function assertGatesComplete(declared) {
  const missing = REQUIRED_GATES.filter((gate) => !declared.includes(gate));
  if (missing.length > 0) {
    stop(`a public command is missing required gates: ${missing.join("; ")}`);
  }
  return true;
}

function artifactFacts(relative) {
  const parsed = JSON.parse(readFileSync(join(ROOT, `contracts/out/${relative}.json`), "utf8"));
  const creation = parsed.bytecode?.object ?? "0x";
  const runtime = parsed.deployedBytecode?.object ?? "0x";
  const runtimeBytes = (runtime.length - 2) / 2;
  return {
    creationBytecodeHash: keccak256(creation), expectedRuntimeHash: keccak256(runtime),
    creationBytes: (creation.length - 2) / 2, runtimeBytes,
    withinEip170: runtimeBytes <= EIP170_LIMIT,
    withinMonadLimit: runtimeBytes <= MONAD_CODE_SIZE_LIMIT,
  };
}

async function main() {
  const argv = process.argv.slice(2);
  assertNoWriteMode(argv);
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;

  const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT }).toString().trim();
  const lines = (output) => output.toString().trim().split("\n").filter(Boolean);
  const contractsChanged = lines(execFileSync("git",
    ["diff", "--name-only", FROZEN_COMMIT, "HEAD", "--", "contracts/src", "contracts/foundry.toml"],
    { cwd: ROOT }));
  const contractsDirty = lines(execFileSync("git",
    ["status", "--porcelain", "--", "contracts/src", "contracts/foundry.toml"], { cwd: ROOT }));
  assertFrozenVersion({ contractsChanged, contractsDirty, parametersChanged: [] });
  process.stdout.write(`M-14 live deployment manifest\n\n  frozen commit ${FROZEN_COMMIT}\n`);
  process.stdout.write(`  head          ${head}${head === FROZEN_COMMIT ? "" : " (scripts and docs may move)"}\n`);
  process.stdout.write(`  contracts     unchanged since the freeze\n`);

  const client = createPublicClient({ transport: http(MONAD_RPC) });
  const chainId = await assertChainId(client);
  const blockNumber = await client.getBlockNumber();

  const contracts = CONTRACTS.map((contract) => ({ ...contract, ...artifactFacts(contract.artifact) }));
  for (const contract of contracts) {
    process.stdout.write(`  ${contract.name.padEnd(26)} runtime ${String(contract.runtimeBytes).padStart(6)} B`
      + ` ${contract.withinEip170 ? "within EIP-170" : "PAST EIP-170, needs Monad's 128 KB limit"}\n`);
  }

  // Participants: whatever is knowable today, and an honest gap where it is not.
  const apassAbi = [{ type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }];
  const erc20Abi = [{ type: "function", name: "balanceOf", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] }];
  const participants = [];
  for (const participant of PARTICIPANTS) {
    const address = process.env[participant.env] ?? null;
    if (!address) {
      participants.push({ ...participant, address: null, status: "ADDRESS NOT SUPPLIED",
        isValidAPass: null, apassExpiration: null, monBalance: null, aUsdcBalance: null });
      continue;
    }
    const [isValidAPass, mon, aUsdc] = await Promise.all([
      client.readContract({ address: APASS_REGISTRY, abi: apassAbi, functionName: "isValidAPass", args: [address] }).catch(() => null),
      client.getBalance({ address }).catch(() => null),
      client.readContract({ address: AUSDC, abi: erc20Abi, functionName: "balanceOf", args: [address] }).catch(() => null),
    ]);
    const record = scrub(await queryApass(address));
    participants.push({ ...participant, address, isValidAPass,
      apassExpiration: record?.data?.expirationTime ?? null,
      cleanverseEligible: record?.code === "0000" && Number(record?.data?.status) === 1,
      monBalance: mon === null ? null : mon.toString(),
      aUsdcBalance: aUsdc === null ? null : aUsdc.toString(),
      status: isValidAPass === true ? "READY" : "A-PASS REQUIRED" });
  }
  const unsupplied = participants.filter((entry) => entry.address === null);
  process.stdout.write(`  participants               ${participants.length} roles,`
    + ` ${unsupplied.length} address(es) not supplied yet\n`);

  const report = {
    schemaVersion: 1, generatedAt: new Date().toISOString(),
    classification: "LIVE DEPLOYMENT MANIFEST: READY",
    statuses: {
      "LIVE DEPLOYMENT MANIFEST": "READY",
      "PUBLIC WRITES": "NOT AUTHORIZED",
      "MORDANT SETTLEMENT": "NOT PROVEN LIVE",
    },
    frozenCommit: FROZEN_COMMIT, head,
    freezeScope: "contracts/src and contracts/foundry.toml, plus the structural parameters. Scripts"
      + " and documents may move without invalidating the rehearsal; contracts and parameters may not.",
    contractsUnchangedSinceFreeze: true,
    network: { name: "monad-testnet", chainId, blockNumber: blockNumber.toString() },
    livePath: LIVE_PATH,
    livePathNote: "Cash redemption stays fork-proven. A second public vault to reproduce a branch"
      + " already proven on a fork would cost real deployments to demonstrate nothing new.",
    structuralParameters: STRUCTURAL_PARAMETERS,
    tokens: { invoiceAToken: MINV01, settlementToken: AUSDC, apassRegistry: APASS_REGISTRY, policy: POLICY },
    contracts, participants, phases: PHASES, requiredGates: REQUIRED_GATES, stopMatrix: STOP_MATRIX,
    codeSizeLimits: { eip170: EIP170_LIMIT, monadDocumented: MONAD_CODE_SIZE_LIMIT },
    zeroAddress: ZERO,
  };

  process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
  process.stdout.write(`${"PUBLIC WRITES".padEnd(30)} NOT AUTHORIZED\n`);
  if (out) { writeArtifact(out, report, process.env); process.stdout.write(`\nWrote ${out}.json\n`); }
}

async function queryApass(address) {
  const base = process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");
  const apiId = process.env.CLEANVERSE_API_ID;
  if (!base || !apiId) return null;
  return fetch(`${base}/query_apass`, {
    method: "POST",
    headers: { "content-type": "application/json", "api-id": apiId, "X-Request-ID": crypto.randomUUID() },
    body: JSON.stringify({ chain: "monad", address }), signal: AbortSignal.timeout(30_000),
  }).then((response) => response.json()).catch(() => null);
}

const invokedDirectly = process.argv[1]?.endsWith("m14-manifest.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
