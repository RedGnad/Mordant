#!/usr/bin/env node
/**
 * M-12: the production adapter and minter path, prepared but not executed.
 *
 * Three read-only modes. None of them writes, deploys, grants or mints, and none accepts a flag
 * that would let it: the write paths are described as calldata for review, never sent.
 *
 *   node --env-file=.env scripts/m12-adapter-path.mjs --inspect [--out <prefix>]
 *   node --env-file=.env scripts/m12-adapter-path.mjs --apass   [--out <prefix>]
 *   node --env-file=.env scripts/m12-adapter-path.mjs --grant   [--out <prefix>]
 *
 * The plan is docs/m12-adapter-minter-path.md. The short version: MINTER_ROLE on this A-Token
 * authorises BURN, not mint. The adapter has no mint function; it burns during redemption. The
 * initial supply is minted to it by the admin wallet, and bindVault then demands that the whole
 * supply sits in the adapter and nowhere else.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, encodeFunctionData, http, keccak256, toBytes } from "viem";

import { ControlError, assertChainId, scrub, writeArtifact } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ADAPTER_ARTIFACT = join(ROOT, "contracts/out/CleanverseCvaAdapter.sol/CleanverseCvaAdapter.json");

const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

/** The invoice A-Token M-11 issued. */
const INVOICE_ATOKEN = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const APASS_ADDRESS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const EXPECTED_POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";

/** What the adapter's Solidity requires of its token, checked against the real one. */
const REQUIRED_TOKEN_SURFACE = Object.freeze([
  { name: "decimals", expect: (value) => Number(value) === 6, describe: "6, matching EXPECTED_DECIMALS" },
  { name: "policy", expect: (value) => String(value).toLowerCase() === EXPECTED_POLICY.toLowerCase(),
    describe: `the known policy ${EXPECTED_POLICY}` },
  { name: "MINTER_ROLE", expect: (value) => value === keccak256(toBytes("MINTER_ROLE")),
    describe: 'keccak256("MINTER_ROLE")' },
]);

/**
 * Every address that will need an A-Pass, derived from the transfer sites in the adapter and the
 * vault rather than from roles on paper, because the policy checks both sides of every transfer.
 */
export const APASS_ROSTER = Object.freeze([
  { role: "adapter", token: "MINV01", why: "holds the whole supply, burns it, transfers out on default",
    knownAddress: null },
  { role: "vault", token: "aUSDC", why: "_requireSettlementIdentity, and it both receives and pays",
    knownAddress: null },
  { role: "funder/buyer", token: "aUSDC", why: "sends the advance into the vault", knownAddress: null },
  { role: "originatorTreasury", token: "aUSDC", why: "receives net proceeds and returned bond",
    knownAddress: null },
  { role: "holder", token: "MINV01 and aUSDC",
    why: "receives units on default release, and settlement in aUSDC", knownAddress: null },
]);

const TOKEN_ABI = [
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
  { type: "function", name: "policy", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "MINTER_ROLE", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "totalSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "hasRole", stateMutability: "view",
    inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "getRoleAdmin", stateMutability: "view",
    inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "grantRole", stateMutability: "nonpayable",
    inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
];

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

export { ControlError as StopError } from "./runner-controls.mjs";

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * The stop condition this mission opens with: proceed only if a real adapter exists.
 *
 * A mock would satisfy the vault's interface while implementing none of the accounting invariants,
 * so binding one would look like progress and prove nothing.
 */
export function assertProductionAdapter({ productionExists, mockOnly, sourcePath }) {
  if (mockOnly || !productionExists) {
    stop("the repository contains no production adapter, only a mock. A mock satisfies the"
      + " interface while implementing none of the accounting invariants, so nothing may be"
      + " deployed or bound until a real one exists.");
  }
  return sourcePath;
}

/**
 * Confirms the issued token really offers what the adapter's Solidity calls.
 *
 * The adapter reads `decimals`, `policy`, `MINTER_ROLE`, `hasRole` and `burn`. A token missing any
 * of them would revert at bind time or, worse, at redemption time with custody already committed.
 */
export function checkTokenSurface(observations) {
  const results = REQUIRED_TOKEN_SURFACE.map(({ name, expect, describe }) => {
    const value = observations[name];
    const present = value !== undefined && value !== null;
    return { member: name, value: present ? String(value) : null, present,
      matches: present ? Boolean(expect(value)) : false, expected: describe };
  });
  return { members: results, ok: results.every((entry) => entry.present && entry.matches) };
}

/**
 * Describes the grant as data. Never a command line carrying a key, for the reason M-10 established:
 * a key in process arguments is visible to anything that can list processes.
 */
export function describeGrant({ token, minterRole, adapterAddress, adminAddress }) {
  return {
    target: token,
    signature: "grantRole(bytes32,address)",
    arguments: [minterRole, adapterAddress],
    calldata: adapterAddress
      ? encodeFunctionData({ abi: TOKEN_ABI, functionName: "grantRole",
        args: [minterRole, adapterAddress] })
      : null,
    mustBeSignedBy: adminAddress,
    authorises: "BURN. The adapter has no mint function; it burns during redemption.",
    note: "Not executed, and deliberately not expressed as a runnable command: any execution must"
      + " read the signing key from the environment, never from process arguments.",
  };
}

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const mode = argv.includes("--apass") ? "apass" : argv.includes("--grant") ? "grant" : "inspect";
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  for (const forbidden of ["--run", "--broadcast", "--deploy", "--execute"]) {
    if (argv.includes(forbidden)) {
      stop(`${forbidden} is not a mode of this runner. M-12 prepares the adapter path and executes`
        + " none of it: no deployment, no grant and no mint is authorised.");
    }
  }

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode,
    classification: "M-12 PREPARATION — NOTHING EXECUTED",
    scope: "Read-only preparation. No deployment, no MINTER_ROLE grant, no mint, no settlement."
      + " MORDANT SETTLEMENT: NOT PROVEN.",
  };
  const write = () => { if (out) { writeArtifact(out, report, process.env); return `${out}.json`; } return null; };

  const client = createPublicClient({ transport: http(MONAD_RPC) });
  const chainId = await assertChainId(client);
  const blockNumber = await client.getBlockNumber();
  report.network = { name: "monad-testnet", chainId, blockNumber: blockNumber.toString() };
  process.stdout.write(`M-12 adapter path, mode=${mode}, chain ${chainId}\n\n`);

  // --- the stop condition, in every mode ---
  let compiled;
  try {
    compiled = JSON.parse(readFileSync(ADAPTER_ARTIFACT, "utf8"));
  } catch (error) {
    stop(`the production adapter artifact could not be read (${error.message}).`
      + " Run forge build --root contracts first.");
  }
  const creationBytecode = compiled.bytecode?.object ?? "0x";
  assertProductionAdapter({
    productionExists: creationBytecode.length > 2, mockOnly: false,
    sourcePath: "contracts/src/cleanverse/CleanverseCvaAdapter.sol" });
  report.adapter = {
    source: "contracts/src/cleanverse/CleanverseCvaAdapter.sol",
    isProduction: true,
    creationBytecodeBytes: (creationBytecode.length - 2) / 2,
    deployedBytecodeBytes: ((compiled.deployedBytecode?.object ?? "0x").length - 2) / 2,
    constructor: "constructor(address initialOwner, ICleanverseAToken token, ICleanverseAPass apass)",
    bindGate: "bindVault refuses unless the vault points back at this adapter and token, decimals"
      + " are 6, the adapter holds a valid A-Pass and MINTER_ROLE, and the ENTIRE supply sits in the"
      + " adapter",
    mintsEver: false,
    burnsUnder: "MINTER_ROLE, in consumeOnRedemption",
  };
  process.stdout.write(`  production adapter        ${report.adapter.source}\n`);
  process.stdout.write(`  creation / deployed       ${report.adapter.creationBytecodeBytes}`
    + ` / ${report.adapter.deployedBytecodeBytes} bytes\n`);

  // --- the token surface the adapter depends on ---
  const observations = {};
  for (const { name } of REQUIRED_TOKEN_SURFACE) {
    observations[name] = await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: name }).catch(() => null);
  }
  const surface = checkTokenSurface(observations);
  const totalSupply = await client.readContract({
    address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "totalSupply" }).catch(() => null);
  report.token = { address: INVOICE_ATOKEN, surface,
    totalSupply: totalSupply === null ? null : totalSupply.toString() };
  for (const member of surface.members) {
    process.stdout.write(`  token.${member.member.padEnd(20)} ${member.value}`
      + ` ${member.matches ? "matches" : "DOES NOT MATCH"} ${member.expected}\n`);
  }
  process.stdout.write(`  token.totalSupply         ${totalSupply}\n`);
  if (!surface.ok) {
    stop("the issued token does not offer the surface the adapter requires. Binding it would revert"
      + " at bind time, or worse at redemption with custody already committed.");
  }

  const adminRole = process.env.MORDANT_M12_ADMIN_ROLE ?? "HOLDER_A";
  const adminAddress = process.env[`MORDANT_ADDRESS_${adminRole}`] ?? null;
  const adapterAddress = process.env.MORDANT_ADAPTER_ADDRESS ?? null;

  if (mode === "apass") {
    // Every address on the roster, with whatever is known about it today.
    const roster = [];
    for (const entry of APASS_ROSTER) {
      const address = entry.role === "adapter" ? adapterAddress : null;
      const valid = address ? await client.readContract({
        address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] })
        .catch(() => null) : null;
      roster.push({ ...entry, address, isValidAPass: valid,
        status: address === null ? "ADDRESS NOT KNOWN YET" : valid ? "A-PASS PRESENT" : "A-PASS MISSING" });
      process.stdout.write(`  ${entry.role.padEnd(20)} ${entry.token.padEnd(16)}`
        + ` ${address ?? "not deployed yet"}  ${roster.at(-1).status}\n`);
    }
    report.apassRoster = roster;
    report.note = "Only HOLDER_A, HOLDER_B and the M-08 probe hold an A-Pass today. Every address"
      + " above is new and must be issued and read back individually; nothing generalises from the"
      + " three that exist. The adapter's address is only known after deployment, and its A-Pass"
      + " must exist before bindVault.";
    process.stdout.write(`\n  ${report.note}\n`);
  }

  if (mode === "grant") {
    const minterRole = observations.MINTER_ROLE;
    const roleAdmin = await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "getRoleAdmin", args: [minterRole] })
      .catch(() => null);
    const adminCanGrant = roleAdmin && adminAddress ? await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "hasRole", args: [roleAdmin, adminAddress] })
      .catch(() => null) : null;
    const adapterHasMinter = adapterAddress ? await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "hasRole", args: [minterRole, adapterAddress] })
      .catch(() => null) : null;
    report.grant = {
      ...describeGrant({ token: INVOICE_ATOKEN, minterRole, adapterAddress, adminAddress }),
      roleAdmin, adminCanGrant, adapterHasMinterRole: adapterHasMinter,
      blocked: adapterAddress === null
        ? "the adapter is not deployed, so there is no address to grant to" : null,
    };
    report.statuses = {
      "MINTER ROLE": adapterHasMinter === true ? "HELD BY ADAPTER" : "NOT GRANTED",
      "MINT/BURN VIA MORDANT ADAPTER": "NOT PROVEN",
      "MORDANT SETTLEMENT": "NOT PROVEN",
    };
    process.stdout.write(`  MINTER_ROLE               ${minterRole}\n`);
    process.stdout.write(`  getRoleAdmin              ${roleAdmin}\n`);
    process.stdout.write(`  admin can grant           ${adminCanGrant}\n`);
    process.stdout.write(`  adapter address           ${adapterAddress ?? "not deployed yet"}\n`);
    process.stdout.write(`  calldata                  ${report.grant.calldata ?? "unavailable until deployed"}\n`);
    process.stdout.write(`\n  This grant authorises BURN. The adapter never mints.\n`);
  }

  report.scrubbedEnvironment = scrub({});
  delete report.scrubbedEnvironment;
  process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
  process.stdout.write(`${"EXECUTED".padEnd(30)} nothing\n`);
  const path = write();
  if (path) process.stdout.write(`\nWrote ${path}\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m12-adapter-path.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    const message = error instanceof ControlError ? error.message : `STOP — ${error.message}`;
    process.stderr.write(`\n${message}\n`);
    process.exitCode = 1;
  });
}
