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
 * The plan is docs/m12-adapter-minter-path.md. The role semantics matter and are easy to get wrong:
 *
 *   - MINTER_ROLE authorises BOTH mint and burn at the token level;
 *   - the ADAPTER uses it only to call burn, since it has no mint function of its own;
 *   - DEFAULT_ADMIN_ROLE lets its holder grant and revoke roles. It does NOT confer minting.
 *
 * Our admin wallet holds DEFAULT_ADMIN_ROLE and not MINTER_ROLE, so it cannot mint today: a
 * read-only simulation of mint reverts with AccessControlUnauthorizedAccount. Issuance therefore
 * needs its own grant/mint/revoke sequence, described here and executed nowhere.
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
const PROBE_ADDRESS = "0x0f8b9a0c064306f938912658c96c681d8655140b";
const EXPECTED_POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** What the adapter's Solidity requires of its token, checked against the real one. */
const REQUIRED_TOKEN_SURFACE = Object.freeze([
  { name: "decimals", expect: (value) => Number(value) === 6, describe: "6, matching EXPECTED_DECIMALS" },
  { name: "policy", expect: (value) => String(value).toLowerCase() === EXPECTED_POLICY.toLowerCase(),
    describe: `the known policy ${EXPECTED_POLICY}` },
  { name: "MINTER_ROLE", expect: (value) => value === keccak256(toBytes("MINTER_ROLE")),
    describe: 'keccak256("MINTER_ROLE")' },
]);

/**
 * Selectors the whole sequence depends on, checked in the implementation's bytecode. `mint` matters
 * as much as `burn`: without it the supply can never be created, and discovering that after
 * deploying an adapter would be the expensive way to find out.
 */
export const REQUIRED_SELECTORS = Object.freeze({
  "mint(address,uint256)": "0x40c10f19",
  "burn(address,uint256)": "0x9dc29fac",
  "hasRole(bytes32,address)": "0x91d14854",
  "getRoleAdmin(bytes32)": "0x248a9ca3",
  "grantRole(bytes32,address)": "0x2f2ff15d",
  "revokeRole(bytes32,address)": "0xd547741f",
});

/**
 * The six participants of MordantInvoiceVault.Init that touch a policy-gated token, with the
 * environment variable that will carry each address.
 *
 * Roles are kept per address rather than per slot, because one wallet may fill several: the roster
 * is deduplicated by address so a single A-Pass is not counted, or requested, twice.
 */
export const PARTICIPANTS = Object.freeze([
  { role: "adapter", initField: "cvaAdapter", env: "MORDANT_ADAPTER_ADDRESS", tokens: ["MINV01"],
    why: "holds the whole supply, burns it, transfers out on default" },
  { role: "vault", initField: "(the vault itself)", env: "MORDANT_VAULT_ADDRESS", tokens: ["aUSDC"],
    why: "_requireSettlementIdentity demands its own identity, and it both receives and pays" },
  { role: "buyer", initField: "buyer", env: "MORDANT_ADDRESS_BUYER", tokens: ["aUSDC"],
    why: "funds the advance into the vault and receives cash settlement" },
  { role: "originatorTreasury", initField: "originatorTreasury", env: "MORDANT_ADDRESS_ORIGINATOR",
    tokens: ["aUSDC"], why: "receives net proceeds and returned bond" },
  { role: "holderA", initField: "holders[0]", env: "MORDANT_ADDRESS_HOLDER_A",
    tokens: ["MINV01", "aUSDC"], why: "receives units on default release, and settlement" },
  { role: "holderB", initField: "holders[1]", env: "MORDANT_ADDRESS_HOLDER_B",
    tokens: ["MINV01", "aUSDC"], why: "receives units on default release, and settlement" },
]);

/**
 * Resolves the roster against the environment and deduplicates by address.
 *
 * An address already holding an A-Pass is not a new requirement: HOLDER_A, HOLDER_B and the M-08
 * probe were issued in earlier missions, and reporting them as missing would overstate the work
 * left.
 */
export function buildRoster(env, apassByAddress = {}) {
  const byAddress = new Map();
  for (const participant of PARTICIPANTS) {
    const address = env[participant.env] ?? null;
    const key = address ? address.toLowerCase() : `unresolved:${participant.role}`;
    const existing = byAddress.get(key);
    if (existing) {
      existing.roles.push(participant.role);
      existing.initFields.push(participant.initField);
      for (const token of participant.tokens) {
        if (!existing.tokens.includes(token)) existing.tokens.push(token);
      }
      continue;
    }
    byAddress.set(key, {
      address, roles: [participant.role], initFields: [participant.initField],
      tokens: [...participant.tokens], env: participant.env, why: participant.why,
      isValidAPass: address ? apassByAddress[address.toLowerCase()] ?? null : null,
    });
  }
  return [...byAddress.values()].map((entry) => ({
    ...entry,
    status: entry.address === null
      ? "ADDRESS NOT KNOWN YET"
      : entry.isValidAPass === true ? "A-PASS PRESENT" : "A-PASS MISSING",
  }));
}

/**
 * The exact transfer tuples the policy will be asked about, on both tokens.
 *
 * Written out rather than described, because "the adapter and the holders need an A-Pass" hides
 * which direction each check runs in, and the policy checks both sides.
 */
export function transferTuples(addresses) {
  const { adapter, vault, buyer, originatorTreasury, holderA, holderB } = addresses;
  return [
    { token: "MINV01", label: "mint to adapter", from: ZERO_ADDRESS, to: adapter },
    { token: "MINV01", label: "burn from adapter", from: adapter, to: ZERO_ADDRESS },
    { token: "MINV01", label: "default release to holderA", from: adapter, to: holderA },
    { token: "MINV01", label: "default release to holderB", from: adapter, to: holderB },
    { token: "aUSDC", label: "advance in", from: buyer, to: vault },
    { token: "aUSDC", label: "net proceeds out", from: vault, to: originatorTreasury },
    { token: "aUSDC", label: "settlement to holderA", from: vault, to: holderA },
    { token: "aUSDC", label: "settlement to holderB", from: vault, to: holderB },
    { token: "aUSDC", label: "cash redemption to buyer", from: vault, to: buyer },
  ];
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

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
  { type: "function", name: "revokeRole", stateMutability: "nonpayable",
    inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "mint", stateMutability: "nonpayable",
    inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
];

const ADAPTER_ABI = [
  { type: "function", name: "token", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "apass", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "boundVault", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
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
/**
 * Preconditions on the adapter address before any grant calldata is produced.
 *
 * Granting MINTER_ROLE to the wrong address, or to an adapter already bound or pointing at another
 * token, would hand mint and burn authority to something outside the reviewed configuration. The
 * calldata is therefore withheld unless every one of these holds.
 */
export function checkAdapterPreconditions({ code, token, apass, owner, boundVault, expected }) {
  const reasons = [];
  if (!code || code === "0x") reasons.push("the adapter address has no code");
  if (String(token ?? "").toLowerCase() !== String(expected.token).toLowerCase()) {
    reasons.push(`token() is ${token}, expected ${expected.token}`);
  }
  if (String(apass ?? "").toLowerCase() !== String(expected.apass).toLowerCase()) {
    reasons.push(`apass() is ${apass}, expected ${expected.apass}`);
  }
  if (String(owner ?? "").toLowerCase() !== String(expected.owner).toLowerCase()) {
    reasons.push(`owner() is ${owner}, expected ${expected.owner}`);
  }
  if (String(boundVault ?? "").toLowerCase() !== ZERO_ADDRESS) {
    reasons.push(`boundVault() is ${boundVault}, expected the zero address; this adapter is already bound`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * The issuance sequence, needed because DEFAULT_ADMIN_ROLE does not confer minting.
 *
 * The admin can grant but not mint. So a wallet has to be given MINTER_ROLE, mint the exact supply,
 * and have the role taken back: leaving an open minter on a token whose supply is meant to be fixed
 * would let the adapter's accounting invariant be broken from outside.
 */
export function describeIssuanceSequence({ token, minterRole, issuanceWallet, adapterAddress, units, adminAddress }) {
  // Encoding is best-effort: a missing or malformed argument yields no calldata rather than
  // crashing the runner, so an incomplete configuration still produces a reviewable plan.
  const encode = (functionName, args) => {
    if (args.some((value) => value === null || value === undefined)) return null;
    try {
      return encodeFunctionData({ abi: TOKEN_ABI, functionName, args });
    } catch {
      return null;
    }
  };
  const step = (signature, args, functionName) => ({
    target: token, signature, arguments: args.map(String),
    calldata: encode(functionName, args),
    mustBeSignedBy: functionName === "mint" ? issuanceWallet : adminAddress,
  });
  return {
    required: true,
    reason: "the admin holds DEFAULT_ADMIN_ROLE but not MINTER_ROLE, so it can grant and revoke but"
      + " cannot mint. A read-only simulation of mint from it reverts.",
    steps: [
      { order: 1, description: "grant MINTER_ROLE to the issuance wallet",
        ...step("grantRole(bytes32,address)", [minterRole, issuanceWallet], "grantRole") },
      { order: 2, description: "mint the exact supply to the adapter",
        ...step("mint(address,uint256)", [adapterAddress, units], "mint") },
      { order: 3, description: "revoke MINTER_ROLE from the issuance wallet",
        ...step("revokeRole(bytes32,address)", [minterRole, issuanceWallet], "revokeRole") },
    ],
    note: "Not executed. Step 3 is not optional: bindVault requires the supply to equal the adapter"
      + " balance exactly, and an open minter could break that invariant afterwards.",
  };
}

export function describeGrant({ token, minterRole, adapterAddress, adminAddress }) {
  return {
    target: token,
    signature: "grantRole(bytes32,address)",
    arguments: [minterRole, adapterAddress],
    calldata: (() => {
      if (!adapterAddress) return null;
      try {
        return encodeFunctionData({ abi: TOKEN_ABI, functionName: "grantRole",
          args: [minterRole, adapterAddress] });
      } catch {
        return null;
      }
    })(),
    mustBeSignedBy: adminAddress,
    authorises: "mint and burn at the token level. The ADAPTER only ever calls burn, having no mint"
      + " function of its own, so this grant exists for the redemption path.",
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
    classification: "PLAN / READ-ONLY INSPECTION / NO FORK EXECUTION",
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

  // The implementation must exist and carry code, and every selector the sequence depends on must
  // be present in it. `mint` matters as much as `burn`: without it no supply can ever be created.
  const implementationWord = await client.getStorageAt({
    address: INVOICE_ATOKEN, slot: EIP1967_IMPLEMENTATION_SLOT });
  const implementation = implementationWord && !/^0x0+$/.test(implementationWord)
    ? `0x${implementationWord.slice(-40)}` : null;
  if (!implementation) stop("the invoice A-Token proxy has no implementation set.");
  const implementationCode = await client.getCode({ address: implementation });
  const implementationCodeBytes = implementationCode ? (implementationCode.length - 2) / 2 : 0;
  if (implementationCodeBytes === 0) stop(`the implementation ${implementation} has no code.`);
  const selectors = Object.entries(REQUIRED_SELECTORS).map(([signature, selector]) => ({
    signature, selector, present: implementationCode.includes(selector.slice(2)) }));
  const missing = selectors.filter((entry) => !entry.present);
  if (missing.length > 0) {
    stop(`the implementation is missing ${missing.map((entry) => entry.signature).join(", ")}.`
      + " The issuance and redemption sequence could not complete.");
  }

  report.token = { address: INVOICE_ATOKEN, surface, implementation, implementationCodeBytes,
    selectors, totalSupply: totalSupply === null ? null : totalSupply.toString() };
  for (const member of surface.members) {
    process.stdout.write(`  token.${member.member.padEnd(20)} ${member.value}`
      + ` ${member.matches ? "matches" : "DOES NOT MATCH"} ${member.expected}\n`);
  }
  process.stdout.write(`  token.totalSupply         ${totalSupply}\n`);
  process.stdout.write(`  token.implementation      ${implementation}, ${implementationCodeBytes} bytes,`
    + ` all ${selectors.length} required selectors present\n`);
  if (!surface.ok) {
    stop("the issued token does not offer the surface the adapter requires. Binding it would revert"
      + " at bind time, or worse at redemption with custody already committed.");
  }
  // Fail-closed: a non-zero supply means units already exist somewhere, and bindVault requires the
  // whole supply to sit in the adapter. Planning a mint on top of an unexplained balance is unsafe.
  if (totalSupply === null) stop("totalSupply could not be read.");
  if (totalSupply !== 0n) {
    stop(`the invoice A-Token already has a supply of ${totalSupply}. bindVault requires the entire`
      + " supply to sit in the adapter, so an existing balance must be explained and reconciled"
      + " before any further mint is planned.");
  }

  const adminRole = process.env.MORDANT_M12_ADMIN_ROLE ?? "HOLDER_A";
  const adminAddress = process.env[`MORDANT_ADDRESS_${adminRole}`] ?? null;

  if (mode === "apass") {
    const addresses = Object.fromEntries(PARTICIPANTS.map(
      (participant) => [participant.role, process.env[participant.env] ?? null]));
    const apassByAddress = {};
    for (const address of new Set(Object.values(addresses).filter(Boolean))) {
      apassByAddress[address.toLowerCase()] = await client.readContract({
        address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] })
        .catch(() => null);
    }
    const roster = buildRoster(process.env, apassByAddress);
    report.apassRoster = roster;
    report.transferTuples = transferTuples({
      adapter: addresses.adapter, vault: addresses.vault, buyer: addresses.buyer,
      originatorTreasury: addresses.originatorTreasury,
      holderA: addresses.holderA, holderB: addresses.holderB });
    for (const entry of roster) {
      process.stdout.write(`  ${entry.roles.join("+").padEnd(20)} ${entry.tokens.join("+").padEnd(14)}`
        + ` ${(entry.address ?? `unset (${entry.env})`).padEnd(44)} ${entry.status}\n`);
    }
    process.stdout.write("\n  transfer tuples the policy will be asked about:\n");
    for (const tuple of report.transferTuples) {
      process.stdout.write(`    ${tuple.token.padEnd(7)} ${tuple.label.padEnd(28)}`
        + ` ${(tuple.from ?? "?")} -> ${(tuple.to ?? "?")}\n`);
    }
    report.note = "HOLDER_A and HOLDER_B already hold an A-Pass from earlier missions and are not"
      + " new requirements. The adapter and vault addresses only exist after deployment, and the"
      + " adapter's A-Pass must precede bindVault.";
    process.stdout.write(`\n  ${report.note}\n`);
  }

  if (mode === "grant") {
    const minterRole = observations.MINTER_ROLE;
    const roleAdmin = await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "getRoleAdmin", args: [minterRole] })
      .catch(() => null);
    const adminHoldsRoleAdmin = roleAdmin && adminAddress ? await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "hasRole", args: [roleAdmin, adminAddress] })
      .catch(() => null) : null;

    // DEFAULT_ADMIN_ROLE grants and revokes; it does not mint. So the question is asked directly.
    const adminIsMinter = adminAddress ? await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "hasRole", args: [minterRole, adminAddress] })
      .catch(() => null) : null;
    let mintSimulation = "not attempted";
    if (adminAddress) {
      try {
        await client.simulateContract({ address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "mint",
          args: [PROBE_ADDRESS, 1n], account: adminAddress });
        mintSimulation = "would succeed";
      } catch (error) {
        mintSimulation = `would revert: ${(error.shortMessage ?? error.message).slice(0, 120)}`;
      }
    }

    const adapterAddress = process.env.MORDANT_ADAPTER_ADDRESS ?? null;
    let preconditions = { ok: false, reasons: ["the adapter is not deployed, so it cannot be checked"] };
    if (adapterAddress) {
      const readAdapter = (functionName) => client.readContract({
        address: adapterAddress, abi: ADAPTER_ABI, functionName }).catch(() => null);
      preconditions = checkAdapterPreconditions({
        code: await client.getCode({ address: adapterAddress }),
        token: await readAdapter("token"), apass: await readAdapter("apass"),
        owner: await readAdapter("owner"), boundVault: await readAdapter("boundVault"),
        expected: { token: INVOICE_ATOKEN, apass: APASS_ADDRESS, owner: adminAddress },
      });
    }
    const adapterHasMinter = adapterAddress ? await client.readContract({
      address: INVOICE_ATOKEN, abi: TOKEN_ABI, functionName: "hasRole", args: [minterRole, adapterAddress] })
      .catch(() => null) : null;

    // The calldata is withheld unless the adapter is exactly the reviewed configuration.
    const grant = preconditions.ok
      ? describeGrant({ token: INVOICE_ATOKEN, minterRole, adapterAddress, adminAddress })
      : { withheld: true, reasons: preconditions.reasons,
          note: "No grant calldata is produced for an adapter that is not verified." };

    report.mintAuthority = { adminAddress, roleAdmin, adminHoldsRoleAdmin, adminIsMinter,
      mintSimulation,
      semantics: "MINTER_ROLE authorises mint AND burn on the token. The adapter uses it only for"
        + " burn. DEFAULT_ADMIN_ROLE grants and revokes roles and confers no minting." };
    report.adapterPreconditions = { adapterAddress, ...preconditions };
    report.grant = { ...grant, adapterHasMinterRole: adapterHasMinter };
    report.issuanceSequence = adminIsMinter === true ? { required: false,
      reason: "the admin already holds MINTER_ROLE and can mint directly." }
      : describeIssuanceSequence({ token: INVOICE_ATOKEN, minterRole,
        issuanceWallet: process.env.MORDANT_ISSUANCE_WALLET ?? adminAddress,
        adapterAddress, units: process.env.MORDANT_INITIAL_UNITS ?? null, adminAddress });
    report.statuses = {
      "MINTER ROLE": adapterHasMinter === true ? "HELD BY ADAPTER" : "NOT GRANTED",
      "MINT/BURN VIA MORDANT ADAPTER": "NOT PROVEN",
      "MORDANT SETTLEMENT": "NOT PROVEN",
    };
    process.stdout.write(`  MINTER_ROLE               ${minterRole}\n`);
    process.stdout.write(`  getRoleAdmin              ${roleAdmin}\n`);
    process.stdout.write(`  admin holds role admin    ${adminHoldsRoleAdmin}\n`);
    process.stdout.write(`  admin holds MINTER_ROLE   ${adminIsMinter}\n`);
    process.stdout.write(`  simulated mint from admin ${mintSimulation}\n`);
    process.stdout.write(`  adapter                   ${adapterAddress ?? "not deployed yet"}\n`);
    process.stdout.write(`  adapter preconditions     ${preconditions.ok ? "ok" : preconditions.reasons.join("; ")}\n`);
    process.stdout.write(`  grant calldata            ${grant.calldata ?? "withheld"}\n`);
    if (report.issuanceSequence.required) {
      process.stdout.write(`\n  Issuance needs its own sequence, because the admin cannot mint:\n`);
      for (const step of report.issuanceSequence.steps) {
        process.stdout.write(`    ${step.order}. ${step.description}\n`);
      }
    }
  }

  report.scrubbedEnvironment = scrub({});
  delete report.scrubbedEnvironment;
  process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
  process.stdout.write(`${"EXECUTED".padEnd(30)} nothing, on chain or on a fork\n`);
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
