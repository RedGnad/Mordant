#!/usr/bin/env node
/**
 * M-15: the live execution runners, one per phase.
 *
 * Every phase is a separate command that consumes the previous phase's artifact and stops. None
 * triggers the next, and none broadcasts: --run is implemented and refused, because public writes
 * are not authorized. What is missing is the authorization, not the code.
 *
 *   node --env-file=.env scripts/m15-phase-runner.mjs --phase A --check
 *   node --env-file=.env scripts/m15-phase-runner.mjs --phase B --check --from <phase-A>.json
 *
 * Ambiguous Cleanverse operations are never retried automatically: a request that may have been
 * accepted must be reconciled by hand, or the second attempt creates a duplicate credential.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, http, keccak256 } from "viem";

import {
  KNOWN_INPUTS, REQUIRED_INPUTS, assessReadiness,
  loadParticipants, loadPreviousArtifact, nextPhase, packageStatus, resolveMode,
} from "./m15-phase-lib.mjs";
import { ControlError, assertChainId, scrub, writeArtifact } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

const AUSDC = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D";
const APASS_REGISTRY = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";

/** Gas each phase's heaviest transaction needs, plus headroom, in wei at a 200 gwei ceiling. */
const MON_PER_PHASE = 200_000_000_000n * 8_000_000n;

/**
 * What each phase does, what it must verify, and what it costs. The runner walks this rather than
 * branching, so every phase carries the same gates by construction.
 */
export const PHASE_PLAN = Object.freeze({
  A: { name: "adapter deployment",
    writes: ["deploy CleanverseCvaAdapter(owner, MINV01, A-Pass registry)"],
    verifies: ["runtime hash against the frozen artifact", "owner(), token(), apass()",
      "boundVault() == address(0)"],
    signer: "holderA", cleanverse: [] },
  B: { name: "adapter credential",
    writes: ["request the adapter's A-Pass through the Cleanverse gateway"],
    verifies: ["the credential through the API and on chain",
      "MINV01 policy: zero to adapter, adapter to zero, adapter to each holder"],
    signer: null, cleanverse: ["generate_apass"],
    ambiguityRule: "never retried automatically; an accepted-but-unconfirmed request is reconciled by hand" },
  C1: { name: "infrastructure and known participants",
    writes: ["deploy CleanverseAPassVerifier", "deploy MordantFactory",
      "setRoleEligibility for every participant", "setFacility, setCvaAdapter, setSettlementToken",
      "request A-Passes for every address already known"],
    verifies: ["both runtime hashes", "role eligibility readbacks", "allowlist readbacks",
      "funding: the funder holds the advance, every signer holds MON"],
    signer: "holderA", cleanverse: ["generate_apass"],
    ambiguityRule: "as phase B" },
  C2: { name: "just-in-time vault creation",
    writes: ["createInvoiceVault from the buyer", "request the vault's A-Pass"],
    verifies: ["the vault address from InvoiceVaultCreated", "protectionEnd computed from that block",
      "the nine exact policy tuples"],
    signer: "buyer", cleanverse: ["generate_apass"],
    note: "run only when D and E can follow immediately: creation starts the 24 hour clock",
    ambiguityRule: "as phase B" },
  D: { name: "supply ceremony and binding",
    writes: ["grantRole MINTER_ROLE to the issuance wallet", "mint exactly initialUnits to the adapter",
      "revokeRole from the issuance wallet", "grantRole MINTER_ROLE to the adapter", "bindVault"],
    verifies: ["the reconstructed active minter set is exactly the adapter",
      "totalSupply and adapter balance equal initialUnits", "VaultBound, then availableBalance"],
    signer: "holderA", cleanverse: [] },
  E: { name: "activation",
    writes: ["the funder approves aUSDC", "the protected facility calls activate"],
    verifies: ["net proceeds, bond, receipts", "cvaAccounted and the adapter's available credit",
      "assertAccounting()"],
    signer: "facilityProtected", cleanverse: [],
    note: "the originator signs the EIP-712 pledge but sends nothing" },
  F: { name: "recourse demonstration",
    writes: ["commitConflict", "revealConflict", "finalizeConflict", "markDefault",
      "releaseDefaultCva by each holder"],
    verifies: ["MINV01 transferred without its supply falling", "receipt units burned",
      "cvaReleasedFace and defaultCvaReleaseStarted", "assertAccounting()"],
    signer: "facilityChallenger", cleanverse: [],
    note: "the only phase with real waiting: one hour to the cure, then twenty-four to default" },
});

const CONTRACT_FOR_PHASE = Object.freeze({
  A: [["CleanverseCvaAdapter", "CleanverseCvaAdapter.sol/CleanverseCvaAdapter"]],
  C1: [["CleanverseAPassVerifier", "CleanverseAPassVerifier.sol/CleanverseAPassVerifier"],
    ["MordantFactory", "MordantFactory.sol/MordantFactory"]],
  C2: [["MordantInvoiceVault", "MordantInvoiceVault.sol/MordantInvoiceVault"]],
});

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/** The frozen runtime hash each deployment of this phase must produce. */
export function expectedRuntimeHashes(phase, read = (relative) =>
  JSON.parse(readFileSync(join(ROOT, `contracts/out/${relative}.json`), "utf8"))) {
  return (CONTRACT_FOR_PHASE[phase] ?? []).map(([name, relative]) => {
    const parsed = read(relative);
    return { name, expectedRuntimeHash: keccak256(parsed.deployedBytecode.object),
      runtimeBytes: (parsed.deployedBytecode.object.length - 2) / 2 };
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const phaseIndex = argv.indexOf("--phase");
  const phase = phaseIndex === -1 ? null : argv[phaseIndex + 1];
  if (!phase || !PHASE_PLAN[phase]) {
    stop(`--phase must be one of ${Object.keys(PHASE_PLAN).join(", ")}.`);
  }
  const fromIndex = argv.indexOf("--from");
  const from = fromIndex === -1 ? null : argv[fromIndex + 1] ?? null;
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;

  // Refuses --run outright: the runners are complete, the authorization is not granted.
  const mode = resolveMode(argv);
  const plan = PHASE_PLAN[phase];
  process.stdout.write(`M-15 phase ${phase}: ${plan.name}, mode=${mode}\n\n`);

  const client = createPublicClient({ transport: http(MONAD_RPC) });
  const chainId = await assertChainId(client);
  const blockNumber = await client.getBlockNumber();
  process.stdout.write(`  network                    chain ${chainId}, block ${blockNumber}\n`);

  // The preceding artifact, refused unless it is the right phase and reports SUCCESS.
  const previous = from ? loadPreviousArtifact(phase, from) : null;
  if (previous) {
    process.stdout.write(`  previous phase             ${previous.phase} SUCCESS, ${from}\n`);
  } else if (phase !== "A") {
    process.stdout.write(`  previous phase             not supplied; --from is required to run\n`);
  }

  // Configuration: reported rather than fatal in check mode, so every gap is listed at once.
  const { participants, missing, complete } = loadParticipants(process.env, { requireAll: false });
  process.stdout.write(`  addresses supplied         ${Object.keys(participants).length}`
    + ` of ${KNOWN_INPUTS.length + REQUIRED_INPUTS.length}\n`);
  if (missing.length > 0) {
    process.stdout.write(`  addresses missing          ${missing.join(", ")}\n`);
  }

  // Readiness of whatever is configured, so the owner sees funding gaps before authorizing.
  const apassAbi = [{ type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }];
  const erc20Abi = [{ type: "function", name: "balanceOf", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] }];
  const assessments = [];
  for (const input of [...KNOWN_INPUTS, ...REQUIRED_INPUTS]) {
    const address = participants[input.key];
    if (!address) continue;
    const [isValidAPass, mon, aUsdc] = await Promise.all([
      client.readContract({ address: APASS_REGISTRY, abi: apassAbi, functionName: "isValidAPass", args: [address] }).catch(() => null),
      client.getBalance({ address }).catch(() => null),
      client.readContract({ address: AUSDC, abi: erc20Abi, functionName: "balanceOf", args: [address] }).catch(() => null),
    ]);
    assessments.push(assessReadiness({ key: input.key, address, isValidAPass, monBalance: mon,
      aUsdcBalance: aUsdc, requiredMon: MON_PER_PHASE, requiredAUsdc: input.needsAUsdc }));
  }
  for (const entry of assessments) {
    process.stdout.write(`  ${entry.key.padEnd(20)} ${entry.ready ? "ready" : entry.problems.join(", ")}\n`);
  }

  const contracts = expectedRuntimeHashes(phase);
  for (const contract of contracts) {
    process.stdout.write(`  ${contract.name.padEnd(20)} expects runtime ${contract.expectedRuntimeHash.slice(0, 18)}...`
      + ` (${contract.runtimeBytes} B)\n`);
  }

  const { next, instruction } = nextPhase(phase);
  const statuses = packageStatus({ runnersComplete: true, inputsComplete: complete });
  const report = {
    schemaVersion: 1, phase, phaseName: plan.name, generatedAt: new Date().toISOString(),
    mode,
    // A check run never claims SUCCESS: only an executed phase can, and none has executed.
    status: "CHECK ONLY",
    statuses,
    network: { name: "monad-testnet", chainId, blockNumber: blockNumber.toString() },
    consumesArtifactFromPhase: previous?.phase ?? null,
    plan: { writes: plan.writes, verifies: plan.verifies, signer: plan.signer,
      cleanverse: plan.cleanverse, note: plan.note ?? null,
      ambiguityRule: plan.ambiguityRule ?? null },
    expectedContracts: contracts,
    participants: scrub(participants), missingAddresses: missing, inputsComplete: complete,
    readiness: assessments,
    nextPhase: next, nextPhaseInstruction: instruction,
    monPerSignerWei: MON_PER_PHASE.toString(),
  };

  process.stdout.write("\n");
  for (const [key, value] of Object.entries(statuses)) {
    process.stdout.write(`${key.padEnd(28)} ${value}\n`);
  }
  process.stdout.write(`${"NEXT".padEnd(28)} ${instruction}\n`);
  if (out) { writeArtifact(out, report, process.env); process.stdout.write(`\nWrote ${out}.json\n`); }
}

const invokedDirectly = process.argv[1]?.endsWith("m15-phase-runner.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
