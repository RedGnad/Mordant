#!/usr/bin/env node
/**
 * M-08: can a Cleanverse A-Pass be issued to a CONTRACT address?
 *
 * Every Mordant settlement path moves aUSDC to or from a contract, the vault or the CVA adapter,
 * and the A-Token policy checks both sides of a transfer. So each of those contracts needs its own
 * A-Pass. No deployed contract holds one today, and issuance to a non-EOA has never been observed,
 * which makes this the dependency that decides whether the current architecture works at all.
 *
 * The question is settled against a disposable probe rather than against a vault, because a negative
 * answer would force a design change and should cost as little as possible to discover.
 *
 *   node --env-file=.env scripts/m08-contract-apass.mjs --check       read-only, the default
 *   node --env-file=.env scripts/m08-contract-apass.mjs --run --out <prefix>
 *
 * --run deploys the probe and requests an A-Pass for it, and --out is mandatory with it, so a run
 * that spends gas always leaves an artifact, including when it stops. The shared controls in
 * ./runner-controls.mjs enforce the rest.
 *
 * The signing key belongs to the wallet owner. This runner reads it from the environment and never
 * generates, derives, requests or persists one.
 *
 * No private key, seed phrase or other secret material is logged or persisted. Public addresses,
 * signatures, transaction hashes, blocks and readbacks may be recorded where required.
 */
import { createCipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createWalletClient, encodeDeployData, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  ControlError, assertChainId, assertFundedFor, assertGasUsable, assertKeyMatchesAddress,
  assertWriteAllowed, checkpointPending, scrub, writeArtifact,
} from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACT = join(ROOT, "contracts/out/CleanverseAPassProbe.sol/CleanverseAPassProbe.json");

const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

const APASS_ADDRESS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const AUSDC = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D";
const POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";

/** One year, matching what M-07 used, so the A-Pass gate's expiry rule is satisfied. */
const APASS_LIFETIME_SECONDS = 365 * 24 * 3600;

/** A deployment costs more than a transfer, so the ceiling is higher, and still bounded. */
const GAS_LIMIT_CEILING = 2_000_000n;

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const POLICY_ABI = [
  { type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] },
];

/** Re-exported so callers and tests have one error type to catch across every runner. */
export { ControlError as StopError } from "./runner-controls.mjs";

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};


/**
 * Reads the A-Pass verdict for an address without deciding the mission outcome: unlike M-07, a
 * negative answer here is a RESULT to record, not an error. Only a malformed or missing response
 * is a failure.
 */
export function classifyApassResponse(envelope, onchainValid, blockTimestamp) {
  if (envelope?.code === undefined) {
    stop("query_apass returned no envelope code, so the A-Pass state could not be determined.");
  }
  if (envelope.code !== "0000") {
    return { present: false, onchainValid, envelopeCode: envelope.code,
      detail: String(envelope.message ?? "").slice(0, 200) };
  }
  const data = envelope.data;
  if (!data || typeof data !== "object") {
    return { present: false, onchainValid, envelopeCode: envelope.code,
      detail: "successful envelope carrying no record" };
  }
  const expiration = Number(data.expirationTime);
  return {
    present: true, onchainValid, envelopeCode: envelope.code,
    status: Number(data.status), tier: data.tier ?? null, subTier: data.subTier ?? null,
    expirationTime: Number.isFinite(expiration) ? expiration : null,
    expired: Number.isFinite(expiration) && expiration > 0
      ? expiration <= Number(blockTimestamp) : null,
    usable: Number(data.status) === 1 && Number.isFinite(expiration) && expiration > 0
      && expiration > Number(blockTimestamp) && onchainValid === true,
  };
}

/**
 * The verdict. Every one of five independent conditions must hold: Cleanverse accepted the request,
 * the record reads back usable, verify_apass agrees for this exact token, and the policy permits the
 * contract to RECEIVE and to SEND.
 *
 * Both directions are required because a vault that can be paid but cannot pay out is not a usable
 * settlement endpoint, and a credential the policy refuses in either direction is one nobody can
 * rely on. A reverting or unread canTransfer is never read as permission.
 */
export function classifyOutcome({ requestAccepted, apass, verifyCode, canReceive, canSend }) {
  if (!requestAccepted) return "CONTRACT APASS: REFUSED BY CLEANVERSE";
  if (!apass?.usable) return "CONTRACT APASS: ACCEPTED BUT NOT USABLE";
  if (Number(verifyCode) !== 4) return "CONTRACT APASS: ACCEPTED BUT NOT USABLE";
  if (canReceive !== true || canSend !== true) {
    return "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED";
  }
  return "CONTRACT APASS: PROVEN";
}

const base = () => process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");

async function cleanverse(path, body) {
  if (!base() || !process.env.CLEANVERSE_API_ID) return { unavailable: true };
  const response = await fetch(`${base()}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "api-id": process.env.CLEANVERSE_API_ID,
      "X-Request-ID": crypto.randomUUID() },
    body: JSON.stringify(body), signal: AbortSignal.timeout(60_000),
  });
  return response.json();
}

/** Encrypts an outbound request body. The key is used here and never printed or stored. */
function encryptBody(payload) {
  const key = Buffer.from(String(process.env.CLEANVERSE_API_KEY).trim(), "base64");
  const cipher = createCipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(true);
  return { data: Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), "utf8")), cipher.final()]).toString("base64") };
}

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const mode = argv.includes("--run") ? "run" : "check";
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const steps = [];
  const note = (label, detail) => {
    steps.push({ label, detail });
    process.stdout.write(`  ${label.padEnd(34)} ${detail}\n`);
  };

  const report = {
    schemaVersion: 1,
    runStartedAt: new Date().toISOString(),
    generatedAt: null,
    mode,
    status: "RUNNING",
    outcome: mode === "check" ? "READ-ONLY PREFLIGHT — NOTHING DEPLOYED" : "PENDING",
    question:
      "Can a Cleanverse A-Pass be issued to a contract address, and does the A-Token policy then"
      + " let an A-Token reach that contract? Settled against a disposable probe, never a vault.",
    scope: "This proves nothing about Mordant settlement. No vault, adapter, pledge or invoice"
      + " A-Token is involved.",
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

  process.stdout.write(`M-08 contract A-Pass probe, mode=${mode}\n\n`);
  const client = createPublicClient({ transport: http(MONAD_RPC) });

  const chainId = await assertChainId(client);
  assertWriteAllowed(mode, "run", out);
  note("network", `chain ${chainId}`);

  const blockNumber = await client.getBlockNumber();
  const block = await client.getBlock({ blockNumber });
  note("pinned block", `${blockNumber} ${block.hash}`);
  report.network = { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(),
    blockHash: block.hash, blockTimestamp: block.timestamp.toString() };

  // The baseline this mission exists to challenge: no known contract holds an A-Pass.
  const knownContracts = {
    AccessCore: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
    DepositGateway: "0x8e084646080a35347B2D053Dd72F550f12245c8B",
    aUsdcToken: AUSDC,
    policy: POLICY,
    apassRegistry: APASS_ADDRESS,
  };
  const baseline = [];
  for (const [name, address] of Object.entries(knownContracts)) {
    const code = await client.getCode({ address });
    const valid = await client.readContract({
      address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
    baseline.push({ name, address, isContract: Boolean(code && code !== "0x"), isValidAPass: valid });
  }
  report.baseline = baseline;
  note("baseline", `${baseline.filter((entry) => entry.isValidAPass).length}`
    + ` of ${baseline.length} known contracts hold an A-Pass`);

  const ownerRole = process.env.MORDANT_M08_OWNER_ROLE ?? "HOLDER_A";
  const ownerAddress = process.env[`MORDANT_ADDRESS_${ownerRole}`];
  if (!ownerAddress) stop(`MORDANT_ADDRESS_${ownerRole} must be set.`);
  note("probe owner", `${ownerRole} ${ownerAddress}`);

  const compiled = JSON.parse(readFileSync(ARTIFACT, "utf8"));
  const bytecode = compiled.bytecode?.object;
  if (!bytecode || bytecode === "0x") {
    stop("the compiled probe has no bytecode. Run forge build --root contracts first.");
  }
  const deployData = encodeDeployData({ abi: compiled.abi, bytecode, args: [ownerAddress] });
  note("probe bytecode", `${(bytecode.length - 2) / 2} bytes`);

  let gasEstimate;
  let gasPrice;
  try {
    gasEstimate = await client.estimateGas({ account: ownerAddress, data: deployData });
  } catch (error) {
    stop(`deployment gas could not be estimated: ${(error.shortMessage ?? error.message).slice(0, 160)}`);
  }
  try {
    gasPrice = await client.getGasPrice();
  } catch (error) {
    stop(`gas price could not be read: ${(error.shortMessage ?? error.message).slice(0, 160)}`);
  }
  const budget = assertGasUsable(gasEstimate, gasPrice, GAS_LIMIT_CEILING);
  const ownerNative = await client.getBalance({ address: ownerAddress });
  note("deployment gas", `estimate ${gasEstimate}, price ${gasPrice} wei, budget ${budget} wei`);
  assertFundedFor(ownerAddress, ownerNative, budget);
  report.gas = { estimate: gasEstimate.toString(), price: gasPrice.toString(),
    budgetWei: budget.toString(), ownerNativeWei: ownerNative.toString() };
  checkpoint();

  if (mode !== "run") {
    report.status = "COMPLETE";
    process.stdout.write(`\n${"OUTCOME".padEnd(34)} ${report.outcome}\n`);
    process.stdout.write(`${"DEPLOYMENT".padEnd(34)} check mode does not deploy; pass --run --out to deploy\n`);
    if (out) { checkpoint(); process.stdout.write(`\nWrote ${out}.json\n`); }
    return;
  }

  // --- deploy the probe ---
  const key = process.env[`MORDANT_KEY_${ownerRole}`];
  assertKeyMatchesAddress(ownerRole, key, ownerAddress, privateKeyToAccount);
  const account = privateKeyToAccount(key);
  const wallet = createWalletClient({ account, transport: http(MONAD_RPC) });
  const deployHash = await wallet.deployContract({
    abi: compiled.abi, bytecode, args: [ownerAddress], chain: null });
  report.deployment = { hash: deployHash, status: "PENDING", probeAddress: null };
  checkpointPending(report, deployHash, out, process.env);
  process.stdout.write(`\n  deploy hash ${deployHash}, checkpointed PENDING\n`);

  const receipt = await client.waitForTransactionReceipt({ hash: deployHash });
  const probeAddress = receipt.contractAddress;
  report.deployment = { hash: deployHash, status: receipt.status,
    blockNumber: receipt.blockNumber.toString(), blockHash: receipt.blockHash,
    gasUsed: receipt.gasUsed.toString(), probeAddress };
  checkpoint();
  if (receipt.status !== "success" || !probeAddress) stop(`the probe deployment failed. Hash ${deployHash}.`);
  const probeCode = await client.getCode({ address: probeAddress });
  note("probe deployed", `${probeAddress}, ${(probeCode.length - 2) / 2} bytes of code`);

  // --- request an A-Pass for the CONTRACT address ---
  const customerId = `mordantm08probe${receipt.blockNumber}`.replace(/[^A-Za-z0-9]/g, "").slice(0, 40);
  const expirationTime = Math.floor(Date.now() / 1000) + APASS_LIFETIME_SECONDS;
  const request = { customerId, expirationTime, wallet: { chain: "monad", address: probeAddress } };
  const response = scrub(await cleanverse("/generate_apass", encryptBody(request)));
  const requestAccepted = response?.code === "0000";
  report.apassRequest = { customerId, expirationTime, address: probeAddress,
    envelopeCode: response?.code ?? null, message: String(response?.message ?? "").slice(0, 300),
    accepted: requestAccepted, data: requestAccepted ? response.data : null };
  note("generate_apass", `${response?.code} "${String(response?.message ?? "").slice(0, 90)}"`);
  checkpoint();

  // --- read back, on chain and through the API ---
  const onchainValid = await client.readContract({
    address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [probeAddress] });
  const record = scrub(await cleanverse("/query_apass", { chain: "monad", address: probeAddress }));
  const apass = classifyApassResponse(record, onchainValid, block.timestamp);
  note("isValidAPass(probe)", String(onchainValid));
  note("query_apass", apass.present
    ? `status ${apass.status} tier ${apass.tier} expiry ${apass.expirationTime} usable ${apass.usable}`
    : `absent (${apass.envelopeCode}) ${apass.detail}`);

  const verify = scrub(await cleanverse("/verify_apass", { chain: "monad", atoken: AUSDC, address: probeAddress }));
  const verifyCode = verify?.code === "0000" ? Number(verify.data?.code) : null;
  note("verify_apass(probe)", `code ${verifyCode} "${verify?.data?.message ?? verify?.message}"`);

  // The decisive read: would the policy let aUSDC reach this contract?
  let canReceive = null;
  let canReceiveDetail = null;
  try {
    canReceive = await client.readContract({
      address: POLICY, abi: POLICY_ABI, functionName: "canTransfer",
      args: [AUSDC, ownerAddress, probeAddress, 1n] });
    canReceiveDetail = `returned ${canReceive}`;
  } catch (error) {
    canReceiveDetail = (error.shortMessage ?? error.message).slice(0, 160);
  }
  note("canTransfer(owner->probe)", canReceiveDetail);

  // And the reverse direction, which a vault paying out would need.
  let canSend = null;
  let canSendDetail = null;
  try {
    canSend = await client.readContract({
      address: POLICY, abi: POLICY_ABI, functionName: "canTransfer",
      args: [AUSDC, probeAddress, ownerAddress, 1n] });
    canSendDetail = `returned ${canSend}`;
  } catch (error) {
    canSendDetail = (error.shortMessage ?? error.message).slice(0, 160);
  }
  note("canTransfer(probe->owner)", canSendDetail);

  report.readback = { onchainValid, apass, verifyApassCode: verifyCode,
    canReceive, canReceiveDetail, canSend, canSendDetail };
  report.outcome = classifyOutcome({ requestAccepted, apass, verifyCode, canReceive, canSend });
  report.statuses = {
    "CONTRACT APASS ISSUANCE": requestAccepted && apass?.usable ? "PROVEN" : "NOT PROVEN",
    "CONTRACT APASS POLICY — RECEIVE": canReceive === true ? "PASSED" : "FAILED",
    "CONTRACT APASS POLICY — SEND": canSend === true ? "PASSED" : "FAILED",
    // Reading that a transfer is permitted is not the same as having moved value to and from
    // the contract. No aUSDC has been sent to this probe.
    "CONTRACT AUSDC LIVE ROUND-TRIP": "NOT PROVEN",
  };
  report.status = "COMPLETE";

  process.stdout.write(`\n${"OUTCOME".padEnd(34)} ${report.outcome}\n`);
  checkpoint();
  process.stdout.write(`\nWrote ${out}.json\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m08-contract-apass.mjs");
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
