#!/usr/bin/env node
/**
 * Read-only qualification of the deployed recourse Adapter V2 demo configuration.
 *
 * Every address is derived from the adapter's own immutables, never from a literal in
 * this file: the adapter names its verifier, its settlement token and its facility, and
 * this script asks the chain what those are before it asks whether they qualify. The two
 * holders are the only inputs, because a holder is a choice rather than a contract fact.
 *
 * It sends no transaction, holds no key and reads no secret. It exits non-zero when any
 * required gate is false, so it can gate a release rather than merely describe one.
 *
 * Usage:
 *   node scripts/verify-recourse-v2-demo-config.mjs
 *   node scripts/verify-recourse-v2-demo-config.mjs --json
 *   node scripts/verify-recourse-v2-demo-config.mjs --block 51444751
 */
import { createPublicClient, defineChain, getAddress, http } from "viem";

import { ControlError, MONAD_CHAIN_ID, assertChainId } from "./runner-controls.mjs";

export const ADAPTER_V2 = "0xbe67DB4F8a1a884C809884eA45c4dD4376B01b18";
export const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
/**
 * Both holders are dedicated, key-controlled EOAs provisioned for this demo.
 *
 * An A-Pass is not custody. The previous holderA, 0x911F99f424D47F08a15fcC771e94dcc2f7252B02,
 * carries a valid A-Pass and passes every policy gate, yet no local key derives to it, so it
 * could never have signed ParticipantAdmissionV1 in the browser. Their keys live in the
 * gitignored .env under MORDANT_KEY_RECOURSE_HOLDER_A and MORDANT_KEY_RECOURSE_HOLDER_B,
 * deliberately NOT under the M-05 runner's MORDANT_KEY_HOLDER_A/B role slots, because that
 * overlap is what disguised an uncontrolled wallet as a holder in the first place.
 */
export const HOLDER_A = "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685";
export const HOLDER_B = "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9";
/** Deliberately unqualified. It proves the gates discriminate rather than always pass. */
export const NEGATIVE_CONTROL = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
/** Privileged addresses, kept separate from the two holders on purpose. */
export const PRIVILEGED = Object.freeze({
  owner: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45",
  facility: "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6",
  attestor: "0xEe3260bA47D097DE5a8601107e1b83454593617c",
});
/** A-Passed but not key-controlled, so never a holder. */
export const UNCONTROLLED_APASS_WALLET = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";

export const ROLE_FACILITY = 3;
export const ROLE_HOLDER = 4;

/** Atomic units of a six-decimal settlement token. 4000 atomic units is 0.004 aUSDC. */
export const PAYOUT_A_ATOMIC = 2400n;
export const PAYOUT_B_ATOMIC = 1600n;

const RPC = process.env.MONAD_RPC_URL ?? process.env.NEXT_PUBLIC_MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

const ADAPTER_ABI = [
  { type: "function", name: "settlementToken", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "cviVerifier", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "facility", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "attestor", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "availableReserve", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "openReserved", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "entitledUnpaid", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "solvent", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "cureWindow", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
];
const VERIFIER_ABI = [
  { type: "function", name: "isEligible", stateMutability: "view", inputs: [{ type: "address" }, { type: "uint8" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "hasValidIdentity", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "isAssetTransferAllowed", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "openRoleMask", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "grantedRoleMask", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
];
const ERC20_ABI = [
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
];

// ------------------------------------------------------------------ pure helpers

/**
 * Checksums an address and refuses anything that is not one.
 *
 * Comparisons downstream are string equality, so a lowercase readback and a checksummed
 * literal would silently disagree. Everything is normalized through here first.
 */
export function normalizeAddress(value, label = "address") {
  if (typeof value !== "string") throw new ControlError(`${label} must be a string, received ${typeof value}`);
  const trimmed = value.trim();
  if (!/^0x[0-9a-fA-F]{40}$/u.test(trimmed)) throw new ControlError(`${label} is not a 20-byte address: ${trimmed}`);
  if (/^0x0{40}$/u.test(trimmed)) throw new ControlError(`${label} must not be the zero address`);
  return getAddress(trimmed);
}

export function sameAddress(a, b) {
  return normalizeAddress(a) === normalizeAddress(b);
}

/** Atomic units to a human string, without floating point. */
export function formatAtomic(atomic, decimals) {
  const units = BigInt(atomic);
  const scale = 10n ** BigInt(decimals);
  const whole = units / scale;
  const frac = (units % scale).toString().padStart(Number(decimals), "0").replace(/0+$/u, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

/**
 * The payout split, checked against what the adapter can actually pay.
 *
 * The reserve is the ceiling, not a suggestion: `consumeGovernedRelease` reverts with
 * InsufficientReserve when the total exceeds it, so a plan that does not fit is not a
 * plan. Nothing here is rounded up to make a nicer human number.
 */
export function planPayouts(availableReserve, payoutA = PAYOUT_A_ATOMIC, payoutB = PAYOUT_B_ATOMIC) {
  const reserve = BigInt(availableReserve);
  const a = BigInt(payoutA);
  const b = BigInt(payoutB);
  if (a <= 0n || b <= 0n) throw new ControlError("both payouts must be strictly positive");
  const total = a + b;
  return {
    payoutA: a,
    payoutB: b,
    total,
    availableReserve: reserve,
    fits: total <= reserve,
    allocationBps: total === 0n ? null : { a: Number((a * 10_000n) / total), b: Number((b * 10_000n) / total) },
  };
}

/**
 * Collapses the readbacks into named gates.
 *
 * Fail-closed by construction: a gate is satisfied only when its observation is exactly
 * `true`. A missing key, a null from a reverted call or the string "true" all read as
 * false, so an unanswered question can never be scored as a passing one.
 */
export function evaluateGates(observed) {
  const o = observed ?? {};
  const gate = (value) => value === true;
  const gates = {
    "holderA A-Pass valid": gate(o.holderAApass),
    "holderB A-Pass valid": gate(o.holderBApass),
    "holderA holder role": gate(o.holderARole),
    "holderB holder role": gate(o.holderBRole),
    "holderA and holderB distinct": gate(o.holdersDistinct),
    "funder to adapter permitted": gate(o.funderToAdapter),
    "adapter to holderA permitted": gate(o.adapterToHolderA),
    "adapter to holderB permitted": gate(o.adapterToHolderB),
    "facility A-Pass valid": gate(o.facilityApass),
    "facility ROLE_FACILITY": gate(o.facilityRole),
    "cure authorization will pass": gate(o.cureAuthorized),
    "payouts fit available reserve": gate(o.payoutsFit),
    "adapter solvent": gate(o.solvent),
    "MINV01 untouched by the adapter": gate(o.minv01Untouched),
    "negative control still refused": gate(o.negativeControlRefused),
    "holders separate from privileged roles": gate(o.holdersNotPrivileged),
    "holders are not the uncontrolled A-Pass wallet": gate(o.holdersNotUncontrolled),
  };
  const failed = Object.entries(gates).filter(([, ok]) => !ok).map(([name]) => name);
  return { gates, failed, ok: failed.length === 0 };
}

// ------------------------------------------------------------------ chain

const monad = defineChain({
  id: MONAD_CHAIN_ID,
  name: "monad-testnet",
  nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/** The public endpoint rate-limits, and a rate-limit must not read as a failed gate. */
async function retry(fn, attempts = 6) {
  let last;
  for (let i = 0; i < attempts; i += 1) {
    try { return await fn(); } catch (error) { last = error; await sleep(1200 * (i + 1)); }
  }
  throw last;
}

export async function collect({ client, blockNumber, holderA = HOLDER_A, holderB = HOLDER_B } = {}) {
  const at = blockNumber === undefined ? {} : { blockNumber: BigInt(blockNumber) };
  const adapter = normalizeAddress(ADAPTER_V2, "adapter");
  const read = (address, abi, functionName, args) =>
    retry(() => client.readContract({ address, abi, functionName, args, ...at }));

  // Everything structural comes from the adapter itself.
  const verifier = normalizeAddress(await read(adapter, ADAPTER_ABI, "cviVerifier"), "verifier");
  const settlementToken = normalizeAddress(await read(adapter, ADAPTER_ABI, "settlementToken"), "settlementToken");
  const facility = normalizeAddress(await read(adapter, ADAPTER_ABI, "facility"), "facility");
  const owner = normalizeAddress(await read(adapter, ADAPTER_ABI, "owner"), "owner");
  const attestor = normalizeAddress(await read(adapter, ADAPTER_ABI, "attestor"), "attestor");

  const a = normalizeAddress(holderA, "holderA");
  const b = normalizeAddress(holderB, "holderB");
  const control = normalizeAddress(NEGATIVE_CONTROL, "negativeControl");

  const availableReserve = await read(adapter, ADAPTER_ABI, "availableReserve");
  const openReserved = await read(adapter, ADAPTER_ABI, "openReserved");
  const entitledUnpaid = await read(adapter, ADAPTER_ABI, "entitledUnpaid");
  const solvent = await read(adapter, ADAPTER_ABI, "solvent");
  const cureWindow = await read(adapter, ADAPTER_ABI, "cureWindow");
  const decimals = await read(settlementToken, ERC20_ABI, "decimals");
  const tokenBalance = await read(settlementToken, ERC20_ABI, "balanceOf", [adapter]);
  const minv01Balance = await read(normalizeAddress(MINV01, "minv01"), ERC20_ABI, "balanceOf", [adapter]);

  const plan = planPayouts(availableReserve);

  const observed = {
    holderAApass: await read(verifier, VERIFIER_ABI, "hasValidIdentity", [a]),
    holderBApass: await read(verifier, VERIFIER_ABI, "hasValidIdentity", [b]),
    holderARole: await read(verifier, VERIFIER_ABI, "isEligible", [a, ROLE_HOLDER]),
    holderBRole: await read(verifier, VERIFIER_ABI, "isEligible", [b, ROLE_HOLDER]),
    holdersDistinct: a !== b,
    // The funder leg is the holder who actually tops the reserve up.
    funderToAdapter: await read(verifier, VERIFIER_ABI, "isAssetTransferAllowed", [settlementToken, a, adapter, plan.total]),
    adapterToHolderA: await read(verifier, VERIFIER_ABI, "isAssetTransferAllowed", [settlementToken, adapter, a, plan.payoutA]),
    adapterToHolderB: await read(verifier, VERIFIER_ABI, "isAssetTransferAllowed", [settlementToken, adapter, b, plan.payoutB]),
    facilityApass: await read(verifier, VERIFIER_ABI, "hasValidIdentity", [facility]),
    facilityRole: await read(verifier, VERIFIER_ABI, "isEligible", [facility, ROLE_FACILITY]),
    payoutsFit: plan.fits,
    solvent,
    minv01Untouched: minv01Balance === 0n,
    // A gate that never says no proves nothing, so the control is read every run.
    negativeControlRefused: (await read(verifier, VERIFIER_ABI, "isEligible", [control, ROLE_HOLDER])) === false,
    // A payout beneficiary must not also be the owner, the cure authority or the bridge signer.
    holdersNotPrivileged: ![owner, facility, attestor].some((p) => p === a || p === b),
    // An A-Pass is not custody, so the wallet nobody holds a key for is never a holder.
    holdersNotUncontrolled: ![a, b].includes(normalizeAddress(UNCONTROLLED_APASS_WALLET)),
  };
  // `cure` calls _requireEligible(msg.sender, ROLE_FACILITY) after msg.sender == facility.
  observed.cureAuthorized = observed.facilityRole === true && observed.facilityApass === true;

  return {
    chainId: MONAD_CHAIN_ID,
    blockNumber: blockNumber === undefined ? await retry(() => client.getBlockNumber()) : BigInt(blockNumber),
    adapter,
    verifier,
    settlementToken,
    facility,
    owner,
    attestor,
    holderA: a,
    holderB: b,
    negativeControl: control,
    decimals: Number(decimals),
    reserve: { availableReserve, openReserved, entitledUnpaid, tokenBalance },
    minv01: { address: normalizeAddress(MINV01, "minv01"), adapterBalance: minv01Balance },
    cureWindowSeconds: Number(cureWindow),
    openRoleMask: await read(verifier, VERIFIER_ABI, "openRoleMask"),
    facilityGrantedRoleMask: await read(verifier, VERIFIER_ABI, "grantedRoleMask", [facility]),
    plan,
    observed,
  };
}

function render(snapshot, result) {
  const s = snapshot;
  const line = (k, v) => process.stdout.write(`${String(k).padEnd(34)} ${v}\n`);
  process.stdout.write("\nRECOURSE ADAPTER V2 DEMO CONFIGURATION\n\n");
  line("chainId", s.chainId);
  line("blockNumber", s.blockNumber);
  line("adapter", s.adapter);
  line("verifier", s.verifier);
  line("settlementToken", `${s.settlementToken} (${s.decimals} decimals)`);
  line("holderA", s.holderA);
  line("holderB", s.holderB);
  line("negative control", s.negativeControl);
  line("facility", s.facility);
  line("owner", s.owner);
  line("attestor", s.attestor);
  process.stdout.write("\n");
  line("holderA A-Pass / role", `${s.observed.holderAApass} / ${s.observed.holderARole}`);
  line("holderB A-Pass / role", `${s.observed.holderBApass} / ${s.observed.holderBRole}`);
  line("facility A-Pass / ROLE_FACILITY", `${s.observed.facilityApass} / ${s.observed.facilityRole}`);
  line("openRoleMask", `${s.openRoleMask} (holder-only)`);
  line("grantedRoleMask(facility)", `${s.facilityGrantedRoleMask} (8 = ROLE_FACILITY)`);
  process.stdout.write("\n");
  line("funder -> adapter", s.observed.funderToAdapter);
  line("adapter -> holderA", s.observed.adapterToHolderA);
  line("adapter -> holderB", s.observed.adapterToHolderB);
  line("negative control refused", s.observed.negativeControlRefused);
  process.stdout.write("\n");
  line("payoutA", `${s.plan.payoutA} atomic (${formatAtomic(s.plan.payoutA, s.decimals)})`);
  line("payoutB", `${s.plan.payoutB} atomic (${formatAtomic(s.plan.payoutB, s.decimals)})`);
  line("total", `${s.plan.total} atomic (${formatAtomic(s.plan.total, s.decimals)})`);
  line("availableReserve", `${s.reserve.availableReserve} atomic (${formatAtomic(s.reserve.availableReserve, s.decimals)})`);
  line("openReserved", s.reserve.openReserved);
  line("entitledUnpaid", s.reserve.entitledUnpaid);
  line("token balance", s.reserve.tokenBalance);
  line("solvent", s.observed.solvent);
  line("MINV01 balance of adapter", `${s.minv01.adapterBalance} (untouched: ${s.observed.minv01Untouched})`);
  process.stdout.write("\nGATES\n");
  for (const [name, ok] of Object.entries(result.gates)) line(`  ${ok ? "PASS" : "FAIL"}`, name);
  process.stdout.write(`\n${result.ok
    ? "PASS: V2 PARTICIPANTS, FACILITY AND AUSDC POLICY QUALIFIED"
    : `FAIL: CLEANVERSE DEMO ROLES REMAIN INCOMPATIBLE (${result.failed.join("; ")})`}\n`);
}

async function main() {
  const argv = process.argv.slice(2);
  const asJson = argv.includes("--json");
  const blockIndex = argv.indexOf("--block");
  const blockNumber = blockIndex >= 0 ? argv[blockIndex + 1] : undefined;

  const client = createPublicClient({ chain: monad, transport: http(RPC) });
  await assertChainId(client);

  const snapshot = await collect({ client, blockNumber });
  const result = evaluateGates(snapshot.observed);

  if (asJson) {
    process.stdout.write(`${JSON.stringify({ ...snapshot, gates: result.gates, failed: result.failed, ok: result.ok },
      (key, value) => (typeof value === "bigint" ? value.toString() : value), 2)}\n`);
  } else {
    render(snapshot, result);
  }
  process.exitCode = result.ok ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : String(error?.stack ?? error)}\n`);
    process.exitCode = 1;
  });
}
