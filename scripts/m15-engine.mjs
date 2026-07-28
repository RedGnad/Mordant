/**
 * M-15 execution engine: the real transactions, decomposed into resumable sub-actions.
 *
 * Each sub-action is one deliberate command that performs its own writes, verifies its own events
 * and readbacks, writes an artifact, and stops. None triggers the next.
 *
 * The engine executes for real against an injected client, so it can be exercised end to end on
 * Anvil or a fork. Monad public is gated by PUBLIC_WRITES_AUTHORIZED below, which is a source
 * constant and deliberately not readable from the environment: an operator who wants a public run
 * has to change reviewed code, not export a variable.
 *
 * The transaction logic reuses what M-07 through M-13 proved rather than restating it: the same
 * ceremony order, the same reconciliation, the same refusals.
 */
import { keccak256, parseEventLogs, toBytes } from "viem";

import { ControlError, assertGasUsable, assertKeyMatchesAddress } from "./runner-controls.mjs";
import { assertAllReady, assertOnlyExpectedMinter, assertRuntimeHash } from "./m15-phase-lib.mjs";

/**
 * Public writes are NOT authorized. This is a constant, not a setting: making it an environment
 * variable would put the last gate before real value inside a file anyone can edit in passing.
 */
export const PUBLIC_WRITES_AUTHORIZED = false;

export const MONAD_PUBLIC_CHAIN_ID = 10_143;
export const MINTER_ROLE = keccak256(toBytes("MINTER_ROLE"));

export const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
export const AUSDC = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D";
export const APASS_REGISTRY = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
export const POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
export const ZERO = "0x0000000000000000000000000000000000000000";

export const INITIAL_UNITS = 100_000n;
export const ADVANCE_AMOUNT = 100_000n;
export const FACE_VALUE = 110_000n;
export const BOND = 10_000n;
export const NET_PROCEEDS = 90_000n;
export const ALLOCATION = 50_000n;
export const PROTECTION_DURATION_SECONDS = 86_400n;
export const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
export const INVOICE_ROOT = `0x${"c3".repeat(32)}`;

const GAS_CAP = 8_000_000n;

const fail = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * Every sub-action, in order, with the signer it needs and the artifact it consumes.
 *
 * D, E and F are not single-signer steps and are not represented as such: the grant, the mint and
 * the binding are signed by different wallets, and an engine that collapsed them would hide a
 * resume point exactly where the ceremony is most exposed.
 */
export const STEPS = Object.freeze([
  { id: "A.deploy", phase: "A", signer: "holderA", needs: null,
    description: "deploy CleanverseCvaAdapter and verify its runtime and readbacks" },
  { id: "B.apass", phase: "B", signer: null, needs: "A.deploy", cleanverse: true,
    description: "request the adapter's A-Pass, exactly once" },
  { id: "C1.infra", phase: "C1", signer: "holderA", needs: "B.apass",
    description: "deploy verifier and factory, configure roles and allowlists" },
  { id: "C2.vault", phase: "C2", signer: "buyer", needs: "C1.infra", cleanverse: true,
    description: "create the vault, read its address, compute protectionEnd, prepare its A-Pass" },
  { id: "D.grant", phase: "D", signer: "holderA", needs: "C2.vault",
    description: "grant MINTER_ROLE to the temporary issuance wallet" },
  { id: "D.mint", phase: "D", signer: "issuanceMinter", needs: "D.grant",
    description: "mint exactly initialUnits to the adapter" },
  { id: "D.revokeGrant", phase: "D", signer: "holderA", needs: "D.mint",
    description: "revoke the issuance wallet, then grant MINTER_ROLE to the adapter" },
  { id: "D.bind", phase: "D", signer: "holderA", needs: "D.revokeGrant",
    description: "reconstruct the active minters, then bindVault" },
  { id: "E.sign", phase: "E", signer: "originator", needs: "D.bind", offchain: true,
    description: "the originator signs the EIP-712 pledge and sends nothing" },
  { id: "E.approve", phase: "E", signer: "funder", needs: "E.sign",
    description: "the funder approves the advance in aUSDC" },
  { id: "E.activate", phase: "E", signer: "facilityProtected", needs: "E.approve",
    description: "activate, then verify net proceeds, bond, receipts and accounting" },
  { id: "F.commit", phase: "F", signer: "facilityChallenger", needs: "E.activate",
    description: "the challenger commits the conflict" },
  { id: "F.reveal", phase: "F", signer: "facilityChallenger", needs: "F.commit",
    description: "the challenger reveals the conflicting signed pledge" },
  { id: "F.finalize", phase: "F", signer: "holderA", needs: "F.reveal",
    description: "finalizeConflict, after the real cure window" },
  { id: "F.markDefault", phase: "F", signer: "holderA", needs: "F.finalize",
    description: "markDefault, after the real protectionEnd" },
  { id: "F.releaseA", phase: "F", signer: "holderA", needs: "F.markDefault",
    description: "holderA releases its MINV01 units" },
  { id: "F.releaseB", phase: "F", signer: "holderB", needs: "F.releaseA",
    description: "holderB releases its MINV01 units" },
]);

export const STEP_IDS = Object.freeze(STEPS.map((step) => step.id));

export function stepById(id) {
  const step = STEPS.find((entry) => entry.id === id);
  if (!step) fail(`${id} is not a known sub-action. Known: ${STEP_IDS.join(", ")}`);
  return step;
}

/** A sub-action names its successor and never runs it. */
export function nextStep(id) {
  const index = STEP_IDS.indexOf(id);
  if (index === -1) fail(`${id} is not a known sub-action.`);
  const next = STEP_IDS[index + 1] ?? null;
  return { next, instruction: next === null
    ? "This is the final sub-action."
    : `STOP. ${next} is a separate, deliberate command and is never triggered from here.` };
}

/**
 * The authorization gate.
 *
 * A non-public chain may execute: that is how the engine is proven. Monad public may not, and the
 * only thing that would change it is editing PUBLIC_WRITES_AUTHORIZED in reviewed source.
 */
export function assertRunAllowed({ chainId, authorized = PUBLIC_WRITES_AUTHORIZED }) {
  if (Number(chainId) !== MONAD_PUBLIC_CHAIN_ID) return "non-public";
  if (authorized !== true) {
    fail("this is Monad public and PUBLIC_WRITES_AUTHORIZED is false. The gate is a source"
      + " constant, not an environment variable: authorizing a public run means editing reviewed"
      + " code, not exporting a setting.");
  }
  return "public";
}

/**
 * Everything a run-mode sub-action must satisfy before it sends anything.
 */
export function assertRunPreconditions({ step, previousArtifact, participants, readiness, signerKey,
  toAccount }) {
  if (step.needs !== null && !previousArtifact) {
    fail(`${step.id} consumes the ${step.needs} artifact; pass --from <path>. A sub-action never`
      + " runs against an assumed predecessor.");
  }
  if (previousArtifact && previousArtifact.step !== step.needs) {
    fail(`${step.id} consumes ${step.needs}, but the artifact is for ${previousArtifact.step}.`);
  }
  if (previousArtifact && previousArtifact.status !== "SUCCESS") {
    fail(`the ${step.needs} artifact reports ${previousArtifact.status}, not SUCCESS.`);
  }
  const missing = [];
  for (const key of ["holderA", "holderB", "buyer", "funder", "originator", "facilityProtected",
    "facilityChallenger", "issuanceMinter"]) {
    if (!participants?.[key]) missing.push(key);
  }
  if (missing.length > 0) {
    fail(`${step.id} needs every address before it can run; missing ${missing.join(", ")}.`);
  }
  assertAllReady(readiness ?? []);
  if (step.signer !== null) {
    // The key must derive the signer this specific sub-action requires, not merely some configured
    // wallet: signing a grant with the buyer's key would revert, late and expensively.
    assertKeyMatchesAddress(step.signer, signerKey, participants[step.signer], toAccount);
  }
  return true;
}

/**
 * One transaction: simulate, send, checkpoint PENDING before awaiting, then verify.
 *
 * The checkpoint is the point. From the moment the hash exists the transaction is real whether or
 * not this process survives, so the artifact records it before anything can be awaited.
 */
export async function sendTracked({ client, wallet, request, gasCap = GAS_CAP, checkpoint,
  label }) {
  let gas;
  let gasPrice;
  try {
    gas = await client.estimateContractGas(request);
  } catch (error) {
    fail(`${label} could not be estimated: ${(error.shortMessage ?? error.message).slice(0, 160)}`);
  }
  try {
    gasPrice = await client.getGasPrice();
  } catch (error) {
    fail(`${label}: the gas price could not be read: ${(error.shortMessage ?? error.message).slice(0, 120)}`);
  }
  assertGasUsable(gas, gasPrice, gasCap);
  await client.simulateContract(request);

  const hash = await wallet.writeContract({ ...request, chain: null });
  await checkpoint?.({ hash, status: "PENDING" });

  const receipt = await client.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    fail(`${label} reverted. Hash ${hash}.`);
  }
  return { hash, receipt, gas: gas.toString(), gasPrice: gasPrice.toString() };
}

/** A raw transaction, for the observed A-Pass issuance call whose ABI is unpublished. */
export async function sendRawTracked({ client, wallet, to, data, checkpoint, label }) {
  const hash = await wallet.sendTransaction({ to, data, value: 0n, chain: null, gas: 2_000_000n });
  await checkpoint?.({ hash, status: "PENDING" });
  const receipt = await client.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") fail(`${label} reverted. Hash ${hash}.`);
  return { hash, receipt };
}

/**
 * Exactly-once handling for a Cleanverse request.
 *
 * An ambiguous response is never retried. It is recorded as AMBIGUOUS with the marker needed to
 * reconcile by hand, because a retry after an accepted-but-unconfirmed request is how a second
 * credential gets created.
 */
export async function requestOnce({ marker, priorMarkers = [], perform }) {
  if (priorMarkers.includes(marker)) {
    fail(`a request with marker ${marker} was already submitted. It is never re-sent: reconcile`
      + " against the gateway by hand instead.");
  }
  let response;
  try {
    response = await perform();
  } catch (error) {
    return { outcome: "AMBIGUOUS", marker,
      detail: `the call did not return: ${String(error.message).slice(0, 200)}`,
      note: "It may still have been accepted. NOT retried; reconcile by hand." };
  }
  if (response?.code !== "0000") {
    return { outcome: "REJECTED", marker, code: response?.code ?? null,
      detail: String(response?.message ?? "").slice(0, 200) };
  }
  return { outcome: "ACCEPTED", marker, data: response.data ?? null };
}

/** Computed from the creation block, never a date fixed in advance. */
export function protectionEndFrom(creationBlockTimestamp) {
  if (typeof creationBlockTimestamp !== "bigint" || creationBlockTimestamp <= 0n) {
    fail("protectionEnd must be computed from the creation block timestamp.");
  }
  return creationBlockTimestamp + PROTECTION_DURATION_SECONDS;
}

/** Reconstructs the active minter set from events, in block then log-index order. */
export function activeMintersFrom(events) {
  const active = new Set();
  const ordered = [...events].sort((a, b) => {
    if (BigInt(a.blockNumber) !== BigInt(b.blockNumber)) {
      return BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : 1;
    }
    return Number(a.logIndex) - Number(b.logIndex);
  });
  for (const event of ordered) {
    if (String(event.role).toLowerCase() !== MINTER_ROLE.toLowerCase()) continue;
    const account = String(event.account).toLowerCase();
    if (event.name === "RoleGranted") active.add(account);
    if (event.name === "RoleRevoked") active.delete(account);
  }
  return [...active];
}

export const TOKEN_ABI = [
  { type: "function", name: "totalSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "hasRole", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "grantRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "revokeRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
  { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "event", name: "RoleGranted", inputs: [
    { name: "role", type: "bytes32", indexed: true }, { name: "account", type: "address", indexed: true },
    { name: "sender", type: "address", indexed: true }] },
  { type: "event", name: "RoleRevoked", inputs: [
    { name: "role", type: "bytes32", indexed: true }, { name: "account", type: "address", indexed: true },
    { name: "sender", type: "address", indexed: true }] },
];

export const ADAPTER_ABI = [
  { type: "function", name: "token", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "apass", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "boundVault", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "availableBalance", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "bindVault", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
];

export const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

export const POLICY_ABI = [
  { type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] },
];

/**
 * Masks the immutable regions before hashing.
 *
 * A contract with `immutable` fields has its constructor arguments burned into the deployed
 * runtime, so the raw bytes never equal the artifact's deployedBytecode, whose immutable slots are
 * zero placeholders. Comparing raw hashes would reject every correct deployment of the adapter.
 * Zeroing exactly the regions Foundry records leaves the code itself compared, byte for byte.
 */
export function normalizeRuntime(code, immutableReferences = {}) {
  const bytes = Buffer.from(String(code).slice(2), "hex");
  for (const references of Object.values(immutableReferences ?? {})) {
    for (const { start, length } of references) {
      bytes.fill(0, start, start + length);
    }
  }
  return `0x${bytes.toString("hex")}`;
}

/** The comparable hash of a deployed contract: immutables masked, everything else exact. */
export function runtimeFingerprint(code, immutableReferences) {
  return keccak256(normalizeRuntime(code, immutableReferences));
}

/** Verifies a freshly deployed adapter is the reviewed contract, wired as the manifest expects. */
export async function verifyAdapter({ client, adapter, expectedRuntimeHash, owner,
  immutableReferences = {} }) {
  const code = await client.getCode({ address: adapter });
  assertRuntimeHash("adapter", code ? runtimeFingerprint(code, immutableReferences) : null,
    expectedRuntimeHash);
  const readbacks = {
    token: await client.readContract({ address: adapter, abi: ADAPTER_ABI, functionName: "token" }),
    apass: await client.readContract({ address: adapter, abi: ADAPTER_ABI, functionName: "apass" }),
    owner: await client.readContract({ address: adapter, abi: ADAPTER_ABI, functionName: "owner" }),
    boundVault: await client.readContract({ address: adapter, abi: ADAPTER_ABI, functionName: "boundVault" }),
  };
  const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
  const problems = [];
  if (!same(readbacks.token, MINV01)) problems.push(`token() is ${readbacks.token}`);
  if (!same(readbacks.apass, APASS_REGISTRY)) problems.push(`apass() is ${readbacks.apass}`);
  if (!same(readbacks.owner, owner)) problems.push(`owner() is ${readbacks.owner}`);
  if (!same(readbacks.boundVault, ZERO)) problems.push(`boundVault() is ${readbacks.boundVault}, not zero`);
  if (problems.length > 0) fail(`the deployed adapter is not wired as expected: ${problems.join("; ")}`);
  return { ...readbacks, runtimeFingerprint: runtimeFingerprint(code, immutableReferences),
    runtimeBytes: (code.length - 2) / 2 };
}

/** The nine tuples, on both tokens, for the exact amounts the ceremony will move. */
export async function readNineTuples({ client, adapter, vault, participants }) {
  const can = async (token, from, to, amount, label) => ({ label, token, from, to,
    amount: amount.toString(),
    answer: await client.readContract({ address: POLICY, abi: POLICY_ABI, functionName: "canTransfer",
      args: [token, from, to, amount] }).catch(() => false) });
  return [
    await can(MINV01, ZERO, adapter, INITIAL_UNITS, "MINV01 mint to adapter"),
    await can(MINV01, adapter, ZERO, INITIAL_UNITS, "MINV01 burn from adapter"),
    await can(MINV01, adapter, participants.holderA, ALLOCATION, "MINV01 release to holderA"),
    await can(MINV01, adapter, participants.holderB, ALLOCATION, "MINV01 release to holderB"),
    await can(AUSDC, participants.funder, vault, ADVANCE_AMOUNT, "aUSDC activation advance in"),
    await can(AUSDC, vault, participants.originator, NET_PROCEEDS, "aUSDC net proceeds out"),
    await can(AUSDC, participants.buyer, vault, FACE_VALUE, "aUSDC redemption funding in"),
    await can(AUSDC, vault, participants.holderA, FACE_VALUE / 2n, "aUSDC redemption to holderA"),
    await can(AUSDC, vault, participants.holderB, FACE_VALUE / 2n, "aUSDC redemption to holderB"),
  ];
}

export function assertTuplesPass(tuples) {
  const refused = tuples.filter((tuple) => tuple.answer !== true);
  if (refused.length > 0) {
    fail(`the policy refuses ${refused.map((tuple) => tuple.label).join(", ")}`);
  }
  return true;
}

export const PLEDGE_TYPES = Object.freeze({ Pledge: [
  { name: "invoiceRoot", type: "bytes32" }, { name: "originatorSigner", type: "address" },
  { name: "facility", type: "address" }, { name: "obligationId", type: "bytes32" },
  { name: "amount", type: "uint256" }, { name: "currency", type: "bytes32" },
  { name: "activeFrom", type: "uint64" }, { name: "activeUntil", type: "uint64" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint64" },
  { name: "exclusive", type: "bool" }] });

export function buildPledge({ facility, originator, nonce, obligationId, now, protectionEnd }) {
  return { invoiceRoot: INVOICE_ROOT, originatorSigner: originator, facility, obligationId,
    amount: FACE_VALUE, currency: CURRENCY, activeFrom: now - 3_600n,
    activeUntil: protectionEnd + 30n * 24n * 3_600n, nonce,
    deadline: protectionEnd + 60n * 24n * 3_600n, exclusive: true };
}

export function parseRoleEvents(logs) {
  return parseEventLogs({ abi: TOKEN_ABI, logs })
    .filter((event) => event.eventName === "RoleGranted" || event.eventName === "RoleRevoked")
    .map((event) => ({ name: event.eventName, role: event.args.role, account: event.args.account,
      blockNumber: event.blockNumber, logIndex: event.logIndex }));
}

export { assertOnlyExpectedMinter };
