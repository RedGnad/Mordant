import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

import {
  createPublicClient, createTestClient, createWalletClient, http, keccak256, parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  ADAPTER_ABI, ADVANCE_AMOUNT, ALLOCATION, APASS_ABI, APASS_REGISTRY, AUSDC, BOND, FACE_VALUE,
  INITIAL_UNITS, MINTER_ROLE, MINV01, NET_PROCEEDS, PLEDGE_TYPES, PUBLIC_WRITES_AUTHORIZED,
  STEP_IDS, TOKEN_ABI, ZERO, activeMintersFrom, assertOnlyExpectedMinter, assertRunAllowed,
  assertRunPreconditions, assertTuplesPass, buildPledge, nextStep, parseRoleEvents,
  protectionEndFrom, readNineTuples, requestOnce, runtimeFingerprint, sendTracked, stepById,
  verifyAdapter,
} from "./m15-engine.mjs";
import {
  M13_FORK_BLOCK, OBSERVED_ISSUANCE, OBSERVED_ISSUER, assertSubstitutionBounded, diffCalldata,
  substituteSubjectAddress,
} from "./m13-fork-lib.mjs";
import { ControlError } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = Number(process.env.M15_TEST_PORT ?? 8_551);
const RPC = `http://127.0.0.1:${PORT}`;
const UPSTREAM = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const MINV01_ADMIN = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const AUSDC_SOURCE = "0x7f7098632b0258Af07e527015D65e6bc743f4CF5";

const stops = (fn) => assert.throws(fn, ControlError);
const artifact = (relative) => JSON.parse(
  readFileSync(join(ROOT, `contracts/out/${relative}.json`), "utf8"));

/** Anvil development keys. A fork only; no real wallet is ever used here. */
const KEYS = {
  holderA: null, holderB: null,
  buyer: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  funder: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  originator: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  facilityProtected: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  facilityChallenger: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  issuanceMinter: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
};

let fork;
let client;
let testClient;
let transport;
const wallets = {};
const participants = {};
/** The chain of artifacts, one per executed sub-action. */
const artifacts = {};
const pendingSeen = [];
/** Role events accumulated from the receipts this run produced, which is exact. */
const roleEvents = [];

const readiness = () => Object.keys(participants).map((key) => ({ key, ready: true, problems: [] }));

/** Writes the PENDING checkpoint the way a runner would, and records that it happened first. */
const checkpointFor = (stepId) => async ({ hash, status }) => {
  artifacts[stepId] = { ...(artifacts[stepId] ?? {}), step: stepId, hash, status };
  if (status === "PENDING") pendingSeen.push({ stepId, hash });
};

const succeed = (stepId, extra = {}) => {
  artifacts[stepId] = { ...(artifacts[stepId] ?? {}), step: stepId, status: "SUCCESS", ...extra };
  return artifacts[stepId];
};

before(async () => {
  fork = spawn("anvil", ["--fork-url", UPSTREAM, "--fork-block-number", String(M13_FORK_BLOCK),
    "--port", String(PORT), "--host", "127.0.0.1", "--chain-id", "10143",
    "--code-size-limit", "131072", "--silent"], { stdio: ["ignore", "ignore", "inherit"] });
  transport = http(RPC);
  client = createPublicClient({ transport });
  testClient = createTestClient({ mode: "anvil", transport });
  for (let attempt = 0; ; attempt += 1) {
    try { await client.getBlockNumber(); break; }
    catch (error) {
      if (attempt > 120) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  // holderA is the MINV01 admin, impersonated; holderB likewise. The rest are fork keys.
  participants.holderA = MINV01_ADMIN;
  participants.holderB = "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6";
  for (const [role, key] of Object.entries(KEYS)) {
    if (!key) continue;
    participants[role] = privateKeyToAccount(key).address;
  }
  for (const address of Object.values(participants)) {
    await testClient.setBalance({ address, value: 10n ** 20n });
    await testClient.impersonateAccount({ address });
  }
  for (const [role, address] of Object.entries(participants)) {
    wallets[role] = KEYS[role]
      ? createWalletClient({ account: privateKeyToAccount(KEYS[role]), transport })
      : createWalletClient({ account: address, transport });
  }
  await testClient.setBalance({ address: OBSERVED_ISSUER, value: 10n ** 19n });
  await testClient.impersonateAccount({ address: OBSERVED_ISSUER });
  await testClient.setBalance({ address: AUSDC_SOURCE, value: 10n ** 19n });
  await testClient.impersonateAccount({ address: AUSDC_SOURCE });
});

after(() => { if (fork && !fork.killed) fork.kill("SIGTERM"); });

/** Issues a fork-local A-Pass by the bounded substitution M-13A proved. */
const issueApass = async (subject) => {
  const substituted = substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, subject);
  assertSubstitutionBounded(diffCalldata(OBSERVED_ISSUANCE.calldata, substituted));
  const wallet = createWalletClient({ account: OBSERVED_ISSUER, transport });
  const hash = await wallet.sendTransaction({ to: APASS_REGISTRY, data: substituted, value: 0n,
    chain: null, gas: 2_000_000n });
  await client.waitForTransactionReceipt({ hash });
  return client.readContract({ address: APASS_REGISTRY, abi: APASS_ABI,
    functionName: "isValidAPass", args: [subject] });
};

// --- gates, before any execution ---

test("Monad public is refused by a source constant, not a setting", () => {
  assert.equal(PUBLIC_WRITES_AUTHORIZED, false);
  assert.throws(() => assertRunAllowed({ chainId: 10_143 }), /source constant/);
  // A non-public chain may execute: that is how the engine is proven.
  assert.equal(assertRunAllowed({ chainId: 31_337 }), "non-public");
});

test("the public gate cannot be opened from the environment", () => {
  process.env.PUBLIC_WRITES_AUTHORIZED = "true";
  process.env.MORDANT_PUBLIC_WRITES = "yes";
  assert.throws(() => assertRunAllowed({ chainId: 10_143 }), ControlError);
  delete process.env.PUBLIC_WRITES_AUTHORIZED;
  delete process.env.MORDANT_PUBLIC_WRITES;
});

test("a sub-action without its predecessor artifact is blocked", () => {
  stops(() => assertRunPreconditions({ step: stepById("D.mint"), previousArtifact: null,
    participants, readiness: readiness(), signerKey: KEYS.issuanceMinter, toAccount: privateKeyToAccount }));
});

test("a predecessor artifact from the wrong sub-action is blocked", () => {
  stops(() => assertRunPreconditions({ step: stepById("D.mint"),
    previousArtifact: { step: "C2.vault", status: "SUCCESS" }, participants, readiness: readiness(),
    signerKey: KEYS.issuanceMinter, toAccount: privateKeyToAccount }));
});

test("a predecessor that is still PENDING is blocked", () => {
  stops(() => assertRunPreconditions({ step: stepById("D.mint"),
    previousArtifact: { step: "D.grant", status: "PENDING" }, participants, readiness: readiness(),
    signerKey: KEYS.issuanceMinter, toAccount: privateKeyToAccount }));
});

test("incomplete inputs block a sub-action", () => {
  const partial = { ...participants };
  delete partial.issuanceMinter;
  stops(() => assertRunPreconditions({ step: stepById("D.grant"),
    previousArtifact: { step: "C2.vault", status: "SUCCESS" }, participants: partial,
    readiness: readiness(), signerKey: KEYS.buyer, toAccount: privateKeyToAccount }));
});

test("incomplete readiness blocks a sub-action", () => {
  stops(() => assertRunPreconditions({ step: stepById("D.grant"),
    previousArtifact: { step: "C2.vault", status: "SUCCESS" }, participants,
    readiness: [{ key: "funder", ready: false, problems: ["no valid A-Pass"] }],
    signerKey: null, toAccount: privateKeyToAccount }));
});

test("a key deriving the wrong signer is blocked", () => {
  // Signing the mint with the buyer's key would revert late; this refuses it early.
  stops(() => assertRunPreconditions({ step: stepById("D.mint"),
    previousArtifact: { step: "D.grant", status: "SUCCESS" }, participants, readiness: readiness(),
    signerKey: KEYS.buyer, toAccount: privateKeyToAccount }));
});

test("no sub-action triggers the next", () => {
  for (const id of STEP_IDS.slice(0, -1)) {
    const { next, instruction } = nextStep(id);
    assert.ok(next);
    assert.match(instruction, /STOP\./);
    assert.match(instruction, /never triggered from here/);
  }
  assert.equal(nextStep("F.releaseB").next, null);
});

test("D, E and F are decomposed rather than collapsed onto one signer", () => {
  const byPhase = (phase) => STEP_IDS.filter((id) => id.startsWith(`${phase}.`));
  assert.deepEqual(byPhase("D"), ["D.grant", "D.mint", "D.revokeGrant", "D.bind"]);
  assert.deepEqual(byPhase("E"), ["E.sign", "E.approve", "E.activate"]);
  assert.equal(byPhase("F").length, 6);
  // The mint is signed by a different wallet from the grant, which is the point of the split.
  assert.notEqual(stepById("D.grant").signer, stepById("D.mint").signer);
});

test("an ambiguous Cleanverse response is never retried", async () => {
  const ambiguous = await requestOnce({ marker: "m1", perform: async () => { throw new Error("timeout"); } });
  assert.equal(ambiguous.outcome, "AMBIGUOUS");
  assert.match(ambiguous.note, /NOT retried/);
  // And a marker already submitted cannot be sent again.
  await assert.rejects(requestOnce({ marker: "m1", priorMarkers: ["m1"], perform: async () => ({ code: "0000" }) }),
    ControlError);
});

// --- the engine, executed for real ---

test("A.deploy deploys the adapter and verifies it", async () => {
  const compiled = artifact("CleanverseCvaAdapter.sol/CleanverseCvaAdapter");
  const hash = await wallets.holderA.deployContract({ abi: compiled.abi,
    bytecode: compiled.bytecode.object, args: [participants.holderA, MINV01, APASS_REGISTRY],
    chain: null });
  await checkpointFor("A.deploy")({ hash, status: "PENDING" });
  const receipt = await client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success");
  const adapter = receipt.contractAddress;
  const verified = await verifyAdapter({ client, adapter,
    expectedRuntimeHash: runtimeFingerprint(compiled.deployedBytecode.object,
      compiled.deployedBytecode.immutableReferences),
    immutableReferences: compiled.deployedBytecode.immutableReferences,
    owner: participants.holderA });
  assert.equal(verified.boundVault.toLowerCase(), ZERO);
  succeed("A.deploy", { adapter, runtimeFingerprint: verified.runtimeFingerprint });
});

test("a PENDING checkpoint was written before the receipt was awaited", () => {
  const entry = pendingSeen.find((item) => item.stepId === "A.deploy");
  assert.ok(entry, "no PENDING checkpoint recorded");
  assert.equal(entry.hash, artifacts["A.deploy"].hash);
});

test("B.apass issues the adapter credential exactly once", async () => {
  const adapter = artifacts["A.deploy"].adapter;
  assert.equal(await client.readContract({ address: APASS_REGISTRY, abi: APASS_ABI,
    functionName: "isValidAPass", args: [adapter] }), false);
  assert.equal(await issueApass(adapter), true);
  succeed("B.apass", { adapter, isValidAPass: true });
});

test("C1.infra deploys the verifier and factory and configures them", async () => {
  const verifierArtifact = artifact("CleanverseAPassVerifier.sol/CleanverseAPassVerifier");
  const factoryArtifact = artifact("MordantFactory.sol/MordantFactory");
  const deploy = async (compiled, args) => {
    const hash = await wallets.holderA.deployContract({ abi: compiled.abi,
      bytecode: compiled.bytecode.object, args, chain: null });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    return receipt.contractAddress;
  };
  const verifier = await deploy(verifierArtifact, [participants.holderA, APASS_REGISTRY, 16n]);
  const factory = await deploy(factoryArtifact, [participants.holderA, verifier]);

  // Credentials precede allowlists: setFacility asks the verifier, which asks the live A-Pass.
  for (const role of ["buyer", "funder", "originator", "facilityProtected", "facilityChallenger"]) {
    if (await client.readContract({ address: APASS_REGISTRY, abi: APASS_ABI,
      functionName: "isValidAPass", args: [participants[role]] }) !== true) {
      assert.equal(await issueApass(participants[role]), true);
    }
  }
  const send = async (address, abi, functionName, args) => {
    const hash = await wallets.holderA.writeContract({ address, abi, functionName, args, chain: null });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success", functionName);
  };
  for (const [role, id] of [["buyer", 1], ["originator", 2], ["facilityProtected", 3],
    ["facilityChallenger", 3], ["funder", 4]]) {
    await send(verifier, verifierArtifact.abi, "setRoleEligibility", [participants[role], id, true]);
  }
  await send(factory, factoryArtifact.abi, "setFacility", [participants.facilityProtected, true]);
  await send(factory, factoryArtifact.abi, "setFacility", [participants.facilityChallenger, true]);
  await send(factory, factoryArtifact.abi, "setCvaAdapter", [artifacts["A.deploy"].adapter, true]);
  await send(factory, factoryArtifact.abi, "setSettlementToken", [AUSDC, true]);
  succeed("C1.infra", { verifier, factory });
});

test("C2.vault creates the vault, computes protectionEnd and passes the nine tuples", async () => {
  const factoryArtifact = artifact("MordantFactory.sol/MordantFactory");
  const now = (await client.getBlock()).timestamp;
  const protectionEnd = protectionEndFrom(now);
  const hash = await wallets.buyer.writeContract({
    address: artifacts["C1.infra"].factory, abi: factoryArtifact.abi,
    functionName: "createInvoiceVault", chain: null,
    args: [{ cvaAdapter: artifacts["A.deploy"].adapter, settlementToken: AUSDC,
      invoiceRoot: `0x${"c3".repeat(32)}`, currency: `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`,
      buyer: participants.buyer, originatorTreasury: participants.originator,
      initialOriginatorSigner: participants.originator, initialUnits: INITIAL_UNITS,
      advanceAmount: ADVANCE_AMOUNT, faceValue: FACE_VALUE, bondBps: 1_000,
      protectionEnd, revealPeriod: 3_600n, curePeriod: 3_600n }] });
  await checkpointFor("C2.vault")({ hash, status: "PENDING" });
  const receipt = await client.waitForTransactionReceipt({ hash });
  const [created] = parseEventLogs({ abi: factoryArtifact.abi, eventName: "InvoiceVaultCreated",
    logs: receipt.logs });
  const vault = created.args.vault;
  assert.equal(await issueApass(vault), true);
  const tuples = await readNineTuples({ client, adapter: artifacts["A.deploy"].adapter, vault,
    participants });
  assertTuplesPass(tuples);
  assert.equal(tuples.length, 9);
  succeed("C2.vault", { vault, protectionEnd: protectionEnd.toString() });
});

test("D.grant grants the temporary minter only", async () => {
  const { hash, receipt } = await sendTracked({ client, wallet: wallets.holderA,
    request: { address: MINV01, abi: TOKEN_ABI, functionName: "grantRole",
      args: [MINTER_ROLE, participants.issuanceMinter], account: participants.holderA },
    checkpoint: checkpointFor("D.grant"), label: "D.grant" });
  roleEvents.push(...parseRoleEvents(receipt.logs));
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole",
    args: [MINTER_ROLE, participants.issuanceMinter] }), true);
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole",
    args: [MINTER_ROLE, artifacts["A.deploy"].adapter] }), false);
  succeed("D.grant", { hash });
});

test("D.mint mints exactly the intended units, signed by the issuance wallet", async () => {
  const { hash } = await sendTracked({ client, wallet: wallets.issuanceMinter,
    request: { address: MINV01, abi: TOKEN_ABI, functionName: "mint",
      args: [artifacts["A.deploy"].adapter, INITIAL_UNITS], account: participants.issuanceMinter },
    checkpoint: checkpointFor("D.mint"), label: "D.mint" });
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "totalSupply" }),
    INITIAL_UNITS);
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "balanceOf",
    args: [artifacts["A.deploy"].adapter] }), INITIAL_UNITS);
  succeed("D.mint", { hash });
});

test("D.revokeGrant closes the temporary minter and opens the adapter", async () => {
  for (const [functionName, account] of [["revokeRole", participants.issuanceMinter],
    ["grantRole", artifacts["A.deploy"].adapter]]) {
    const { receipt } = await sendTracked({ client, wallet: wallets.holderA,
      request: { address: MINV01, abi: TOKEN_ABI, functionName, args: [MINTER_ROLE, account],
        account: participants.holderA },
      checkpoint: checkpointFor("D.revokeGrant"), label: functionName });
    roleEvents.push(...parseRoleEvents(receipt.logs));
  }
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole",
    args: [MINTER_ROLE, participants.issuanceMinter] }), false);
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole",
    args: [MINTER_ROLE, artifacts["A.deploy"].adapter] }), true);
  succeed("D.revokeGrant", {});
});

test("D.bind refuses an unexpected minter, then binds", async () => {
  const adapter = artifacts["A.deploy"].adapter;
  // The exclusivity gate must refuse a set containing anyone else.
  stops(() => assertOnlyExpectedMinter([adapter.toLowerCase(), participants.buyer.toLowerCase()], adapter));

  // Reconstructed from the receipts this run produced, so no log window can be too narrow.
  const active = activeMintersFrom(roleEvents);
  assert.deepEqual(active, [adapter.toLowerCase()]);
  assertOnlyExpectedMinter(active, adapter);

  const { hash } = await sendTracked({ client, wallet: wallets.holderA,
    request: { address: adapter, abi: ADAPTER_ABI, functionName: "bindVault",
      args: [artifacts["C2.vault"].vault, INITIAL_UNITS], account: participants.holderA },
    checkpoint: checkpointFor("D.bind"), label: "D.bind" });
  assert.equal((await client.readContract({ address: adapter, abi: ADAPTER_ABI,
    functionName: "boundVault" })).toLowerCase(), artifacts["C2.vault"].vault.toLowerCase());
  succeed("D.bind", { hash });
});

test("E.sign produces a pledge signature and sends nothing", async () => {
  const before = await client.getBlockNumber();
  const now = (await client.getBlock()).timestamp;
  const pledge = buildPledge({ facility: participants.facilityProtected,
    originator: participants.originator, nonce: 1n, obligationId: `0x${"a1".repeat(32)}`,
    now, protectionEnd: BigInt(artifacts["C2.vault"].protectionEnd) });
  const signature = await privateKeyToAccount(KEYS.originator).signTypedData({
    domain: { name: "Mordant", version: "1", chainId: 10_143,
      verifyingContract: artifacts["C2.vault"].vault },
    types: PLEDGE_TYPES, primaryType: "Pledge", message: pledge });
  assert.match(signature, /^0x[0-9a-f]{130}$/);
  assert.equal(await client.getBlockNumber(), before, "signing must not send a transaction");
  succeed("E.sign", { pledge: { ...pledge, activeFrom: pledge.activeFrom.toString(),
    activeUntil: pledge.activeUntil.toString(), nonce: pledge.nonce.toString(),
    deadline: pledge.deadline.toString(), amount: pledge.amount.toString() }, signature });
  artifacts["E.sign"].raw = { pledge, signature };
});

test("E.approve moves the funder's allowance, funded from a real holder", async () => {
  const sourceWallet = createWalletClient({ account: AUSDC_SOURCE, transport });
  const fundHash = await sourceWallet.writeContract({ address: AUSDC, abi: TOKEN_ABI,
    functionName: "approve", args: [participants.funder, 0n], chain: null }).catch(() => null);
  if (fundHash) await client.waitForTransactionReceipt({ hash: fundHash });
  const transferAbi = [{ type: "function", name: "transfer", stateMutability: "nonpayable",
    inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] }];
  const moved = await sourceWallet.writeContract({ address: AUSDC, abi: transferAbi,
    functionName: "transfer", args: [participants.funder, ADVANCE_AMOUNT], chain: null });
  await client.waitForTransactionReceipt({ hash: moved });

  const { hash } = await sendTracked({ client, wallet: wallets.funder,
    request: { address: AUSDC, abi: TOKEN_ABI, functionName: "approve",
      args: [artifacts["C2.vault"].vault, ADVANCE_AMOUNT], account: participants.funder },
    checkpoint: checkpointFor("E.approve"), label: "E.approve" });
  succeed("E.approve", { hash });
});

test("E.activate settles the advance exactly", async () => {
  const vaultAbi = artifact("MordantInvoiceVault.sol/MordantInvoiceVault").abi;
  const vault = artifacts["C2.vault"].vault;
  const originatorBefore = await client.readContract({ address: AUSDC, abi: TOKEN_ABI,
    functionName: "balanceOf", args: [participants.originator] });
  const { raw } = artifacts["E.sign"];
  const { hash } = await sendTracked({ client, wallet: wallets.facilityProtected,
    request: { address: vault, abi: vaultAbi, functionName: "activate",
      args: [raw.pledge, raw.signature, participants.funder,
        [participants.holderA, participants.holderB], [ALLOCATION, ALLOCATION]],
      account: participants.facilityProtected },
    checkpoint: checkpointFor("E.activate"), label: "E.activate" });

  const originatorAfter = await client.readContract({ address: AUSDC, abi: TOKEN_ABI,
    functionName: "balanceOf", args: [participants.originator] });
  assert.equal(originatorAfter - originatorBefore, NET_PROCEEDS);
  assert.equal(await client.readContract({ address: vault, abi: vaultAbi, functionName: "bondLocked" }), BOND);
  assert.equal(await client.readContract({ address: vault, abi: vaultAbi, functionName: "balanceOf",
    args: [participants.holderA] }), ALLOCATION);
  await client.readContract({ address: vault, abi: vaultAbi, functionName: "assertAccounting" });
  succeed("E.activate", { hash });
});

test("F runs commit, reveal, finalize, default and both releases as separate sub-actions", async () => {
  const vaultAbi = artifact("MordantInvoiceVault.sol/MordantInvoiceVault").abi;
  const vault = artifacts["C2.vault"].vault;
  const adapter = artifacts["A.deploy"].adapter;
  const now = (await client.getBlock()).timestamp;
  const conflicting = buildPledge({ facility: participants.facilityChallenger,
    originator: participants.originator, nonce: 2n, obligationId: `0x${"b2".repeat(32)}`,
    now, protectionEnd: BigInt(artifacts["C2.vault"].protectionEnd) });
  const signature = await privateKeyToAccount(KEYS.originator).signTypedData({
    domain: { name: "Mordant", version: "1", chainId: 10_143, verifyingContract: vault },
    types: PLEDGE_TYPES, primaryType: "Pledge", message: conflicting });
  const salt = `0x${"5a".repeat(32)}`;
  const digest = await client.readContract({ address: vault, abi: vaultAbi,
    functionName: "hashPledge", args: [conflicting] });
  const commitment = await client.readContract({ address: vault, abi: vaultAbi,
    functionName: "conflictCommitment",
    args: [digest, keccak256(signature), participants.facilityChallenger, salt] });

  await sendTracked({ client, wallet: wallets.facilityChallenger,
    request: { address: vault, abi: vaultAbi, functionName: "commitConflict", args: [commitment],
      account: participants.facilityChallenger },
    checkpoint: checkpointFor("F.commit"), label: "F.commit" });
  succeed("F.commit", {});

  await sendTracked({ client, wallet: wallets.facilityChallenger,
    request: { address: vault, abi: vaultAbi, functionName: "revealConflict",
      args: [conflicting, signature, salt], account: participants.facilityChallenger },
    checkpoint: checkpointFor("F.reveal"), label: "F.reveal" });
  succeed("F.reveal", {});

  await testClient.increaseTime({ seconds: 3_601 });
  await testClient.mine({ blocks: 1 });
  await sendTracked({ client, wallet: wallets.holderA,
    request: { address: vault, abi: vaultAbi, functionName: "finalizeConflict", args: [],
      account: participants.holderA },
    checkpoint: checkpointFor("F.finalize"), label: "F.finalize" });
  succeed("F.finalize", {});

  const protectionEnd = BigInt(artifacts["C2.vault"].protectionEnd);
  await testClient.increaseTime({ seconds: Number(protectionEnd - (await client.getBlock()).timestamp) + 60 });
  await testClient.mine({ blocks: 1 });
  await sendTracked({ client, wallet: wallets.holderA,
    request: { address: vault, abi: vaultAbi, functionName: "markDefault", args: [],
      account: participants.holderA },
    checkpoint: checkpointFor("F.markDefault"), label: "F.markDefault" });
  succeed("F.markDefault", {});

  const supplyBefore = await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "totalSupply" });
  for (const [stepId, role] of [["F.releaseA", "holderA"], ["F.releaseB", "holderB"]]) {
    const units = await client.readContract({ address: vault, abi: vaultAbi, functionName: "balanceOf",
      args: [participants[role]] });
    const before = await client.readContract({ address: MINV01, abi: TOKEN_ABI,
      functionName: "balanceOf", args: [participants[role]] });
    await sendTracked({ client, wallet: wallets[role],
      request: { address: vault, abi: vaultAbi, functionName: "releaseDefaultCva", args: [units],
        account: participants[role] },
      checkpoint: checkpointFor(stepId), label: stepId });
    const after = await client.readContract({ address: MINV01, abi: TOKEN_ABI,
      functionName: "balanceOf", args: [participants[role]] });
    assert.equal(after - before, units, `${role} did not receive its units`);
    succeed(stepId, {});
  }

  // A release transfers; the token supply does not fall. The vault receipts are what burn.
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "totalSupply" }),
    supplyBefore);
  assert.equal(await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "balanceOf",
    args: [adapter] }), 0n);
  assert.equal(await client.readContract({ address: vault, abi: vaultAbi, functionName: "totalSupply" }), 0n);
  await client.readContract({ address: vault, abi: vaultAbi, functionName: "assertAccounting" });
});

test("the whole chain executed, each sub-action leaving a SUCCESS artifact", () => {
  for (const id of STEP_IDS) {
    assert.equal(artifacts[id]?.status, "SUCCESS", `${id} did not complete`);
  }
});

test("every sending sub-action wrote PENDING before its receipt", () => {
  const sending = STEP_IDS.filter((id) => !stepById(id).offchain && id !== "B.apass"
    && id !== "C1.infra" && id !== "D.revokeGrant");
  for (const id of sending) {
    assert.ok(pendingSeen.some((entry) => entry.stepId === id), `${id} wrote no PENDING checkpoint`);
  }
});
