import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256, toBytes } from "viem";

import {
  EVIDENCE_GRADES, OBSERVED_ISSUANCE, TRANSFER_TOPIC0, assertAnvilClient, assertDeploymentBlock,
  assertForkChain, assertIssuanceMintEvent, assertLoopbackRpc, assertPinnedBlock,
  assertSubstitutionBounded, assertUpstreamSeparate, assumptionRegister, diffCalldata,
  substituteSubjectAddress,
} from "./m13-fork-lib.mjs";
import { classifyMinterExclusivity, deriveActiveMinters } from "./m13a-ceremony.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);
const MINTER = keccak256(toBytes("MINTER_ROLE"));
const ADAPTER = "0xc0bf43a4ca27e0976195e6661b099742f10507e5";
const OTHER = "0x1111111111111111111111111111111111111111";

// --- fork hygiene ---

test("loopback write endpoints are accepted", () => {
  for (const url of ["http://127.0.0.1:8548", "http://localhost:8545"]) {
    assert.ok(assertLoopbackRpc(url));
  }
});

test("a non-loopback write endpoint is refused", () => {
  // This is what stands between a rehearsal and the public network.
  stops(() => assertLoopbackRpc("https://testnet-rpc.monad.xyz"));
  stops(() => assertLoopbackRpc("http://10.0.0.5:8545"));
  stops(() => assertLoopbackRpc("not a url"));
});

test("the upstream must be a separate, non-loopback endpoint", () => {
  assert.ok(assertUpstreamSeparate("https://testnet-rpc.monad.xyz", "http://127.0.0.1:8548"));
  stops(() => assertUpstreamSeparate("http://127.0.0.1:8548", "http://127.0.0.1:8548"));
  stops(() => assertUpstreamSeparate("http://127.0.0.1:9999", "http://127.0.0.1:8548"));
});

test("only a client identifying as Anvil may receive writes", () => {
  assert.ok(assertAnvilClient("anvil/v1.5.0"));
  stops(() => assertAnvilClient("Geth/v1.13"));
  stops(() => assertAnvilClient(undefined));
  stops(() => assertAnvilClient(""));
});

test("the fork must present chain 10143", () => {
  assert.equal(assertForkChain(10_143), 10_143);
  stops(() => assertForkChain(1));
  stops(() => assertForkChain(143));
});

// --- bounded substitution ---

test("substitution replaces only the address in word 0", () => {
  const substituted = substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, ADAPTER);
  const diff = diffCalldata(OBSERVED_ISSUANCE.calldata, substituted);
  assert.equal(diff.sameSelector, true);
  assert.equal(diff.sameLength, true);
  assert.equal(diff.onlySubjectAddressChanged, true);
  assert.deepEqual(diff.differingWords, [0]);
  assert.equal(diff.wordCount, 8);
  assert.ok(substituted.toLowerCase().includes(ADAPTER.slice(2).toLowerCase()));
});

test("words 1 to 7 survive the substitution untouched", () => {
  const substituted = substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, ADAPTER);
  const original = OBSERVED_ISSUANCE.calldata.slice(10 + 64);
  assert.equal(substituted.slice(10 + 64), original);
});

test("a malformed replacement address is refused", () => {
  stops(() => substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, "0xshort"));
  stops(() => substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, undefined));
});

test("calldata that is not word-aligned is refused", () => {
  stops(() => substituteSubjectAddress("0xb8dd366400", ADAPTER));
  stops(() => substituteSubjectAddress("not hex", ADAPTER));
});

test("a first word that is not a padded address is never substituted", () => {
  // Guessing which word carries the subject is exactly what this refuses to do.
  const notAnAddress = `0xb8dd3664${"ff".repeat(32)}`;
  stops(() => substituteSubjectAddress(notAnAddress, ADAPTER));
});

test("a substitution touching any other word is refused before sending", () => {
  const tampered = `${OBSERVED_ISSUANCE.calldata.slice(0, 10 + 64)}${"0".repeat(63)}9`
    + OBSERVED_ISSUANCE.calldata.slice(10 + 128);
  stops(() => assertSubstitutionBounded(diffCalldata(OBSERVED_ISSUANCE.calldata, tampered)));
});

test("a substitution with a different selector or length is refused", () => {
  stops(() => assertSubstitutionBounded({ sameSelector: false, sameLength: true, onlySubjectAddressChanged: true, differingWords: [] }));
  stops(() => assertSubstitutionBounded({ sameSelector: true, sameLength: false, onlySubjectAddressChanged: true, differingWords: [] }));
});

// --- minter exclusivity ---

const event = (name, account, blockNumber, logIndex = 0, role = MINTER) =>
  ({ name, account, role, blockNumber: BigInt(blockNumber), logIndex });

test("a grant then revoke leaves no active minter", () => {
  assert.deepEqual(deriveActiveMinters([
    event("RoleGranted", OTHER, 1), event("RoleRevoked", OTHER, 2)]), []);
});

test("ordering is by block then log index, not array order", () => {
  // A revoke that arrives first in the array but later on chain must still win.
  assert.deepEqual(deriveActiveMinters([
    event("RoleRevoked", OTHER, 5), event("RoleGranted", OTHER, 3)]), []);
  assert.deepEqual(deriveActiveMinters([
    event("RoleRevoked", OTHER, 3, 0), event("RoleGranted", OTHER, 3, 1)]), [OTHER.toLowerCase()]);
});

test("role changes other than MINTER_ROLE are ignored", () => {
  assert.deepEqual(deriveActiveMinters([
    event("RoleGranted", OTHER, 1, 0, `0x${"00".repeat(32)}`)]), []);
});

test("the ceremony sequence leaves exactly the adapter as minter", () => {
  const active = deriveActiveMinters([
    event("RoleGranted", OTHER, 1), event("RoleRevoked", OTHER, 3),
    event("RoleGranted", ADAPTER, 4)]);
  assert.deepEqual(active, [ADAPTER.toLowerCase()]);
  assert.equal(classifyMinterExclusivity(active, ADAPTER), "PROVEN");
});

test("any unexpected surviving minter fails exclusivity", () => {
  assert.equal(classifyMinterExclusivity([ADAPTER.toLowerCase(), OTHER.toLowerCase()], ADAPTER), "NOT PROVEN");
});

test("an adapter that is not a minter fails exclusivity", () => {
  assert.equal(classifyMinterExclusivity([], ADAPTER), "NOT PROVEN");
  assert.equal(classifyMinterExclusivity([OTHER.toLowerCase()], ADAPTER), "NOT PROVEN");
});

test("an unreconstructable history is NOT PROVEN, never assumed clean", () => {
  assert.equal(classifyMinterExclusivity(null, ADAPTER), "NOT PROVEN");
  assert.equal(classifyMinterExclusivity(undefined, ADAPTER), "NOT PROVEN");
});

// --- assumption register ---

test("every premise carries a known grade", () => {
  for (const entry of assumptionRegister()) {
    assert.ok(EVIDENCE_GRADES.includes(entry.grade), `${entry.premise} has grade ${entry.grade}`);
    assert.ok(entry.basis.length > 0);
  }
});

test("unproven premises default to NOT PROVEN rather than to optimism", () => {
  const register = assumptionRegister();
  const controlA = register.find((entry) => entry.value === "control A");
  assert.equal(controlA.grade, "NOT PROVEN");
});

test("the issuance ABI is never graded above what one observation supports", () => {
  const register = assumptionRegister();
  const wordZero = register.find((entry) => entry.premise.startsWith("Word 0"));
  assert.equal(wordZero.grade, "INFERRED");
  const shape = register.find((entry) => entry.premise === "The issuance calldata shape");
  assert.equal(shape.grade, "ON-CHAIN OBSERVED");
  assert.match(shape.basis, /No ABI is published and none is claimed/);
});

test("an unknown grade is refused outright", () => {
  // A typo in a grade must not silently pass as evidence.
  assert.equal(EVIDENCE_GRADES.includes("PROBABLY FINE"), false);
});

// --- pinning by number and hash ---

const HASH_A = "0xd0eb4a2826e180c62bd08b387dacfda87665e35ee3b5b4b18412d1629e664b83";

test("a block matching both number and hash is accepted", () => {
  const pinned = assertPinnedBlock("A", { number: 48_889_104n, hash: HASH_A }, 48_889_104n, HASH_A);
  assert.equal(pinned.number, "48889104");
});

test("the right height with the wrong hash is refused", () => {
  // This is the reorg case: same height, different ground.
  assert.throws(
    () => assertPinnedBlock("A", { number: 48_889_104n, hash: `0x${"ff".repeat(32)}` }, 48_889_104n, HASH_A),
    /reorged/);
});

test("the wrong height is refused even with a plausible hash", () => {
  stops(() => assertPinnedBlock("A", { number: 1n, hash: HASH_A }, 48_889_104n, HASH_A));
});

test("hash comparison ignores casing", () => {
  assert.ok(assertPinnedBlock("A", { number: 1n, hash: HASH_A.toUpperCase().replace("0X", "0x") }, 1n, HASH_A));
});

// --- deployment block derivation ---

test("no code at the parent and code at the receipt confirms the deployment block", () => {
  const result = assertDeploymentBlock("MINV01", "0x", `0x${"60".repeat(122)}`, 48_901_234n);
  assert.equal(result.blockNumber, "48901234");
  assert.equal(result.codeBytes, 122);
});

test("code already present at the parent means the block is wrong", () => {
  // Scanning from here would miss earlier role history.
  stops(() => assertDeploymentBlock("MINV01", "0x6060", "0x6060", 48_901_234n));
});

test("no code at the receipt means the block is wrong", () => {
  stops(() => assertDeploymentBlock("MINV01", "0x", "0x", 48_901_234n));
  stops(() => assertDeploymentBlock("MINV01", undefined, undefined, 48_901_234n));
});

// --- the issuance mint event ---

const pad = (address) => `0x000000000000000000000000${address.slice(2).toLowerCase()}`;
const REGISTRY = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const SUBJECT = "0x0f8b9a0c064306f938912658c96c681d8655140b";
const transferLog = (from, to, address = REGISTRY) => ({
  address,
  topics: [TRANSFER_TOPIC0, pad(from), pad(to), `0x${"00".repeat(31)}07`],
});
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

test("a Transfer from zero to the subject is accepted and its token id read", () => {
  const event = assertIssuanceMintEvent([transferLog(ZERO_ADDR, SUBJECT)], REGISTRY, SUBJECT);
  assert.equal(event.to, SUBJECT);
  assert.equal(event.tokenId, "7");
  assert.equal(event.topicCount, 4);
});

test("a receipt with no registry Transfer is refused", () => {
  stops(() => assertIssuanceMintEvent([], REGISTRY, SUBJECT));
  stops(() => assertIssuanceMintEvent([{ address: REGISTRY, topics: ["0xdead"] }], REGISTRY, SUBJECT));
});

test("a Transfer to somebody else does not count as issuance to the subject", () => {
  stops(() => assertIssuanceMintEvent([transferLog(ZERO_ADDR, OTHER)], REGISTRY, SUBJECT));
});

test("a Transfer that is not a mint does not count", () => {
  // An existing A-Pass moving between holders is not an issuance.
  stops(() => assertIssuanceMintEvent([transferLog(OTHER, SUBJECT)], REGISTRY, SUBJECT));
});

test("a Transfer from another contract does not count", () => {
  stops(() => assertIssuanceMintEvent(
    [transferLog(ZERO_ADDR, SUBJECT, "0x1111111111111111111111111111111111111111")], REGISTRY, SUBJECT));
});

test("the correct mint is found among unrelated registry logs", () => {
  const event = assertIssuanceMintEvent(
    [{ address: REGISTRY, topics: ["0xb64285e3"] }, transferLog(ZERO_ADDR, SUBJECT)], REGISTRY, SUBJECT);
  assert.equal(event.to, SUBJECT);
});
