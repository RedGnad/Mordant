import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256, toBytes } from "viem";

import {
  EVIDENCE_GRADES, OBSERVED_ISSUANCE, assertAnvilClient, assertForkChain, assertLoopbackRpc,
  assertSubstitutionBounded, assertUpstreamSeparate, assumptionRegister, diffCalldata,
  substituteSubjectAddress,
} from "./m13-fork-lib.mjs";
import { classifyMinterExclusivity, deriveActiveMinters } from "./m13-rehearsal.mjs";
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
