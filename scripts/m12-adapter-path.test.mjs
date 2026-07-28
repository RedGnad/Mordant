import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256, toBytes } from "viem";

import {
  APASS_ROSTER, assertProductionAdapter, checkTokenSurface, describeGrant,
} from "./m12-adapter-path.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);
const MINTER = keccak256(toBytes("MINTER_ROLE"));
const POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";

test("a real adapter passes the stop condition", () => {
  assert.equal(
    assertProductionAdapter({ productionExists: true, mockOnly: false, sourcePath: "a.sol" }), "a.sol");
});

test("a mock-only repository stops the mission", () => {
  // A mock satisfies the interface while implementing none of the accounting invariants.
  stops(() => assertProductionAdapter({ productionExists: true, mockOnly: true }));
  stops(() => assertProductionAdapter({ productionExists: false, mockOnly: false }));
});

test("the real token surface is accepted", () => {
  const result = checkTokenSurface({ decimals: 6, policy: POLICY, MINTER_ROLE: MINTER });
  assert.equal(result.ok, true);
  assert.equal(result.members.length, 3);
});

test("wrong decimals are rejected, since the adapter hard-codes six", () => {
  assert.equal(checkTokenSurface({ decimals: 18, policy: POLICY, MINTER_ROLE: MINTER }).ok, false);
});

test("a foreign policy is rejected", () => {
  assert.equal(checkTokenSurface({
    decimals: 6, policy: "0x0000000000000000000000000000000000000001", MINTER_ROLE: MINTER }).ok, false);
});

test("a MINTER_ROLE that is not the keccak of the name is rejected", () => {
  assert.equal(checkTokenSurface({ decimals: 6, policy: POLICY, MINTER_ROLE: `0x${"11".repeat(32)}` }).ok, false);
});

test("a missing member is reported as absent, never as matching", () => {
  const result = checkTokenSurface({ decimals: null, policy: POLICY, MINTER_ROLE: MINTER });
  assert.equal(result.ok, false);
  const decimals = result.members.find((entry) => entry.member === "decimals");
  assert.equal(decimals.present, false);
  assert.equal(decimals.matches, false);
});

test("policy comparison ignores checksum casing", () => {
  assert.equal(checkTokenSurface({
    decimals: 6, policy: POLICY.toLowerCase(), MINTER_ROLE: MINTER }).ok, true);
});

test("the grant is described as data, with no key anywhere", () => {
  const grant = describeGrant({ token: "0xtoken", minterRole: MINTER,
    adapterAddress: "0x0f8b9a0c064306f938912658c96c681d8655140b", adminAddress: "0xadmin" });
  assert.equal(grant.signature, "grantRole(bytes32,address)");
  assert.match(grant.calldata, /^0x2f2ff15d/);
  const serialized = JSON.stringify(grant);
  for (const forbidden of ["--private-key", "MORDANT_KEY_", "cast send"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal("command" in grant, false);
});

test("the grant states plainly that it authorises burning, not minting", () => {
  const grant = describeGrant({ token: "0xtoken", minterRole: MINTER, adapterAddress: null,
    adminAddress: "0xadmin" });
  assert.match(grant.authorises, /BURN/);
  assert.match(grant.authorises, /no mint function/);
  // Without a deployed adapter there is nothing to encode, and that is stated rather than faked.
  assert.equal(grant.calldata, null);
});

test("the A-Pass roster covers both tokens and every transfer counterparty", () => {
  const roles = APASS_ROSTER.map((entry) => entry.role);
  for (const expected of ["adapter", "vault", "funder/buyer", "originatorTreasury", "holder"]) {
    assert.ok(roles.includes(expected), `roster is missing ${expected}`);
  }
  // No roster entry may claim a known address: none of these is deployed yet.
  assert.equal(APASS_ROSTER.every((entry) => entry.knownAddress === null), true);
});
