import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256, toBytes } from "viem";

import {
  REQUIRED_SELECTORS, assertProductionAdapter, buildRoster, checkAdapterPreconditions,
  checkTokenSurface, describeGrant, describeIssuanceSequence, transferTuples,
} from "./m12-adapter-path.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);
const MINTER = keccak256(toBytes("MINTER_ROLE"));
const ISSUER = "0x1111111111111111111111111111111111111111";
const ADAPTER = "0x2222222222222222222222222222222222222222";
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
  assert.match(grant.authorises, /only ever calls burn/);
  // Without a deployed adapter there is nothing to encode, and that is stated rather than faked.
  assert.equal(grant.calldata, null);
});


// --- role semantics ---

test("the grant states that MINTER_ROLE covers mint and burn, and the adapter only burns", () => {
  const grant = describeGrant({ token: "0xtoken", minterRole: MINTER,
    adapterAddress: "0x0f8b9a0c064306f938912658c96c681d8655140b", adminAddress: "0xadmin" });
  assert.match(grant.authorises, /mint and burn at the token level/);
  assert.match(grant.authorises, /only ever calls burn/);
});

test("the issuance sequence is grant, mint, revoke, in that order", () => {
  const sequence = describeIssuanceSequence({ token: "0xtoken", minterRole: MINTER,
    issuanceWallet: "0x1111111111111111111111111111111111111111",
    adapterAddress: "0x2222222222222222222222222222222222222222", units: 1000n, adminAddress: "0xadmin" });
  assert.equal(sequence.required, true);
  assert.deepEqual(sequence.steps.map((step) => step.order), [1, 2, 3]);
  assert.match(sequence.steps[0].signature, /^grantRole/);
  assert.match(sequence.steps[1].signature, /^mint/);
  assert.match(sequence.steps[2].signature, /^revokeRole/);
  // The revoke is not optional, and the artifact must say why.
  assert.match(sequence.note, /Step 3 is not optional/);
  assert.match(sequence.reason, /cannot mint/);
});

test("the mint step is signed by the issuance wallet, the role changes by the admin", () => {
  const sequence = describeIssuanceSequence({ token: "0xtoken", minterRole: MINTER,
    issuanceWallet: ISSUER, adapterAddress: ADAPTER, units: 1n, adminAddress: "0xadmin" });
  assert.equal(sequence.steps[1].mustBeSignedBy, ISSUER);
  assert.equal(sequence.steps[0].mustBeSignedBy, "0xadmin");
  assert.equal(sequence.steps[2].mustBeSignedBy, "0xadmin");
});

test("a step with an unknown argument reports no calldata rather than fabricating one", () => {
  const sequence = describeIssuanceSequence({ token: "0xtoken", minterRole: MINTER,
    issuanceWallet: ISSUER, adapterAddress: null, units: null, adminAddress: "0xadmin" });
  assert.equal(sequence.steps[1].calldata, null);
});

// --- adapter preconditions ---

const TOKEN = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const OWNER = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const ZERO = "0x0000000000000000000000000000000000000000";
const goodAdapter = (overrides = {}) => ({
  code: "0x6080", token: TOKEN, apass: APASS, owner: OWNER, boundVault: ZERO,
  expected: { token: TOKEN, apass: APASS, owner: OWNER }, ...overrides,
});

test("a correctly configured, unbound adapter passes", () => {
  assert.equal(checkAdapterPreconditions(goodAdapter()).ok, true);
});

test("an adapter with no code is refused", () => {
  assert.equal(checkAdapterPreconditions(goodAdapter({ code: "0x" })).ok, false);
});

test("an adapter pointing at another token or A-Pass is refused", () => {
  assert.equal(checkAdapterPreconditions(goodAdapter({ token: ZERO })).ok, false);
  assert.equal(checkAdapterPreconditions(goodAdapter({ apass: ZERO })).ok, false);
});

test("an adapter owned by someone else is refused", () => {
  assert.equal(checkAdapterPreconditions(goodAdapter({ owner: ZERO })).ok, false);
});

test("an already bound adapter is refused, since bindVault is one-shot", () => {
  const result = checkAdapterPreconditions(goodAdapter({ boundVault: "0xdead" }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /already bound/);
});

test("preconditions ignore checksum casing", () => {
  assert.equal(checkAdapterPreconditions(goodAdapter({ token: TOKEN.toLowerCase() })).ok, true);
});

// --- roster ---

test("the roster resolves addresses and keeps HOLDER_A and HOLDER_B as existing", () => {
  const roster = buildRoster(
    { MORDANT_ADDRESS_HOLDER_A: OWNER, MORDANT_ADDRESS_HOLDER_B: "0xbbb" },
    { [OWNER.toLowerCase()]: true, "0xbbb": true });
  const holderA = roster.find((entry) => entry.roles.includes("holderA"));
  assert.equal(holderA.status, "A-PASS PRESENT");
  const adapter = roster.find((entry) => entry.roles.includes("adapter"));
  assert.equal(adapter.status, "ADDRESS NOT KNOWN YET");
});

test("one wallet filling several roles is listed once, keeping every role", () => {
  const roster = buildRoster(
    { MORDANT_ADDRESS_BUYER: OWNER, MORDANT_ADDRESS_HOLDER_A: OWNER }, { [OWNER.toLowerCase()]: true });
  const shared = roster.filter((entry) => entry.address === OWNER);
  assert.equal(shared.length, 1, "a shared address must not be counted twice");
  assert.deepEqual(shared[0].roles.sort(), ["buyer", "holderA"]);
  assert.deepEqual(shared[0].tokens.sort(), ["MINV01", "aUSDC"]);
});

test("an address without an A-Pass is reported missing, not unknown", () => {
  const roster = buildRoster({ MORDANT_ADDRESS_HOLDER_A: OWNER }, { [OWNER.toLowerCase()]: false });
  assert.equal(roster.find((entry) => entry.roles.includes("holderA")).status, "A-PASS MISSING");
});

// --- tuples ---

test("every required transfer tuple is present, in both directions where the flow demands it", () => {
  const tuples = transferTuples({ adapter: "0xadapter", vault: "0xvault", buyer: "0xbuyer",
    originatorTreasury: "0xorig", holderA: "0xha", holderB: "0xhb" });
  const labels = tuples.map((tuple) => `${tuple.token}:${tuple.from}->${tuple.to}`);
  assert.ok(labels.includes(`MINV01:${ZERO}->0xadapter`), "mint to adapter");
  assert.ok(labels.includes(`MINV01:0xadapter->${ZERO}`), "burn from adapter");
  assert.ok(labels.includes("MINV01:0xadapter->0xha"));
  assert.ok(labels.includes("MINV01:0xadapter->0xhb"));
  assert.ok(labels.includes("aUSDC:0xbuyer->0xvault"));
  assert.ok(labels.includes("aUSDC:0xvault->0xorig"));
  assert.ok(labels.includes("aUSDC:0xvault->0xha"));
  assert.ok(labels.includes("aUSDC:0xvault->0xhb"));
  assert.ok(labels.includes("aUSDC:0xvault->0xbuyer"));
});

test("every required selector is listed, including mint and revokeRole", () => {
  for (const signature of ["mint(address,uint256)", "burn(address,uint256)", "hasRole(bytes32,address)",
    "getRoleAdmin(bytes32)", "grantRole(bytes32,address)", "revokeRole(bytes32,address)"]) {
    assert.ok(REQUIRED_SELECTORS[signature], `missing ${signature}`);
    assert.match(REQUIRED_SELECTORS[signature], /^0x[0-9a-f]{8}$/);
  }
});
