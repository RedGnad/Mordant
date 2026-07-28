import assert from "node:assert/strict";
import { test } from "node:test";

import {
  INCOMPATIBLE_PAIRS, KNOWN_INPUTS, PHASES, PHASE_INPUT, REQUIRED_INPUTS, assertAllReady,
  assertOnlyExpectedMinter, assertReadbacksMatch, assertRolesCompatible, assertRuntimeHash,
  assessReadiness, loadParticipants, loadPreviousArtifact, nextPhase, packageStatus, resolveMode,
} from "./m15-phase-lib.mjs";
import { PHASE_PLAN, expectedRuntimeHashes } from "./m15-phase-runner.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);
const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";
const C = "0x3333333333333333333333333333333333333333";

const fullEnv = (overrides = {}) => ({
  MORDANT_ADDRESS_HOLDER_A: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45",
  MORDANT_ADDRESS_HOLDER_B: "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6",
  MORDANT_ADDRESS_BUYER: A, MORDANT_ADDRESS_FUNDER: B,
  MORDANT_ADDRESS_ORIGINATOR: C,
  MORDANT_ADDRESS_FACILITY_A: "0x4444444444444444444444444444444444444444",
  MORDANT_ADDRESS_FACILITY_B: "0x5555555555555555555555555555555555555555",
  MORDANT_ADDRESS_ISSUANCE_MINTER: "0x6666666666666666666666666666666666666666",
  ...overrides,
});

// --- configuration: nothing is chosen or defaulted ---

test("a complete configuration loads", () => {
  const { complete, missing, participants } = loadParticipants(fullEnv());
  assert.equal(complete, true);
  assert.deepEqual(missing, []);
  assert.equal(Object.keys(participants).length, 8);
});

test("a missing address is refused, never defaulted", () => {
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_BUYER: undefined })));
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_FUNDER: "" })));
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_ORIGINATOR: "   " })));
});

test("check mode reports every gap at once rather than stopping at the first", () => {
  const { complete, missing } = loadParticipants(
    { MORDANT_ADDRESS_HOLDER_A: A }, { requireAll: false });
  assert.equal(complete, false);
  assert.ok(missing.includes("buyer"));
  assert.ok(missing.includes("issuanceMinter"));
  assert.equal(missing.length, 7);
});

test("a malformed address is refused even when nothing is missing", () => {
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_BUYER: "0xnothex" })));
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_BUYER: "1111111111111111111111111111111111111111" })));
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_BUYER: `${A}00` })));
});

test("the six required inputs are exactly the ones the owner still owes", () => {
  assert.deepEqual(REQUIRED_INPUTS.map((entry) => entry.key),
    ["buyer", "funder", "originator", "facilityProtected", "facilityChallenger", "issuanceMinter"]);
  assert.deepEqual(KNOWN_INPUTS.map((entry) => entry.key), ["holderA", "holderB"]);
});

test("only the funder is required to hold aUSDC", () => {
  const funded = [...KNOWN_INPUTS, ...REQUIRED_INPUTS].filter((entry) => entry.needsAUsdc > 0n);
  assert.equal(funded.length, 1);
  assert.equal(funded[0].key, "funder");
});

// --- incompatible roles ---

test("the funder may not be the buyer", () => {
  assert.throws(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_FUNDER: A })),
    /funder and buyer are the same address/);
});

test("the two facilities may not be the same address", () => {
  assert.throws(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_FACILITY_B: "0x4444444444444444444444444444444444444444" })),
    /facilityProtected and facilityChallenger are the same address/);
});

test("the issuance minter may not be a holder that outlives the ceremony", () => {
  stops(() => loadParticipants(fullEnv({
    MORDANT_ADDRESS_ISSUANCE_MINTER: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45" })));
});

test("the originator may not also be a facility or the buyer", () => {
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_ORIGINATOR: A })));
  stops(() => loadParticipants(fullEnv({ MORDANT_ADDRESS_ORIGINATOR: "0x4444444444444444444444444444444444444444" })));
});

test("role comparison ignores checksum casing", () => {
  stops(() => assertRolesCompatible({ funder: A.toUpperCase().replace("0X", "0x"), buyer: A }));
});

test("every incompatible pair carries the reason the contracts refuse it", () => {
  for (const pair of INCOMPATIBLE_PAIRS) {
    assert.ok(pair.why.length > 20, `${pair.a}/${pair.b} has no explanation`);
  }
});

// --- readiness ---

const ready = (overrides = {}) => assessReadiness({ key: "funder", address: B,
  isValidAPass: true, monBalance: 10n ** 18n, aUsdcBalance: 100_000n,
  requiredMon: 10n ** 15n, requiredAUsdc: 100_000n, ...overrides });

test("a funded, credentialed participant is ready", () => {
  assert.equal(ready().ready, true);
});

test("a participant without an A-Pass is not ready", () => {
  assert.equal(ready({ isValidAPass: false }).ready, false);
  assert.equal(ready({ isValidAPass: null }).ready, false);
});

test("insufficient MON blocks a participant", () => {
  const result = ready({ monBalance: 1n });
  assert.equal(result.ready, false);
  assert.match(result.problems.join(), /MON 1 below/);
});

test("insufficient aUSDC blocks only those who need it", () => {
  assert.equal(ready({ aUsdcBalance: 1n }).ready, false);
  // A participant needing none is unaffected by holding none.
  assert.equal(assessReadiness({ key: "buyer", address: A, isValidAPass: true,
    monBalance: 10n ** 18n, aUsdcBalance: 0n, requiredMon: 1n, requiredAUsdc: 0n }).ready, true);
});

test("an unreadable balance is treated as insufficient, not as unknown", () => {
  assert.equal(ready({ monBalance: null }).ready, false);
  assert.equal(ready({ aUsdcBalance: undefined }).ready, false);
});

test("a phase refuses to run while any participant is blocked", () => {
  assert.equal(assertAllReady([ready()]), true);
  stops(() => assertAllReady([ready(), ready({ key: "buyer", isValidAPass: false })]));
});

// --- phase chaining ---

test("each phase consumes exactly the previous one", () => {
  assert.deepEqual(PHASES, ["A", "B", "C1", "C2", "D", "E", "F"]);
  assert.equal(PHASE_INPUT.A, null);
  assert.equal(PHASE_INPUT.B, "A");
  assert.equal(PHASE_INPUT.D, "C2");
  assert.equal(PHASE_INPUT.F, "E");
});

test("phase A needs no predecessor", () => {
  assert.equal(loadPreviousArtifact("A", null), null);
});

test("a later phase without its predecessor artifact is refused", () => {
  stops(() => loadPreviousArtifact("B", null));
});

test("an artifact from the wrong phase is refused", () => {
  const read = () => JSON.stringify({ phase: "C1", status: "SUCCESS" });
  assert.throws(() => loadPreviousArtifact("B", "x.json", read), /is a phase C1 artifact/);
});

test("a predecessor that did not succeed is refused", () => {
  for (const status of ["PENDING", "STOPPED", "CHECK ONLY"]) {
    const read = () => JSON.stringify({ phase: "A", status });
    assert.throws(() => loadPreviousArtifact("B", "x.json", read), /not SUCCESS/);
  }
});

test("an unreadable or corrupt artifact is refused", () => {
  stops(() => loadPreviousArtifact("B", "x.json", () => "not json"));
  stops(() => loadPreviousArtifact("B", "x.json", () => { throw new Error("missing"); }));
});

test("a correct predecessor is accepted and returned", () => {
  const read = () => JSON.stringify({ phase: "A", status: "SUCCESS", adapter: A });
  assert.equal(loadPreviousArtifact("B", "x.json", read).adapter, A);
});

// --- no phase triggers the next ---

test("every phase reports the next as a separate deliberate command", () => {
  for (const phase of PHASES.slice(0, -1)) {
    const { next, instruction } = nextPhase(phase);
    assert.ok(next);
    assert.match(instruction, /STOP\./);
    assert.match(instruction, /never triggered from here/);
  }
});

test("the final phase reports no successor", () => {
  assert.equal(nextPhase("F").next, null);
});

test("an unknown phase is refused", () => {
  stops(() => nextPhase("G"));
});

// --- the write gate ---

test("check is the default and needs nothing", () => {
  assert.equal(resolveMode([]), "check");
  assert.equal(resolveMode(["--check"]), "check");
});

test("--run is refused while public writes are not authorized", () => {
  assert.throws(() => resolveMode(["--run", "--out", "x"]), /NOT AUTHORIZED/);
});

test("--run without --out is refused even once authorized", () => {
  assert.throws(() => resolveMode(["--run"], { publicWritesAuthorized: true }), /--out/);
});

test("--run with --out is allowed only once authorized", () => {
  assert.equal(resolveMode(["--run", "--out", "x"], { publicWritesAuthorized: true }), "run");
});

// --- on-chain state must match the manifest ---

const HASH = `0x${"ab".repeat(32)}`;

test("a matching runtime hash passes", () => {
  assert.equal(assertRuntimeHash("adapter", HASH, HASH.toUpperCase().replace("0X", "0x")), true);
});

test("a wrong contract hash is refused", () => {
  assert.throws(() => assertRuntimeHash("adapter", `0x${"cd".repeat(32)}`, HASH),
    /not the reviewed contract/);
});

test("an address with no code is refused", () => {
  stops(() => assertRuntimeHash("adapter", "0x", HASH));
  stops(() => assertRuntimeHash("adapter", null, HASH));
});

test("readbacks matching the manifest pass", () => {
  assert.equal(assertReadbacksMatch("adapter", { owner: A, units: 100n }, { owner: A, units: 100n }), true);
});

test("an unexpected on-chain readback is refused and named", () => {
  assert.throws(() => assertReadbacksMatch("adapter", { owner: B }, { owner: A }), /owner is/);
  assert.throws(() => assertReadbacksMatch("adapter", { units: 99n }, { units: 100n }), /units is 99/);
});

// --- minter exclusivity before binding ---

test("the adapter alone as active minter passes", () => {
  assert.equal(assertOnlyExpectedMinter([A], A), true);
});

test("an unexpected minter before binding is refused", () => {
  assert.throws(() => assertOnlyExpectedMinter([A, B], A), /unexpected active minter/);
  assert.throws(() => assertOnlyExpectedMinter([B], A), /unexpected active minter/);
});

test("an adapter that is not a minter is refused", () => {
  assert.throws(() => assertOnlyExpectedMinter([], A), /does not hold MINTER_ROLE/);
});

test("an unreconstructable history is refused, never assumed clean", () => {
  assert.throws(() => assertOnlyExpectedMinter(null, A), /unproven. Do not bind/);
});

// --- the package's own status ---

test("the package is ready while its inputs are not", () => {
  const statuses = packageStatus({ runnersComplete: true, inputsComplete: false });
  assert.equal(statuses["LIVE EXECUTION ENGINE"], "READY");
  assert.equal(statuses["EXECUTION INPUTS"], "INCOMPLETE");
});

test("public writes stay unauthorized whatever else holds", () => {
  for (const runnersComplete of [true, false]) {
    for (const inputsComplete of [true, false]) {
      const statuses = packageStatus({ runnersComplete, inputsComplete });
      assert.equal(statuses["PUBLIC WRITES"], "NOT AUTHORIZED");
      assert.equal(statuses["MORDANT SETTLEMENT"], "NOT PROVEN LIVE");
    }
  }
});

// --- the plan each phase carries ---

test("every phase has a plan naming what it writes and verifies", () => {
  for (const phase of PHASES) {
    const plan = PHASE_PLAN[phase];
    assert.ok(plan, `phase ${phase} has no plan`);
    assert.ok(plan.writes.length > 0, `phase ${phase} writes nothing`);
    assert.ok(plan.verifies.length > 0, `phase ${phase} verifies nothing`);
  }
});

test("every phase touching Cleanverse forbids an automatic retry", () => {
  for (const phase of PHASES) {
    const plan = PHASE_PLAN[phase];
    if (plan.cleanverse.length === 0) continue;
    assert.ok(plan.ambiguityRule, `phase ${phase} calls Cleanverse with no ambiguity rule`);
  }
});

test("C2 records that creation starts the clock", () => {
  assert.match(PHASE_PLAN.C2.note, /24 hour clock/);
});

test("the expected runtime hashes come from the frozen artifacts", () => {
  const hashes = expectedRuntimeHashes("A");
  assert.equal(hashes.length, 1);
  assert.equal(hashes[0].name, "CleanverseCvaAdapter");
  assert.match(hashes[0].expectedRuntimeHash, /^0x[0-9a-f]{64}$/);
});

test("phases that deploy nothing expect no contract hash", () => {
  for (const phase of ["B", "D", "E", "F"]) {
    assert.deepEqual(expectedRuntimeHashes(phase), []);
  }
});
