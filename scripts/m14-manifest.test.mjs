import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTRACTS, FROZEN_COMMIT, LIVE_PATH, PARTICIPANTS, PHASES, REQUIRED_GATES, STOP_MATRIX,
  PUBLIC_SCHEDULE, REHEARSAL, STRUCTURAL_PARAMETERS, assertFrozenVersion, assertGatesComplete,
  assertNoWriteMode, classifyManifest, computeProtectionEnd, parameterSetHash,
} from "./m14-manifest.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

// --- M-14 never writes ---

test("a read-only invocation is allowed", () => {
  assert.equal(assertNoWriteMode(["--out", "x"]), true);
  assert.equal(assertNoWriteMode([]), true);
});

test("every write flag is refused", () => {
  for (const flag of ["--run", "--broadcast", "--deploy", "--execute", "--send"]) {
    stops(() => assertNoWriteMode([flag]));
    stops(() => assertNoWriteMode(["--out", "x", flag]));
  }
});

// --- the freeze covers contracts and parameters, not the whole tree ---

const clean = { contractsChanged: [], contractsDirty: [], parametersChanged: [] };

test("an unchanged contract tree passes and returns the frozen commit", () => {
  assert.equal(assertFrozenVersion(clean), FROZEN_COMMIT);
});

test("a changed contract stops the manifest", () => {
  stops(() => assertFrozenVersion({ ...clean, contractsChanged: ["contracts/src/MordantInvoiceVault.sol"] }));
});

test("uncommitted contract changes stop the manifest", () => {
  stops(() => assertFrozenVersion({ ...clean, contractsDirty: [" M contracts/src/x.sol"] }));
});

test("a changed structural parameter stops the manifest", () => {
  // The parameters are what the rehearsal exercised, so moving one invalidates it too.
  stops(() => assertFrozenVersion({ ...clean, parametersChanged: ["faceValue"] }));
});

test("the freeze does not fire on scripts or documents", () => {
  // Otherwise the manifest could never be written, since writing it changes the tree.
  assert.equal(assertFrozenVersion(clean), FROZEN_COMMIT);
});

// --- the gates every future public command must carry ---

test("a command declaring every gate passes", () => {
  assert.equal(assertGatesComplete([...REQUIRED_GATES]), true);
});

test("a command missing any single gate is refused, and the gate is named", () => {
  for (const gate of REQUIRED_GATES) {
    const declared = REQUIRED_GATES.filter((entry) => entry !== gate);
    assert.throws(() => assertGatesComplete(declared), (error) => {
      assert.ok(error instanceof ControlError);
      assert.ok(error.message.includes(gate), `expected ${gate} to be named`);
      return true;
    });
  }
});

test("the required gates cover the controls earlier missions established", () => {
  const joined = REQUIRED_GATES.join(" | ");
  for (const expected of ["--run and --out", "chain id 10143", "derived from the signing key",
    "simulates or estimates", "gas ceilings", "PENDING before awaiting the receipt",
    "PENDING, STOPPED and SUCCESS", "differs from the preceding manifest"]) {
    assert.ok(joined.includes(expected), `missing gate: ${expected}`);
  }
});

// --- the manifest's own shape ---

test("the live path is the recourse demonstration, not cash redemption", () => {
  assert.deepEqual(LIVE_PATH, ["activation", "conflict commit", "conflict reveal", "finalisation",
    "default", "MINV01 release"]);
  assert.equal(LIVE_PATH.some((step) => step.includes("redemption")), false);
});

test("exactly the intended participant roles are listed", () => {
  const roles = PARTICIPANTS.map((entry) => entry.role);
  for (const expected of ["holderA", "holderB", "buyer", "funder", "originator",
    "facilityProtected", "facilityChallenger", "issuanceMinter"]) {
    assert.ok(roles.includes(expected), `missing ${expected}`);
  }
  // Two facilities, because the protected one cannot challenge itself.
  assert.equal(roles.filter((role) => role.startsWith("facility")).length, 2);
});

test("only the funder needs aUSDC, and exactly the advance", () => {
  const funded = PARTICIPANTS.filter((entry) => entry.needsAUsdc !== "0");
  assert.equal(funded.length, 1);
  assert.equal(funded[0].role, "funder");
  assert.equal(funded[0].needsAUsdc, STRUCTURAL_PARAMETERS.advanceAmount);
});

test("the buyer funds nothing, since the live path stops before redemption", () => {
  const buyer = PARTICIPANTS.find((entry) => entry.role === "buyer");
  assert.equal(buyer.needsAUsdc, "0");
  assert.match(buyer.note, /never funds redemption/);
});

test("every phase ends at a stop, so none can trigger the next", () => {
  for (const phase of PHASES.slice(0, -1)) {
    assert.equal(phase.steps.at(-1), "STOP", `phase ${phase.id} does not end at a stop`);
  }
});

test("phase B forbids an automatic retry of the Cleanverse request", () => {
  const phaseB = PHASES.find((phase) => phase.id === "B");
  assert.ok(phaseB.steps.some((step) => step.includes("never retry automatically")));
});

test("phase D refuses to bind unless the adapter is the only minter", () => {
  const phaseD = PHASES.find((phase) => phase.id === "D");
  const exclusivity = phaseD.steps.findIndex((step) => step.includes("only active minter"));
  const bind = phaseD.steps.findIndex((step) => step.startsWith("bindVault"));
  assert.ok(exclusivity !== -1 && bind !== -1);
  assert.ok(exclusivity < bind, "exclusivity must be checked before binding");
});

test("the factory is recorded as exceeding EIP-170", () => {
  // It only deploys because Monad documents 128 KB; that is a deployment precondition, not a detail.
  const factory = CONTRACTS.find((entry) => entry.name === "MordantFactory");
  assert.equal(factory.phase, "C1");
  assert.equal(factory.addressPredictable, false);
});

test("no contract claims a predictable address", () => {
  // Both the adapter and the vault are created dynamically, which is why their A-Passes follow.
  assert.equal(CONTRACTS.every((entry) => entry.addressPredictable === false), true);
});

// --- the stop matrix ---

test("every stop point in the sequence has an entry", () => {
  const entries = STOP_MATRIX.map((entry) => entry.after);
  for (const expected of ["adapter deployed, no A-Pass", "adapter A-Pass issued, no infrastructure",
    "vault created, no A-Pass", "temporary minter granted, not revoked", "supply minted, not bound",
    "adapter bound, vault not activated", "activated, conflict not started"]) {
    assert.ok(entries.includes(expected), `missing stop entry: ${expected}`);
  }
});

test("the two dangerous stop states are marked urgent", () => {
  const urgent = STOP_MATRIX.filter((entry) => entry.urgent === true).map((entry) => entry.after);
  assert.ok(urgent.includes("temporary minter granted, not revoked"));
  assert.ok(urgent.includes("supply minted, not bound"));
});

test("an unrevoked minter is told to revoke before anything else", () => {
  const entry = STOP_MATRIX.find((item) => item.after === "temporary minter granted, not revoked");
  assert.match(entry.action, /REVOKE FIRST/);
});

test("no stop entry describes an automatic recovery", () => {
  // An automatic recovery is how a half-finished deployment becomes two.
  for (const entry of STOP_MATRIX) {
    assert.equal(/automatic(ally)? (recover|retr|resum)/i.test(entry.action), false, entry.after);
  }
});

test("states past binding are marked non-redeployable", () => {
  for (const after of ["supply minted, not bound", "adapter bound, vault not activated",
    "activated, conflict not started"]) {
    assert.equal(STOP_MATRIX.find((entry) => entry.after === after).redeployable, false, after);
  }
});

// --- the 24 hour protection window ---

test("protectionEnd is computed from the creation block, never fixed in advance", () => {
  assert.equal(computeProtectionEnd(1_785_000_000n), 1_785_000_000n + 86_400n);
});

test("a caller with no creation timestamp is refused rather than given a guess", () => {
  stops(() => computeProtectionEnd(undefined));
  stops(() => computeProtectionEnd(0n));
  stops(() => computeProtectionEnd(1_785_000_000));
});

test("the public protection duration is 24 hours", () => {
  assert.equal(STRUCTURAL_PARAMETERS.protectionDurationSeconds, 86_400);
});

test("the parameter set hash is stable and order-independent", () => {
  assert.equal(parameterSetHash(), parameterSetHash({ ...STRUCTURAL_PARAMETERS }));
  const reordered = Object.fromEntries(Object.entries(STRUCTURAL_PARAMETERS).reverse());
  assert.equal(parameterSetHash(reordered), parameterSetHash());
});

test("any parameter change moves the hash, so a drift cannot be argued away", () => {
  assert.notEqual(parameterSetHash({ ...STRUCTURAL_PARAMETERS, protectionDurationSeconds: 3_600 }),
    parameterSetHash());
  assert.notEqual(parameterSetHash({ ...STRUCTURAL_PARAMETERS, faceValue: "1" }), parameterSetHash());
});

test("the rehearsal records both commits separately", () => {
  // The contracts are frozen at one commit; the rehearsal that proved these parameters is another.
  assert.equal(REHEARSAL.contractsCommit, FROZEN_COMMIT);
  assert.notEqual(REHEARSAL.rehearsalCommit, FROZEN_COMMIT);
  assert.match(REHEARSAL.verdict, /PROVEN/);
});

// --- phase C is split so the window is not spent waiting ---

test("phase C is split into C1 and C2", () => {
  const ids = PHASES.map((phase) => phase.id);
  assert.deepEqual(ids, ["A", "B", "C1", "C2", "D", "E", "F"]);
});

test("the vault is created only when the rest can follow immediately", () => {
  const c2 = PHASES.find((phase) => phase.id === "C2");
  assert.ok(c2.steps[0].includes("ONLY when phases D and E can run immediately"));
  assert.ok(c2.steps.some((step) => step.includes("never a date fixed earlier")));
});

test("known participants are credentialed before the vault exists", () => {
  const c1 = PHASES.find((phase) => phase.id === "C1");
  assert.ok(c1.steps.some((step) => step.includes("addresses already known")));
  assert.ok(c1.steps.some((step) => step.includes("verify funding")));
});

// --- status while inputs are missing ---

test("a complete structure with missing addresses is not a ready manifest", () => {
  const statuses = classifyManifest({ structureComplete: true, unsuppliedAddresses: 6 });
  assert.equal(statuses["MANIFEST STRUCTURE"], "READY");
  assert.equal(statuses["EXECUTION INPUTS"], "INCOMPLETE");
  assert.equal(statuses["LIVE DEPLOYMENT MANIFEST"], undefined);
});

test("only a complete structure with every address is a ready manifest", () => {
  const statuses = classifyManifest({ structureComplete: true, unsuppliedAddresses: 0 });
  assert.equal(statuses["LIVE DEPLOYMENT MANIFEST"], "READY");
  assert.equal(statuses["EXECUTION INPUTS"], undefined);
});

test("public writes stay unauthorized in every status combination", () => {
  for (const structureComplete of [true, false]) {
    for (const unsuppliedAddresses of [0, 6]) {
      assert.equal(classifyManifest({ structureComplete, unsuppliedAddresses })["PUBLIC WRITES"],
        "NOT AUTHORIZED");
    }
  }
});

// --- the public schedule ---

test("the schedule creates and activates in one sitting, then waits the real windows", () => {
  const slots = PUBLIC_SCHEDULE.map((entry) => entry.slot);
  assert.ok(slots.some((slot) => slot.includes("T0, one sitting")));
  assert.ok(slots.some((slot) => slot.includes("1 hour")));
  assert.ok(slots.some((slot) => slot.includes("24 hours")));
  assert.equal(PUBLIC_SCHEDULE[0].does.includes("activation"), true);
});

// --- address vocabulary ---

test("CREATE addresses are called deterministic but not stable before confirmation", () => {
  const adapter = CONTRACTS.find((entry) => entry.name === "CleanverseCvaAdapter");
  assert.match(adapter.addressNote, /deterministic/);
  assert.match(adapter.addressNote, /not treated as stable until the deployment is confirmed/);
  assert.match(adapter.addressNote, /No A-Pass is requested on the strength of a computed address/);
});

test("no contract note claims addresses are unpredictable", () => {
  for (const contract of CONTRACTS) {
    assert.equal(/not predictable|unpredictable/i.test(contract.addressNote ?? ""), false, contract.name);
  }
});
