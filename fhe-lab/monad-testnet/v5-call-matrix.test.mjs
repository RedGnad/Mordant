// The call matrix must be verified against the compiled ABI, not trusted.
//
// When this matrix was first written, six selectors were filled in from memory
// and every one of them was wrong. That is the failure mode this file exists to
// make impossible: a plausible-looking selector that no contract implements.
import assert from "node:assert/strict";
import test from "node:test";

import { CALLS, resolveCall, verifyCallMatrix, renderCallMatrix } from "./v5-call-matrix.mjs";

test("every declared call resolves against the compiled ABI", async () => {
  const resolved = await verifyCallMatrix();
  assert.equal(resolved.length, CALLS.length);
  for (const call of resolved) {
    assert.equal(call.resolvedSelector, call.selector, `${call.key}.${call.fn}`);
    assert.equal(call.resolvedMutability, call.mutability, `${call.key}.${call.fn}`);
  }
});

test("every selector is pinned, none left as a placeholder", () => {
  for (const call of CALLS) {
    assert.match(call.selector, /^0x[0-9a-f]{8}$/, `${call.key}.${call.fn}`);
    assert.notEqual(call.selector, "0x00000000", `${call.key}.${call.fn} is unpinned`);
  }
});

test("a function that does not exist fails loudly", async () => {
  await assert.rejects(
    () => resolveCall({ key: "factory", fn: "attestationDigest", mutability: "view" }),
    /CALL_MATRIX_MISSING_FUNCTION: factory.attestationDigest/,
  );
});

// This is the specific API gap recorded in the reconciliation: the factory has
// no attestationDigest view, so the runner derives that digest off chain from
// pinned vectors. If the frozen factory ever gained one, this test would fail
// and the derivation should be replaced by the view.
test("the factory still has no attestationDigest view", async () => {
  await assert.rejects(
    () => resolveCall({ key: "factory", fn: "attestationDigest", mutability: "view" }),
    /CALL_MATRIX_MISSING_FUNCTION/,
  );
});

test("a wrong selector is rejected", async () => {
  const broken = { key: "binder", fn: "bindRecourse", selector: "0xdeadbeef", caller: "any", mutability: "nonpayable" };
  const resolved = await resolveCall(broken);
  assert.notEqual(resolved.resolvedSelector, broken.selector);
});

// The two producer views added after the provisional deployment. Their absence
// is what made that deployment provisional, so their presence is asserted.
test("the producer-side digest views exist with their pinned selectors", async () => {
  const wanted = {
    resultCommitmentOf: "0xf417e039",
    resultStructHash: "0xa2538a0c",
  };
  for (const [fn, selector] of Object.entries(wanted)) {
    const call = await resolveCall({ key: "verifier", fn, mutability: "pure" });
    assert.equal(call.resolvedSelector, selector, fn);
  }
});

// acceptMatch must never be broadcast externally. Recording its caller as the
// binder contract is how the runner knows not to expose it.
test("acceptMatch is declared as an internal-only call", () => {
  const call = CALLS.find((entry) => entry.key === "verifier" && entry.fn === "acceptMatch");
  assert.equal(call.caller, "binder-contract");
  assert.match(call.effect, /INTERNAL ONLY/);
});

test("bindRecourse is the only external state-changing binder call", () => {
  const binderCalls = CALLS.filter((entry) => entry.key === "binder");
  const mutating = binderCalls.filter((entry) => entry.mutability === "nonpayable");
  assert.deepEqual(mutating.map((entry) => entry.fn), ["bindRecourse"]);
});

// Each caller matters: several of these revert for the wrong sender by design.
test("privileged calls record a specific caller", () => {
  const expected = {
    commitSession: "relayer",
    commitSource: "submitter",
    createIdentityAnchoredVault: "buyer",
  };
  for (const [fn, caller] of Object.entries(expected)) {
    const call = CALLS.find((entry) => entry.fn === fn);
    assert.equal(call.caller, caller, fn);
  }
});

test("the rendered matrix carries a signature and effect for every call", async () => {
  const rows = await renderCallMatrix();
  assert.equal(rows.length, CALLS.length);
  for (const row of rows) {
    assert.ok(row.signature.includes("("), row.signature);
    assert.ok(row.effect && row.effect.length > 0, `${row.contract} missing effect`);
  }
});
