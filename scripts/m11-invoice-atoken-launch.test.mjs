import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertLaunchKeyUnused, assertNameAndSymbolFree, classifyLaunch, classifyMinterAuthority, launchKey,
  profilesSatisfying, resolveRule,
} from "./m11-invoice-atoken-launch.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

const profile = (label, overrides = {}) => ({
  label, address: `0x${label}`, tier: 50, subTier: 0, group: "", subGroup: "", ...overrides,
});

// --- the rule is derived, never assumed ---

test("the rule takes the lowest tier any planned profile holds", () => {
  const rule = resolveRule([profile("a"), profile("b", { tier: 20 }), profile("c", { tier: 50 })]);
  assert.equal(rule.min_tier, 20);
  assert.equal(rule.min_sub_tier, 0);
});

test("the rule takes the lowest subTier too", () => {
  const rule = resolveRule([profile("a", { subTier: 30 }), profile("b", { subTier: 10 })]);
  assert.equal(rule.min_sub_tier, 10);
});

test("with our real profiles the rule is min_tier 50 and nothing else constrained", () => {
  const rule = resolveRule([profile("HOLDER_A"), profile("HOLDER_B"), profile("probe")]);
  assert.deepEqual(rule, { allowed_group: "", allowed_sub_group: "", min_tier: 50, min_sub_tier: 0 });
});

test("a group shared by every profile may be required", () => {
  const rule = resolveRule([profile("a", { group: "EU" }), profile("b", { group: "EU" })]);
  assert.equal(rule.allowed_group, "EU");
});

test("mixed groups leave the constraint open, since requiring one would exclude the others", () => {
  const rule = resolveRule([profile("a", { group: "EU" }), profile("b", { group: "US" })]);
  assert.equal(rule.allowed_group, "");
});

test("an empty group is never turned into a constraint", () => {
  assert.equal(resolveRule([profile("a"), profile("b")]).allowed_group, "");
});

test("no profiles, or an unreadable tier, stops rather than guessing a rule", () => {
  stops(() => resolveRule([]));
  stops(() => resolveRule(null));
  stops(() => resolveRule([profile("a", { tier: null })]));
  stops(() => resolveRule([profile("a", { tier: undefined })]));
  stops(() => resolveRule([profile("a", { tier: "" })]));
  stops(() => resolveRule([profile("a", { tier: "x" })]));
  stops(() => resolveRule([profile("a", { subTier: null })]));
  stops(() => resolveRule([profile("a", { subTier: -1 })]));
});

// --- and the derived rule must actually admit everyone ---

test("every planned profile satisfies the rule derived from it", () => {
  const profiles = [profile("a"), profile("b", { tier: 20 })];
  const rule = resolveRule(profiles);
  assert.equal(profilesSatisfying(rule, profiles).every((entry) => entry.satisfies), true);
});

test("a profile below the rule is reported with its reason", () => {
  const rule = { allowed_group: "", allowed_sub_group: "", min_tier: 50, min_sub_tier: 0 };
  const [checked] = profilesSatisfying(rule, [profile("low", { tier: 20 })]);
  assert.equal(checked.satisfies, false);
  assert.match(checked.reasons.join(), /tier 20 < 50/);
});

test("a group mismatch is reported", () => {
  const rule = { allowed_group: "EU", allowed_sub_group: "", min_tier: 0, min_sub_tier: 0 };
  const [checked] = profilesSatisfying(rule, [profile("us", { group: "US" })]);
  assert.equal(checked.satisfies, false);
  assert.match(checked.reasons.join(), /group "US" is not "EU"/);
});

// --- the deterministic key ---

const request = (overrides = {}) => ({
  chain: "monad", token_name: "Mordant Invoice Note", token_symbol: "MINV01", decimals: 6,
  admin_address: "0xABCdef0000000000000000000000000000000001",
  rule: { allowed_group: "", allowed_sub_group: "", min_tier: 50, min_sub_tier: 0 },
  icon: "https://example.test/icon.png", ...overrides,
});

test("the same intent always produces the same key", () => {
  assert.equal(launchKey(request()), launchKey(request()));
});

test("the key ignores fields that do not define the token", () => {
  // A different icon is the same launch; it must not look like a fresh one.
  assert.equal(launchKey(request()), launchKey(request({ icon: "https://other.test/x.png" })));
});

test("admin address casing does not change the key", () => {
  assert.equal(launchKey(request()),
    launchKey(request({ admin_address: "0xabcdef0000000000000000000000000000000001" })));
});

test("any defining change produces a different key", () => {
  const baseline = launchKey(request());
  assert.notEqual(baseline, launchKey(request({ token_symbol: "MINV02" })));
  assert.notEqual(baseline, launchKey(request({ token_name: "Other" })));
  assert.notEqual(baseline, launchKey(request({ decimals: 18 })));
  assert.notEqual(baseline, launchKey(request({
    rule: { allowed_group: "", allowed_sub_group: "", min_tier: 20, min_sub_tier: 0 } })));
});

// --- the key is binding, not merely informative ---

const KEY = "a".repeat(64);
const artifact = (overrides = {}) => ({
  path: "docs/evidence/prior.json",
  report: { launchKey: KEY, launchAttemptedAt: "2026-07-28T19:22:21.502Z", ...overrides },
});

test("an unused key passes, including against an empty evidence directory", () => {
  assert.equal(assertLaunchKeyUnused(KEY, []), true);
  assert.equal(assertLaunchKeyUnused(KEY, [artifact({ launchKey: "b".repeat(64) })]), true);
});

test("a prior attempt blocks the key whatever its outcome", () => {
  // All three outcomes must block: PENDING may still be issuing, an ambiguous failure may have been
  // accepted anyway, and an issued one already exists.
  for (const classification of [
    "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING",
    "INVOICE A-TOKEN LAUNCH: FAILED",
    "INVOICE A-TOKEN LAUNCH: ISSUED / READBACK PROVEN",
  ]) {
    stops(() => assertLaunchKeyUnused(KEY, [artifact({ classification })]));
  }
});

test("a stopped run that had already sent still blocks the key", () => {
  stops(() => assertLaunchKeyUnused(KEY, [artifact({ status: "STOPPED", classification: undefined })]));
});

test("an artifact carrying the key but no attempt does not block", () => {
  // A check-mode artifact records the key without having sent anything.
  assert.equal(assertLaunchKeyUnused(KEY, [artifact({ launchAttemptedAt: undefined })]), true);
});

test("the blocking message names the artifact and the time, so it can be reconciled", () => {
  assert.throws(() => assertLaunchKeyUnused(KEY, [artifact()]),
    /docs\/evidence\/prior\.json at 2026-07-28T19:22:21\.502Z/);
});

// --- minter authority, read only ---

const MINTER = `0x${"9f".repeat(32)}`;
const ADMIN_ROLE = `0x${"00".repeat(32)}`;

test("an admin holding the administering role can grant", () => {
  assert.equal(
    classifyMinterAuthority({ minterRole: MINTER, roleAdmin: ADMIN_ROLE, adminHoldsRoleAdmin: true }),
    "MINTER ROLE AUTHORITY: ADMIN CAN GRANT");
});

test("an admin without the administering role cannot grant", () => {
  for (const adminHoldsRoleAdmin of [false, null, undefined, "true"]) {
    assert.equal(
      classifyMinterAuthority({ minterRole: MINTER, roleAdmin: ADMIN_ROLE, adminHoldsRoleAdmin }),
      "MINTER ROLE AUTHORITY: ADMIN CANNOT GRANT");
  }
});

test("an unreadable role is reported as unreadable, not as a refusal", () => {
  assert.equal(classifyMinterAuthority({ minterRole: MINTER, roleAdmin: null, adminHoldsRoleAdmin: true }),
    "MINTER ROLE AUTHORITY: NOT READABLE");
  assert.equal(classifyMinterAuthority({ minterRole: null, roleAdmin: ADMIN_ROLE, adminHoldsRoleAdmin: true }),
    "MINTER ROLE AUTHORITY: NOT READABLE");
});

test("authority is never described as a granted role", () => {
  for (const adminHoldsRoleAdmin of [true, false]) {
    const verdict = classifyMinterAuthority({ minterRole: MINTER, roleAdmin: ADMIN_ROLE, adminHoldsRoleAdmin });
    assert.match(verdict, /^MINTER ROLE AUTHORITY: /);
    assert.equal(verdict.includes("GRANTED"), false);
  }
});

// --- uniqueness ---

const existing = [
  { requestId: "IA1", applyStatus: "ISSUED", tokenName: "Clearwave USD", tokenSymbol: "CWUSD" },
  { requestId: "IA2", applyStatus: "ISSUE_FAILED", tokenName: "SPT Probe 0001", tokenSymbol: "SPT0001" },
];

test("a free name and symbol passes", () => {
  assert.equal(assertNameAndSymbolFree(existing, "Mordant Invoice Note", "MINV01"), true);
});

test("a taken name stops the run, whatever its case", () => {
  stops(() => assertNameAndSymbolFree(existing, "clearwave usd", "MINV01"));
});

test("a taken symbol stops the run, whatever its case", () => {
  stops(() => assertNameAndSymbolFree(existing, "Mordant Invoice Note", "cwusd"));
});

test("a failed prior launch still reserves the name, since it may be retried by its owner", () => {
  stops(() => assertNameAndSymbolFree(existing, "SPT Probe 0001", "MINV01"));
});

// --- the verdict ---

const readbackOk = { ok: true };

test("a launch that never left is failed", () => {
  assert.equal(classifyLaunch({ submitted: false }), "INVOICE A-TOKEN LAUNCH: FAILED");
});

test("a rejected or failed issuance is failed", () => {
  for (const applyStatus of ["REJECTED", "ISSUE_FAILED"]) {
    assert.equal(classifyLaunch({ submitted: true, applyStatus }), "INVOICE A-TOKEN LAUNCH: FAILED");
  }
});

test("an accepted launch that has not settled is pending, never failed", () => {
  // Calling an in-flight launch failed would invite a second submission.
  for (const applyStatus of ["PENDING", "APPROVED", "ISSUING", null, undefined]) {
    assert.equal(classifyLaunch({ submitted: true, applyStatus }),
      "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING");
  }
});

test("ISSUED without a clean readback stays pending", () => {
  // Cleanverse saying issued is not the chain saying it.
  assert.equal(classifyLaunch({ submitted: true, applyStatus: "ISSUED", readback: null }),
    "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING");
  assert.equal(classifyLaunch({ submitted: true, applyStatus: "ISSUED", readback: { ok: false } }),
    "INVOICE A-TOKEN LAUNCH: SUBMITTED / PENDING");
});

test("only ISSUED with a clean readback is proven", () => {
  assert.equal(classifyLaunch({ submitted: true, applyStatus: "ISSUED", readback: readbackOk }),
    "INVOICE A-TOKEN LAUNCH: ISSUED / READBACK PROVEN");
});

test("no verdict is ever a Mordant settlement", () => {
  for (const applyStatus of ["PENDING", "ISSUED", "REJECTED", "ISSUE_FAILED", null]) {
    for (const readback of [null, readbackOk, { ok: false }]) {
      const verdict = classifyLaunch({ submitted: true, applyStatus, readback });
      assert.equal(verdict.includes("MORDANT SETTLEMENT"), false);
      assert.match(verdict, /^INVOICE A-TOKEN LAUNCH: /);
    }
  }
});
