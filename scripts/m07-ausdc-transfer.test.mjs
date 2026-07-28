import assert from "node:assert/strict";
import { test } from "node:test";

import {
  StopError, assertBroadcastAuthorized, assertDistinct, assertUnchanged, assertWithinCeilings, scrub,
} from "./m07-ausdc-transfer.mjs";

const stops = (fn) => assert.throws(fn, StopError);

test("an unchanged address passes regardless of checksum casing", () => {
  assertUnchanged("aUSDC", "0xAC0893567D43C3E7E6E35A72803DF05416C1F20D",
    "0xaC0893567D43C3E7e6e35a72803df05416C1f20D");
});

test("a changed implementation stops the run", () => {
  stops(() => assertUnchanged("implementation", "0x0000000000000000000000000000000000000001", "0xabc"));
});

test("a missing observation stops the run rather than passing as absent", () => {
  stops(() => assertUnchanged("implementation", null, "0xabc"));
  stops(() => assertUnchanged("implementation", undefined, "0xabc"));
});

test("check mode never requires broadcast authorization", () => {
  assertBroadcastAuthorized("check", {});
});

test("the flag alone cannot broadcast", () => {
  stops(() => assertBroadcastAuthorized("broadcast", {}));
});

test("a near-miss authorization value cannot broadcast", () => {
  for (const value of ["", "no", "YES", "true", "1", " yes"]) {
    stops(() => assertBroadcastAuthorized("broadcast", { MORDANT_M07_BROADCAST_AUTHORIZED: value }));
  }
});

test("both the flag and the variable authorize a broadcast", () => {
  assertBroadcastAuthorized("broadcast", { MORDANT_M07_BROADCAST_AUTHORIZED: "yes" });
});

test("a self-transfer is refused, including across casing", () => {
  stops(() => assertDistinct("0xabc", "0xabc"));
  stops(() => assertDistinct("0xAbC", "0xaBc"));
});

test("an unset participant stops the run", () => {
  stops(() => assertDistinct(undefined, "0xabc"));
  stops(() => assertDistinct("0xabc", ""));
});

test("two distinct wallets pass", () => {
  assertDistinct("0xaaa", "0xbbb");
});

test("a transfer within the measured envelope passes", () => {
  assertWithinCeilings(319_513n, 102_000_000_000n);
});

test("an abnormal gas estimate stops the run", () => {
  stops(() => assertWithinCeilings(400_001n, 1n));
});

test("an abnormal gas price stops the run", () => {
  stops(() => assertWithinCeilings(21_000n, 200_000_000_001n));
});

test("scrub removes the magickLink verify_apass returns, keeping the verdict", () => {
  const scrubbed = scrub({ code: "0000", data: { code: 4, message: "ok", magickLink: "https://x/abc" } });
  assert.equal(scrubbed.data.magickLink, "[REDACTED]");
  assert.equal(scrubbed.data.code, 4);
  assert.equal(scrubbed.data.message, "ok");
});

test("scrub reaches nested and array-held credentials", () => {
  const scrubbed = scrub({ items: [{ apiKey: "secret-value" }], nested: { token: "t" } });
  assert.equal(scrubbed.items[0].apiKey, "[REDACTED]");
  assert.equal(scrubbed.nested.token, "[REDACTED]");
});

test("scrub leaves an absent credential absent rather than inventing a placeholder", () => {
  assert.equal(scrub({ magickLink: null }).magickLink, null);
});
