import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  representations, scanCanaries, scanFieldNames, sweep, readManifest, FORBIDDEN_FIELD_NAMES,
} from "./leak-scan.mjs";

const HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const bytes32 = (party = "a", field = "invoice_identifier") => ({ party, field, kind: "bytes32", value: HEX });
const uintCanary = () => ({ party: "a", field: "amount", kind: "uint", value: HEX, numeric: "1234567890123" });

async function scratch() {
  return mkdtemp(join(tmpdir(), "mordant-v4-scan-"));
}

// The core positive control: every representation the scanner claims to cover
// must actually be detected when planted on its own. A representation that
// silently fails here is exactly the M-PRIV4 defect.
test("every enumerated representation is detected when planted alone", async () => {
  const forms = representations(uintCanary());
  assert.ok(forms.length >= 15, `expected a broad representation set, got ${forms.length}`);
  const seen = new Set();
  for (const form of forms) {
    const dir = await scratch();
    await writeFile(join(dir, "planted.bin"), form.bytes);
    const report = await scanCanaries({ canaries: [uintCanary()], roots: [dir] });
    assert.ok(
      report.leaks.some((leak) => leak.representation === form.name),
      `representation ${form.name} was planted but not detected`,
    );
    seen.add(form.name);
  }
  // The named representations the mission requires are all present.
  for (const required of [
    "raw-bytes", "utf8-lower-hex", "utf8-upper-hex", "prefixed-hex", "base64",
    "decimal", "big-endian", "little-endian", "json-escaped",
    "numeric-decimal", "numeric-word-be", "numeric-word-le",
  ]) {
    assert.ok(seen.has(required), `missing required representation ${required}`);
  }
});

test("the raw-byte form the client actually writes is detected", async () => {
  // This is the representation V3 could not see: the canary enters the pledge
  // as raw bytes, not as hex text.
  const dir = await scratch();
  await writeFile(join(dir, "envelope.bin"), Buffer.from(HEX, "hex"));
  const report = await scanCanaries({ canaries: [bytes32()], roots: [dir] });
  assert.ok(report.leaks.some((leak) => leak.representation === "raw-bytes"));
});

test("a clean evidence tree produces no leak and still searches every form", async () => {
  const dir = await scratch();
  await writeFile(join(dir, "public.json"), JSON.stringify({ resultCommitment: "0xabc", conflictConfirmed: true }));
  await writeFile(join(dir, "ciphertext.bin"), Buffer.alloc(4096, 7));
  const report = await scanCanaries({ canaries: [uintCanary(), bytes32("b", "obligation_id")], roots: [dir] });
  assert.equal(report.leaks.length, 0);
  assert.ok(report.representationsPerCanary >= 11);
});

test("a deliberately injected leak fails the gate", async () => {
  const dir = await scratch();
  const privateDir = await scratch();
  await mkdir(join(dir, "nested"), { recursive: true });
  await writeFile(
    join(privateDir, "canaries.json"),
    JSON.stringify({ party: "a", fields: { invoice_identifier: HEX } }),
  );
  await writeFile(join(dir, "clean.json"), JSON.stringify({ ok: true }));
  let report = await sweep({ manifestPaths: [join(privateDir, "canaries.json")], roots: [dir] });
  assert.equal(report.ok, true, "clean tree should pass");

  // Inject the leak in a representation V3 would have missed.
  await writeFile(join(dir, "nested", "calldata.bin"), Buffer.concat([Buffer.alloc(32, 1), Buffer.from(HEX, "hex")]));
  report = await sweep({ manifestPaths: [join(privateDir, "canaries.json")], roots: [dir] });
  assert.equal(report.ok, false, "injected leak must fail the gate");
  assert.equal(report.leaks[0].representation, "raw-bytes");
  assert.equal(report.leaks[0].field, "invoice_identifier");
});

test("an injected uppercase-hex and base64 leak both fail the gate", async () => {
  for (const [name, payload] of [
    ["upper", Buffer.from(HEX.toUpperCase(), "utf8")],
    ["base64", Buffer.from(Buffer.from(HEX, "hex").toString("base64"), "utf8")],
  ]) {
    const dir = await scratch();
    const privateDir = await scratch();
    await writeFile(join(privateDir, "canaries.json"), JSON.stringify({ party: "a", fields: { exclusivity: HEX } }));
    await writeFile(join(dir, `${name}.txt`), payload);
    const report = await sweep({ manifestPaths: [join(privateDir, "canaries.json")], roots: [dir] });
    assert.equal(report.ok, false, `${name} leak must fail`);
  }
});

test("field-name scan flags restricted names and reports oversize skips", async () => {
  const dir = await scratch();
  await writeFile(join(dir, "fine.json"), JSON.stringify({ commitment: "0x1" }));
  let report = await scanFieldNames([dir]);
  assert.equal(report.violations.length, 0);
  await writeFile(join(dir, "bad.json"), JSON.stringify({ thresholdShare: "x" }));
  report = await scanFieldNames([dir]);
  assert.equal(report.violations.length, 1);
  assert.match(report.violations[0].code, /FORBIDDEN_FIELD_NAME/);
  assert.ok(FORBIDDEN_FIELD_NAMES.test("shamir"));
});

test("manifest reading rejects malformed canaries and carries numeric kinds", async () => {
  const dir = await scratch();
  const good = join(dir, "good.json");
  await writeFile(good, JSON.stringify({
    party: "b",
    fields: {
      amount: { kind: "uint", value: HEX, numeric: "999" },
      obligation_id: HEX,
    },
  }));
  const { party, canaries } = await readManifest(good);
  assert.equal(party, "b");
  assert.equal(canaries.length, 2);
  assert.equal(canaries.find((c) => c.field === "amount").kind, "uint");
  assert.equal(canaries.find((c) => c.field === "amount").numeric, "999");

  const bad = join(dir, "bad.json");
  await writeFile(bad, JSON.stringify({ party: "b", fields: { amount: "not-hex" } }));
  await assert.rejects(() => readManifest(bad), /CANARY_MANIFEST_INVALID/);

  const empty = join(dir, "empty.json");
  await writeFile(empty, JSON.stringify({ party: "b", fields: {} }));
  await assert.rejects(() => readManifest(empty), /CANARY_MANIFEST_EMPTY/);
});

test("sweep opens one party manifest at a time and can delete them", async () => {
  const dir = await scratch();
  const privateA = await scratch();
  const privateB = await scratch();
  const manifestA = join(privateA, "a.json");
  const manifestB = join(privateB, "b.json");
  await writeFile(manifestA, JSON.stringify({ party: "a", fields: { invoice_identifier: HEX } }));
  await writeFile(manifestB, JSON.stringify({
    party: "b", fields: { invoice_identifier: "0".repeat(63) + "1" },
  }));
  await writeFile(join(dir, "public.json"), JSON.stringify({ ok: true }));

  const report = await sweep({ manifestPaths: [manifestA, manifestB], roots: [dir], deleteManifests: true });
  assert.equal(report.ok, true);
  assert.equal(report.parties.length, 2);
  assert.deepEqual(report.parties.map((entry) => entry.party), ["a", "b"]);
  // The report carries digests, never canary values.
  const serialised = JSON.stringify(report);
  assert.ok(!serialised.includes(HEX), "sweep report must not echo a canary value");
  assert.equal(report.privateCanaryManifestsDeleted, true);
  await assert.rejects(() => access(manifestA));
  await assert.rejects(() => access(manifestB));
});

test("a leak in any scanned root fails, not just the first", async () => {
  const first = await scratch();
  const second = await scratch();
  const privateDir = await scratch();
  await writeFile(join(privateDir, "c.json"), JSON.stringify({ party: "a", fields: { currency: HEX } }));
  await writeFile(join(first, "clean.json"), JSON.stringify({ ok: true }));
  await writeFile(join(second, "journal.json"), JSON.stringify({ calldata: `0x${HEX}` }));
  const report = await sweep({ manifestPaths: [join(privateDir, "c.json")], roots: [first, second] });
  assert.equal(report.ok, false);
  assert.equal(report.leaks[0].field, "currency");
});
