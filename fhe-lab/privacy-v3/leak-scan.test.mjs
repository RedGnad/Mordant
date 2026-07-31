import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanPublicEvidence } from "./leak-scan.mjs";

test("public evidence scanner flags a forbidden field name", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mordant-privacy-"));
  await writeFile(join(dir, "artifact.json"), '{"resultCommitment":"0xabc"}');
  assert.equal((await scanPublicEvidence(dir)).violations.length, 0);
  await writeFile(join(dir, "bad.json"), '{"plaintextPledge":"no"}');
  assert.equal((await scanPublicEvidence(dir)).violations.length, 1);
});
