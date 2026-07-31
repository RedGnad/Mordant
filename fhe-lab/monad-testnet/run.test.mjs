import assert from "node:assert/strict";
import test from "node:test";

import {
  AcceptanceError,
  MONAD_MAX_CREATION_BYTES,
  MONAD_TESTNET_CHAIN_ID,
  POLICY_ID,
  POLICY_VERSION,
  parseArgs,
} from "./run.mjs";

test("requires an explicit read-only check or a recorded run", () => {
  assert.throws(() => parseArgs([]), (error) => error instanceof AcceptanceError && error.code === "CLI_MODE_REQUIRED");
  assert.throws(
    () => parseArgs(["--run"]),
    (error) => error instanceof AcceptanceError && error.code === "CLI_OUT_REQUIRED",
  );
  assert.deepEqual(parseArgs(["--check"]), { mode: "check", out: null });
  assert.equal(parseArgs(["--run", "--out", "fhe-run.json"]).mode, "run");
});

test("pins only Monad testnet and the existing FHE policy", () => {
  assert.equal(MONAD_TESTNET_CHAIN_ID, 10_143);
  assert.equal(POLICY_VERSION, 1);
  assert.match(POLICY_ID, /^0x[0-9a-f]{64}$/);
  assert.equal(MONAD_MAX_CREATION_BYTES, 131_072);
});
