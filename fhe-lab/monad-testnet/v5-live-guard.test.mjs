// The live-execution gate must be unreachable-by-default and impossible to
// bypass by adding a broadcast somewhere else.
//
// The second property is the one that decays over time, so it is enforced
// statically: every V5 runner source is read and any direct wallet
// send/deploy/write outside the guard module fails this file.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LIVE_GATE, TARGETS, LiveExecutionBlocked, assertLiveExecutionAllowed,
  guardStatus, guardedBroadcast, isLiveExecutionEnabled,
} from "./v5-live-guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------ gate semantics */

test("the gate is disabled unless the value is exactly 1", () => {
  const disabled = [
    {},                       // absent
    { [LIVE_GATE]: "" },      // empty
    { [LIVE_GATE]: "0" },
    { [LIVE_GATE]: "true" },
    { [LIVE_GATE]: "TRUE" },
    { [LIVE_GATE]: "yes" },
    { [LIVE_GATE]: "1 " },    // trailing space, a real shell mistake
    { [LIVE_GATE]: " 1" },
    { [LIVE_GATE]: "1\n" },   // heredoc newline
    { [LIVE_GATE]: "01" },
    { [LIVE_GATE]: "11" },
    { [LIVE_GATE]: "on" },
    { [LIVE_GATE]: undefined },
  ];
  for (const env of disabled) {
    assert.equal(isLiveExecutionEnabled(env), false, JSON.stringify(env));
  }
  assert.equal(isLiveExecutionEnabled({ [LIVE_GATE]: "1" }), true);
});

test("assertLiveExecutionAllowed throws with the offending value named", () => {
  assert.throws(
    () => assertLiveExecutionAllowed({ [LIVE_GATE]: "true" }),
    (error) => {
      assert.ok(error instanceof LiveExecutionBlocked);
      assert.match(error.message, /"true"/);
      return true;
    },
  );
  assert.throws(
    () => assertLiveExecutionAllowed({}),
    (error) => /absent/.test(error.message),
  );
  assert.doesNotThrow(() => assertLiveExecutionAllowed({ [LIVE_GATE]: "1" }));
});

/* ---------------------------------------------------- the chokepoint */

test("a Monad broadcast never runs without the gate", async () => {
  let sent = false;
  await assert.rejects(
    () => guardedBroadcast({
      target: TARGETS.MONAD,
      description: "deploy verifier",
      send: async () => { sent = true; return "0xhash"; },
      env: {},
    }),
    (error) => error.code === "LIVE_EXECUTION_BLOCKED",
  );
  assert.equal(sent, false, "the send function must never be invoked");
});

test("a Monad broadcast runs with the exact gate", async () => {
  const hash = await guardedBroadcast({
    target: TARGETS.MONAD,
    description: "deploy verifier",
    send: async () => "0xhash",
    env: { [LIVE_GATE]: "1" },
  });
  assert.equal(hash, "0xhash");
});

// The rehearsal must be able to complete a full atomic binding without anyone
// setting a production gate; an ephemeral chain carries no value.
test("a local broadcast runs without the gate", async () => {
  const hash = await guardedBroadcast({
    target: TARGETS.LOCAL,
    description: "local deploy",
    send: async () => "0xlocal",
    env: {},
  });
  assert.equal(hash, "0xlocal");
});

test("an unknown target is refused even with the gate set", async () => {
  await assert.rejects(
    () => guardedBroadcast({
      target: "mainnet", description: "x", send: async () => "0x",
      env: { [LIVE_GATE]: "1" },
    }),
    (error) => /unknown broadcast target/.test(error.message),
  );
});

test("guardStatus reports the gate without inventing a value", () => {
  assert.deepEqual(guardStatus({}), {
    variable: LIVE_GATE, present: false, enabled: false, value: null,
  });
  assert.deepEqual(guardStatus({ [LIVE_GATE]: "true" }), {
    variable: LIVE_GATE, present: true, enabled: false, value: "true",
  });
  assert.deepEqual(guardStatus({ [LIVE_GATE]: "1" }), {
    variable: LIVE_GATE, present: true, enabled: true, value: "1",
  });
});

/* ------------------------------------- static enforcement of the chokepoint */

// A gate is only as good as the guarantee that nothing routes around it. This
// reads every V5 runner source and fails if a broadcast primitive appears
// outside the guard module.
test("no V5 runner source broadcasts outside the guard", async () => {
  const files = (await readdir(HERE))
    .filter((name) => name.startsWith("v5-") && name.endsWith(".mjs"))
    .filter((name) => !name.endsWith(".test.mjs"))
    .filter((name) => name !== "v5-live-guard.mjs")
    // The local rehearsal harness is exempt by construction, and the exemption
    // is bounded by the test below: it can only ever reach 127.0.0.1, its
    // broadcast target is always LOCAL, and LOCAL is ungated on purpose because
    // an ephemeral chain carries no value. Exempting it is safer than routing
    // the rehearsal through a production gate nobody should have to set.
    .filter((name) => name !== "v5-local-chain.mjs");

  assert.ok(files.length > 0, "expected V5 runner sources to scan");

  // These put a transaction on the wire. Reading state does not.
  const broadcastPrimitives = [
    /\.deployContract\s*\(/,
    /\.writeContract\s*\(/,
    /\.sendTransaction\s*\(/,
    /\.sendRawTransaction\s*\(/,
  ];

  const offenders = [];
  for (const name of files) {
    const source = await readFile(resolve(HERE, name), "utf8");
    for (const pattern of broadcastPrimitives) {
      if (pattern.test(source)) offenders.push(`${name} matches ${pattern}`);
    }
  }
  assert.deepEqual(
    offenders, [],
    "every broadcast must go through guardedBroadcast in v5-live-guard.mjs",
  );
});

// The exemption above is only defensible if the harness genuinely cannot reach
// a real network. It builds its RPC URL from a locally bound ephemeral port and
// hard-codes the loopback host, so there is no path from it to Monad.
test("the local rehearsal harness can only reach loopback", async () => {
  const source = await readFile(resolve(HERE, "v5-local-chain.mjs"), "utf8");
  const urls = source.match(/https?:\/\/[^`"'\s]+/g) ?? [];
  for (const url of urls) {
    assert.match(url, /^http:\/\/127\.0\.0\.1/, `harness references a non-loopback URL: ${url}`);
  }
  assert.ok(urls.length > 0, "expected the harness to build a loopback RPC URL");
  // It must not read the Monad RPC or any deployer key from the environment.
  assert.doesNotMatch(source, /FHE_MONAD_RPC_URL/);
  assert.doesNotMatch(source, /FHE_MONAD_DEPLOYER_PRIVATE_KEY/);
  // Its chain id is the local one; a handler cannot be tricked into thinking
  // the rehearsal was Monad.
  assert.match(source, /LOCAL_CHAIN_ID = 31_337/);
});

// The runner must never read a private key belonging to a signer it does not
// own. The deployer key is the runner's own; party, relayer, validator and
// controller keys are not.
test("no V5 runner source reads a foreign private key", async () => {
  const files = (await readdir(HERE))
    .filter((name) => name.startsWith("v5-") && name.endsWith(".mjs"))
    .filter((name) => !name.endsWith(".test.mjs"));

  const forbidden = [
    /RELAYER_PRIVATE_KEY/,
    /VALIDATOR_PRIVATE_KEY/,
    /CONTROLLER_PRIVATE_KEY/,
    /PARTY_PRIVATE_KEY/,
    /party\.key/,
    /validator\.key/,
  ];
  const offenders = [];
  for (const name of files) {
    const source = await readFile(resolve(HERE, name), "utf8");
    for (const pattern of forbidden) {
      if (pattern.test(source)) offenders.push(`${name} matches ${pattern}`);
    }
  }
  assert.deepEqual(offenders, [], "the runner must not read foreign signer keys");
});
