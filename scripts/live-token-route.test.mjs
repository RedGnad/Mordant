import assert from "node:assert/strict";
import Module, { createRequire } from "node:module";
import test from "node:test";
import { fileURLToPath } from "node:url";

/**
 * Exercises the deployed token route's decision logic directly.
 *
 * The point is one rule: a holder the active Monad policy refuses must never receive a
 * launch token, and the route must never leak the shared worker secret or the RPC target
 * into what it returns.
 */

const ELIGIBLE = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const CONTROL = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
const SECRET = "a".repeat(64);

process.env.MORDANT_WORKER_TOKEN_SECRET = SECRET;
process.env.NEXT_PUBLIC_MORDANT_WORKER_ORIGIN = "https://worker.example";
process.env.MORDANT_WORKER_TOKEN_LIFETIME_MS = "300000";
process.env.MONAD_RPC_URL = "https://testnet-rpc.monad.xyz";

// tsc leaves the `@/` alias in its emitted CommonJS, so CommonJS resolution is mapped
// here. The CCP module resolves to a double whose only difference is the reader factory.
const DOUBLE = fileURLToPath(new URL("../test/fixtures/ccp-eligibility-double.cjs", import.meta.url));
const DIST = new URL("../.product-test-dist/src/", import.meta.url);
const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "@/lib/protection/ccp-eligibility") return DOUBLE;
  if (request.startsWith("@/")) return fileURLToPath(new URL(`${request.slice(2)}.js`, DIST));
  return resolveFilename.call(this, request, ...rest);
};

const { state } = createRequire(import.meta.url)("../test/fixtures/ccp-eligibility-double.cjs");
const route = await import("../.product-test-dist/src/app/api/live-protection/token/route.js");

function post(body, { raw = false } = {}) {
  return route.POST(new Request("https://app.example/api/live-protection/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: raw ? body : JSON.stringify(body),
  }));
}

test("a token is issued when the holder is eligible", async () => {
  const response = await post({ holderAddress: ELIGIBLE });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(typeof body.token, "string");
  assert.equal(body.workerOrigin, "https://worker.example");
  assert.equal(body.eligibility.eligible, true);
  assert.equal(body.eligibility.holderAddress, ELIGIBLE);
  assert.equal(body.eligibility.chainId, 10_143);
});

test("no token is issued when the holder is refused", async () => {
  const response = await post({ holderAddress: CONTROL });
  const body = await response.json();
  assert.equal(response.status, 403);
  assert.equal(body.token, null);
  assert.equal(body.eligibility.eligible, false);
});

test("the refusal never carries a token or the shared secret", async () => {
  const encoded = JSON.stringify(await (await post({ holderAddress: CONTROL })).json());
  assert.ok(!encoded.includes(SECRET));
  assert.ok(!encoded.includes("testnet-rpc.monad.xyz"));
});

test("an issued response never carries the shared secret", async () => {
  const encoded = JSON.stringify(await (await post({ holderAddress: ELIGIBLE })).json());
  assert.ok(!encoded.includes(SECRET));
  assert.ok(!encoded.includes("testnet-rpc.monad.xyz"));
});

test("the request shape is exact", async () => {
  for (const body of [
    { holderAddress: ELIGIBLE, extra: 1 },
    { holder: ELIGIBLE },
    {},
    [ELIGIBLE],
    null,
  ]) {
    assert.equal((await post(body)).status, 400, `expected a refusal for ${JSON.stringify(body)}`);
  }
  assert.equal((await post("{not json", { raw: true })).status, 400);
});

test("a malformed holder address is refused", async () => {
  for (const holderAddress of ["", "0x", "nope", 7, null]) {
    assert.equal((await post({ holderAddress })).status, 400);
  }
});

test("an unregistered gate refuses issuance", async () => {
  state.registered = false;
  const response = await post({ holderAddress: ELIGIBLE });
  state.registered = true;
  assert.equal(response.status, 503);
  assert.equal((await response.json()).code, "GATE");
});

test("a wrong chain refuses issuance", async () => {
  state.chainId = 1;
  const response = await post({ holderAddress: ELIGIBLE });
  state.chainId = 10_143;
  assert.equal(response.status, 503);
  assert.equal((await response.json()).code, "CHAIN");
});

test("GET is not allowed", async () => {
  assert.equal(route.GET().status, 405);
});
