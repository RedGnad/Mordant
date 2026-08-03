import assert from "node:assert/strict";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { test } from "node:test";

import {
  LocalProtectionAdapterError,
  isLoopbackAddress,
  readLocalAdapterConfiguration,
  startLocalProtectionAdapter,
} from "./protection-local-adapter.mjs";

const CAPABILITY = "server-only-capability-0123456789abcdef";
const BROWSER_ORIGIN = "http://127.0.0.1:3000";

function configuration() {
  return {
    bindAddress: "127.0.0.1",
    port: 43125,
    browserOrigin: BROWSER_ORIGIN,
    downstreamOrigin: "http://127.0.0.1:3000",
    capability: CAPABILITY,
    sourceCommit: "1".repeat(40),
  };
}

async function withAdapter(fetchImpl, run) {
  const server = await startLocalProtectionAdapter({ configuration: configuration(), port: 0, fetchImpl });
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    await run(`http://127.0.0.1:${address.port}/protection`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

function browserFetch(url, init = {}) {
  return fetch(url, { ...init, headers: { origin: BROWSER_ORIGIN, ...init.headers } });
}

test("adapter configuration is fail-closed and every configured origin is loopback", () => {
  assert.throws(() => readLocalAdapterConfiguration({ NODE_ENV: "production" }), LocalProtectionAdapterError);
  assert.throws(() => readLocalAdapterConfiguration({ NODE_ENV: "development" }), LocalProtectionAdapterError);
  assert.throws(() => readLocalAdapterConfiguration({
    NODE_ENV: "development",
    MORDANT_LOCAL_EXECUTION_ENABLED: "1",
    MORDANT_LOCAL_ADMIN_CAPABILITY: CAPABILITY,
    MORDANT_PROTECTION_SOURCE_COMMIT: "1".repeat(40),
    MORDANT_LOCAL_DOWNSTREAM_ORIGIN: "https://mordant.example",
  }), LocalProtectionAdapterError);
});

test("only a kernel-derived loopback peer is accepted", () => {
  for (const value of ["127.0.0.1", "127.42.0.9", "::1", "::ffff:127.0.0.1"]) assert.equal(isLoopbackAddress(value), true);
  for (const value of [undefined, "localhost", "0.0.0.0", "192.168.1.5", "::ffff:192.168.1.5"]) {
    assert.equal(isLoopbackAddress(value), false);
  }
});

test("browser never supplies or receives the capability while downstream receives it", async () => {
  const downstream = [];
  const fetchImpl = async (_url, init) => {
    downstream.push(init);
    return Response.json({
      runId: "11111111-1111-4111-8111-111111111111",
      stage: "CASE_CREATED",
    });
  };
  await withAdapter(fetchImpl, async (url) => {
    const response = await browserFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", host: "attacker.example", "x-forwarded-for": "203.0.113.7" },
      body: JSON.stringify({ intent: "create", scenario: "conflict" }),
    });
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.doesNotMatch(text, /server-only-capability/);
    assert.equal(downstream.length, 1);
    assert.equal(downstream[0].headers["x-mordant-admin-capability"], CAPABILITY);
  });
});

test("origin, unknown operations and every additional private field are refused before forwarding", async () => {
  let forwarded = 0;
  const fetchImpl = async () => { forwarded += 1; return Response.json({}); };
  await withAdapter(fetchImpl, async (url) => {
    const noOrigin = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: "create", scenario: "conflict" }),
    });
    assert.equal(noOrigin.status, 403);
    for (const body of [
      { intent: "create", scenario: "conflict", privateKey: CAPABILITY },
      { intent: "execute", runId: "11111111-1111-4111-8111-111111111111", operation: "arbitrary", path: "/tmp/private" },
      { intent: "execute", runId: "11111111-1111-4111-8111-111111111111", operation: "retainProtectionEvidence" },
    ]) {
      const response = await browserFetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      assert.equal(response.status, 400);
    }
    assert.equal(forwarded, 0);
  });
});

test("export performs fixed retention and exact durable readback", async () => {
  const calls = [];
  const evidence = {
    runId: "11111111-1111-4111-8111-111111111111",
    sourceCommit: "1".repeat(40),
    scenario: "conflict",
    manifestDigest: "sha256:manifest",
    fhe: { caseId: "sha256:case" },
  };
  const view = {
    runId: evidence.runId,
    stage: "COMPLETE",
    protectionCase: { productScenario: "conflict", fheCaseId: evidence.fhe.caseId },
    evidence,
  };
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (calls.length === 2) return Response.json({
      schemaVersion: "mordant.retained-protection-view/1",
      runId: evidence.runId,
      scenario: evidence.scenario,
      caseId: evidence.fhe.caseId,
      manifestDigest: evidence.manifestDigest,
      evidence,
    });
    return Response.json(view);
  };
  await withAdapter(fetchImpl, async (url) => {
    const response = await browserFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent: "execute",
        runId: evidence.runId,
        operation: "exportProtectionEvidence",
      }),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).evidence.manifestDigest, evidence.manifestDigest);
    assert.equal(calls.length, 2);
    assert.match(calls[1].init.body, /retainProtectionEvidence/);
  });
});

test("a COMPLETE refresh resumes fixed retention after export-to-retain interruption", async () => {
  const calls = [];
  const runId = "11111111-1111-4111-8111-111111111111";
  const evidence = {
    runId, scenario: "no-conflict", sourceCommit: "1".repeat(40),
    manifestDigest: "sha256:manifest", fhe: { caseId: "sha256:case" },
  };
  const view = {
    runId, stage: "COMPLETE",
    protectionCase: { productScenario: evidence.scenario, fheCaseId: evidence.fhe.caseId },
    evidence,
  };
  await withAdapter(async (url, init) => {
    calls.push({ url: String(url), init });
    if (init.method === "GET") return Response.json(view);
    return Response.json({
      schemaVersion: "mordant.retained-protection-view/1",
      runId,
      scenario: evidence.scenario,
      caseId: evidence.fhe.caseId,
      manifestDigest: evidence.manifestDigest,
      evidence,
    });
  }, async (url) => {
    const response = await browserFetch(`${url}?runId=${runId}`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).evidence.manifestDigest, evidence.manifestDigest);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init.method, "GET");
    assert.match(calls[1].init.body, /retainProtectionEvidence/);
  });
});

test("GET cardinality and every POST or OPTIONS query parameter are rejected", async () => {
  let forwarded = 0;
  await withAdapter(async () => { forwarded += 1; return Response.json({}); }, async (url) => {
    const duplicateGet = await browserFetch(`${url}?runId=11111111-1111-4111-8111-111111111111&runId=11111111-1111-4111-8111-111111111111`);
    assert.equal(duplicateGet.status, 400);
    const post = await browserFetch(`${url}?path=/tmp/private`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: "create", scenario: "conflict" }),
    });
    assert.equal(post.status, 400);
    const options = await browserFetch(`${url}?target=other`, { method: "OPTIONS" });
    assert.equal(options.status, 400);
    assert.equal(forwarded, 0);
  });
});

test("durable readback must match the configured source pin", async () => {
  const runId = "11111111-1111-4111-8111-111111111111";
  const evidence = { runId, scenario: "conflict", sourceCommit: "2".repeat(40), manifestDigest: "sha256:manifest", fhe: { caseId: "sha256:case" } };
  const view = { runId, stage: "COMPLETE", protectionCase: { productScenario: "conflict", fheCaseId: evidence.fhe.caseId }, evidence };
  let call = 0;
  await withAdapter(async () => {
    call += 1;
    return call === 1 ? Response.json(view) : Response.json({
      schemaVersion: "mordant.retained-protection-view/1", runId, scenario: "conflict",
      caseId: evidence.fhe.caseId, manifestDigest: evidence.manifestDigest, evidence,
    });
  }, async (url) => {
    const response = await browserFetch(url, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent: "execute", runId, operation: "exportProtectionEvidence" }),
    });
    assert.equal(response.status, 502);
  });
});

test("CORS preflight exposes no private header", async () => {
  await withAdapter(async () => Response.json({}), async (url) => {
    const response = await browserFetch(url, { method: "OPTIONS" });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-headers"), "content-type");
    assert.doesNotMatch([...response.headers].flat().join(" "), /admin|capability/i);
  });
});

test("caller-controlled Host and forwarding headers are not consulted as authority", async () => {
  await withAdapter(async () => Response.json({ runId: "11111111-1111-4111-8111-111111111111", stage: "CASE_CREATED" }), async (url) => {
    const parsed = new URL(url);
    const response = await new Promise((resolve, reject) => {
      const request = httpRequest({
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          host: "remote.example",
          origin: BROWSER_ORIGIN,
          forwarded: "for=203.0.113.9;host=localhost",
          "x-forwarded-for": "203.0.113.9",
          "content-type": "application/json",
        },
      }, resolve);
      request.once("error", reject);
      request.end(JSON.stringify({ intent: "create", scenario: "no-conflict" }));
    });
    assert.equal(response.statusCode, 200);
    response.resume();
  });
});
