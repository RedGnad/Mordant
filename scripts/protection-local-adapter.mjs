#!/usr/bin/env node

import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

const OPERATIONS = new Set([
  "preparePrivateMatch",
  "submitParticipantA",
  "submitParticipantB",
  "evaluatePrivateConflict",
  "releaseGovernedResult",
  "openRecourseCase",
  "completeCureChronology",
  "exportProtectionEvidence",
  "retainProtectionEvidence",
]);
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BODY_BYTES = 2_048;

export class LocalProtectionAdapterError extends Error {
  constructor(message, status = 503) {
    super(message);
    this.name = "LocalProtectionAdapterError";
    this.status = status;
  }
}

function exactKeys(value, expected) {
  if (value === null || Array.isArray(value) || typeof value !== "object") return false;
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

export function isLoopbackAddress(address) {
  if (typeof address !== "string") return false;
  const normalized = address.toLowerCase().replace(/^::ffff:/, "");
  if (normalized === "::1") return true;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(normalized);
  return match !== null && Number(match[1]) === 127 && match.slice(1).every((part) => Number(part) <= 255);
}

function loopbackOrigin(value, name) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new LocalProtectionAdapterError(`${name} must be an exact loopback HTTP origin`);
  }
  if (
    parsed.protocol !== "http:"
    || !["127.0.0.1", "[::1]"].includes(parsed.hostname)
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
  ) throw new LocalProtectionAdapterError(`${name} must be an exact loopback HTTP origin`);
  return parsed.origin;
}

export function readLocalAdapterConfiguration(environment = process.env) {
  if (environment.NODE_ENV !== "development") {
    throw new LocalProtectionAdapterError("The local protection adapter is available only in development", 405);
  }
  if (environment.MORDANT_LOCAL_EXECUTION_ENABLED !== "1") {
    throw new LocalProtectionAdapterError("Local protection execution requires explicit opt-in", 404);
  }
  const capability = environment.MORDANT_LOCAL_ADMIN_CAPABILITY;
  if (typeof capability !== "string" || capability.length < 32) {
    throw new LocalProtectionAdapterError("A server-held local administrator capability is required");
  }
  const sourceCommit = environment.MORDANT_PROTECTION_SOURCE_COMMIT;
  if (typeof sourceCommit !== "string" || !/^[0-9a-f]{40}$/.test(sourceCommit) || /^0{40}$/.test(sourceCommit)) {
    throw new LocalProtectionAdapterError("An exact non-zero product source pin is required");
  }
  const port = Number(environment.MORDANT_LOCAL_ADAPTER_PORT ?? "43125");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new LocalProtectionAdapterError("MORDANT_LOCAL_ADAPTER_PORT is invalid");
  }
  return Object.freeze({
    bindAddress: "127.0.0.1",
    port,
    browserOrigin: loopbackOrigin(
      environment.MORDANT_LOCAL_BROWSER_ORIGIN ?? "http://127.0.0.1:3000",
      "MORDANT_LOCAL_BROWSER_ORIGIN",
    ),
    downstreamOrigin: loopbackOrigin(
      environment.MORDANT_LOCAL_DOWNSTREAM_ORIGIN ?? "http://127.0.0.1:3000",
      "MORDANT_LOCAL_DOWNSTREAM_ORIGIN",
    ),
    capability,
    sourceCommit,
  });
}

function corsHeaders(origin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "600",
    "cache-control": "no-store, max-age=0",
    "content-type": "application/json; charset=utf-8",
    "vary": "Origin",
  };
}

function send(response, origin, status, value) {
  response.writeHead(status, corsHeaders(origin));
  response.end(JSON.stringify(value));
}

async function readJsonBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw new LocalProtectionAdapterError("Request body is too large", 413);
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new LocalProtectionAdapterError("An exact JSON product operation is required", 400);
  }
}

function exactPledgeWindow(value) {
  if (!exactKeys(value, ["activeFrom", "activeUntil"])) return false;
  for (const bound of [value.activeFrom, value.activeUntil]) {
    // No coercion: strings, floats, booleans, null and unsafe integers are
    // rejections, never conversions.
    if (typeof bound !== "number" || !Number.isSafeInteger(bound) || bound < 0 || Object.is(bound, -0)) return false;
  }
  return value.activeFrom < value.activeUntil;
}

function exactPledgeWindows(value) {
  return exactKeys(value, ["participantA", "participantB"])
    && exactPledgeWindow(value.participantA)
    && exactPledgeWindow(value.participantB);
}

function validateBrowserOperation(value) {
  if (
    exactKeys(value, ["intent", "scenario", "creationRequestId"])
    && value.intent === "create"
    && (value.scenario === "conflict" || value.scenario === "no-conflict")
    && typeof value.creationRequestId === "string"
    && RUN_ID.test(value.creationRequestId)
  ) return value;
  // Supervised custom create. The scenario remains a routing value; the bound
  // scenario is derived server-side from these windows.
  if (
    exactKeys(value, ["intent", "scenario", "creationRequestId", "pledges"])
    && value.intent === "create"
    && (value.scenario === "conflict" || value.scenario === "no-conflict")
    && typeof value.creationRequestId === "string"
    && RUN_ID.test(value.creationRequestId)
    && exactPledgeWindows(value.pledges)
  ) return value;
  if (
    exactKeys(value, ["intent", "runId", "operation"])
    && value.intent === "execute"
    && typeof value.runId === "string"
    && RUN_ID.test(value.runId)
    && typeof value.operation === "string"
    && OPERATIONS.has(value.operation)
  ) return value;
  throw new LocalProtectionAdapterError("Unsupported or non-exact product operation", 400);
}

function mutationCorrelation(value) {
  if (
    value !== null && !Array.isArray(value) && typeof value === "object"
    && value.intent === "execute"
    && typeof value.runId === "string" && RUN_ID.test(value.runId)
    && typeof value.operation === "string" && OPERATIONS.has(value.operation)
  ) return { runId: value.runId, operation: value.operation };
  return null;
}

async function downstreamJson(configuration, fetchImpl, method, query, body, onDispatch) {
  const target = new URL("/api/protection/conflicting-pledge", configuration.downstreamOrigin);
  for (const [name, value] of Object.entries(query ?? {})) target.searchParams.set(name, value);
  onDispatch();
  const response = await fetchImpl(target, {
    method,
    cache: "no-store",
    redirect: "error",
    headers: method === "POST" ? {
      "content-type": "application/json",
      "x-mordant-admin-capability": configuration.capability,
    } : undefined,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok) {
    throw new LocalProtectionAdapterError(
      value !== null && typeof value === "object" && typeof value.error === "string"
        ? value.error : "The fixed protection operation failed",
      response.status,
    );
  }
  return value;
}

function retainedEvidence(value, configuration, exported) {
  if (
    !exactKeys(value, ["schemaVersion", "runId", "scenario", "caseId", "manifestDigest", "evidence"])
    || value.schemaVersion !== "mordant.retained-protection-view/1"
    || value.evidence === null || typeof value.evidence !== "object" || Array.isArray(value.evidence)
    || value.runId !== exported.runId
    || value.scenario !== exported.protectionCase?.productScenario
    || value.caseId !== exported.protectionCase?.fheCaseId
    || value.manifestDigest !== exported.evidence?.manifestDigest
    || value.evidence.runId !== value.runId
    || value.evidence.scenario !== value.scenario
    || value.evidence.sourceCommit !== configuration.sourceCommit
    || value.evidence.manifestDigest !== value.manifestDigest
    || value.evidence.fhe?.caseId !== value.caseId
  ) throw new LocalProtectionAdapterError("Final retained evidence readback was rejected", 502);
  return value.evidence;
}

async function executeBrowserOperation(configuration, fetchImpl, operation, onDispatch) {
  const view = await downstreamJson(configuration, fetchImpl, "POST", undefined, operation, onDispatch);
  if (operation.intent !== "execute" || operation.operation !== "exportProtectionEvidence") return view;
  return ensureDurablyRetained(configuration, fetchImpl, view, onDispatch);
}

async function ensureDurablyRetained(configuration, fetchImpl, view, onDispatch) {
  if (view === null || typeof view !== "object" || view.stage !== "COMPLETE") {
    throw new LocalProtectionAdapterError("Evidence export did not reach COMPLETE", 502);
  }
  const retained = await downstreamJson(configuration, fetchImpl, "POST", undefined, {
    intent: "execute",
    runId: view.runId,
    operation: "retainProtectionEvidence",
  }, onDispatch);
  const evidence = retainedEvidence(retained, configuration, view);
  return { ...view, evidence };
}

function requestOrigin(request) {
  const value = request.headers.origin;
  return Array.isArray(value) ? null : value ?? null;
}

export function createLocalProtectionAdapter(configuration, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  return createServer(async (request, response) => {
    const origin = requestOrigin(request);
    let downstreamDispatched = false;
    let correlatedMutation = null;
    const markDownstreamDispatched = () => { downstreamDispatched = true; };
    try {
      // Only the kernel-derived peer address is authority. Host, URL,
      // Forwarded and X-Forwarded-For are deliberately ignored.
      if (!isLoopbackAddress(request.socket.remoteAddress)) {
        throw new LocalProtectionAdapterError("Non-loopback peer rejected", 403);
      }
      if (origin !== configuration.browserOrigin) {
        throw new LocalProtectionAdapterError("Browser origin rejected", 403);
      }
      const url = new URL(request.url ?? "/", "http://adapter.invalid");
      if (url.pathname !== "/protection") throw new LocalProtectionAdapterError("Unknown local adapter route", 404);
      if (request.method === "OPTIONS") {
        if (url.search !== "") throw new LocalProtectionAdapterError("Query parameters are not accepted", 400);
        response.writeHead(204, corsHeaders(configuration.browserOrigin));
        response.end();
        return;
      }
      if (request.method === "GET") {
        const keys = [...url.searchParams.keys()];
        const runId = url.searchParams.get("runId");
        const creationRequestId = url.searchParams.get("creationRequestId");
        const exactRunLookup = keys.length === 1
          && url.searchParams.getAll("runId").length === 1
          && RUN_ID.test(runId ?? "");
        const exactCreationLookup = keys.length === 1
          && url.searchParams.getAll("creationRequestId").length === 1
          && RUN_ID.test(creationRequestId ?? "");
        if (!exactRunLookup && !exactCreationLookup) {
          throw new LocalProtectionAdapterError("An exact runId or creationRequestId is required", 400);
        }
        const view = await downstreamJson(
          configuration,
          fetchImpl,
          "GET",
          exactRunLookup ? { runId } : { creationRequestId },
          undefined,
          markDownstreamDispatched,
        );
        // Resume is a readback boundary. It may observe/reconcile work that was
        // already admitted, but it must never admit the separate retention
        // operation. A COMPLETE downstream view is returned only after the API
        // has independently verified the configured retained envelope.
        send(response, configuration.browserOrigin, 200, view);
        return;
      }
      if (request.method !== "POST" || request.headers["content-type"]?.split(";", 1)[0] !== "application/json") {
        throw new LocalProtectionAdapterError("Only fixed JSON GET/POST operations are available", 405);
      }
      const body = await readJsonBody(request);
      correlatedMutation = mutationCorrelation(body);
      const operation = validateBrowserOperation(body);
      if (url.search !== "") throw new LocalProtectionAdapterError("Query parameters are not accepted", 400);
      send(
        response,
        configuration.browserOrigin,
        200,
        await executeBrowserOperation(configuration, fetchImpl, operation, markDownstreamDispatched),
      );
    } catch (error) {
      const status = error instanceof LocalProtectionAdapterError ? error.status : 502;
      const message = status >= 500 ? "Local protection adapter operation failed" : error.message;
      const definitelyNotAdmitted = request.method === "POST"
        && status >= 400 && status < 500
        && !downstreamDispatched
        && correlatedMutation !== null;
      send(response, configuration.browserOrigin, status, definitelyNotAdmitted ? {
        schemaVersion: "mordant.local-mutation-error/1",
        mutationAdmission: "NOT_ADMITTED",
        runId: correlatedMutation.runId,
        operation: correlatedMutation.operation,
        error: message,
      } : { error: message });
    }
  });
}

export async function startLocalProtectionAdapter(options = {}) {
  const configuration = options.configuration ?? readLocalAdapterConfiguration(options.environment);
  const server = createLocalProtectionAdapter(configuration, options);
  const port = options.port ?? configuration.port;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, configuration.bindAddress, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return server;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const configuration = readLocalAdapterConfiguration();
    await startLocalProtectionAdapter({ configuration });
    process.stdout.write(`Mordant local protection adapter listening on http://${configuration.bindAddress}:${configuration.port}/protection\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Local protection adapter failed"}\n`);
    process.exitCode = 1;
  }
}
