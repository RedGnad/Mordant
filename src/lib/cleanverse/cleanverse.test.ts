import assert from "node:assert/strict";
import { createDecipheriv } from "node:crypto";
import { test } from "node:test";

import { CleanverseApiError, CleanverseClient, type CleanverseFetch } from "./client";
import {
  CleanverseConfigError,
  parseCleanverseConfig,
  type CleanverseConfig,
} from "./config";
import { CleanverseKeyError, encryptCleanverseRequest } from "./crypto";
import { toPublicAPass, toPublicApplyStatus, toPublicDiscovery } from "./public-view";
import {
  queryAPassDataSchema,
  queryApplyStatusDataSchema,
  querySupportedATokensDataSchema,
} from "./schemas";

const TEST_AES_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const TEST_API_ID = "test-application-id";
const TEST_BASE_URL = "https://cleanverse.invalid/api/cooperate";
const ADDRESS_A = `0x${"11".repeat(20)}`;
const ADDRESS_B = `0x${"22".repeat(20)}`;
const OWNER_SIGNATURE = `0x${"33".repeat(65)}`;

const TEST_CONFIG: CleanverseConfig = Object.freeze({
  baseUrl: TEST_BASE_URL,
  apiId: TEST_API_ID,
  apiKey: TEST_AES_KEY,
});

type CapturedRequest = {
  url: string;
  init: RequestInit;
};

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function createFetchMock(
  responder: (url: string, init: RequestInit) => unknown,
  captured: CapturedRequest[] = [],
): CleanverseFetch {
  return async (input, init = {}) => {
    const url = requestUrl(input);
    captured.push({ url, init });
    return Response.json({ code: "0000", message: "ok", data: responder(url, init) });
  };
}

function jsonBody(request: CapturedRequest): Record<string, unknown> {
  if (typeof request.init.body !== "string") {
    throw new Error("Expected a JSON string request body");
  }
  return JSON.parse(request.init.body) as Record<string, unknown>;
}

function decryptTestPayload(ciphertext: string): unknown {
  const key = Buffer.from(TEST_AES_KEY, "base64");
  const decipher = createDecipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  decipher.setAutoPadding(true);
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext) as unknown;
}

function relativePath(url: string): string {
  return new URL(url).pathname.replace("/api/cooperate", "");
}

test("AES-CBC request encryption matches a deterministic OpenSSL vector", () => {
  const payload = { hello: "world" };
  const expected = "+d7NR8jh6w4wiD7LhxRMKyC0ig/2y1/Vni2rYVi1TzI=";

  assert.equal(encryptCleanverseRequest(payload, TEST_AES_KEY), expected);
  assert.equal(encryptCleanverseRequest(payload, TEST_AES_KEY), expected);
});

test("API key and base URL validation rejects unsafe configuration", () => {
  const parsed = parseCleanverseConfig({
    CLEANVERSE_API_BASE_URL: `${TEST_BASE_URL}/`,
    CLEANVERSE_API_ID: TEST_API_ID,
    CLEANVERSE_API_KEY: TEST_AES_KEY,
  });
  assert.equal(parsed.baseUrl, TEST_BASE_URL);

  assert.throws(
    () =>
      parseCleanverseConfig({
        CLEANVERSE_API_BASE_URL: "ftp://cleanverse.invalid/api/cooperate",
        CLEANVERSE_API_ID: TEST_API_ID,
        CLEANVERSE_API_KEY: TEST_AES_KEY,
      }),
    CleanverseConfigError,
  );
  assert.throws(
    () =>
      parseCleanverseConfig({
        CLEANVERSE_API_BASE_URL: TEST_BASE_URL,
        CLEANVERSE_API_ID: TEST_API_ID,
        CLEANVERSE_API_KEY: "not-a-valid-aes-key",
      }),
    CleanverseConfigError,
  );
  assert.throws(
    () => encryptCleanverseRequest({ test: true }, "not-base64"),
    CleanverseKeyError,
  );
});

test("a non-0000 Cleanverse envelope becomes a typed, redacted error", async () => {
  const fetchMock: CleanverseFetch = async () =>
    Response.json({ code: "0002", message: "upstream internal detail", data: "{}" });
  const client = new CleanverseClient(TEST_CONFIG, fetchMock);

  await assert.rejects(
    () => client.querySupportedATokens({ chain: "monad" }),
    (error: unknown) => {
      assert.ok(error instanceof CleanverseApiError);
      assert.equal(error.upstreamCode, "0002");
      assert.doesNotMatch(error.message, /upstream internal detail/);
      return true;
    },
  );
});

test("client sends auth headers and encrypts only the two documented write endpoints", async () => {
  const captured: CapturedRequest[] = [];
  const fixtures: Record<string, unknown> = {
    "/atoken/launch": { requestId: "IA123", issueAssetId: 7 },
    "/atoken/query_apply_status/IA123": {
      flowType: "LAUNCH",
      requestId: "IA123",
      applyStatus: "ISSUED",
      chain: "monad",
      atokenAddress: ADDRESS_A,
      tokenSymbol: "MINV",
      txHash: `0x${"44".repeat(32)}`,
      issuedAt: "2026-07-26 18:00:00",
    },
    "/query_deposit_atoken_list": { chain: "monad", tokens: [] },
    "/query_apass": {
      cvRecordId: "record-test",
      subTier: 0,
      tier: "30",
      status: 1,
      expirationTime: 1_900_000_000,
      subGroup: "",
      currentKycHash: "fixture-kyc-hash",
      group: "",
      countries: [],
    },
    "/verify_apass": {
      chain: "monad",
      atoken: ADDRESS_A,
      address: ADDRESS_B,
      code: 4,
      message: "apass verify success",
      magickLink: "https://register.cleanverse.invalid/apass/test",
    },
    "/validator/register": {
      chain: "monad",
      contract_address: ADDRESS_A,
      tx_hash: `0x${"55".repeat(32)}`,
    },
    "/validator/verify": {
      chain: "monad",
      contract_address: ADDRESS_A,
      user_address: ADDRESS_B,
      valid: true,
    },
  };
  const fetchMock = createFetchMock((url) => {
    const fixture = fixtures[relativePath(url)];
    if (fixture === undefined) throw new Error(`Missing fixture for ${relativePath(url)}`);
    return fixture;
  }, captured);
  const client = new CleanverseClient(TEST_CONFIG, fetchMock);

  const launchInput = {
    chain: "monad" as const,
    token_name: "Mordant Invoice",
    token_symbol: "MINV",
    decimals: 6,
    admin_address: ADDRESS_A,
    rule: {
      allowed_group: "",
      allowed_sub_group: "",
      min_tier: 0,
      min_sub_tier: 0,
      is_black_list: false,
      countries: [],
    },
    icon: "https://assets.invalid/minv.svg",
  };
  const registerInput = {
    chain: "monad" as const,
    contract_address: ADDRESS_A,
    rule: {
      allowed_group: "",
      allowed_sub_group: "",
      min_tier: 0,
      min_sub_tier: 0,
      is_black_list: false,
      countries: [],
    },
    owner_signature: OWNER_SIGNATURE,
  };

  await client.launchAToken(launchInput);
  await client.queryApplyStatus("IA123");
  await client.querySupportedATokens({ chain: "monad" });
  await client.queryAPass({ chain: "monad", address: ADDRESS_B });
  await client.verifyAPass({ chain: "monad", atoken: ADDRESS_A, address: ADDRESS_B });
  await client.registerValidatorPool(registerInput);
  await client.verifyValidatorPool({
    chain: "monad",
    contract_address: ADDRESS_A,
    user_address: ADDRESS_B,
  });

  assert.equal(captured.length, 7);
  for (const request of captured) {
    const headers = new Headers(request.init.headers);
    assert.equal(headers.get("api-id"), TEST_API_ID);
    assert.match(headers.get("x-request-id") ?? "", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    assert.equal(headers.has("authorization"), false);
    assert.doesNotMatch(JSON.stringify(request.init.headers), new RegExp(TEST_AES_KEY.replace(/[+/=]/g, "\\$&")));
  }

  const byPath = new Map(captured.map((request) => [relativePath(request.url), request]));
  const encryptedPaths = ["/atoken/launch", "/validator/register"];
  for (const path of encryptedPaths) {
    const request = byPath.get(path);
    assert.ok(request);
    const body = jsonBody(request);
    assert.deepEqual(Object.keys(body), ["data"]);
    assert.equal(typeof body.data, "string");
    assert.doesNotMatch(body.data as string, /Mordant|owner_signature|contract_address/);
  }

  assert.deepEqual(
    decryptTestPayload(jsonBody(byPath.get("/atoken/launch")!).data as string),
    launchInput,
  );
  assert.deepEqual(
    decryptTestPayload(jsonBody(byPath.get("/validator/register")!).data as string),
    registerInput,
  );

  for (const path of [
    "/query_deposit_atoken_list",
    "/query_apass",
    "/verify_apass",
    "/validator/verify",
  ]) {
    const request = byPath.get(path);
    assert.ok(request);
    assert.equal(Object.hasOwn(jsonBody(request), "data"), false);
  }

  const statusRequest = byPath.get("/atoken/query_apply_status/IA123");
  assert.ok(statusRequest);
  assert.equal(statusRequest.init.method, "GET");
  assert.equal(statusRequest.init.body, undefined);
  assert.equal(new Headers(statusRequest.init.headers).has("content-type"), false);
});

test("public route projections strip internal and future upstream fields", () => {
  const status = queryApplyStatusDataSchema.parse({
    flowType: "LAUNCH",
    requestId: "IA123",
    applyStatus: "REJECTED",
    rejectReason: "private-review-detail",
    issueErrorMsg: "private-chain-detail",
    chain: "monad",
    callbackUrl: "https://internal.invalid/hook",
    callbackLastError: "private-callback-detail",
    futureSecret: "do-not-forward",
  });
  const publicStatus = JSON.stringify(toPublicApplyStatus(status));
  assert.doesNotMatch(publicStatus, /private|internal|futureSecret|callback/i);

  const aPass = queryAPassDataSchema.parse({
    cvRecordId: "private-record-id",
    subTier: 2,
    tier: "30",
    status: 1,
    expirationTime: 1_900_000_000,
    subGroup: "CD",
    currentKycHash: "private-kyc-hash",
    group: "AB",
    countries: ["SG"],
    futureSecret: "do-not-forward",
  });
  const publicAPass = JSON.stringify(toPublicAPass(aPass));
  assert.doesNotMatch(publicAPass, /private|cvRecordId|currentKycHash|futureSecret|countries|SG/);
  assert.match(publicAPass, /"tier":"30"/);

  const discovery = querySupportedATokensDataSchema.parse({
    chain: "monad",
    internalAssetId: "do-not-forward",
    tokens: [
      {
        origin_token: {
          address: ADDRESS_A,
          name: "USDC",
          symbol: "usdc",
          decimals: 6,
          icon: "https://assets.invalid/usdc.svg",
          internalIssuerId: "do-not-forward",
        },
        atoken: {
          address: ADDRESS_B,
          name: "aUSDC",
          symbol: "ausdc",
          decimals: 6,
          icon: "https://assets.invalid/ausdc.svg",
          internalIssuerId: "do-not-forward",
        },
        accesscore_address: ADDRESS_A,
        apass_address: ADDRESS_B,
        futureSecret: "do-not-forward",
      },
    ],
  });
  const publicDiscovery = JSON.stringify(toPublicDiscovery(discovery));
  assert.doesNotMatch(publicDiscovery, /internal|futureSecret|do-not-forward/i);
  assert.match(publicDiscovery, /"symbol":"ausdc"/);
});
