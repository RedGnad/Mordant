import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LIVE_TOKEN_ACTION,
  LIVE_TOKEN_AUDIENCE,
  LIVE_TOKEN_MAX_LIFETIME_MS,
  LiveLaunchTokenError,
  issuanceAllowed,
  issueLiveLaunchToken,
  readLiveTokenConfiguration,
} from "./live-launch-token";

const SECRET = "0123456789abcdef0123456789abcdef0123456789";
const WORKER = "https://mordant-worker.up.railway.app";

function environment(overrides: Record<string, string | undefined> = {}) {
  return {
    MORDANT_WORKER_TOKEN_SECRET: SECRET,
    NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: WORKER,
    ...overrides,
  } as unknown as NodeJS.ProcessEnv;
}

function decode(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8")) as Record<string, unknown>;
}

test("an issued token carries only the five neutral claims", () => {
  const now = 1_800_000_000_000;
  const issued = issueLiveLaunchToken(readLiveTokenConfiguration(environment()), now);
  const claims = decode(issued.token);
  assert.deepEqual(Object.keys(claims).sort(), ["action", "audience", "expiresAt", "issuedAt", "tokenId"]);
  assert.equal(claims.audience, LIVE_TOKEN_AUDIENCE);
  assert.equal(claims.action, LIVE_TOKEN_ACTION);
  assert.equal(claims.issuedAt, now);
});

test("a token never carries pledge values and expires within five minutes", () => {
  const now = 1_800_000_000_000;
  const issued = issueLiveLaunchToken(readLiveTokenConfiguration(environment()), now);
  assert.ok(issued.expiresAt - now <= LIVE_TOKEN_MAX_LIFETIME_MS);
  assert.ok(issued.expiresAt > now);
  const encoded = JSON.stringify(decode(issued.token));
  for (const forbidden of ["activeFrom", "activeUntil", "participantA", "participantB", "120", "420", SECRET]) {
    assert.equal(encoded.includes(forbidden), false, `token leaked ${forbidden}`);
  }
});

test("the signing secret never appears in the issued response", () => {
  const issued = issueLiveLaunchToken(readLiveTokenConfiguration(environment()), Date.now());
  assert.equal(JSON.stringify(issued).includes(SECRET), false);
  // The worker origin is public by design; the secret is not.
  assert.equal(issued.workerOrigin, WORKER);
});

test("configuration is fail-closed and never half-enabled", () => {
  for (const [name, broken] of Object.entries({
    "missing secret": environment({ MORDANT_WORKER_TOKEN_SECRET: undefined }),
    "short secret": environment({ MORDANT_WORKER_TOKEN_SECRET: "tooshort" }),
    "missing worker origin": environment({ NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: undefined }),
    "non-https worker": environment({ NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: "http://worker.example" }),
    "unparseable worker": environment({ NEXT_PUBLIC_MORDANT_WORKER_ORIGIN: "not a url" }),
    "lifetime beyond the cap": environment({ MORDANT_WORKER_TOKEN_LIFETIME_MS: String(LIVE_TOKEN_MAX_LIFETIME_MS + 1) }),
    "zero lifetime": environment({ MORDANT_WORKER_TOKEN_LIFETIME_MS: "0" }),
  })) {
    assert.throws(
      () => readLiveTokenConfiguration(broken),
      (error: unknown) => error instanceof LiveLaunchTokenError && error.status === 503,
      `${name} must disable live execution rather than half-enable it`,
    );
  }
});

test("issuance is bounded within its window", () => {
  const window = { issued: [] as number[] };
  const now = 1_800_000_000_000;
  for (let index = 0; index < 5; index += 1) {
    assert.equal(issuanceAllowed(window, now, 5, 60_000), true);
  }
  assert.equal(issuanceAllowed(window, now, 5, 60_000), false);
  // The window slides.
  assert.equal(issuanceAllowed(window, now + 60_001, 5, 60_000), true);
});
