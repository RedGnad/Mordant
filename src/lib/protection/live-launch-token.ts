import "server-only";

import { createHmac, randomUUID } from "node:crypto";

/**
 * Short-lived launch token for the live execution worker.
 *
 * The token authorizes exactly one action against exactly one audience. It
 * carries no pledge values: the browser sends those straight to the worker over
 * HTTPS, so Vercel never proxies or stores a visitor's private windows.
 *
 * The signing secret is server-side only. It must never be exposed through a
 * NEXT_PUBLIC variable or reach a browser bundle.
 */

export const LIVE_TOKEN_AUDIENCE = "MORDANT_RAILWAY_WORKER" as const;
export const LIVE_TOKEN_ACTION = "CREATE_CUSTOM_CASE" as const;
export const LIVE_TOKEN_MAX_LIFETIME_MS = 5 * 60 * 1_000;

export type LiveLaunchClaims = Readonly<{
  tokenId: string;
  issuedAt: number;
  expiresAt: number;
  audience: typeof LIVE_TOKEN_AUDIENCE;
  action: typeof LIVE_TOKEN_ACTION;
}>;

export class LiveLaunchTokenError extends Error {
  constructor(readonly code: string, readonly status: number, message: string) {
    super(message);
    this.name = "LiveLaunchTokenError";
  }
}

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64").replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

/** Fixed member order so Vercel and the worker sign identical bytes. */
function canonicalPayload(claims: LiveLaunchClaims): string {
  return JSON.stringify({
    tokenId: claims.tokenId,
    issuedAt: claims.issuedAt,
    expiresAt: claims.expiresAt,
    audience: claims.audience,
    action: claims.action,
  });
}

export function signLiveLaunchToken(claims: LiveLaunchClaims, secret: string): string {
  const payload = canonicalPayload(claims);
  return `${base64url(payload)}.${base64url(createHmac("sha256", secret).update(payload).digest())}`;
}

/**
 * Bounded issuance for a public demo. This is deliberately coarse: the worker
 * enforces the real limits (single use, one active case, cooldown, daily cap).
 * Its purpose is only to stop a trivial script from minting tokens in bulk.
 */
export type IssuanceWindow = { issued: number[] };

export function issuanceAllowed(
  window: IssuanceWindow,
  nowMs: number,
  limit: number,
  windowMs: number,
): boolean {
  window.issued = window.issued.filter((at) => at > nowMs - windowMs);
  if (window.issued.length >= limit) return false;
  window.issued.push(nowMs);
  return true;
}

export type LiveTokenConfiguration = Readonly<{
  secret: string;
  workerOrigin: string;
  lifetimeMs: number;
}>;

export function readLiveTokenConfiguration(
  environment: NodeJS.ProcessEnv = process.env,
): LiveTokenConfiguration {
  const secret = environment.MORDANT_WORKER_TOKEN_SECRET;
  if (typeof secret !== "string" || secret.length < 32) {
    throw new LiveLaunchTokenError("CONFIG", 503, "Live execution is not configured");
  }
  const workerOrigin = environment.NEXT_PUBLIC_MORDANT_WORKER_ORIGIN;
  if (typeof workerOrigin !== "string" || workerOrigin.trim() === "") {
    throw new LiveLaunchTokenError("CONFIG", 503, "Live execution is not configured");
  }
  let parsed: URL;
  try {
    parsed = new URL(workerOrigin);
  } catch {
    throw new LiveLaunchTokenError("CONFIG", 503, "Live execution is not configured");
  }
  if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    throw new LiveLaunchTokenError("CONFIG", 503, "Live execution is not configured");
  }
  const lifetime = Number(environment.MORDANT_WORKER_TOKEN_LIFETIME_MS ?? LIVE_TOKEN_MAX_LIFETIME_MS);
  if (!Number.isSafeInteger(lifetime) || lifetime <= 0 || lifetime > LIVE_TOKEN_MAX_LIFETIME_MS) {
    throw new LiveLaunchTokenError("CONFIG", 503, "Live execution is not configured");
  }
  return Object.freeze({ secret, workerOrigin: parsed.origin, lifetimeMs: lifetime });
}

export function issueLiveLaunchToken(
  configuration: LiveTokenConfiguration,
  nowMs: number,
): Readonly<{ token: string; expiresAt: number; workerOrigin: string }> {
  const claims: LiveLaunchClaims = {
    tokenId: randomUUID(),
    issuedAt: nowMs,
    expiresAt: nowMs + configuration.lifetimeMs,
    audience: LIVE_TOKEN_AUDIENCE,
    action: LIVE_TOKEN_ACTION,
  };
  return Object.freeze({
    token: signLiveLaunchToken(claims, configuration.secret),
    expiresAt: claims.expiresAt,
    workerOrigin: configuration.workerOrigin,
  });
}
