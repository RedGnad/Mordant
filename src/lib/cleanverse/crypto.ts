import "server-only";

import { createCipheriv } from "node:crypto";

const ZERO_IV = Buffer.alloc(16, 0);
const AES_KEY_LENGTHS = new Set([16, 24, 32]);

export class CleanverseKeyError extends Error {
  constructor() {
    super("Cleanverse API key configuration is invalid");
    this.name = "CleanverseKeyError";
  }
}

function decodeAesKey(apiKeyBase64: string): Buffer {
  const encoded = apiKeyBase64.trim();
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new CleanverseKeyError();
  }

  const key = Buffer.from(encoded, "base64");
  if (!AES_KEY_LENGTHS.has(key.byteLength)) {
    throw new CleanverseKeyError();
  }

  return key;
}

export function isValidCleanverseApiKey(apiKeyBase64: string): boolean {
  try {
    decodeAesKey(apiKeyBase64);
    return true;
  } catch {
    return false;
  }
}

/** Encrypts only outbound request JSON. Cleanverse v5.6 does not demonstrate encrypted responses. */
export function encryptCleanverseRequest(payload: unknown, apiKeyBase64: string): string {
  const key = decodeAesKey(apiKeyBase64);
  const algorithm = `aes-${key.byteLength * 8}-cbc`;
  const cipher = createCipheriv(algorithm, key, ZERO_IV);
  cipher.setAutoPadding(true);

  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  return Buffer.concat([cipher.update(plaintext), cipher.final()]).toString("base64");
}
