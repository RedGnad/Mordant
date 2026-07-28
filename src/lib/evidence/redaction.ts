import { createHash } from "node:crypto";

/**
 * Evidence artifacts are committed and shared with reviewers, so nothing secret may reach them.
 * The scan reports only the CATEGORY and the location of a leak, never the value itself.
 */

export type SecretLeakKind =
  | "documentation-access-code"
  | "cleanverse-api-key"
  | "deployer-private-key"
  | "authorization-header"
  | "cookie-header"
  | "session-token-url"
  | "docs-invite-code"
  | "provider-key-in-rpc-url"
  | "private-key-material"
  | "known-secret-value";

export type SecretLeak = Readonly<{
  kind: SecretLeakKind;
  /** Where the leak was found, never what it contained. */
  location: string;
  /**
   * `sha256:<hex>` over the normalized matched value. It lets an allowlist bind a suppression to
   * one exact piece of content, so changing a single character invalidates that suppression.
   * A digest is not the value: it is one-way, and it is never printed alongside the value.
   */
  fingerprint: string;
}>;

export const REDACTED = "[REDACTED]";

type NamedPattern = Readonly<{
  kind: SecretLeakKind;
  pattern: RegExp;
  /** Only environment assignments may legitimately hold a reference instead of a value. */
  allowsReference?: boolean;
}>;

/**
 * A secret value, in any of the shapes a leak takes. The negative lookahead keeps an already
 * redacted artifact from being reported as a fresh leak.
 */
const VALUE = String.raw`(?!\[REDACTED\])("[^"]*"|'[^']*'|<[^>\n]{1,64}>|\S+)`;

/**
 * The separator uses `[ \t]*` rather than `\s*` on purpose: `\s` matches newlines, so an empty
 * assignment such as `DEPLOYER_PRIVATE_KEY=` would otherwise swallow the following line and report
 * it as that variable's value.
 */
function assignmentPattern(name: string): RegExp {
  return new RegExp(String.raw`(${name}[ \t]*[:=][ \t]*)${VALUE}`, "gi");
}

/**
 * Headers carry the credential in the rest of the line, e.g. `Authorization: Bearer <token>`.
 * The value must start with a non-space character, otherwise the separator's `\s*` can backtrack
 * and re-match an already redacted line.
 */
function headerPattern(name: string): RegExp {
  return new RegExp(String.raw`(${name}[ \t]*[:=][ \t]*)(?!\[REDACTED\])([^\s\n\r][^\n\r]*)`, "gi");
}

/**
 * Each pattern captures the assignment/header prefix in group 1 so redaction can keep the
 * surrounding context readable while dropping the value.
 */
const SECRET_PATTERNS: readonly NamedPattern[] = Object.freeze([
  {
    kind: "documentation-access-code",
    allowsReference: true,
    pattern: assignmentPattern("CLEANVERSE_DOCS_ACCESS_CODE"),
  },
  {
    kind: "cleanverse-api-key",
    allowsReference: true,
    pattern: assignmentPattern("CLEANVERSE_API_KEY"),
  },
  {
    kind: "deployer-private-key",
    allowsReference: true,
    pattern: assignmentPattern("DEPLOYER_PRIVATE_KEY"),
  },
  {
    kind: "authorization-header",
    pattern: headerPattern("authorization"),
  },
  {
    kind: "cookie-header",
    pattern: headerPattern("(?:set-)?cookie"),
  },
  {
    kind: "session-token-url",
    pattern: new RegExp(
      String.raw`(https?:\/\/\S*?[?&](?:token|access_code|api[-_]?key|session)=)(?!\[REDACTED\])([^&\s"']+)`,
      "gi",
    ),
  },
  {
    // The documentation gate is unlocked by GET /api/docs/invite/<code>. The code must never be
    // written down, so any occurrence of that path with a trailing value is a leak.
    kind: "docs-invite-code",
    pattern: new RegExp(
      String.raw`(/api/docs/invite/)(?!\[REDACTED\])([^\s"'/?]+)`,
      "gi",
    ),
  },
  {
    // Managed RPC endpoints embed the account key in the path (Alchemy, Infura, QuickNode...).
    // Committing one leaks a third-party credential even though it looks like a plain URL.
    kind: "provider-key-in-rpc-url",
    pattern: new RegExp(
      String.raw`(https?:\/\/[a-z0-9.-]*\.(?:g\.alchemy\.com|infura\.io|quiknode\.pro|alchemyapi\.io)\/[a-z0-9/]*\/)(?!\[REDACTED\])([A-Za-z0-9_-]{16,})`,
      "gi",
    ),
  },
  {
    // A 32-byte hex blob is never legitimate evidence content: on-chain hashes are reported
    // through dedicated fields, and this shape is exactly a raw private key.
    kind: "private-key-material",
    pattern: /()\b(?:0x)?[0-9a-f]{64}\b(?=\s*(?:private|key|secret))/gi,
  },
]);

function locate(text: string, index: number): string {
  const line = text.slice(0, index).split("\n").length;
  return `line ${line}`;
}

/**
 * Digest of the matched value, normalized so that surrounding quoting or trailing punctuation
 * does not change it while the value itself still does.
 */
export function fingerprintValue(rawValue: string): string {
  const normalized = rawValue.trim().replace(/^["']|["']$/g, "").replace(/,$/, "").trim();
  return `sha256:${createHash("sha256").update(normalized, "utf8").digest("hex")}`;
}

/** A member expression such as `process.env.X` or `config.apiKey`. */
const MEMBER_EXPRESSION = /^[A-Za-z_$][\w$]*(?:\.[\w$]+)+$/;

/** A SCREAMING_SNAKE constant name such as `TEST_AES_KEY`. Real keys are not shaped this way. */
const CONSTANT_REFERENCE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

/**
 * Values that are meant to be committed: template placeholders, and the deliberately malformed
 * fixtures a negative test needs in order to assert that a bad credential is rejected.
 *
 * These are anchored *shapes*, not substrings. An earlier version matched any value merely
 * containing "example" or "sample", which would have let a realistic credential through as long
 * as it happened to contain one of those words. A placeholder must look like a placeholder from
 * beginning to end.
 */
const PLACEHOLDER_SHAPES: readonly RegExp[] = Object.freeze([
  /^<[^>]{1,64}>$/,
  /^(?:replace[-_]with|your|example|placeholder|changeme|change[-_]me|todo)[-_][a-z0-9]+(?:[-_][a-z0-9]+)*$/i,
  /^not[-_]a[-_](?:valid[-_])?[a-z0-9]+(?:[-_][a-z0-9]+)*$/i,
  /^(?:dummy|fake|sample|invalid|synthetic)[-_][a-z0-9]+(?:[-_][a-z0-9]+)*$/i,
  /^x{4,}$/i,
  /^0x0+$/,
]);

function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_SHAPES.some((shape) => shape.test(value));
}

/**
 * Distinguishes a real credential from a *reference* to one. `CLEANVERSE_API_KEY: process.env.X`
 * and a documented placeholder are not leaks; a literal value is. Without this the scanner cries
 * wolf on ordinary configuration code and gets switched off, which is worse than no scanner.
 *
 * Applied only to environment-variable assignments. In a header or a URL there is no such thing as
 * a "reference": whatever follows is the credential itself.
 */
function isEnvironmentReference(rawValue: string): boolean {
  const trimmed = rawValue.trim();
  const wasQuoted = /^["']/.test(trimmed);
  const value = trimmed.replace(/^["']|["']$/g, "").replace(/,$/, "").trim();

  if (value.length === 0 || value === REDACTED) {
    return true;
  }
  // A quoted literal is a value, never an identifier.
  if (!wasQuoted && (MEMBER_EXPRESSION.test(value) || CONSTANT_REFERENCE.test(value))) {
    return true;
  }
  return isPlaceholderValue(value);
}

/**
 * @param text the artifact about to be written
 * @param knownSecretValues values the caller knows are secret (never logged, only compared)
 */
export function findSecretLeaks(
  text: string,
  knownSecretValues: readonly string[] = [],
): readonly SecretLeak[] {
  const leaks: SecretLeak[] = [];

  for (const { kind, pattern, allowsReference } of SECRET_PATTERNS) {
    const scanner = new RegExp(pattern.source, pattern.flags);
    let match = scanner.exec(text);
    while (match !== null) {
      const value = match[2];
      if (value === undefined || allowsReference !== true || !isEnvironmentReference(value)) {
        leaks.push({
          kind,
          location: locate(text, match.index),
          fingerprint: fingerprintValue(value ?? match[0]),
        });
      }
      match = scanner.exec(text);
    }
  }

  for (const value of knownSecretValues) {
    // Short values would produce meaningless matches against ordinary prose.
    if (value.length < 6) {
      continue;
    }
    const index = text.indexOf(value);
    if (index !== -1) {
      leaks.push({
        kind: "known-secret-value",
        location: locate(text, index),
        fingerprint: fingerprintValue(value),
      });
    }
  }

  return Object.freeze(leaks);
}

export function redactSecrets(text: string, knownSecretValues: readonly string[] = []): string {
  let output = text;

  for (const { pattern, allowsReference } of SECRET_PATTERNS) {
    const scanner = new RegExp(pattern.source, pattern.flags);
    output = output.replace(
      scanner,
      (whole: string, prefix: string | undefined, value: string | undefined) => {
        if (value !== undefined && allowsReference === true && isEnvironmentReference(value)) {
          return whole;
        }
        return prefix === undefined || prefix === "" ? REDACTED : `${prefix}${REDACTED}`;
      },
    );
  }

  for (const value of knownSecretValues) {
    if (value.length < 6) {
      continue;
    }
    output = output.split(value).join(REDACTED);
  }

  return output;
}

export class SecretLeakError extends Error {
  readonly leaks: readonly SecretLeak[];

  constructor(leaks: readonly SecretLeak[]) {
    super(
      `Refusing to write an evidence artifact containing secret material: `
      + leaks.map((leak) => `${leak.kind} at ${leak.location}`).join(", "),
    );
    this.name = "SecretLeakError";
    this.leaks = leaks;
  }
}

/** Fails closed: an artifact that still contains a leak after redaction is never written. */
export function assertNoSecretLeak(
  text: string,
  knownSecretValues: readonly string[] = [],
): void {
  const leaks = findSecretLeaks(text, knownSecretValues);
  if (leaks.length !== 0) {
    throw new SecretLeakError(leaks);
  }
}
