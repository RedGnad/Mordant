import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";

import { findSecretLeaks, type SecretLeak } from "./redaction";

/**
 * Scans every Git-tracked file for secret material before a commit.
 *
 * Only the category and location of a finding are ever reported. The offending value is never
 * read into a message, printed, or written anywhere.
 */

const SKIPPED_EXTENSIONS: readonly string[] = Object.freeze([
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf",
]);

/** Lockfiles legitimately contain long opaque hashes that are not credentials. */
const SKIPPED_PATHS: readonly string[] = Object.freeze(["pnpm-lock.yaml"]);

const MAX_BYTES = 2_000_000;

export type ScanFinding = Readonly<{ file: string; leak: SecretLeak }>;

export const ALLOWLIST_FILE = ".secret-scan-allow.json";

export type AllowlistEntry = Readonly<{
  path: string;
  kind: string;
  reason: string;
}>;

export type ScanResult = Readonly<{
  findings: readonly ScanFinding[];
  /** Findings suppressed by an explicit, reasoned allowlist entry. Reported, never hidden. */
  allowed: readonly ScanFinding[];
}>;

/**
 * Loads the committed allowlist. An entry without a non-empty reason is ignored, so a suppression
 * can never be introduced without stating why in the diff.
 */
export function loadAllowlist(repositoryRoot: string): readonly AllowlistEntry[] {
  let raw: string;
  try {
    raw = readFileSync(`${repositoryRoot}/${ALLOWLIST_FILE}`, "utf8");
  } catch {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${ALLOWLIST_FILE} is not valid JSON`);
  }

  if (typeof parsed !== "object" || parsed === null || !("allow" in parsed)) {
    return [];
  }
  const allow = (parsed as { allow: unknown }).allow;
  if (!Array.isArray(allow)) {
    return [];
  }

  return Object.freeze(
    allow.filter((entry): entry is AllowlistEntry =>
      typeof entry === "object" && entry !== null
      && typeof (entry as AllowlistEntry).path === "string"
      && typeof (entry as AllowlistEntry).kind === "string"
      && typeof (entry as AllowlistEntry).reason === "string"
      && (entry as AllowlistEntry).reason.trim().length > 0),
  );
}

function isAllowed(finding: ScanFinding, allowlist: readonly AllowlistEntry[]): boolean {
  return allowlist.some(
    (entry) => entry.path === finding.file && entry.kind === finding.leak.kind,
  );
}

export function listTrackedFiles(repositoryRoot: string): readonly string[] {
  const output = execFileSync("git", ["ls-files", "-z"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return output.split("\0").filter((path) => path.length > 0);
}

function shouldScan(path: string): boolean {
  if (SKIPPED_PATHS.includes(path)) {
    return false;
  }
  return !SKIPPED_EXTENSIONS.some((extension) => path.toLowerCase().endsWith(extension));
}

/**
 * @param repositoryRoot repository to scan
 * @param extraPaths files to scan even if untracked, such as freshly generated artifacts
 * @param knownSecretValues values the caller knows are secret; compared, never logged
 */
export function scanRepositoryForSecrets(
  repositoryRoot: string,
  extraPaths: readonly string[] = [],
  knownSecretValues: readonly string[] = [],
): ScanResult {
  const allowlist = loadAllowlist(repositoryRoot);
  const files = [...new Set([...listTrackedFiles(repositoryRoot), ...extraPaths])];
  const findings: ScanFinding[] = [];

  for (const file of files) {
    if (!shouldScan(file)) {
      continue;
    }
    const absolute = file.startsWith("/") ? file : `${repositoryRoot}/${file}`;
    let content: string;
    try {
      if (statSync(absolute).size > MAX_BYTES) {
        continue;
      }
      content = readFileSync(absolute, "utf8");
    } catch {
      continue;
    }

    for (const leak of findSecretLeaks(content, knownSecretValues)) {
      findings.push({ file, leak });
    }
  }

  return Object.freeze({
    findings: Object.freeze(findings.filter((finding) => !isAllowed(finding, allowlist))),
    allowed: Object.freeze(findings.filter((finding) => isAllowed(finding, allowlist))),
  });
}

export function describeFindings(findings: readonly ScanFinding[]): string {
  return findings
    .map((finding) => `${finding.file}: ${finding.leak.kind} at ${finding.leak.location}`)
    .join("\n");
}
