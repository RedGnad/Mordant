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

/**
 * A suppression is bound to one exact piece of content, never to a file or a rule.
 *
 * A whole-file or wildcard exemption is the failure mode this scanner exists to prevent: it would
 * let a real credential pasted into an already-exempt file pass unnoticed. Every entry therefore
 * carries the fingerprint of the exact match it suppresses, so changing a single character of that
 * content invalidates the suppression and the finding reappears.
 */
export type AllowlistEntry = Readonly<{
  path: string;
  ruleId: string;
  matchFingerprint: string;
  reason: string;
  reviewedAt: string;
}>;

export type RejectedAllowlistEntry = Readonly<{ index: number; problem: string }>;

export type Allowlist = Readonly<{
  entries: readonly AllowlistEntry[];
  /** Malformed or over-broad entries, reported so a bad suppression is loud, not silent. */
  rejected: readonly RejectedAllowlistEntry[];
}>;

export type ScanResult = Readonly<{
  findings: readonly ScanFinding[];
  /** Findings suppressed by an explicit, reasoned allowlist entry. Reported, never hidden. */
  allowed: readonly ScanFinding[];
  rejectedAllowlistEntries: readonly RejectedAllowlistEntry[];
}>;

const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

function validateEntry(candidate: unknown): string | null {
  if (typeof candidate !== "object" || candidate === null) {
    return "entry is not an object";
  }
  const entry = candidate as Record<string, unknown>;

  for (const field of ["path", "ruleId", "matchFingerprint", "reason", "reviewedAt"]) {
    if (typeof entry[field] !== "string" || (entry[field] as string).trim().length === 0) {
      return `"${field}" must be a non-empty string`;
    }
  }

  const path = entry.path as string;
  const ruleId = entry.ruleId as string;

  // No wildcards anywhere: a suppression may never widen beyond the content it names.
  if (path.includes("*") || ruleId.includes("*")) {
    return "wildcards are not allowed in \"path\" or \"ruleId\"";
  }
  if (path.endsWith("/") || path.length === 0) {
    return "\"path\" must name a file, not a directory";
  }
  if (!FINGERPRINT_PATTERN.test(entry.matchFingerprint as string)) {
    return "\"matchFingerprint\" must be sha256:<64 hex characters>";
  }
  if (!ISO_DATE_PATTERN.test(entry.reviewedAt as string)
    || Number.isNaN(Date.parse(entry.reviewedAt as string))) {
    return "\"reviewedAt\" must be a valid YYYY-MM-DD date";
  }
  return null;
}

/**
 * Loads the committed allowlist. Any entry that is malformed, wildcarded or missing a reason is
 * rejected rather than applied, so an over-broad suppression cannot silently take effect.
 */
export function loadAllowlist(repositoryRoot: string): Allowlist {
  let raw: string;
  try {
    raw = readFileSync(`${repositoryRoot}/${ALLOWLIST_FILE}`, "utf8");
  } catch {
    return Object.freeze({ entries: [], rejected: [] });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${ALLOWLIST_FILE} is not valid JSON`);
  }

  if (typeof parsed !== "object" || parsed === null || !("allow" in parsed)) {
    return Object.freeze({ entries: [], rejected: [] });
  }
  const allow = (parsed as { allow: unknown }).allow;
  if (!Array.isArray(allow)) {
    return Object.freeze({ entries: [], rejected: [] });
  }

  const entries: AllowlistEntry[] = [];
  const rejected: RejectedAllowlistEntry[] = [];

  allow.forEach((candidate, index) => {
    const problem = validateEntry(candidate);
    if (problem === null) {
      entries.push(candidate as AllowlistEntry);
    } else {
      rejected.push({ index, problem });
    }
  });

  return Object.freeze({ entries: Object.freeze(entries), rejected: Object.freeze(rejected) });
}

/** A finding is suppressed only when path, rule and exact content all match. */
export function isFindingAllowed(
  finding: ScanFinding,
  allowlist: readonly AllowlistEntry[],
): boolean {
  return allowlist.some(
    (entry) => entry.path === finding.file
      && entry.ruleId === finding.leak.kind
      && entry.matchFingerprint === finding.leak.fingerprint,
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
  const { entries: allowlist, rejected } = loadAllowlist(repositoryRoot);
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
    findings: Object.freeze(findings.filter((finding) => !isFindingAllowed(finding, allowlist))),
    allowed: Object.freeze(findings.filter((finding) => isFindingAllowed(finding, allowlist))),
    rejectedAllowlistEntries: rejected,
  });
}

/** Reports category, location and fingerprint. Never the matched value. */
export function describeFindings(findings: readonly ScanFinding[]): string {
  return findings
    .map((finding) =>
      `${finding.file}: ${finding.leak.kind} at ${finding.leak.location}`
      + ` [${finding.leak.fingerprint}]`)
    .join("\n");
}
