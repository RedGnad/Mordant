import { describeFindings, scanRepositoryForSecrets } from "./secret-scan";

/**
 * Fails the build when any tracked file, or any artifact passed as an argument, contains secret
 * material. The detected value is never printed: only its category and location.
 *
 * Allowlisted findings are always reported too, so an exception stays visible rather than
 * silently vanishing from the output.
 */
const extraPaths = process.argv.slice(2).filter((argument) => argument !== "--");
const { findings, allowed, rejectedAllowlistEntries } =
  scanRepositoryForSecrets(process.cwd(), extraPaths);

if (rejectedAllowlistEntries.length !== 0) {
  // An unusable suppression must be loud: silently ignoring it looks identical to it working.
  process.stderr.write(
    `${rejectedAllowlistEntries.length} allowlist entry/entries rejected as invalid:\n`
    + `${rejectedAllowlistEntries
      .map((entry) => `  allow[${entry.index}]: ${entry.problem}`)
      .join("\n")}\n`,
  );
  process.exitCode = 1;
}

if (allowed.length !== 0) {
  process.stdout.write(
    `${allowed.length} finding(s) suppressed by .secret-scan-allow.json:\n`
    + `${describeFindings(allowed)}\n`,
  );
}

if (findings.length !== 0) {
  process.stderr.write(`Secret material detected in ${findings.length} location(s):\n`);
  process.stderr.write(`${describeFindings(findings)}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(
    `Secret scan clean: no unreviewed credential pattern in tracked files`
    + `${extraPaths.length === 0 ? "" : ` or ${extraPaths.length} artifact(s)`}.\n`,
  );
}
