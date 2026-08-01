#!/usr/bin/env node

// M-PRIV8 leak gate.
//
// Two classes of secret are checked, because they have different rules.
//
//   NEVER: the strict asset identity, its preimages, both sides' commercial
//   terms, the issuer master secrets, the per-anchor salts, operator shares and
//   every private key. None of these may appear in ANY artifact, at any point.
//
//   REVEALED-AT-BINDING: the session salt and the three initiation signatures.
//   These are published deliberately in the binding transaction, so they are
//   forbidden only in the pre-binding surface. Scanning them everywhere would
//   report the product working as designed as a leak.
//
// Positive controls are planted first. A scanner that finds nothing is only
// meaningful once it has been shown to find something.

import { mkdir, readFile, writeFile, rm, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createPublicClient, defineChain, http, keccak256, stringToHex } from "viem";
import {
  representations, scanCanaries, scanFieldNames, readManifest, canaryDigests,
} from "../privacy-v4/leak-scan.mjs";
import { REPO } from "./priv8-chain.mjs";
import { receivableIdentity, sideCommitments } from "./priv8-deploy.mjs";
import { strictStableAssetId } from "../shared/identity/asset-identity.mjs";

const [, , runRoot, evidenceDirectory, journalPath, outPath, mode] = process.argv;
/// `fields-only` re-runs the coarse field-name tripwire and its classification
/// over the same surface. It needs no private manifests, so it can be repeated
/// after the one-shot canary sweep has consumed and deleted them.
const fieldsOnly = mode === "fields-only";

const env = {};
for (const line of (await readFile(resolve(REPO, ".env"), "utf8")).split("\n")) {
  const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
}
const chain = defineChain({
  id: 10_143, name: "Monad testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [env.FHE_MONAD_RPC_URL] } },
});
const client = createPublicClient({ chain, transport: http(env.FHE_MONAD_RPC_URL) });

const evidence = JSON.parse(await readFile(resolve(evidenceDirectory, "priv8-evidence.json"), "utf8"));
const journal = JSON.parse(await readFile(journalPath, "utf8"));
const session = evidence.sessionCommitment.sessionCommitment;
const jsonSafe = (value) => JSON.stringify(value, (key, entry) => (typeof entry === "bigint" ? String(entry) : entry), 2);

/**
 * Finds the ceremony working root whose evaluator output is the one that was
 * bound, by matching the enrollment nonces the runner recomputed. Guessing by
 * timestamp would be a coincidence; matching the binding is a fact.
 */
async function ceremonyWorkingRoot() {
  const wanted = evidence.ceremony.enrollmentNonceA.toLowerCase();
  for (const name of await readdir(runRoot)) {
    if (!name.startsWith("ceremony")) continue;
    const candidate = resolve(runRoot, name);
    const result = await readFile(resolve(candidate, "public/evaluator-result.json"), "utf8").catch(() => null);
    if (!result) continue;
    if (JSON.parse(result).enrollmentNonceA?.toLowerCase() === wanted) return candidate;
  }
  throw new Error("CEREMONY_WORKING_ROOT_NOT_FOUND");
}
const ceremonyRoot = await ceremonyWorkingRoot();

/* ------------------------------------------- materialise the public surface */

// Calldata, events and receipts are pulled off the chain and written down so the
// scanner examines what an observer can actually see.
const captures = resolve(evidenceDirectory, "captures");
await mkdir(captures, { recursive: true });
// The receivable label is part of the journal key, so it is recovered from the
// journal rather than assumed.
const label = Object.entries(journal.steps)
  .find(([name, entry]) => name.startsWith("recourse:bind:") && name.endsWith(session) && entry.status === "success")
  ?.[0]?.split(":")[2];
if (!label) throw new Error(`BOUND_SESSION_NOT_IN_JOURNAL:${session}`);
const commitHash = journal.steps[`session:commit:${label}:${session}`].hash;
const bindHash = journal.steps[`recourse:bind:${label}:${session}`].hash;
await writeFile(resolve(captures, "pre-binding-commitment.json"), jsonSafe({
  transaction: await client.getTransaction({ hash: commitHash }),
  receipt: await client.getTransactionReceipt({ hash: commitHash }),
}));
await writeFile(resolve(captures, "post-binding-recourse.json"), jsonSafe({
  transaction: await client.getTransaction({ hash: bindHash }),
  receipt: await client.getTransactionReceipt({ hash: bindHash }),
}));

/* --------------------------------------------------------- runner canaries */

const identity = receivableIdentity(`INV-2026-00${String(40 + Number(label)).padStart(2, "0")}`);
const stableId = strictStableAssetId(identity);
const anchorMasterSecret = keccak256(stringToHex(`mordant.priv8.anchor-platform.master/${label}`));
const sourceMasterSecret = keccak256(stringToHex(`mordant.priv8.non-vault-facility.master/${label}`));
const sides = sideCommitments(stableId, { anchorMasterSecret, sourceMasterSecret });

const never = {
  strictStableAssetId: stableId,
  sellerId: identity.sellerId,
  debtorId: identity.debtorId,
  invoiceId: identity.invoiceId,
  anchorMasterSecret,
  sourceMasterSecret,
  anchorSalt: sides.anchorSalt,
  sourceSalt: sides.sourceSalt,
};
for (const [label, path] of [
  ["controller-a", "parties/controller-a/party.key"],
  ["controller-b", "parties/controller-b/party.key"],
  ["issuer", "parties/issuer/party.key"],
  ["relayer", "parties/relayer/party.key"],
  ["validator-1", "validators/validator-1/validator.key"],
  ["validator-2", "validators/validator-2/validator.key"],
  ["validator-3", "validators/validator-3/validator.key"],
]) {
  const key = await readFile(resolve(runRoot, path), "utf8").catch(() => null);
  if (key) never[`privateKey:${label}`] = key.trim();
}
// Every operator's threshold share bundle, so a share crossing into a public
// artifact is caught rather than assumed impossible.
for (const point of [1, 2, 3]) {
  const bundle = await readFile(resolve(ceremonyRoot, `operators/${point}/share.json`), "utf8").catch(() => null);
  if (bundle) never[`operatorShare:${point}`] = keccak256(stringToHex(bundle));
}

const revealedAtBinding = {
  sessionSalt: journal.sessions?.[session]?.salt ?? null,
  initiationSignatureA: journal.sessions?.[session]?.signatures?.controllerA ?? null,
  initiationSignatureB: journal.sessions?.[session]?.signatures?.controllerB ?? null,
  initiationSignatureIssuer: journal.sessions?.[session]?.signatures?.issuer ?? null,
};

const asCanaries = (party, values) => Object.entries(values)
  .filter(([, value]) => typeof value === "string" && /^(0x)?[0-9a-fA-F]{64}/.test(value))
  .map(([field, value]) => ({
    party, field, kind: "bytes32", value: value.replace(/^0x/, "").toLowerCase().slice(0, 64),
  }));

/* ------------------------------------------------------------ scan targets */

const publicSurface = [
  evidenceDirectory,
  journalPath,
  resolve(ceremonyRoot, "public"),
];
const preBindingSurface = [resolve(captures, "pre-binding-commitment.json")];

/* ------------------------------------------------------- positive controls */

// Planted OUTSIDE the scanned surface: a control is proof the scanner works,
// not a leak, and counting it as one would mask a real finding.
const controlDirectory = resolve(evidenceDirectory, "..", `.priv8-positive-controls-${label}`);
await mkdir(controlDirectory, { recursive: true });
const controlValue = anchorMasterSecret.replace(/^0x/, "").toLowerCase();
const controlForms = representations({ party: "control", field: "planted", kind: "bytes32", value: controlValue });
for (const [index, form] of controlForms.entries()) {
  await writeFile(resolve(controlDirectory, `control-${index}-${form.name}.bin`), form.bytes);
}

/* ---------------------------------------------------------------- the scan */

const report = { schemaVersion: "mordant.priv8-leak-scan/1", session, receivable: label, ceremonyRoot, classes: {} };

/**
 * The field-name tripwire is deliberately coarse: it matches the whole file, so
 * a refusal message mentioning a threshold share trips it exactly as a leaked
 * share would. Rather than blunt the regex, every match is extracted and
 * classified. Anything outside this allowlist fails the gate.
 *
 * Each entry is a string that PROVES a protection worked, not one that leaks
 * anything: a refusal the evaluator returned, a boolean flag on an operator
 * statement, or the name of the isolation method.
 */
const BENIGN_FIELD_MATCHES = new Set([
  // Refusals the evaluator returned when it tried to decrypt, provision
  // operators or build a release share. Evidence that a protection held.
  "REFUSED: insufficient threshold shares",
  "evaluatorSourceReferencesSecretMaterialAPIs",
  "clientRejectsEvaluatorSubstitutedPublicKey",
  // Boolean flags and labels on operator statements, proving share isolation.
  "holdsLocalSecretKey",
  "threshold-share-sealed",
  // The BGV plaintext MODULUS (t = 65537) in the collective public material. It
  // is the modulus of the plaintext space, not plaintext data, and it must be
  // public for anyone to encrypt at all.
  "PlaintextModulus",
  // A field NAME in the public coverage assertion, which declares each
  // commercial term's confidentiality class and consuming path and carries only
  // `canarySha256`, never the value. The value itself is swept separately in
  // every representation.
  "authorization_credential",
]);
const FIELD_PATTERN = /"[^"]*(?:plaintext|private.?key|threshold.?share|shamir|credential|secret.?key|seed.?phrase)[^"]*"/gi;

report.fieldNameScan = await scanFieldNames(publicSurface);
report.fieldNameClassification = [];
for (const violation of report.fieldNameScan.violations ?? []) {
  const contents = await readFile(violation.file, "utf8").catch(() => "");
  const matches = [...new Set((contents.match(FIELD_PATTERN) ?? []).map((entry) => entry.slice(1, -1)))];
  const unexplained = matches.filter((entry) => !BENIGN_FIELD_MATCHES.has(entry));
  report.fieldNameClassification.push({ file: violation.file, matches, unexplained });
}
report.unexplainedFieldMatches = report.fieldNameClassification.flatMap((entry) => entry.unexplained);

if (fieldsOnly) {
  report.summary = {
    mode: "fields-only",
    fieldNameTripwireHits: report.fieldNameScan.violations?.length ?? 0,
    fieldNameHitsAllBenign: report.unexplainedFieldMatches.length === 0,
    unexplainedFieldMatches: report.unexplainedFieldMatches,
  };
  await writeFile(outPath, `${jsonSafe(report)}\n`);
  console.log(jsonSafe(report.summary));
  if (report.unexplainedFieldMatches.length > 0) process.exitCode = 1;
  process.exit(process.exitCode ?? 0);
}

// Client commercial terms and identity preimages, one party at a time so the
// auditing process never holds both sides' terms simultaneously.
const manifests = [
  resolve(ceremonyRoot, "clients/private-a/canaries.json"),
  resolve(ceremonyRoot, "clients/private-b/canaries.json"),
];
const manifestDigests = [];
const clientCanaries = [];
for (const path of manifests) {
  const { party, canaries } = await readManifest(path);
  manifestDigests.push({ path, party, fields: canaries.length, digests: canaryDigests(canaries) });
  clientCanaries.push(...canaries);
}

const neverCanaries = [...clientCanaries, ...asCanaries("runner", never)];
report.classes.never = {
  description: "must not appear in any artifact, before or after binding",
  canaries: neverCanaries.length,
  scan: await scanCanaries({
    canaries: neverCanaries,
    roots: [...publicSurface, ...preBindingSurface, resolve(captures, "post-binding-recourse.json")],
  }),
};

const revealedCanaries = asCanaries("session", revealedAtBinding);
const bindingCapture = await readFile(resolve(captures, "post-binding-recourse.json"), "utf8");
report.classes.revealedAtBinding = {
  description: "published deliberately at binding; forbidden only before it",
  canaries: revealedCanaries.length,
  scan: await scanCanaries({ canaries: revealedCanaries, roots: preBindingSurface }),
  presentInBindingCalldata: revealedCanaries.every(
    (canary) => bindingCapture.toLowerCase().includes(canary.value),
  ),
};

report.positiveControls = {
  plantedRepresentations: controlForms.length,
  scan: await scanCanaries({
    canaries: [{ party: "control", field: "planted", kind: "bytes32", value: controlValue }],
    roots: [controlDirectory],
  }),
};
// Encodings overlap (lower-hex is a substring of prefixed-hex and of the
// JSON-escaped form), so one planted file can satisfy several representations.
// The meaningful assertion is that EVERY representation was detected at least
// once, not that the counts match.
const detectedRepresentations = new Set(report.positiveControls.scan.leaks.map((leak) => leak.representation));
report.positiveControls.detected = detectedRepresentations.size;
report.positiveControls.detectedRepresentations = [...detectedRepresentations].sort();
report.positiveControls.expectedRepresentations = controlForms.map((form) => form.name).sort();
report.positiveControls.allRepresentationsDetected =
  report.positiveControls.expectedRepresentations.every((name) => detectedRepresentations.has(name));

report.manifestDigests = manifestDigests;
report.summary = {
  neverLeaks: report.classes.never.scan.leaks.length,
  preBindingLeaks: report.classes.revealedAtBinding.scan.leaks.length,
  fieldNameTripwireHits: report.fieldNameScan.violations?.length ?? 0,
  fieldNameHitsAllBenign: report.unexplainedFieldMatches.length === 0,
  unexplainedFieldMatches: report.unexplainedFieldMatches,
  positiveControlsDetected: report.positiveControls.detected,
  positiveControlsExpected: new Set(controlForms.map((form) => form.name)).size,
  representationsPerCanary: report.classes.never.scan.representationsPerCanary,
  filesScanned: report.classes.never.scan.scannedFiles,
  saltRevealedOnlyAtBinding: report.classes.revealedAtBinding.presentInBindingCalldata
    && report.classes.revealedAtBinding.scan.leaks.length === 0,
};

// Manifests are deleted only after the complete scan; their digests are kept.
for (const path of manifests) await rm(path, { force: true });
report.manifestsDeleted = manifests;
await rm(controlDirectory, { recursive: true, force: true });
report.positiveControlsRemovedAfterScan = true;

await writeFile(outPath, `${jsonSafe(report)}\n`);
console.log(jsonSafe(report.summary));
if (report.summary.neverLeaks > 0 || report.summary.preBindingLeaks > 0) {
  console.error("LEAK_SCAN_FAILED");
  process.exitCode = 1;
}
if (!report.positiveControls.allRepresentationsDetected) {
  console.error("POSITIVE_CONTROL_FAILED");
  process.exitCode = 1;
}
if (report.unexplainedFieldMatches.length > 0) {
  console.error("UNEXPLAINED_FIELD_NAME");
  process.exitCode = 1;
}
