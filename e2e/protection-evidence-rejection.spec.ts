import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

import {
  protectionEvidenceDigest,
  type MordantProtectionEvidence,
} from "../src/lib/protection/protection-evidence";

const fixtureRoot = process.env.MORDANT_PROTECTION_REJECTION_FIXTURE_ROOT;
if (fixtureRoot === undefined) throw new Error("Marker-rejection fixture root is unavailable");
const fixturePath = join(fixtureRoot, "conflict.json");
const pristine = JSON.parse(readFileSync(fixturePath, "utf8")) as MordantProtectionEvidence;

const LITERAL_MARKERS = [
  ["case principal", ["protectionCase", "originalReceivable", "principalMinorUnits"], "910000001"],
  ["case units", ["protectionCase", "originalReceivable", "units"], "910000002"],
  ["preservation principal", ["originalReceivablePreservation", "principalMinorUnits"], "910000003"],
  ["preservation units", ["originalReceivablePreservation", "units"], "910000004"],
] as const;

const METADATA_MARKERS = [
  ["schema literal", ["governedFheEvidence", "schemaVersion"], "mordant.R2_SCHEMA_MARKER/99"],
  [
    "evidence reference",
    ["protectionCase", "evidenceReferences", 0],
    "docs/evidence/R2_REFERENCE_MARKER.json?private=1",
  ],
  ["digest syntax", ["fhe", "evaluatorProvenance"], `sha256:${"A".repeat(64)}`],
  ["canonical date", ["generatedAt"], "R2_DATE_MARKER"],
  [
    "case manifest cross-reference",
    ["governedFheEvidence", "caseManifestDigest"],
    `sha256:${"b".repeat(64)}`,
  ],
  [
    "exactRetry type",
    ["governedFheEvidence", "measurements", "release", "exactRetry"],
    "R2_EXACT_RETRY_MARKER",
  ],
] as const;

const BOOLEAN_MARKERS = [
  ["recourse opened", ["recourse", "opened"], "A6_RECOURSE_OPENED_MARKER"],
  [
    "reserve accounting separate",
    ["originalReceivablePreservation", "reserveAccountingSeparate"],
    "A6_RESERVE_SEPARATE_MARKER",
  ],
  [
    "protection claim burn or transfer",
    ["originalReceivablePreservation", "claimBurnedOrTransferredByProtection"],
    "A6_CLAIM_TRANSFER_MARKER",
  ],
  [
    "governed public structure",
    ["governedFheEvidence", "publicStructureValidated"],
    "A6_PUBLIC_STRUCTURE_MARKER",
  ],
  [
    "recourse production isolation",
    ["recourseAttestation", "attestation", "productionIsolationProven"],
    "A6_PRODUCTION_ISOLATION_MARKER",
  ],
] as const;

function replaceJsonPath(root: unknown, path: readonly (string | number)[], value: unknown): void {
  let cursor = root as Record<string, unknown>;
  for (const part of path.slice(0, -1)) cursor = cursor[part] as Record<string, unknown>;
  cursor[path.at(-1)!] = value;
}

function rehash(evidence: MordantProtectionEvidence): MordantProtectionEvidence {
  const clone = structuredClone(evidence);
  const value = Object.fromEntries(Object.entries(clone).filter(([key]) => key !== "manifestDigest")) as Omit<
    MordantProtectionEvidence,
    "manifestDigest"
  >;
  return { ...value, manifestDigest: protectionEvidenceDigest(value) };
}

async function expectRejectedFromEveryPublicSurface(
  page: Page,
  request: APIRequestContext,
  marker: string,
): Promise<void> {
  const apiResponse = await request.get("/api/protection/conflicting-pledge?scenario=conflict");
  expect(apiResponse.status()).toBe(500);
  const apiText = await apiResponse.text();
  expect(apiText).toBe('{"error":"Protection operation failed"}');
  expect(apiText).not.toContain(marker);

  const htmlResponse = await request.get("/protection?scenario=conflict");
  expect(htmlResponse.ok()).toBeTruthy();
  const html = await htmlResponse.text();
  expect(html).toContain("Verified protection evidence is unavailable.");
  expect(html).not.toContain(marker);

  const rscResponse = await request.get("/protection?scenario=conflict", {
    headers: { RSC: "1", "Next-Url": "/protection?scenario=conflict" },
  });
  expect(rscResponse.ok()).toBeTruthy();
  const rsc = await rscResponse.text();
  expect(rsc).toContain("Verified protection evidence is unavailable.");
  expect(rsc).not.toContain(marker);

  await page.goto("/protection?scenario=conflict");
  await expect(page.getByTestId("protection-product").getByRole("alert")).toHaveText(
    "Verified protection evidence is unavailable.",
  );
  await expect(page.locator("body")).not.toContainText(marker);
  expect(await page.locator("body").innerHTML()).not.toContain(marker);
}

for (const [field, path, marker] of LITERAL_MARKERS) {
  test(`A4-01-R1 ${field} marker is absent from API, HTML, RSC and DOM`, async ({ page, request }) => {
    const evidence = structuredClone(pristine);
    replaceJsonPath(evidence, path, marker);
    writeFileSync(fixturePath, `${JSON.stringify(rehash(evidence), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

    await expectRejectedFromEveryPublicSurface(page, request, marker);
  });
}

for (const [field, path, marker] of METADATA_MARKERS) {
  test(`A4-01-R2 ${field} marker is absent from API, HTML, RSC and DOM`, async ({ page, request }) => {
    const evidence = structuredClone(pristine);
    replaceJsonPath(evidence, path, marker);
    writeFileSync(fixturePath, `${JSON.stringify(rehash(evidence), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await expectRejectedFromEveryPublicSurface(page, request, marker);
  });
}

for (const [field, path, marker] of BOOLEAN_MARKERS) {
  test(`A6-F01 ${field} marker is absent from API, HTML, RSC, hydration and visible DOM`, async ({ page, request }) => {
    const evidence = structuredClone(pristine);
    replaceJsonPath(evidence, path, marker);
    writeFileSync(fixturePath, `${JSON.stringify(rehash(evidence), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await expectRejectedFromEveryPublicSurface(page, request, marker);
  });
}
