import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BridgeExecutionError,
  type CanonicalAdapterV2CompatibilityReport,
} from "../../../../lib/protection/bridge-executor";

import { createRecourseCompatibilityGetHandler } from "./route";

const REPORT = Object.freeze({
  schemaVersion: "mordant.adapter-v2-compatibility-report/1",
  compatible: true,
  adapter: {
    address: "0xbe67DB4F8a1a884C809884eA45c4dD4376B01b18",
    chainId: 10_143,
    codeHash: `0x${"12".repeat(32)}`,
    runtimeBytes: 10_088,
    settlementToken: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
    cviVerifier: "0xCFFA4cbF5117718EB7fC0dE2E13E07ce75B840aB",
    facility: "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6",
    availableReserve: "4000",
    openReserved: "0",
    entitledUnpaid: "0",
    tokenBalance: "4000",
    solvent: true,
    roleHolder: 4,
    roleFacility: 3,
  },
  participants: {
    holderA: "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685",
    holderB: "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9",
    payoutA: "2400",
    payoutB: "1600",
  },
  pins: {
    attestor: "0xEe3260bA47D097DE5a8601107e1b83454593617c",
    governedReleaseAuthorityId: `0x${"13".repeat(32)}`,
    assetIdentityDigest: `0x${"14".repeat(32)}`,
    releaseMode: `0x${"15".repeat(32)}`,
    circuitHash: `0x${"16".repeat(32)}`,
    parameterFingerprint: `0x${"17".repeat(32)}`,
  },
  eligibility: {
    holderA: true,
    holderB: true,
    facility: true,
    negativeControl: false,
    negativeControlCanonicalParticipant: false,
    uncontrolledApassWallet: true,
    uncontrolledApassWalletCanonicalParticipant: false,
  },
  digestParity: true,
  retainedVector: {
    governedResultDigest: `0x${"18".repeat(32)}`,
    conflict: true,
    nonce: "1",
    issuedAt: 1_785_000_000,
    expiry: 1_785_003_600,
    typedDataDigest: `0x${"19".repeat(32)}`,
    structHash: `0x${"20".repeat(32)}`,
  },
}) as CanonicalAdapterV2CompatibilityReport;

test("recourse compatibility GET returns only the sanitized no-store report", async () => {
  const response = await createRecourseCompatibilityGetHandler(async () => REPORT)();
  const body = await response.json() as Record<string, unknown>;
  assert.equal(response.status, 200);
  assert.match(response.headers.get("cache-control") ?? "", /no-store/u);
  assert.equal(body.compatible, true);
  const serialized = JSON.stringify(body).toLowerCase();
  for (const forbidden of ["signature", "payload", "private", "key"]) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} must not be exposed`);
  }
});

test("recourse compatibility GET masks bridge failures without request input", async () => {
  const response = await createRecourseCompatibilityGetHandler(async () => {
    throw new BridgeExecutionError("ADAPTER_INCOMPATIBLE", "internal detail");
  })();
  const body = await response.json() as Record<string, unknown>;
  assert.equal(response.status, 503);
  assert.equal(body.compatible, false);
  assert.equal(body.code, "ADAPTER_INCOMPATIBLE");
  assert.equal(JSON.stringify(body).includes("internal detail"), false);
});
