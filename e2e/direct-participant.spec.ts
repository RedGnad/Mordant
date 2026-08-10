import { expect, test, type Page, type Route } from "@playwright/test";

import {
  LIVE_WORKER_SCHEMA,
  PARTICIPANT_ADMISSION_DOMAIN_SALT,
  PARTICIPANT_ADMISSION_DOMAIN_VERSION,
  PARTICIPANT_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_TYPES,
  PARTICIPANT_CHALLENGE_SCHEMA,
} from "../src/components/live-product/participant-admission-client";

const PORT = Number(process.env.MORDANT_DIRECT_E2E_PORT ?? "3222");
const APP_ORIGIN = `http://127.0.0.1:${PORT}`;
const WORKER_ORIGIN = "https://mordant-worker.test";
const CASE_CODE = "ABCDEFGH23456789";
const RUN_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const HOLDER_A = "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685";
const HOLDER_B = "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9";
const CHAIN_ID = 10_143;
const CHAIN_HEX = `0x${CHAIN_ID.toString(16)}`;
const VALIDATOR = "0xac7e5179c2c7f03f209136886c172eb34f161792";
const GATE = "0x3ffb28a13fd6dc372ae952f15b55263285d5a280";

type Role = "PARTICIPANT_A" | "PARTICIPANT_B";
type ChallengeDefect = "none" | "expired" | "changed-payload";
type JsonRecord = Record<string, unknown>;

function digest(seed: string): string {
  return `sha256:${seed.repeat(64).slice(0, 64)}`;
}

function bytes32(seed: string): string {
  return `0x${seed.repeat(64).slice(0, 64)}`;
}

function asRecord(value: unknown): JsonRecord {
  expect(value).not.toBeNull();
  expect(Array.isArray(value)).toBe(false);
  expect(typeof value).toBe("object");
  return value as JsonRecord;
}

function participantView(aAdmitted: boolean, bAdmitted: boolean): JsonRecord {
  const stage = bAdmitted ? "PARTICIPANT_B_PUBLISHED" : aAdmitted ? "PARTICIPANT_A_SUBMITTED" : "MATCH_PREPARED";
  return {
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: RUN_ID,
    executionVariant: "CUSTOM_SUPERVISED",
    stage,
    nextOperation: bAdmitted ? "evaluatePrivateConflict" : aAdmitted ? "awaitParticipantBAdmission" : "awaitParticipantAAdmission",
    terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: digest("a"),
      fheCaseId: digest("b"),
      incidentState: "PRIVATE_MATCH_OPEN",
      recourseState: "NOT_OPEN",
      cureDeadline: null,
    },
    participantArtifactDigests: {
      participantA: aAdmitted ? digest("c") : null,
      participantB: bAdmitted ? digest("d") : null,
    },
    evaluatedArtifactDigest: null,
    governedResult: null,
    recourse: null,
    receipt: null,
  };
}

function admissionProjection(aAdmitted: boolean, bAdmitted: boolean, aWallet = HOLDER_A): JsonRecord {
  return {
    schemaVersion: "mordant.participant-case/1",
    caseCode: CASE_CODE,
    runId: RUN_ID,
    lifecycle: bAdmitted ? "PARTICIPANT_B_ADMITTED" : aAdmitted ? "PARTICIPANT_A_ADMITTED" : "MATCH_PREPARED",
    participantA: { admitted: aAdmitted, wallet: aAdmitted ? aWallet : null },
    participantB: { admitted: bAdmitted, wallet: bAdmitted ? HOLDER_B : null },
    bothAdmitted: aAdmitted && bAdmitted,
    abandoned: false,
  };
}

function caseBody(aAdmitted: boolean, bAdmitted: boolean, aWallet = HOLDER_A): JsonRecord {
  return {
    schemaVersion: "mordant.live-worker/1",
    view: participantView(aAdmitted, bAdmitted),
    admission: admissionProjection(aAdmitted, bAdmitted, aWallet),
    progress: bAdmitted ? "Participant B encrypted" : aAdmitted ? "Participant A encrypted" : "Private encryption prepared",
  };
}

const CORS_HEADERS = {
  "access-control-allow-origin": APP_ORIGIN,
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type",
  "cache-control": "no-store",
  vary: "Origin",
} as const;

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    headers: { ...CORS_HEADERS, "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
}

class DeterministicParticipantWorker {
  aAdmitted: boolean;
  bAdmitted = false;
  readonly aWallet: string;
  readonly defect: ChallengeDefect;
  readonly loseFirstBAdmission: boolean;
  readonly createBodies: string[] = [];
  readonly challengeBodies: JsonRecord[] = [];
  readonly admissionBodies: Array<{ raw: string; parsed: JsonRecord }> = [];
  readonly eligibilityWallets: string[] = [];
  readonly requestPaths: string[] = [];
  readCount = 0;
  private lostBResponse = false;

  constructor(options: Readonly<{
    aAdmitted?: boolean;
    aWallet?: string;
    defect?: ChallengeDefect;
    loseFirstBAdmission?: boolean;
  }> = {}) {
    this.aAdmitted = options.aAdmitted ?? false;
    this.aWallet = options.aWallet ?? HOLDER_A;
    this.defect = options.defect ?? "none";
    this.loseFirstBAdmission = options.loseFirstBAdmission ?? false;
  }

  async install(page: Page) {
    await page.route("**/api/live-protection/token", async (route) => {
      const request = route.request();
      const body = asRecord(request.postDataJSON());
      expect(Object.keys(body)).toEqual(["holderAddress"]);
      expect(typeof body.holderAddress).toBe("string");
      const holderAddress = body.holderAddress as string;
      this.eligibilityWallets.push(holderAddress);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          schemaVersion: "mordant.live-launch-token/1",
          token: `deterministic-browser-token-${this.eligibilityWallets.length}`,
          expiresAt: Date.now() + 10 * 60 * 1_000,
          workerOrigin: WORKER_ORIGIN,
          eligibility: {
            schemaVersion: "mordant.ccp-eligibility/1",
            chainId: CHAIN_ID,
            validatorAddress: VALIDATOR,
            gateAddress: GATE,
            holderAddress,
            eligible: true,
            observedBlock: 51_500_001 + this.eligibilityWallets.length,
          },
        }),
      });
    });

    await page.route(`${WORKER_ORIGIN}/**`, async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers: CORS_HEADERS, body: "" });
        return;
      }
      this.requestPaths.push(url.pathname);

      if (request.method() === "POST" && url.pathname === "/v1/participant-cases") {
        const raw = request.postData() ?? "";
        this.createBodies.push(raw);
        expect(request.headers().authorization).toMatch(/^Bearer deterministic-browser-token-/u);
        await json(route, 201, caseBody(false, false, this.aWallet));
        return;
      }

      if (request.method() === "GET" && url.pathname === `/v1/participant-cases/${CASE_CODE}`) {
        this.readCount += 1;
        await json(route, 200, caseBody(this.aAdmitted, this.bAdmitted, this.aWallet));
        return;
      }

      if (request.method() === "POST" && url.pathname === `/v1/participant-cases/${CASE_CODE}/challenge`) {
        const requestBody = asRecord(request.postDataJSON());
        this.challengeBodies.push(requestBody);
        const claim = asRecord(requestBody.claim);
        const role = requestBody.role as Role;
        const now = Math.floor(Date.now() / 1_000);
        const issuedAt = this.defect === "expired" ? now - 600 : now - 1;
        const expiresAt = this.defect === "expired" ? now - 1 : now + 600;
        const activeUntil = Number(claim.activeUntil) + (this.defect === "changed-payload" ? 1 : 0);
        await json(route, 200, {
          schemaVersion: LIVE_WORKER_SCHEMA,
          challenge: {
            schemaVersion: PARTICIPANT_CHALLENGE_SCHEMA,
            domain: {
              name: "Mordant Participant Admission",
              version: PARTICIPANT_ADMISSION_DOMAIN_VERSION,
              chainId: CHAIN_ID,
              salt: PARTICIPANT_ADMISSION_DOMAIN_SALT,
            },
            primaryType: PARTICIPANT_ADMISSION_PRIMARY_TYPE,
            types: PARTICIPANT_ADMISSION_TYPES,
            message: {
              verifyingService: APP_ORIGIN,
              runId: RUN_ID,
              fheCaseId: bytes32("b"),
              protectionBindingDigest: bytes32("e"),
              assetIdentityDigest: bytes32("a"),
              role,
              activeFrom: claim.activeFrom,
              activeUntil,
              participantWallet: requestBody.participantWallet,
              authorizationNonce: bytes32(role === "PARTICIPANT_A" ? "1" : "2"),
              issuedAt,
              expiresAt,
              participantSigningKeyDigest: bytes32(role === "PARTICIPANT_A" ? "c" : "d"),
            },
          },
        });
        return;
      }

      if (request.method() === "POST" && url.pathname === `/v1/participant-cases/${CASE_CODE}/admissions`) {
        const raw = request.postData() ?? "";
        const parsed = asRecord(request.postDataJSON());
        this.admissionBodies.push({ raw, parsed });
        const role = parsed.role as Role;
        if (role === "PARTICIPANT_B" && this.loseFirstBAdmission && !this.lostBResponse) {
          // Model the ambiguous failure precisely: the durable admission lands,
          // then the browser loses the response. Its only safe recovery is to
          // resend the exact signed request and rely on server idempotency.
          this.lostBResponse = true;
          this.bAdmitted = true;
          await route.abort("failed");
          return;
        }
        const newlyAdmitted = role === "PARTICIPANT_A" ? !this.aAdmitted : !this.bAdmitted;
        if (role === "PARTICIPANT_A") this.aAdmitted = true;
        if (role === "PARTICIPANT_B") this.bAdmitted = true;
        const participantWallet = asRecord(parsed.authorization).participantWallet as string;
        await json(route, 201, {
          ...caseBody(this.aAdmitted, this.bAdmitted, this.aWallet),
          role,
          participantWallet,
          eligibilityBlock: 51_500_010,
          newlyAdmitted,
        });
        return;
      }

      await json(route, 404, { code: "ROUTE_NOT_FOUND" });
    });
  }
}

async function installProviders(page: Page, betaAddress = HOLDER_B) {
  await page.addInitScript(({ holderA, holderB, chainHex }) => {
    type ProviderCall = { provider: string; method: string; params: unknown };
    type Listener = (...args: unknown[]) => void;
    const target = window as unknown as {
      ethereum: unknown;
      __mordantProviderCalls: ProviderCall[];
    };
    target.__mordantProviderCalls = [];

    const makeProvider = (definition: Readonly<{
      name: string;
      rdns: string;
      uuid: string;
      address: string;
      signatureByte: string;
    }>) => {
      let chainId = "0x1";
      let connected = false;
      const listeners = new Map<string, Set<Listener>>();
      const emit = (event: string, ...args: unknown[]) => {
        for (const listener of listeners.get(event) ?? []) listener(...args);
      };
      const provider = {
        request: async ({ method, params }: { method: string; params?: unknown }) => {
          target.__mordantProviderCalls.push({ provider: definition.name, method, params: params ?? null });
          if (method === "eth_chainId") return chainId;
          if (method === "eth_accounts") return connected ? [definition.address] : [];
          if (method === "eth_requestAccounts") {
            connected = true;
            return [definition.address];
          }
          if (method === "wallet_switchEthereumChain") {
            const requested = Array.isArray(params) ? (params[0] as { chainId?: unknown } | undefined)?.chainId : null;
            if (requested !== chainHex) throw new Error("Unexpected deterministic chain request");
            chainId = chainHex;
            queueMicrotask(() => emit("chainChanged", chainId));
            return null;
          }
          if (method === "eth_signTypedData_v4") {
            if (!connected || chainId !== chainHex) throw new Error("Deterministic provider is not ready to sign");
            return `0x${definition.signatureByte.repeat(65)}`;
          }
          return null;
        },
        on: (event: string, listener: Listener) => {
          const existing = listeners.get(event) ?? new Set<Listener>();
          existing.add(listener);
          listeners.set(event, existing);
        },
        removeListener: (event: string, listener: Listener) => {
          listeners.get(event)?.delete(listener);
        },
      };
      const detail = Object.freeze({
        info: Object.freeze({
          uuid: definition.uuid,
          name: definition.name,
          rdns: definition.rdns,
          icon: "data:image/png;base64,iVBORw0KGgo=",
        }),
        provider,
      });
      const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
      window.addEventListener("eip6963:requestProvider", announce);
      announce();
      return provider;
    };

    target.ethereum = makeProvider({
      name: "Canonical Participant A",
      rdns: "test.mordant.participant-a",
      uuid: "00000000-0000-4000-8000-00000000000a",
      address: holderA,
      signatureByte: "aa",
    });
    makeProvider({
      name: "Canonical Participant B",
      rdns: "test.mordant.participant-b",
      uuid: "00000000-0000-4000-8000-00000000000b",
      address: holderB,
      signatureByte: "bb",
    });
  }, { holderA: HOLDER_A, holderB: betaAddress, chainHex: CHAIN_HEX });
}

async function providerCalls(page: Page) {
  return page.evaluate(() => (
    window as unknown as { __mordantProviderCalls: Array<{ provider: string; method: string; params: unknown }> }
  ).__mordantProviderCalls);
}

async function connectAndVerify(page: Page, role: "A" | "B", walletName: string) {
  const panel = page.locator(`[data-testid="participant-admission"] [data-role="${role}"]`);
  await expect(panel).toBeVisible();
  await panel.getByRole("button", { name: "Connect a wallet" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText(`Participant ${role}`);
  await dialog.getByRole("button", { name: new RegExp(walletName, "u") }).click();
  await expect(dialog).toContainText("Wallet connected on the wrong network.");
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(panel).toContainText("Wrong network");
  await panel.getByRole("button", { name: "Switch to Monad testnet" }).click();
  await expect(panel).toContainText("Monad testnet");
  await panel.getByRole("button", { name: "Check A-Pass eligibility" }).click();
  await expect(panel).toContainText(/Verified · block 5150000[23]/u);
  return panel;
}

function typedPayload(call: Readonly<{ params: unknown }>): JsonRecord {
  expect(Array.isArray(call.params)).toBe(true);
  const params = call.params as unknown[];
  expect(params).toHaveLength(2);
  expect(typeof params[1]).toBe("string");
  return asRecord(JSON.parse(params[1] as string));
}

function numeric(value: unknown): bigint {
  expect(["string", "number"]).toContain(typeof value);
  return BigInt(value as string | number);
}

async function expectNoOutcome(page: Page, disclosureRequired = false) {
  if (disclosureRequired) {
    await expect(page.locator("body")).toContainText("No result exists until the governed decryptor releases a signed Boolean.");
  }
  await expect(page.getByTestId("reveal")).toHaveCount(0);
  await expect(page.getByTestId("decision-rail")).toHaveCount(0);
  const text = (await page.locator("body").innerText()).toLowerCase();
  expect(text).not.toContain("conflict confirmed");
  expect(text).not.toMatch(/\bno conflict\b/u);
}

test.describe("direct participant browser integration", () => {
  test("runs the real two-wallet controller, restores it, and retries the exact signed B admission", async ({ page }) => {
    const worker = new DeterministicParticipantWorker({ loseFirstBAdmission: true });
    await installProviders(page);
    await worker.install(page);

    await page.goto("/design-lab/live/direct");
    await expect(page.getByTestId("direct-execution-harness")).toBeVisible();
    await page.waitForTimeout(250);
    let calls = await providerCalls(page);
    for (const forbidden of ["eth_requestAccounts", "wallet_switchEthereumChain", "eth_signTypedData_v4"]) {
      expect(calls.some((call) => call.method === forbidden)).toBe(false);
    }
    expect(worker.createBodies).toEqual([]);

    const panelA = await connectAndVerify(page, "A", "Canonical Participant A");
    await panelA.getByLabel("Active from").fill("137");
    await panelA.getByLabel("Active until").fill("463");
    await panelA.getByRole("button", { name: "Authorize claim A" }).click();
    await expect(page.getByTestId("handoff")).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/protection/live\\?caseCode=${CASE_CODE}$`, "u"));

    expect(worker.createBodies).toEqual(["{}"]);
    expect(worker.challengeBodies[0]).toEqual({
      role: "PARTICIPANT_A",
      participantWallet: HOLDER_A,
      claim: { activeFrom: 137, activeUntil: 463 },
    });
    calls = await providerCalls(page);
    const signedA = calls.filter((call) => call.provider === "Canonical Participant A" && call.method === "eth_signTypedData_v4");
    expect(signedA).toHaveLength(1);
    const typedA = typedPayload(signedA[0]);
    expect(typedA.primaryType).toBe(PARTICIPANT_ADMISSION_PRIMARY_TYPE);
    expect(asRecord(typedA.types).ParticipantAdmissionV2).toEqual(PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV2);
    expect(asRecord(typedA.domain).name).toBe("Mordant Participant Admission");
    expect(asRecord(typedA.domain).version).toBe(PARTICIPANT_ADMISSION_DOMAIN_VERSION);
    expect(numeric(asRecord(typedA.domain).chainId)).toBe(BigInt(CHAIN_ID));
    expect(asRecord(typedA.domain).salt).toBe(PARTICIPANT_ADMISSION_DOMAIN_SALT);
    const messageA = asRecord(typedA.message);
    expect(messageA.verifyingService).toBe(APP_ORIGIN);
    expect(messageA.runId).toBe(RUN_ID);
    expect(messageA.role).toBe("PARTICIPANT_A");
    expect(String(messageA.participantWallet).toLowerCase()).toBe(HOLDER_A.toLowerCase());
    expect(numeric(messageA.activeFrom)).toBe(137n);
    expect(numeric(messageA.activeUntil)).toBe(463n);
    await expectNoOutcome(page);

    // The production controller writes the canonical recovery URL. The dev-only
    // harness reuses that exact caseCode after a real document refresh.
    await page.evaluate((caseCode) => {
      window.history.replaceState(null, "", `/design-lab/live/direct?caseCode=${caseCode}`);
    }, CASE_CODE);
    await page.reload();
    await expect(page.getByTestId("direct-execution-harness")).toBeVisible();
    await expect(page.getByTestId("handoff")).toBeVisible();
    expect(worker.readCount).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(caseBody(worker.aAdmitted, worker.bAdmitted))).not.toMatch(/activeFrom|activeUntil/u);
    await expect(page.locator("body")).not.toContainText("Design fixture. Not a real execution.");

    await page.getByTestId("handoff").getByRole("button", { name: "Continue as Participant B" }).click();
    const panelB = await connectAndVerify(page, "B", "Canonical Participant B");
    await expect(panelB.getByLabel("Active from")).toHaveValue("");
    await expect(panelB.getByLabel("Active until")).toHaveValue("");
    await panelB.getByLabel("Active from").fill("271");
    await panelB.getByLabel("Active until").fill("809");
    await panelB.getByRole("button", { name: "Authorize claim B" }).click();
    await expect(panelB.getByRole("button", { name: "Retry this signed admission" })).toBeVisible();
    expect(worker.bAdmitted).toBe(true);
    await expect(panelB.getByLabel("Active from")).toBeDisabled();
    await expect(panelB.getByLabel("Active until")).toBeDisabled();

    const failedBPost = worker.admissionBodies.filter((entry) => entry.parsed.role === "PARTICIPANT_B");
    expect(failedBPost).toHaveLength(1);
    await panelB.getByRole("button", { name: "Retry this signed admission" }).click();
    await expect(page.getByTestId("participant-admission")).toHaveCount(0);

    const bPosts = worker.admissionBodies.filter((entry) => entry.parsed.role === "PARTICIPANT_B");
    expect(bPosts).toHaveLength(2);
    expect(bPosts[1].raw).toBe(bPosts[0].raw);
    expect(Object.keys(bPosts[0].parsed).sort()).toEqual(["authorization", "claim", "role", "signature"]);
    expect(bPosts[0].parsed.claim).toEqual({ activeFrom: 271, activeUntil: 809 });
    expect(worker.challengeBodies[1]).toEqual({
      role: "PARTICIPANT_B",
      participantWallet: HOLDER_B,
      claim: { activeFrom: 271, activeUntil: 809 },
    });
    expect(worker.requestPaths.some((path) => path.includes("custom-cases"))).toBe(false);

    calls = await providerCalls(page);
    const signedB = calls.filter((call) => call.provider === "Canonical Participant B" && call.method === "eth_signTypedData_v4");
    expect(signedB).toHaveLength(1);
    const typedB = typedPayload(signedB[0]);
    expect(typedB.primaryType).toBe("ParticipantAdmissionV2");
    expect(asRecord(typedB.types).ParticipantAdmissionV2).toEqual(PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV2);
    const messageB = asRecord(typedB.message);
    expect(messageB.role).toBe("PARTICIPANT_B");
    expect(String(messageB.participantWallet).toLowerCase()).toBe(HOLDER_B.toLowerCase());
    expect(numeric(messageB.activeFrom)).toBe(271n);
    expect(numeric(messageB.activeUntil)).toBe(809n);
    expect(calls.filter((call) => call.provider === "Canonical Participant B" && call.method === "wallet_switchEthereumChain")).toHaveLength(1);
    await expectNoOutcome(page, true);
  });

  test("refuses the same wallet for both roles before challenge or signature", async ({ page }) => {
    const worker = new DeterministicParticipantWorker({ aAdmitted: true });
    await installProviders(page, HOLDER_A);
    await worker.install(page);

    await page.goto(`/design-lab/live/direct?caseCode=${CASE_CODE}`);
    await expect(page.getByTestId("handoff")).toBeVisible();
    await page.getByTestId("handoff").getByRole("button", { name: "Continue as Participant B" }).click();
    await connectAndVerify(page, "B", "Canonical Participant B");
    const panel = page.locator('[data-testid="participant-admission"] [data-role="B"]');
    await expect(page.getByTestId("same-address-B")).toContainText("must use a different address");
    await expect(panel.getByRole("button", { name: "Authorize claim B" })).toBeDisabled();
    expect(worker.challengeBodies).toEqual([]);
    const calls = await providerCalls(page);
    expect(calls.filter((call) => call.method === "eth_signTypedData_v4")).toHaveLength(0);
  });

  for (const scenario of [
    { defect: "expired" as const, title: "an expired authorization nonce" },
    { defect: "changed-payload" as const, title: "a challenge whose signed payload changed" },
  ]) {
    test(`rejects ${scenario.title} before opening a signature request`, async ({ page }) => {
      const worker = new DeterministicParticipantWorker({ defect: scenario.defect });
      await installProviders(page);
      await worker.install(page);

      await page.goto("/design-lab/live/direct");
      const panel = await connectAndVerify(page, "A", "Canonical Participant A");
      await panel.getByLabel("Active from").fill("149");
      await panel.getByLabel("Active until").fill("487");
      await panel.getByRole("button", { name: "Authorize claim A" }).click();
      await expect(page.locator("body")).toContainText("The worker response was rejected.");
      await expect(page.locator("body")).toContainText("No admission or result is shown");
      expect(worker.admissionBodies).toEqual([]);
      const calls = await providerCalls(page);
      expect(calls.filter((call) => call.method === "eth_signTypedData_v4")).toHaveLength(0);
      await expect(page.getByTestId("reveal")).toHaveCount(0);
    });
  }
});
