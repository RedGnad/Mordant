import { expect, test } from "@playwright/test";

import { encodeQr, reedSolomon } from "../src/components/wallet/qr-matrix";
import { safeWalletIcon, dedupeConnectors } from "../src/components/wallet/wallet-presentation";

// A representative WalletConnect v2 pairing URI: this is the payload the modal
// has to encode, so the encoder is exercised at the real length.
const PAIRING_URI =
  "wc:8f1e889ac6e0747ae0913bd4c33be4a81f2d3c4b5a69788d0e1f2a3b4c5d6e7f@2"
  + "?relay-protocol=irn&symKey=3b0247593d022fb18aadd2b554329f85c5a19898d8a8091c65499b5e85494fe08";

/** Evaluates the codeword polynomial at the roots the generator was built from. */
function syndrome(codeword: readonly number[], ecLength: number): number[] {
  const exp = new Uint8Array(512);
  const log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i += 1) { exp[i] = x; log[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i += 1) exp[i] = exp[i - 255];
  const mul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : exp[log[a] + log[b]]);

  const out: number[] = [];
  for (let i = 0; i < ecLength; i += 1) {
    let value = 0;
    for (const byte of codeword) value = mul(value, exp[i]) ^ byte;
    out.push(value);
  }
  return out;
}

test.describe("QR encoding for the WalletConnect pairing surface", () => {
  test("the error-correction block is a valid Reed-Solomon codeword", () => {
    const data = Array.from({ length: 40 }, (_value, index) => (index * 7 + 3) & 0xff);
    for (const ecLength of [7, 10, 18, 20, 24, 30]) {
      const parity = reedSolomon(data, ecLength);
      expect(parity).toHaveLength(ecLength);
      // A correct codeword evaluates to zero at every generator root.
      expect(syndrome([...data, ...parity], ecLength)).toEqual(new Array(ecLength).fill(0));
    }
  });

  test("a pairing URI produces a well-formed matrix", () => {
    const qr = encodeQr(PAIRING_URI);
    expect(qr.size).toBe(qr.version * 4 + 17);
    expect(qr.modules).toHaveLength(qr.size);
    for (const row of qr.modules) expect(row).toHaveLength(qr.size);

    // Three finder patterns, each a 7x7 ring with a 3x3 core.
    const finderAt = (r0: number, c0: number) => {
      for (let r = 0; r < 7; r += 1) {
        for (let c = 0; c < 7; c += 1) {
          const dark = r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          expect(qr.modules[r0 + r][c0 + c]).toBe(dark);
        }
      }
    };
    finderAt(0, 0);
    finderAt(0, qr.size - 7);
    finderAt(qr.size - 7, 0);

    // Timing patterns alternate on row 6 and column 6.
    for (let i = 8; i < qr.size - 8; i += 1) {
      expect(qr.modules[6][i]).toBe(i % 2 === 0);
      expect(qr.modules[i][6]).toBe(i % 2 === 0);
    }

    // The dark module is fixed by the specification.
    expect(qr.modules[qr.size - 8][8]).toBe(true);
  });

  test("version scales with payload and refuses an oversized one", () => {
    expect(encodeQr("wc:short@2").version).toBeLessThan(encodeQr(PAIRING_URI).version);
    expect(() => encodeQr("x".repeat(4_000))).toThrow(/too long/u);
  });
});

test.describe("wallet presentation metadata is untrusted", () => {
  test("only image data URIs and https icons are rendered", () => {
    expect(safeWalletIcon("data:image/png;base64,iVBORw0KGgo=")).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(safeWalletIcon("https://wallet.example/icon.png")).toBe("https://wallet.example/icon.png");

    // Anything that could execute, navigate or smuggle markup is refused.
    expect(safeWalletIcon("javascript:alert(1)")).toBeNull();
    expect(safeWalletIcon("data:text/html;base64,PHNjcmlwdD4=")).toBeNull();
    expect(safeWalletIcon("<svg onload=alert(1)>")).toBeNull();
    expect(safeWalletIcon("http://wallet.example/icon.png")).toBeNull();
    expect(safeWalletIcon("")).toBeNull();
    expect(safeWalletIcon(undefined)).toBeNull();
  });

  test("repeated providers collapse to one row", () => {
    const rows = dedupeConnectors([
      { uid: "1", id: "io.metamask", name: "MetaMask", icon: undefined, type: "injected" },
      { uid: "2", id: "io.metamask", name: "MetaMask", icon: undefined, type: "injected" },
      { uid: "3", id: "injected", name: "MetaMask", icon: undefined, type: "injected" },
      { uid: "4", id: "com.rabby", name: "Rabby", icon: undefined, type: "injected" },
      { uid: "5", id: "walletConnect", name: "WalletConnect", icon: undefined, type: "walletConnect" },
    ]);
    expect(rows.map((row) => row.name)).toEqual(["MetaMask", "Rabby", "WalletConnect"]);
    // Identity for the UI comes from the connector uid, never the wallet name.
    expect(rows[0].uid).toBe("1");
  });

  test("a generic injected fallback is dropped when a named provider exists", () => {
    const rows = dedupeConnectors([
      { uid: "1", id: "injected", name: "Injected", icon: undefined, type: "injected" },
      { uid: "2", id: "io.rabby", name: "Rabby", icon: undefined, type: "injected" },
    ]);
    expect(rows.map((row) => row.name)).toEqual(["Rabby"]);
  });

  test("a lone generic injected provider is still offered", () => {
    const rows = dedupeConnectors([
      { uid: "1", id: "injected", name: "Injected", icon: undefined, type: "injected" },
    ]);
    expect(rows).toHaveLength(1);
  });
});

// ---------------------------------------------------------------- runtime behaviour

/**
 * Installs two EIP-6963 providers and records every RPC method they are asked
 * for, so the request discipline can be asserted rather than assumed.
 */
const INSTALL_PROVIDERS = `
window.__mordantCalls = [];
function makeProvider(name, rdns, accounts) {
  const provider = {
    request: async ({ method }) => {
      window.__mordantCalls.push(method);
      if (method === "eth_chainId") return "0x1";
      if (method === "eth_accounts") return [];
      if (method === "eth_requestAccounts") return accounts;
      if (method === "wallet_switchEthereumChain") return null;
      return null;
    },
    on: () => {},
    removeListener: () => {},
  };
  const detail = Object.freeze({
    info: Object.freeze({ uuid: rdns + "-uuid", name, rdns, icon: "data:image/png;base64,iVBORw0KGgo=" }),
    provider,
  });
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
  return provider;
}
window.ethereum = makeProvider("Alpha Wallet", "app.alpha", ["0x911F99f424D47F08a15fcC771e94dcc2f7252B02"]);
makeProvider("Beta Wallet", "app.beta", ["0x1111111111111111111111111111111111111111"]);
`;

test.describe("wallet modal runtime discipline", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(INSTALL_PROVIDERS);
  });

  test("no wallet request is made on mount", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await expect(page.getByTestId("open-wallet")).toBeVisible();
    await page.waitForTimeout(1_200);

    const calls: string[] = await page.evaluate(() => (window as never as { __mordantCalls: string[] }).__mordantCalls);
    for (const forbidden of [
      "eth_requestAccounts",
      "wallet_requestPermissions",
      "wallet_switchEthereumChain",
      "wallet_addEthereumChain",
      "eth_signTypedData_v4",
      "personal_sign",
    ]) {
      expect(calls).not.toContain(forbidden);
    }
  });

  test("opening the modal alone still requests nothing", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.waitForTimeout(600);

    const calls: string[] = await page.evaluate(() => (window as never as { __mordantCalls: string[] }).__mordantCalls);
    expect(calls).not.toContain("eth_requestAccounts");
  });

  test("discovered wallets are listed once each, with context and no dead rows", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    const dialog = page.getByRole("dialog");

    await expect(dialog.getByRole("heading", { name: "Choose the wallet representing this participant" })).toBeVisible();
    await expect(dialog).toContainText("MINV01");
    await expect(dialog).toContainText("Monad testnet");
    await expect(dialog).toContainText("Participant A");
    await expect(dialog).toContainText("Connecting does not submit a claim");
    await expect(dialog).toContainText("one typed authorization");

    await expect(dialog.getByRole("button", { name: /Alpha Wallet/u })).toHaveCount(1);
    await expect(dialog.getByRole("button", { name: /Beta Wallet/u })).toHaveCount(1);
    // The generic injected fallback must not appear beside the named providers.
    await expect(dialog.getByRole("button", { name: /^Injected/u })).toHaveCount(0);
  });

  test("WalletConnect is absent when unconfigured and present when configured", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    await expect(page.getByRole("dialog").getByText("On a phone")).toHaveCount(0);

    await page.goto("/design-lab/wallet?wc=configured");
    await page.getByTestId("open-wallet").click();
    await expect(page.getByRole("dialog").getByText("On a phone")).toBeVisible();
  });

  test("one click produces exactly one account request", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    await page.getByRole("button", { name: /Alpha Wallet/u }).click();
    await page.waitForTimeout(1_000);

    const calls: string[] = await page.evaluate(() => (window as never as { __mordantCalls: string[] }).__mordantCalls);
    expect(calls.filter((method) => method === "eth_requestAccounts")).toHaveLength(1);
    // Connecting never switches the network by itself.
    expect(calls).not.toContain("wallet_switchEthereumChain");
  });

  test("the dialog traps focus, closes with Escape and restores focus", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    const opener = page.getByTestId("open-wallet");
    await opener.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Focus starts inside the dialog.
    expect(await page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null)).toBe(true);

    // Tab many times: focus never escapes the dialog.
    for (let index = 0; index < 12; index += 1) {
      await page.keyboard.press("Tab");
      expect(await page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null)).toBe(true);
    }

    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  test("the page behind the dialog cannot be scrolled", async ({ page }) => {
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    expect(await page.evaluate(() => getComputedStyle(document.body).overflow)).toBe("hidden");
  });

  test("a declined connection is explained without a raw provider payload", async ({ page }) => {
    await page.addInitScript(`
      window.__mordantReject = true;
      const original = window.ethereum.request;
      window.ethereum.request = async (args) => {
        window.__mordantCalls.push(args.method);
        if (args.method === "eth_requestAccounts") {
          const error = new Error("User rejected the request.");
          error.code = 4001;
          throw error;
        }
        return original(args);
      };
    `);
    await page.goto("/design-lab/wallet");
    await page.getByTestId("open-wallet").click();
    await page.getByRole("button", { name: /Alpha Wallet/u }).click();

    const alert = page.getByRole("dialog").getByRole("alert");
    await expect(alert).toContainText("declined in your wallet");
    await expect(alert).not.toContainText("4001");
    await expect(alert).not.toContainText("{");
  });
});
