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
