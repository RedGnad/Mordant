/**
 * Presentation rules for wallet-supplied metadata.
 *
 * A wallet's name and icon arrive from an untrusted provider. They are shown so
 * a person can recognise their wallet, and they are never treated as authority:
 * identity for the interface is the Wagmi connector uid, and the icon is only
 * ever rendered through a constrained image source. No provider markup is
 * inserted into the document.
 */

export type ConnectorRow = Readonly<{
  uid: string;
  id: string;
  name: string;
  icon: string | undefined;
  type: string;
}>;

/**
 * Accepts an image data URI or an HTTPS URL. Everything else, including raw
 * markup, `javascript:`, plain HTTP and non-image data URIs, is refused and the
 * row falls back to the Mordant mark.
 */
export function safeWalletIcon(icon: string | undefined | null): string | null {
  if (typeof icon !== "string") return null;
  const value = icon.trim();
  if (value === "" || value.length > 256_000) return null;
  if (/^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,[a-z0-9+/=]+$/iu.test(value)) return value;
  if (/^https:\/\/[^\s"'<>]+$/iu.test(value)) return value;
  return null;
}

const GENERIC_INJECTED = new Set(["injected", "io.metamask.injected"]);

/**
 * Collapses the duplicates EIP-6963 discovery routinely produces: the same
 * wallet announced twice, and the generic injected fallback that shadows a
 * provider which already announced itself properly.
 */
export function dedupeConnectors(rows: readonly ConnectorRow[]): readonly ConnectorRow[] {
  const namedInjected = rows.filter(
    (row) => row.type === "injected" && !GENERIC_INJECTED.has(row.id),
  );

  const seenId = new Set<string>();
  const seenName = new Set<string>();
  const out: ConnectorRow[] = [];

  for (const row of rows) {
    // Drop the generic fallback only when a named injected provider exists,
    // otherwise a browser with a single unnamed wallet would offer nothing.
    if (row.type === "injected" && GENERIC_INJECTED.has(row.id) && namedInjected.length > 0) continue;

    const nameKey = row.name.trim().toLowerCase();
    if (seenId.has(row.id) || seenName.has(nameKey)) continue;
    seenId.add(row.id);
    seenName.add(nameKey);
    out.push(row);
  }

  return Object.freeze(out);
}

/**
 * Digs the EIP-1193 code out of whatever the connector threw. Wagmi wraps
 * provider errors, so the number is often one or two causes down.
 */
export function providerErrorCode(error: unknown, depth = 0): number | null {
  if (error === null || typeof error !== "object" || depth > 4) return null;
  const candidate = (error as { code?: unknown }).code;
  if (typeof candidate === "number") return candidate;
  return providerErrorCode((error as { cause?: unknown }).cause, depth + 1);
}

/** Provider failures become sentences a person can act on. */
export function walletProblemMessage(code: unknown, fallback: string): string {
  const numeric = typeof code === "number" ? code : null;
  switch (numeric) {
    case 4001: return "The request was declined in your wallet. Nothing was submitted.";
    case 4100: return "This wallet has not authorized the account. Unlock it and try again.";
    case 4200: return "This wallet does not support the request Mordant made.";
    case 4900: return "The wallet is disconnected. Reconnect it and try again.";
    case 4901: return "The wallet is not connected to Monad testnet.";
    case 4902: return "Monad testnet is not available in this wallet yet.";
    case -32002: return "A request is already open in your wallet. Finish it there first.";
    default: return fallback;
  }
}
