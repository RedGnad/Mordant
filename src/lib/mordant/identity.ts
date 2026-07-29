/**
 * Synthetic visual identity helpers for the Mordant prototype.
 *
 * Folios and rootlines are matching/navigation aids. They do not establish
 * authenticity, invoice truth, legal priority, or cryptographic verification.
 */

export const ROOTLINE_USAGE_NOTICE =
  "Visual index derived from invoice root. Navigation aid only; not cryptographic proof." as const;

export const ROOTLINE_WIDTHS = [1, 2, 3, 5, 7, 11] as const;
export const ROOTLINE_SPACINGS = [1, 2, 3] as const;

export type RootlineWidth = (typeof ROOTLINE_WIDTHS)[number];
export type RootlineSpacing = (typeof ROOTLINE_SPACINGS)[number];

export type RootlineSegment = Readonly<{
  width: RootlineWidth;
  spacing: RootlineSpacing;
}>;

const SYNTHETIC_FOLIOS = {
  healthy: "MRD-S02487",
  "cure-expiring": "MRD-S02481",
  "pending-finality": "MRD-S02468",
  "funds-missing": "MRD-S02476",
  "allowance-missing": "MRD-S02472",
  "wrong-role": "MRD-S02441",
  "credential-required": "MRD-S02453",
  "prerequisite-missing": "MRD-S02462",
  completed: "MRD-S02497",
  "recovery-required": "MRD-S02388",
  "stale-observation": "MRD-S02409",
  "unknown-observation": "MRD-S02397",
  "partial-redemption": "MRD-S02457",
  "protection-settled": "MRD-S02494",
} as const;

export type SyntheticIdentityScenario = keyof typeof SYNTHETIC_FOLIOS;
export type SyntheticFolio = (typeof SYNTHETIC_FOLIOS)[SyntheticIdentityScenario];
export type SyntheticInvoiceRoot = `synroot:mordant-demo-invoice-${string}`;

export function syntheticInvoiceRootForScenario(scenario: string): SyntheticInvoiceRoot {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(scenario)) {
    throw new TypeError(`Invalid synthetic scenario identity: ${scenario}`);
  }

  return `synroot:mordant-demo-invoice-${scenario}`;
}

export function syntheticFolioForScenario(scenario: string): SyntheticFolio {
  if (!Object.hasOwn(SYNTHETIC_FOLIOS, scenario)) {
    throw new RangeError(`No synthetic folio is registered for scenario: ${scenario}`);
  }

  return SYNTHETIC_FOLIOS[scenario as SyntheticIdentityScenario];
}

function hashRoot(root: string): number {
  let hash = 0x811c9dc5;

  for (let index = 0; index < root.length; index += 1) {
    hash ^= root.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return hash >>> 0;
}

function nextState(state: number): number {
  let next = state || 0x9e3779b9;
  next ^= next << 13;
  next ^= next >>> 17;
  next ^= next << 5;
  return next >>> 0;
}

function shuffled<T>(values: readonly T[], initialState: number): { values: T[]; state: number } {
  const result = [...values];
  let state = initialState;

  for (let index = result.length - 1; index > 0; index -= 1) {
    state = nextState(state);
    const swapIndex = state % (index + 1);
    [result[index], result[swapIndex]] = [result[swapIndex] as T, result[index] as T];
  }

  return { values: result, state };
}

/**
 * Produces the eight-stroke visual index used beside a deal folio.
 *
 * Every index uses the complete vocabulary of six stroke widths and three
 * spacings. The ordering and two repeated widths are derived deterministically
 * from the immutable invoice root. This is deliberately not a security or
 * cryptographic primitive; see ROOTLINE_USAGE_NOTICE.
 */
export function rootlineSegments(root: string): readonly RootlineSegment[] {
  if (root.length === 0) {
    throw new TypeError("An immutable invoice root is required to derive a rootline.");
  }

  const widthShuffle = shuffled(ROOTLINE_WIDTHS, hashRoot(root));
  let state = widthShuffle.state;
  const widths: RootlineWidth[] = [...widthShuffle.values];

  while (widths.length < 8) {
    state = nextState(state);
    widths.push(ROOTLINE_WIDTHS[state % ROOTLINE_WIDTHS.length] as RootlineWidth);
  }

  const spacingShuffle = shuffled(ROOTLINE_SPACINGS, nextState(state));
  const spacings = spacingShuffle.values;
  const spacingOffset = nextState(spacingShuffle.state) % spacings.length;

  return Object.freeze(
    widths.map((width, index) =>
      Object.freeze({
        width,
        spacing: spacings[(index + spacingOffset) % spacings.length] as RootlineSpacing,
      }),
    ),
  );
}
