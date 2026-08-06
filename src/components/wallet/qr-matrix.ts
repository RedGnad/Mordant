/**
 * Minimal QR encoder, byte mode, error-correction level L.
 *
 * Written here rather than pulled in as a dependency: the only thing the wallet
 * modal needs is a boolean matrix for one short pairing URI, and adding a
 * package for that would touch the shared lockfile that other branches are also
 * editing.
 *
 * Scope is deliberately narrow: byte mode only, level L only, versions 1 to 15,
 * which covers a WalletConnect pairing URI with room to spare. Anything longer
 * is refused rather than silently truncated.
 */

export type QrMatrix = Readonly<{ size: number; modules: readonly (readonly boolean[])[]; version: number }>;

/** Data codeword capacity at level L, versions 1..15. */
const DATA_CODEWORDS_L = [19, 34, 55, 80, 108, 136, 156, 194, 232, 274, 324, 370, 428, 461, 523];

/** [blocks, codewords per block] at level L. Level L uses one group for 1..15. */
const EC_BLOCKS_L: readonly (readonly [number, number])[] = [
  [1, 7], [1, 10], [1, 15], [1, 20], [1, 26], [2, 18], [2, 20], [2, 24], [2, 30], [4, 18],
  [4, 20], [4, 24], [4, 26], [4, 30], [6, 22],
];

/** Alignment-pattern centre coordinates per version. */
const ALIGNMENT: readonly (readonly number[])[] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
  [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70],
];

// ---------------------------------------------------------------- GF(256)

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

function generatorPolynomial(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

export function reedSolomon(data: readonly number[], ecLength: number): number[] {
  const generator = generatorPolynomial(ecLength);
  const remainder = new Array<number>(ecLength).fill(0);
  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.shift();
    remainder.push(0);
    if (factor !== 0) {
      for (let i = 0; i < ecLength; i += 1) remainder[i] ^= gfMul(generator[i + 1], factor);
    }
  }
  return remainder;
}

// ---------------------------------------------------------------- encoding

function chooseVersion(byteLength: number): number {
  for (let version = 1; version <= 15; version += 1) {
    const countBits = version < 10 ? 8 : 16;
    const needed = 4 + countBits + byteLength * 8;
    if (needed <= DATA_CODEWORDS_L[version - 1] * 8) return version;
  }
  throw new Error("The pairing payload is too long for this encoder");
}

function dataCodewords(bytes: Uint8Array, version: number): number[] {
  const capacity = DATA_CODEWORDS_L[version - 1];
  const countBits = version < 10 ? 8 : 16;
  const bits: number[] = [];
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };

  push(0b0100, 4);
  push(bytes.length, countBits);
  for (const byte of bytes) push(byte, 8);

  const capacityBits = capacity * 8;
  push(0, Math.min(4, capacityBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    codewords.push(bits.slice(i, i + 8).reduce((acc, bit) => (acc << 1) | bit, 0));
  }
  const padding = [0xec, 0x11];
  let index = 0;
  while (codewords.length < capacity) {
    codewords.push(padding[index % 2]);
    index += 1;
  }
  return codewords;
}

/** Interleaves data and error-correction blocks in the order the spec places them. */
function finalCodewords(data: readonly number[], version: number): number[] {
  const [blockCount, ecPerBlock] = EC_BLOCKS_L[version - 1];
  const total = data.length;
  const shortLength = Math.floor(total / blockCount);
  const longCount = total % blockCount;

  const dataBlocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let offset = 0;
  for (let i = 0; i < blockCount; i += 1) {
    const length = shortLength + (i >= blockCount - longCount ? 1 : 0);
    const block = data.slice(offset, offset + length);
    offset += length;
    dataBlocks.push(block);
    ecBlocks.push(reedSolomon(block, ecPerBlock));
  }

  const out: number[] = [];
  const maxData = Math.max(...dataBlocks.map((block) => block.length));
  for (let i = 0; i < maxData; i += 1) {
    for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  }
  for (let i = 0; i < ecPerBlock; i += 1) {
    for (const block of ecBlocks) out.push(block[i]);
  }
  return out;
}

// ---------------------------------------------------------------- matrix

type Grid = { modules: (boolean | null)[][]; reserved: boolean[][]; size: number };

function blankGrid(size: number): Grid {
  return {
    size,
    modules: Array.from({ length: size }, () => new Array<boolean | null>(size).fill(null)),
    reserved: Array.from({ length: size }, () => new Array<boolean>(size).fill(false)),
  };
}

function place(grid: Grid, row: number, column: number, value: boolean, reserved = true) {
  if (row < 0 || column < 0 || row >= grid.size || column >= grid.size) return;
  grid.modules[row][column] = value;
  grid.reserved[row][column] = reserved;
}

function finder(grid: Grid, row: number, column: number) {
  for (let r = -1; r <= 7; r += 1) {
    for (let c = -1; c <= 7; c += 1) {
      const inner = r >= 0 && r <= 6 && c >= 0 && c <= 6;
      const dark = inner && ((r === 0 || r === 6 || c === 0 || c === 6) || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
      place(grid, row + r, column + c, dark);
    }
  }
}

function alignment(grid: Grid, version: number) {
  const centres = ALIGNMENT[version - 1];
  for (const row of centres) {
    for (const column of centres) {
      const nearFinder = (row <= 8 && column <= 8)
        || (row <= 8 && column >= grid.size - 9)
        || (row >= grid.size - 9 && column <= 8);
      if (nearFinder) continue;
      for (let r = -2; r <= 2; r += 1) {
        for (let c = -2; c <= 2; c += 1) {
          place(grid, row + r, column + c, Math.max(Math.abs(r), Math.abs(c)) !== 1);
        }
      }
    }
  }
}

function timing(grid: Grid) {
  for (let i = 8; i < grid.size - 8; i += 1) {
    place(grid, 6, i, i % 2 === 0);
    place(grid, i, 6, i % 2 === 0);
  }
}

function reserveFormat(grid: Grid) {
  for (let i = 0; i < 9; i += 1) {
    // Index 6 belongs to the timing patterns, which the format area must not
    // overwrite: doing so breaks the alternating line a scanner locks onto.
    if (i === 6) continue;
    place(grid, 8, i, false);
    place(grid, i, 8, false);
  }
  for (let i = 0; i < 8; i += 1) {
    place(grid, 8, grid.size - 1 - i, false);
    place(grid, grid.size - 1 - i, 8, false);
  }
  place(grid, grid.size - 8, 8, true);
}

function reserveVersion(grid: Grid, version: number) {
  if (version < 7) return;
  for (let i = 0; i < 18; i += 1) {
    const row = Math.floor(i / 3);
    const column = grid.size - 11 + (i % 3);
    place(grid, row, column, false);
    place(grid, column, row, false);
  }
}

const MASKS: readonly ((row: number, column: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function placeData(grid: Grid, codewords: readonly number[], mask: number) {
  const bits: number[] = [];
  for (const codeword of codewords) {
    for (let i = 7; i >= 0; i -= 1) bits.push((codeword >> i) & 1);
  }
  let index = 0;
  let upward = true;
  for (let right = grid.size - 1; right >= 1; right -= 2) {
    if (right === 6) right -= 1;
    for (let step = 0; step < grid.size; step += 1) {
      const row = upward ? grid.size - 1 - step : step;
      for (const column of [right, right - 1]) {
        if (grid.reserved[row][column]) continue;
        const bit = index < bits.length ? bits[index] === 1 : false;
        index += 1;
        grid.modules[row][column] = MASKS[mask](row, column) ? !bit : bit;
      }
    }
    upward = !upward;
  }
}

const FORMAT_GENERATOR = 0b10100110111;

function formatBits(mask: number): number {
  // Level L is 01 in the two most significant bits of the format string.
  let value = ((0b01 << 3) | mask) << 10;
  const data = value;
  for (let i = 14; i >= 10; i -= 1) {
    if ((value >> i) & 1) value ^= FORMAT_GENERATOR << (i - 10);
  }
  return (data | value) ^ 0b101010000010010;
}

function writeFormat(grid: Grid, mask: number) {
  const bits = formatBits(mask);
  for (let i = 0; i < 15; i += 1) {
    const bit = ((bits >> i) & 1) === 1;
    if (i < 6) place(grid, i, 8, bit);
    else if (i < 8) place(grid, i + 1, 8, bit);
    else if (i === 8) place(grid, 8, 7, bit);
    else place(grid, 8, 14 - i, bit);

    if (i < 8) place(grid, 8, grid.size - 1 - i, bit);
    else place(grid, grid.size - 15 + i, 8, bit);
  }
  place(grid, grid.size - 8, 8, true);
}

const VERSION_GENERATOR = 0b1111100100101;

function writeVersion(grid: Grid, version: number) {
  if (version < 7) return;
  let value = version << 12;
  for (let i = 17; i >= 12; i -= 1) {
    if ((value >> i) & 1) value ^= VERSION_GENERATOR << (i - 12);
  }
  const bits = (version << 12) | value;
  for (let i = 0; i < 18; i += 1) {
    const bit = ((bits >> i) & 1) === 1;
    const row = Math.floor(i / 3);
    const column = grid.size - 11 + (i % 3);
    place(grid, row, column, bit);
    place(grid, column, row, bit);
  }
}

/** Standard penalty score, used to pick the mask that reads most reliably. */
function penalty(grid: Grid): number {
  const size = grid.size;
  const at = (r: number, c: number) => grid.modules[r][c] === true;
  let score = 0;

  for (let r = 0; r < size; r += 1) {
    for (const horizontal of [true, false]) {
      let run = 1;
      for (let i = 1; i < size; i += 1) {
        const current = horizontal ? at(r, i) : at(i, r);
        const previous = horizontal ? at(r, i - 1) : at(i - 1, r);
        if (current === previous) run += 1;
        else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const first = at(r, c);
      if (first === at(r, c + 1) && first === at(r + 1, c) && first === at(r + 1, c + 1)) score += 3;
    }
  }

  let dark = 0;
  for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) if (at(r, c)) dark += 1;
  const percent = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

export function encodeQr(payload: string): QrMatrix {
  const bytes = new TextEncoder().encode(payload);
  const version = chooseVersion(bytes.length);
  const codewords = finalCodewords(dataCodewords(bytes, version), version);
  const size = version * 4 + 17;

  let best: { grid: Grid; score: number } | null = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const grid = blankGrid(size);
    finder(grid, 0, 0);
    finder(grid, 0, size - 7);
    finder(grid, size - 7, 0);
    alignment(grid, version);
    timing(grid);
    reserveFormat(grid);
    reserveVersion(grid, version);
    placeData(grid, codewords, mask);
    writeFormat(grid, mask);
    writeVersion(grid, version);
    const score = penalty(grid);
    if (best === null || score < best.score) best = { grid, score };
  }

  const grid = best!.grid;
  return Object.freeze({
    size,
    version,
    modules: Object.freeze(grid.modules.map((row) => Object.freeze(row.map((value) => value === true)))),
  });
}
