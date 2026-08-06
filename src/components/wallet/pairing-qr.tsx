"use client";

import { useMemo } from "react";

import { encodeQr } from "./qr-matrix";

/**
 * The pairing code, drawn as ink squares on paper inside the Mordant modal.
 *
 * One path per row rather than one rect per module: a version 10 code is 57x57,
 * and 3249 elements would be a real cost on a phone for no visual gain.
 */
export function PairingQr({ uri, title }: { readonly uri: string; readonly title: string }) {
  const matrix = useMemo(() => {
    try {
      return encodeQr(uri);
    } catch {
      return null;
    }
  }, [uri]);

  if (matrix === null) return null;

  const quiet = 2;
  const span = matrix.size + quiet * 2;
  const rows: string[] = [];
  for (let row = 0; row < matrix.size; row += 1) {
    let column = 0;
    while (column < matrix.size) {
      if (!matrix.modules[row][column]) { column += 1; continue; }
      let run = 1;
      while (column + run < matrix.size && matrix.modules[row][column + run]) run += 1;
      rows.push(`M${column + quiet} ${row + quiet}h${run}v1h-${run}z`);
      column += run;
    }
  }

  return (
    <svg viewBox={`0 0 ${span} ${span}`} role="img" aria-label={title} shapeRendering="crispEdges">
      <rect width={span} height={span} fill="var(--paper)" />
      <path d={rows.join("")} fill="var(--ink)" />
    </svg>
  );
}
