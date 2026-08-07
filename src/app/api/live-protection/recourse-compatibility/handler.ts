import { NextResponse } from "next/server";

import {
  BridgeExecutionError,
  readCanonicalAdapterV2Compatibility,
  type CanonicalAdapterV2CompatibilityReport,
} from "../../../../lib/protection/bridge-executor";

function response(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, {
    status,
    headers: { "cache-control": "no-store, max-age=0" },
  });
}

/**
 * Read-only Adapter V2 preflight. It accepts no request input: the helper uses
 * only the retained canonical vector and the two read-only bridge environment
 * settings. It neither loads an attestor key nor creates a payload/signature.
 */
export function createRecourseCompatibilityGetHandler(
  readReport: () => Promise<CanonicalAdapterV2CompatibilityReport> = readCanonicalAdapterV2Compatibility,
): () => Promise<NextResponse> {
  return async () => {
    try {
      return response(await readReport());
    } catch (error) {
      if (error instanceof BridgeExecutionError) {
        return response({
          schemaVersion: "mordant.adapter-v2-compatibility-report/1",
          compatible: false,
          code: error.code,
          error: "Adapter V2 compatibility is unavailable.",
        }, 503);
      }
      return response({
        schemaVersion: "mordant.adapter-v2-compatibility-report/1",
        compatible: false,
        error: "Adapter V2 compatibility is unavailable.",
      }, 503);
    }
  };
}
