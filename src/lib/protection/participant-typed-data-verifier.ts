import "server-only";

import { createPublicClient, http } from "viem";

import { readCcpRpcUrl, type EnvironmentLike } from "./ccp-eligibility";
import type { TypedDataVerifier } from "./participant-authorization";

/**
 * Authoritative signature validation against Monad.
 *
 * `verifyTypedData` is used rather than address recovery because it answers for
 * both account kinds from one call: an EOA is checked by recovery, and a deployed
 * ERC-1271 contract account is asked its own `isValidSignature`. It receives the
 * exact ParticipantAdmissionV1 struct the runtime built, so the browser and the
 * server cannot disagree about what was signed.
 *
 * Which account kind a given wallet actually is, is not asserted anywhere in this
 * codebase. Only the EOA A-Pass holders are covered by tests, and no
 * smart-account qualification is claimed on that basis.
 *
 * The RPC URL is read through the same validated accessor the compliance check
 * uses, so there is one place where a network can be configured and one place
 * where a bad one is refused.
 */
export function createMonadTypedDataVerifier(
  environment: EnvironmentLike = process.env,
): TypedDataVerifier {
  const client = createPublicClient({ transport: http(readCcpRpcUrl(environment)) });
  return async ({ address, typedData, signature }) => client.verifyTypedData({
    address,
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
    signature,
  });
}
