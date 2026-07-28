import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { NextResponse } from "next/server";

/**
 * Serves the local deal-room deployment: addresses, the deterministic Anvil accounts and the ABIs
 * compiled by Foundry.
 *
 * This is a LOCAL development surface. The accounts it returns are Anvil's published development
 * keys, which exist so the demo is reproducible from an empty chain and hold nothing anywhere else.
 * The route refuses to answer outside development or off the local chain id, so it can never expose
 * anything on a deployed environment.
 */

const LOCAL_CHAIN_ID = 31_337;

const ARTIFACTS: readonly (readonly [string, string, string])[] = [
  ["vault", "MordantInvoiceVault.sol", "MordantInvoiceVault"],
  ["factory", "MordantFactory.sol", "MordantFactory"],
  ["erc20", "MockERC20.sol", "MockERC20"],
  ["adapter", "MockCvaAdapter.sol", "MockCvaAdapter"],
  ["eligibility", "MockEligibility.sol", "MockEligibility"],
];

export const dynamic = "force-dynamic";

export function GET() {
  if (process.env.NODE_ENV === "production") {
    return NextResponse.json(
      { error: "The local deal room is not available in a production build." },
      { status: 404 },
    );
  }

  const root = process.cwd();
  const deploymentPath = join(root, ".dealroom", "deployment.json");
  if (!existsSync(deploymentPath)) {
    return NextResponse.json(
      { error: "No local deployment found. Run `pnpm localnet` first." },
      { status: 503 },
    );
  }

  let deployment: { chainId?: number };
  try {
    deployment = JSON.parse(readFileSync(deploymentPath, "utf8"));
  } catch {
    return NextResponse.json({ error: "Local deployment file is unreadable." }, { status: 500 });
  }

  if (deployment.chainId !== LOCAL_CHAIN_ID) {
    return NextResponse.json(
      { error: `Refusing to serve a deployment for chain ${deployment.chainId}.` },
      { status: 409 },
    );
  }

  const abis: Record<string, unknown> = {};
  for (const [key, file, name] of ARTIFACTS) {
    const path = join(root, "contracts", "out", file, `${name}.json`);
    if (!existsSync(path)) {
      return NextResponse.json(
        { error: "Contract artifacts are missing. Run `pnpm build:contracts` first." },
        { status: 503 },
      );
    }
    abis[key] = JSON.parse(readFileSync(path, "utf8")).abi;
  }

  return NextResponse.json({ ...deployment, abis });
}
