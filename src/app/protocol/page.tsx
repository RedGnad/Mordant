import type { Metadata } from "next";
import { ProductShell } from "@/components/product-shell";
import { ProtocolOperations } from "@/components/protocol-operations";
import deploymentManifest from "../../../docs/evidence/monad-m14-manifest-2026-07-29.json";

export const metadata: Metadata = {
  title: "Protocol operations",
  description:
    "Inspect execution gates, state transitions, on-chain evidence, and recovery paths in the Mordant prototype.",
};

export default function ProtocolPage() {
  const artifactContext = {
    artifact: "docs/evidence/monad-m14-manifest-2026-07-29.json",
    classification: deploymentManifest.classification,
    parameterSetHash: deploymentManifest.parameterSetHash,
    frozenCommit: deploymentManifest.frozenCommit,
    network: deploymentManifest.network,
    publicWrites: deploymentManifest.statuses["PUBLIC WRITES"],
    settlementEvidence: deploymentManifest.statuses["MORDANT SETTLEMENT"],
  };

  return (
    <ProductShell active="protocol">
      <ProtocolOperations artifactContext={artifactContext} />
    </ProductShell>
  );
}
