import type { Metadata } from "next";

import { ProtectionExperience } from "@/components/protection-experience";
import { loadImportedProtectionEvidence } from "@/lib/protection/governed-fhe-product-server";

export const metadata: Metadata = {
  title: "Conflicting Pledge Protection",
  description: "Protect one Cleanverse receivable with private BGV matching and governed recourse evidence.",
};

export default function ProtectionPage() {
  const evidence = loadImportedProtectionEvidence("conflict");
  return (
    <ProtectionExperience
      initialEvidence={evidence}
      localExecutionAvailable={process.env.NODE_ENV !== "production" && process.env.MORDANT_LOCAL_EXECUTION_ENABLED === "1"}
    />
  );
}
