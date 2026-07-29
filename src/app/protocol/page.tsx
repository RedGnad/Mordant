import type { Metadata } from "next";
import { ProductShell } from "@/components/product-shell";
import { ProtocolOperations } from "@/components/protocol-operations";

export const metadata: Metadata = {
  title: "Protocol operations",
  description:
    "Inspect execution gates, state transitions, on-chain evidence, and recovery paths in the Mordant prototype.",
};

export default function ProtocolPage() {
  return (
    <ProductShell active="protocol">
      <ProtocolOperations />
    </ProductShell>
  );
}
