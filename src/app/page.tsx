import type { Metadata } from "next";
import { DealWorkspace } from "@/components/deal-workspace";
import { ProductShell } from "@/components/product-shell";

export const metadata: Metadata = {
  title: "Deal workspace",
  description:
    "Monitor responsibilities, action windows, and evidence across Mordant synthetic receivable deals.",
};

export default function Home() {
  return (
    <ProductShell active="workspace">
      <DealWorkspace />
    </ProductShell>
  );
}
