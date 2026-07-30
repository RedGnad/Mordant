import type { Metadata } from "next";

import { ProductShell } from "@/components/product-shell";
import { TransactionDrivenExperience } from "@/components/transaction-driven-experience";
import { TRANSACTION_DEMO_QUERY } from "@/lib/dealroom/living-demo";

export const metadata: Metadata = {
  title: "Deal workspace",
  description: "Monitor responsibilities, action windows, and evidence across Mordant receivable deals.",
};

export default async function WorkspacePage({
  searchParams,
}: {
  searchParams: Promise<{ demo?: string | string[] }>;
}) {
  const demo = process.env.NODE_ENV !== "production"
    && (await searchParams).demo === TRANSACTION_DEMO_QUERY;
  return (
    <ProductShell active="workspace" mode={demo ? "transaction-demo" : "executed-review"}>
      <TransactionDrivenExperience surface="workspace" mode={demo ? "live" : "review"} />
    </ProductShell>
  );
}
