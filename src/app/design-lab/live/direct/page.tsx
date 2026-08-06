import { notFound } from "next/navigation";

import { DirectExecutionHarness } from "./direct-execution-harness";

export default function DirectExecutionHarnessPage() {
  if (process.env.NODE_ENV === "production") notFound();
  return <DirectExecutionHarness />;
}
