import { notFound } from "next/navigation";

import { DirectExecutionHarness } from "./direct-execution-harness";

const CASE_CODE = /^[0-9A-HJKMNP-TV-Z]{16}$/u;

export default async function DirectExecutionHarnessPage({ searchParams }: {
  readonly searchParams: Promise<Readonly<Record<string, string | string[] | undefined>>>;
}) {
  if (process.env.NODE_ENV === "production") notFound();
  const query = await searchParams;
  const rawCaseCode = typeof query.caseCode === "string" ? query.caseCode : null;
  const initialCaseCode = Object.keys(query).length === 1 && rawCaseCode !== null && CASE_CODE.test(rawCaseCode)
    ? rawCaseCode
    : null;
  return <DirectExecutionHarness initialCaseCode={initialCaseCode} />;
}
