import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { GovernedRecourseExperiment } from "./governed-recourse-experiment";

export const metadata: Metadata = {
  title: "Governed recourse policy experiment",
  description: "Evidence-only design-lab proof for pre-bound institutional recourse policy.",
  robots: { index: false, follow: false, nocache: true },
};

export default function GovernedRecoursePolicyExperimentPage() {
  if (process.env.NODE_ENV === "production") notFound();
  return <GovernedRecourseExperiment />;
}
