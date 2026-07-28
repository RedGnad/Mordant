import type { Metadata } from "next";

import { DealDetailStudy } from "@/components/design-lab/deal-detail-study";
import "./aero.css";

export const metadata: Metadata = {
  title: "Aero Fiduciary visual direction study",
  description:
    "Three visual directions for one Mordant screen, using fork rehearsal data. A design study,"
    + " not a live deployment and not the final UI.",
  robots: { index: false, follow: false },
};

export default function AeroFiduciaryStudyPage() {
  return <DealDetailStudy />;
}
