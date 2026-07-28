import type { Metadata } from "next";
import "@fontsource-variable/manrope";
import "@fontsource/space-mono/400.css";
import "@fontsource/space-mono/700.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mordant: the programmable recourse layer for tokenized receivables",
  description:
    "When a tokenized receivable becomes ineligible after funding, Mordant turns a pre-funded"
    + " reserve into protection for the compliant investors carrying the exposure.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
