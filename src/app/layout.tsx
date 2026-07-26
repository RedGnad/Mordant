import type { Metadata } from "next";
import "@fontsource-variable/manrope";
import "@fontsource/space-mono/400.css";
import "@fontsource/space-mono/700.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mordant — funded protection for tokenized invoices",
  description: "A conflicting pledge turns the originator reserve into protection for invoice holders.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
