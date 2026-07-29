import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans, Newsreader } from "next/font/google";
import "./foundations.css";
import "./globals.css";
import "./instruments.css";
import "./surfaces.css";

const identityFont = Newsreader({
  variable: "--font-identity",
  subsets: ["latin"],
  weight: "variable",
  axes: ["opsz"],
  display: "swap",
});

const interfaceFont = IBM_Plex_Sans({
  variable: "--font-interface",
  subsets: ["latin"],
  weight: "variable",
  display: "swap",
});

const proofFont = IBM_Plex_Mono({
  variable: "--font-proof",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "Mordant — programmable recourse",
    template: "%s · Mordant",
  },
  description: "Operational control, funded consequences, and verifiable evidence for tokenized receivables.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${identityFont.variable} ${interfaceFont.variable} ${proofFont.variable}`}
      data-scroll-behavior="smooth"
    >
      <body>{children}</body>
    </html>
  );
}
