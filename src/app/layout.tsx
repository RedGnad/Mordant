import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans, Newsreader } from "next/font/google";
import localFont from "next/font/local";
import "./foundations.css";
import "./globals.css";
import "./instruments.css";
import "./surfaces.css";
import "./product-language.css";

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

const productFont = localFont({
  src: "./fonts/Chillax-Variable.woff2",
  variable: "--font-product",
  weight: "200 700",
  style: "normal",
  display: "swap",
  fallback: ["Arial", "sans-serif"],
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
      className={`${identityFont.variable} ${interfaceFont.variable} ${proofFont.variable} ${productFont.variable}`}
      data-scroll-behavior="smooth"
    >
      <body>{children}</body>
    </html>
  );
}
