import type { NextConfig } from "next";

// The dev overlay sits on top of the design study and lands in every screenshot.
const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  turbopack: {
    root: process.cwd(),
  },
  devIndicators: false,
};

export default nextConfig;
