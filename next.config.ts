import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The dev server paints its own indicator into the page, and an element
  // screenshot captures whatever overlays the element's box. It landed inside
  // the 360px surface and was frozen into admitted-360x800: a reference that
  // claimed to be the product was partly dev-server chrome. On the other two
  // viewports it also moved between capture passes, so no reference could be
  // agreed at all and the mobile regime had no coverage. Off for the visual
  // run only; ordinary `next dev` keeps its indicator.
  devIndicators: process.env.MORDANT_VISUAL_E2E === "1" ? false : undefined,
  async redirects() {
    return [
      {
        source: "/deal-room",
        destination: "/participant",
        permanent: true,
      },
    ];
  },
  turbopack: {
    root: process.cwd(),
  },
};

export default nextConfig;
