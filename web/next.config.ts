import type { NextConfig } from "next";

/**
 * Security headers per threat model SEC-50 (nosniff, referrer policy,
 * frame-ancestors). The CSP itself (SEC-31: default-src 'self', nonce'd
 * scripts, no inline script) is set per-request in src/middleware.ts so the
 * nonce can be generated per response.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Self-contained production server for the container image
  // (ops/docker/web.Dockerfile copies .next/standalone). No effect on `next dev`.
  output: "standalone",
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-Frame-Options", value: "DENY" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
