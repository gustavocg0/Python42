import type { Metadata } from "next";
import type { ReactNode } from "react";
import Providers from "@/components/Providers";
import "./globals.css";

// Per-request rendering so the CSP nonce from middleware applies (SEC-31/50).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: { default: "SOC Console", template: "%s — SOC Console" },
  description: "Self-serve security operations console",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
