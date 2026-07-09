import { NextResponse, type NextRequest } from "next/server";

/**
 * Per-request CSP with a script nonce (SEC-31: default-src 'self', no inline
 * script; SEC-50 console hardening). Next.js picks up the nonce from the
 * incoming Content-Security-Policy request header for its own script tags.
 * connect-src allows exactly the two API origins (design §2).
 */
export function middleware(request: NextRequest) {
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = btoa(String.fromCharCode(...nonceBytes));

  const controlplane = process.env.NEXT_PUBLIC_CONTROLPLANE_URL ?? "http://localhost:8001";
  const dataplane = process.env.NEXT_PUBLIC_DATAPLANE_URL ?? "http://localhost:8000";

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src 'self' ${controlplane} ${dataplane}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    // All paths except static assets.
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
