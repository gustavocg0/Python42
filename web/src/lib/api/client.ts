/**
 * Core fetch wrapper for both API origins (design §2: controlplane-api for
 * signup/auth/entitlements, dataplane-api for everything else).
 *
 * - Cookie auth: credentials 'include'; session cookie is HttpOnly (SEC-2) —
 *   auth state is discovered via GET /v1/me, never stored client-side.
 * - CSRF (SEC-3, contract §1): double-submit — mutating requests echo the
 *   readable `csrf_token` cookie in the `X-CSRF-Token` header.
 * - Errors: contract error envelope surfaced as a typed ApiError; central
 *   handlers for 401 (login redirect) and 403 TENANT_FROZEN (frozen banner).
 */
import { ApiError, type ErrorEnvelope } from "./errors";

export type Plane = "controlplane" | "dataplane";

const DEFAULT_BASE: Record<Plane, string> = {
  controlplane: "http://localhost:8001",
  dataplane: "http://localhost:8000",
};

export function baseUrl(plane: Plane): string {
  const configured =
    plane === "controlplane"
      ? process.env.NEXT_PUBLIC_CONTROLPLANE_URL
      : process.env.NEXT_PUBLIC_DATAPLANE_URL;
  return (configured ?? DEFAULT_BASE[plane]).replace(/\/+$/, "");
}

/** Cookie the backend must set (non-HttpOnly) at session creation. */
export const CSRF_COOKIE_NAME = "csrf_token";
export const CSRF_HEADER_NAME = "X-CSRF-Token";

export function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const c = part.trim();
    if (c.startsWith(prefix)) {
      return decodeURIComponent(c.slice(prefix.length));
    }
  }
  return null;
}

export interface ApiHandlers {
  /** 401 AUTH_REQUIRED / SESSION_EXPIRED on console calls. */
  onUnauthorized?: (error: ApiError) => void;
  /** 403 TENANT_FROZEN — cause 'trial' | 'abuse' (SEC-39). */
  onTenantFrozen?: (cause: "trial" | "abuse" | undefined, error: ApiError) => void;
}

let handlers: ApiHandlers = {};

export function setApiHandlers(next: ApiHandlers): void {
  handlers = next;
}

export type QueryValue = string | number | boolean | undefined | null | string[];
export type QueryParams = Record<string, QueryValue>;

export function buildUrl(plane: Plane, path: string, query?: QueryParams): string {
  const url = new URL(baseUrl(plane) + path);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const v of value) url.searchParams.append(key, v);
      } else {
        url.searchParams.append(key, String(value));
      }
    }
  }
  return url.toString();
}

export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface RequestOptions {
  body?: unknown;
  query?: QueryParams;
  signal?: AbortSignal;
}

export async function request<T>(
  plane: Plane,
  method: Method,
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const token = readCookie(CSRF_COOKIE_NAME);
    if (token) headers[CSRF_HEADER_NAME] = token;
  }

  const response = await fetch(buildUrl(plane, path, options.query), {
    method,
    headers,
    credentials: "include",
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
  });

  if (response.status === 204) return undefined as T;

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const envelope = payload as ErrorEnvelope | null;
    const code = envelope?.error?.code ?? "UNKNOWN_ERROR";
    const message = envelope?.error?.message ?? response.statusText ?? "Request failed";
    const headerRetry = response.headers.get("Retry-After");
    const retryAfter =
      envelope?.error?.retry_after_seconds ??
      (headerRetry !== null && !Number.isNaN(Number(headerRetry))
        ? Number(headerRetry)
        : undefined);
    const error = new ApiError(
      response.status,
      code,
      message,
      envelope?.error?.details,
      retryAfter,
    );

    if (
      response.status === 401 &&
      (code === "AUTH_REQUIRED" || code === "SESSION_EXPIRED")
    ) {
      handlers.onUnauthorized?.(error);
    }
    if (response.status === 403 && code === "TENANT_FROZEN") {
      const cause = error.details?.cause;
      handlers.onTenantFrozen?.(
        cause === "abuse" || cause === "trial" ? cause : undefined,
        error,
      );
    }
    throw error;
  }

  return payload as T;
}

export const http = {
  get: <T>(plane: Plane, path: string, query?: QueryParams, signal?: AbortSignal) =>
    request<T>(plane, "GET", path, { query, signal }),
  post: <T>(plane: Plane, path: string, body?: unknown, query?: QueryParams) =>
    request<T>(plane, "POST", path, { body, query }),
  put: <T>(plane: Plane, path: string, body?: unknown) =>
    request<T>(plane, "PUT", path, { body }),
  patch: <T>(plane: Plane, path: string, body?: unknown) =>
    request<T>(plane, "PATCH", path, { body }),
  delete: <T = void>(plane: Plane, path: string) =>
    request<T>(plane, "DELETE", path),
};
