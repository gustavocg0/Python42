import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request, setApiHandlers, buildUrl } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";

function mockResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "status",
    headers: new Headers(headers),
    json: async () => body,
  } as unknown as Response;
}

describe("api client", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    // clear cookies
    document.cookie = "csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setApiHandlers({});
  });

  it("builds URLs with repeatable query params and skips empty values", () => {
    const url = buildUrl("dataplane", "/v1/alerts", {
      state: ["new", "acknowledged"],
      severity: undefined,
      host: "",
      sort: "-priority",
      limit: 50,
    });
    expect(url).toContain("/v1/alerts?");
    expect(url).toContain("state=new");
    expect(url).toContain("state=acknowledged");
    expect(url).toContain("sort=-priority");
    expect(url).toContain("limit=50");
    expect(url).not.toContain("severity=");
    expect(url).not.toContain("host=");
  });

  it("sends credentials and no CSRF header on GET", async () => {
    fetchMock.mockResolvedValue(mockResponse(200, { items: [] }));
    await request("dataplane", "GET", "/v1/alerts");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
    expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("echoes the csrf_token cookie as X-CSRF-Token on mutating requests (SEC-3 double-submit)", async () => {
    document.cookie = "csrf_token=tok-123";
    fetchMock.mockResolvedValue(mockResponse(200, {}));
    await request("dataplane", "POST", "/v1/alerts/al_1/acknowledge");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok-123");
  });

  it("maps the error envelope to a typed ApiError with machine code and details", async () => {
    fetchMock.mockResolvedValue(
      mockResponse(403, {
        error: {
          code: "QUOTA_EXCEEDED_DEEP_INVESTIGATION",
          message: "quota exhausted",
          details: { remaining: 0, resets_at: "2026-07-09T00:00:00Z" },
        },
      }),
    );
    const err = await request("dataplane", "POST", "/v1/alerts/al_1/deep-investigation").catch(
      (e) => e as ApiError,
    );
    expect(err).toBeInstanceOf(ApiError);
    const apiErr = err as ApiError;
    expect(apiErr.status).toBe(403);
    expect(apiErr.code).toBe("QUOTA_EXCEEDED_DEEP_INVESTIGATION");
    expect(apiErr.details?.resets_at).toBe("2026-07-09T00:00:00Z");
  });

  it("surfaces retry_after_seconds and falls back to the Retry-After header", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(429, {
        error: { code: "RATE_LIMITED", message: "slow down", retry_after_seconds: 30 },
      }),
    );
    const err1 = await request("controlplane", "POST", "/v1/auth/login", {
      body: {},
    }).catch((e) => e as ApiError);
    expect((err1 as ApiError).retryAfterSeconds).toBe(30);

    fetchMock.mockResolvedValueOnce(
      mockResponse(
        429,
        { error: { code: "RATE_LIMITED", message: "slow down" } },
        { "Retry-After": "45" },
      ),
    );
    const err2 = await request("controlplane", "POST", "/v1/auth/login", {
      body: {},
    }).catch((e) => e as ApiError);
    expect((err2 as ApiError).retryAfterSeconds).toBe(45);
  });

  it("invokes the central 401 handler for AUTH_REQUIRED/SESSION_EXPIRED", async () => {
    const onUnauthorized = vi.fn();
    setApiHandlers({ onUnauthorized });
    fetchMock.mockResolvedValue(
      mockResponse(401, { error: { code: "SESSION_EXPIRED", message: "expired" } }),
    );
    await request("dataplane", "GET", "/v1/alerts").catch(() => undefined);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("invokes the frozen handler with the cause on 403 TENANT_FROZEN", async () => {
    const onTenantFrozen = vi.fn();
    setApiHandlers({ onTenantFrozen });
    fetchMock.mockResolvedValue(
      mockResponse(403, {
        error: {
          code: "TENANT_FROZEN",
          message: "frozen",
          details: { cause: "abuse" },
        },
      }),
    );
    await request("dataplane", "POST", "/v1/ingest-keys", { body: { name: "x" } }).catch(
      () => undefined,
    );
    expect(onTenantFrozen).toHaveBeenCalledWith("abuse", expect.any(ApiError));
  });

  it("returns undefined for 204 responses", async () => {
    fetchMock.mockResolvedValue(mockResponse(204, null));
    const result = await request("controlplane", "POST", "/v1/auth/logout");
    expect(result).toBeUndefined();
  });
});
