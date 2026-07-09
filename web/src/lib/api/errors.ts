/**
 * Error envelope + machine-readable taxonomy per docs/contracts/api-contracts.md §1–2.
 * Every non-2xx response is `{"error": {code, message, details?, retry_after_seconds?}}`.
 */

export const ERROR_CODES = [
  "VALIDATION_ERROR",
  "PASSWORD_POLICY_VIOLATION",
  "PASSWORD_BREACHED",
  "SIGNUP_CHALLENGE_REQUIRED",
  "AUTH_REQUIRED",
  "SESSION_EXPIRED",
  "INGEST_KEY_INVALID",
  "INGEST_KEY_REVOKED",
  "DEVICE_IDENTITY_INVALID",
  "DEVICE_REVOKED",
  "TRIAL_EXPIRED",
  "FORBIDDEN_ROLE",
  "TENANT_FROZEN",
  "ENTITLEMENT_DENIED",
  "QUOTA_EXCEEDED_DEEP_INVESTIGATION",
  "NOT_FOUND",
  "INVALID_STATE_TRANSITION",
  "DOMAIN_ALREADY_REGISTERED",
  "VERIFICATION_ALREADY_USED",
  "VERIFICATION_EXPIRED",
  "ENROLLMENT_TOKEN_EXPIRED",
  "ENROLLMENT_TOKEN_REVOKED",
  "ENROLLMENT_TOKEN_INVALID",
  "ENDPOINT_CAP_REACHED",
  "BATCH_TOO_LARGE",
  "INGEST_QUOTA_EXCEEDED",
  "RATE_LIMITED",
  "SERVICE_UNAVAILABLE",
  "ENTITLEMENTS_UNAVAILABLE",
] as const;

export type KnownErrorCode = (typeof ERROR_CODES)[number];
/** Servers may add codes; treat unknown codes as opaque strings. */
export type ErrorCode = KnownErrorCode | (string & {});

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    details?: Record<string, unknown>;
    retry_after_seconds?: number;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly details: Record<string, unknown> | undefined;
  readonly retryAfterSeconds: number | undefined;

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    details?: Record<string, unknown>,
    retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** Plain-language messages for the P1 persona (non-security IT generalist). */
export function friendlyMessage(e: unknown): string {
  if (!isApiError(e)) {
    return e instanceof Error && e.message
      ? e.message
      : "Something went wrong. Please try again.";
  }
  switch (e.code) {
    case "TENANT_FROZEN":
      return e.details?.cause === "abuse"
        ? "This account is temporarily frozen. Changes are disabled — contact support."
        : "Your trial has ended, so the console is read-only. Data is still viewable.";
    case "TRIAL_EXPIRED":
      return "Your trial has ended. Upgrade to keep sending data.";
    case "FORBIDDEN_ROLE":
      return "Your role does not allow this action. Ask a tenant admin.";
    case "ENTITLEMENT_DENIED":
      return "This feature is not included in your current plan.";
    case "QUOTA_EXCEEDED_DEEP_INVESTIGATION":
      return "You have used all deep investigations for today.";
    case "RATE_LIMITED":
      return e.retryAfterSeconds
        ? `Too many attempts. Try again in about ${e.retryAfterSeconds} seconds.`
        : "Too many attempts. Please wait a moment and try again.";
    case "INVALID_STATE_TRANSITION":
      return "That alert changed in the meantime. Refresh and try again.";
    case "NOT_FOUND":
      return "That item does not exist (or is no longer available).";
    case "SESSION_EXPIRED":
    case "AUTH_REQUIRED":
      return "Your session has ended. Please sign in again.";
    case "SERVICE_UNAVAILABLE":
    case "ENTITLEMENTS_UNAVAILABLE":
      return "The service is briefly unavailable. Please retry in a moment.";
    default:
      return e.message || "The request failed. Please try again.";
  }
}
