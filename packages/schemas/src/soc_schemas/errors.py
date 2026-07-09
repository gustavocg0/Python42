"""API error envelope + machine-readable error-code taxonomy.

Transcribed from docs/contracts/api-contracts.md §1 (envelope) and §2 (codes).
Every non-2xx response body is:
    {"error": {"code": "<TAXONOMY_CODE>", "message": "<human>",
               "details": {...}?, "retry_after_seconds": int?}}
Stable codes, no stack traces to clients.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorCode(enum.StrEnum):
    """Machine-readable error codes (api-contracts.md §2)."""

    # 400
    VALIDATION_ERROR = "VALIDATION_ERROR"
    PASSWORD_POLICY_VIOLATION = "PASSWORD_POLICY_VIOLATION"  # noqa: S105
    PASSWORD_BREACHED = "PASSWORD_BREACHED"  # noqa: S105
    SIGNUP_CHALLENGE_REQUIRED = "SIGNUP_CHALLENGE_REQUIRED"
    # 401
    AUTH_REQUIRED = "AUTH_REQUIRED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    INGEST_KEY_INVALID = "INGEST_KEY_INVALID"
    INGEST_KEY_REVOKED = "INGEST_KEY_REVOKED"
    DEVICE_IDENTITY_INVALID = "DEVICE_IDENTITY_INVALID"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    # 402
    TRIAL_EXPIRED = "TRIAL_EXPIRED"
    # 403
    FORBIDDEN_ROLE = "FORBIDDEN_ROLE"
    TENANT_FROZEN = "TENANT_FROZEN"
    ENTITLEMENT_DENIED = "ENTITLEMENT_DENIED"
    QUOTA_EXCEEDED_DEEP_INVESTIGATION = "QUOTA_EXCEEDED_DEEP_INVESTIGATION"
    ENROLLMENT_TOKEN_REVOKED = "ENROLLMENT_TOKEN_REVOKED"  # noqa: S105
    ENROLLMENT_TOKEN_INVALID = "ENROLLMENT_TOKEN_INVALID"  # noqa: S105
    ENDPOINT_CAP_REACHED = "ENDPOINT_CAP_REACHED"
    # 404
    NOT_FOUND = "NOT_FOUND"
    # 409
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    DOMAIN_ALREADY_REGISTERED = "DOMAIN_ALREADY_REGISTERED"
    VERIFICATION_ALREADY_USED = "VERIFICATION_ALREADY_USED"
    # 410
    VERIFICATION_EXPIRED = "VERIFICATION_EXPIRED"
    ENROLLMENT_TOKEN_EXPIRED = "ENROLLMENT_TOKEN_EXPIRED"  # noqa: S105
    # 413
    BATCH_TOO_LARGE = "BATCH_TOO_LARGE"
    # 429
    INGEST_QUOTA_EXCEEDED = "INGEST_QUOTA_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    # 500 (Architect-ratified 2026-07-08): unhandled server error — never
    # SERVICE_UNAVAILABLE, which signals fail-closed dependency denial.
    INTERNAL_ERROR = "INTERNAL_ERROR"
    # 503
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    ENTITLEMENTS_UNAVAILABLE = "ENTITLEMENTS_UNAVAILABLE"


ERROR_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.VALIDATION_ERROR: 400,
    ErrorCode.PASSWORD_POLICY_VIOLATION: 400,
    ErrorCode.PASSWORD_BREACHED: 400,
    ErrorCode.SIGNUP_CHALLENGE_REQUIRED: 400,
    ErrorCode.AUTH_REQUIRED: 401,
    ErrorCode.SESSION_EXPIRED: 401,
    ErrorCode.INGEST_KEY_INVALID: 401,
    ErrorCode.INGEST_KEY_REVOKED: 401,
    ErrorCode.DEVICE_IDENTITY_INVALID: 401,
    ErrorCode.DEVICE_REVOKED: 401,
    ErrorCode.TRIAL_EXPIRED: 402,
    ErrorCode.FORBIDDEN_ROLE: 403,
    ErrorCode.TENANT_FROZEN: 403,
    ErrorCode.ENTITLEMENT_DENIED: 403,
    ErrorCode.QUOTA_EXCEEDED_DEEP_INVESTIGATION: 403,
    ErrorCode.ENROLLMENT_TOKEN_REVOKED: 403,
    ErrorCode.ENROLLMENT_TOKEN_INVALID: 403,
    ErrorCode.ENDPOINT_CAP_REACHED: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.INVALID_STATE_TRANSITION: 409,
    ErrorCode.DOMAIN_ALREADY_REGISTERED: 409,
    ErrorCode.VERIFICATION_ALREADY_USED: 409,
    ErrorCode.VERIFICATION_EXPIRED: 410,
    ErrorCode.ENROLLMENT_TOKEN_EXPIRED: 410,
    ErrorCode.BATCH_TOO_LARGE: 413,
    ErrorCode.INGEST_QUOTA_EXCEEDED: 429,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.INTERNAL_ERROR: 500,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
    ErrorCode.ENTITLEMENTS_UNAVAILABLE: 503,
}
"""Default HTTP status for each code (api-contracts.md §2)."""


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ErrorCode
    message: str
    details: dict[str, Any] | None = None
    retry_after_seconds: int | None = Field(default=None, ge=0)


class ErrorEnvelope(BaseModel):
    """The wire shape of every non-2xx response (api-contracts.md §1)."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


def error_envelope(
    code: ErrorCode,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    retry_after_seconds: int | None = None,
) -> ErrorEnvelope:
    return ErrorEnvelope(
        error=ErrorBody(
            code=code,
            message=message,
            details=details,
            retry_after_seconds=retry_after_seconds,
        )
    )


class ApiError(Exception):
    """Framework-agnostic structured API error.

    Services register a single exception handler that renders
    `exc.envelope()` with `exc.status_code` (and a `Retry-After` header when
    `retry_after_seconds` is set). Keeps stable codes and prevents stack
    traces from reaching clients.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status_code = status_code if status_code is not None else ERROR_HTTP_STATUS[code]
        self.details = details
        self.retry_after_seconds = retry_after_seconds

    def envelope(self) -> ErrorEnvelope:
        return error_envelope(
            self.code,
            self.message,
            details=self.details,
            retry_after_seconds=self.retry_after_seconds,
        )
