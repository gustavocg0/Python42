"""Error-envelope exception handlers (contract §1/§2).

Every non-2xx body is the stable envelope; no stack traces ever reach a
client. `Retry-After` is emitted BOTH as a header and as
`error.retry_after_seconds` (ratified agent behavior reads either).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from soc_entitlements import EntitlementsUnavailable
from soc_schemas import ApiError, ErrorCode, error_envelope

logger = logging.getLogger(__name__)


def _render(
    status_code: int,
    code: ErrorCode,
    message: str,
    *,
    details: dict | None = None,
    retry_after_seconds: int | None = None,
) -> JSONResponse:
    envelope = error_envelope(
        code, message, details=details, retry_after_seconds=retry_after_seconds
    )
    headers = {}
    if retry_after_seconds is not None:
        headers["Retry-After"] = str(retry_after_seconds)
    return JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(exclude_none=True),
        headers=headers,
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _render(
            exc.status_code,
            exc.code,
            exc.message,
            details=exc.details,
            retry_after_seconds=exc.retry_after_seconds,
        )

    @app.exception_handler(EntitlementsUnavailable)
    async def _entitlements_unavailable(
        request: Request, exc: EntitlementsUnavailable
    ) -> JSONResponse:
        return _render(
            503,
            ErrorCode.ENTITLEMENTS_UNAVAILABLE,
            "Entitlements are temporarily unavailable; retry with backoff.",
            retry_after_seconds=30,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted(
            {".".join(str(loc) for loc in err.get("loc", []) if loc != "body") for err in
             exc.errors()}
        )
        return _render(
            400,
            ErrorCode.VALIDATION_ERROR,
            "Request validation failed.",
            details={"fields": fields[:50]},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        # Ratified taxonomy: 500 INTERNAL_ERROR — never SERVICE_UNAVAILABLE
        # (that code means fail-closed dependency denial). Agents treat any
        # 5xx as buffer-and-retry (AC-66/68).
        return _render(500, ErrorCode.INTERNAL_ERROR, "Internal error.")
