"""Exception -> error-envelope wiring (contract §1/§2; no stack traces to clients)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from soc_schemas.errors import ApiError, ErrorCode, error_envelope

logger = logging.getLogger(__name__)


def _render(envelope: Any, status_code: int, retry_after: int | None = None) -> JSONResponse:
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(mode="json", exclude_none=True),
        headers=headers,
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _render(exc.envelope(), exc.status_code, exc.retry_after_seconds)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field list only — never echo submitted values (they may be secrets).
        fields = [
            {
                "loc": ".".join(str(part) for part in err.get("loc", ())),
                "msg": err.get("msg", "invalid"),
            }
            for err in exc.errors()
        ]
        envelope = error_envelope(
            ErrorCode.VALIDATION_ERROR,
            "Request validation failed.",
            details={"fields": fields},
        )
        return _render(envelope, 400)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Logged server-side with trace correlation; the client gets a stable
        # code and nothing else. INTERNAL_ERROR per the Architect-ratified §2
        # row (2026-07-08) — SERVICE_UNAVAILABLE stays reserved for fail-closed
        # dependency denials with retry semantics.
        logger.exception("unhandled error", extra={"path": request.url.path})
        envelope = error_envelope(ErrorCode.INTERNAL_ERROR, "Internal server error.")
        return _render(envelope, 500)
