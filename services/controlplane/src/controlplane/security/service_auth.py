"""Internal-API service authentication (design §5.1 item 2, SEC-40).

HMAC-signed short-lived service tokens (`Authorization: Bearer
v1.<service>.<expires>.<sig>`), verified with soc_entitlements.tokens against
the per-service keys from the secrets store (env `CP_SVC_KEY_<SERVICE>`).

Operator-facing mutations (plan change, abuse freeze) additionally require an
operator identity claim in `X-Operator-Id`, recorded in the audit entry — no
anonymous plan changes (SEC-40).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Request

from soc_entitlements import ServiceTokenError, verify_service_token
from soc_schemas.errors import ApiError, ErrorCode

logger = logging.getLogger(__name__)

OPERATOR_HEADER = "X-Operator-Id"
_BEARER_PREFIX = "Bearer "


@dataclass(frozen=True, slots=True)
class ServiceCaller:
    service_name: str
    operator_id: str | None


def require_service_auth(*, operator_required: bool = False):
    """FastAPI dependency for /internal/v1 routes. Fails closed on ANY token error."""

    async def dependency(request: Request) -> ServiceCaller:
        services = request.app.state.services
        header = request.headers.get("Authorization", "")
        if not header.startswith(_BEARER_PREFIX):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "Service authentication required.")
        token = header[len(_BEARER_PREFIX) :].strip()
        try:
            service_name = verify_service_token(
                token, keys=services.settings.inbound_service_keys
            )
        except ServiceTokenError as exc:
            # Uniform rejection; the reason is logged server-side only.
            logger.warning(
                "internal service auth rejected",
                extra={"path": request.url.path, "reason": type(exc).__name__},
            )
            raise ApiError(
                ErrorCode.AUTH_REQUIRED, "Service authentication required."
            ) from None

        operator_id: str | None = None
        if operator_required:
            operator_id = (request.headers.get(OPERATOR_HEADER) or "").strip()
            if not operator_id:
                raise ApiError(
                    ErrorCode.VALIDATION_ERROR,
                    "Operator identity required for this operation.",
                    details={"header": OPERATOR_HEADER},
                )
        return ServiceCaller(service_name=service_name, operator_id=operator_id)

    dependency.__soc_authz__ = {"service": True, "operator_required": operator_required}
    return dependency
