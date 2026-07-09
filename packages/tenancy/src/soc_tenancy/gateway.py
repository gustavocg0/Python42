"""Gateway-auth middleware primitive (SEC-14 / B-3, design §5 + §5.1 item 1).

Pure ASGI middleware for dataplane-api:
1. Constant-time compare of `X-Gateway-Auth` against the configured
   per-deployment 256-bit secret.
2. Requests WITHOUT valid gateway auth: all reserved identity headers
   (`X-Device-Id`, `X-Device-Tenant`, `X-Client-Cert-*`) are DISCARDED before
   the app sees them; agent routes are rejected 401 (fail closed) with the
   standard error envelope.
3. Requests WITH valid gateway auth: identity headers pass through (they were
   set by nginx from the verified client cert); the `X-Gateway-Auth` header
   itself is removed so it never reaches handlers/logs.
4. `scope["state"]["gateway_authenticated"]` is set for downstream resolvers
   (GatewayDeviceTenantResolver only trusts identity headers when True).
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence

from soc_schemas.errors import ErrorCode, error_envelope

GATEWAY_AUTH_HEADER = "x-gateway-auth"
IDENTITY_HEADERS: tuple[str, ...] = ("x-device-id", "x-device-tenant")
RESERVED_IDENTITY_HEADER_PREFIXES: tuple[str, ...] = ("x-client-cert-",)
GATEWAY_AUTHENTICATED_STATE_KEY = "gateway_authenticated"

_MIN_SECRET_BYTES = 32  # 256 bits


def _is_reserved_identity_header(name: str) -> bool:
    return name in IDENTITY_HEADERS or any(
        name.startswith(prefix) for prefix in RESERVED_IDENTITY_HEADER_PREFIXES
    )


class GatewayAuthMiddleware:
    """ASGI middleware enforcing the gateway->dataplane trust hop (SEC-14)."""

    def __init__(
        self,
        app,
        *,
        secret: str | bytes,
        agent_route_prefixes: Sequence[str] = ("/v1/agent",),
    ) -> None:
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(secret_bytes) < _MIN_SECRET_BYTES:
            raise ValueError(
                f"gateway auth secret must be at least {_MIN_SECRET_BYTES} bytes (256-bit)"
            )
        self._app = app
        self._secret = secret_bytes
        self._agent_route_prefixes = tuple(agent_route_prefixes)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        presented: bytes | None = None
        filtered_headers: list[tuple[bytes, bytes]] = []
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            if name == GATEWAY_AUTH_HEADER:
                presented = raw_value
                continue  # never forward the secret downstream
            filtered_headers.append((raw_name, raw_value))

        authenticated = presented is not None and hmac.compare_digest(presented, self._secret)

        if not authenticated:
            # SEC-14 (3)/(4): discard identity headers from unauthenticated hops...
            filtered_headers = [
                (n, v)
                for n, v in filtered_headers
                if not _is_reserved_identity_header(n.decode("latin-1").lower())
            ]
            # ...and fail closed on agent routes.
            path = scope.get("path", "")
            if any(path.startswith(prefix) for prefix in self._agent_route_prefixes):
                await self._reject(send)
                return

        scope = dict(scope)
        scope["headers"] = filtered_headers
        state = scope.setdefault("state", {})
        state[GATEWAY_AUTHENTICATED_STATE_KEY] = authenticated
        await self._app(scope, receive, send)

    @staticmethod
    async def _reject(send) -> None:
        body = (
            error_envelope(
                ErrorCode.AUTH_REQUIRED,
                "Agent routes require the authenticated ingest gateway.",
            )
            .model_dump_json(exclude_none=True)
            .encode("utf-8")
        )
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("latin-1")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
