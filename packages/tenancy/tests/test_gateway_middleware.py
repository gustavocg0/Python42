"""SEC-14 negative/positive tests for GatewayAuthMiddleware."""

import json
import secrets

import pytest

from soc_tenancy import GatewayAuthMiddleware

SECRET = secrets.token_hex(32)  # 64 chars >= 32 bytes


class EchoApp:
    """Records the scope it received; replies 200."""

    def __init__(self):
        self.last_scope = None

    async def __call__(self, scope, receive, send):
        self.last_scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def call(app, path, headers):
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def header_names(scope):
    return [name.decode().lower() for name, _ in scope["headers"]]


async def test_agent_route_without_gateway_auth_is_401():
    inner = EchoApp()
    mw = GatewayAuthMiddleware(inner, secret=SECRET)
    sent = await call(mw, "/v1/agent/events", [("X-Device-Id", "dev_1")])
    assert sent[0]["status"] == 401
    body = json.loads(sent[1]["body"])
    assert body["error"]["code"] == "AUTH_REQUIRED"
    assert inner.last_scope is None  # app never reached — fail closed


async def test_identity_header_injection_discarded_on_non_agent_routes():
    inner = EchoApp()
    mw = GatewayAuthMiddleware(inner, secret=SECRET)
    sent = await call(
        mw,
        "/v1/ingest/events",
        [
            ("X-Device-Id", "dev_evil"),
            ("X-Device-Tenant", "11111111-1111-4111-8111-111111111111"),
            ("X-Client-Cert-Serial", "01"),
            ("X-Ingest-Key", "ik_1.secret"),
        ],
    )
    assert sent[0]["status"] == 200
    names = header_names(inner.last_scope)
    assert "x-device-id" not in names
    assert "x-device-tenant" not in names
    assert "x-client-cert-serial" not in names
    assert "x-ingest-key" in names  # non-identity headers untouched
    assert inner.last_scope["state"]["gateway_authenticated"] is False


async def test_valid_gateway_auth_passes_identity_headers():
    inner = EchoApp()
    mw = GatewayAuthMiddleware(inner, secret=SECRET)
    sent = await call(
        mw,
        "/v1/agent/events",
        [
            ("X-Gateway-Auth", SECRET),
            ("X-Device-Id", "dev_1"),
            ("X-Device-Tenant", "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f"),
        ],
    )
    assert sent[0]["status"] == 200
    names = header_names(inner.last_scope)
    assert "x-device-id" in names
    assert "x-device-tenant" in names
    assert "x-gateway-auth" not in names  # secret never forwarded downstream
    assert inner.last_scope["state"]["gateway_authenticated"] is True


async def test_wrong_secret_rejected_on_agent_route():
    inner = EchoApp()
    mw = GatewayAuthMiddleware(inner, secret=SECRET)
    sent = await call(
        mw, "/v1/agent/heartbeat", [("X-Gateway-Auth", "x" * 64), ("X-Device-Id", "dev_1")]
    )
    assert sent[0]["status"] == 401
    assert inner.last_scope is None


def test_short_secret_refused_at_construction():
    with pytest.raises(ValueError):
        GatewayAuthMiddleware(EchoApp(), secret="too-short")
