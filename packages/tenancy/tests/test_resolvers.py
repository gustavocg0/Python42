import uuid

import pytest
from fastapi import Request

from soc_schemas.errors import ApiError, ErrorCode
from soc_tenancy import (
    GatewayDeviceTenantResolver,
    IngestKeyTenantResolver,
    ResolvedTenant,
    SessionTenantResolver,
    get_current_tenant,
    tenant_dependency,
)

TENANT = uuid.UUID("8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f")


def make_request(headers=None, cookies=None, state=None) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/assets",
        "headers": raw_headers,
        "query_string": b"",
        "state": dict(state or {}),
    }
    return Request(scope)


def session_tenant(session_id: str) -> ResolvedTenant:
    return ResolvedTenant(tenant_id=TENANT, principal_type="session", principal_id=session_id)


async def test_session_resolver_reads_cookie():
    async def lookup(session_id):
        assert session_id == "s-123"
        return session_tenant(session_id)

    resolver = SessionTenantResolver(lookup)
    resolved = await resolver.resolve(make_request(cookies={"sid": "s-123"}))
    assert resolved.tenant_id == TENANT


async def test_session_resolver_falls_through_without_cookie():
    async def lookup(_):
        raise AssertionError("must not be called")

    resolver = SessionTenantResolver(lookup)
    assert await resolver.resolve(make_request()) is None


async def test_ingest_key_resolver_reads_header():
    async def lookup(key):
        assert key == "ik_1.secret"
        return ResolvedTenant(tenant_id=TENANT, principal_type="ingest_key", principal_id="ik_1")

    resolver = IngestKeyTenantResolver(lookup)
    resolved = await resolver.resolve(make_request(headers={"X-Ingest-Key": "ik_1.secret"}))
    assert resolved.principal_type == "ingest_key"


async def test_device_resolver_requires_gateway_auth_flag():
    async def verify(tenant_id, device_id):
        raise AssertionError("must not be called without gateway auth")

    resolver = GatewayDeviceTenantResolver(verify)
    request = make_request(
        headers={"X-Device-Id": "dev_1", "X-Device-Tenant": str(TENANT)},
        state={"gateway_authenticated": False},
    )
    assert await resolver.resolve(request) is None


async def test_device_resolver_verifies_when_gateway_authenticated():
    async def verify(tenant_id, device_id):
        assert tenant_id == TENANT
        assert device_id == "dev_1"
        return ResolvedTenant(tenant_id=tenant_id, principal_type="device", principal_id=device_id)

    resolver = GatewayDeviceTenantResolver(verify)
    request = make_request(
        headers={"X-Device-Id": "dev_1", "X-Device-Tenant": str(TENANT)},
        state={"gateway_authenticated": True},
    )
    resolved = await resolver.resolve(request)
    assert resolved.principal_type == "device"


async def test_device_resolver_invalid_tenant_uuid_rejects():
    async def verify(tenant_id, device_id):
        raise AssertionError("unreachable")

    resolver = GatewayDeviceTenantResolver(verify)
    request = make_request(
        headers={"X-Device-Id": "dev_1", "X-Device-Tenant": "not-a-uuid"},
        state={"gateway_authenticated": True},
    )
    with pytest.raises(ApiError) as exc:
        await resolver.resolve(request)
    assert exc.value.code == ErrorCode.DEVICE_IDENTITY_INVALID


async def test_dependency_first_resolver_wins_and_sets_contextvar():
    async def session_lookup(sid):
        return session_tenant(sid)

    dep = tenant_dependency([SessionTenantResolver(session_lookup)])
    resolved = await dep(make_request(cookies={"sid": "s-1"}))
    assert resolved.tenant_id == TENANT
    assert get_current_tenant() == TENANT


async def test_dependency_fails_closed_with_no_match():
    async def lookup(_):
        return None

    dep = tenant_dependency([SessionTenantResolver(lookup)])
    with pytest.raises(ApiError) as exc:
        await dep(make_request(cookies={"sid": "s-1"}))
    assert exc.value.code == ErrorCode.AUTH_REQUIRED
    assert exc.value.status_code == 401


def test_dependency_requires_resolvers():
    with pytest.raises(ValueError):
        tenant_dependency([])
