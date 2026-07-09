"""Enrollment & agent lifecycle (contract §10 as ratified 2026-07-08, ADR-0006).

- Console: enrollment-token CRUD (show-once wire token, sha256 at rest,
  SEC-7/13) and device revocation (SEC-10 delete-on-change cache).
- Agent: enroll (token-authenticated body, plain TLS via the gateway — no
  client cert yet; SEC-12 rate limits), heartbeat, renew-credential
  (ratified body: certificate_pem / ca_chain_pem / certificate_expires_at).

Identity is assigned entirely server-side (SEC-8): CSRs are accepted with an
EMPTY subject; CN=<device_id> and URI SAN urn:platform:tenant:{t}:device:{d}
are set by the CA module.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, Response

from dataplane.api.deps import (
    DeviceIdentity,
    agent_auth,
    enrollment_route,
    get_resources,
    not_found,
    session_auth,
)
from dataplane.api.models import (
    EnrollmentTokenCreateRequest,
    EnrollRequest,
    HeartbeatRequest,
    RenewRequest,
)
from dataplane.core.ca import CsrError
from dataplane.core.db import to_jsonb
from dataplane.core.ids import new_id
from dataplane.core.onboarding import signal_step
from dataplane.core.seclog import log_security_event
from dataplane.core.sessions import SessionPrincipal
from dataplane.core.tokens import (
    MalformedCredential,
    mint_secret,
    parse_credential,
    secret_matches,
)
from soc_audit import Actor, Target, write_audit
from soc_pipeline.streams import STREAM_ASSET_OBSERVATIONS
from soc_schemas import ApiError, ErrorCode, Host
from soc_tenancy import set_current_tenant

logger = logging.getLogger(__name__)
router = APIRouter()

_TOKEN_SQL = (
    "SELECT token_hash, expires_at, revoked_at "  # noqa: S105 - SQL, not a credential
    "FROM tenantdata.enrollment_tokens WHERE id = $1"
)
_BILLABLE_COUNT_SQL = (
    "SELECT count(*) FROM tenantdata.assets WHERE state = 'active' "
    "AND agent_status <> 'revoked' AND last_seen >= now() - make_interval(days => $1)"
)
_INSERT_ASSET_SQL = (
    "INSERT INTO tenantdata.assets "
    "(tenant_id, hostname, os_family, os_name, os_version, ip, mac, sources, "
    " agent_status, created_via, dedup_rule) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, ARRAY['agent'], 'enrolled', "
    "        'agent_enrollment', 'device_id_match') RETURNING id"
)
_INSERT_IDENTITY_SQL = (
    "INSERT INTO tenantdata.asset_identities (tenant_id, asset_id, source, identifier_type, value) "
    "VALUES ($1, $2, 'agent', 'device_id', $3)"
)
_INSERT_DEVICE_SQL = (
    "INSERT INTO tenantdata.devices "
    "(id, tenant_id, asset_id, status, cert_serial, cert_issued_at, cert_expires_at, "
    " public_key_fingerprint, enrollment_token_id, enrolled_ip, claimed_hostname, agent_version) "
    "VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9, $10, $11)"
)
_BUMP_TOKEN_SQL = (
    "UPDATE tenantdata.enrollment_tokens "  # noqa: S105 - SQL, not a credential
    "SET enrollment_count = enrollment_count + 1, "
    "last_enrollment_at = now() WHERE id = $1"
)
_HEARTBEAT_SQL = (
    "UPDATE tenantdata.devices SET last_heartbeat_at = now(), agent_version = $2, "
    "provider_status = $3::jsonb, updated_at = now() "
    "WHERE id = $1 AND status = 'active' RETURNING asset_id"
)
_HEARTBEAT_ASSET_SQL = (
    "UPDATE tenantdata.assets SET agent_status = 'healthy', last_seen = now(), "
    "updated_at = now() WHERE id = $1 AND agent_status <> 'revoked'"
)
_RENEW_SQL = (
    "UPDATE tenantdata.devices SET prev_cert_serial = cert_serial, "
    "prev_cert_rotated_at = now(), cert_serial = $2, cert_issued_at = $3, "
    "cert_expires_at = $4, public_key_fingerprint = $5, updated_at = now() "
    "WHERE id = $1 AND status = 'active' RETURNING prev_cert_serial"
)
_REVOKE_DEVICE_SQL = (
    "UPDATE tenantdata.devices SET status = 'revoked', revoked_at = now(), revoked_by = $2, "
    "updated_at = now() WHERE id = $1 AND status = 'active' RETURNING asset_id"
)
_DEVICE_EXISTS_SQL = "SELECT status, revoked_at FROM tenantdata.devices WHERE id = $1"
_REVOKE_ASSET_SQL = (
    "UPDATE tenantdata.assets SET agent_status = 'revoked', billable = false, "
    "updated_at = now() WHERE id = $1"
)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ------------------------------------------------- console: enrollment tokens
@router.post("/v1/enrollment-tokens", status_code=201)
async def create_enrollment_token(
    body: EnrollmentTokenCreateRequest,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    settings = resources.settings
    hours = body.expires_in_hours or settings.enrollment_token_default_expiry_hours
    expires_at = datetime.now(UTC) + timedelta(hours=hours)
    token_id = new_id("et")
    minted = mint_secret(token_id, principal.tenant_id)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        await conn.execute(
            "INSERT INTO tenantdata.enrollment_tokens "
            "(id, tenant_id, name, token_hash, expires_at, created_by) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            token_id,
            principal.tenant_id,
            body.name,
            minted.secret_hash,
            expires_at,
            principal.user_id,
        )
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="enrollment_token.create",
            target=Target(type="enrollment_token", id=token_id),
            after={"name": body.name, "expires_at": expires_at.isoformat()},
        )
    install_command = (
        "msiexec /i soc-agent.msi /qn "
        f'ENROLLMENT_TOKEN="{minted.wire_token}" '
        f'INGEST_URL="{settings.public_ingest_base_url}"'
    )
    return {
        "id": token_id,
        "name": body.name,
        "token": minted.wire_token,  # shown once (SEC-7)
        "expires_at": expires_at,
        "install_command": install_command,
    }


@router.get("/v1/enrollment-tokens")
async def list_enrollment_tokens(
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth())],
) -> dict[str, Any]:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        rows = await conn.fetch(
            "SELECT id, name, expires_at, revoked_at, enrollment_count, last_enrollment_at, "
            "created_at FROM tenantdata.enrollment_tokens ORDER BY created_at DESC"
        )
    items = [
        {
            "id": r["id"],
            "name": r["name"],
            "expires_at": r["expires_at"],
            "revoked_at": r["revoked_at"],
            "enrollment_count": r["enrollment_count"],
            "last_enrollment_at": r["last_enrollment_at"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return {"items": items, "next_cursor": None, "total_estimate": len(items)}


@router.delete("/v1/enrollment-tokens/{token_id}", status_code=204)
async def revoke_enrollment_token(
    token_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> Response:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        row = await conn.fetchrow(
            "UPDATE tenantdata.enrollment_tokens SET revoked_at = now(), revoked_by = $2 "
            "WHERE id = $1 AND revoked_at IS NULL RETURNING id",
            token_id,
            principal.user_id,
        )
        if row is None:
            not_found("enrollment_token", token_id, principal.tenant_id)
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="enrollment_token.revoke",
            target=Target(type="enrollment_token", id=token_id),
        )
    return Response(status_code=204)


# ------------------------------------------------------------- agent: enroll
def _enroll_rejected(reason: str, *, token_id: str | None, ip: str) -> None:
    """AC-58: every failed attempt is server-logged."""
    log_security_event("enroll_rejected", reason=reason, token_id=token_id, ip=ip)


@router.post(
    "/v1/agent/enroll",
    status_code=201,
    dependencies=[Depends(enrollment_route)],
)
async def enroll(body: EnrollRequest, request: Request) -> dict[str, Any]:
    resources = get_resources(request)
    settings = resources.settings
    ip = _client_ip(request)

    # SEC-12: per-IP rate limit before any token processing.
    await resources.quotas.check_rate_limit(
        f"rl:enroll:ip:{ip}", settings.enroll_rate_limit_per_ip_per_min
    )
    try:
        parsed = parse_credential(body.enrollment_token, expected_prefix="et_")
    except MalformedCredential:
        _enroll_rejected("ENROLLMENT_TOKEN_INVALID", token_id=None, ip=ip)
        raise ApiError(ErrorCode.ENROLLMENT_TOKEN_INVALID, "Enrollment token invalid.") from None
    tenant_id = parsed.tenant_id
    token_id = parsed.credential_id
    # SEC-12: per-token rate limit.
    await resources.quotas.check_rate_limit(
        f"rl:enroll:token:{tenant_id}:{token_id}", settings.enroll_rate_limit_per_token_per_min
    )
    set_current_tenant(tenant_id)

    # Token validation (RLS-scoped: unknown and foreign-tenant are identical).
    async with resources.db.tenant_transaction(tenant_id) as conn:
        token_row = await conn.fetchrow(_TOKEN_SQL, token_id)
    if token_row is None or not secret_matches(parsed.secret, token_row["token_hash"]):
        _enroll_rejected("ENROLLMENT_TOKEN_INVALID", token_id=token_id, ip=ip)
        raise ApiError(ErrorCode.ENROLLMENT_TOKEN_INVALID, "Enrollment token invalid.")
    if token_row["revoked_at"] is not None:
        _enroll_rejected("ENROLLMENT_TOKEN_REVOKED", token_id=token_id, ip=ip)
        raise ApiError(ErrorCode.ENROLLMENT_TOKEN_REVOKED, "Enrollment token revoked.")
    if token_row["expires_at"] <= datetime.now(UTC):
        _enroll_rejected("ENROLLMENT_TOKEN_EXPIRED", token_id=token_id, ip=ip)
        raise ApiError(ErrorCode.ENROLLMENT_TOKEN_EXPIRED, "Enrollment token expired.")

    # Abuse/trial freeze (SEC-39: enrollment rejected while frozen).
    try:
        await resources.status_stores.require_writes_allowed(tenant_id)
    except ApiError:
        _enroll_rejected("TENANT_FROZEN", token_id=token_id, ip=ip)
        raise

    # CSR proof-of-possession (SEC-8) BEFORE consuming cap.
    try:
        csr = resources.ca.validate_csr(body.csr_pem)
        fingerprint = resources.ca.spki_fingerprint(csr)
    except CsrError as exc:
        _enroll_rejected("CSR_INVALID", token_id=token_id, ip=ip)
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, str(exc), details={"fields": ["csr_pem"]}
        ) from None

    snapshot = await resources.entitlements.get(tenant_id)
    endpoint_cap = int(snapshot.entitlements.endpoint_cap)

    device_id = new_id("dev")
    issued = resources.ca.sign_device_csr(
        body.csr_pem, tenant_id=tenant_id, device_id=device_id
    )
    host: Host = body.host
    async with resources.db.tenant_transaction(tenant_id) as conn:
        # AC-14/SEC-12: atomic cap check — the advisory xact lock serializes
        # concurrent enrollments for this tenant; abort creates no rows.
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('enroll:' || $1::text, 0))",
            str(tenant_id),
        )
        billable = await conn.fetchval(_BILLABLE_COUNT_SQL, settings.billable_window_days)
        if int(billable) >= endpoint_cap:
            _enroll_rejected("ENDPOINT_CAP_REACHED", token_id=token_id, ip=ip)
            raise ApiError(
                ErrorCode.ENDPOINT_CAP_REACHED,
                "Endpoint cap reached for this plan.",
                details={"endpoint_cap": endpoint_cap, "billable_count": int(billable)},
            )
        asset_id = await conn.fetchval(
            _INSERT_ASSET_SQL,
            tenant_id,
            host.hostname,
            host.os_family.value,
            host.os_name,
            host.os_version,
            host.ip,
            host.mac,
        )
        await conn.execute(_INSERT_IDENTITY_SQL, tenant_id, asset_id, device_id)
        await conn.execute(
            _INSERT_DEVICE_SQL,
            device_id,
            tenant_id,
            asset_id,
            issued.serial_hex,
            issued.issued_at,
            issued.expires_at,
            fingerprint,
            token_id,
            ip,
            host.hostname,
            body.agent_version,
        )
        await conn.execute(_BUMP_TOKEN_SQL, token_id)
        # SEC-13: audit with token id + source IP (metadata only).
        await write_audit(
            conn,
            tenant_id=tenant_id,
            actor=Actor(type="device", id=device_id),
            action_type="device.enroll",
            target=Target(type="device", id=device_id),
            after={
                "enrollment_token_id": token_id,
                "source_ip": ip,
                "claimed_hostname": host.hostname,
                "agent_version": body.agent_version,
                "cert_serial": issued.serial_hex,
            },
        )
    # Post-commit, best-effort: dedup observation (BINDING AssetObservation
    # shape for the asset-dedup consumer) + onboarding signal.
    try:
        await resources.producer.publish(
            STREAM_ASSET_OBSERVATIONS,
            tenant_id=tenant_id,
            trace_id=uuid4().hex,
            payload={
                "observed_at": datetime.now(UTC).isoformat(),
                "source": "agent",
                "hostname": host.hostname,
                "os_family": host.os_family.value,
                "os_name": host.os_name,
                "os_version": host.os_version,
                "ip": host.ip,
                "mac": host.mac,
                "device_id": device_id,
                "agent_version": body.agent_version,
            },
        )
    except Exception:
        logger.exception("asset observation publish failed (dedup catches up from events)")
    await signal_step(resources.redis, tenant_id, "install_agent")

    return {
        "device_id": device_id,
        "certificate_pem": issued.certificate_pem,
        "ca_chain_pem": issued.ca_chain_pem,
        "certificate_expires_at": issued.expires_at,
        # Ratified §10: BASE url — agent appends /v1/agent/{events,heartbeat,
        # renew-credential}.
        "ingest_url": settings.public_ingest_base_url,
        "heartbeat_interval_seconds": settings.heartbeat_interval_seconds,
    }


# ---------------------------------------------------------- agent: heartbeat
@router.post("/v1/agent/heartbeat")
async def heartbeat(
    body: HeartbeatRequest,
    request: Request,
    device: Annotated[DeviceIdentity, Depends(agent_auth)],
) -> dict[str, Any]:
    resources = get_resources(request)
    provider_status = {
        "providers": [p.model_dump() for p in body.providers],
        "os_version": body.os_version,
        "buffer_utilization_pct": body.buffer_utilization_pct,
        "cpu_pct": body.cpu_pct,
        "rss_mb": body.rss_mb,
        "dropped_events_since_last": body.dropped_events_since_last.model_dump(),
        "reported_at": datetime.now(UTC).isoformat(),
    }
    async with resources.db.tenant_transaction(device.tenant_id) as conn:
        asset_id = await conn.fetchval(
            _HEARTBEAT_SQL, device.device_id, body.agent_version, to_jsonb(provider_status)
        )
        if asset_id is None:
            raise ApiError(ErrorCode.DEVICE_REVOKED, "This device credential has been revoked.")
        await conn.execute(_HEARTBEAT_ASSET_SQL, asset_id)
    return {"config_version": "1", "actions": []}


# --------------------------------------------------- agent: renew-credential
@router.post("/v1/agent/renew-credential")
async def renew_credential(
    body: RenewRequest,
    request: Request,
    device: Annotated[DeviceIdentity, Depends(agent_auth)],
) -> dict[str, Any]:
    # SEC-10 allowlist check ran FIRST (agent_auth); revoked devices never
    # reach the signer.
    resources = get_resources(request)
    try:
        csr = resources.ca.validate_csr(body.csr_pem)
        fingerprint = resources.ca.spki_fingerprint(csr)
    except CsrError as exc:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, str(exc), details={"fields": ["csr_pem"]}
        ) from None
    issued = resources.ca.sign_device_csr(
        body.csr_pem, tenant_id=device.tenant_id, device_id=device.device_id
    )
    async with resources.db.tenant_transaction(device.tenant_id) as conn:
        old_serial = await conn.fetchval(
            _RENEW_SQL,
            device.device_id,
            issued.serial_hex,
            issued.issued_at,
            issued.expires_at,
            fingerprint,
        )
        if old_serial is None:
            raise ApiError(ErrorCode.DEVICE_REVOKED, "This device credential has been revoked.")
        await write_audit(
            conn,
            tenant_id=device.tenant_id,
            actor=Actor(type="device", id=device.device_id),
            action_type="device.renew_credential",
            target=Target(type="device", id=device.device_id),
            before={"cert_serial": old_serial},
            after={"cert_serial": issued.serial_hex},
        )
    # Delete-on-change: next request re-reads PG (old serial honored <=24h).
    await resources.status_stores.invalidate_device(device.tenant_id, device.device_id)
    return {
        "certificate_pem": issued.certificate_pem,
        "ca_chain_pem": issued.ca_chain_pem,
        "certificate_expires_at": issued.expires_at,
    }


# ---------------------------------------------------- console: device revoke
@router.post("/v1/devices/{device_id}/revoke")
async def revoke_device(
    device_id: str,
    request: Request,
    principal: Annotated[SessionPrincipal, Depends(session_auth("admin"))],
) -> dict[str, Any]:
    resources = get_resources(request)
    async with resources.db.tenant_transaction(principal.tenant_id) as conn:
        asset_id = await conn.fetchval(_REVOKE_DEVICE_SQL, device_id, principal.user_id)
        if asset_id is None:
            existing = await conn.fetchrow(_DEVICE_EXISTS_SQL, device_id)
            if existing is None:
                not_found("device", device_id, principal.tenant_id)
            # Already revoked — idempotent 200.
            return {"id": device_id, "status": "revoked", "revoked_at": existing["revoked_at"]}
        await conn.execute(_REVOKE_ASSET_SQL, asset_id)
        await write_audit(
            conn,
            tenant_id=principal.tenant_id,
            actor=Actor(type="user", id=str(principal.user_id)),
            action_type="device.revoke",
            target=Target(type="device", id=device_id),
            after={"status": "revoked"},
        )
    # SEC-10: delete-on-change; effective at next connect, <=60s worst case.
    await resources.status_stores.invalidate_device(principal.tenant_id, device_id)
    return {"id": device_id, "status": "revoked", "asset_id": str(asset_id)}
