"""Auth endpoints (contract §4; SEC-1/3/4/6; AC-77).

Login rules:
- uniform error (message AND timing) for unknown email vs wrong password;
- per-account lockout after 10 failures + per-IP throttle => 429 RATE_LIMITED
  (Redis `throttle:login:acct:{user_id}` / `throttle:login:ip:{ip}`);
- sessions only for tenants in status active|frozen (frozen = read-only
  console, signalled via tenant.status; purged/failed/provisioning => no
  session, uniform 401);
- new session id + CSRF token at every login; cookies `sid` (HttpOnly) and
  `csrf_token` (readable by the console) per contract §14.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response

from controlplane import queries, redis_keys
from controlplane.auditing import audit_standalone
from controlplane.authz import SessionPrincipal, client_ip, public, require_roles
from controlplane.ids import TENANT_PREFIX, USER_PREFIX, public_id, rfc3339
from controlplane.models import (
    AcceptInviteRequest,
    ChangePasswordRequest,
    LoginRequest,
    SessionEnvelope,
    TenantPayload,
    UserPayload,
)
from controlplane.security.passwords import PasswordPolicyViolation, validate_password_policy
from controlplane.security.tokens import hash_token
from controlplane.sessions import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME
from soc_audit import Actor, Target
from soc_schemas.errors import ApiError, ErrorCode

logger = logging.getLogger(__name__)

router = APIRouter()

_LOGIN_FAILED = "Invalid email or password."
_LOGINABLE_TENANT_STATUSES = frozenset({"active", "frozen"})

any_role = require_roles("admin", "analyst")
any_role_allow_frozen = require_roles("admin", "analyst", allow_frozen_write=True)


def _set_session_cookies(response: Response, *, sid: str, csrf: str, settings) -> None:
    common = {
        "secure": settings.cookie_secure,
        "samesite": "lax",
        "path": "/",
        "max_age": settings.session_absolute_seconds,
    }
    response.set_cookie(SESSION_COOKIE_NAME, sid, httponly=True, **common)
    # Double-submit CSRF cookie — deliberately NOT HttpOnly (contract §14).
    response.set_cookie(CSRF_COOKIE_NAME, csrf, httponly=False, **common)


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


async def _throttle_count(services, key: str) -> int:
    value = await services.redis.get(key)
    return int(value) if value else 0


async def _throttle_bump(services, key: str) -> int:
    count = await services.redis.incr(key)
    if int(count) == 1:
        await services.redis.expire(key, services.settings.login_throttle_window_seconds)
    return int(count)


async def _retry_after(services, key: str) -> int:
    ttl = await services.redis.ttl(key)
    return max(int(ttl), 1) if ttl and int(ttl) > 0 else (
        services.settings.login_throttle_window_seconds
    )


@router.post(
    "/v1/auth/login", response_model=SessionEnvelope, response_model_exclude_none=True
)
@public
async def login(body: LoginRequest, request: Request, response: Response) -> SessionEnvelope:
    services = request.app.state.services
    settings = services.settings
    ip = client_ip(request)

    # Per-IP throttle first (SEC-4) — applies before any account lookup.
    if ip:
        ip_key = redis_keys.throttle_login_ip(ip)
        if await _throttle_count(services, ip_key) >= settings.login_ip_threshold:
            raise ApiError(
                ErrorCode.RATE_LIMITED,
                "Too many login attempts — try again later.",
                retry_after_seconds=await _retry_after(services, ip_key),
            )

    async with services.db.acquire() as conn:
        user = await conn.fetchrow(queries.SELECT_USER_FOR_LOGIN, body.email.strip())

    if user is None:
        # Burn hash-verification work anyway: uniform timing + message (SEC-4/6).
        await services.passwords.dummy_verify()
        if ip:
            await _throttle_bump(services, redis_keys.throttle_login_ip(ip))
        raise ApiError(ErrorCode.AUTH_REQUIRED, _LOGIN_FAILED)

    acct_key = redis_keys.throttle_login_acct(user["id"])
    now = services.clock()
    locked_until = user["locked_until"]
    if await _throttle_count(services, acct_key) >= settings.login_lockout_threshold or (
        locked_until is not None and locked_until > now
    ):
        raise ApiError(
            ErrorCode.RATE_LIMITED,
            "Too many failed logins — account temporarily locked.",
            retry_after_seconds=await _retry_after(services, acct_key),
        )

    password_ok = bool(user["password_hash"]) and await services.passwords.verify(
        user["password_hash"], body.password
    )
    tenant_ok = str(user["tenant_status"]) in _LOGINABLE_TENANT_STATUSES
    user_ok = user["state"] == "active"

    if not (password_ok and tenant_ok and user_ok):
        if ip:
            await _throttle_bump(services, redis_keys.throttle_login_ip(ip))
        if not password_ok:
            failures = await _throttle_bump(services, acct_key)
            lock = (
                now + timedelta(seconds=settings.login_throttle_window_seconds)
                if failures >= settings.login_lockout_threshold
                else None
            )
            async with services.db.acquire() as conn:
                await conn.execute(queries.RECORD_LOGIN_FAILURE, user["id"], lock, now)
        # Security log with source IP (SEC-4) + audit (AC-85).
        logger.warning(
            "login failed",
            extra={
                "user_id": str(user["id"]),
                "tenant_id": str(user["tenant_id"]),
                "source_ip": ip,
                "reason": (
                    "bad_password"
                    if not password_ok
                    else ("tenant_unavailable" if not tenant_ok else "user_inactive")
                ),
            },
        )
        try:
            await audit_standalone(
                services.db,
                tenant_id=user["tenant_id"],
                actor=Actor(type="user", id=public_id(USER_PREFIX, user["id"])),
                action_type="auth.login_failed",
                target=Target(type="user", id=public_id(USER_PREFIX, user["id"])),
                reason_code="bad_password" if not password_ok else "not_loginable",
            )
        except Exception:
            logger.exception("failed to audit login failure")
        raise ApiError(ErrorCode.AUTH_REQUIRED, _LOGIN_FAILED)

    # Success: clear throttles, mint a NEW session id (no fixation, SEC-3).
    await services.redis.delete(acct_key)
    async with services.db.acquire() as conn:
        await conn.execute(queries.RESET_LOGIN_FAILURES, user["id"], now)
    session = await services.sessions.create(
        user_id=user["id"],
        tenant_id=user["tenant_id"],
        role=str(user["role"]),
        ip=ip,
        user_agent=request.headers.get("User-Agent"),
    )
    _set_session_cookies(
        response, sid=session.session_id, csrf=session.csrf_token, settings=settings
    )
    return SessionEnvelope(
        user=UserPayload(
            id=public_id(USER_PREFIX, user["id"]), email=user["email"], role=str(user["role"])
        ),
        tenant=TenantPayload(
            id=public_id(TENANT_PREFIX, user["tenant_id"]),
            name=user["tenant_name"],
            status=str(user["tenant_status"]),
            abuse_frozen=bool(user["abuse_frozen"]),
            trial_expires_at=(
                rfc3339(user["trial_expires_at"]) if user["trial_expires_at"] else None
            ),
        ),
    )


@router.post("/v1/auth/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    principal: SessionPrincipal = Depends(any_role_allow_frozen),
) -> Response:
    """[A] Session termination always works, including on frozen tenants."""
    services = request.app.state.services
    await services.sessions.revoke(principal.session_id, reason="logout")
    await audit_standalone(
        services.db,
        tenant_id=principal.tenant_id,
        actor=Actor(type="user", id=public_id(USER_PREFIX, principal.user_id)),
        action_type="auth.logout",
        target=Target(type="user", id=public_id(USER_PREFIX, principal.user_id)),
    )
    out = Response(status_code=204)
    _clear_session_cookies(out)
    return out


@router.get("/v1/me", response_model=SessionEnvelope, response_model_exclude_none=True)
async def me(
    request: Request, principal: SessionPrincipal = Depends(any_role)
) -> SessionEnvelope:
    services = request.app.state.services
    async with services.db.acquire() as conn:
        row = await conn.fetchrow(queries.SELECT_USER_WITH_TENANT, principal.user_id)
    if row is None:
        raise ApiError(ErrorCode.SESSION_EXPIRED, "Session expired.")
    return SessionEnvelope(
        user=UserPayload(
            id=public_id(USER_PREFIX, row["id"]), email=row["email"], role=str(row["role"])
        ),
        tenant=TenantPayload(
            id=public_id(TENANT_PREFIX, row["tenant_id"]),
            name=row["tenant_name"],
            status=str(row["tenant_status"]),
            abuse_frozen=bool(row["abuse_frozen"]),
            trial_expires_at=(
                rfc3339(row["trial_expires_at"]) if row["trial_expires_at"] else None
            ),
        ),
    )


@router.post("/v1/auth/change-password", status_code=204)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    principal: SessionPrincipal = Depends(any_role_allow_frozen),
) -> Response:
    """[A] Invalidates every OTHER session of the user (AC-77/SEC-3).

    Exempt from the frozen-tenant write block (Architect-ratified 2026-07-08):
    compromised-account rotation must work on frozen tenants."""
    services = request.app.state.services
    async with services.db.acquire() as conn:
        row = await conn.fetchrow(queries.SELECT_USER_AUTH_BY_ID, principal.user_id)
    if row is None or not row["password_hash"]:
        raise ApiError(ErrorCode.SESSION_EXPIRED, "Session expired.")
    if not await services.passwords.verify(row["password_hash"], body.current_password):
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "Current password is incorrect.",
            details={"fields": [{"loc": "current_password", "msg": "incorrect"}]},
        )
    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyViolation as exc:
        raise ApiError(ErrorCode.PASSWORD_POLICY_VIOLATION, exc.message) from None
    if await services.breached_checker.is_breached(body.new_password):
        raise ApiError(
            ErrorCode.PASSWORD_BREACHED,
            "This password appears in known breach datasets — choose a different one.",
        )
    new_hash = await services.passwords.hash(body.new_password)
    now = services.clock()
    async with services.db.acquire() as conn:
        await conn.execute(queries.UPDATE_USER_PASSWORD, principal.user_id, new_hash, now)
    await services.sessions.revoke_all_for_user(
        principal.user_id, reason="password_change", except_session_id=principal.session_id
    )
    await audit_standalone(
        services.db,
        tenant_id=principal.tenant_id,
        actor=Actor(type="user", id=public_id(USER_PREFIX, principal.user_id)),
        action_type="user.password_changed",
        target=Target(type="user", id=public_id(USER_PREFIX, principal.user_id)),
        reason_code="self_service",
    )
    return Response(status_code=204)


@router.post("/v1/auth/accept-invite", status_code=204)
@public
async def accept_invite(body: AcceptInviteRequest, request: Request) -> Response:
    """[A] Invited user sets a password and becomes active (contract §4,
    Architect-ratified 2026-07-08).

    The password policy/breached check runs BEFORE the single-use token is
    consumed, so a rejected password never burns the invite; the CAS consume
    guards concurrent submissions (SEC-2)."""
    services = request.app.state.services
    token_hash = hash_token(body.token)
    now = services.clock()

    async with services.db.acquire() as conn:
        row = await conn.fetchrow(queries.SELECT_VERIFICATION_BY_HASH, token_hash)
    if row is None or row["purpose"] != "user_invite" or row["user_id"] is None:
        # Unknown tokens and wrong-purpose tokens are indistinguishable (SEC-6).
        raise ApiError(
            ErrorCode.VERIFICATION_EXPIRED,
            "This invite link has expired — ask your administrator for a new one.",
        )
    if row["used_at"] is not None:
        raise ApiError(
            ErrorCode.VERIFICATION_ALREADY_USED, "This invite link was already used."
        )
    if row["expires_at"] <= now:
        raise ApiError(
            ErrorCode.VERIFICATION_EXPIRED,
            "This invite link has expired — ask your administrator for a new one.",
        )

    try:
        validate_password_policy(body.password)
    except PasswordPolicyViolation as exc:
        raise ApiError(ErrorCode.PASSWORD_POLICY_VIOLATION, exc.message) from None
    if await services.breached_checker.is_breached(body.password):
        raise ApiError(
            ErrorCode.PASSWORD_BREACHED,
            "This password appears in known breach datasets — choose a different one.",
        )
    password_hash = await services.passwords.hash(body.password)

    async with services.db.acquire() as conn:
        consumed = await conn.fetchrow(queries.CONSUME_VERIFICATION, token_hash, now)
        if consumed is None:  # lost a concurrent-consume race
            raise ApiError(
                ErrorCode.VERIFICATION_ALREADY_USED, "This invite link was already used."
            )
        activated = await conn.fetchrow(
            queries.ACTIVATE_INVITED_USER, row["user_id"], password_hash, now
        )
    if activated is None:
        # User deleted (or no longer invited) since the invite was sent.
        raise ApiError(
            ErrorCode.VERIFICATION_EXPIRED,
            "This invite link has expired — ask your administrator for a new one.",
        )

    await audit_standalone(
        services.db,
        tenant_id=activated["tenant_id"],
        actor=Actor(type="user", id=public_id(USER_PREFIX, activated["id"])),
        action_type="user.invite_accepted",
        target=Target(type="user", id=public_id(USER_PREFIX, activated["id"])),
        before={"state": "invited"},
        after={"state": "active", "role": str(activated["role"])},
    )
    return Response(status_code=204)
