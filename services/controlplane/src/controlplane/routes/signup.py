"""Signup & provisioning endpoints (contract §3; AC-1..8; SEC-2/5/6).

Enumeration posture (SEC-6): resend-verification always returns 202; the ONLY
deliberate disclosure is AC-4's DOMAIN_ALREADY_REGISTERED, which sits behind
the same per-IP signup counter as everything else on this router.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Request

from controlplane import queries, redis_keys
from controlplane.auditing import audit_standalone
from controlplane.authz import client_ip, public
from controlplane.ids import ACCOUNT_PREFIX, TENANT_PREFIX, parse_public_id, public_id
from controlplane.models import (
    ProvisioningStatusResponse,
    ResendVerificationRequest,
    SignupRequest,
    SignupResponse,
    VerifyRequest,
    VerifyResponse,
)
from controlplane.security.passwords import PasswordPolicyViolation, validate_password_policy
from controlplane.security.tokens import hash_token, new_url_token
from soc_audit import Actor, Target
from soc_schemas.errors import ApiError, ErrorCode

logger = logging.getLogger(__name__)

router = APIRouter()

SIGNUP_ABUSE_WINDOW_SECONDS = 3600  # abuse:signup:ip:{ip} TTL per key registry


def _email_domain(email: str) -> str:
    return email.rpartition("@")[2].lower()


async def _bump_signup_counter(services, ip: str | None) -> int:
    if not ip:
        return 0
    key = redis_keys.abuse_signup_ip(ip)
    count = await services.redis.incr(key)
    if int(count) == 1:
        await services.redis.expire(key, SIGNUP_ABUSE_WINDOW_SECONDS)
    return int(count)


async def _signup_ip_threshold(services) -> int:
    async with services.db.acquire() as conn:
        row = await conn.fetchrow(
            queries.SELECT_PLATFORM_CONFIG_VALUE, "signup_per_ip_hourly_threshold"
        )
    if row is None:
        return services.settings.signup_ip_threshold_default
    return int(json.loads(row["value"]))


async def _log_abuse(
    services, *, email: str, ip: str | None, outcome: str, reason: str
) -> None:
    """Durable record in control.signup_abuse_log (AC-8/SEC-5)."""
    async with services.db.acquire() as conn:
        await conn.execute(
            queries.INSERT_SIGNUP_ABUSE_LOG, email, _email_domain(email), ip, outcome, reason
        )


async def _send_verification_email(services, *, account_id: UUID, email: str) -> None:
    token = new_url_token()
    now = services.clock()
    async with services.db.acquire() as conn:
        await conn.fetchrow(
            queries.INSERT_VERIFICATION,
            "signup_verification",
            account_id,
            None,
            hash_token(token),
            now + timedelta(seconds=services.settings.verification_ttl_seconds),
        )
    link = (
        f"{services.settings.console_origin}/signup/verify"
        f"?token={token}&account_id={public_id(ACCOUNT_PREFIX, account_id)}"
    )
    await services.mailer.send(
        to=email,
        subject="Verify your email to activate your SOC trial",
        body=(
            "Welcome! Confirm your email address to start provisioning your "
            f"tenant:\n\n{link}\n\nThis link is valid for 24 hours and can be "
            "used once. If you did not sign up, ignore this email."
        ),
    )


@router.post("/v1/signup", status_code=202, response_model=SignupResponse)
@public
async def signup(body: SignupRequest, request: Request) -> SignupResponse:
    services = request.app.state.services
    ip = client_ip(request)
    email = body.email.strip()
    domain = _email_domain(email)

    # --- abuse controls (AC-8/SEC-5): per-IP velocity + disposable domains ---
    count = await _bump_signup_counter(services, ip)
    threshold = await _signup_ip_threshold(services)
    challenge_reasons = []
    if ip and count > threshold:
        challenge_reasons.append("ip_velocity")
    if domain in services.disposable_domains:
        challenge_reasons.append("disposable_domain")
    if challenge_reasons:
        reason = ",".join(challenge_reasons)
        if body.challenge_response:
            passed = await services.challenge_verifier.verify(
                response=body.challenge_response, ip=ip
            )
            if not passed:
                await _log_abuse(
                    services, email=email, ip=ip, outcome="blocked", reason="challenge_failed"
                )
                raise ApiError(
                    ErrorCode.SIGNUP_CHALLENGE_REQUIRED,
                    "Challenge verification failed — please retry.",
                    details={"challenge": {"status": "failed", "reason": reason}},
                )
            await _log_abuse(
                services, email=email, ip=ip, outcome="allowed", reason="challenge_passed"
            )
        else:
            await _log_abuse(services, email=email, ip=ip, outcome="challenged", reason=reason)
            raise ApiError(
                ErrorCode.SIGNUP_CHALLENGE_REQUIRED,
                "Additional verification is required to create this account.",
                details={"challenge": {"status": "required", "reason": reason}},
            )

    # --- password policy + breached check (SEC-1) -----------------------------
    try:
        validate_password_policy(body.password)
    except PasswordPolicyViolation as exc:
        raise ApiError(ErrorCode.PASSWORD_POLICY_VIOLATION, exc.message) from None
    if await services.breached_checker.is_breached(body.password):
        raise ApiError(
            ErrorCode.PASSWORD_BREACHED,
            "This password appears in known breach datasets — choose a different one.",
        )

    # --- one account per domain (AC-4; message reveals nothing further) -------
    async with services.db.acquire() as conn:
        existing = await conn.fetchrow(queries.SELECT_ACCOUNT_BY_DOMAIN, domain)
    if existing is not None:
        raise ApiError(
            ErrorCode.DOMAIN_ALREADY_REGISTERED,
            "An account already exists for this email domain.",
        )

    password_hash = await services.passwords.hash(body.password)
    try:
        async with services.db.acquire() as conn:
            row = await conn.fetchrow(
                queries.INSERT_ACCOUNT, body.org_name.strip(), email, domain, password_hash
            )
    except Exception:
        # Unique-index race (same domain/email concurrently): identical 409.
        raise ApiError(
            ErrorCode.DOMAIN_ALREADY_REGISTERED,
            "An account already exists for this email domain.",
        ) from None

    await _send_verification_email(services, account_id=row["id"], email=email)
    return SignupResponse(
        account_id=public_id(ACCOUNT_PREFIX, row["id"]), state="pending_verification"
    )


@router.post("/v1/signup/verify", response_model=VerifyResponse)
@public
async def verify(body: VerifyRequest, request: Request) -> VerifyResponse:
    """Consume the single-use token (CAS), create the tenant row, and kick off
    the remaining provisioning steps in the background (AC-2/3). [A]"""
    services = request.app.state.services
    token_hash = hash_token(body.token)
    now = services.clock()
    async with services.db.acquire() as conn:
        consumed = await conn.fetchrow(queries.CONSUME_VERIFICATION, token_hash, now)
        if consumed is None:
            existing = await conn.fetchrow(queries.SELECT_VERIFICATION_BY_HASH, token_hash)
            if existing is not None and existing["used_at"] is not None:
                raise ApiError(
                    ErrorCode.VERIFICATION_ALREADY_USED,
                    "This verification link was already used.",
                )
            # Unknown token and expired token are indistinguishable (SEC-6).
            raise ApiError(
                ErrorCode.VERIFICATION_EXPIRED,
                "This verification link has expired — request a new one.",
            )
        if consumed["purpose"] != "signup_verification" or consumed["account_id"] is None:
            raise ApiError(
                ErrorCode.VERIFICATION_EXPIRED,
                "This verification link has expired — request a new one.",
            )
        account_id: UUID = consumed["account_id"]
        await conn.execute(queries.MARK_ACCOUNT_VERIFIED, account_id)
        account = await conn.fetchrow(queries.SELECT_ACCOUNT_BY_ID, account_id)

    saga_id, tenant_id = await services.saga.ensure_started(account_id, account["org_name"])
    await audit_standalone(
        services.db,
        tenant_id=tenant_id,
        actor=Actor(type="user", id=public_id(ACCOUNT_PREFIX, account_id)),
        action_type="signup.verified",
        target=Target(type="tenant", id=str(tenant_id)),
        after={"account_state": "verified", "provisioning": "in_progress"},
    )
    services.spawn(services.saga.run(saga_id))
    return VerifyResponse(
        tenant_id=public_id(TENANT_PREFIX, tenant_id), provisioning="in_progress"
    )


@router.post("/v1/signup/resend-verification", status_code=202)
@public
async def resend_verification(body: ResendVerificationRequest, request: Request) -> dict:
    """Always 202 — no account enumeration (SEC-6)."""
    services = request.app.state.services
    ip = client_ip(request)
    count = await _bump_signup_counter(services, ip)
    threshold = await _signup_ip_threshold(services)
    if ip and count > threshold:
        # Silently accept without sending (rate-limited like login, SEC-6).
        await _log_abuse(
            services, email=body.email, ip=ip, outcome="held", reason="resend_ip_velocity"
        )
        return {}
    async with services.db.acquire() as conn:
        account = await conn.fetchrow(queries.SELECT_ACCOUNT_BY_EMAIL, body.email.strip())
    if account is not None and account["state"] == "pending_verification":
        await _send_verification_email(
            services, account_id=account["id"], email=account["email"]
        )
    return {}


@router.get(
    "/v1/signup/provisioning-status",
    response_model=ProvisioningStatusResponse,
    response_model_exclude_none=True,
)
@public
async def provisioning_status(account_id: str, request: Request) -> ProvisioningStatusResponse:
    services = request.app.state.services
    account_uuid = parse_public_id(ACCOUNT_PREFIX, account_id)
    async with services.db.acquire() as conn:
        account = await conn.fetchrow(queries.SELECT_ACCOUNT_BY_ID, account_uuid)
        if account is None:
            raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
        if account["state"] == "pending_verification":
            return ProvisioningStatusResponse(state="pending_verification")
        tenant = await conn.fetchrow(queries.SELECT_TENANT_BY_ACCOUNT, account_uuid)
    if tenant is None or str(tenant["status"]) == "provisioning":
        return ProvisioningStatusResponse(state="provisioning")
    status = str(tenant["status"])
    if status == "provisioning_failed":
        return ProvisioningStatusResponse(state="provisioning_failed")
    if status == "purged":
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    return ProvisioningStatusResponse(
        state="ready", console_url=services.settings.console_origin
    )
