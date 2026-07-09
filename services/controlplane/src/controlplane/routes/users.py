"""User management (contract §4) — admin only, tenant-scoped (AC-78/81).

Role change and delete invalidate the target user's sessions (SEC-3) via the
`sess:user:{uid}` index. All mutations are audited in the same flow ([A]).
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from controlplane import queries
from controlplane.auditing import audit_standalone
from controlplane.authz import SessionPrincipal, require_roles
from controlplane.ids import USER_PREFIX, parse_public_id, public_id, rfc3339
from controlplane.models import (
    CreateUserRequest,
    PatchUserRequest,
    UserItem,
    UserListResponse,
)
from controlplane.security.tokens import hash_token, new_url_token
from soc_audit import Actor, Target
from soc_schemas.errors import ApiError, ErrorCode

router = APIRouter()

admin_only = require_roles("admin")


def _actor(principal: SessionPrincipal) -> Actor:
    return Actor(type="user", id=public_id(USER_PREFIX, principal.user_id))


def _user_item(row) -> UserItem:
    return UserItem(
        id=public_id(USER_PREFIX, row["id"]),
        email=row["email"],
        role=str(row["role"]),
        state=row["state"],
        created_at=rfc3339(row["created_at"]),
    )


async def _fetch_target(services, user_id: UUID, tenant_id: UUID):
    """Tenant-scoped fetch: foreign-tenant ids are indistinguishable from
    unknown ids (404, AC-81)."""
    async with services.db.acquire() as conn:
        row = await conn.fetchrow(queries.SELECT_USER_IN_TENANT, user_id, tenant_id)
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    return row


@router.get("/v1/users", response_model=UserListResponse, response_model_exclude_none=False)
async def list_users(
    request: Request, principal: SessionPrincipal = Depends(admin_only)
) -> UserListResponse:
    services = request.app.state.services
    async with services.db.acquire() as conn:
        rows = await conn.fetch(queries.LIST_USERS, principal.tenant_id)
    return UserListResponse(
        items=[_user_item(row) for row in rows], next_cursor=None, total_estimate=len(rows)
    )


@router.post("/v1/users", status_code=201, response_model=UserItem)
async def create_user(
    body: CreateUserRequest,
    request: Request,
    principal: SessionPrincipal = Depends(admin_only),
) -> UserItem:
    """[A] 201 + invite email (single-use, 24h, hashed at rest per SEC-2)."""
    services = request.app.state.services
    email = body.email.strip()
    async with services.db.acquire() as conn:
        existing = await conn.fetchrow(
            queries.SELECT_USER_BY_TENANT_EMAIL, principal.tenant_id, email
        )
        if existing is not None:
            raise ApiError(
                ErrorCode.VALIDATION_ERROR,
                "A user with this email already exists.",
                details={"fields": [{"loc": "email", "msg": "already exists"}]},
            )
        row = await conn.fetchrow(
            queries.INSERT_INVITED_USER, principal.tenant_id, email, body.role
        )
        user_id = row["id"]
        token = new_url_token()
        now = services.clock()
        await conn.fetchrow(
            queries.INSERT_VERIFICATION,
            "user_invite",
            None,
            user_id,
            hash_token(token),
            now + timedelta(seconds=services.settings.verification_ttl_seconds),
        )
    link = (
        f"{services.settings.console_origin}/invite/accept"
        f"?token={token}&user_id={public_id(USER_PREFIX, user_id)}"
    )
    await services.mailer.send(
        to=email,
        subject="You have been invited to your organization's SOC console",
        body=(
            f"An administrator invited you as {body.role}. Set your password "
            f"here within 24 hours:\n\n{link}\n"
        ),
    )
    await audit_standalone(
        services.db,
        tenant_id=principal.tenant_id,
        actor=_actor(principal),
        action_type="user.created",
        target=Target(type="user", id=public_id(USER_PREFIX, user_id)),
        after={"email": email, "role": body.role, "state": "invited"},
    )
    return UserItem(
        id=public_id(USER_PREFIX, user_id),
        email=email,
        role=body.role,
        state="invited",
        created_at=rfc3339(row["created_at"]),
    )


@router.patch("/v1/users/{user_id}", response_model=UserItem)
async def patch_user(
    user_id: str,
    body: PatchUserRequest,
    request: Request,
    principal: SessionPrincipal = Depends(admin_only),
) -> UserItem:
    """[A] Role change invalidates the target's sessions (SEC-3)."""
    services = request.app.state.services
    target_id = parse_public_id(USER_PREFIX, user_id)
    row = await _fetch_target(services, target_id, principal.tenant_id)
    if body.role is None or body.role == str(row["role"]):
        return _user_item(row)
    if target_id == principal.user_id:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "You cannot change your own role.",
            details={"fields": [{"loc": "role", "msg": "cannot self-modify"}]},
        )
    now = services.clock()
    async with services.db.acquire() as conn:
        updated = await conn.fetchrow(
            queries.UPDATE_USER_ROLE, target_id, principal.tenant_id, body.role, now
        )
    if updated is None:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    await services.sessions.revoke_all_for_user(target_id, reason="role_change")
    await audit_standalone(
        services.db,
        tenant_id=principal.tenant_id,
        actor=_actor(principal),
        action_type="user.role_changed",
        target=Target(type="user", id=public_id(USER_PREFIX, target_id)),
        before={"role": str(row["role"])},
        after={"role": body.role},
    )
    refreshed = await _fetch_target(services, target_id, principal.tenant_id)
    return _user_item(refreshed)


@router.delete("/v1/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    request: Request,
    principal: SessionPrincipal = Depends(admin_only),
) -> Response:
    """[A] Soft delete; the target's sessions are invalidated (SEC-3)."""
    services = request.app.state.services
    target_id = parse_public_id(USER_PREFIX, user_id)
    if target_id == principal.user_id:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "You cannot delete your own user.",
            details={"fields": [{"loc": "user_id", "msg": "cannot self-delete"}]},
        )
    row = await _fetch_target(services, target_id, principal.tenant_id)
    now = services.clock()
    async with services.db.acquire() as conn:
        deleted = await conn.fetchrow(
            queries.SOFT_DELETE_USER, target_id, principal.tenant_id, now
        )
    if deleted is None:
        raise ApiError(ErrorCode.NOT_FOUND, "Resource not found.")
    await services.sessions.revoke_all_for_user(target_id, reason="user_deleted")
    await audit_standalone(
        services.db,
        tenant_id=principal.tenant_id,
        actor=_actor(principal),
        action_type="user.deleted",
        target=Target(type="user", id=public_id(USER_PREFIX, target_id)),
        before={"email": row["email"], "role": str(row["role"]), "state": row["state"]},
        after={"state": "deleted"},
    )
    return Response(status_code=204)
