"""Request/response models for controlplane-api (contract §3/§4/§5, §14)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Role = Literal["admin", "analyst"]
PlanId = Literal["trial", "core", "pro"]


def _validate_email(value: str) -> str:
    value = value.strip()
    if len(value) > 320 or value.count("@") != 1:
        raise ValueError("invalid email address")
    local, _, domain = value.partition("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("invalid email address")
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- signup (§3) -------------------------------------------------------------


class SignupRequest(_StrictModel):
    org_name: str = Field(min_length=2, max_length=120)
    email: str
    password: str = Field(max_length=4096)  # policy enforced in the handler for stable codes
    challenge_response: str | None = None

    _email = field_validator("email")(_validate_email)


class SignupResponse(_StrictModel):
    account_id: str
    state: Literal["pending_verification"]


class VerifyRequest(_StrictModel):
    token: str = Field(min_length=1, max_length=512)


class VerifyResponse(_StrictModel):
    tenant_id: str
    provisioning: Literal["in_progress"]


class ResendVerificationRequest(_StrictModel):
    email: str

    _email = field_validator("email")(_validate_email)


class ProvisioningStatusResponse(_StrictModel):
    state: Literal["pending_verification", "provisioning", "ready", "provisioning_failed"]
    console_url: str | None = None


# --- auth & users (§4, §14) ---------------------------------------------------


class LoginRequest(_StrictModel):
    email: str
    password: str = Field(max_length=4096)

    _email = field_validator("email")(_validate_email)


class UserPayload(_StrictModel):
    id: str
    email: str
    role: Role


class TenantPayload(_StrictModel):
    id: str
    name: str
    status: str
    abuse_frozen: bool
    trial_expires_at: str | None = None


class SessionEnvelope(_StrictModel):
    """Login response AND /v1/me (contract §14 item 3: identical shapes)."""

    user: UserPayload
    tenant: TenantPayload


class ChangePasswordRequest(_StrictModel):
    current_password: str = Field(max_length=4096)
    new_password: str = Field(max_length=4096)


class AcceptInviteRequest(_StrictModel):
    """POST /v1/auth/accept-invite (Architect-ratified 2026-07-08)."""

    token: str = Field(min_length=1, max_length=512)
    password: str = Field(max_length=4096)


class CreateUserRequest(_StrictModel):
    email: str
    role: Role

    _email = field_validator("email")(_validate_email)


class UserItem(_StrictModel):
    id: str
    email: str
    role: Role
    state: str
    created_at: str


class UserListResponse(_StrictModel):
    items: list[UserItem]
    next_cursor: str | None = None
    total_estimate: int


class PatchUserRequest(_StrictModel):
    role: Role | None = None


# --- entitlements (§5) --------------------------------------------------------


class PlanChangeRequest(_StrictModel):
    plan: PlanId


class AbuseFreezeRequest(_StrictModel):
    frozen: bool
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class OkResponse(_StrictModel):
    status: Literal["ok"] = "ok"
    details: dict[str, Any] | None = None
