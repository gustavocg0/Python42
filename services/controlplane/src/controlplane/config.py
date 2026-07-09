"""Environment-driven settings for controlplane-api (SEC-49: secrets from env).

All variables are prefixed `CP_`. Inbound service-token verification keys are
read from `CP_SVC_KEY_<SERVICE>` (e.g. CP_SVC_KEY_DATAPLANE) — the env-var
suffix, lowercased, is the authenticated service name (design §5.1 item 2).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

_SVC_KEY_PREFIX = "CP_SVC_KEY_"


def _get_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    return default if raw is None or not raw.strip() else int(raw)


def _get_float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    return default if raw is None or not raw.strip() else float(raw)


@dataclass(frozen=True, slots=True)
class Settings:
    env: str = "dev"
    # Listeners: public app and internal app are SEPARATE processes/apps
    # (SEC-30/40 — internal routes never mounted on public listeners).
    host: str = "0.0.0.0"
    port: int = 8001
    internal_host: str = "127.0.0.1"
    internal_port: int = 8101
    # Stores.
    database_url: str = "postgresql://svc_controlplane:dev@localhost:5432/soc"
    redis_url: str = "redis://localhost:6379/0"
    # Console origin: CORS allowlist + verification-link base (contract §14).
    console_origin: str = "http://localhost:3000"
    cookie_secure: bool = True
    trust_proxy_headers: bool = False
    # Cross-plane internal HTTP (design §5.1): controlplane -> dataplane.
    dataplane_internal_url: str = "http://localhost:8100"
    outbound_service_name: str = "controlplane"
    outbound_service_key: str = ""
    # Inbound verification keys: service_name -> shared HMAC key.
    inbound_service_keys: dict[str, str] = field(default_factory=dict)
    # Mail (dev default: mailpit on localhost:1025; console = log fallback).
    mailer: str = "console"  # console | smtp
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_from: str = "no-reply@soc.local"
    smtp_starttls: bool = False
    smtp_username: str = ""
    smtp_password: str = ""
    # Signup abuse challenge (SEC-5 / OQ-5): stub verifier accepts this exact
    # value when set; empty => reject all challenge responses (fail closed).
    challenge_stub_token: str = ""
    # Sessions (SEC-3).
    session_idle_seconds: int = 24 * 3600
    session_absolute_seconds: int = 7 * 24 * 3600
    # Login throttles (SEC-4 / AC-77).
    login_lockout_threshold: int = 10
    login_ip_threshold: int = 20
    login_throttle_window_seconds: int = 900
    # Signup abuse fallback threshold when platform_config row is absent.
    signup_ip_threshold_default: int = 5
    # Email verification (SEC-2).
    verification_ttl_seconds: int = 24 * 3600
    # Provisioning saga (AC-3/5).
    saga_step_max_attempts: int = 3
    saga_retry_delay_seconds: float = 2.0
    docs_enabled: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ
        svc_keys = {
            name[len(_SVC_KEY_PREFIX) :].lower(): value
            for name, value in env.items()
            if name.startswith(_SVC_KEY_PREFIX) and value
        }
        return cls(
            env=env.get("CP_ENV", "dev"),
            host=env.get("CP_HOST", "0.0.0.0"),
            port=_get_int(env, "CP_PORT", 8001),
            internal_host=env.get("CP_INTERNAL_HOST", "127.0.0.1"),
            internal_port=_get_int(env, "CP_INTERNAL_PORT", 8101),
            database_url=env.get(
                "CP_DATABASE_URL", "postgresql://svc_controlplane:dev@localhost:5432/soc"
            ),
            redis_url=env.get("CP_REDIS_URL", "redis://localhost:6379/0"),
            console_origin=env.get("CP_CONSOLE_ORIGIN", "http://localhost:3000").rstrip("/"),
            cookie_secure=_get_bool(env, "CP_COOKIE_SECURE", True),
            trust_proxy_headers=_get_bool(env, "CP_TRUST_PROXY_HEADERS", False),
            dataplane_internal_url=env.get(
                "CP_DATAPLANE_INTERNAL_URL", "http://localhost:8100"
            ).rstrip("/"),
            outbound_service_name=env.get("CP_OUTBOUND_SERVICE_NAME", "controlplane"),
            outbound_service_key=env.get("CP_OUTBOUND_SERVICE_KEY", ""),
            inbound_service_keys=svc_keys,
            mailer=env.get("CP_MAILER", "console"),
            smtp_host=env.get("CP_SMTP_HOST", "localhost"),
            smtp_port=_get_int(env, "CP_SMTP_PORT", 1025),
            smtp_from=env.get("CP_SMTP_FROM", "no-reply@soc.local"),
            smtp_starttls=_get_bool(env, "CP_SMTP_STARTTLS", False),
            smtp_username=env.get("CP_SMTP_USERNAME", ""),
            smtp_password=env.get("CP_SMTP_PASSWORD", ""),
            challenge_stub_token=env.get("CP_CHALLENGE_STUB_TOKEN", ""),
            session_idle_seconds=_get_int(env, "CP_SESSION_IDLE_SECONDS", 24 * 3600),
            session_absolute_seconds=_get_int(env, "CP_SESSION_ABSOLUTE_SECONDS", 7 * 24 * 3600),
            login_lockout_threshold=_get_int(env, "CP_LOGIN_LOCKOUT_THRESHOLD", 10),
            login_ip_threshold=_get_int(env, "CP_LOGIN_IP_THRESHOLD", 20),
            login_throttle_window_seconds=_get_int(env, "CP_LOGIN_THROTTLE_WINDOW_SECONDS", 900),
            signup_ip_threshold_default=_get_int(env, "CP_SIGNUP_IP_THRESHOLD_DEFAULT", 5),
            verification_ttl_seconds=_get_int(env, "CP_VERIFICATION_TTL_SECONDS", 24 * 3600),
            saga_step_max_attempts=_get_int(env, "CP_SAGA_STEP_MAX_ATTEMPTS", 3),
            saga_retry_delay_seconds=_get_float(env, "CP_SAGA_RETRY_DELAY_SECONDS", 2.0),
            docs_enabled=_get_bool(env, "CP_DOCS_ENABLED", False),
        )
