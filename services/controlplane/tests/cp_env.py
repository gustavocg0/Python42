"""Test environment assembly + end-to-end flow helpers (fakes only)."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

import fakeredis.aioredis
import httpx
from argon2 import PasswordHasher
from cp_fakes import FakeDataplane, FakeDb, FakeMailer, MutableClock, seed_plans

from controlplane.abuse import build_challenge_verifier
from controlplane.app import create_public_app
from controlplane.config import Settings
from controlplane.internal_app import create_internal_app
from controlplane.security.passwords import FileBreachedPasswordChecker, PasswordService
from controlplane.services import AppServices, build_services

DEFAULT_PASSWORD = "orange-battery-staple-42"
CHALLENGE_TOKEN = "stub-challenge-pass"

SVC_KEY_DATAPLANE = "d" * 32
SVC_KEY_OPS = "p" * 32
OUTBOUND_KEY = "o" * 32

_cheap_hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)


@dataclass
class Env:
    settings: Settings
    clock: MutableClock
    db: FakeDb
    redis: object
    mailer: FakeMailer
    dataplane: FakeDataplane
    services: AppServices
    public_app: object
    internal_app: object
    public: httpx.AsyncClient
    internal: httpx.AsyncClient
    _extra_clients: list[httpx.AsyncClient] = field(default_factory=list)

    async def drain_background(self) -> None:
        while self.services.background_tasks:
            await asyncio.gather(*list(self.services.background_tasks))

    def csrf(self, client: httpx.AsyncClient | None = None) -> str:
        return (client or self.public).cookies.get("csrf_token") or ""

    def new_client(self) -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.public_app),
            base_url="https://testserver",
        )
        self._extra_clients.append(client)
        return client

    async def aclose(self) -> None:
        await self.drain_background()
        for client in (self.public, self.internal, *self._extra_clients):
            await client.aclose()
        await self.redis.aclose()


async def make_env(**settings_overrides) -> Env:
    settings = Settings(
        cookie_secure=True,
        console_origin="https://console.test",
        dataplane_internal_url="http://dataplane-internal",
        outbound_service_key=OUTBOUND_KEY,
        inbound_service_keys={"dataplane": SVC_KEY_DATAPLANE, "opsconsole": SVC_KEY_OPS},
        challenge_stub_token=CHALLENGE_TOKEN,
        saga_retry_delay_seconds=0.0,
        saga_step_max_attempts=2,
        **settings_overrides,
    )
    clock = MutableClock()
    db = FakeDb(clock)
    seed_plans(db)
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    mailer = FakeMailer()
    dataplane = FakeDataplane()

    services = build_services(
        settings=settings,
        db=db,
        redis=redis,
        mailer=mailer,
        breached_checker=FileBreachedPasswordChecker(),
        challenge_verifier=build_challenge_verifier(settings),
        dataplane_client=dataplane.client(settings.dataplane_internal_url),
        clock=clock,
        password_service=PasswordService(_cheap_hasher),
    )
    public_app = create_public_app(settings, services)
    internal_app = create_internal_app(settings, services)
    public = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=public_app), base_url="https://testserver"
    )
    internal = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=internal_app), base_url="https://testserver"
    )
    return Env(
        settings=settings,
        clock=clock,
        db=db,
        redis=redis,
        mailer=mailer,
        dataplane=dataplane,
        services=services,
        public_app=public_app,
        internal_app=internal_app,
        public=public,
        internal=internal,
    )


# --- flow helpers -------------------------------------------------------------


async def do_signup(
    env: Env,
    *,
    email: str = "admin@acme.example",
    org: str = "Acme GmbH",
    password: str = DEFAULT_PASSWORD,
) -> httpx.Response:
    return await env.public.post(
        "/v1/signup", json={"org_name": org, "email": email, "password": password}
    )


async def provision_tenant(
    env: Env,
    *,
    email: str = "admin@acme.example",
    org: str = "Acme GmbH",
    password: str = DEFAULT_PASSWORD,
) -> uuid.UUID:
    """Full signup -> verify -> saga completion. Returns the tenant UUID."""
    response = await do_signup(env, email=email, org=org, password=password)
    assert response.status_code == 202, response.text
    token = env.mailer.last_token()
    verified = await env.public.post("/v1/signup/verify", json={"token": token})
    assert verified.status_code == 200, verified.text
    tenant_public = verified.json()["tenant_id"]
    await env.drain_background()
    return uuid.UUID(tenant_public.removeprefix("tn_"))


async def login(
    env: Env,
    *,
    email: str = "admin@acme.example",
    password: str = DEFAULT_PASSWORD,
    client: httpx.AsyncClient | None = None,
) -> httpx.Response:
    return await (client or env.public).post(
        "/v1/auth/login", json={"email": email, "password": password}
    )


async def create_active_user(
    env: Env,
    tenant_id: uuid.UUID,
    *,
    email: str,
    role: str,
    password: str = DEFAULT_PASSWORD,
) -> uuid.UUID:
    """Directly seed an active user (the invite-accept endpoint is not yet ratified)."""
    password_hash = await env.services.passwords.hash(password)
    user_id = uuid.uuid4()
    env.db.users[user_id] = {
        "id": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "role": role,
        "state": "active",
        "password_hash": password_hash,
        "failed_login_count": 0,
        "locked_until": None,
        "created_at": env.db._tick(),
        "deleted_at": None,
    }
    return user_id


def make_second_tenant(env: Env, *, name: str = "Other Org") -> uuid.UUID:
    """Directly seed a second active tenant for cross-tenant (404) tests."""
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    env.db.tenants[tenant_id] = {
        "id": tenant_id,
        "account_id": account_id,
        "name": name,
        "status": "active",
        "abuse_frozen": False,
        "abuse_frozen_reason": None,
        "plan_id": "trial",
        "trial_expires_at": None,
        "provisioned_at": env.clock(),
    }
    return tenant_id
