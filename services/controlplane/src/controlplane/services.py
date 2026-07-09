"""Composition root: everything request handlers reach via app.state.services.

Built once per process — from real clients in the runtime lifespan, or from
fakes in unit tests (no live PG/ES/Redis required).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from controlplane.abuse import ChallengeVerifier, load_disposable_domains
from controlplane.config import Settings
from controlplane.entitlements import EntitlementsService
from controlplane.mailer import Mailer
from controlplane.saga import ProvisioningSagaRunner
from controlplane.security.passwords import BreachedPasswordChecker, PasswordService
from controlplane.sessions import SessionStore
from controlplane.tenantstatus import TenantStatusStore

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class AppServices:
    settings: Settings
    db: Any
    redis: Any
    mailer: Mailer
    breached_checker: BreachedPasswordChecker
    challenge_verifier: ChallengeVerifier
    dataplane_client: Any
    clock: Clock
    passwords: PasswordService
    sessions: SessionStore
    tenant_status: TenantStatusStore
    entitlements: EntitlementsService
    saga: ProvisioningSagaRunner
    disposable_domains: frozenset[str]
    background_tasks: set[asyncio.Task] = field(default_factory=set)

    def spawn(self, coro) -> asyncio.Task:
        """Track background tasks (saga runs) so they are awaitable/cancellable."""
        task = asyncio.create_task(coro)
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)
        return task


def build_services(
    *,
    settings: Settings,
    db: Any,
    redis: Any,
    mailer: Mailer,
    breached_checker: BreachedPasswordChecker,
    challenge_verifier: ChallengeVerifier,
    dataplane_client: Any,
    clock: Clock = utc_now,
    password_service: PasswordService | None = None,
    disposable_domains: frozenset[str] | None = None,
) -> AppServices:
    passwords = password_service or PasswordService()
    sessions = SessionStore(db=db, redis=redis, clock=clock, settings=settings)
    tenant_status = TenantStatusStore(db=db, redis=redis)
    entitlements = EntitlementsService(db=db, redis=redis, clock=clock)
    saga = ProvisioningSagaRunner(
        db=db,
        entitlements=entitlements,
        tenant_status=tenant_status,
        dataplane_client=dataplane_client,
        settings=settings,
        clock=clock,
    )
    return AppServices(
        settings=settings,
        db=db,
        redis=redis,
        mailer=mailer,
        breached_checker=breached_checker,
        challenge_verifier=challenge_verifier,
        dataplane_client=dataplane_client,
        clock=clock,
        passwords=passwords,
        sessions=sessions,
        tenant_status=tenant_status,
        entitlements=entitlements,
        saga=saga,
        disposable_domains=(
            disposable_domains if disposable_domains is not None else load_disposable_domains()
        ),
    )
