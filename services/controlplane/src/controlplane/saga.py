"""Provisioning saga (AC-3/AC-5, design §5): idempotent persisted step machine.

Steps, in order (control.provisioning_saga_steps CHECK constraint is binding):
  tenant_row   -> create control.tenants row (status 'provisioning')
  rls_context  -> validate RLS tenant context is usable (SET LOCAL + probe)
  es_index     -> PUT dataplane /internal/v1/tenants/{id}/provision (HMAC
                  service token; contract §13 — controlplane never touches ES)
  entitlements -> compose Trial entitlements + warm ent:{t} (validates plan
                  config is usable)
  admin_user   -> create the first admin user from the signup account
  trial_expiry -> set trial_expires_at + flip tenant to 'active'

Idempotency: one saga per account (UNIQUE), completed steps are skipped on
re-run, and every step body is itself idempotent (ON CONFLICT DO NOTHING /
idempotent dataplane call / absolute UPDATEs). Terminal failure => tenant
status 'provisioning_failed', ops alert log + audit, and the status endpoint
surfaces it (AC-5). No session is issuable for non-active tenants.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta
from typing import Any
from uuid import UUID

from controlplane import queries
from controlplane.auditing import audit_standalone
from controlplane.config import Settings
from soc_audit import Actor, Target
from soc_entitlements import generate_service_token
from soc_tenancy import set_local_tenant

logger = logging.getLogger(__name__)

STEP_ORDER = (
    "tenant_row",
    "rls_context",
    "es_index",
    "entitlements",
    "admin_user",
    "trial_expiry",
)

_SAGA_ACTOR = Actor(type="system", id="controlplane-provisioning-saga")
DEFAULT_TRIAL_DURATION_DAYS = 14


class SagaStepError(Exception):
    """A step attempt failed; retried up to settings.saga_step_max_attempts."""


class ProvisioningSagaRunner:
    def __init__(
        self,
        *,
        db: Any,
        entitlements: Any,
        tenant_status: Any,
        dataplane_client: Any,
        settings: Settings,
        clock,
    ) -> None:
        self._db = db
        self._entitlements = entitlements
        self._tenant_status = tenant_status
        self._dataplane = dataplane_client
        self._settings = settings
        self._clock = clock

    # -- lifecycle ------------------------------------------------------------

    async def ensure_started(self, account_id: UUID, org_name: str) -> tuple[UUID, UUID]:
        """Create (or fetch) the saga for an account and run the tenant_row step
        synchronously so the verify response can carry the tenant id.

        Returns (saga_id, tenant_id). Idempotent: safe under verify retries.
        """
        now = self._clock()
        async with self._db.acquire() as conn:
            await conn.fetchrow(queries.INSERT_SAGA, account_id, f"signup:{account_id}")
            saga = await conn.fetchrow(queries.SELECT_SAGA_BY_ACCOUNT, account_id)
            for step in STEP_ORDER:
                await conn.execute(queries.INSERT_SAGA_STEP, saga["id"], step)

            tenant_id = saga["tenant_id"]
            if tenant_id is None:
                row = await conn.fetchrow(queries.INSERT_TENANT, account_id, org_name)
                tenant_id = row["id"]
                await conn.execute(queries.UPDATE_SAGA_TENANT, saga["id"], tenant_id, now)
                await conn.execute(
                    queries.MARK_SAGA_STEP, saga["id"], "tenant_row", "done", 1, None, now
                )
        return saga["id"], tenant_id

    async def run(self, saga_id: UUID) -> str:
        """Drive the saga to 'succeeded' or terminal 'failed'. Idempotent."""
        async with self._db.acquire() as conn:
            saga = await conn.fetchrow(queries.SELECT_SAGA, saga_id)
            if saga is None:
                raise RuntimeError(f"unknown saga {saga_id}")
            if saga["state"] != "running":
                return saga["state"]
            step_rows = await conn.fetch(queries.SELECT_SAGA_STEPS, saga_id)
        steps = {row["step"]: dict(row) for row in step_rows}
        tenant_id: UUID | None = saga["tenant_id"]
        account_id: UUID = saga["account_id"]

        for step in STEP_ORDER:
            state = steps.get(step, {"status": "pending", "attempts": 0})
            if state["status"] == "done":
                continue
            attempts = int(state["attempts"])
            done = False
            last_error = ""
            while attempts < self._settings.saga_step_max_attempts:
                attempts += 1
                try:
                    await self._execute_step(step, account_id=account_id, tenant_id=tenant_id)
                    done = True
                    break
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "provisioning saga step failed",
                        extra={
                            "saga_id": str(saga_id),
                            "step": step,
                            "attempt": attempts,
                            "error": last_error,
                        },
                    )
                    if attempts < self._settings.saga_step_max_attempts:
                        await asyncio.sleep(self._settings.saga_retry_delay_seconds)
            now = self._clock()
            async with self._db.acquire() as conn:
                await conn.execute(
                    queries.MARK_SAGA_STEP,
                    saga_id,
                    step,
                    "done" if done else "failed",
                    attempts,
                    None if done else last_error[:2000],
                    now if done else None,
                )
                await conn.execute(queries.UPDATE_SAGA_PROGRESS, saga_id, step, now)
            if not done:
                await self._fail_terminally(saga_id, tenant_id, step, last_error)
                return "failed"

        now = self._clock()
        async with self._db.acquire() as conn:
            await conn.execute(queries.COMPLETE_SAGA, saga_id, "succeeded", None, now)
        return "succeeded"

    async def resume_running(self) -> list[asyncio.Task]:
        """Restart-recovery: schedule every saga still in 'running' (AC-5)."""
        async with self._db.acquire() as conn:
            rows = await conn.fetch(queries.SELECT_RUNNING_SAGAS)
        return [asyncio.create_task(self.run(row["id"])) for row in rows]

    # -- steps ----------------------------------------------------------------

    async def _execute_step(self, step: str, *, account_id: UUID, tenant_id: UUID | None) -> None:
        if step == "tenant_row":
            # Executed by ensure_started; reaching here pending means the verify
            # transaction half-applied — treat missing tenant as a failure.
            if tenant_id is None:
                raise SagaStepError("tenant_row pending but no tenant id recorded")
            return
        if tenant_id is None:
            raise SagaStepError(f"step {step} requires a tenant id")
        if step == "rls_context":
            await self._step_rls_context(tenant_id)
        elif step == "es_index":
            await self._step_es_index(tenant_id)
        elif step == "entitlements":
            await self._entitlements.warm(tenant_id)
        elif step == "admin_user":
            await self._step_admin_user(account_id, tenant_id)
        elif step == "trial_expiry":
            await self._step_trial_expiry(tenant_id)
        else:  # pragma: no cover - guarded by STEP_ORDER
            raise SagaStepError(f"unknown step {step}")

    async def _step_rls_context(self, tenant_id: UUID) -> None:
        """SET LOCAL app.tenant_id + probe round-trip (design §5 saga row)."""
        async with self._db.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant_id)
                value = await conn.fetchval(queries.RLS_PROBE)
                if value != str(tenant_id):
                    raise SagaStepError(f"RLS GUC probe mismatch: {value!r}")

    async def _step_es_index(self, tenant_id: UUID) -> None:
        """Cross-plane provision call (contract §13), HMAC service token (§5.1)."""
        if not self._settings.outbound_service_key:
            raise SagaStepError("CP_OUTBOUND_SERVICE_KEY is not configured")
        token = generate_service_token(
            service_name=self._settings.outbound_service_name,
            key=self._settings.outbound_service_key,
        )
        response = await self._dataplane.put(
            f"/internal/v1/tenants/{tenant_id}/provision",
            json={"tenant_id": str(tenant_id)},
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code not in (200, 201, 204):
            raise SagaStepError(f"dataplane provision returned {response.status_code}")

    async def _step_admin_user(self, account_id: UUID, tenant_id: UUID) -> None:
        async with self._db.acquire() as conn:
            account = await conn.fetchrow(queries.SELECT_ACCOUNT_BY_ID, account_id)
            if account is None:
                raise SagaStepError(f"account {account_id} not found")
            await conn.execute(
                queries.INSERT_ADMIN_USER, tenant_id, account["email"], account["password_hash"]
            )

    async def _step_trial_expiry(self, tenant_id: UUID) -> None:
        now = self._clock()
        duration_days = await self._trial_duration_days()
        expires = now + timedelta(days=duration_days)
        async with self._db.acquire() as conn:
            async with conn.transaction():
                await set_local_tenant(conn, tenant_id)
                await conn.execute(queries.SET_TENANT_ACTIVE, tenant_id, expires, now)
                await audit_write_provisioned(conn, tenant_id, expires)
        # Status changed provisioning -> active: delete-on-change (SEC-39).
        await self._entitlements.invalidate(tenant_id)

    async def _trial_duration_days(self) -> int:
        async with self._db.acquire() as conn:
            rows = await conn.fetch(queries.SELECT_PLAN_CONFIG, "trial")
        for row in rows:
            if row["key"] == "trial_duration_days":
                return int(json.loads(row["value"]))
        return DEFAULT_TRIAL_DURATION_DAYS

    # -- terminal failure (AC-5) ----------------------------------------------

    async def _fail_terminally(
        self, saga_id: UUID, tenant_id: UUID | None, step: str, error: str
    ) -> None:
        now = self._clock()
        async with self._db.acquire() as conn:
            await conn.execute(
                queries.COMPLETE_SAGA, saga_id, "failed", f"{step}: {error}"[:2000], now
            )
            if tenant_id is not None:
                await conn.execute(queries.SET_TENANT_PROVISIONING_FAILED, tenant_id, now)
        if tenant_id is not None:
            await self._tenant_status.invalidate(tenant_id)
            try:
                await audit_standalone(
                    self._db,
                    tenant_id=tenant_id,
                    actor=_SAGA_ACTOR,
                    action_type="tenant.provisioning_failed",
                    target=Target(type="tenant", id=str(tenant_id)),
                    after={"status": "provisioning_failed", "failed_step": step},
                    reason_code="saga_terminal_failure",
                )
            except Exception:
                logger.exception("failed to audit provisioning failure")
        # Ops alert: structured ERROR log — observability alerts on this (AC-5).
        logger.error(
            "OPS ALERT: provisioning saga terminally failed",
            extra={
                "saga_id": str(saga_id),
                "tenant_id": str(tenant_id) if tenant_id else None,
                "failed_step": step,
                "error": error,
            },
        )


async def audit_write_provisioned(conn: Any, tenant_id: UUID, expires) -> None:
    """Same-transaction audit for the activation state change (SEC-43)."""
    from soc_audit import write_audit

    await write_audit(
        conn,
        tenant_id=tenant_id,
        actor=_SAGA_ACTOR,
        action_type="tenant.provisioned",
        target=Target(type="tenant", id=str(tenant_id)),
        after={"status": "active", "trial_expires_at": expires.isoformat()},
    )
