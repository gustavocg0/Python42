"""Test fakes: in-memory asyncpg-like DB (dispatching on the exact SQL
constants from controlplane.queries — same pattern as packages/audit/tests),
mailer, challenge verifier, and a mock dataplane."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx

from controlplane import queries
from soc_audit import AUDIT_INSERT_SQL
from soc_tenancy import SET_TENANT_GUC_SQL


class MutableClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now = self.now + timedelta(**kwargs)


class InjectedFailure(RuntimeError):
    pass


class _NullTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Acquire:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, db: FakeDb) -> None:
        self._db = db

    def transaction(self):
        return _NullTransaction()

    async def fetchrow(self, sql: str, *args):
        rows = self._db.dispatch(sql, args)
        return rows[0] if rows else None

    async def fetch(self, sql: str, *args):
        return self._db.dispatch(sql, args)

    async def fetchval(self, sql: str, *args):
        rows = self._db.dispatch(sql, args)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    async def execute(self, sql: str, *args):
        self._db.dispatch(sql, args)
        return "OK"


class FakeDb:
    """In-memory stand-in for the asyncpg pool + control-schema tables."""

    def __init__(self, clock: MutableClock | None = None) -> None:
        self.clock = clock or MutableClock()
        self.accounts: dict[uuid.UUID, dict] = {}
        self.verifications: dict[uuid.UUID, dict] = {}
        self.tenants: dict[uuid.UUID, dict] = {}
        self.users: dict[uuid.UUID, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.sagas: dict[uuid.UUID, dict] = {}
        self.saga_steps: dict[tuple[uuid.UUID, str], dict] = {}
        self.plan_config: dict[tuple[str, str], str] = {}
        self.platform_config: dict[str, str] = {}
        self.overrides: dict[tuple[uuid.UUID, str], dict] = {}
        self.abuse_log: list[dict] = []
        self.audit_log: list[dict] = []
        self.guc_tenant: str | None = None
        self.fail_on: dict[str, int] = {}
        self._seq = 0
        self._conn = FakeConn(self)

    def acquire(self):
        return _Acquire(self._conn)

    async def close(self):  # pool-compat
        return None

    def inject_failure(self, sql: str, times: int = 1) -> None:
        self.fail_on[sql] = times

    def _now(self) -> datetime:
        return self.clock()

    def _tick(self) -> datetime:
        # Strictly increasing timestamps for ORDER BY created_at determinism.
        self._seq += 1
        return self._now() + timedelta(microseconds=self._seq)

    # -- dispatch --------------------------------------------------------------

    def dispatch(self, sql: str, args: tuple) -> list[dict]:
        remaining = self.fail_on.get(sql, 0)
        if remaining > 0:
            self.fail_on[sql] = remaining - 1
            raise InjectedFailure(f"injected failure for {sql.splitlines()[0]!r}")
        handler = _HANDLERS.get(sql)
        if handler is None:
            raise AssertionError(f"FakeDb has no handler for SQL: {sql!r}")
        return handler(self, args) or []


# --- handlers ----------------------------------------------------------------


def _h_select_one(db, args):
    return [{"?column?": 1}]


def _h_set_guc(db, args):
    db.guc_tenant = args[0]
    return [{"set_config": args[0]}]


def _h_rls_probe(db, args):
    return [{"current_setting": db.guc_tenant}]


def _h_audit_insert(db, args):
    db.audit_log.append(
        {
            "tenant_id": args[0],
            "actor_type": args[1],
            "actor_id": args[2],
            "action_type": args[3],
            "target_type": args[4],
            "target_id": args[5],
            "before": args[6],
            "after": args[7],
            "reason_code": args[8],
        }
    )
    return []


def _h_insert_account(db, args):
    org_name, email, domain, password_hash = args
    for row in db.accounts.values():
        if row["email"].lower() == email.lower() or row["email_domain"] == domain.lower():
            raise RuntimeError("unique violation: accounts")
    account_id = uuid.uuid4()
    db.accounts[account_id] = {
        "id": account_id,
        "org_name": org_name,
        "email": email,
        "email_domain": domain.lower(),
        "password_hash": password_hash,
        "state": "pending_verification",
        "created_at": db._tick(),
    }
    return [{"id": account_id}]


def _account_row(row):
    return {
        "id": row["id"],
        "org_name": row["org_name"],
        "email": row["email"],
        "state": row["state"],
        "password_hash": row["password_hash"],
    }


def _h_account_by_domain(db, args):
    return [
        {"id": r["id"]}
        for r in db.accounts.values()
        if r["email_domain"] == args[0].lower()
    ]


def _h_account_by_email(db, args):
    return [
        _account_row(r) for r in db.accounts.values() if r["email"].lower() == args[0].lower()
    ]


def _h_account_by_id(db, args):
    row = db.accounts.get(args[0])
    return [_account_row(row)] if row else []


def _h_mark_verified(db, args):
    if args[0] in db.accounts:
        db.accounts[args[0]]["state"] = "verified"
    return []


def _h_insert_verification(db, args):
    purpose, account_id, user_id, token_hash, expires_at = args
    vid = uuid.uuid4()
    db.verifications[vid] = {
        "id": vid,
        "purpose": purpose,
        "account_id": account_id,
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "used_at": None,
    }
    return [{"id": vid}]


def _h_consume_verification(db, args):
    token_hash, now = args
    for row in db.verifications.values():
        if row["token_hash"] == token_hash and row["used_at"] is None and row["expires_at"] > now:
            row["used_at"] = now
            return [
                {
                    "id": row["id"],
                    "purpose": row["purpose"],
                    "account_id": row["account_id"],
                    "user_id": row["user_id"],
                }
            ]
    return []


def _h_verification_by_hash(db, args):
    return [dict(r) for r in db.verifications.values() if r["token_hash"] == args[0]]


def _h_insert_tenant(db, args):
    account_id, name = args
    tenant_id = uuid.uuid4()
    db.tenants[tenant_id] = {
        "id": tenant_id,
        "account_id": account_id,
        "name": name,
        "status": "provisioning",
        "abuse_frozen": False,
        "abuse_frozen_reason": None,
        "plan_id": "trial",
        "trial_expires_at": None,
        "provisioned_at": None,
    }
    return [{"id": tenant_id}]


def _tenant_row(t):
    return {
        "id": t["id"],
        "account_id": t["account_id"],
        "name": t["name"],
        "status": t["status"],
        "abuse_frozen": t["abuse_frozen"],
        "abuse_frozen_reason": t["abuse_frozen_reason"],
        "plan_id": t["plan_id"],
        "trial_expires_at": t["trial_expires_at"],
    }


def _h_tenant_by_id(db, args):
    t = db.tenants.get(args[0])
    return [_tenant_row(t)] if t else []


def _h_tenant_by_account(db, args):
    return [_tenant_row(t) for t in db.tenants.values() if t["account_id"] == args[0]]


def _h_set_tenant_active(db, args):
    tenant_id, expires, now = args
    t = db.tenants.get(tenant_id)
    if t:
        t["status"] = "active"
        t["trial_expires_at"] = expires
        t["provisioned_at"] = now
    return []


def _h_set_tenant_failed(db, args):
    t = db.tenants.get(args[0])
    if t:
        t["status"] = "provisioning_failed"
    return []


def _h_update_tenant_plan(db, args):
    tenant_id, plan, _now = args
    t = db.tenants.get(tenant_id)
    if not t:
        return []
    t["plan_id"] = plan
    if plan != "trial":
        t["trial_expires_at"] = None
        if t["status"] == "frozen":
            t["status"] = "active"
    return [
        {"plan_id": t["plan_id"], "status": t["status"], "trial_expires_at": t["trial_expires_at"]}
    ]


def _h_update_abuse_freeze(db, args):
    tenant_id, frozen, reason, now = args
    t = db.tenants.get(tenant_id)
    if not t:
        return []
    t["abuse_frozen"] = frozen
    t["abuse_frozen_reason"] = reason
    t["abuse_frozen_at"] = now
    return [{"abuse_frozen": frozen}]


def _live_users(db):
    return [u for u in db.users.values() if u["deleted_at"] is None]


def _h_insert_admin_user(db, args):
    tenant_id, email, password_hash = args
    for u in _live_users(db):
        if u["tenant_id"] == tenant_id and u["email"].lower() == email.lower():
            return []  # ON CONFLICT DO NOTHING
    user_id = uuid.uuid4()
    db.users[user_id] = {
        "id": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "role": "admin",
        "state": "active",
        "password_hash": password_hash,
        "failed_login_count": 0,
        "locked_until": None,
        "created_at": db._tick(),
        "deleted_at": None,
    }
    return []


def _h_user_for_login(db, args):
    matches = sorted(
        (u for u in _live_users(db) if u["email"].lower() == args[0].lower()),
        key=lambda u: u["created_at"],
    )
    rows = []
    for u in matches[:1]:
        t = db.tenants[u["tenant_id"]]
        rows.append(
            {
                "id": u["id"],
                "tenant_id": u["tenant_id"],
                "email": u["email"],
                "role": u["role"],
                "state": u["state"],
                "password_hash": u["password_hash"],
                "failed_login_count": u["failed_login_count"],
                "locked_until": u["locked_until"],
                "tenant_name": t["name"],
                "tenant_status": t["status"],
                "abuse_frozen": t["abuse_frozen"],
                "trial_expires_at": t["trial_expires_at"],
            }
        )
    return rows


def _h_user_with_tenant(db, args):
    u = db.users.get(args[0])
    if not u or u["deleted_at"] is not None:
        return []
    t = db.tenants[u["tenant_id"]]
    return [
        {
            "id": u["id"],
            "email": u["email"],
            "role": u["role"],
            "state": u["state"],
            "tenant_id": t["id"],
            "tenant_name": t["name"],
            "tenant_status": t["status"],
            "abuse_frozen": t["abuse_frozen"],
            "trial_expires_at": t["trial_expires_at"],
        }
    ]


def _h_user_auth_by_id(db, args):
    u = db.users.get(args[0])
    if not u or u["deleted_at"] is not None:
        return []
    return [{"id": u["id"], "password_hash": u["password_hash"]}]


def _h_activate_invited_user(db, args):
    user_id, password_hash, now = args
    u = db.users.get(user_id)
    if not u or u["deleted_at"] is not None or u["state"] != "invited":
        return []
    u["state"] = "active"
    u["password_hash"] = password_hash
    u["password_changed_at"] = now
    return [{"id": u["id"], "tenant_id": u["tenant_id"], "email": u["email"], "role": u["role"]}]


def _user_item(u):
    return {
        "id": u["id"],
        "email": u["email"],
        "role": u["role"],
        "state": u["state"],
        "created_at": u["created_at"],
    }


def _h_user_in_tenant(db, args):
    user_id, tenant_id = args
    u = db.users.get(user_id)
    if not u or u["deleted_at"] is not None or u["tenant_id"] != tenant_id:
        return []
    return [_user_item(u)]


def _h_user_by_tenant_email(db, args):
    tenant_id, email = args
    return [
        {"id": u["id"]}
        for u in _live_users(db)
        if u["tenant_id"] == tenant_id and u["email"].lower() == email.lower()
    ]


def _h_list_users(db, args):
    rows = sorted(
        (u for u in _live_users(db) if u["tenant_id"] == args[0]),
        key=lambda u: u["created_at"],
    )
    return [_user_item(u) for u in rows]


def _h_insert_invited_user(db, args):
    tenant_id, email, role = args
    for u in _live_users(db):
        if u["tenant_id"] == tenant_id and u["email"].lower() == email.lower():
            raise RuntimeError("unique violation: users")
    user_id = uuid.uuid4()
    created = db._tick()
    db.users[user_id] = {
        "id": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "role": role,
        "state": "invited",
        "password_hash": None,
        "failed_login_count": 0,
        "locked_until": None,
        "created_at": created,
        "deleted_at": None,
    }
    return [{"id": user_id, "created_at": created}]


def _h_update_user_role(db, args):
    user_id, tenant_id, role, _now = args
    u = db.users.get(user_id)
    if not u or u["deleted_at"] is not None or u["tenant_id"] != tenant_id:
        return []
    u["role"] = role
    return [{"id": user_id, "role": role}]


def _h_soft_delete_user(db, args):
    user_id, tenant_id, now = args
    u = db.users.get(user_id)
    if not u or u["deleted_at"] is not None or u["tenant_id"] != tenant_id:
        return []
    u["deleted_at"] = now
    return [{"id": user_id}]


def _h_update_user_password(db, args):
    user_id, password_hash, now = args
    u = db.users.get(user_id)
    if u:
        u["password_hash"] = password_hash
        u["password_changed_at"] = now
    return []


def _h_record_login_failure(db, args):
    user_id, lock, _now = args
    u = db.users.get(user_id)
    if u:
        u["failed_login_count"] += 1
        u["locked_until"] = lock
    return []


def _h_reset_login_failures(db, args):
    u = db.users.get(args[0])
    if u:
        u["failed_login_count"] = 0
        u["locked_until"] = None
    return []


def _h_insert_session(db, args):
    sid_hash, user_id, tenant_id, absolute, ip, user_agent, now = args
    db.sessions[sid_hash] = {
        "session_id_hash": sid_hash,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "absolute_expires_at": absolute,
        "ip": ip,
        "user_agent": user_agent,
        "created_at": now,
        "revoked_at": None,
        "revoke_reason": None,
    }
    return []


def _h_revoke_session(db, args):
    sid_hash, now, reason = args
    s = db.sessions.get(sid_hash)
    if s and s["revoked_at"] is None:
        s["revoked_at"] = now
        s["revoke_reason"] = reason
    return []


def _h_revoke_user_sessions(db, args):
    user_id, now, reason = args
    for s in db.sessions.values():
        if s["user_id"] == user_id and s["revoked_at"] is None:
            s["revoked_at"] = now
            s["revoke_reason"] = reason
    return []


def _h_revoke_user_sessions_except(db, args):
    user_id, now, reason, keep_hash = args
    for s in db.sessions.values():
        if (
            s["user_id"] == user_id
            and s["revoked_at"] is None
            and s["session_id_hash"] != keep_hash
        ):
            s["revoked_at"] = now
            s["revoke_reason"] = reason
    return []


def _h_insert_saga(db, args):
    account_id, key = args
    for s in db.sagas.values():
        if s["account_id"] == account_id:
            return []  # ON CONFLICT DO NOTHING
    saga_id = uuid.uuid4()
    db.sagas[saga_id] = {
        "id": saga_id,
        "account_id": account_id,
        "idempotency_key": key,
        "tenant_id": None,
        "state": "running",
        "current_step": None,
        "last_error": None,
        "completed_at": None,
    }
    return [{"id": saga_id}]


def _saga_row(s):
    return {
        "id": s["id"],
        "account_id": s["account_id"],
        "tenant_id": s["tenant_id"],
        "state": s["state"],
        "current_step": s["current_step"],
    }


def _h_saga_by_account(db, args):
    return [_saga_row(s) for s in db.sagas.values() if s["account_id"] == args[0]]


def _h_saga_by_id(db, args):
    s = db.sagas.get(args[0])
    return [_saga_row(s)] if s else []


def _h_running_sagas(db, args):
    return [{"id": s["id"]} for s in db.sagas.values() if s["state"] == "running"]


def _h_update_saga_tenant(db, args):
    saga_id, tenant_id, _now = args
    if saga_id in db.sagas:
        db.sagas[saga_id]["tenant_id"] = tenant_id
    return []


def _h_update_saga_progress(db, args):
    saga_id, step, _now = args
    if saga_id in db.sagas:
        db.sagas[saga_id]["current_step"] = step
    return []


def _h_complete_saga(db, args):
    saga_id, state, error, now = args
    s = db.sagas.get(saga_id)
    if s:
        s["state"] = state
        s["last_error"] = error
        s["completed_at"] = now
    return []


def _h_insert_saga_step(db, args):
    saga_id, step = args
    key = (saga_id, step)
    if key not in db.saga_steps:
        db.saga_steps[key] = {
            "saga_id": saga_id,
            "step": step,
            "status": "pending",
            "attempts": 0,
            "last_error": None,
            "completed_at": None,
        }
    return []


def _h_saga_steps(db, args):
    return [
        {
            "step": s["step"],
            "status": s["status"],
            "attempts": s["attempts"],
            "last_error": s["last_error"],
        }
        for (sid, _), s in db.saga_steps.items()
        if sid == args[0]
    ]


def _h_mark_saga_step(db, args):
    saga_id, step, status, attempts, last_error, completed_at = args
    s = db.saga_steps.get((saga_id, step))
    if s:
        s["status"] = status
        s["attempts"] = attempts
        s["last_error"] = last_error
        s["completed_at"] = completed_at
    return []


def _h_plan_config(db, args):
    return [
        {"key": key, "value": value}
        for (plan, key), value in db.plan_config.items()
        if plan == args[0]
    ]


def _h_plan_exists(db, args):
    return [{"id": args[0]}] if args[0] in ("trial", "core", "pro") else []


def _h_platform_config(db, args):
    value = db.platform_config.get(args[0])
    return [{"value": value}] if value is not None else []


def _h_overrides(db, args):
    tenant_id, now = args
    return [
        {"key": key, "value": row["value"]}
        for (tid, key), row in db.overrides.items()
        if tid == tenant_id and (row["expires_at"] is None or row["expires_at"] > now)
    ]


def _h_abuse_log(db, args):
    email, domain, ip, outcome, reason = args
    db.abuse_log.append(
        {"email": email, "email_domain": domain, "source_ip": ip, "outcome": outcome, "reason": reason}
    )
    return []


_HANDLERS = {
    queries.SELECT_ONE: _h_select_one,
    SET_TENANT_GUC_SQL: _h_set_guc,
    queries.RLS_PROBE: _h_rls_probe,
    AUDIT_INSERT_SQL: _h_audit_insert,
    queries.INSERT_ACCOUNT: _h_insert_account,
    queries.SELECT_ACCOUNT_BY_DOMAIN: _h_account_by_domain,
    queries.SELECT_ACCOUNT_BY_EMAIL: _h_account_by_email,
    queries.SELECT_ACCOUNT_BY_ID: _h_account_by_id,
    queries.MARK_ACCOUNT_VERIFIED: _h_mark_verified,
    queries.INSERT_VERIFICATION: _h_insert_verification,
    queries.CONSUME_VERIFICATION: _h_consume_verification,
    queries.SELECT_VERIFICATION_BY_HASH: _h_verification_by_hash,
    queries.INSERT_TENANT: _h_insert_tenant,
    queries.SELECT_TENANT_BY_ID: _h_tenant_by_id,
    queries.SELECT_TENANT_BY_ACCOUNT: _h_tenant_by_account,
    queries.SET_TENANT_ACTIVE: _h_set_tenant_active,
    queries.SET_TENANT_PROVISIONING_FAILED: _h_set_tenant_failed,
    queries.UPDATE_TENANT_PLAN: _h_update_tenant_plan,
    queries.UPDATE_TENANT_ABUSE_FREEZE: _h_update_abuse_freeze,
    queries.INSERT_ADMIN_USER: _h_insert_admin_user,
    queries.SELECT_USER_FOR_LOGIN: _h_user_for_login,
    queries.SELECT_USER_WITH_TENANT: _h_user_with_tenant,
    queries.SELECT_USER_AUTH_BY_ID: _h_user_auth_by_id,
    queries.ACTIVATE_INVITED_USER: _h_activate_invited_user,
    queries.SELECT_USER_IN_TENANT: _h_user_in_tenant,
    queries.SELECT_USER_BY_TENANT_EMAIL: _h_user_by_tenant_email,
    queries.LIST_USERS: _h_list_users,
    queries.INSERT_INVITED_USER: _h_insert_invited_user,
    queries.UPDATE_USER_ROLE: _h_update_user_role,
    queries.SOFT_DELETE_USER: _h_soft_delete_user,
    queries.UPDATE_USER_PASSWORD: _h_update_user_password,
    queries.RECORD_LOGIN_FAILURE: _h_record_login_failure,
    queries.RESET_LOGIN_FAILURES: _h_reset_login_failures,
    queries.INSERT_SESSION: _h_insert_session,
    queries.REVOKE_SESSION: _h_revoke_session,
    queries.REVOKE_USER_SESSIONS: _h_revoke_user_sessions,
    queries.REVOKE_USER_SESSIONS_EXCEPT: _h_revoke_user_sessions_except,
    queries.INSERT_SAGA: _h_insert_saga,
    queries.SELECT_SAGA_BY_ACCOUNT: _h_saga_by_account,
    queries.SELECT_SAGA: _h_saga_by_id,
    queries.SELECT_RUNNING_SAGAS: _h_running_sagas,
    queries.UPDATE_SAGA_TENANT: _h_update_saga_tenant,
    queries.UPDATE_SAGA_PROGRESS: _h_update_saga_progress,
    queries.COMPLETE_SAGA: _h_complete_saga,
    queries.INSERT_SAGA_STEP: _h_insert_saga_step,
    queries.SELECT_SAGA_STEPS: _h_saga_steps,
    queries.MARK_SAGA_STEP: _h_mark_saga_step,
    queries.SELECT_PLAN_CONFIG: _h_plan_config,
    queries.SELECT_PLAN_EXISTS: _h_plan_exists,
    queries.SELECT_PLATFORM_CONFIG_VALUE: _h_platform_config,
    queries.SELECT_ENTITLEMENT_OVERRIDES: _h_overrides,
    queries.INSERT_SIGNUP_ABUSE_LOG: _h_abuse_log,
}


def seed_plans(db: FakeDb) -> None:
    """Mirror db/migrations/0009_seed_plans.sql (values are JSON text)."""
    db.plan_config.update(
        {
            ("trial", "trial_duration_days"): "14",
            ("trial", "endpoint_cap"): "100",
            ("trial", "retention_days"): "14",
            ("trial", "deep_investigation_daily_quota"): "5",
            ("trial", "response_mode"): '"recommend_only"',
            ("trial", "ingest_events_per_min"): "5000",
            ("core", "endpoint_cap"): "250",
            ("core", "retention_days"): "30",
            ("core", "deep_investigation_daily_quota"): "5",
            ("core", "response_mode"): '"recommend_only"',
            ("core", "ingest_events_per_min"): "10000",
            ("pro", "endpoint_cap"): "1000",
            ("pro", "retention_days"): "90",
            ("pro", "deep_investigation_daily_quota"): "-1",
            ("pro", "response_mode"): '"playbooks_with_approval"',
            ("pro", "ingest_events_per_min"): "40000",
        }
    )
    db.platform_config.setdefault("signup_per_ip_hourly_threshold", "100")


class FakeMailer:
    def __init__(self) -> None:
        self.outbox: list[dict] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})

    def last_token(self) -> str:
        match = re.search(r"[?&]token=([^&\s]+)", self.outbox[-1]["body"])
        assert match, f"no token link in mail body: {self.outbox[-1]['body']!r}"
        return match.group(1)

    def last_link(self) -> str:
        match = re.search(r"https?://\S+", self.outbox[-1]["body"])
        assert match
        return match.group(0)


class FakeDataplane:
    """httpx.MockTransport backend for the dataplane internal provision API."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status_queue: list[int] = []  # pop-per-request; empty => 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.status_queue.pop(0) if self.status_queue else 200
        return httpx.Response(status, json={"status": "ok"})

    def client(self, base_url: str = "http://dataplane-internal") -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=base_url, transport=httpx.MockTransport(self.handler))


class AcceptAllChallenge:
    async def verify(self, *, response: str, ip: str | None) -> bool:
        return True
