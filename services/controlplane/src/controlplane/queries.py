"""All control-plane SQL, as named constants (asyncpg placeholder style).

Centralizing the statements keeps every data access reviewable for tenant
scoping and lets unit tests dispatch a fake asyncpg-like connection on the
exact statement identity (see services/controlplane/tests/fakes.py).

Schema is BINDING per db/migrations/0003_control_tables.sql. Time-sensitive
predicates take the timestamp as a parameter (deterministic under test);
audit rows use the DB clock via soc_audit.AUDIT_INSERT_SQL (SEC-45).
"""

SELECT_ONE = "SELECT 1"

RLS_PROBE = "SELECT current_setting('app.tenant_id', true)"

# --- accounts (AC-1..8) ----------------------------------------------------

INSERT_ACCOUNT = """\
INSERT INTO control.accounts (org_name, email, email_domain, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING id\
"""

SELECT_ACCOUNT_BY_DOMAIN = """\
SELECT id FROM control.accounts WHERE lower(email_domain) = lower($1)\
"""

SELECT_ACCOUNT_BY_EMAIL = """\
SELECT id, org_name, email, state, password_hash
FROM control.accounts WHERE lower(email) = lower($1)\
"""

SELECT_ACCOUNT_BY_ID = """\
SELECT id, org_name, email, state, password_hash
FROM control.accounts WHERE id = $1\
"""

MARK_ACCOUNT_VERIFIED = """\
UPDATE control.accounts SET state = 'verified' WHERE id = $1\
"""

# --- email_verifications (SEC-2: hashed at rest, single-use CAS) -----------

INSERT_VERIFICATION = """\
INSERT INTO control.email_verifications (purpose, account_id, user_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id\
"""

CONSUME_VERIFICATION = """\
UPDATE control.email_verifications
SET used_at = $2
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
RETURNING id, purpose, account_id, user_id\
"""

SELECT_VERIFICATION_BY_HASH = """\
SELECT id, purpose, account_id, user_id, expires_at, used_at
FROM control.email_verifications WHERE token_hash = $1\
"""

# --- tenants ---------------------------------------------------------------

INSERT_TENANT = """\
INSERT INTO control.tenants (account_id, name, status, plan_id)
VALUES ($1, $2, 'provisioning', 'trial')
RETURNING id\
"""

SELECT_TENANT_BY_ID = """\
SELECT id, account_id, name, status, abuse_frozen, abuse_frozen_reason,
       plan_id, trial_expires_at
FROM control.tenants WHERE id = $1\
"""

SELECT_TENANT_BY_ACCOUNT = """\
SELECT id, account_id, name, status, abuse_frozen, abuse_frozen_reason,
       plan_id, trial_expires_at
FROM control.tenants WHERE account_id = $1\
"""

SET_TENANT_ACTIVE = """\
UPDATE control.tenants
SET status = 'active', trial_expires_at = $2, provisioned_at = $3, updated_at = $3
WHERE id = $1\
"""

SET_TENANT_PROVISIONING_FAILED = """\
UPDATE control.tenants SET status = 'provisioning_failed', updated_at = $2 WHERE id = $1\
"""

UPDATE_TENANT_PLAN = """\
UPDATE control.tenants
SET plan_id = $2,
    trial_expires_at = CASE WHEN $2 = 'trial' THEN trial_expires_at ELSE NULL END,
    status = CASE WHEN $2 <> 'trial' AND status = 'frozen'
                  THEN 'active'::control.tenant_status ELSE status END,
    updated_at = $3
WHERE id = $1
RETURNING plan_id, status, trial_expires_at\
"""

UPDATE_TENANT_ABUSE_FREEZE = """\
UPDATE control.tenants
SET abuse_frozen = $2, abuse_frozen_reason = $3, abuse_frozen_at = $4, updated_at = $4
WHERE id = $1
RETURNING abuse_frozen\
"""

# --- users (AC-77/78) ------------------------------------------------------

INSERT_ADMIN_USER = """\
INSERT INTO control.users (tenant_id, email, role, state, password_hash)
VALUES ($1, $2, 'admin', 'active', $3)
ON CONFLICT (tenant_id, lower(email)) WHERE deleted_at IS NULL DO NOTHING\
"""

SELECT_USER_FOR_LOGIN = """\
SELECT u.id, u.tenant_id, u.email, u.role, u.state, u.password_hash,
       u.failed_login_count, u.locked_until,
       t.name AS tenant_name, t.status AS tenant_status,
       t.abuse_frozen, t.trial_expires_at
FROM control.users u
JOIN control.tenants t ON t.id = u.tenant_id
WHERE lower(u.email) = lower($1) AND u.deleted_at IS NULL
ORDER BY u.created_at
LIMIT 1\
"""

SELECT_USER_WITH_TENANT = """\
SELECT u.id, u.email, u.role, u.state,
       t.id AS tenant_id, t.name AS tenant_name, t.status AS tenant_status,
       t.abuse_frozen, t.trial_expires_at
FROM control.users u
JOIN control.tenants t ON t.id = u.tenant_id
WHERE u.id = $1 AND u.deleted_at IS NULL\
"""

SELECT_USER_AUTH_BY_ID = """\
SELECT id, password_hash FROM control.users WHERE id = $1 AND deleted_at IS NULL\
"""

SELECT_USER_IN_TENANT = """\
SELECT id, email, role, state, created_at
FROM control.users
WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL\
"""

SELECT_USER_BY_TENANT_EMAIL = """\
SELECT id FROM control.users
WHERE tenant_id = $1 AND lower(email) = lower($2) AND deleted_at IS NULL\
"""

LIST_USERS = """\
SELECT id, email, role, state, created_at
FROM control.users
WHERE tenant_id = $1 AND deleted_at IS NULL
ORDER BY created_at\
"""

INSERT_INVITED_USER = """\
INSERT INTO control.users (tenant_id, email, role, state)
VALUES ($1, $2, $3, 'invited')
RETURNING id, created_at\
"""

UPDATE_USER_ROLE = """\
UPDATE control.users SET role = $3, updated_at = $4
WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
RETURNING id, role\
"""

SOFT_DELETE_USER = """\
UPDATE control.users SET deleted_at = $3, updated_at = $3
WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
RETURNING id\
"""

ACTIVATE_INVITED_USER = """\
UPDATE control.users
SET state = 'active', password_hash = $2, password_changed_at = $3, updated_at = $3
WHERE id = $1 AND deleted_at IS NULL AND state = 'invited'
RETURNING id, tenant_id, email, role\
"""

UPDATE_USER_PASSWORD = """\
UPDATE control.users SET password_hash = $2, password_changed_at = $3, updated_at = $3
WHERE id = $1\
"""  # noqa: S105 - SQL statement, not a credential

RECORD_LOGIN_FAILURE = """\
UPDATE control.users
SET failed_login_count = failed_login_count + 1, locked_until = $2, updated_at = $3
WHERE id = $1\
"""

RESET_LOGIN_FAILURES = """\
UPDATE control.users
SET failed_login_count = 0, locked_until = NULL, updated_at = $2
WHERE id = $1\
"""

# --- sessions metadata (SEC-3; Redis sess:{sid} is the live store) ----------

INSERT_SESSION = """\
INSERT INTO control.sessions
    (session_id_hash, user_id, tenant_id, absolute_expires_at, ip, user_agent,
     created_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)\
"""

REVOKE_SESSION = """\
UPDATE control.sessions SET revoked_at = $2, revoke_reason = $3
WHERE session_id_hash = $1 AND revoked_at IS NULL\
"""

REVOKE_USER_SESSIONS = """\
UPDATE control.sessions SET revoked_at = $2, revoke_reason = $3
WHERE user_id = $1 AND revoked_at IS NULL\
"""

REVOKE_USER_SESSIONS_EXCEPT = """\
UPDATE control.sessions SET revoked_at = $2, revoke_reason = $3
WHERE user_id = $1 AND revoked_at IS NULL AND session_id_hash <> $4\
"""

# --- provisioning saga (AC-3/5, design §5) ----------------------------------

INSERT_SAGA = """\
INSERT INTO control.provisioning_sagas (account_id, idempotency_key)
VALUES ($1, $2)
ON CONFLICT (account_id) DO NOTHING
RETURNING id\
"""

SELECT_SAGA_BY_ACCOUNT = """\
SELECT id, account_id, tenant_id, state, current_step
FROM control.provisioning_sagas WHERE account_id = $1\
"""

SELECT_SAGA = """\
SELECT id, account_id, tenant_id, state, current_step
FROM control.provisioning_sagas WHERE id = $1\
"""

SELECT_RUNNING_SAGAS = """\
SELECT id FROM control.provisioning_sagas WHERE state = 'running'\
"""

UPDATE_SAGA_TENANT = """\
UPDATE control.provisioning_sagas SET tenant_id = $2, updated_at = $3 WHERE id = $1\
"""

UPDATE_SAGA_PROGRESS = """\
UPDATE control.provisioning_sagas SET current_step = $2, updated_at = $3 WHERE id = $1\
"""

COMPLETE_SAGA = """\
UPDATE control.provisioning_sagas
SET state = $2, last_error = $3, completed_at = $4, updated_at = $4
WHERE id = $1\
"""

INSERT_SAGA_STEP = """\
INSERT INTO control.provisioning_saga_steps (saga_id, step)
VALUES ($1, $2)
ON CONFLICT (saga_id, step) DO NOTHING\
"""

SELECT_SAGA_STEPS = """\
SELECT step, status, attempts, last_error
FROM control.provisioning_saga_steps WHERE saga_id = $1\
"""

MARK_SAGA_STEP = """\
UPDATE control.provisioning_saga_steps
SET status = $3, attempts = $4, last_error = $5, completed_at = $6
WHERE saga_id = $1 AND step = $2\
"""

# --- plans / config / overrides (AC-11..18) ---------------------------------

SELECT_PLAN_CONFIG = """\
SELECT key, value::text AS value FROM control.plan_config WHERE plan_id = $1\
"""

SELECT_PLAN_EXISTS = """\
SELECT id FROM control.plans WHERE id = $1\
"""

SELECT_PLATFORM_CONFIG_VALUE = """\
SELECT value::text AS value FROM control.platform_config WHERE key = $1\
"""

SELECT_ENTITLEMENT_OVERRIDES = """\
SELECT key, value::text AS value
FROM control.entitlement_overrides
WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > $2)\
"""

# --- signup abuse log (AC-8/SEC-5) ------------------------------------------

INSERT_SIGNUP_ABUSE_LOG = """\
INSERT INTO control.signup_abuse_log (email, email_domain, source_ip, outcome, reason)
VALUES ($1, $2, $3, $4, $5)\
"""
