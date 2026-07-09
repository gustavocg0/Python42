# Contract: Platform Foundation MVP — REST APIs v1

- **Status:** Ratified v1.1 — 2026-07-08 (amended per threat model: abuse-freeze semantics G-1/SEC-39, fail-closed 503 B-1/SEC-10/17, internal auth SEC-40)
- **Owner:** solution-architect (resolves PRD OQ-8; satisfies AC-9/14/17/26/30/44/45/47/53/54/56..61/77/78/81/86)
- **Consumers:** backend-architect (server), frontend-architect + ux-designer (console), endpoint-agent (agent APIs), ai-platform (triage/investigation fields), qa (contract tests)
- Changes to this file require Architect approval BEFORE implementation diverges.

## 1. Conventions

| Topic | Rule |
|---|---|
| Base paths | Console/tenant APIs: `/v1/...` on dataplane-api; signup/auth/entitlements: `/v1/...` on controlplane-api; internal-only: `/internal/v1/...` (network-restricted, service auth per design §5.1 / SEC-40) |
| Auth methods | (a) Session cookie `sid` (HttpOnly, Secure, SameSite=Lax) for console; (b) `X-Ingest-Key: <key>` for generic ingest; (c) mTLS device cert for agent routes (gateway strips + injects `X-Device-Id`, `X-Device-Tenant` per B-3/SEC-14 — clients can never supply these). CSRF token header required for cookie-authed mutating requests. |
| Roles | `admin` = all; `analyst` = read + alert triage + deep investigation. Role column per endpoint below. Enforced server-side, deny-by-default route declarations (AC-78, SEC-30). |
| Tenancy | Tenant is always derived from the credential. Resource IDs of other tenants ⇒ **404** `NOT_FOUND` (never 403) + security log (AC-81). |
| Timestamps | RFC3339 UTC everywhere. |
| IDs | Server-generated; prefixed opaque strings or UUIDs as listed. Clients treat all IDs as opaque. |
| Pagination | Cursor: request `?limit=` (default 50, max 200) `&cursor=`; response `{"items":[...], "next_cursor": "..."\|null, "total_estimate": int}` |
| Error envelope | Every non-2xx: `{"error": {"code": "<TAXONOMY_CODE>", "message": "<human>", "details": {...}?, "retry_after_seconds": int?}}` |
| Frozen trial | Read endpoints work; mutating console endpoints ⇒ 403 `TENANT_FROZEN`; ingest ⇒ 402 `TRIAL_EXPIRED` (AC-9). |
| Abuse-frozen tenant (SEC-39) | `tenant.abuse_frozen = true` ⇒ ingest, enrollment, and ALL console writes ⇒ 403 `TENANT_FROZEN` (`details.cause = "abuse"`); reads remain. Effective ≤60s after the flag is set. |
| Fail-closed 5xx | Agent/ingest routes return 503 `SERVICE_UNAVAILABLE` (+`Retry-After`) when device/key/tenant status stores are unreachable (B-1/SEC-10/17) and 503 `ENTITLEMENTS_UNAVAILABLE` on cold entitlement cache (ADR-0005). Agents treat any 5xx as buffer-and-retry with backoff (AC-66/68). |
| Audit | Every endpoint marked **[A]** writes an audit record (AC-83). |

## 2. Error-code taxonomy (machine-readable)

| HTTP | Code | Where |
|---|---|---|
| 400 | `VALIDATION_ERROR` | any malformed request (details lists fields) |
| 400 | `PASSWORD_POLICY_VIOLATION`, `PASSWORD_BREACHED` | signup / password change |
| 400 | `SIGNUP_CHALLENGE_REQUIRED` | AC-8 abuse hold (details: challenge info) |
| 401 | `AUTH_REQUIRED`, `SESSION_EXPIRED` | console |
| 401 | `INGEST_KEY_INVALID`, `INGEST_KEY_REVOKED` | generic ingest (AC-29) |
| 401 | `DEVICE_IDENTITY_INVALID` | agent routes: unknown cert/device, serial mismatch, or absent from the device-status allowlist (B-1/SEC-10) |
| 401 | `DEVICE_REVOKED` | agent routes after revocation (AC-59) |
| 402 | `TRIAL_EXPIRED` | ingest for frozen trial (AC-9) |
| 403 | `FORBIDDEN_ROLE` | role check failure (AC-78) |
| 403 | `TENANT_FROZEN` | console writes on frozen trial; ingest/enrollment/console writes for abuse-frozen tenant (`details.cause = "trial"\|"abuse"`, SEC-39) |
| 403 | `ENTITLEMENT_DENIED` | feature not in plan (AC-17; details.entitlement) |
| 403 | `QUOTA_EXCEEDED_DEEP_INVESTIGATION` | AC-54 |
| 404 | `NOT_FOUND` | missing OR foreign-tenant resource (AC-81) |
| 409 | `INVALID_STATE_TRANSITION` | alert state machine (AC-47) |
| 409 | `DOMAIN_ALREADY_REGISTERED` | AC-4 |
| 409 | `VERIFICATION_ALREADY_USED` | AC-2 |
| 410 | `VERIFICATION_EXPIRED` | AC-2 |
| 410 | `ENROLLMENT_TOKEN_EXPIRED` | AC-58 |
| 403 | `ENROLLMENT_TOKEN_REVOKED`, `ENROLLMENT_TOKEN_INVALID` | AC-58 (invalid incl. foreign-tenant: indistinguishable from unknown) |
| 403 | `ENDPOINT_CAP_REACHED` | enrollment at cap (AC-14) |
| 413 | `BATCH_TOO_LARGE` | ingest >1000 events or >5MB (AC-30) |
| 429 | `INGEST_QUOTA_EXCEEDED` | + `Retry-After` header (AC-86) |
| 429 | `RATE_LIMITED` | login backoff (AC-77), enrollment per-IP/per-token limits (SEC-12), general API limits |
| 503 | `SERVICE_UNAVAILABLE` | agent/ingest routes when device/key/tenant status stores are down — fail-closed deny (B-1/SEC-10/17) + `Retry-After`; agents buffer and retry |
| 503 | `ENTITLEMENTS_UNAVAILABLE` | fail-closed with empty cache (ADR-0005) + `Retry-After` |
| 401 | `AUTH_REQUIRED` | **(clarification, Architect-ratified 2026-07-08)** also returned on agent routes when the request lacks a valid `X-Gateway-Auth` header (SEC-14 gateway hop missing) — a missing gateway hop is not a device-identity verdict, so `DEVICE_*` codes are not used; also returned on CSRF-token failures for cookie-authed mutations |
| 500 | `INTERNAL_ERROR` | **(added by Architect ratification 2026-07-08)** unhandled server error; never reuses `SERVICE_UNAVAILABLE` (which signals fail-closed dependency denial and drives client buffer-and-retry semantics) |

## 3. Signup & provisioning (controlplane-api)

### POST /v1/signup — public
Req: `{"org_name": str(2..120), "email": str, "password": str(≥12)}` (+ `"challenge_response": str?` after AC-8 hold)
- 202 `{"account_id": "acc_...", "state": "pending_verification"}` (verification email sent, 24h single-use link)
- 400 `PASSWORD_POLICY_VIOLATION` | `PASSWORD_BREACHED` | `SIGNUP_CHALLENGE_REQUIRED`; 409 `DOMAIN_ALREADY_REGISTERED` (message reveals nothing beyond "domain has an account", AC-4; rate-limited per SEC-6)

### POST /v1/signup/verify — public **[A]**
Req: `{"token": str}`
- 200 `{"tenant_id": "tn_...", "provisioning": "in_progress"}` → poll status
- 410 `VERIFICATION_EXPIRED`, 409 `VERIFICATION_ALREADY_USED` (both: UI offers resend)

### POST /v1/signup/resend-verification — public
Req: `{"email": str}` → 202 always (no account enumeration, SEC-6).

### GET /v1/signup/provisioning-status?account_id=acc_...
- 200 `{"state": "pending_verification"|"provisioning"|"ready"|"provisioning_failed"}` — `ready` includes `{"console_url": ...}`; `provisioning_failed` shows "we're on it" (AC-5). Target verify→ready ≤60s p95 (AC-3).

## 4. Auth & users (controlplane-api)

| Endpoint | Role | Notes |
|---|---|---|
| POST /v1/auth/login `{email, password}` | public | 200 sets session cookie + `{"user": {...}, "tenant": {"id","name","status","abuse_frozen","trial_expires_at"?}}`; 429 `RATE_LIMITED` after 10 failures (lockout/backoff + per-IP throttle, AC-77/SEC-4) |
| POST /v1/auth/logout **[A]** | any | 204 |
| GET /v1/me | any | user + role + tenant status |
| GET /v1/users | admin | list |
| POST /v1/users `{email, role: "admin"\|"analyst"}` **[A]** | admin | 201; invite email |
| PATCH /v1/users/{user_id} `{role?}` **[A]** | admin | role change invalidates the user's sessions (SEC-3) |
| DELETE /v1/users/{user_id} **[A]** | admin | 204; sessions invalidated |
| POST /v1/auth/change-password **[A]** | any | invalidates other sessions (AC-77); **exempt from the frozen-tenant write block** (Architect-ratified 2026-07-08: compromised-account rotation must work on frozen tenants; logout likewise exempt) |
| POST /v1/auth/accept-invite `{token, password}` **[A]** | public | *(added by Architect ratification 2026-07-08)* Invited user sets password (full policy + breached check) and becomes `active`; single-use expiring token from the invite email (`/invite/accept?token=...&user_id=usr_...`); 410 `VERIFICATION_EXPIRED` / 409 `VERIFICATION_ALREADY_USED` reuse the signup taxonomy |

## 5. Entitlements (controlplane-api)

### GET /v1/tenant/entitlements — any role
200:
```json
{
  "plan": "trial", "tenant_status": "active", "abuse_frozen": false,
  "trial_expires_at": "2026-07-22T09:00:00Z",
  "entitlements": {
    "endpoint_cap": 100,
    "retention_days": 14,
    "deep_investigation_daily_quota": 5,          
    "response_mode": "recommend_only",
    "ingest_events_per_min": 5000
  },
  "as_of": "2026-07-08T10:00:00Z"
}
```
`deep_investigation_daily_quota: -1` means unlimited. p95 ≤50ms; caches allowed TTL ≤5 min (AC-13). Same shape served internally at `GET /internal/v1/tenants/{tenant_id}/entitlements` for the entitlements client (ADR-0005). NOTE (SEC-39): `abuse_frozen`, device status, and key status are enforced from their own stores — this payload is informational for them, never the enforcement source.

### PUT /internal/v1/tenants/{tenant_id}/plan `{"plan": "trial"|"core"|"pro"}` — internal operator only **[A]**
200; all enforcement points reflect within 5 min (AC-11/15); audit stores old+new values + operator identity (SEC-40).

### PUT /internal/v1/tenants/{tenant_id}/abuse-freeze `{"frozen": bool, "reason": str}` — internal operator only **[A]** (SEC-39)
200; enforcement effective ≤60s (status-store path, not entitlement cache).

## 6. Ingestion (dataplane-api)

### POST /v1/agent/events — auth: mTLS device cert
### POST /v1/ingest/events — auth: `X-Ingest-Key`
Req body (both): `{"events": [ <event objects per event-schema.md §5> ]}` — ≤1,000 events AND ≤5MB.
- **202** `{"batch_id": "b_...", "accepted": int}` — p95 ≤300ms; "accepted" = queued for normalization (malformed items are detected async and dead-lettered per AC-32)
- 401 `DEVICE_IDENTITY_INVALID` / `DEVICE_REVOKED` / `INGEST_KEY_INVALID` / `INGEST_KEY_REVOKED`; foreign-tenant key ⇒ `INGEST_KEY_INVALID` (indistinguishable)
- 402 `TRIAL_EXPIRED` (AC-9)
- 403 `TENANT_FROZEN` (`details.cause="abuse"`) for abuse-frozen tenants (SEC-39)
- 413 `BATCH_TOO_LARGE`
- 429 `INGEST_QUOTA_EXCEEDED` + `Retry-After: <seconds>`; never 202-then-drop (AC-86)
- 503 `SERVICE_UNAVAILABLE` + `Retry-After` when device/key/tenant status stores are down (fail-closed, B-1/SEC-10/17); 503 `ENTITLEMENTS_UNAVAILABLE` + `Retry-After` on cold entitlement cache (ADR-0005). Agents buffer per AC-66/68 in both cases.

### Ingest keys (console) — admin **[A]**
| Endpoint | Response |
|---|---|
| POST /v1/ingest-keys `{"name": str}` | 201 `{"id":"ik_...","name":...,"key":"<shown once>","created_at":...}` (AC-29; format/storage per SEC-16) |
| GET /v1/ingest-keys | list (no key material, `last_used_at`) |
| DELETE /v1/ingest-keys/{id} | 204 (revoke; takes effect ≤60s via key-status allowlist, SEC-17) |

### GET /v1/tenant/usage/ingest — any role (AC-88)
200 `{"events_per_min_current": int, "events_per_min_limit": int, "throttled_batches_24h": int, "rejected_events_24h": int, "warning_active": bool}`.

## 7. Asset inventory (dataplane-api)

Asset object:
```json
{
  "id": "as_01J9ZKQ8", "hostname": "fin-laptop-07",
  "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "10.0.26100",
  "sources": ["agent", "log_ingest"],
  "agent_status": "healthy",             
  "agent": {"device_id": "dev_01J9ZK3T", "version": "0.3.1", "last_heartbeat_at": "..."},
  "identities": [
    {"source": "agent", "identifier_type": "device_id", "value": "dev_01J9ZK3T"},
    {"source": "log_ingest", "identifier_type": "hostname_os", "value": "fin-laptop-07|windows"}
  ],
  "merge_audit": [{"at": "...", "rule": "hostname_os_match", "merged_identity": {...}, "actor": "system"}],
  "billable": true, "first_seen": "...", "last_seen": "...",
  "created_via": "agent_enrollment"
}
```
`agent_status ∈ enrolled|healthy|offline|revoked|none` (AC-21/59/61).

| Endpoint | Role | Notes |
|---|---|---|
| GET /v1/assets | any | Filters: `source=agent\|log_ingest`, `agent_status=`, `billable=true\|false`, `q=<hostname substring>`; paginated (AC-21) |
| GET /v1/assets/{id} | any | Full object incl. `identities`, `merge_audit` (AC-24) |
| GET /v1/assets/billable-count | any | 200 `{"billable_count": int, "endpoint_cap": int, "window_days": 30, "computed_at": "..."}` — deduped, last-seen ≤30d (AC-26/27) |
| POST /v1/assets/merge `{"asset_ids": [..≥2], "reason": str}` **[A]** | admin | 200 merged asset; writes identity **pins** preventing auto re-split (AC-25) |
| POST /v1/assets/{id}/split `{"identity_ids": [...], "reason": str}` **[A]** | admin | 200 `{"assets":[orig, new]}`; pins prevent auto re-merge (AC-25) |
| POST /v1/devices/{device_id}/revoke **[A]** | admin | 200; device-status record set `revoked` (allowlist, effective at next connect ≤60s), asset `agent_status=revoked`, non-billable (AC-59, SEC-10) |

Merge/split are forward-looking only (PRD OQ-9 assumption).

## 8. Alerts (dataplane-api)

Alert object (fields marked ⚑ are AI-triage-owned, written by worker-triager):
```json
{
  "id": "al_01J9ZM2W", "tenant_id": "...",
  "state": "new",
  "rule": {"id": "win_susp_encoded_powershell", "version": "1.2.0", "title": "Suspicious encoded PowerShell", "severity": "high", "mitre_technique_ids": ["T1059.001"]},
  "entity": {"hostname": "fin-laptop-07", "user": "sam.jones", "asset_id": "as_01J9ZKQ8"},
  "occurrence_count": 7, "first_seen": "...", "last_seen": "...",
  "correlation_group_id": "cg_01J9ZM9X",
  "priority_score": 86,
  "priority_inputs": {"rule_severity": "high", "ai_severity": "high", "ai_severity_effective": "high", "occurrence_count": 7, "agent_status": "offline", "priority_formula_version": 1},
  "triage": {                       
    "status": "completed",
    "summary": "⚑ plain-language ≤120 words: what happened, why it matters, next step",
    "ai_severity": "high",
    "model_id": "⚑", "completed_at": "⚑", "attempts": 1
  },
  "event_refs": [{"event_id": "...", "es_index": "events-v1-...-2026.07"}],
  "close_reason": null, "closed_by": null, "closed_at": null,
  "acknowledged_by": null, "acknowledged_at": null,
  "created_at": "..."
}
```
`triage.status ∈ pending|completed|unavailable` (AC-50: `unavailable` after 3 failed attempts; alert queue never waits). `priority_score` and `priority_inputs` (incl. the B-4/SEC-34 clamped `ai_severity_effective`) per `docs/contracts/priority-score.md`. `triage.ai_severity` is always the RAW model output (displayed per AC-49); the clamp affects scoring only. Triage strings are rendered as plain text by all clients (SEC-31/33).

### GET /v1/alerts — any role (AC-44)
Query params: `state=new|acknowledged|closed` (repeatable), `severity=` (rule severity; repeatable), `ai_severity=`, `rule_id=`, `host=`, `correlation_group_id=`, `from=`/`to=` (RFC3339, on `last_seen`), `sort=priority|-priority|last_seen|-last_seen` (default `-priority`, tie-break `-last_seen`, then `id`), cursor pagination. p95 ≤500ms @10k alerts.

### GET /v1/alerts/{id} — any role
Full object + `siblings`: alerts sharing `correlation_group_id` (AC-43/74) + `history`: audit trail entries for this alert.

### GET /v1/alerts/{id}/events — any role *(added by Architect ratification 2026-07-08, closes the AC-74 gap)*
Returns the normalized event bodies for the alert's `event_refs`, read via the tenant-scoped ES alias (fail-closed per SEC-24). Cursor-paginated; items are full normalized events per event-schema.md. Unknown/foreign alert id ⇒ 404. Events already purged by retention are omitted; response carries `"missing_event_ids": [...]` so the UI can say "no longer retained".

### State transitions (AC-45/47) — role: admin or analyst, all **[A]**

| Endpoint | Valid from | Result |
|---|---|---|
| POST /v1/alerts/{id}/acknowledge | `new` | `acknowledged` |
| POST /v1/alerts/{id}/close `{"reason": "resolved"\|"false_positive"\|"expected_behavior"\|"duplicate", "comment": str?}` | `new`, `acknowledged` | `closed` (reason required; FP records queryable for detection-engineering, AC-46) |
| POST /v1/alerts/{id}/reopen | `closed` | `new` |

Invalid transition ⇒ 409 `INVALID_STATE_TRANSITION` `{details: {current_state}}`; unknown/foreign id ⇒ 404. Transitions atomic (compare-and-set on state).

### POST /v1/alerts/bulk — admin/analyst **[A]** (AC-73)
Req: `{"action": "acknowledge"|"close", "reason": str (close only), "alert_ids": [..≤50]}`
- 200 `{"succeeded": ["al_.."], "failed": [{"id": "al_..", "code": "INVALID_STATE_TRANSITION"}]}` (partial success allowed; each item atomic)

## 9. Deep investigation (dataplane-api) — resolves OQ-8

### POST /v1/alerts/{id}/deep-investigation — admin/analyst **[A]** (AC-53..55)
- 200 (MVP stub completes synchronously, no model call per SEC-35) / future async ⇒ 202 with same object, `status: "queued"`. **Response shape below is the permanent contract; real engine fills the arrays without breaking clients:**
```json
{
  "investigation_id": "inv_01J9ZN7K",
  "alert_id": "al_01J9ZM2W",
  "status": "completed",
  "is_stub": true,
  "engine_version": "stub-1",
  "requested_at": "...", "completed_at": "...",
  "requested_by": "usr_...",
  "summary": "Deep investigation is coming soon. This placeholder confirms your entitlement and quota flow.",
  "confidence": null,
  "findings": [],
  "timeline": [],
  "evidence_graph": {"nodes": [], "edges": []},
  "recommended_actions": [],
  "quota": {"limit": 5, "remaining": 3, "resets_at": "2026-07-09T00:00:00Z"}
}
```
Future element shapes (fixed now so `web` can build renderers): `findings[]: {id, title, description, severity, technique_ids[], evidence_refs[]}`; `timeline[]: {at, description, event_id?}`; `evidence_graph.nodes[]: {id, type: host|user|process|ip|file, label}`, `edges[]: {from, to, relation}`; `recommended_actions[]: {id, title, description, requires_response_mode}`.
- 403 `QUOTA_EXCEEDED_DEEP_INVESTIGATION` `{details: {remaining: 0, resets_at: "..."}}` — no quota consumed (AC-54); concurrency-safe decrement (AC-55)
- 403 `ENTITLEMENT_DENIED` if plan lacks the feature entirely

### GET /v1/alerts/{id}/deep-investigations — any role
List of prior runs (paginated). `GET /v1/tenant/quotas/deep-investigation` → `{"limit": int(-1=unlimited), "remaining": int, "resets_at": "..."}`.

## 10. Enrollment & agent lifecycle (dataplane-api) — AC-56..61, ADR-0006

### Console side — admin **[A]**
| Endpoint | Notes |
|---|---|
| POST /v1/enrollment-tokens `{"name": str, "expires_in_hours": int? (default 72, plan-config)}` | 201 `{"id":"et_...","token":"<shown once>","expires_at":...,"install_command":"<copy-paste silent install>"}` (AC-56); token is multi-use until expiry/revocation (GPO/Intune rollout; theft-visibility conditions per SEC-13) |
| GET /v1/enrollment-tokens | list (no token material; `enrollment_count`) |
| DELETE /v1/enrollment-tokens/{id} | 204 revoke |

### Agent side
**POST /v1/agent/enroll** — auth: enrollment token in body; plain TLS (no client cert yet); rate-limited per IP and per token (SEC-12 ⇒ 429 `RATE_LIMITED`)
Req: `{"enrollment_token": str, "csr_pem": str, "host": {<host object per event-schema §2.1>}, "agent_version": str}` — CSR is proof-of-possession only; server assigns all identity (SEC-8).
- 201 `{"device_id": "dev_...", "certificate_pem": "...", "ca_chain_pem": "...", "certificate_expires_at": "...", "ingest_url": "...", "heartbeat_interval_seconds": 60}` — asset record visible ≤60s (AC-19/57); audit-logged with token ID + source IP (SEC-13)
- 410 `ENROLLMENT_TOKEN_EXPIRED`; 403 `ENROLLMENT_TOKEN_REVOKED` | `ENROLLMENT_TOKEN_INVALID` (unknown and foreign-tenant identical) | `ENDPOINT_CAP_REACHED` (atomic cap check, no partial device record, AC-14/SEC-12; all attempts server-logged, AC-58) | `TENANT_FROZEN` (abuse-frozen tenant)

**POST /v1/agent/heartbeat** — auth: mTLS (AC-60)
Req: `{"agent_version": str, "os_version": str, "providers": [{"name": "etw"|"simulated", "status": "ok"|"degraded"|"failed"}], "buffer_utilization_pct": num, "cpu_pct": num, "rss_mb": num, "dropped_events_since_last": {"network_activity": int, "process_activity": int, "authentication": int}}`
- 200 `{"config_version": str, "actions": []}` (`actions` reserved for future policy pushes; empty in MVP)
- 401 `DEVICE_REVOKED` ⇒ agent stops sending, per AC-59; 503 `SERVICE_UNAVAILABLE` ⇒ retry with backoff

**POST /v1/agent/renew-credential** — auth: mTLS (current valid, non-revoked cert; SEC-10 check runs first) — Req `{"csr_pem": str}` → 200 `{"certificate_pem": str, "ca_chain_pem": str, "certificate_expires_at": rfc3339}` *(response body ratified by Architect 2026-07-08 — mirrors enroll's credential fields)* (same device identity per SEC-11; old serial ≤24h overlap; audit-logged with old/new serial).

*Clarification (Architect-ratified 2026-07-08):* `ingest_url` returned by enroll is a **base URL**; the agent appends `/v1/agent/events`, `/v1/agent/heartbeat`, `/v1/agent/renew-credential` to it.

Offline marking (AC-61): server job flags `agent_status=offline` after 3 missed intervals (≤1 min detection); next heartbeat restores `healthy`.

## 11. Rules (dataplane-api) — AC-36/38

| Endpoint | Role | Notes |
|---|---|---|
| GET /v1/rules | any | `{id, version, title, severity, mitre_technique_ids, event_classes, enabled (tenant-effective), description}`; paginated |
| PUT /v1/rules/{rule_id}/enabled `{"enabled": bool}` **[A]** | admin | Per-tenant overlay toggle; 404 for unknown rule |

## 12. Audit & onboarding (dataplane-api)

| Endpoint | Role | Notes |
|---|---|---|
| GET /v1/audit-logs | admin | Filters: `actor=`, `action_type=`, `from=`/`to=`; paginated; records: `{id, at, tenant_id, actor: {type: user\|system\|device, id}, action_type, target: {type, id}, before?, after?, reason_code?}` (AC-83..85; content rules per SEC-44 — never secret material or raw payloads) |
| GET /v1/onboarding/status | any | `{"steps": [{"id": "install_agent"\|"create_ingest_key"\|"first_event"\|"view_queue", "state": "todo"\|"done", "completed_at"?}]}` — `first_event` auto-completes on first ingested event (AC-70) |

## 13. Internal APIs (network-restricted; not tenant-facing)

Auth: HMAC-signed short-lived service tokens per design §5.1 (SEC-40); never mounted on public listeners; plan/abuse-freeze changes additionally carry an operator identity recorded in audit.

| Endpoint | Purpose |
|---|---|
| GET /internal/v1/tenants/{id}/entitlements | Entitlements client source (ADR-0005) |
| PUT /internal/v1/tenants/{id}/provision | *(added by Architect ratification 2026-07-08)* Idempotent data-plane provisioning step called by the controlplane saga: creates the tenant's first monthly ES index + `events-{tenant}` alias and seeds `tenantdata.onboarding_steps`. Keeps ES ownership inside the data plane (ADR-0001/0003 boundary); controlplane never talks to ES directly |
| PUT /internal/v1/tenants/{id}/plan | Operator plan change (AC-11) |
| PUT /internal/v1/tenants/{id}/abuse-freeze | Operator abuse freeze/unfreeze (SEC-39) |
| GET /internal/v1/metering/llm?tenant_id=&from=&to= | Per-tenant/day: `{tokens_in, tokens_out, model_id, calls, cost_usd, latency_ms_p95}` per AC-51 |
| GET /internal/v1/metering/deep-investigation?... | Run records (AC-53) |
| GET /internal/v1/fp-feedback?rule_id=&from=&to= | `{rule_id, entity, reason, comment, at}` export for detection-engineering (AC-46) |
| GET /healthz, /readyz (all services) | Compose/Helm probes (AC-90) |

## 14. Clarifications (Architect-ratified, 2026-07-08)

Raised during web-console implementation; binding for server implementations:

1. **CSRF mechanism:** double-submit cookie named `csrf_token` (non-HttpOnly, readable by the console origin); clients echo it as `X-CSRF-Token` on every mutating cookie-authed request. Controlplane issues/rotates it at login.
2. **CORS:** both APIs allow the console origin with `Access-Control-Allow-Credentials: true` and request headers `X-CSRF-Token`, `Content-Type`.
3. **`GET /v1/me` shape:** mirrors the login payload — `{"user": {"id","email","role"}, "tenant": {"id","name","status","abuse_frozen","trial_expires_at"?}}`.
4. **Asset identities:** each `identities[]` entry carries a server-generated `id` (required by `POST /v1/assets/{id}/split`'s `identity_ids`); the §7 example predates this.
5. **Verification email link format:** `/signup/verify?token=...&account_id=acc_...` on the console origin, so a fresh browser can verify and then poll provisioning status.
6. **`GET /v1/alerts/{id}/events`** added in §8 to close the AC-74 gap (refs-only display is not sufficient).
