# web — Minimal SOC Console (PRD Epic E9)

Next.js 15 (App Router) + TypeScript (strict) + @tanstack/react-query, plain
CSS. Talks to the two API origins defined in `docs/contracts/api-contracts.md`;
it never invents endpoints.

## Environment

| Variable | Meaning | Default (dev) |
|---|---|---|
| `NEXT_PUBLIC_CONTROLPLANE_URL` | controlplane-api base (signup/auth/users/entitlements) | `http://localhost:8001` |
| `NEXT_PUBLIC_DATAPLANE_URL` | dataplane-api base (alerts/assets/rules/keys/tokens/audit/onboarding) | `http://localhost:8000` |

Set them in `.env.local` for dev. They are compiled into the client bundle and
also used by `src/middleware.ts` for the CSP `connect-src` allowlist.

## Run

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # production build
npm test           # vitest (jsdom, mocked fetch)
npm run typecheck
```

## Backend expectations (chosen by frontend, must be honored)

1. **CSRF (contract §1, SEC-3):** double-submit. The backend must set a
   **non-HttpOnly** cookie named **`csrf_token`** at session creation; the
   console echoes it in the **`X-CSRF-Token`** header on every mutating
   (non-GET) cookie-authenticated request. The cookie must be readable from
   the console origin (same registrable domain, or same-origin reverse proxy).
2. **Session:** `sid` cookie HttpOnly/Secure/SameSite=Lax (SEC-3). The console
   never stores credentials or tokens in localStorage (SEC-2); auth state is
   discovered via `GET /v1/me`.
3. **`GET /v1/me` shape:** assumed to mirror the login payload:
   `{"user": {id, email, role}, "tenant": {id, name, status, abuse_frozen, trial_expires_at?}}`.
4. **CORS:** both APIs must allow the console origin with
   `Access-Control-Allow-Credentials: true` and allow the `X-CSRF-Token` and
   `Content-Type` request headers.
5. **Asset identities:** `POST /v1/assets/{id}/split` takes `identity_ids`,
   so each entry of `asset.identities[]` must carry an **`id`** field (the
   contract example omits it).
6. **Verification email link:** should point at
   `/signup/verify?token=...&account_id=acc_...` — `account_id` lets the
   console poll `GET /v1/signup/provisioning-status` from a fresh browser.
   Without it the console falls back to sessionStorage or a generic
   "sign in shortly" message.

## Security notes

- SEC-31/33: every event-derived or AI-generated string is rendered as plain
  text (React text nodes). No `dangerouslySetInnerHTML`, no markdown
  rendering, anywhere. `src/__tests__/alert-row.test.tsx` is the regression
  test.
- SEC-31/50: per-request nonce CSP (`default-src 'self'`, no inline script)
  in `src/middleware.ts`; nosniff/referrer-policy/frame-deny in
  `next.config.ts`. Root layout forces dynamic rendering so the nonce applies.
- Role-aware UI (admin vs analyst) is a courtesy only; every 403
  `FORBIDDEN_ROLE` / `TENANT_FROZEN` is handled gracefully (AC-17/78).

## Route map

| Route | Purpose |
|---|---|
| `/signup`, `/signup/verify`, `/signup/status` | Trial signup, email verification, provisioning poll ("we're on it" on failure) |
| `/login` | Email+password session login |
| `/onboarding` | AC-70 checklist with live (polled) step states, inline token/key creation |
| `/alerts` | Prioritized queue; AC-44 filters as shareable URL params; single/bulk (≤50) ack/close with required reason; optimistic updates |
| `/alerts/[id]` | AI summary (labeled) + rule vs AI severity, priority breakdown, MITRE plain-language, siblings, raw event refs, action history, deep investigation with quota |
| `/assets`, `/assets/[id]` | AC-21 inventory + billable count/cap banner; identities, merge audit, manual merge/split with reason, device revoke |
| `/rules` | Managed rule list; admin per-tenant on/off toggle |
| `/settings/users` | Admin user CRUD (invite, role change, delete) |
| `/settings/ingest-keys` | Create (show-once) / list / revoke |
| `/settings/enrollment-tokens` | Create (show-once + install command) / list / revoke |
| `/settings/audit` | Admin audit log with filters |
| `/settings/usage` | AC-88 usage vs quota (80% warning), plan entitlements incl. read-only response mode |
