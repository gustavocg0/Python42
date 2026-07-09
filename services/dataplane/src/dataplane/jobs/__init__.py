"""jobs-scheduler — cron-style loop of data-plane housekeeping jobs (design §2).

Run: ``python -m dataplane.jobs``            (continuous loop)
     ``python -m dataplane.jobs --once J``   (single job, for tests/CI/runbooks)
     ``python -m dataplane.jobs --list``

Jobs (each under a Redis ``lock:job:{name}`` singleton lock):
- ``retention_purge``  — delete expired monthly ES indices per tenant
  retention entitlement, ≤24h after expiry (AC-16);
- ``trial_freeze``     — freeze trials past ``trial_expires_at`` (AC-9, SEC-46);
- ``trial_purge``      — purge frozen trials after 30 days via the
  ``control.purge_registry`` inventory, honoring ``retain`` rows (AC-10, SEC-46);
- ``billable_window``  — assets not seen for 30 days become non-billable (AC-26);
- ``agent_offline``    — mark assets offline after 3 missed heartbeats (AC-61);
- ``dlq_cleanup``      — dead_letter_events older than 7 days (AC-32).

Tenant-crossing jobs iterate ``control.tenants`` and pin the RLS GUC per
tenant — RLS is never bypassed (db/README.md, SEC-46).
"""
