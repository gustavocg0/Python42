"""/healthz and /readyz on both listeners (contract §13, AC-90)."""

from __future__ import annotations


async def test_health_and_ready_on_both_apps(env):
    for client in (env.public, env.internal):
        health = await client.get("/healthz")
        assert health.status_code == 200 and health.json() == {"status": "ok"}
        ready = await client.get("/readyz")
        assert ready.status_code == 200 and ready.json() == {"status": "ready"}


async def test_readyz_fails_closed_when_db_down(env):
    from controlplane import queries

    env.db.inject_failure(queries.SELECT_ONE, times=2)
    for client in (env.public, env.internal):
        response = await client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
        assert response.headers.get("Retry-After") == "5"
