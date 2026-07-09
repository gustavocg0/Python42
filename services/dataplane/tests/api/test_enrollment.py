"""Enrollment/agent lifecycle tests: token taxonomy, atomic cap, real CSR
signing, renewal overlap, revoke cache delete (AC-56..61, SEC-7..13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography import x509
from cryptography.x509.oid import NameOID
from dp_api_testkit import (
    GATEWAY_HEADERS,
    OTHER_TENANT_ID,
    TENANT_ID,
    agent_headers,
    make_csr,
    make_session,
    mint_enrollment_token,
    seed_device,
    seed_tenant_status,
    session_kwargs,
)

NOW = datetime.now(UTC)


def enroll_body(token: str, csr: str | None = None) -> dict:
    return {
        "enrollment_token": token,
        "csr_pem": csr or make_csr(),
        "host": {
            "hostname": "Fin-Laptop-07",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
        },
        "agent_version": "0.3.1",
    }


def register_valid_token(sql, secret_hash: str, **overrides) -> None:
    row = {
        "token_hash": secret_hash,
        "expires_at": NOW + timedelta(hours=72),
        "revoked_at": None,
    }
    row.update(overrides)
    sql.on(r"FROM tenantdata\.enrollment_tokens WHERE id", rows=[row])


def register_enroll_writes(sql, billable: int = 0) -> None:
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.assets", value=billable)
    sql.on(r"INSERT INTO tenantdata\.assets", rows=[{"id": uuid4()}])


async def test_enroll_happy_path_issues_server_assigned_identity(client, fake_redis, sql):
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash)
    register_enroll_writes(sql)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == {
        "device_id",
        "certificate_pem",
        "ca_chain_pem",
        "certificate_expires_at",
        "ingest_url",
        "heartbeat_interval_seconds",
    }
    assert body["device_id"].startswith("dev_")
    assert body["ingest_url"] == "https://ingest.example.test"  # BASE url (ratified)
    assert body["heartbeat_interval_seconds"] == 60
    # Real X.509: server-assigned CN + tenant-scoped URI SAN (SEC-8/ADR-0006).
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == body["device_id"]
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [f"urn:platform:tenant:{TENANT_ID}:device:{body['device_id']}"]
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert timedelta(days=89) < lifetime < timedelta(days=91)
    # Device row + audit written; token counter bumped (SEC-13).
    assert sql.executed(r"INSERT INTO tenantdata\.devices")
    assert sql.executed(r"INSERT INTO audit_log")
    assert sql.executed(r"SET enrollment_count = enrollment_count \+ 1")
    # cert serial stored as lowercase hex matching the certificate serial
    device_args = sql.executed(r"INSERT INTO tenantdata\.devices")[0][1]
    assert device_args[3] == format(cert.serial_number, "x")
    # onboarding signal
    assert await fake_redis.hget(f"onboarding:{TENANT_ID}", "install_agent") == "1"


async def test_enroll_empty_subject_csr_accepted(client, fake_redis, sql):
    """Ratified §10: agent sends EMPTY-subject PKCS#10 (ECDSA P-256)."""
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash)
    register_enroll_writes(sql)
    await seed_tenant_status(fake_redis)
    csr = make_csr()
    parsed = x509.load_pem_x509_csr(csr.encode())
    assert list(parsed.subject) == []  # precondition: truly empty subject
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire, csr), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 201


async def test_enroll_malformed_token_invalid(client, fake_redis):
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body("garbage-token"), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ENROLLMENT_TOKEN_INVALID"


async def test_enroll_unknown_and_foreign_tokens_indistinguishable(client, fake_redis, sql):
    sql.on(r"FROM tenantdata\.enrollment_tokens WHERE id", rows=[])  # RLS: zero rows
    unknown_wire, _ = mint_enrollment_token(TENANT_ID, "et_UNKNOWN")
    foreign_wire, _ = mint_enrollment_token(OTHER_TENANT_ID, "et_FOREIGN")
    r1 = await client.post(
        "/v1/agent/enroll", json=enroll_body(unknown_wire), headers=GATEWAY_HEADERS
    )
    r2 = await client.post(
        "/v1/agent/enroll", json=enroll_body(foreign_wire), headers=GATEWAY_HEADERS
    )
    assert r1.status_code == r2.status_code == 403
    assert (
        r1.json()["error"]["code"]
        == r2.json()["error"]["code"]
        == "ENROLLMENT_TOKEN_INVALID"
    )


async def test_enroll_wrong_secret_invalid(client, fake_redis, sql):
    _, stored_hash = mint_enrollment_token()
    register_valid_token(sql, stored_hash)
    fresh_wire, _ = mint_enrollment_token(TENANT_ID, "et_TEST")  # same id, new secret
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(fresh_wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ENROLLMENT_TOKEN_INVALID"


async def test_enroll_revoked_token(client, fake_redis, sql):
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash, revoked_at=NOW)
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ENROLLMENT_TOKEN_REVOKED"


async def test_enroll_expired_token_410(client, fake_redis, sql):
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash, expires_at=NOW - timedelta(hours=1))
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "ENROLLMENT_TOKEN_EXPIRED"


async def test_enroll_abuse_frozen_tenant_403(client, fake_redis, sql):
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash)
    await seed_tenant_status(fake_redis, abuse_frozen=True)
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TENANT_FROZEN"


async def test_enroll_cap_reached_atomic_no_partial_device_row(client, fake_redis, sql):
    """AC-14/SEC-12: cap check aborts BEFORE any device/asset write."""
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash)
    sql.on(r"SELECT count\(\*\) FROM tenantdata\.assets", value=100)  # == trial cap
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "ENDPOINT_CAP_REACHED"
    assert body["details"]["endpoint_cap"] == 100
    assert not sql.executed(r"INSERT INTO tenantdata\.devices")
    assert not sql.executed(r"INSERT INTO tenantdata\.assets")
    # advisory lock was taken inside the same transaction (atomicity)
    assert sql.executed(r"pg_advisory_xact_lock")


async def test_enroll_invalid_csr_is_400(client, fake_redis, sql):
    wire, secret_hash = mint_enrollment_token()
    register_valid_token(sql, secret_hash)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/agent/enroll",
        json=enroll_body(wire, csr="-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----"),
        headers=GATEWAY_HEADERS,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_enroll_per_ip_rate_limit_429(client, fake_redis):
    await fake_redis.set("rl:enroll:ip:127.0.0.1", 10)  # SEC-12 default 10/min
    wire, _ = mint_enrollment_token()
    response = await client.post(
        "/v1/agent/enroll", json=enroll_body(wire), headers=GATEWAY_HEADERS
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"


async def test_enroll_without_gateway_hop_is_401(client):
    wire, _ = mint_enrollment_token()
    response = await client.post("/v1/agent/enroll", json=enroll_body(wire))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


# ------------------------------------------------------------------ heartbeat
def heartbeat_body() -> dict:
    return {
        "agent_version": "0.3.1",
        "os_version": "10.0.26100",
        "providers": [{"name": "etw", "status": "ok"}],
        "buffer_utilization_pct": 12.5,
        "cpu_pct": 1.2,
        "rss_mb": 48.0,
        "dropped_events_since_last": {
            "network_activity": 0,
            "process_activity": 0,
            "authentication": 0,
        },
    }


async def test_heartbeat_updates_device_and_asset(client, fake_redis, sql):
    await seed_device(fake_redis)
    sql.on(r"UPDATE tenantdata\.devices SET last_heartbeat_at", rows=[{"asset_id": uuid4()}])
    response = await client.post(
        "/v1/agent/heartbeat", json=heartbeat_body(), headers=agent_headers()
    )
    assert response.status_code == 200
    assert response.json() == {"config_version": "1", "actions": []}
    assert sql.executed(r"UPDATE tenantdata\.assets SET agent_status = 'healthy'")


async def test_heartbeat_revoked_device_401_stops_agent(client, fake_redis):
    await seed_device(fake_redis, status="revoked")
    response = await client.post(
        "/v1/agent/heartbeat", json=heartbeat_body(), headers=agent_headers()
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_REVOKED"


# ------------------------------------------------------------------- renewal
async def test_renew_credential_ratified_body_and_cache_delete(client, fake_redis, sql):
    await seed_device(fake_redis)
    sql.on(r"UPDATE tenantdata\.devices SET prev_cert_serial", value="serial1")
    response = await client.post(
        "/v1/agent/renew-credential", json={"csr_pem": make_csr()}, headers=agent_headers()
    )
    assert response.status_code == 200
    body = response.json()
    # Ratified §10 body: exactly these three fields.
    assert set(body) == {"certificate_pem", "ca_chain_pem", "certificate_expires_at"}
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "dev_TEST"  # SEC-11: same device identity
    # audit carries old/new serials
    assert sql.executed(r"INSERT INTO audit_log")
    # delete-on-change: allowlist cache dropped
    assert await fake_redis.hgetall(f"device:{TENANT_ID}:dev_TEST") == {}


async def test_renewal_overlap_old_serial_accepted_within_24h(client, fake_redis, sql):
    until = (datetime.now(UTC) + timedelta(hours=23)).isoformat()
    await seed_device(
        fake_redis, cert_serial="newserial", prev_cert_serial="oldserial",
        prev_valid_until=until,
    )
    sql.on(r"UPDATE tenantdata\.devices SET last_heartbeat_at", rows=[{"asset_id": uuid4()}])
    response = await client.post(
        "/v1/agent/heartbeat",
        json=heartbeat_body(),
        headers=agent_headers(serial="oldserial"),
    )
    assert response.status_code == 200


async def test_renewal_overlap_old_serial_rejected_after_24h(client, fake_redis):
    until = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    await seed_device(
        fake_redis, cert_serial="newserial", prev_cert_serial="oldserial",
        prev_valid_until=until,
    )
    response = await client.post(
        "/v1/agent/heartbeat",
        json=heartbeat_body(),
        headers=agent_headers(serial="oldserial"),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_IDENTITY_INVALID"


# -------------------------------------------------------------- device revoke
async def test_device_revoke_deletes_cache_and_marks_asset(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    await seed_device(fake_redis)  # cached allowlist entry to be dropped
    sql.on(r"UPDATE tenantdata\.devices SET status = 'revoked'", rows=[{"asset_id": uuid4()}])
    response = await client.post(
        "/v1/devices/dev_TEST/revoke", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    # <=60s SLO: cache deleted immediately; TTL is only the worst case.
    assert await fake_redis.hgetall(f"device:{TENANT_ID}:dev_TEST") == {}
    assert sql.executed(r"UPDATE tenantdata\.assets SET agent_status = 'revoked'")
    assert sql.executed(r"INSERT INTO audit_log")


async def test_device_revoke_unknown_404(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/devices/dev_NOPE/revoke", **session_kwargs(sid, csrf)
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


async def test_enrollment_token_create_show_once(client, fake_redis, sql):
    sid, csrf = await make_session(fake_redis)
    await seed_tenant_status(fake_redis)
    response = await client.post(
        "/v1/enrollment-tokens", json={"name": "rollout"}, **session_kwargs(sid, csrf)
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token"].startswith(body["id"] + ".")
    assert body["token"] in body["install_command"]
    assert "INGEST_URL" in body["install_command"]
    insert_args = sql.executed(r"INSERT INTO tenantdata\.enrollment_tokens")[0][1]
    assert body["token"].split(".", 1)[1] not in insert_args  # only the hash is stored
