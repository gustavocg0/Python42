"""Fixtures for dataplane API tests — fakes only, no live services.

All fake classes and helpers live in `dp_api_testkit` (a uniquely named
module, importable even when multiple test roots are collected together).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from dp_api_testkit import (
    GATEWAY_SECRET,
    INTERNAL_KEY,
    FakeConn,
    FakeES,
    FakePool,
    SqlRouter,
    StubEntitlements,
)

from dataplane.core.ca import CertificateAuthority
from dataplane.core.db import Database
from dataplane.core.quotas import QuotaService
from dataplane.core.resources import AppResources
from dataplane.core.sessions import SessionStore
from dataplane.core.settings import Settings
from dataplane.core.status_stores import StatusStores
from dataplane.internal_main import create_internal_app
from dataplane.main import create_app
from soc_pipeline import StreamProducer
from soc_telemetry import PipelineMetrics


@pytest.fixture(scope="session")
def dev_ca(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SOC Dev CA")])
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("ca")
    cert_path = directory / "ca.pem"
    key_path = directory / "ca.key"
    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {"cert": str(cert_path), "key": str(key_path)}


@pytest.fixture
def settings(dev_ca: dict[str, str]) -> Settings:
    return Settings(
        database_url="postgresql://fake/fake",
        redis_url="redis://fake",
        es_url="http://fake:9200",
        gateway_auth_secret=GATEWAY_SECRET,
        ca_cert_path=dev_ca["cert"],
        ca_key_path=dev_ca["key"],
        entitlements_base_url="http://controlplane:8081",
        entitlements_signing_key="e" * 32,
        internal_service_keys={"controlplane": INTERNAL_KEY},
        public_ingest_base_url="https://ingest.example.test",
    )


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
def sql() -> SqlRouter:
    return SqlRouter()


@pytest.fixture
def fake_es() -> FakeES:
    return FakeES()


@pytest.fixture
def entitlements() -> StubEntitlements:
    return StubEntitlements()


@pytest.fixture
def resources(settings, fake_redis, sql, fake_es, entitlements) -> AppResources:
    db = Database(FakePool(FakeConn(sql)))
    return AppResources(
        settings=settings,
        db=db,
        redis=fake_redis,
        es=fake_es,
        producer=StreamProducer(fake_redis),
        entitlements=entitlements,
        status_stores=StatusStores(fake_redis, db),
        quotas=QuotaService(fake_redis),
        sessions=SessionStore(fake_redis),
        ca=CertificateAuthority.from_files(
            settings.ca_cert_path, settings.ca_key_path, lifetime_days=90
        ),
        metrics=PipelineMetrics(),
    )


@pytest.fixture
def app(settings, resources):
    return create_app(settings, resources)


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://dp.test") as c:
        yield c


@pytest.fixture
def internal_app(settings, resources):
    return create_internal_app(settings, resources)


@pytest_asyncio.fixture
async def internal_client(internal_app):
    transport = httpx.ASGITransport(app=internal_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://dp-int.test") as c:
        yield c
