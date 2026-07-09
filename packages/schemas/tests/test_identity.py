import hashlib

import pytest

from soc_schemas import derive_es_document_id

TENANT = "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f"


def test_known_vector():
    expected = hashlib.sha256(
        f"{TENANT}:dev_01J9ZK3T:etw-4688-000123456".encode()
    ).hexdigest()
    assert derive_es_document_id(TENANT, "dev_01J9ZK3T", "etw-4688-000123456") == expected


def test_deterministic_and_scope_sensitive():
    a = derive_es_document_id(TENANT, "dev_A", "e1")
    assert a == derive_es_document_id(TENANT, "dev_A", "e1")
    assert a != derive_es_document_id(TENANT, "dev_B", "e1")
    assert a != derive_es_document_id(TENANT, "dev_A", "e2")


def test_tenant_id_canonicalized():
    assert derive_es_document_id(TENANT.upper(), "d", "e") == derive_es_document_id(TENANT, "d", "e")


def test_invalid_tenant_rejected():
    with pytest.raises(ValueError):
        derive_es_document_id("not-a-uuid", "d", "e")


def test_empty_parts_rejected():
    with pytest.raises(ValueError):
        derive_es_document_id(TENANT, "", "e")
    with pytest.raises(ValueError):
        derive_es_document_id(TENANT, "d", "")
