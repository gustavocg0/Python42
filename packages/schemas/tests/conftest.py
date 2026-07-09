"""Shared fixtures: the four JSON examples from docs/contracts/event-schema.md §4."""

import pytest

TENANT_ID = "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f"
BATCH_ID = "0b7e3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c6d"


@pytest.fixture
def process_event() -> dict:
    return {
        "event_id": "5f0c9a52-1b2e-4c3d-9e8f-7a6b5c4d3e2f",
        "tenant_id": TENANT_ID,
        "schema_version": "1.0.0",
        "event_class": "process_activity",
        "activity": "process_launched",
        "event_time": "2026-07-08T09:14:03.221Z",
        "ingest_time": "2026-07-08T09:14:05.100Z",
        "source_type": "agent",
        "source_event_id": "etw-4688-000123456",
        "batch_id": BATCH_ID,
        "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
        "host": {
            "hostname": "fin-laptop-07",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
            "ip": "10.1.4.23",
            "mac": "a4:bb:6d:12:34:56",
        },
        "process": {
            "pid": 4312,
            "name": "powershell.exe",
            "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cmd_line": "powershell -enc SQBFAFgA...",
            "sha256": "9f2c" + "a" * 56 + "aa10",
        },
        "parent": {
            "pid": 1180,
            "name": "winword.exe",
            "exe_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        },
        "user": {"name": "sam.jones", "domain": "ACME", "uid": "S-1-5-21-...-1104"},
    }


@pytest.fixture
def network_event() -> dict:
    return {
        "event_id": "a1b2c3d4-0000-4000-8000-000000000001",
        "tenant_id": TENANT_ID,
        "schema_version": "1.0.0",
        "event_class": "network_activity",
        "activity": "connection_opened",
        "event_time": "2026-07-08T09:14:04.001Z",
        "ingest_time": "2026-07-08T09:14:05.100Z",
        "source_type": "agent",
        "source_event_id": "etw-net-000778812",
        "batch_id": BATCH_ID,
        "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
        "host": {
            "hostname": "fin-laptop-07",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
        },
        "direction": "outbound",
        "protocol": "tcp",
        "src": {"ip": "10.1.4.23", "port": 51544},
        "dst": {"ip": "185.220.101.7", "port": 443, "hostname": "unknown-host.example"},
        "process": {"pid": 4312, "name": "powershell.exe"},
    }


@pytest.fixture
def auth_event() -> dict:
    return {
        "event_id": "a1b2c3d4-0000-4000-8000-000000000002",
        "tenant_id": TENANT_ID,
        "schema_version": "1.0.0",
        "event_class": "authentication",
        "activity": "logon_failed",
        "event_time": "2026-07-08T09:13:59.900Z",
        "ingest_time": "2026-07-08T09:14:05.100Z",
        "source_type": "agent",
        "source_event_id": "etw-4625-000031007",
        "batch_id": BATCH_ID,
        "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
        "host": {
            "hostname": "fin-laptop-07",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
        },
        "status": "failure",
        "logon_type": "remote_interactive",
        "user": {"name": "administrator", "domain": "ACME"},
        "src_ip": "203.0.113.50",
        "failure_reason": "bad_password",
    }


@pytest.fixture
def generic_event() -> dict:
    return {
        "event_id": "a1b2c3d4-0000-4000-8000-000000000003",
        "tenant_id": TENANT_ID,
        "schema_version": "1.0.0",
        "event_class": "generic",
        "activity": "log",
        "event_time": "2026-07-08T09:12:00Z",
        "ingest_time": "2026-07-08T09:14:06.400Z",
        "source_type": "generic",
        "source_event_id": "fw-88213",
        "batch_id": "77aa3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c99",
        "source": {"ingest_key_id": "ik_01J9ZKAB", "vendor": "acme-fw", "product": "edge-fw-200"},
        "host": {
            "hostname": "edge-fw-1",
            "os_family": "other",
            "os_name": "AcmeFW OS",
            "os_version": "4.2",
        },
        "message": "Blocked outbound connection to known-bad IP",
        "category": "firewall.block",
        "fields": {"src_ip": "10.1.4.23", "dst_ip": "185.220.101.7", "action": "block"},
        "raw": {"ts": 1783514000, "msg": "BLOCK out 10.1.4.23->185.220.101.7:443", "rule": 17},
    }
