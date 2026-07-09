"""Validation tests against the contract's own examples (event-schema.md §4)."""

import pytest

from soc_schemas import (
    SCHEMA_VERSION,
    AuthenticationEvent,
    GenericEvent,
    MalformedEventError,
    NetworkActivityEvent,
    ProcessActivityEvent,
    parse_event,
)


def test_schema_version_constant():
    assert SCHEMA_VERSION == "1.0.0"


def test_contract_examples_parse(process_event, network_event, auth_event, generic_event):
    assert isinstance(parse_event(process_event), ProcessActivityEvent)
    assert isinstance(parse_event(network_event), NetworkActivityEvent)
    assert isinstance(parse_event(auth_event), AuthenticationEvent)
    assert isinstance(parse_event(generic_event), GenericEvent)


def test_hostname_lowercased(process_event):
    process_event["host"]["hostname"] = "FIN-Laptop-07"
    event = parse_event(process_event)
    assert event.host.hostname == "fin-laptop-07"


def test_mac_format_enforced(process_event):
    process_event["host"]["mac"] = "A4-BB-6D-12-34-56"
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_unknown_event_class_rejected(process_event):
    process_event["event_class"] = "registry_activity"
    with pytest.raises(MalformedEventError) as exc:
        parse_event(process_event)
    assert exc.value.error_code == "UNKNOWN_EVENT_CLASS"


def test_missing_required_field_dead_letters(process_event):
    del process_event["process"]
    with pytest.raises(MalformedEventError) as exc:
        parse_event(process_event)
    assert exc.value.error_code == "SCHEMA_VALIDATION_FAILED"


def test_launched_requires_cmd_line_and_parent(process_event):
    del process_event["process"]["cmd_line"]
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_agent_event_requires_source_event_id(process_event):
    del process_event["source_event_id"]
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_agent_event_requires_host(process_event):
    del process_event["host"]
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_source_device_xor_ingest_key(process_event):
    process_event["source"]["ingest_key_id"] = "ik_01J9ZKAB"
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_tcp_requires_ports(network_event):
    del network_event["src"]["port"]
    with pytest.raises(MalformedEventError):
        parse_event(network_event)


def test_icmp_ports_optional(network_event):
    network_event["protocol"] = "icmp"
    del network_event["src"]["port"]
    del network_event["dst"]["port"]
    parse_event(network_event)


def test_logon_failed_derives_failure_status(auth_event):
    del auth_event["status"]
    event = parse_event(auth_event)
    assert event.status == "failure"


def test_logon_failed_requires_failure_reason(auth_event):
    del auth_event["failure_reason"]
    with pytest.raises(MalformedEventError):
        parse_event(auth_event)


def test_generic_requires_message_and_raw(generic_event):
    del generic_event["message"]
    with pytest.raises(MalformedEventError):
        parse_event(generic_event)


def test_generic_oversized_raw_rejected(generic_event):
    generic_event["raw"] = {"blob": "x" * (33 * 1024)}
    with pytest.raises(MalformedEventError):
        parse_event(generic_event)


def test_unknown_top_level_field_rejected_by_strict_model(process_event):
    # extras must be moved to `unmapped` first (move_unknown_to_unmapped);
    # the strict model never accepts stray fields silently.
    process_event["totally_new_field"] = 1
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_unmapped_size_cap(process_event):
    process_event["unmapped"] = {"big": "x" * (17 * 1024)}
    with pytest.raises(MalformedEventError):
        parse_event(process_event)


def test_naive_datetime_rejected(process_event):
    process_event["event_time"] = "2026-07-08T09:14:03"  # no timezone
    with pytest.raises(MalformedEventError):
        parse_event(process_event)
