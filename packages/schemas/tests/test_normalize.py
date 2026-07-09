from soc_schemas import (
    CLIENT_ASSIGNED_FIELDS,
    move_unknown_to_unmapped,
    parse_event,
    strip_client_assigned_fields,
    truncate_generic_raw,
)


def test_strip_client_assigned_fields_sec18(process_event):
    payload = dict(process_event)
    payload["tenant_id"] = "11111111-1111-4111-8111-111111111111"  # attacker-claimed
    stripped = strip_client_assigned_fields(payload)
    for field in CLIENT_ASSIGNED_FIELDS:
        assert field not in stripped
    assert "process" in stripped  # class content untouched


def test_move_unknown_to_unmapped_preserves_fields(process_event):
    process_event["vendor_specific_thing"] = {"a": 1}
    normalized = move_unknown_to_unmapped(process_event)
    assert normalized["unmapped"]["vendor_specific_thing"] == {"a": 1}
    assert "vendor_specific_thing" not in normalized
    event = parse_event(normalized)
    assert event.unmapped == {"vendor_specific_thing": {"a": 1}}


def test_move_unknown_merges_existing_unmapped(process_event):
    process_event["unmapped"] = {"prior": True}
    process_event["extra"] = 1
    normalized = move_unknown_to_unmapped(process_event)
    assert normalized["unmapped"] == {"prior": True, "extra": 1}


def test_truncate_generic_raw_under_cap():
    raw, truncated = truncate_generic_raw({"msg": "small"})
    assert raw == {"msg": "small"}
    assert truncated is False


def test_truncate_generic_raw_over_cap(generic_event):
    big = {"blob": "x" * (64 * 1024)}
    raw, truncated = truncate_generic_raw(big)
    assert truncated is True
    generic_event["raw"] = raw
    generic_event["raw_truncated"] = True
    parse_event(generic_event)  # truncated form always validates
