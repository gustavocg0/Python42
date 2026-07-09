import pytest

from soc_audit import (
    REDACTED,
    AuditValueTooLarge,
    redact_secrets,
    serialize_audit_value,
)


@pytest.mark.parametrize(
    "key",
    [
        "token",
        "enrollment_token",
        "password",
        "user_password",
        "secret",
        "client_secret",
        "api_key",
        "private_key",
        "ingest_key",
        "key",
        "keys",
        "session.key",
    ],
)
def test_secret_named_keys_redacted(key):
    assert redact_secrets({key: "hunter2"})[key] == REDACTED


@pytest.mark.parametrize("key", ["monkey", "keyboard", "hockey_team", "role", "plan"])
def test_innocent_keys_untouched(key):
    assert redact_secrets({key: "value"})[key] == "value"


def test_nested_and_list_redaction():
    data = {"user": {"password": "x", "name": "sam"}, "items": [{"token": "t", "id": 1}]}
    redacted = redact_secrets(data)
    assert redacted["user"]["password"] == REDACTED
    assert redacted["user"]["name"] == "sam"
    assert redacted["items"][0]["token"] == REDACTED
    assert redacted["items"][0]["id"] == 1


def test_serialize_none_passthrough():
    assert serialize_audit_value(None) is None


def test_serialize_caps_size():
    with pytest.raises(AuditValueTooLarge):
        serialize_audit_value({"raw": "x" * (17 * 1024)})


def test_serialize_rejects_non_mapping():
    with pytest.raises(TypeError):
        serialize_audit_value("a raw payload string")  # type: ignore[arg-type]


def test_serialize_applies_redaction():
    assert '"[REDACTED]"' in serialize_audit_value({"token": "abc"})
