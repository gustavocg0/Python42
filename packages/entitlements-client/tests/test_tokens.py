"""HMAC service-token tests (design §5.1 item 2, SEC-40)."""

import pytest

from soc_entitlements import (
    ExpiredServiceToken,
    InvalidServiceToken,
    generate_service_token,
    verify_service_token,
)

KEY = b"k" * 32
KEYS = {"dataplane": KEY}
NOW = 1_780_000_000


def test_round_trip():
    token = generate_service_token(service_name="dataplane", key=KEY, now=NOW)
    assert token.startswith("v1.dataplane.")
    assert verify_service_token(token, keys=KEYS, now=NOW) == "dataplane"


def test_expired_beyond_skew_rejected():
    token = generate_service_token(service_name="dataplane", key=KEY, ttl_seconds=60, now=NOW)
    with pytest.raises(ExpiredServiceToken):
        verify_service_token(token, keys=KEYS, now=NOW + 60 + 31)


def test_expired_within_skew_accepted():
    token = generate_service_token(service_name="dataplane", key=KEY, ttl_seconds=60, now=NOW)
    assert verify_service_token(token, keys=KEYS, now=NOW + 60 + 29) == "dataplane"


def test_tampered_signature_rejected():
    token = generate_service_token(service_name="dataplane", key=KEY, now=NOW)
    head, sig = token.rsplit(".", 1)
    bad = head + "." + ("0" if sig[0] != "0" else "1") + sig[1:]
    with pytest.raises(InvalidServiceToken):
        verify_service_token(bad, keys=KEYS, now=NOW)


def test_tampered_service_name_rejected():
    token = generate_service_token(service_name="dataplane", key=KEY, now=NOW)
    forged = token.replace("v1.dataplane.", "v1.controlplane.", 1)
    with pytest.raises(InvalidServiceToken):
        verify_service_token(forged, keys={"controlplane": KEY, "dataplane": KEY}, now=NOW)


def test_unknown_service_rejected():
    token = generate_service_token(service_name="dataplane", key=KEY, now=NOW)
    with pytest.raises(InvalidServiceToken):
        verify_service_token(token, keys={}, now=NOW)


def test_over_lifetime_token_rejected():
    # expires further out than 300s + skew: forged/misconfigured — refuse.
    forged = generate_service_token(service_name="dataplane", key=KEY, ttl_seconds=300, now=NOW)
    with pytest.raises(InvalidServiceToken):
        verify_service_token(forged, keys=KEYS, now=NOW - 100)


@pytest.mark.parametrize(
    "bad",
    ["", "v1", "v2.dataplane.123.abc", "v1.dataplane.notanint.abc", "v1..123.abc"],
)
def test_malformed_tokens_rejected(bad):
    with pytest.raises(InvalidServiceToken):
        verify_service_token(bad, keys=KEYS, now=NOW)


def test_generate_enforces_max_ttl_and_key_length():
    with pytest.raises(ValueError):
        generate_service_token(service_name="dataplane", key=KEY, ttl_seconds=301)
    with pytest.raises(ValueError):
        generate_service_token(service_name="dataplane", key=b"short")
    with pytest.raises(ValueError):
        generate_service_token(service_name="Bad.Name", key=KEY)


def test_key_lookup_callable():
    token = generate_service_token(service_name="dataplane", key=KEY, now=NOW)
    assert (
        verify_service_token(
            token, keys=lambda name: KEY if name == "dataplane" else None, now=NOW
        )
        == "dataplane"
    )
