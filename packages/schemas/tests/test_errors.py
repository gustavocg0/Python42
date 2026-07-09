import json

from soc_schemas import ERROR_HTTP_STATUS, ApiError, ErrorCode, error_envelope


def test_every_code_has_a_status():
    assert set(ERROR_HTTP_STATUS) == set(ErrorCode)


def test_envelope_wire_shape():
    env = error_envelope(
        ErrorCode.INGEST_QUOTA_EXCEEDED,
        "Ingest quota exceeded",
        retry_after_seconds=30,
    )
    data = json.loads(env.model_dump_json(exclude_none=True))
    assert data == {
        "error": {
            "code": "INGEST_QUOTA_EXCEEDED",
            "message": "Ingest quota exceeded",
            "retry_after_seconds": 30,
        }
    }


def test_tenant_frozen_details_cause():
    env = error_envelope(ErrorCode.TENANT_FROZEN, "Tenant frozen", details={"cause": "abuse"})
    assert env.error.details == {"cause": "abuse"}


def test_api_error_defaults_status_from_taxonomy():
    err = ApiError(ErrorCode.ENTITLEMENTS_UNAVAILABLE, "cold cache", retry_after_seconds=15)
    assert err.status_code == 503
    assert err.envelope().error.code == ErrorCode.ENTITLEMENTS_UNAVAILABLE
    assert err.envelope().error.retry_after_seconds == 15


def test_api_error_status_override():
    err = ApiError(ErrorCode.TENANT_FROZEN, "frozen", status_code=403)
    assert err.status_code == 403


def test_internal_error_is_500_and_distinct_from_service_unavailable():
    # Architect-ratified 2026-07-08: unhandled server errors use INTERNAL_ERROR;
    # SERVICE_UNAVAILABLE stays reserved for fail-closed dependency denials.
    assert ERROR_HTTP_STATUS[ErrorCode.INTERNAL_ERROR] == 500
    assert ApiError(ErrorCode.INTERNAL_ERROR, "boom").status_code == 500
    assert ErrorCode.INTERNAL_ERROR != ErrorCode.SERVICE_UNAVAILABLE
    assert ERROR_HTTP_STATUS[ErrorCode.SERVICE_UNAVAILABLE] == 503
