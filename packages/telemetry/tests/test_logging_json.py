import io
import json
import logging

from soc_telemetry import JsonLogFormatter, configure_json_logging


def make_logger(stream):
    logger = logging.getLogger("test.soc")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLogFormatter("dataplane-api"))
    logger.handlers = [handler]
    return logger


def test_json_line_structure():
    stream = io.StringIO()
    logger = make_logger(stream)
    logger.info("batch accepted", extra={"tenant_id": "t-1", "batch_id": "b_1"})
    entry = json.loads(stream.getvalue())
    assert entry["message"] == "batch accepted"
    assert entry["service"] == "dataplane-api"
    assert entry["level"] == "INFO"
    assert entry["logger"] == "test.soc"
    assert entry["tenant_id"] == "t-1"
    assert entry["batch_id"] == "b_1"
    assert "ts" in entry


def test_secret_extras_redacted():
    stream = io.StringIO()
    logger = make_logger(stream)
    logger.info("key created", extra={"ingest_key": "ik_1.supersecret", "label": "fw"})
    entry = json.loads(stream.getvalue())
    assert entry["ingest_key"] == "[REDACTED]"
    assert entry["label"] == "fw"


def test_exception_serialized_as_text():
    stream = io.StringIO()
    logger = make_logger(stream)
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logger.exception("failed")
    entry = json.loads(stream.getvalue())
    assert entry["level"] == "ERROR"
    assert "RuntimeError: boom" in entry["exception"]


def test_configure_json_logging_idempotent():
    stream = io.StringIO()
    first = configure_json_logging("svc", stream=stream)
    second = configure_json_logging("svc", stream=stream)
    root = logging.getLogger()
    json_handlers = [h for h in root.handlers if isinstance(h.formatter, JsonLogFormatter)]
    assert json_handlers == [second]
    root.removeHandler(second)
    assert first is not second
