"""Opaque cursor pagination (contract §1: limit default 50 / max 200,
response {"items": [...], "next_cursor": ..., "total_estimate": int})."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from soc_schemas import ApiError, ErrorCode

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1 or limit > MAX_LIMIT:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            f"limit must be between 1 and {MAX_LIMIT}.",
            details={"fields": ["limit"]},
        )
    return limit


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str) -> dict[str, Any]:
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, "cursor is invalid.", details={"fields": ["cursor"]}
        ) from None
    if not isinstance(payload, dict):
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, "cursor is invalid.", details={"fields": ["cursor"]}
        )
    return payload


def page(items: list[Any], next_cursor: str | None, total_estimate: int) -> dict[str, Any]:
    return {"items": items, "next_cursor": next_cursor, "total_estimate": total_estimate}
