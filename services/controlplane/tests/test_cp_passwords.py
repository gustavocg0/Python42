"""Password policy + breached checker unit tests (SEC-1)."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from controlplane.security.passwords import (
    FileBreachedPasswordChecker,
    PasswordPolicyViolation,
    PasswordService,
    validate_password_policy,
)


def test_policy_boundaries():
    validate_password_policy("a" * 12)
    validate_password_policy("a" * 512)
    with pytest.raises(PasswordPolicyViolation):
        validate_password_policy("a" * 11)
    with pytest.raises(PasswordPolicyViolation):
        validate_password_policy("a" * 513)


async def test_bundled_breached_list_case_insensitive():
    checker = FileBreachedPasswordChecker()
    assert await checker.is_breached("password12345")
    assert await checker.is_breached("PASSWORD12345")
    assert not await checker.is_breached("orange-battery-staple-42")


async def test_hash_and_verify_roundtrip():
    service = PasswordService(PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1))
    digest = await service.hash("orange-battery-staple-42")
    assert digest.startswith("$argon2id$")
    assert await service.verify(digest, "orange-battery-staple-42")
    assert not await service.verify(digest, "wrong-password-1")
    await service.dummy_verify()  # must not raise
