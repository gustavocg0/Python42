"""Pytest fixtures for the triage suite (fakes live in triage_fixtures.py)."""

from __future__ import annotations

import pytest
from triage_fixtures import FakePool, FakeStore

from dataplane.triage.config import TriageSettings


@pytest.fixture
def settings() -> TriageSettings:
    return TriageSettings(backoff_base_s=0.0)  # no real sleeps in tests


@pytest.fixture
def fake_redis():
    import fakeredis.aioredis

    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def pool(store: FakeStore) -> FakePool:
    return FakePool(store)
