"""Fixtures: fully-faked controlplane environments (no live PG/ES/Redis)."""

from __future__ import annotations

import pytest
from cp_env import Env, make_env


@pytest.fixture
async def env_factory():
    created: list[Env] = []

    async def factory(**overrides) -> Env:
        e = await make_env(**overrides)
        created.append(e)
        return e

    yield factory
    for e in created:
        await e.aclose()


@pytest.fixture
async def env(env_factory) -> Env:
    return await env_factory()
