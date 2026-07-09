"""Rule-pack state for worker-detector: PG load, 30s hot reload, effective
enablement (AC-38/39, SEC-28(a), design §5 rule row).

Effective-enabled for (rule, tenant) =
    pack ``enabled_default``
    overridden by the tenant's ``rule_toggles`` row when one exists (AC-38)
    AND rule not in ``rule_runtime_disables`` (SEC-28(c) — beats any toggle)
    AND rule compiled successfully at load (SEC-28(a)).

Both overlays are cached for <= 30 seconds (AC-38: a toggle takes effect on
new events within 30s; same bound as the pack-version poll of AC-39).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence, Set
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from dataplane.rulepub.compiler import CompiledRule, RuleCompileError, compile_rule
from dataplane.workers.common import tenant_transaction

logger = logging.getLogger(__name__)

PACK_POLL_INTERVAL_SECONDS = 30.0
"""AC-39: the detector polls the active pack version every 30s (no restart)."""

OVERLAY_TTL_SECONDS = 30.0
"""AC-38: runtime-disable + per-tenant toggle overlays cached <= 30s."""

SQL_ACTIVE_PACK_VERSION = (
    "SELECT version FROM tenantdata.rule_packs "
    "WHERE status = 'active' ORDER BY published_at DESC LIMIT 1"
)
SQL_FETCH_PACK_RULES = (
    "SELECT pack_version, rule_id, rule_version, definition, enabled_default "
    "FROM tenantdata.rules WHERE pack_version = $1 ORDER BY rule_id"
)
SQL_FETCH_RUNTIME_DISABLED = "SELECT rule_id FROM tenantdata.rule_runtime_disables"
SQL_FETCH_TENANT_TOGGLES = (
    "SELECT rule_id, enabled FROM tenantdata.rule_toggles WHERE tenant_id = $1"
)
SQL_INSERT_RUNTIME_DISABLE = (
    "INSERT INTO tenantdata.rule_runtime_disables "
    "(rule_id, reason, error_fraction, tenants_affected, created_by) "
    "VALUES ($1, $2, $3, $4, 'worker-detector') "
    "ON CONFLICT (rule_id) DO NOTHING"
)


@dataclass(frozen=True)
class RuleRow:
    """One tenantdata.rules row as the detector needs it."""

    pack_version: str
    rule_id: str
    rule_version: str
    definition: Mapping[str, Any]
    enabled_default: bool


class RuleStore(Protocol):
    """Persistence surface the detector needs (PG in prod, fake in tests)."""

    async def active_pack_version(self) -> str | None: ...

    async def fetch_rules(self, pack_version: str) -> Sequence[RuleRow]: ...

    async def fetch_runtime_disabled(self) -> Set[str]: ...

    async def fetch_tenant_toggles(self, tenant_id: UUID | str) -> Mapping[str, bool]: ...

    async def insert_runtime_disable(
        self, *, rule_id: str, reason: str, error_fraction: float, tenants_affected: int
    ) -> bool: ...


@dataclass(frozen=True)
class LoadedRule:
    compiled: CompiledRule
    enabled_default: bool

    @property
    def rule_id(self) -> str:
        return self.compiled.rule_id


class LoadedPack:
    """Compiled, class-indexed view of one published pack version."""

    def __init__(
        self,
        pack_version: str,
        rules: Iterable[LoadedRule],
        load_errors: Mapping[str, str] | None = None,
    ) -> None:
        self.pack_version = pack_version
        self.load_errors: dict[str, str] = dict(load_errors or {})
        by_class: dict[str, list[LoadedRule]] = {}
        for rule in rules:
            by_class.setdefault(rule.compiled.event_class, []).append(rule)
        self._by_class: dict[str, tuple[LoadedRule, ...]] = {
            cls: tuple(items) for cls, items in by_class.items()
        }

    @classmethod
    def from_rows(cls, pack_version: str, rows: Sequence[RuleRow]) -> LoadedPack:
        """Compile PG rule rows. SEC-28(a): a compile error at detector load
        time (should not happen post-publish) disables THAT rule and fires an
        ops alert — all other rules keep running."""
        loaded: list[LoadedRule] = []
        load_errors: dict[str, str] = {}
        for row in rows:
            definition = row.definition
            if isinstance(definition, str):  # asyncpg returns jsonb as text
                definition = json.loads(definition)
            try:
                compiled = compile_rule(definition)
            except RuleCompileError as exc:
                load_errors[row.rule_id] = str(exc)
                logger.error(
                    "ops_alert: rule failed to compile at detector load time; "
                    "rule disabled (SEC-28a)",
                    extra={
                        "ops_alert": "rule_compile_error_at_load",
                        "rule_id": row.rule_id,
                        "pack_version": pack_version,
                        "error": str(exc),
                    },
                )
                continue
            loaded.append(LoadedRule(compiled=compiled, enabled_default=row.enabled_default))
        return cls(pack_version, loaded, load_errors)

    def candidates(self, event_class: Any) -> tuple[LoadedRule, ...]:
        """§5.1 gate 1: rules whose event_class equals the event's (exact)."""
        if not isinstance(event_class, str):
            return ()
        return self._by_class.get(event_class, ())

    @property
    def rule_count(self) -> int:
        return sum(len(rules) for rules in self._by_class.values())


class PackManager:
    """Holds the current LoadedPack; hot-reloads on version change (AC-39)."""

    def __init__(
        self,
        store: RuleStore,
        *,
        poll_interval_seconds: float = PACK_POLL_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._poll_interval = poll_interval_seconds
        self._pack: LoadedPack | None = None
        self._lock = asyncio.Lock()

    @property
    def pack(self) -> LoadedPack | None:
        return self._pack

    async def ensure_loaded(self) -> LoadedPack | None:
        if self._pack is None:
            await self.refresh()
        return self._pack

    async def refresh(self) -> bool:
        """Check the active pack version; reload on change. True if reloaded."""
        async with self._lock:
            version = await self._store.active_pack_version()
            if version is None:
                if self._pack is not None:
                    logger.warning("no active rule pack in PG; keeping last loaded pack")
                return False
            if self._pack is not None and self._pack.pack_version == version:
                return False
            rows = await self._store.fetch_rules(version)
            pack = LoadedPack.from_rows(version, rows)
            previous = self._pack.pack_version if self._pack else None
            self._pack = pack
            logger.info(
                "rule pack loaded",
                extra={
                    "pack_version": version,
                    "previous_version": previous,
                    "rule_count": pack.rule_count,
                    "load_disabled": sorted(pack.load_errors),
                },
            )
            return True

    async def poll_forever(self, stop: asyncio.Event) -> None:
        """30s version poll (AC-39). Errors are logged, never fatal."""
        while not stop.is_set():
            try:
                await self.refresh()
            except Exception:
                logger.exception("rule pack refresh failed; will retry")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._poll_interval)
            except TimeoutError:
                continue


class EnablementCache:
    """Effective-enablement overlay with <= 30s TTL caches (AC-38)."""

    def __init__(
        self,
        store: RuleStore,
        *,
        ttl_seconds: float = OVERLAY_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._ttl = ttl_seconds
        self._clock = clock
        self._runtime_disabled: Set[str] = frozenset()
        self._runtime_expires = 0.0
        self._toggles: dict[str, tuple[float, Mapping[str, bool]]] = {}

    async def runtime_disabled(self) -> Set[str]:
        now = self._clock()
        if now >= self._runtime_expires:
            self._runtime_disabled = frozenset(await self._store.fetch_runtime_disabled())
            self._runtime_expires = now + self._ttl
        return self._runtime_disabled

    async def tenant_toggles(self, tenant_id: UUID | str) -> Mapping[str, bool]:
        key = str(tenant_id)
        now = self._clock()
        cached = self._toggles.get(key)
        if cached is not None and now < cached[0]:
            return cached[1]
        toggles = dict(await self._store.fetch_tenant_toggles(tenant_id))
        if len(self._toggles) > 10_000:  # bounded memory: drop expired entries
            self._toggles = {
                k: v for k, v in self._toggles.items() if v[0] > now
            }
        self._toggles[key] = (now + self._ttl, toggles)
        return toggles

    def note_runtime_disable(self, rule_id: str) -> None:
        """Apply a runtime disable locally at once (don't wait out the TTL)."""
        self._runtime_disabled = frozenset(self._runtime_disabled | {rule_id})

    async def is_enabled(self, rule: LoadedRule, tenant_id: UUID | str) -> bool:
        if rule.rule_id in await self.runtime_disabled():
            return False  # SEC-28(c) disable beats any tenant toggle
        toggles = await self.tenant_toggles(tenant_id)
        return toggles.get(rule.rule_id, rule.enabled_default)


class PostgresRuleStore:
    """RuleStore over an asyncpg pool.

    rule_packs/rules/rule_runtime_disables are GLOBAL tables (no RLS,
    migration 0006 header); rule_toggles is tenant-scoped + RLS, so that
    read runs inside an RLS-pinned transaction (SEC-23).
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def active_pack_version(self) -> str | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(SQL_ACTIVE_PACK_VERSION)

    async def fetch_rules(self, pack_version: str) -> Sequence[RuleRow]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(SQL_FETCH_PACK_RULES, pack_version)
        out: list[RuleRow] = []
        for row in rows:
            definition = row["definition"]
            if isinstance(definition, str):
                definition = json.loads(definition)
            out.append(
                RuleRow(
                    pack_version=row["pack_version"],
                    rule_id=row["rule_id"],
                    rule_version=row["rule_version"],
                    definition=definition,
                    enabled_default=row["enabled_default"],
                )
            )
        return out

    async def fetch_runtime_disabled(self) -> Set[str]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(SQL_FETCH_RUNTIME_DISABLED)
        return {row["rule_id"] for row in rows}

    async def fetch_tenant_toggles(self, tenant_id: UUID | str) -> Mapping[str, bool]:
        async with tenant_transaction(self._pool, tenant_id) as conn:
            rows = await conn.fetch(SQL_FETCH_TENANT_TOGGLES, UUID(str(tenant_id)))
        return {row["rule_id"]: row["enabled"] for row in rows}

    async def insert_runtime_disable(
        self, *, rule_id: str, reason: str, error_fraction: float, tenants_affected: int
    ) -> bool:
        async with self._pool.acquire() as conn:
            status = await conn.execute(
                SQL_INSERT_RUNTIME_DISABLE, rule_id, reason, error_fraction, tenants_affected
            )
        return isinstance(status, str) and status.endswith("1")


__all__ = [
    "OVERLAY_TTL_SECONDS",
    "PACK_POLL_INTERVAL_SECONDS",
    "EnablementCache",
    "LoadedPack",
    "LoadedRule",
    "PackManager",
    "PostgresRuleStore",
    "RuleRow",
    "RuleStore",
]
