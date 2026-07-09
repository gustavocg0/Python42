"""Tenancy errors — all fail closed."""


class TenancyError(Exception):
    """Base class for tenancy failures."""


class InvalidTenantError(TenancyError):
    """tenant_id absent or not a valid UUID — refuse before any data access (SEC-24)."""


class TenantContextError(TenancyError):
    """An operation required tenant context but none was established."""
