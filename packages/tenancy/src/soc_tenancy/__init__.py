"""soc_tenancy — the ONLY place tenant context is established (design §2, AC-82).

Tenant context enters exclusively via this package:
- session -> tenant, ingest key -> tenant, gateway-verified device -> tenant
  (pluggable resolvers + FastAPI dependency);
- Postgres RLS GUC `app.tenant_id` set per transaction via SET LOCAL (SEC-23);
- ES index/alias names built only from validated server-side tenant UUIDs,
  fail closed (SEC-24);
- gateway-auth middleware: agent routes reject requests without a valid
  X-Gateway-Auth header; identity headers are discarded on requests lacking
  gateway auth (SEC-14).
"""

from soc_tenancy.context import (
    get_current_tenant,
    require_current_tenant,
    reset_current_tenant,
    set_current_tenant,
    tenant_context,
)
from soc_tenancy.errors import InvalidTenantError, TenancyError, TenantContextError
from soc_tenancy.es import events_alias, events_index, validate_tenant_uuid
from soc_tenancy.gateway import (
    GATEWAY_AUTH_HEADER,
    IDENTITY_HEADERS,
    RESERVED_IDENTITY_HEADER_PREFIXES,
    GatewayAuthMiddleware,
)
from soc_tenancy.pg import SET_TENANT_GUC_SQL, set_local_tenant, set_local_tenant_sql
from soc_tenancy.resolvers import (
    GatewayDeviceTenantResolver,
    IngestKeyTenantResolver,
    ResolvedTenant,
    SessionTenantResolver,
    TenantResolver,
    tenant_dependency,
)

__all__ = [
    "GATEWAY_AUTH_HEADER",
    "IDENTITY_HEADERS",
    "RESERVED_IDENTITY_HEADER_PREFIXES",
    "SET_TENANT_GUC_SQL",
    "GatewayAuthMiddleware",
    "GatewayDeviceTenantResolver",
    "IngestKeyTenantResolver",
    "InvalidTenantError",
    "ResolvedTenant",
    "SessionTenantResolver",
    "TenancyError",
    "TenantContextError",
    "TenantResolver",
    "events_alias",
    "events_index",
    "get_current_tenant",
    "require_current_tenant",
    "reset_current_tenant",
    "set_current_tenant",
    "set_local_tenant",
    "set_local_tenant_sql",
    "tenant_context",
    "tenant_dependency",
    "validate_tenant_uuid",
]
