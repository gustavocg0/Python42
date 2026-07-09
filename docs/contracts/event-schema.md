# Contract: Internal Event Schema v1.0.0 (OCSF-inspired)

- **Status:** Draft v1 for ratification — 2026-07-08
- **Owner:** solution-architect (resolves PRD OQ-3; satisfies AC-31)
- **Consumers:** endpoint-agent (produce shapes), backend-architect (normalizer), detection-engineering (rule fields), database-architect (ES mappings), qa
- **Canonical models:** `packages/schemas` (pydantic) MUST be generated from this document; this document wins on conflict.

## 1. Versioning rules

- `schema_version` is semver, current `"1.0.0"`. Additive optional fields ⇒ minor bump. Renamed/removed/retyped fields ⇒ major bump (requires new ES index template `events-v2-*` and dual-read window).
- Every stored event carries the version it was normalized under. Rules declare `min_schema_version`.
- Unknown incoming fields are preserved under `unmapped` (object), never dropped silently.

## 2. Envelope (all event classes)

| Field | Type | Req | Set by | Notes |
|---|---|---|---|---|
| `event_id` | UUIDv4 string | yes | normalizer | Platform-assigned |
| `tenant_id` | UUID string | yes | ingest auth | Never trusted from payload |
| `schema_version` | string | yes | normalizer | e.g. `"1.0.0"` |
| `event_class` | enum | yes | normalizer | `process_activity` \| `network_activity` \| `authentication` \| `generic` |
| `activity` | string enum | yes | source/normalizer | Class-specific (see §3) |
| `event_time` | RFC3339 UTC | yes | source | If missing/unparseable ⇒ set to `ingest_time`, `time_inferred=true` |
| `time_inferred` | bool | no (default false) | normalizer | |
| `ingest_time` | RFC3339 UTC | yes | ingest API | |
| `source_type` | enum | yes | ingest auth | `agent` \| `generic` |
| `source_event_id` | string ≤128 | agent: yes; generic: no | source | Dedup key (AC-34). Generic without it gets a server UUID (no dedup) |
| `batch_id` | UUID string | yes | ingest API | Batch receipt correlation |
| `source` | object | yes | ingest auth | `{device_id?, agent_version?, ingest_key_id?, vendor?, product?}` — device_id XOR ingest_key_id present |
| `host` | object | agent: yes; generic: best-effort | source | See §2.1; drives asset dedup (AC-20/22) |
| `severity_hint` | enum | no | source | `low\|medium\|high\|critical` (informational; rules decide severity) |
| `unmapped` | object ≤16KB | no | normalizer | Unrecognized source fields |

### 2.1 `host` object

| Field | Type | Req (agent) | Notes |
|---|---|---|---|
| `hostname` | string ≤253, stored lowercased | yes | Dedup key #2 with os_family |
| `os_family` | enum `windows\|linux\|macos\|other` | yes | |
| `os_name` | string | yes | e.g. `Windows 11 Pro` |
| `os_version` | string | yes | e.g. `10.0.26100` |
| `ip` | string (v4/v6) | no | Primary interface at event time |
| `mac` | string `aa:bb:cc:dd:ee:ff` lowercased | no | Dedup key #3 |

### 2.2 `user` object (used by classes below)

`{ "name": string (req), "domain": string?, "uid": string? }` — `uid` = Windows SID / POSIX uid.

## 3. Class-specific fields

Validation: missing any **Req=yes** field ⇒ event is malformed ⇒ dead-letter with parse error (AC-32). Extra fields ⇒ `unmapped`.

### 3.1 `process_activity`

| Field | Type | Req | Notes |
|---|---|---|---|
| `activity` | `process_launched` \| `process_terminated` | yes | |
| `process.pid` | int | yes | |
| `process.name` | string | yes | Image name, e.g. `powershell.exe` |
| `process.exe_path` | string | yes | Full path |
| `process.cmd_line` | string ≤32KB | launched: yes | |
| `process.sha256` | hex string | no | Image hash when available |
| `process.created_time` | RFC3339 | no | |
| `parent.pid` | int | launched: yes | |
| `parent.name` | string | launched: yes | |
| `parent.exe_path` | string | no | |
| `user` | user object | yes | Process owner |
| `exit_code` | int | terminated only, optional | |

### 3.2 `network_activity`

| Field | Type | Req | Notes |
|---|---|---|---|
| `activity` | `connection_opened` \| `connection_closed` | yes | |
| `direction` | `inbound` \| `outbound` \| `unknown` | yes | |
| `protocol` | `tcp` \| `udp` \| `icmp` \| `other` | yes | |
| `src.ip` | string | yes | |
| `src.port` | int 0-65535 | tcp/udp: yes | |
| `dst.ip` | string | yes | |
| `dst.port` | int | tcp/udp: yes | |
| `dst.hostname` | string | no | DNS name when known |
| `process.pid` / `process.name` / `process.exe_path` | | no | Owning process when resolvable |
| `bytes_sent` / `bytes_received` | long | no | closed only |
| `user` | user object | no | |

### 3.3 `authentication`

| Field | Type | Req | Notes |
|---|---|---|---|
| `activity` | `logon` \| `logoff` \| `logon_failed` | yes | |
| `status` | `success` \| `failure` | yes | Derived: `logon_failed` ⇒ `failure` |
| `logon_type` | `interactive` \| `network` \| `remote_interactive` \| `service` \| `batch` \| `unlock` \| `other` | yes | Windows logon type mapped; generic sources may send `other` |
| `user` | user object | yes | Target account |
| `src_ip` | string | no | Origin of logon attempt |
| `session_id` | string | no | Windows logon ID etc. |
| `failure_reason` | `bad_password` \| `unknown_user` \| `account_locked` \| `account_disabled` \| `expired` \| `other` | logon_failed: yes | |

### 3.4 `generic`

Fallback for generic-ingest events not mappable to the classes above.

| Field | Type | Req | Notes |
|---|---|---|---|
| `activity` | fixed `"log"` | yes | |
| `message` | string ≤32KB | yes | Human-readable line/summary |
| `category` | string | no | Source-declared, freeform |
| `fields` | flat object (string/number/bool values) ≤16KB | no | Extracted key-values; rules may match on `fields.*` |
| `raw` | object ≤32KB | yes | Original payload as received (truncated with `raw_truncated=true` if over) |
| `raw_truncated` | bool | no | |

## 4. JSON examples

```json
{
  "event_id": "5f0c9a52-1b2e-4c3d-9e8f-7a6b5c4d3e2f",
  "tenant_id": "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "schema_version": "1.0.0",
  "event_class": "process_activity",
  "activity": "process_launched",
  "event_time": "2026-07-08T09:14:03.221Z",
  "ingest_time": "2026-07-08T09:14:05.100Z",
  "source_type": "agent",
  "source_event_id": "etw-4688-000123456",
  "batch_id": "0b7e3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c6d",
  "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
  "host": {"hostname": "fin-laptop-07", "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "10.0.26100", "ip": "10.1.4.23", "mac": "a4:bb:6d:12:34:56"},
  "process": {"pid": 4312, "name": "powershell.exe", "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmd_line": "powershell -enc SQBFAFgA...", "sha256": "9f2c...aa10"},
  "parent": {"pid": 1180, "name": "winword.exe", "exe_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
  "user": {"name": "sam.jones", "domain": "ACME", "uid": "S-1-5-21-...-1104"}
}
```

```json
{
  "event_id": "a1b2c3d4-0000-4000-8000-000000000001",
  "tenant_id": "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "schema_version": "1.0.0",
  "event_class": "network_activity",
  "activity": "connection_opened",
  "event_time": "2026-07-08T09:14:04.001Z",
  "ingest_time": "2026-07-08T09:14:05.100Z",
  "source_type": "agent",
  "source_event_id": "etw-net-000778812",
  "batch_id": "0b7e3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c6d",
  "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
  "host": {"hostname": "fin-laptop-07", "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "10.0.26100"},
  "direction": "outbound",
  "protocol": "tcp",
  "src": {"ip": "10.1.4.23", "port": 51544},
  "dst": {"ip": "185.220.101.7", "port": 443, "hostname": "unknown-host.example"},
  "process": {"pid": 4312, "name": "powershell.exe"}
}
```

```json
{
  "event_id": "a1b2c3d4-0000-4000-8000-000000000002",
  "tenant_id": "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "schema_version": "1.0.0",
  "event_class": "authentication",
  "activity": "logon_failed",
  "event_time": "2026-07-08T09:13:59.900Z",
  "ingest_time": "2026-07-08T09:14:05.100Z",
  "source_type": "agent",
  "source_event_id": "etw-4625-000031007",
  "batch_id": "0b7e3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c6d",
  "source": {"device_id": "dev_01J9ZK3T", "agent_version": "0.3.1"},
  "host": {"hostname": "fin-laptop-07", "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "10.0.26100"},
  "status": "failure",
  "logon_type": "remote_interactive",
  "user": {"name": "administrator", "domain": "ACME"},
  "src_ip": "203.0.113.50",
  "failure_reason": "bad_password"
}
```

```json
{
  "event_id": "a1b2c3d4-0000-4000-8000-000000000003",
  "tenant_id": "8c9d0e1f-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "schema_version": "1.0.0",
  "event_class": "generic",
  "activity": "log",
  "event_time": "2026-07-08T09:12:00Z",
  "ingest_time": "2026-07-08T09:14:06.400Z",
  "source_type": "generic",
  "source_event_id": "fw-88213",
  "batch_id": "77aa3c1a-9d2f-4a5b-8c6d-1e2f3a4b5c99",
  "source": {"ingest_key_id": "ik_01J9ZKAB", "vendor": "acme-fw", "product": "edge-fw-200"},
  "host": {"hostname": "edge-fw-1", "os_family": "other", "os_name": "AcmeFW OS", "os_version": "4.2"},
  "message": "Blocked outbound connection to known-bad IP",
  "category": "firewall.block",
  "fields": {"src_ip": "10.1.4.23", "dst_ip": "185.220.101.7", "action": "block"},
  "raw": {"ts": 1783514000, "msg": "BLOCK out 10.1.4.23->185.220.101.7:443", "rule": 17}
}
```

## 5. Agent wire format vs normalized form

Agents submit **pre-classified** events (they know `event_class`, `activity`, class fields, `host`, `source_event_id`, `event_time`) but MUST NOT send `event_id`, `tenant_id`, `ingest_time`, `batch_id`, `source.*` identity fields — the platform assigns these from the authenticated context (any client-sent values are ignored). Generic ingest may submit either pre-classified events (same rules) or arbitrary JSON objects, which normalize to `generic` with `message` = best-effort (`message`/`msg`/`log` key, else JSON-stringified, truncated) and full payload in `raw`.

## 6. Dead-letter record (AC-32)

PG `dead_letter_events`: `{id, tenant_id, batch_id, source_type, received_at, raw payload (≤64KB), error_code, error_detail}`; retained 7 days; per-tenant `events_rejected` counter metric incremented on write.

## 7. Clarifications (Architect-ratified, 2026-07-08)

Raised during implementation of `soc_schemas`; binding for all consumers:

1. **UUID strictness:** `event_id` is validated as a strict RFC4122 UUIDv4. `tenant_id` and `batch_id` are validated as generic UUIDs (any version/variant), matching how they are minted by provisioning and ingest.
2. **`host` on generic events:** `host` is **optional** when `source_type = generic`. When present, it must carry `hostname`, `os_family`, `os_name`, `os_version` (same shape as agent events). Agent events still require `host` unconditionally.
