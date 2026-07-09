//! Agent wire-event model.
//!
//! Shapes match `docs/contracts/event-schema.md` §3 + §5 exactly. Agents send
//! *pre-classified* events carrying `event_class`, `activity`, class fields,
//! `host`, `source_event_id`, `event_time` — and MUST NOT send `event_id`,
//! `tenant_id`, `ingest_time`, `batch_id` or `source.*` (platform-assigned).
//!
//! `source_event_id` is a UUIDv4 generated ONCE at event creation and
//! persisted with the buffered event so replays after reconnect/restart are
//! deduplicated server-side (AC-34 / AC-66).

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// RFC3339 UTC "now", the wire timestamp format.
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    ProcessActivity,
    NetworkActivity,
    Authentication,
}

impl EventClass {
    /// Shedding priority per AC-65/67 (documented order): drop
    /// `network_activity` first, then `process_activity`; retain
    /// `authentication` longest. Lower = shed first.
    pub fn shed_priority(self) -> usize {
        match self {
            EventClass::NetworkActivity => 0,
            EventClass::ProcessActivity => 1,
            EventClass::Authentication => 2,
        }
    }

    pub const ALL: [EventClass; 3] = [
        EventClass::NetworkActivity,
        EventClass::ProcessActivity,
        EventClass::Authentication,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EventClass::ProcessActivity => "process_activity",
            EventClass::NetworkActivity => "network_activity",
            EventClass::Authentication => "authentication",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Linux,
    Macos,
    Other,
}

/// Envelope `host` object (event-schema §2.1). Required for every agent event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub hostname: String,
    pub os_family: OsFamily,
    pub os_name: String,
    pub os_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// `user` object (event-schema §2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Windows SID / POSIX uid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

impl User {
    pub fn unknown() -> Self {
        User { name: "unknown".into(), domain: None, uid: None }
    }
}

// ---------------------------------------------------------------------------
// process_activity (§3.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessActivity {
    ProcessLaunched,
    ProcessTerminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    /// Required for `process_launched` (schema); providers must supply a
    /// value (ETW falls back to `exe_path` when the real command line is
    /// unavailable — documented gap).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentInfo {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFields {
    pub activity: ProcessActivity,
    pub process: ProcessInfo,
    /// Required for `process_launched`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentInfo>,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
}

// ---------------------------------------------------------------------------
// network_activity (§3.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkActivity {
    ConnectionOpened,
    ConnectionClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEndpoint {
    pub ip: String,
    /// Required for tcp/udp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Owning process, when resolvable (all fields optional per schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFields {
    pub activity: NetworkActivity,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src: NetEndpoint,
    pub dst: NetEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
}

// ---------------------------------------------------------------------------
// authentication (§3.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthActivity {
    Logon,
    Logoff,
    LogonFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogonType {
    Interactive,
    Network,
    RemoteInteractive,
    Service,
    Batch,
    Unlock,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    BadPassword,
    UnknownUser,
    AccountLocked,
    AccountDisabled,
    Expired,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFields {
    pub activity: AuthActivity,
    pub status: AuthStatus,
    pub logon_type: LogonType,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Required for `logon_failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<FailureReason>,
}

// ---------------------------------------------------------------------------
// The wire event
// ---------------------------------------------------------------------------

/// Class-specific fields, flattened to the top level on the wire.
///
/// Untagged: each variant's `activity` enum has disjoint string values, so
/// deserialization (buffer replay) is unambiguous.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClassFields {
    Process(ProcessFields),
    Network(NetworkFields),
    Auth(AuthFields),
}

impl ClassFields {
    pub fn class(&self) -> EventClass {
        match self {
            ClassFields::Process(_) => EventClass::ProcessActivity,
            ClassFields::Network(_) => EventClass::NetworkActivity,
            ClassFields::Auth(_) => EventClass::Authentication,
        }
    }
}

/// One agent telemetry event as submitted in `POST /v1/agent/events` batches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// Stable dedup key (AC-34): UUIDv4 minted once at creation, persisted
    /// through the disk buffer, never regenerated on retry/replay.
    pub source_event_id: Uuid,
    pub event_class: EventClass,
    /// RFC3339 UTC.
    pub event_time: String,
    pub host: Host,
    #[serde(flatten)]
    pub fields: ClassFields,
}

impl AgentEvent {
    pub fn new(host: Host, event_time: String, fields: ClassFields) -> Self {
        Self::with_id(Uuid::new_v4(), host, event_time, fields)
    }

    /// Used by deterministic-seed simulation (CI) where the UUID comes from a
    /// seeded RNG.
    pub fn with_id(id: Uuid, host: Host, event_time: String, fields: ClassFields) -> Self {
        AgentEvent {
            source_event_id: id,
            event_class: fields.class(),
            event_time,
            host,
            fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            hostname: "fin-laptop-07".into(),
            os_family: OsFamily::Windows,
            os_name: "Windows 11 Pro".into(),
            os_version: "10.0.26100".into(),
            ip: None,
            mac: None,
        }
    }

    #[test]
    fn process_event_wire_shape() {
        let ev = AgentEvent::new(
            host(),
            "2026-07-08T09:14:03.221Z".into(),
            ClassFields::Process(ProcessFields {
                activity: ProcessActivity::ProcessLaunched,
                process: ProcessInfo {
                    pid: 4312,
                    name: "powershell.exe".into(),
                    exe_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                        .into(),
                    cmd_line: Some("powershell -enc SQBFAFgA".into()),
                    sha256: None,
                    created_time: None,
                },
                parent: Some(ParentInfo { pid: 1180, name: "winword.exe".into(), exe_path: None }),
                user: User { name: "sam.jones".into(), domain: Some("ACME".into()), uid: None },
                exit_code: None,
            }),
        );
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        // Flattened class fields at top level; platform-assigned fields absent.
        assert_eq!(v["event_class"], "process_activity");
        assert_eq!(v["activity"], "process_launched");
        assert_eq!(v["process"]["pid"], 4312);
        assert_eq!(v["parent"]["name"], "winword.exe");
        assert_eq!(v["host"]["os_family"], "windows");
        assert!(v.get("event_id").is_none());
        assert!(v.get("tenant_id").is_none());
        assert!(v.get("ingest_time").is_none());
        assert!(v.get("batch_id").is_none());
        assert!(v.get("source").is_none());
    }

    #[test]
    fn roundtrip_untagged_all_classes() {
        let evs = vec![
            AgentEvent::new(
                host(),
                now_rfc3339(),
                ClassFields::Network(NetworkFields {
                    activity: NetworkActivity::ConnectionOpened,
                    direction: Direction::Outbound,
                    protocol: Protocol::Tcp,
                    src: NetEndpoint { ip: "10.1.4.23".into(), port: Some(51544), hostname: None },
                    dst: NetEndpoint { ip: "185.220.101.7".into(), port: Some(443), hostname: None },
                    process: None,
                    bytes_sent: None,
                    bytes_received: None,
                    user: None,
                }),
            ),
            AgentEvent::new(
                host(),
                now_rfc3339(),
                ClassFields::Auth(AuthFields {
                    activity: AuthActivity::LogonFailed,
                    status: AuthStatus::Failure,
                    logon_type: LogonType::RemoteInteractive,
                    user: User { name: "administrator".into(), domain: None, uid: None },
                    src_ip: Some("203.0.113.50".into()),
                    session_id: None,
                    failure_reason: Some(FailureReason::BadPassword),
                }),
            ),
        ];
        for ev in evs {
            let s = serde_json::to_string(&ev).unwrap();
            let back: AgentEvent = serde_json::from_str(&s).unwrap();
            assert_eq!(back.event_class, ev.event_class);
            assert_eq!(back.source_event_id, ev.source_event_id);
        }
    }
}
