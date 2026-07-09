//! Cross-platform simulated telemetry provider (AC-62b, AC-64).
//!
//! Produces realistic process / network / authentication event streams on
//! any OS for development, CI, and demo. Includes suspicious scenarios
//! designed to trip detection rules (see [`Scenario`]). Two modes:
//!
//! - **deterministic** (`seed != 0`): a seeded RNG drives both the event
//!   content AND the `source_event_id` UUIDs, so a given seed produces a
//!   byte-identical event sequence (modulo `event_time`) — required for
//!   reproducible CI (AC-64) and buffer/dedup tests.
//! - **random** (`seed == 0`): seeded from entropy for demos.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use soc_collector_core::model::*;
use soc_collector_core::provider::{EventSink, ProviderError, ProviderStatus, TelemetryProvider};

/// Suspicious patterns that will produce detections downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Failed-logon brute force burst, then a success (credential access).
    BruteForceLogon,
    /// Office app spawning an encoded PowerShell + outbound to a known-bad
    /// IP (execution + C2).
    OfficeSpawnsEncodedPowershell,
    /// lsass access / credential-dump-like process pattern.
    CredentialDump,
}

#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Target event emission rate.
    pub events_per_second: u32,
    /// 0 ⇒ random (entropy seed); non-zero ⇒ deterministic.
    pub seed: u64,
    /// Emit suspicious scenarios interleaved with benign noise.
    pub suspicious_patterns: bool,
    pub hostname: String,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            events_per_second: 5,
            seed: 0,
            suspicious_patterns: true,
            hostname: "sim-host-01".into(),
        }
    }
}

/// Pure, side-effect-free event generator. `next()` yields one event and
/// advances internal state deterministically from the seed.
pub struct Generator {
    rng: SmallRng,
    host: Host,
    suspicious: bool,
    counter: u64,
    /// Pending events from an in-flight multi-step scenario.
    pending: Vec<ClassFields>,
    /// Fixed wall-clock base for deterministic mode (event_time excluded
    /// from determinism guarantees, but stable ordering helps tests).
    tick: u64,
}

const BENIGN_PROCS: &[(&str, &str)] = &[
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("teams.exe", "C:\\Users\\sam\\AppData\\Local\\Microsoft\\Teams\\Teams.exe"),
];

const BENIGN_USERS: &[&str] = &["sam.jones", "ana.li", "dev.svc", "backup.svc"];

impl Generator {
    pub fn new(cfg: &SimConfig) -> Self {
        let rng = if cfg.seed == 0 {
            SmallRng::from_entropy()
        } else {
            SmallRng::seed_from_u64(cfg.seed)
        };
        let host = Host {
            hostname: cfg.hostname.to_lowercase(),
            os_family: OsFamily::Windows,
            os_name: "Windows 11 Pro".into(),
            os_version: "10.0.26100".into(),
            ip: Some("10.1.4.23".into()),
            mac: Some("a4:bb:6d:12:34:56".into()),
        };
        Generator {
            rng,
            host,
            suspicious: cfg.suspicious_patterns,
            counter: 0,
            pending: Vec::new(),
            tick: 1_783_500_000,
        }
    }

    /// Deterministic UUID derived from the RNG so a seed reproduces IDs.
    fn next_id(&mut self) -> Uuid {
        let mut bytes = [0u8; 16];
        self.rng.fill(&mut bytes);
        // Set version (4) and variant bits for a well-formed UUIDv4.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    fn event_time(&mut self) -> String {
        self.tick += 1;
        now_rfc3339()
    }

    /// Produce the next event. Never blocks.
    #[allow(clippy::should_implement_trait)] // intentionally not an Iterator (infinite stream)
    pub fn next(&mut self) -> AgentEvent {
        self.counter += 1;
        if let Some(fields) = self.pending.pop() {
            return self.wrap(fields);
        }
        // Roughly every 40 events, if enabled, inject a suspicious scenario.
        if self.suspicious && self.counter % 40 == 0 {
            let scenario = match (self.counter / 40) % 3 {
                0 => Scenario::BruteForceLogon,
                1 => Scenario::OfficeSpawnsEncodedPowershell,
                _ => Scenario::CredentialDump,
            };
            self.enqueue_scenario(scenario);
            let fields = self.pending.pop().expect("scenario produced events");
            return self.wrap(fields);
        }
        let fields = match self.rng.gen_range(0..100) {
            0..=54 => self.benign_process(),
            55..=89 => self.benign_network(),
            _ => self.benign_auth(),
        };
        self.wrap(fields)
    }

    fn wrap(&mut self, fields: ClassFields) -> AgentEvent {
        let id = self.next_id();
        let t = self.event_time();
        AgentEvent::with_id(id, self.host.clone(), t, fields)
    }

    fn benign_process(&mut self) -> ClassFields {
        let (name, path) = BENIGN_PROCS[self.rng.gen_range(0..BENIGN_PROCS.len())];
        let user = BENIGN_USERS[self.rng.gen_range(0..BENIGN_USERS.len())].to_string();
        let pid = self.rng.gen_range(1000..60000);
        ClassFields::Process(ProcessFields {
            activity: ProcessActivity::ProcessLaunched,
            process: ProcessInfo {
                pid,
                name: name.into(),
                exe_path: path.into(),
                cmd_line: Some(format!("\"{path}\"")),
                sha256: None,
                created_time: None,
            },
            parent: Some(ParentInfo {
                pid: self.rng.gen_range(500..1000),
                name: "explorer.exe".into(),
                exe_path: Some("C:\\Windows\\explorer.exe".into()),
            }),
            user: User { name: user, domain: Some("ACME".into()), uid: None },
            exit_code: None,
        })
    }

    fn benign_network(&mut self) -> ClassFields {
        let dsts = ["140.82.112.3", "13.107.42.14", "142.250.72.14", "10.1.4.10"];
        let dst = dsts[self.rng.gen_range(0..dsts.len())];
        ClassFields::Network(NetworkFields {
            activity: NetworkActivity::ConnectionOpened,
            direction: Direction::Outbound,
            protocol: Protocol::Tcp,
            src: NetEndpoint {
                ip: "10.1.4.23".into(),
                port: Some(self.rng.gen_range(49152..65535)),
                hostname: None,
            },
            dst: NetEndpoint { ip: dst.into(), port: Some(443), hostname: None },
            process: Some(ProcessRef {
                pid: Some(self.rng.gen_range(1000..60000)),
                name: Some("chrome.exe".into()),
                exe_path: None,
            }),
            bytes_sent: None,
            bytes_received: None,
            user: None,
        })
    }

    fn benign_auth(&mut self) -> ClassFields {
        let user = BENIGN_USERS[self.rng.gen_range(0..BENIGN_USERS.len())].to_string();
        ClassFields::Auth(AuthFields {
            activity: AuthActivity::Logon,
            status: AuthStatus::Success,
            logon_type: LogonType::Interactive,
            user: User { name: user, domain: Some("ACME".into()), uid: None },
            src_ip: None,
            session_id: Some(format!("0x{:x}", self.rng.gen_range(0x10000..0xffffff))),
            failure_reason: None,
        })
    }

    /// Push a scenario's events into `pending` (LIFO; we push in reverse so
    /// they emit in chronological order).
    fn enqueue_scenario(&mut self, scenario: Scenario) {
        let mut steps: Vec<ClassFields> = match scenario {
            Scenario::BruteForceLogon => {
                let attacker_ip = "203.0.113.50";
                let mut v = Vec::new();
                for _ in 0..8 {
                    v.push(ClassFields::Auth(AuthFields {
                        activity: AuthActivity::LogonFailed,
                        status: AuthStatus::Failure,
                        logon_type: LogonType::RemoteInteractive,
                        user: User { name: "administrator".into(), domain: Some("ACME".into()), uid: None },
                        src_ip: Some(attacker_ip.into()),
                        session_id: None,
                        failure_reason: Some(FailureReason::BadPassword),
                    }));
                }
                v.push(ClassFields::Auth(AuthFields {
                    activity: AuthActivity::Logon,
                    status: AuthStatus::Success,
                    logon_type: LogonType::RemoteInteractive,
                    user: User { name: "administrator".into(), domain: Some("ACME".into()), uid: None },
                    src_ip: Some(attacker_ip.into()),
                    session_id: Some("0xA1B2C3".into()),
                    failure_reason: None,
                }));
                v
            }
            Scenario::OfficeSpawnsEncodedPowershell => {
                let ps_pid = self.rng.gen_range(4000..5000);
                vec![
                    ClassFields::Process(ProcessFields {
                        activity: ProcessActivity::ProcessLaunched,
                        process: ProcessInfo {
                            pid: ps_pid,
                            name: "powershell.exe".into(),
                            exe_path:
                                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                                    .into(),
                            cmd_line: Some(
                                "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==".into(),
                            ),
                            sha256: None,
                            created_time: None,
                        },
                        parent: Some(ParentInfo {
                            pid: 1180,
                            name: "winword.exe".into(),
                            exe_path: Some(
                                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE".into(),
                            ),
                        }),
                        user: User { name: "sam.jones".into(), domain: Some("ACME".into()), uid: None },
                        exit_code: None,
                    }),
                    ClassFields::Network(NetworkFields {
                        activity: NetworkActivity::ConnectionOpened,
                        direction: Direction::Outbound,
                        protocol: Protocol::Tcp,
                        src: NetEndpoint { ip: "10.1.4.23".into(), port: Some(51544), hostname: None },
                        dst: NetEndpoint {
                            ip: "185.220.101.7".into(),
                            port: Some(443),
                            hostname: Some("unknown-host.example".into()),
                        },
                        process: Some(ProcessRef {
                            pid: Some(ps_pid),
                            name: Some("powershell.exe".into()),
                            exe_path: None,
                        }),
                        bytes_sent: None,
                        bytes_received: None,
                        user: None,
                    }),
                ]
            }
            Scenario::CredentialDump => {
                let pid = self.rng.gen_range(6000..7000);
                vec![ClassFields::Process(ProcessFields {
                    activity: ProcessActivity::ProcessLaunched,
                    process: ProcessInfo {
                        pid,
                        name: "rundll32.exe".into(),
                        exe_path: "C:\\Windows\\System32\\rundll32.exe".into(),
                        cmd_line: Some(
                            "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 640 C:\\temp\\lsass.dmp full".into(),
                        ),
                        sha256: None,
                        created_time: None,
                    },
                    parent: Some(ParentInfo {
                        pid: self.rng.gen_range(500..1000),
                        name: "cmd.exe".into(),
                        exe_path: Some("C:\\Windows\\System32\\cmd.exe".into()),
                    }),
                    user: User {
                        name: "administrator".into(),
                        domain: Some("ACME".into()),
                        uid: Some("S-1-5-21-1004".into()),
                    },
                    exit_code: None,
                })]
            }
        };
        // Reverse so pop() (LIFO) yields chronological order.
        steps.reverse();
        self.pending = steps;
    }
}

/// Threaded provider wrapping [`Generator`].
pub struct SimulatedProvider {
    cfg: SimConfig,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SimulatedProvider {
    pub fn new(cfg: SimConfig) -> Self {
        SimulatedProvider { cfg, running: Arc::new(AtomicBool::new(false)), handle: None }
    }
}

impl TelemetryProvider for SimulatedProvider {
    fn name(&self) -> &'static str {
        "simulated"
    }

    fn start(&mut self, sink: EventSink) -> Result<(), ProviderError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let cfg = self.cfg.clone();
        let running = self.running.clone();
        let eps = cfg.events_per_second.max(1);
        let interval = Duration::from_secs_f64(1.0 / eps as f64);
        let handle = std::thread::Builder::new()
            .name("sim-provider".into())
            .spawn(move || {
                let mut gen = Generator::new(&cfg);
                while running.load(Ordering::SeqCst) {
                    let ev = gen.next();
                    if !sink.send_blocking(ev) {
                        break; // pipeline shut down
                    }
                    std::thread::sleep(interval);
                }
            })
            .map_err(|e| ProviderError::Start(e.to_string()))?;
        self.handle = Some(handle);
        Ok(())
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    fn status(&self) -> ProviderStatus {
        if self.running.load(Ordering::SeqCst) {
            ProviderStatus::Ok
        } else {
            ProviderStatus::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_cfg(seed: u64) -> SimConfig {
        SimConfig { events_per_second: 100, seed, suspicious_patterns: true, hostname: "h".into() }
    }

    fn gen_ids_and_bodies(seed: u64, n: usize) -> (Vec<Uuid>, Vec<String>) {
        let mut g = Generator::new(&det_cfg(seed));
        let mut ids = Vec::new();
        let mut bodies = Vec::new();
        for _ in 0..n {
            let ev = g.next();
            ids.push(ev.source_event_id);
            // Body excluding event_time (which is wall-clock, not seeded).
            let mut v = serde_json::to_value(&ev).unwrap();
            v.as_object_mut().unwrap().remove("event_time");
            bodies.push(v.to_string());
        }
        (ids, bodies)
    }

    #[test]
    fn same_seed_is_deterministic() {
        let (ids_a, bodies_a) = gen_ids_and_bodies(1234, 200);
        let (ids_b, bodies_b) = gen_ids_and_bodies(1234, 200);
        assert_eq!(ids_a, ids_b, "seeded UUIDs must match");
        assert_eq!(bodies_a, bodies_b, "seeded event bodies must match");
    }

    #[test]
    fn different_seed_diverges() {
        let (ids_a, _) = gen_ids_and_bodies(1, 200);
        let (ids_b, _) = gen_ids_and_bodies(2, 200);
        assert_ne!(ids_a, ids_b);
    }

    #[test]
    fn all_event_classes_are_produced() {
        let mut g = Generator::new(&det_cfg(42));
        let mut seen = [false; 3];
        for _ in 0..500 {
            seen[g.next().event_class.shed_priority()] = true;
        }
        assert!(seen.iter().all(|s| *s), "process/network/auth all produced");
    }

    #[test]
    fn suspicious_scenarios_appear() {
        let mut g = Generator::new(&det_cfg(7));
        let mut brute_force_failures = 0;
        let mut encoded_ps = false;
        let mut lsass_dump = false;
        for _ in 0..2000 {
            let ev = g.next();
            match &ev.fields {
                ClassFields::Auth(a)
                    if a.activity == AuthActivity::LogonFailed
                        && a.user.name == "administrator" =>
                {
                    brute_force_failures += 1;
                }
                ClassFields::Process(p) => {
                    if p.process.cmd_line.as_deref().unwrap_or("").contains("-enc") {
                        encoded_ps = true;
                    }
                    if p.process.cmd_line.as_deref().unwrap_or("").contains("lsass.dmp") {
                        lsass_dump = true;
                    }
                }
                _ => {}
            }
        }
        assert!(brute_force_failures >= 8, "brute-force burst present");
        assert!(encoded_ps, "encoded powershell present");
        assert!(lsass_dump, "credential-dump pattern present");
    }

    #[test]
    fn suspicious_disabled_is_all_benign() {
        let cfg = SimConfig {
            events_per_second: 100,
            seed: 5,
            suspicious_patterns: false,
            hostname: "h".into(),
        };
        let mut g = Generator::new(&cfg);
        for _ in 0..1000 {
            let ev = g.next();
            if let ClassFields::Auth(a) = &ev.fields {
                assert_ne!(a.status, AuthStatus::Failure, "no failures when suspicious disabled");
            }
        }
    }

    #[test]
    fn events_conform_to_schema_fields() {
        let mut g = Generator::new(&det_cfg(99));
        for _ in 0..300 {
            let ev = g.next();
            let v = serde_json::to_value(&ev).unwrap();
            assert!(v.get("source_event_id").is_some());
            assert!(v.get("event_class").is_some());
            assert!(v.get("host").is_some());
            match ev.event_class {
                EventClass::ProcessActivity => {
                    assert!(v["process"]["pid"].is_number());
                    if v["activity"] == "process_launched" {
                        assert!(v["process"]["cmd_line"].is_string());
                        assert!(v["parent"]["pid"].is_number());
                    }
                }
                EventClass::NetworkActivity => {
                    assert!(v["src"]["ip"].is_string());
                    assert!(v["dst"]["ip"].is_string());
                }
                EventClass::Authentication => {
                    assert!(v["user"]["name"].is_string());
                    if v["activity"] == "logon_failed" {
                        assert!(v["failure_reason"].is_string());
                    }
                }
            }
        }
    }
}
