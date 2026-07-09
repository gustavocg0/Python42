//! Integration tests against a mock ingestion server (wiremock).
//!
//! Debug builds allow http:// server URLs (see `http::validate_server_url`),
//! so these exercise the enroll / deliver / backoff / revocation paths
//! end-to-end without TLS. They cover the wire contract in api-contracts
//! §6/§10 and AC-59/66/68.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex, RwLock};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use soc_collector_core::buffer::{BufferConfig, DiskBuffer};
use soc_collector_core::delivery::{Deliverer, DeliveryConfig, DeliveryOutcome};
use soc_collector_core::enroll::{enroll, generate_key_and_csr, EnrollError};
use soc_collector_core::http::{build_enroll_client, TlsOptions};
use soc_collector_core::model::*;

fn tls() -> TlsOptions {
    TlsOptions::default()
}

fn host() -> Host {
    Host {
        hostname: "it-host".into(),
        os_family: OsFamily::Windows,
        os_name: "Windows 11 Pro".into(),
        os_version: "10.0.26100".into(),
        ip: None,
        mac: None,
    }
}

fn proc_event(marker: u32) -> AgentEvent {
    AgentEvent::new(
        host(),
        now_rfc3339(),
        ClassFields::Process(ProcessFields {
            activity: ProcessActivity::ProcessLaunched,
            process: ProcessInfo {
                pid: marker,
                name: "p.exe".into(),
                exe_path: "C:\\p.exe".into(),
                cmd_line: Some("p.exe".into()),
                sha256: None,
                created_time: None,
            },
            parent: Some(ParentInfo { pid: 1, name: "init.exe".into(), exe_path: None }),
            user: User::unknown(),
            exit_code: None,
        }),
    )
}

fn buffer(dir: &std::path::Path) -> Arc<Mutex<DiskBuffer>> {
    let cfg = BufferConfig::new(dir.join("buffer"));
    Arc::new(Mutex::new(DiskBuffer::open(cfg).unwrap()))
}

#[tokio::test]
async fn enroll_success_returns_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/enroll"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "device_id": "dev_01TEST",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
            "ca_chain_pem": "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
            "certificate_expires_at": "2026-10-06T00:00:00Z",
            "ingest_url": server_uri_placeholder(),
            "heartbeat_interval_seconds": 60
        })))
        .mount(&server)
        .await;

    let material = generate_key_and_csr().unwrap();
    let client = build_enroll_client(&tls()).unwrap();
    let resp = enroll(&client, &server.uri(), "et_token", &material.csr_pem, &host(), "0.1.0")
        .await
        .expect("enroll ok");
    assert_eq!(resp.device_id, "dev_01TEST");
    assert_eq!(resp.heartbeat_interval_seconds, 60);
    assert!(resp.certificate_pem.contains("BEGIN CERTIFICATE"));
}

fn server_uri_placeholder() -> String {
    "http://ingest.local".into()
}

#[tokio::test]
async fn enroll_expired_token_is_distinct_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/enroll"))
        .respond_with(ResponseTemplate::new(410).set_body_json(serde_json::json!({
            "error": {"code": "ENROLLMENT_TOKEN_EXPIRED", "message": "expired"}
        })))
        .mount(&server)
        .await;
    let material = generate_key_and_csr().unwrap();
    let client = build_enroll_client(&tls()).unwrap();
    let err = enroll(&client, &server.uri(), "et", &material.csr_pem, &host(), "0.1.0")
        .await
        .unwrap_err();
    assert!(matches!(err, EnrollError::TokenExpired), "got {err:?}");
}

#[tokio::test]
async fn enroll_cap_reached_is_distinct_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/enroll"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"code": "ENDPOINT_CAP_REACHED", "message": "cap"}
        })))
        .mount(&server)
        .await;
    let material = generate_key_and_csr().unwrap();
    let client = build_enroll_client(&tls()).unwrap();
    let err = enroll(&client, &server.uri(), "et", &material.csr_pem, &host(), "0.1.0")
        .await
        .unwrap_err();
    assert!(matches!(err, EnrollError::EndpointCapReached), "got {err:?}");
}

#[tokio::test]
async fn delivery_202_drains_buffer_and_respects_batch_size() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/events"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "batch_id": "b_1", "accepted": 0
        })))
        .mount(&server)
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let buffer = buffer(dir.path());
    {
        let mut b = buffer.lock().await;
        for i in 0..2500 {
            b.enqueue(&proc_event(i)).unwrap();
        }
    }
    let client = Arc::new(RwLock::new(build_enroll_client(&tls()).unwrap()));
    let mut deliverer = Deliverer::new(
        client,
        server.uri(),
        DeliveryConfig { max_batch_events: 1000, ..Default::default() },
    );

    let mut delivered = 0usize;
    for _ in 0..10 {
        match deliverer.deliver_once(&buffer).await {
            DeliveryOutcome::Delivered { accepted } => {
                assert!(accepted <= 1000, "batch must be <=1000 events");
                delivered += accepted;
            }
            DeliveryOutcome::Idle => break,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(delivered, 2500);
    assert!(!buffer.lock().await.has_pending(), "buffer fully drained");

    // The server saw at least 3 batches (2500 / 1000).
    let reqs = server.received_requests().await.unwrap();
    let event_posts = reqs.iter().filter(|r| r.url.path() == "/v1/agent/events").count();
    assert!(event_posts >= 3, "expected >=3 batches, saw {event_posts}");
    // Each batch body is well-formed and within the event cap.
    for r in reqs.iter().filter(|r| r.url.path() == "/v1/agent/events") {
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let n = v["events"].as_array().unwrap().len();
        assert!(n <= 1000);
        // events carry stable source_event_id + no platform-assigned fields
        assert!(v["events"][0]["source_event_id"].is_string());
        assert!(v["events"][0].get("tenant_id").is_none());
    }
}

#[tokio::test]
async fn delivery_429_honors_retry_after_without_tight_loop() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/events"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "2")
                .set_body_json(serde_json::json!({
                    "error": {"code": "INGEST_QUOTA_EXCEEDED", "message": "slow down"}
                })),
        )
        .mount(&server)
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let buffer = buffer(dir.path());
    buffer.lock().await.enqueue(&proc_event(1)).unwrap();

    let client = Arc::new(RwLock::new(build_enroll_client(&tls()).unwrap()));
    let mut deliverer = Deliverer::new(client, server.uri(), DeliveryConfig::default());
    let outcome = deliverer.deliver_once(&buffer).await;
    match outcome {
        DeliveryOutcome::Backoff(d) => {
            assert!(d >= Duration::from_secs(2), "must honor Retry-After floor, got {d:?}");
            assert!(d <= Duration::from_secs(4), "jitter bounded, got {d:?}");
        }
        other => panic!("expected backoff, got {other:?}"),
    }
    // The batch was NOT consumed (still pending for replay).
    assert!(buffer.lock().await.has_pending());
}

#[tokio::test]
async fn delivery_5xx_backs_off_then_succeeds() {
    let server = MockServer::start().await;
    // First response 503, then 202.
    Mock::given(method("POST"))
        .and(path("/v1/agent/events"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": {"code": "SERVICE_UNAVAILABLE", "message": "down"}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/events"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "batch_id": "b_2", "accepted": 0
        })))
        .mount(&server)
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let buffer = buffer(dir.path());
    buffer.lock().await.enqueue(&proc_event(1)).unwrap();

    let client = Arc::new(RwLock::new(build_enroll_client(&tls()).unwrap()));
    let mut deliverer = Deliverer::new(
        client,
        server.uri(),
        DeliveryConfig {
            backoff_base: Duration::from_millis(100),
            backoff_cap: Duration::from_millis(500),
            ..Default::default()
        },
    );

    let start = Instant::now();
    let first = deliverer.deliver_once(&buffer).await;
    let wait = match first {
        DeliveryOutcome::Backoff(d) => d,
        other => panic!("expected backoff on 503, got {other:?}"),
    };
    assert!(buffer.lock().await.has_pending(), "not consumed on 5xx");
    tokio::time::sleep(wait).await;
    let second = deliverer.deliver_once(&buffer).await;
    assert!(matches!(second, DeliveryOutcome::Delivered { .. }), "recovered, got {second:?}");
    assert!(!buffer.lock().await.has_pending());
    assert!(start.elapsed() >= wait, "waited out the backoff");
}

#[tokio::test]
async fn delivery_401_device_revoked_stops_sending() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/events"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": {"code": "DEVICE_REVOKED", "message": "revoked"}
        })))
        .mount(&server)
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let buffer = buffer(dir.path());
    buffer.lock().await.enqueue(&proc_event(1)).unwrap();

    let client = Arc::new(RwLock::new(build_enroll_client(&tls()).unwrap()));
    let deliverer = Deliverer::new(client, server.uri(), DeliveryConfig::default());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (revoked_tx, mut revoked_rx) = watch::channel(false);
    let buf2 = buffer.clone();
    let handle = tokio::spawn(deliverer.run(buf2, shutdown_rx, revoked_tx));

    // The run loop must flip `revoked` and exit on DEVICE_REVOKED (AC-59).
    tokio::time::timeout(Duration::from_secs(5), revoked_rx.changed())
        .await
        .expect("revoked signal within timeout")
        .unwrap();
    assert!(*revoked_rx.borrow());
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("delivery loop exits")
        .unwrap();

    // Data stays buffered (not accepted) per AC-59.
    assert!(buffer.lock().await.has_pending());
}
