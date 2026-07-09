//! Real-time ETW consumer for `Microsoft-Windows-Kernel-Process`.
//!
//! Design: `start()` spins up a private real-time trace session, enables the
//! Kernel-Process provider (process keyword), then opens a consumer and runs
//! `ProcessTrace` on a dedicated OS thread. Each `EVENT_RECORD` is decoded
//! with TDH into a process-start/stop event and pushed into the core sink.
//! `stop()` stops the session (which unblocks `ProcessTrace`) and joins the
//! thread. Any setup failure returns an error; the agent keeps running and
//! reports provider status `failed` in its heartbeat (crash isolation,
//! ADR-0002 #3) — the ETW provider never takes down the host or the agent.

#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use tracing::{debug, error, warn};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::*;

use soc_collector_core::model::*;
use soc_collector_core::provider::{EventSink, ProviderError, ProviderStatus};

/// `Microsoft-Windows-Kernel-Process` {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.
const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// WINEVENT keyword `WINEVENT_KEYWORD_PROCESS` for the Kernel-Process provider.
const KEYWORD_PROCESS: u64 = 0x10;
/// Event IDs in the Kernel-Process manifest.
const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_PROCESS_STOP: u16 = 2;

const SESSION_NAME: &str = "SocAgentKernelProcess";

const STATUS_STOPPED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_FAILED: u8 = 2;

/// Context handed to the ETW callback via `EVENT_TRACE_LOGFILEW.Context`.
struct CallbackContext {
    sink: EventSink,
    host: Host,
}

/// Wrapper making the boxed-context raw pointer sendable into the consumer
/// thread. Safe: the `Box<CallbackContext>` outlives the thread (kept in
/// `EtwSession::_context` and only dropped after `stop()` joins the thread).
struct SendCtx(*mut CallbackContext);
unsafe impl Send for SendCtx {}

pub struct EtwSession {
    status: Arc<AtomicU8>,
    handle: Option<JoinHandle<()>>,
    /// Live session control handle for teardown (stored as raw u64).
    control_handle: Arc<AtomicU8>, // placeholder marker; real handle lives in the thread
    session_control: std::sync::Mutex<Option<u64>>,
    /// Boxed context kept alive for the trace lifetime.
    _context: Option<Box<CallbackContext>>,
}

impl EtwSession {
    pub fn new() -> Self {
        EtwSession {
            status: Arc::new(AtomicU8::new(STATUS_STOPPED)),
            handle: None,
            control_handle: Arc::new(AtomicU8::new(0)),
            session_control: std::sync::Mutex::new(None),
            _context: None,
        }
    }

    pub fn status(&self) -> ProviderStatus {
        match self.status.load(Ordering::SeqCst) {
            STATUS_RUNNING => ProviderStatus::Degraded, // process-only coverage: honest "degraded"
            STATUS_FAILED => ProviderStatus::Failed,
            _ => ProviderStatus::Failed,
        }
    }

    pub fn start(&mut self, sink: EventSink) -> Result<(), ProviderError> {
        let host = soc_collector_core::health::collect_host();
        let mut ctx = Box::new(CallbackContext { sink, host });
        let ctx_ptr: *mut CallbackContext = ctx.as_mut();

        // 1. Start (or restart) the real-time session.
        let control_handle = unsafe { start_session() }?;
        *self.session_control.lock().unwrap() = Some(control_handle.Value);

        // 2. Enable the Kernel-Process provider on the session.
        if let Err(e) = unsafe { enable_provider(control_handle) } {
            unsafe { stop_session_by_handle(control_handle) };
            self.status.store(STATUS_FAILED, Ordering::SeqCst);
            return Err(e);
        }

        // 3. Open the consumer and run ProcessTrace on a worker thread.
        let status = self.status.clone();
        let send_ctx = SendCtx(ctx_ptr);
        let handle = std::thread::Builder::new()
            .name("etw-consumer".into())
            .spawn(move || {
                // Bind the whole wrapper first so edition-2021 disjoint
                // capture moves `SendCtx` (Send), not the inner raw pointer.
                let send_ctx = send_ctx;
                let ctx_ptr = send_ctx.0;
                match unsafe { open_and_process(ctx_ptr) } {
                    Ok(()) => debug!("ETW ProcessTrace returned cleanly"),
                    Err(e) => {
                        error!("ETW consumer failed: {e}");
                        status.store(STATUS_FAILED, Ordering::SeqCst);
                    }
                }
            })
            .map_err(|e| ProviderError::Start(format!("spawn consumer: {e}")))?;

        self.handle = Some(handle);
        self._context = Some(ctx);
        self.status.store(STATUS_RUNNING, Ordering::SeqCst);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(control) = self.session_control.lock().unwrap().take() {
            unsafe {
                stop_session_by_handle(CONTROLTRACE_HANDLE { Value: control });
            }
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.status.store(STATUS_STOPPED, Ordering::SeqCst);
        let _ = &self.control_handle;
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// EVENT_TRACE_PROPERTIES + trailing session-name buffer, allocated as one
/// block per the ETW ABI (the name is written just past the struct).
fn alloc_trace_properties() -> (Vec<u8>, usize) {
    let name = wide(SESSION_NAME);
    let name_bytes = name.len() * 2;
    let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = struct_size + name_bytes;
    let mut buf = vec![0u8; total];
    // SAFETY: buf is sized for the struct; we only write documented fields.
    unsafe {
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC timestamps
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = struct_size as u32;
        // Copy the session name into the trailing buffer.
        let name_dst = buf.as_mut_ptr().add(struct_size) as *mut u16;
        std::ptr::copy_nonoverlapping(name.as_ptr(), name_dst, name.len());
    }
    (buf, struct_size)
}

unsafe fn start_session() -> Result<CONTROLTRACE_HANDLE, ProviderError> {
    let (mut buf, _off) = alloc_trace_properties();
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let name = wide(SESSION_NAME);
    let mut handle = CONTROLTRACE_HANDLE::default();

    // Best-effort: stop a stale session left by a previous crashed run.
    let _ = ControlTraceW(
        CONTROLTRACE_HANDLE::default(),
        PCWSTR(name.as_ptr()),
        props,
        EVENT_TRACE_CONTROL_STOP,
    );
    // The stop above may have zeroed control fields; rebuild.
    let (mut buf, _off) = alloc_trace_properties();
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    let rc = StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props);
    if rc != ERROR_SUCCESS {
        return Err(ProviderError::Start(format!(
            "StartTraceW failed: {:?} (are you elevated?)",
            rc
        )));
    }
    Ok(handle)
}

unsafe fn enable_provider(handle: CONTROLTRACE_HANDLE) -> Result<(), ProviderError> {
    let rc = EnableTraceEx2(
        handle,
        &KERNEL_PROCESS_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        TRACE_LEVEL_INFORMATION as u8,
        KEYWORD_PROCESS,
        0,
        0,
        None,
    );
    if rc != ERROR_SUCCESS {
        return Err(ProviderError::Start(format!("EnableTraceEx2 failed: {:?}", rc)));
    }
    Ok(())
}

unsafe fn stop_session_by_handle(handle: CONTROLTRACE_HANDLE) {
    let (mut buf, _off) = alloc_trace_properties();
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let name = wide(SESSION_NAME);
    let rc = ControlTraceW(handle, PCWSTR(name.as_ptr()), props, EVENT_TRACE_CONTROL_STOP);
    if rc != ERROR_SUCCESS {
        warn!("ControlTraceW(STOP) returned {:?}", rc);
    }
}

#[allow(clippy::field_reassign_with_default)] // union fields can't use struct-literal init
unsafe fn open_and_process(ctx: *mut CallbackContext) -> Result<(), ProviderError> {
    let mut name = wide(SESSION_NAME);
    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = PWSTR(name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = ctx as *mut c_void;

    let trace = OpenTraceW(&mut logfile);
    if trace.Value == u64::MAX {
        let err: WIN32_ERROR = GetLastError();
        return Err(ProviderError::Start(format!("OpenTraceW failed: {:?}", err)));
    }

    // Blocks until the session is stopped (from stop()).
    let rc = ProcessTrace(&[trace], None, None);
    let _ = CloseTrace(trace);
    if rc != ERROR_SUCCESS {
        // ERROR_CANCELLED is the normal stop path.
        debug!("ProcessTrace returned {:?}", rc);
    }
    Ok(())
}

/// ETW callback: invoked for each event on the consumer thread.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    let Some(record) = record.as_ref() else { return };
    let ctx_ptr = record.UserContext as *mut CallbackContext;
    let Some(ctx) = ctx_ptr.as_ref() else { return };

    // Filter to the Kernel-Process provider.
    if record.EventHeader.ProviderId != KERNEL_PROCESS_GUID {
        return;
    }
    let id = record.EventHeader.EventDescriptor.Id;
    let activity = match id {
        EVENT_ID_PROCESS_START => ProcessActivity::ProcessLaunched,
        EVENT_ID_PROCESS_STOP => ProcessActivity::ProcessTerminated,
        _ => return,
    };

    let fields = match parse_process_event(record, activity) {
        Some(f) => f,
        None => return,
    };
    let ev = AgentEvent::new(ctx.host.clone(), now_rfc3339(), ClassFields::Process(fields));
    // try_send: never block the ETW callback thread (dropping under
    // backpressure is acceptable; the disk buffer is the durable layer).
    let _ = ctx.sink.try_send(ev);
}

/// Extract process fields from a Kernel-Process event using TDH.
unsafe fn parse_process_event(
    record: &EVENT_RECORD,
    activity: ProcessActivity,
) -> Option<ProcessFields> {
    let pid = get_u32_property(record, "ProcessID")
        .or_else(|| get_u32_property(record, "ProcessId"))
        .unwrap_or(record.EventHeader.ProcessId);
    let image = get_string_property(record, "ImageName").unwrap_or_default();
    let exe_path = if image.is_empty() { "unknown".to_string() } else { image };
    let name = exe_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_path)
        .to_string();
    let cmd_line = get_string_property(record, "CommandLine").filter(|s| !s.is_empty());

    let (parent, cmd_line) = match activity {
        ProcessActivity::ProcessLaunched => {
            let ppid = get_u32_property(record, "ParentProcessID")
                .or_else(|| get_u32_property(record, "ParentProcessId"))
                .unwrap_or(0);
            let parent = Some(ParentInfo {
                pid: ppid,
                name: "unknown".into(), // parent image name not in this event; join deferred
                exe_path: None,
            });
            // Schema requires cmd_line for launched: fall back to exe_path.
            let cl = cmd_line.or_else(|| Some(exe_path.clone()));
            (parent, cl)
        }
        ProcessActivity::ProcessTerminated => (None, cmd_line),
    };

    let exit_code = if matches!(activity, ProcessActivity::ProcessTerminated) {
        get_u32_property(record, "ExitCode").map(|c| c as i64)
    } else {
        None
    };

    Some(ProcessFields {
        activity,
        process: ProcessInfo {
            pid,
            name,
            exe_path,
            cmd_line,
            sha256: None,
            created_time: None,
        },
        parent,
        user: User::unknown(), // owner resolution deferred (documented gap)
        exit_code,
    })
}

/// Read a scalar u32 property by name via TdhGetProperty.
unsafe fn get_u32_property(record: &EVENT_RECORD, prop: &str) -> Option<u32> {
    let bytes = get_property_bytes(record, prop)?;
    match bytes.len() {
        4 => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        8 => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        2 => Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u32),
        _ => None,
    }
}

/// Read a UTF-16 string property by name via TdhGetProperty.
unsafe fn get_string_property(record: &EVENT_RECORD, prop: &str) -> Option<String> {
    let bytes = get_property_bytes(record, prop)?;
    if bytes.len() < 2 {
        return Some(String::new());
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    Some(String::from_utf16_lossy(&u16s))
}

/// Core TDH property fetch: size then value, by property name.
unsafe fn get_property_bytes(record: &EVENT_RECORD, prop: &str) -> Option<Vec<u8>> {
    let name = wide(prop);
    let mut descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        ..Default::default()
    };

    let record_ptr = record as *const EVENT_RECORD as *mut EVENT_RECORD;
    let mut size: u32 = 0;
    let rc = TdhGetPropertySize(record_ptr, None, &[descriptor], &mut size);
    if rc != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = TdhGetProperty(record_ptr, None, &[descriptor], &mut buf);
    // touch descriptor so the compiler keeps `name` alive through the calls
    descriptor.ArrayIndex = u32::MAX;
    if rc != ERROR_SUCCESS.0 {
        return None;
    }
    Some(buf)
}

/// Elevated smoke test — run manually / in QA on a real Windows host:
/// `cargo test -p soc-provider-etw -- --ignored --nocapture`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an elevated Windows host with ETW privileges"]
    fn process_start_events_flow() {
        use soc_collector_core::provider::TelemetryProvider;
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let sink = EventSink::new(tx);
        let mut p = crate::EtwProvider::new();
        p.start(sink).expect("start ETW (elevated?)");
        // Generate process activity.
        for _ in 0..3 {
            let _ = std::process::Command::new("cmd").args(["/C", "echo etw-smoke"]).status();
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        p.stop();
        let mut saw_process = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.event_class == EventClass::ProcessActivity {
                saw_process = true;
            }
        }
        assert!(saw_process, "expected at least one process event");
    }
}
