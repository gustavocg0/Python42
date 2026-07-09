//! Disk ring buffer with class-priority shedding (AC-66/67).
//!
//! Layout: one subdirectory per event class under the buffer dir, containing
//! append-only segment files `seg-<first_seq>.log`. Each line is
//! `<seq:020> <event-json>\n` where `seq` is a buffer-global monotonic
//! sequence assigned at enqueue, so oldest-first replay merges the three
//! class queues back into arrival order (AC-66).
//!
//! **Shedding order (documented, AC-65/67):** when an enqueue would exceed
//! the total cap (default 256 MiB), whole oldest segments are dropped from
//! the lowest-priority class that still has data: `network_activity` first,
//! then `process_activity`, and `authentication` last. Dropped-event counts
//! are tracked per class and reported (as deltas) in the next heartbeat.
//!
//! **Delivery/replay semantics:** `next_batch` reads a prefix without
//! mutating state; `commit` (called only after the server accepted the
//! batch) advances consumption and deletes fully consumed segments.
//! Consumption offsets are deliberately NOT persisted: after a crash the
//! agent may re-deliver up to the last uncommitted prefix, and the server
//! deduplicates by `source_event_id` (AC-34) — events carry their IDs inside
//! the persisted JSON, so replayed events keep stable IDs.
//!
//! Durability: writes are flushed to the OS per event but not fsynced; an OS
//! crash may lose the final unsynced bytes. Torn trailing lines are
//! truncated at recovery.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use tracing::warn;

use crate::model::{AgentEvent, EventClass};

pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_SEGMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BufferConfig {
    pub dir: PathBuf,
    pub max_total_bytes: u64,
    pub segment_max_bytes: u64,
}

impl BufferConfig {
    pub fn new(dir: PathBuf) -> Self {
        BufferConfig {
            dir,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            segment_max_bytes: DEFAULT_SEGMENT_MAX_BYTES,
        }
    }
}

/// Heartbeat `dropped_events_since_last` wire shape (api-contracts §10).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DroppedCounts {
    pub network_activity: u64,
    pub process_activity: u64,
    pub authentication: u64,
}

#[derive(Debug, Default)]
struct DropCounters {
    total: [u64; 3],
    reported: [u64; 3],
}

impl DropCounters {
    fn add(&mut self, class: EventClass, n: u64) {
        self.total[class.shed_priority()] += n;
    }

    fn take_delta(&mut self) -> DroppedCounts {
        let delta = |i: usize, s: &mut Self| {
            let d = s.total[i] - s.reported[i];
            s.reported[i] = s.total[i];
            d
        };
        DroppedCounts {
            network_activity: delta(EventClass::NetworkActivity.shed_priority(), self),
            process_activity: delta(EventClass::ProcessActivity.shed_priority(), self),
            authentication: delta(EventClass::Authentication.shed_priority(), self),
        }
    }
}

#[derive(Debug)]
struct Segment {
    path: PathBuf,
    bytes: u64,
    entries: u64,
}

#[derive(Debug)]
struct ClassQueue {
    class: EventClass,
    dir: PathBuf,
    /// Closed segments, oldest first.
    segments: VecDeque<Segment>,
    active: Option<Segment>,
    active_file: Option<File>,
    /// Entries/bytes consumed from the front of this queue (within the
    /// oldest not-yet-deleted segment; a committed prefix may span segments,
    /// in which case fully consumed segments are deleted immediately).
    consumed_entries: u64,
    consumed_bytes: u64,
}

impl ClassQueue {
    fn open(class: EventClass, root: &Path) -> io::Result<(Self, u64, u64)> {
        let dir = root.join(class.as_str());
        fs::create_dir_all(&dir)?;
        let mut paths: Vec<PathBuf> = fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("seg-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        paths.sort();

        let mut segments = VecDeque::new();
        let mut total_bytes = 0u64;
        let mut max_seq = 0u64;
        for path in paths {
            truncate_torn_tail(&path)?;
            let (entries, bytes, last_seq) = scan_segment(&path)?;
            if entries == 0 {
                let _ = fs::remove_file(&path);
                continue;
            }
            total_bytes += bytes;
            max_seq = max_seq.max(last_seq);
            segments.push_back(Segment { path, bytes, entries });
        }
        Ok((
            ClassQueue {
                class,
                dir,
                segments,
                active: None,
                active_file: None,
                consumed_entries: 0,
                consumed_bytes: 0,
            },
            total_bytes,
            max_seq,
        ))
    }

    fn append(&mut self, line: &str, seq: u64, segment_max: u64) -> io::Result<()> {
        if self.active.is_none() {
            let path = self.dir.join(format!("seg-{seq:020}.log"));
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.active = Some(Segment { path, bytes: 0, entries: 0 });
            self.active_file = Some(file);
        }
        let file = self.active_file.as_mut().expect("active file");
        file.write_all(line.as_bytes())?;
        file.flush()?;
        let seg = self.active.as_mut().expect("active segment");
        seg.bytes += line.len() as u64;
        seg.entries += 1;
        if seg.bytes >= segment_max {
            self.rotate();
        }
        Ok(())
    }

    fn rotate(&mut self) {
        if let Some(seg) = self.active.take() {
            if seg.entries > 0 {
                self.segments.push_back(seg);
            } else {
                let _ = fs::remove_file(&seg.path);
            }
        }
        self.active_file = None;
    }

    fn pending_entries(&self) -> u64 {
        let total: u64 = self.segments.iter().map(|s| s.entries).sum::<u64>()
            + self.active.as_ref().map(|s| s.entries).unwrap_or(0);
        total.saturating_sub(self.consumed_entries)
    }

    /// Snapshot of readable files (front→active) for a batch read.
    fn file_snapshot(&self) -> Vec<(PathBuf, u64)> {
        let mut v: Vec<(PathBuf, u64)> = self
            .segments
            .iter()
            .map(|s| (s.path.clone(), s.bytes))
            .collect();
        if let Some(s) = &self.active {
            if s.entries > 0 {
                v.push((s.path.clone(), s.bytes));
            }
        }
        v
    }

    /// Drop the oldest segment (rotating the active one in if needed),
    /// returning (unconsumed entries dropped, bytes freed). `None` if empty.
    fn drop_front(&mut self) -> Option<(u64, u64)> {
        if self.segments.is_empty() {
            if self.active.as_ref().map(|s| s.entries).unwrap_or(0) == 0 {
                return None;
            }
            self.rotate();
        }
        let seg = self.segments.pop_front()?;
        let _ = fs::remove_file(&seg.path);
        let unconsumed = seg.entries.saturating_sub(self.consumed_entries);
        // Whatever consumption state applied to this front is gone with it.
        self.consumed_entries = 0;
        self.consumed_bytes = 0;
        Some((unconsumed, seg.bytes))
    }

    /// Advance consumption by a committed prefix; deletes fully consumed
    /// segments. Returns bytes freed from disk.
    fn advance(&mut self, entries: u64, bytes: u64) -> u64 {
        self.consumed_entries += entries;
        self.consumed_bytes += bytes;
        let mut freed = 0u64;
        loop {
            if let Some(front) = self.segments.front() {
                if self.consumed_entries >= front.entries {
                    let seg = self.segments.pop_front().expect("front");
                    let _ = fs::remove_file(&seg.path);
                    self.consumed_entries -= seg.entries;
                    self.consumed_bytes = self.consumed_bytes.saturating_sub(seg.bytes);
                    freed += seg.bytes;
                    continue;
                }
                break;
            } else if let Some(active) = &self.active {
                if active.entries > 0 && self.consumed_entries >= active.entries {
                    let seg = self.active.take().expect("active");
                    self.active_file = None;
                    let _ = fs::remove_file(&seg.path);
                    self.consumed_entries -= seg.entries;
                    self.consumed_bytes = self.consumed_bytes.saturating_sub(seg.bytes);
                    freed += seg.bytes;
                }
                break;
            } else {
                break;
            }
        }
        freed
    }
}

/// A read-only prefix of the buffer, oldest-first across classes.
/// Committed only after the server accepts it.
#[derive(Debug)]
pub struct Batch {
    /// Serialized event JSON objects, oldest-first.
    pub items: Vec<String>,
    /// Sum of `items` lengths (excluding array separators).
    pub total_event_bytes: u64,
    /// Per shed-priority-index: (entries, bytes) consumed from that class.
    taken: [(u64, u64); 3],
}

impl Batch {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

pub struct DiskBuffer {
    cfg: BufferConfig,
    /// Indexed by `EventClass::shed_priority()`.
    queues: [ClassQueue; 3],
    next_seq: u64,
    /// Sum of all segment file bytes currently on disk (including consumed
    /// prefixes of not-yet-deleted segments) — this is what the cap bounds.
    stored_bytes: u64,
    drops: DropCounters,
}

impl DiskBuffer {
    /// Open (or recover) a buffer directory. Recovery re-scans segments;
    /// consumption offsets are not persisted (see module docs).
    pub fn open(cfg: BufferConfig) -> io::Result<Self> {
        fs::create_dir_all(&cfg.dir)?;
        let mut total = 0u64;
        let mut max_seq = 0u64;
        let mut queues = Vec::with_capacity(3);
        // Build in shed-priority order.
        for class in [
            EventClass::NetworkActivity,
            EventClass::ProcessActivity,
            EventClass::Authentication,
        ] {
            let (q, bytes, seq) = ClassQueue::open(class, &cfg.dir)?;
            total += bytes;
            max_seq = max_seq.max(seq);
            queues.push(q);
        }
        let queues: [ClassQueue; 3] = queues
            .try_into()
            .map_err(|_| io::Error::other("queue init"))?;
        Ok(DiskBuffer {
            cfg,
            queues,
            next_seq: max_seq + 1,
            stored_bytes: total,
            drops: DropCounters::default(),
        })
    }

    /// Append an event; sheds lower-priority data first if the cap would be
    /// exceeded (AC-67). Never grows disk usage beyond `max_total_bytes`.
    pub fn enqueue(&mut self, event: &AgentEvent) -> io::Result<()> {
        let json = serde_json::to_string(event)?;
        let line = format!("{:020} {}\n", self.next_seq, json);
        let len = line.len() as u64;
        if len > self.cfg.max_total_bytes {
            // Pathological single event larger than the whole buffer.
            self.drops.add(event.event_class, 1);
            return Ok(());
        }
        while self.stored_bytes + len > self.cfg.max_total_bytes {
            if !self.shed_one() {
                self.drops.add(event.event_class, 1);
                return Ok(());
            }
        }
        let qi = event.event_class.shed_priority();
        self.queues[qi].append(&line, self.next_seq, self.cfg.segment_max_bytes)?;
        self.stored_bytes += len;
        self.next_seq += 1;
        Ok(())
    }

    /// Drop the oldest segment of the most-sheddable non-empty class.
    fn shed_one(&mut self) -> bool {
        for qi in 0..3 {
            let class = self.queues[qi].class;
            if let Some((dropped_entries, freed)) = self.queues[qi].drop_front() {
                self.stored_bytes = self.stored_bytes.saturating_sub(freed);
                if dropped_entries > 0 {
                    self.drops.add(class, dropped_entries);
                    warn!(
                        class = class.as_str(),
                        dropped = dropped_entries,
                        "buffer full: shed oldest segment"
                    );
                }
                return true;
            }
        }
        false
    }

    /// Read (without consuming) the next batch, oldest-first by global
    /// sequence, bounded by `max_events` and `max_bytes` of event JSON.
    pub fn next_batch(&mut self, max_events: usize, max_bytes: u64) -> io::Result<Option<Batch>> {
        let mut readers: Vec<ClassReader> = Vec::with_capacity(3);
        for (qi, q) in self.queues.iter().enumerate() {
            readers.push(ClassReader::new(qi, q.file_snapshot(), q.consumed_bytes));
        }

        let mut batch = Batch { items: Vec::new(), total_event_bytes: 0, taken: [(0, 0); 3] };
        while batch.items.len() < max_events {
            // Pick the class whose next entry has the smallest sequence.
            let mut best: Option<(usize, u64)> = None;
            for (i, r) in readers.iter_mut().enumerate() {
                if let Some(entry) = r.peek()? {
                    if best.map(|(_, s)| entry.seq < s).unwrap_or(true) {
                        best = Some((i, entry.seq));
                    }
                }
            }
            let Some((i, _)) = best else { break };
            {
                let entry = readers[i].peek()?.expect("peeked");
                let cost = entry.json.len() as u64 + 1;
                if !batch.items.is_empty() && batch.total_event_bytes + cost > max_bytes {
                    break;
                }
            }
            let entry = readers[i].take().expect("peeked entry");
            batch.total_event_bytes += entry.json.len() as u64 + 1;
            batch.taken[i].0 += 1;
            batch.taken[i].1 += entry.line_len;
            batch.items.push(entry.json);
            // Skipped (corrupt) lines still consume their bytes/entries.
            let (skipped_entries, skipped_bytes) = readers[i].take_skipped();
            batch.taken[i].0 += skipped_entries;
            batch.taken[i].1 += skipped_bytes;
        }

        if batch.items.is_empty() {
            Ok(None)
        } else {
            Ok(Some(batch))
        }
    }

    /// Acknowledge a delivered batch: advance consumption, delete fully
    /// consumed segments.
    pub fn commit(&mut self, batch: &Batch) {
        for (qi, (entries, bytes)) in batch.taken.iter().enumerate() {
            if *entries > 0 || *bytes > 0 {
                let freed = self.queues[qi].advance(*entries, *bytes);
                self.stored_bytes = self.stored_bytes.saturating_sub(freed);
            }
        }
    }

    pub fn has_pending(&self) -> bool {
        self.queues.iter().any(|q| q.pending_entries() > 0)
    }

    pub fn pending_events(&self) -> u64 {
        self.queues.iter().map(|q| q.pending_entries()).sum()
    }

    pub fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    /// Heartbeat `buffer_utilization_pct`.
    pub fn utilization_pct(&self) -> f64 {
        if self.cfg.max_total_bytes == 0 {
            return 0.0;
        }
        (self.stored_bytes as f64 / self.cfg.max_total_bytes as f64) * 100.0
    }

    /// Per-class drops since last call (heartbeat `dropped_events_since_last`).
    pub fn take_drop_delta(&mut self) -> DroppedCounts {
        self.drops.take_delta()
    }
}

struct ReadEntry {
    seq: u64,
    line_len: u64,
    json: String,
}

/// Lazy oldest-first reader over one class's segment snapshot.
struct ClassReader {
    #[allow(dead_code)]
    class_idx: usize,
    files: Vec<(PathBuf, u64)>,
    file_idx: usize,
    reader: Option<BufReader<File>>,
    /// Byte offset to skip in the first file (already-consumed prefix).
    initial_skip: u64,
    peeked: Option<ReadEntry>,
    skipped_entries: u64,
    skipped_bytes: u64,
}

impl ClassReader {
    fn new(class_idx: usize, files: Vec<(PathBuf, u64)>, initial_skip: u64) -> Self {
        ClassReader {
            class_idx,
            files,
            file_idx: 0,
            reader: None,
            initial_skip,
            peeked: None,
            skipped_entries: 0,
            skipped_bytes: 0,
        }
    }

    fn peek(&mut self) -> io::Result<Option<&ReadEntry>> {
        if self.peeked.is_none() {
            self.peeked = self.read_next()?;
        }
        Ok(self.peeked.as_ref())
    }

    fn take(&mut self) -> Option<ReadEntry> {
        self.peeked.take()
    }

    fn take_skipped(&mut self) -> (u64, u64) {
        let out = (self.skipped_entries, self.skipped_bytes);
        self.skipped_entries = 0;
        self.skipped_bytes = 0;
        out
    }

    fn read_next(&mut self) -> io::Result<Option<ReadEntry>> {
        loop {
            if self.reader.is_none() {
                if self.file_idx >= self.files.len() {
                    return Ok(None);
                }
                let (path, _) = &self.files[self.file_idx];
                let mut f = File::open(path)?;
                if self.file_idx == 0 && self.initial_skip > 0 {
                    f.seek(SeekFrom::Start(self.initial_skip))?;
                }
                self.reader = Some(BufReader::new(f));
            }
            let reader = self.reader.as_mut().expect("reader");
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                self.reader = None;
                self.file_idx += 1;
                continue;
            }
            // Ignore torn trailing lines (no newline): they were never
            // durably counted at recovery either.
            if !line.ends_with('\n') {
                self.reader = None;
                self.file_idx += 1;
                continue;
            }
            match parse_line(&line) {
                Some((seq, json)) => {
                    return Ok(Some(ReadEntry { seq, line_len: n as u64, json }));
                }
                None => {
                    warn!("skipping corrupt buffer line ({n} bytes)");
                    self.skipped_entries += 1;
                    self.skipped_bytes += n as u64;
                    continue;
                }
            }
        }
    }
}

fn parse_line(line: &str) -> Option<(u64, String)> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let (seq_str, json) = line.split_at_checked(20)?;
    let json = json.strip_prefix(' ')?;
    let seq: u64 = seq_str.parse().ok()?;
    if !json.starts_with('{') || !json.ends_with('}') {
        return None;
    }
    Some((seq, json.to_string()))
}

/// Count entries/bytes and last sequence of a recovered segment.
fn scan_segment(path: &PathBuf) -> io::Result<(u64, u64, u64)> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut entries = 0u64;
    let mut bytes = 0u64;
    let mut last_seq = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        entries += 1;
        bytes += n as u64;
        if let Some((seq, _)) = parse_line(&line) {
            last_seq = last_seq.max(seq);
        }
    }
    Ok((entries, bytes, last_seq))
}

/// Truncate a possibly torn (no trailing newline) tail after a crash.
fn truncate_torn_tail(path: &PathBuf) -> io::Result<()> {
    let data = fs::read(path)?;
    if data.is_empty() || data.ends_with(b"\n") {
        return Ok(());
    }
    let keep = data.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
    let f = OpenOptions::new().write(true).open(path)?;
    f.set_len(keep as u64)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use tempfile::TempDir;

    fn host() -> Host {
        Host {
            hostname: "h1".into(),
            os_family: OsFamily::Windows,
            os_name: "Windows 11".into(),
            os_version: "10.0.26100".into(),
            ip: None,
            mac: None,
        }
    }

    fn ev(class: EventClass, marker: u32) -> AgentEvent {
        let fields = match class {
            EventClass::ProcessActivity => ClassFields::Process(ProcessFields {
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
            EventClass::NetworkActivity => ClassFields::Network(NetworkFields {
                activity: NetworkActivity::ConnectionOpened,
                direction: Direction::Outbound,
                protocol: Protocol::Tcp,
                src: NetEndpoint { ip: "10.0.0.1".into(), port: Some(1000 + marker as u16 % 1000), hostname: None },
                dst: NetEndpoint { ip: "10.0.0.2".into(), port: Some(443), hostname: None },
                process: None,
                bytes_sent: None,
                bytes_received: None,
                user: None,
            }),
            EventClass::Authentication => ClassFields::Auth(AuthFields {
                activity: AuthActivity::LogonFailed,
                status: AuthStatus::Failure,
                logon_type: LogonType::Network,
                user: User { name: format!("u{marker}"), domain: None, uid: None },
                src_ip: None,
                session_id: None,
                failure_reason: Some(FailureReason::BadPassword),
            }),
        };
        AgentEvent::new(host(), now_rfc3339(), fields)
    }

    fn cfg(dir: &TempDir, max_total: u64, seg_max: u64) -> BufferConfig {
        BufferConfig {
            dir: dir.path().to_path_buf(),
            max_total_bytes: max_total,
            segment_max_bytes: seg_max,
        }
    }

    #[test]
    fn oldest_first_across_classes() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 10_000_000, 100_000)).unwrap();
        let classes = [
            EventClass::ProcessActivity,
            EventClass::NetworkActivity,
            EventClass::Authentication,
            EventClass::NetworkActivity,
            EventClass::ProcessActivity,
        ];
        let mut ids = Vec::new();
        for (i, c) in classes.iter().enumerate() {
            let e = ev(*c, i as u32);
            ids.push(e.source_event_id);
            buf.enqueue(&e).unwrap();
        }
        let batch = buf.next_batch(100, 10_000_000).unwrap().unwrap();
        assert_eq!(batch.len(), 5);
        let got: Vec<uuid::Uuid> = batch
            .items
            .iter()
            .map(|j| serde_json::from_str::<AgentEvent>(j).unwrap().source_event_id)
            .collect();
        assert_eq!(got, ids, "replay must be oldest-first in arrival order");
    }

    #[test]
    fn uncommitted_batch_is_re_read_with_stable_ids() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 10_000_000, 100_000)).unwrap();
        for i in 0..3 {
            buf.enqueue(&ev(EventClass::Authentication, i)).unwrap();
        }
        let b1 = buf.next_batch(10, 10_000_000).unwrap().unwrap();
        let b2 = buf.next_batch(10, 10_000_000).unwrap().unwrap();
        assert_eq!(b1.items, b2.items, "no commit => identical re-read (stable source_event_id)");
        buf.commit(&b2);
        assert!(buf.next_batch(10, 10_000_000).unwrap().is_none());
        assert!(!buf.has_pending());
    }

    #[test]
    fn batch_respects_event_and_byte_limits() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 10_000_000, 100_000)).unwrap();
        for i in 0..50 {
            buf.enqueue(&ev(EventClass::ProcessActivity, i)).unwrap();
        }
        let b = buf.next_batch(10, 10_000_000).unwrap().unwrap();
        assert_eq!(b.len(), 10);

        let one = serde_json::to_string(&ev(EventClass::ProcessActivity, 0)).unwrap();
        let b = buf.next_batch(1000, (one.len() * 3) as u64).unwrap().unwrap();
        assert!(b.len() >= 2 && b.len() <= 3, "byte cap should bound batch, got {}", b.len());
        assert!(b.total_event_bytes <= (one.len() * 3 + 64) as u64);
    }

    #[test]
    fn shedding_order_network_then_process_auth_last() {
        const N: u32 = 30;
        // Size the cap from real serialized bytes: large enough to retain ALL
        // auth plus a little headroom, but far too small for the 60 network +
        // process events — so shedding must sacrifice network first, then
        // process, and never touch auth.
        let auth_line = serde_json::to_string(&ev(EventClass::Authentication, 0)).unwrap().len() + 22;
        let cap = (auth_line as u64) * (N as u64) + (auth_line as u64) * 6;

        let dir = TempDir::new().unwrap();
        // Segments hold ~3 events so shedding is reasonably granular.
        let mut buf = DiskBuffer::open(cfg(&dir, cap, (auth_line * 3) as u64)).unwrap();
        for i in 0..N {
            buf.enqueue(&ev(EventClass::NetworkActivity, i)).unwrap();
            buf.enqueue(&ev(EventClass::ProcessActivity, i)).unwrap();
            buf.enqueue(&ev(EventClass::Authentication, i)).unwrap();
        }
        assert!(buf.stored_bytes() <= cap, "cap must hold: {} > {cap}", buf.stored_bytes());
        let drops = buf.take_drop_delta();
        assert!(drops.network_activity > 0, "network must be shed first");
        assert_eq!(drops.authentication, 0, "auth must be retained longest: {drops:?}");
        assert!(
            drops.network_activity >= drops.process_activity,
            "network sheds before process: {drops:?}"
        );
        // Every auth event must still be replayable.
        let mut auth = 0;
        while let Some(b) = buf.next_batch(1000, 10_000_000).unwrap() {
            for j in &b.items {
                let e: AgentEvent = serde_json::from_str(j).unwrap();
                if e.event_class == EventClass::Authentication {
                    auth += 1;
                }
            }
            buf.commit(&b);
        }
        assert_eq!(auth, N as usize, "all auth retained");
    }

    #[test]
    fn auth_dropped_only_when_alone_and_over_cap() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 3_000, 500)).unwrap();
        for i in 0..100 {
            buf.enqueue(&ev(EventClass::Authentication, i)).unwrap();
        }
        assert!(buf.stored_bytes() <= 3_000);
        let drops = buf.take_drop_delta();
        assert!(drops.authentication > 0, "auth sheds only when it is all that's left");
    }

    #[test]
    fn drop_counters_delta_semantics() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 2_000, 400)).unwrap();
        for i in 0..40 {
            buf.enqueue(&ev(EventClass::NetworkActivity, i)).unwrap();
        }
        let d1 = buf.take_drop_delta();
        assert!(d1.network_activity > 0);
        let d2 = buf.take_drop_delta();
        assert_eq!(d2, DroppedCounts::default(), "second take must be a delta of zero");
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = TempDir::new().unwrap();
        let config = cfg(&dir, 10_000_000, 1_000);
        let mut ids = Vec::new();
        {
            let mut buf = DiskBuffer::open(config.clone()).unwrap();
            for i in 0..25 {
                let e = ev(EventClass::ProcessActivity, i);
                ids.push(e.source_event_id);
                buf.enqueue(&e).unwrap();
            }
        }
        let mut buf = DiskBuffer::open(config).unwrap();
        assert_eq!(buf.pending_events(), 25);
        let b = buf.next_batch(1000, 10_000_000).unwrap().unwrap();
        let got: Vec<uuid::Uuid> = b
            .items
            .iter()
            .map(|j| serde_json::from_str::<AgentEvent>(j).unwrap().source_event_id)
            .collect();
        assert_eq!(got, ids, "recovered events keep order and stable IDs");
        // New enqueues after recovery keep the global sequence increasing.
        buf.commit(&b);
        buf.enqueue(&ev(EventClass::Authentication, 9)).unwrap();
        let b2 = buf.next_batch(10, 10_000_000).unwrap().unwrap();
        assert_eq!(b2.len(), 1);
    }

    #[test]
    fn torn_tail_is_truncated_on_recovery() {
        let dir = TempDir::new().unwrap();
        let config = cfg(&dir, 10_000_000, 1_000_000);
        {
            let mut buf = DiskBuffer::open(config.clone()).unwrap();
            for i in 0..5 {
                buf.enqueue(&ev(EventClass::Authentication, i)).unwrap();
            }
        }
        // Simulate a torn write on the newest auth segment.
        let class_dir = dir.path().join("authentication");
        let seg = fs::read_dir(&class_dir).unwrap().next().unwrap().unwrap().path();
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(b"00000000000000000099 {\"truncated").unwrap();
        drop(f);
        let mut buf = DiskBuffer::open(config).unwrap();
        assert_eq!(buf.pending_events(), 5);
        let b = buf.next_batch(100, 10_000_000).unwrap().unwrap();
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn utilization_reflects_stored_bytes() {
        let dir = TempDir::new().unwrap();
        let mut buf = DiskBuffer::open(cfg(&dir, 100_000, 10_000)).unwrap();
        assert_eq!(buf.utilization_pct(), 0.0);
        for i in 0..10 {
            buf.enqueue(&ev(EventClass::ProcessActivity, i)).unwrap();
        }
        assert!(buf.utilization_pct() > 0.0 && buf.utilization_pct() <= 100.0);
    }
}
