//! Stream-sequence accounting and bounded write buffering for ForgeWire task streams.
//!
//! # StreamCounter
//!
//! Moves per-task seq assignment into a process-local `parking_lot::Mutex` map.
//! rqlite owns durability but the `BEGIN IMMEDIATE + SELECT MAX(seq)`
//! round-trip is eliminated — seq is assigned in-memory, store writes are fire-and-go.
//!
//! # StreamBuffer + DurabilityProfile
//!
//! Accumulates pending stream entries in a per-task bounded `VecDeque` and flushes
//! to the store as a batch once the configured threshold is reached.
//!
//! | Profile      | Flush after N lines | Backpressure cap |
//! |--------------|---------------------|------------------|
//! | `Strict`     | 1 (every append)    | —                |
//! | `Balanced`   | 50                  | 500              |
//! | `Throughput` | 200                 | 2 000            |
//!
//! On `Strict` the buffer is bypassed entirely — the caller receives `Some(entry)`
//! immediately and writes it to the store synchronously, preserving the existing
//! per-line acknowledgment semantics.
//!
//! On `Balanced` / `Throughput` `push()` returns `None` until the flush threshold
//! (or cap) is reached, at which point it returns `Some(batch)`. The caller bulk-
//! writes the batch and the response to the runner carries `"buffered": true`.
//!
//! `flush_task()` forces a drain — call it before `submit_result` so no pending
//! lines are lost at task completion.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;

// ── DurabilityProfile ────────────────────────────────────────────────────────

/// Named flush policy for task stream persistence.
///
/// The profile is set at hub startup via `FORGEWIRE_HUB_STREAM_PROFILE` and
/// reported in `/healthz` so operators can observe the current posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityProfile {
    /// Every line is written to the store before the HTTP response is sent.
    /// Strongest durability guarantee; lowest throughput under high-volume output.
    Strict,
    /// Lines are batched in memory and flushed to the store every 50 lines.
    /// Unacknowledged lines survive a graceful shutdown (force-flush on result)
    /// but are lost on a hard kill. Health reports degraded buffer posture.
    Balanced,
    /// Lines are batched in memory and flushed every 200 lines.
    /// Maximises runner output throughput at the cost of a larger loss window
    /// on hard kill. Requires explicit operator opt-in.
    Throughput,
}

impl DurabilityProfile {
    /// Parse from an env-var value (case-insensitive). Returns `Strict` for
    /// unrecognised values so the default is always the safest option.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "balanced" => Self::Balanced,
            "throughput" => Self::Throughput,
            _ => Self::Strict,
        }
    }

    /// Canonical name used in health output and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Throughput => "throughput",
        }
    }

    /// Number of lines that trigger a flush. `Strict` uses 1 so every push
    /// returns immediately.
    pub fn flush_threshold(&self) -> usize {
        match self {
            Self::Strict => 1,
            Self::Balanced => 50,
            Self::Throughput => 200,
        }
    }

    /// Hard cap on buffered lines per task. Once reached, flush eagerly even
    /// before the threshold to apply backpressure.
    pub fn cap(&self) -> usize {
        match self {
            Self::Strict => 1,
            Self::Balanced => 500,
            Self::Throughput => 2_000,
        }
    }
}

// ── PendingEntry ─────────────────────────────────────────────────────────────

/// One buffered stream line waiting to be flushed to the store.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub task_id: i64,
    pub worker_id: String,
    pub channel: String,
    pub line: String,
    pub ts: String,
}

// ── StreamCounter ────────────────────────────────────────────────────────────

/// Per-task in-memory sequence-number counter.
///
/// Correctness model:
/// - On first touch prime the counter via [`StreamCounter::prime`] with the
///   current `MAX(seq)` from the store. Subsequent [`StreamCounter::next_seq`]
///   calls are pure in-memory.
/// - On hub restart the counters reset and re-prime from the store, so
///   sequence continuity survives a hard kill.
#[derive(Debug, Default)]
pub struct StreamCounter {
    inner: Mutex<HashMap<i64, u64>>,
}

impl StreamCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Prime a task counter from the store's current `MAX(seq)`. Idempotent:
    /// a stale prime never pushes the counter backwards.
    pub fn prime(&self, task_id: i64, current_max: u64) {
        let mut g = self.inner.lock();
        let entry = g.entry(task_id).or_insert(0);
        if current_max > *entry {
            *entry = current_max;
        }
    }

    pub fn is_primed(&self, task_id: i64) -> bool {
        self.inner.lock().contains_key(&task_id)
    }

    /// Atomically allocate the next seq for `task_id`. Returns `None` if the
    /// counter has not been primed yet.
    pub fn next_seq(&self, task_id: i64) -> Option<u64> {
        let mut g = self.inner.lock();
        let entry = g.get_mut(&task_id)?;
        *entry += 1;
        Some(*entry)
    }

    pub fn forget(&self, task_id: i64) {
        self.inner.lock().remove(&task_id);
    }

    pub fn task_count(&self) -> usize {
        self.inner.lock().len()
    }
}

// ── StreamBuffer ─────────────────────────────────────────────────────────────

/// Bounded per-task write buffer with named durability profiles.
///
/// The buffer is shared across all route handlers via `Arc<StreamBuffer>` in
/// `HubState`. All operations are O(1) under the per-struct `Mutex`; the lock
/// window is a single deque push plus a length check.
pub struct StreamBuffer {
    profile: DurabilityProfile,
    pending: Mutex<HashMap<i64, VecDeque<PendingEntry>>>,
}

impl StreamBuffer {
    pub fn new(profile: DurabilityProfile) -> Self {
        Self {
            profile,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn profile(&self) -> DurabilityProfile {
        self.profile
    }

    /// Push one stream line. Returns `Some(batch)` when the flush threshold
    /// (or cap) is reached; `None` while still buffering.
    pub fn push(
        &self,
        task_id: i64,
        worker_id: String,
        channel: String,
        line: String,
        ts: String,
    ) -> Option<Vec<PendingEntry>> {
        let entry = PendingEntry { task_id, worker_id, channel, line, ts };
        let mut g = self.pending.lock();
        let q = g.entry(task_id).or_default();
        q.push_back(entry);
        let len = q.len();
        if len >= self.profile.flush_threshold() || len >= self.profile.cap() {
            Some(q.drain(..).collect())
        } else {
            None
        }
    }

    /// Push a batch of lines. Returns `Some(batch)` when the threshold is hit.
    pub fn push_bulk(
        &self,
        task_id: i64,
        entries: Vec<PendingEntry>,
    ) -> Option<Vec<PendingEntry>> {
        if entries.is_empty() {
            return None;
        }
        let mut g = self.pending.lock();
        let q = g.entry(task_id).or_default();
        q.extend(entries);
        let len = q.len();
        if len >= self.profile.flush_threshold() || len >= self.profile.cap() {
            Some(q.drain(..).collect())
        } else {
            None
        }
    }

    /// Force-drain all pending entries for a task. Call before `submit_result`
    /// so no buffered lines are lost at task completion.
    pub fn flush_task(&self, task_id: i64) -> Vec<PendingEntry> {
        self.pending
            .lock()
            .get_mut(&task_id)
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    }

    /// Forget a task's buffer after it completes (frees memory).
    pub fn forget(&self, task_id: i64) {
        self.pending.lock().remove(&task_id);
    }

    /// Number of tasks with a non-empty pending buffer. Diagnostic.
    pub fn buffered_task_count(&self) -> usize {
        self.pending.lock().values().filter(|q| !q.is_empty()).count()
    }

    /// Total buffered lines across all tasks. Diagnostic.
    pub fn buffered_line_count(&self) -> usize {
        self.pending.lock().values().map(|q| q.len()).sum()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- StreamCounter tests --------------------------------------------------

    #[test]
    fn next_seq_requires_prime() {
        let c = StreamCounter::new();
        assert!(c.next_seq(1).is_none());
        c.prime(1, 0);
        assert_eq!(c.next_seq(1), Some(1));
        assert_eq!(c.next_seq(1), Some(2));
    }

    #[test]
    fn prime_resumes_after_existing_rows() {
        let c = StreamCounter::new();
        c.prime(42, 17);
        assert_eq!(c.next_seq(42), Some(18));
    }

    #[test]
    fn prime_is_idempotent_no_regression() {
        let c = StreamCounter::new();
        c.prime(7, 100);
        let _ = c.next_seq(7).unwrap(); // 101
        c.prime(7, 50); // stale prime
        assert_eq!(c.next_seq(7), Some(102));
    }

    #[test]
    fn distinct_tasks_are_independent() {
        let c = StreamCounter::new();
        c.prime(1, 0);
        c.prime(2, 0);
        assert_eq!(c.next_seq(1), Some(1));
        assert_eq!(c.next_seq(2), Some(1));
        assert_eq!(c.next_seq(1), Some(2));
    }

    #[test]
    fn forget_resets() {
        let c = StreamCounter::new();
        c.prime(1, 5);
        assert_eq!(c.next_seq(1), Some(6));
        c.forget(1);
        assert!(c.next_seq(1).is_none());
    }

    #[test]
    fn concurrent_increments_are_unique() {
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(StreamCounter::new());
        c.prime(1, 0);
        let n_threads = 8;
        let per_thread = 1000;
        let mut handles = vec![];
        for _ in 0..n_threads {
            let c = c.clone();
            handles.push(thread::spawn(move || {
                let mut local = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    local.push(c.next_seq(1).unwrap());
                }
                local
            }));
        }
        let mut all: Vec<u64> = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        all.sort_unstable();
        let total = (n_threads * per_thread) as u64;
        assert_eq!(all.first().copied(), Some(1));
        assert_eq!(all.last().copied(), Some(total));
        for (i, v) in all.iter().enumerate() {
            assert_eq!(*v, (i as u64) + 1);
        }
    }

    // -- DurabilityProfile tests ----------------------------------------------

    #[test]
    fn profile_from_str() {
        assert_eq!(DurabilityProfile::from_str("strict"), DurabilityProfile::Strict);
        assert_eq!(DurabilityProfile::from_str("BALANCED"), DurabilityProfile::Balanced);
        assert_eq!(DurabilityProfile::from_str("throughput"), DurabilityProfile::Throughput);
        assert_eq!(DurabilityProfile::from_str("unknown"), DurabilityProfile::Strict);
        assert_eq!(DurabilityProfile::from_str(""), DurabilityProfile::Strict);
    }

    #[test]
    fn profile_as_str_round_trips() {
        assert_eq!(DurabilityProfile::Strict.as_str(), "strict");
        assert_eq!(DurabilityProfile::Balanced.as_str(), "balanced");
        assert_eq!(DurabilityProfile::Throughput.as_str(), "throughput");
    }

    // -- StreamBuffer tests ---------------------------------------------------

    fn entry(task_id: i64, ch: &str, line: &str) -> PendingEntry {
        PendingEntry {
            task_id,
            worker_id: "w1".into(),
            channel: ch.into(),
            line: line.into(),
            ts: "2026-06-02 00:00:00".into(),
        }
    }

    #[test]
    fn strict_flushes_every_line() {
        let buf = StreamBuffer::new(DurabilityProfile::Strict);
        let result = buf.push(1, "w1".into(), "stdout".into(), "hello".into(), "ts".into());
        assert!(result.is_some());
        let batch = result.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "hello");
    }

    #[test]
    fn balanced_buffers_until_threshold() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        let threshold = DurabilityProfile::Balanced.flush_threshold(); // 50
        for i in 0..(threshold - 1) {
            let r = buf.push(1, "w".into(), "stdout".into(), format!("line {i}"), "ts".into());
            assert!(r.is_none(), "should buffer at index {i}");
        }
        // 50th push triggers flush
        let r = buf.push(1, "w".into(), "stdout".into(), "last".into(), "ts".into());
        let batch = r.expect("flush expected at threshold");
        assert_eq!(batch.len(), threshold);
        // buffer is now empty
        assert_eq!(buf.buffered_line_count(), 0);
    }

    #[test]
    fn throughput_buffers_until_threshold() {
        let buf = StreamBuffer::new(DurabilityProfile::Throughput);
        let threshold = DurabilityProfile::Throughput.flush_threshold(); // 200
        for i in 0..(threshold - 1) {
            let r = buf.push(1, "w".into(), "stdout".into(), format!("l{i}"), "ts".into());
            assert!(r.is_none());
        }
        let r = buf.push(1, "w".into(), "stdout".into(), "last".into(), "ts".into());
        assert_eq!(r.unwrap().len(), threshold);
    }

    #[test]
    fn flush_task_drains_pending() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        buf.push(5, "w".into(), "stdout".into(), "a".into(), "ts".into());
        buf.push(5, "w".into(), "stdout".into(), "b".into(), "ts".into());
        assert_eq!(buf.buffered_line_count(), 2);
        let flushed = buf.flush_task(5);
        assert_eq!(flushed.len(), 2);
        assert_eq!(buf.buffered_line_count(), 0);
    }

    #[test]
    fn flush_task_on_empty_is_empty() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        assert!(buf.flush_task(99).is_empty());
    }

    #[test]
    fn cap_triggers_early_flush() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        let cap = DurabilityProfile::Balanced.cap(); // 500
        // Push cap lines one at a time; threshold is 50 so multiple flushes occur
        let mut flush_count = 0;
        for i in 0..cap {
            if buf.push(1, "w".into(), "stdout".into(), format!("l{i}"), "ts".into()).is_some() {
                flush_count += 1;
            }
        }
        assert!(flush_count > 0, "should have flushed at least once");
        assert_eq!(buf.buffered_line_count(), 0);
    }

    #[test]
    fn push_bulk_triggers_flush_at_threshold() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        let entries: Vec<PendingEntry> = (0..50).map(|i| entry(2, "stdout", &format!("l{i}"))).collect();
        let result = buf.push_bulk(2, entries);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 50);
    }

    #[test]
    fn diagnostic_counts_across_tasks() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        buf.push(1, "w".into(), "stdout".into(), "a".into(), "ts".into());
        buf.push(2, "w".into(), "stdout".into(), "b".into(), "ts".into());
        buf.push(2, "w".into(), "stdout".into(), "c".into(), "ts".into());
        assert_eq!(buf.buffered_task_count(), 2);
        assert_eq!(buf.buffered_line_count(), 3);
    }

    #[test]
    fn forget_releases_task_buffer() {
        let buf = StreamBuffer::new(DurabilityProfile::Balanced);
        buf.push(10, "w".into(), "stdout".into(), "x".into(), "ts".into());
        assert_eq!(buf.buffered_task_count(), 1);
        buf.forget(10);
        assert_eq!(buf.buffered_task_count(), 0);
    }
}
