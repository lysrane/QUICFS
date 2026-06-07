use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One deferred write chunk. Stays in the buffer until its flush is ACKed
/// (Status::Ok); a send no longer removes it, so a failed send leaves it here to
/// be re-sent (idempotently, positioned) after a reconnect.
struct PendingWrite {
    offset: u64,
    data: Vec<u8>,
    queued_at: Instant,
}

/// Per-handle queue plus a single-sender guard.
#[derive(Default)]
struct HandleBuf {
    chunks: Vec<PendingWrite>,
    /// True while a flush of this handle is mid-flight (snapshot taken, awaiting
    /// ack). Prevents the FUSE thread and the background task from transmitting
    /// the same chunks twice. (Positioned re-send is idempotent, so a double-send
    /// would be wasteful, not wrong; this avoids the waste.)
    sending: bool,
}

impl HandleBuf {
    fn bytes(&self) -> usize {
        self.chunks.iter().map(|w| w.data.len()).sum()
    }
}

/// Coalescing, keep-until-acked write buffer.
///
/// Accumulates small FUSE writes per handle and flushes them as one streaming
/// Write RPC. Unlike a drain-on-send buffer, chunks are removed ONLY when the
/// server acknowledges them (`ack_flush`); a failed send leaves them buffered so
/// a reconnect can re-send them. Positioned writes are idempotent, so a re-send
/// after a partial commit overwrites the same bytes with no server-side dedup.
///
/// Memory is hard-bounded: `push` rejects once `hard_total_bytes` would be
/// exceeded (the caller then fails the write loudly), so a black-holing server
/// cannot grow the buffer without bound now that a send no longer frees memory.
pub struct WriteBuffer {
    per_handle: HashMap<u64, HandleBuf>,
    total_bytes: usize,
    /// Soft per-handle limit: exceeding it asks the caller to flush this handle.
    pub max_per_handle_bytes: usize,
    /// Soft global limit: exceeding it asks the caller to flush the largest handle.
    pub max_total_bytes: usize,
    /// Hard global limit: `push` refuses to enqueue past this (caller fails loud).
    pub hard_total_bytes: usize,
    /// Coalesce window: the background task force-flushes data older than this.
    pub window: Duration,
}

impl WriteBuffer {
    pub fn new(max_per_handle_bytes: usize, max_total_bytes: usize, window_ms: u64) -> Self {
        Self {
            per_handle: HashMap::new(),
            total_bytes: 0,
            max_per_handle_bytes,
            max_total_bytes,
            // Hard ceiling at 2x the soft global cap: room to keep unacked data
            // for a retry across a brief blip, but still a firm bound past which
            // writes fail loudly instead of growing the buffer toward OOM.
            hard_total_bytes: max_total_bytes.saturating_mul(2),
            window: Duration::from_millis(window_ms),
        }
    }

    /// Buffer a write chunk, or refuse it if the hard memory bound would be
    /// exceeded. On refusal nothing is enqueued and the caller MUST fail the
    /// write loudly (sticky EIO) rather than acknowledge data it cannot hold.
    pub fn push(&mut self, handle: u64, offset: u64, data: Vec<u8>) -> PushDecision {
        let n = data.len();
        if self.total_bytes + n > self.hard_total_bytes {
            return PushDecision::Reject;
        }
        let entry = self.per_handle.entry(handle).or_default();
        entry.chunks.push(PendingWrite {
            offset,
            data,
            queued_at: Instant::now(),
        });
        self.total_bytes += n;

        if entry.bytes() >= self.max_per_handle_bytes {
            return PushDecision::FlushThis(handle);
        }
        if self.total_bytes >= self.max_total_bytes {
            let biggest = self
                .per_handle
                .iter()
                .max_by_key(|(_, v)| v.bytes())
                .map(|(h, _)| *h)
                .unwrap_or(handle);
            return PushDecision::FlushOther(biggest);
        }
        PushDecision::Buffered
    }

    /// Begin a flush of `handle`: mark it sending and return a COALESCED snapshot
    /// of its chunks to transmit, plus how many original chunks the snapshot
    /// covers (`sent_count`, for `ack_flush`). Returns `None` if the handle is
    /// empty or already has a flush in flight. The chunks are NOT removed yet.
    ///
    /// The snapshot includes every buffered chunk (even ones a prior failed send
    /// already transmitted), so a reconnect re-sends them all idempotently.
    pub fn begin_flush(&mut self, handle: u64) -> Option<FlushBatch> {
        let hb = self.per_handle.get_mut(&handle)?;
        if hb.sending || hb.chunks.is_empty() {
            return None;
        }
        hb.sending = true;
        let sent_count = hb.chunks.len();

        // Offset-sort and coalesce contiguous runs (clone the bytes so the buffer
        // lock can be released during the async send while the originals stay put
        // until acked).
        let mut pairs: Vec<(u64, Vec<u8>)> = hb
            .chunks
            .iter()
            .map(|w| (w.offset, w.data.clone()))
            .collect();
        pairs.sort_by_key(|(off, _)| *off);
        let mut merged: Vec<(u64, Vec<u8>)> = Vec::with_capacity(pairs.len());
        for (off, data) in pairs {
            match merged.last_mut() {
                Some((last_off, last_data)) if *last_off + last_data.len() as u64 == off => {
                    last_data.extend_from_slice(&data);
                }
                _ => merged.push((off, data)),
            }
        }
        Some(FlushBatch {
            chunks: merged,
            sent_count,
        })
    }

    /// The flush of `handle` was acknowledged: drop the first `sent_count` chunks
    /// (the snapshot) and clear the sending guard. Chunks pushed during the send
    /// are a later suffix and are kept.
    pub fn ack_flush(&mut self, handle: u64, sent_count: usize) {
        if let Some(hb) = self.per_handle.get_mut(&handle) {
            let take = sent_count.min(hb.chunks.len());
            let removed: usize = hb.chunks.drain(..take).map(|w| w.data.len()).sum();
            self.total_bytes = self.total_bytes.saturating_sub(removed);
            hb.sending = false;
            if hb.chunks.is_empty() {
                self.per_handle.remove(&handle);
            }
        }
    }

    /// The flush of `handle` failed: clear the sending guard so a later flush
    /// (after a reconnect) can retry. Chunks remain buffered.
    pub fn fail_flush(&mut self, handle: u64) {
        if let Some(hb) = self.per_handle.get_mut(&handle) {
            hb.sending = false;
        }
    }

    /// Drop all of `handle`'s buffered chunks (a loud, deliberate discard) and
    /// return the bytes freed. Used for an O_APPEND handle on reconnect (no
    /// replay) and for the max-unacked-age reclaim; callers set the sticky error.
    pub fn drop_handle(&mut self, handle: u64) -> usize {
        if let Some(hb) = self.per_handle.remove(&handle) {
            let bytes = hb.bytes();
            self.total_bytes = self.total_bytes.saturating_sub(bytes);
            bytes
        } else {
            0
        }
    }

    /// Handles whose oldest chunk has waited at least `window` (background flush).
    pub fn expired_handles(&self) -> Vec<u64> {
        self.older_than(self.window)
    }

    /// Handles whose oldest chunk has waited at least `deadline` (age-drop reclaim).
    pub fn older_than(&self, deadline: Duration) -> Vec<u64> {
        let now = Instant::now();
        self.per_handle
            .iter()
            .filter(|(_, hb)| {
                hb.chunks
                    .first()
                    .map(|w| now.duration_since(w.queued_at) >= deadline)
                    .unwrap_or(false)
            })
            .map(|(h, _)| *h)
            .collect()
    }

    /// All handles that currently hold buffered data.
    pub fn handles(&self) -> Vec<u64> {
        self.per_handle.keys().copied().collect()
    }

    /// True if `handle` has any buffered chunks.
    pub fn has_buffered(&self, handle: u64) -> bool {
        self.per_handle
            .get(&handle)
            .map(|hb| !hb.chunks.is_empty())
            .unwrap_or(false)
    }

    /// Current total buffered bytes across all handles (pending + unacked).
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// A coalesced snapshot to transmit for one handle.
pub struct FlushBatch {
    /// Offset-sorted, contiguous-coalesced `(offset, data)` runs to send.
    pub chunks: Vec<(u64, Vec<u8>)>,
    /// Number of original chunks this snapshot covers (passed back to `ack_flush`).
    pub sent_count: usize,
}

/// What the caller should do after a `push`.
#[derive(Debug, PartialEq, Eq)]
pub enum PushDecision {
    /// Buffered; no flush needed right now.
    Buffered,
    /// Per-handle soft limit hit; flush this handle.
    FlushThis(u64),
    /// Global soft limit hit; flush this (possibly other) handle to reclaim.
    FlushOther(u64),
    /// Hard memory bound would be exceeded; nothing was buffered. The caller MUST
    /// fail the write loudly (sticky EIO) - never silently accept un-bufferable data.
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_via_flush(wb: &mut WriteBuffer, h: u64) -> Vec<(u64, Vec<u8>)> {
        match wb.begin_flush(h) {
            Some(b) => {
                wb.ack_flush(h, b.sent_count);
                b.chunks
            }
            None => vec![],
        }
    }

    #[test]
    fn small_writes_buffer_then_flush_on_per_handle_limit() {
        let mut wb = WriteBuffer::new(100, 1000, 60_000);
        assert_eq!(wb.push(1, 0, vec![0u8; 40]), PushDecision::Buffered);
        assert_eq!(wb.push(1, 40, vec![0u8; 40]), PushDecision::Buffered);
        assert_eq!(wb.total_bytes(), 80);
        assert_eq!(wb.push(1, 80, vec![0u8; 40]), PushDecision::FlushThis(1));
    }

    #[test]
    fn global_limit_evicts_the_largest_handle() {
        let mut wb = WriteBuffer::new(10_000, 100, 60_000);
        assert_eq!(wb.push(1, 0, vec![0u8; 70]), PushDecision::Buffered);
        assert_eq!(wb.push(2, 0, vec![0u8; 40]), PushDecision::FlushOther(1));
    }

    #[test]
    fn hard_cap_rejects_without_enqueuing() {
        // soft total 100, hard total = 200.
        let mut wb = WriteBuffer::new(10_000, 100, 60_000);
        assert_eq!(wb.push(1, 0, vec![0u8; 150]), PushDecision::FlushOther(1));
        // total is 150; another 100 would be 250 > 200 hard cap -> reject, not buffered.
        assert_eq!(wb.push(1, 150, vec![0u8; 100]), PushDecision::Reject);
        assert_eq!(wb.total_bytes(), 150, "rejected chunk must not be buffered");
    }

    #[test]
    fn keep_until_ack_then_remove() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 60_000);
        wb.push(7, 0, vec![1u8; 10]);
        let b = wb.begin_flush(7).expect("has data");
        // Still buffered until ack.
        assert_eq!(wb.total_bytes(), 10);
        // A second begin_flush is refused while sending.
        assert!(wb.begin_flush(7).is_none(), "single sender per handle");
        wb.ack_flush(7, b.sent_count);
        assert_eq!(wb.total_bytes(), 0, "ack removes the snapshot");
        assert!(wb.begin_flush(7).is_none(), "nothing left");
    }

    #[test]
    fn failed_flush_keeps_chunks_for_retry() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 60_000);
        wb.push(3, 0, vec![9u8; 20]);
        let _ = wb.begin_flush(3).unwrap();
        wb.fail_flush(3);
        assert_eq!(wb.total_bytes(), 20, "failed flush retains data");
        // Retry: begin_flush works again and re-sends the same chunk.
        let b = wb.begin_flush(3).expect("retry");
        assert_eq!(b.chunks.len(), 1);
        assert_eq!(b.chunks[0], (0, vec![9u8; 20]));
    }

    #[test]
    fn ack_keeps_chunks_pushed_during_send() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 60_000);
        wb.push(1, 0, vec![0u8; 10]);
        let b = wb.begin_flush(1).unwrap();
        // A write lands while the flush is in flight.
        // (sending is set, but push does not consult it.)
        wb.fail_flush(1); // clear sending so push path is normal; then re-add
        wb.push(1, 10, vec![0u8; 10]);
        // Ack only the original snapshot (sent_count = 1 chunk).
        wb.ack_flush(1, b.sent_count);
        assert_eq!(wb.total_bytes(), 10, "the later push survives the ack");
    }

    #[test]
    fn drain_sorts_and_coalesces() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 60_000);
        wb.push(1, 10, vec![b'b'; 10]);
        wb.push(1, 0, vec![b'a'; 10]);
        wb.push(1, 20, vec![b'c'; 10]);
        wb.push(1, 100, vec![b'd'; 10]);
        let chunks = drain_via_flush(&mut wb, 1);
        assert_eq!(chunks.len(), 2, "0..30 coalesces, gap stays separate");
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1.len(), 30);
        assert_eq!(chunks[1].0, 100);
        assert_eq!(wb.total_bytes(), 0);
    }

    #[test]
    fn drop_handle_frees_and_reports_bytes() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 60_000);
        wb.push(5, 0, vec![0u8; 30]);
        wb.push(5, 30, vec![0u8; 20]);
        assert_eq!(wb.drop_handle(5), 50);
        assert_eq!(wb.total_bytes(), 0);
        assert_eq!(wb.drop_handle(5), 0, "second drop is a no-op");
    }

    #[test]
    fn age_query_reports_old_handles() {
        let mut wb = WriteBuffer::new(10_000, 100_000, 0);
        assert!(wb.older_than(Duration::ZERO).is_empty());
        wb.push(3, 0, vec![0u8; 8]);
        assert_eq!(wb.older_than(Duration::ZERO), vec![3]);
        assert!(wb.older_than(Duration::from_secs(3600)).is_empty());
    }
}
