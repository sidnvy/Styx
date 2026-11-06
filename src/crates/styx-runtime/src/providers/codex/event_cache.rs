//! Bounded retention of the same native event stream. A complete contiguous
//! output/exited/closed prefix is independent of the upstream 30s read cache.
//! It is DATA only; the existing decoded reader still validates owner/policy.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

// Charge allocator/queue/permit metadata as well as decoded bytes. The peer's
// existing unused reservation supplies this budget; no new memory partition.
const CHUNK_ACCOUNTING: usize = 512;
pub(super) struct Chunk {
    seq: u64,
    stream: &'static str,
    bytes: Vec<u8>,
    budget: Option<OwnedSemaphorePermit>,
}
impl Chunk {
    pub(super) fn into_parts(mut self) -> (String, Vec<u8>, OwnedSemaphorePermit) {
        (
            self.stream.into(),
            std::mem::take(&mut self.bytes),
            self.budget.take().expect("retained chunk budget"),
        )
    }
}
impl Drop for Chunk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
#[derive(Default)]
struct Stream {
    last_seq: u64,
    exited: Option<(u64, i32)>,
    closed: Option<u64>,
    unavailable: bool,
    chunks: VecDeque<Chunk>,
}
impl Stream {
    fn refuse(&mut self) {
        self.unavailable = true;
        self.chunks = VecDeque::new(); // Drop zeroizes and releases reservations.
    }
    fn observe(&mut self, memory: &Arc<Semaphore>, method: &str, params: &Value) {
        if self.unavailable {
            return;
        }
        let seq = params.get("seq").and_then(Value::as_u64);
        if self.closed.is_some() || self.last_seq.checked_add(1) != seq {
            self.refuse();
            return;
        }
        let seq = seq.expect("checked positive successor");
        match method {
            "process/output" => {
                let stream = match params.get("stream").and_then(Value::as_str) {
                    Some("stdout") => "stdout",
                    Some("stderr") => "stderr",
                    Some("pty") => "pty",
                    _ => {
                        self.refuse();
                        return;
                    }
                };
                let Some(encoded) = params.get("chunk").and_then(Value::as_str) else {
                    self.refuse();
                    return;
                };
                let Some(charge) = encoded
                    .len()
                    .checked_add(CHUNK_ACCOUNTING)
                    .and_then(|n| u32::try_from(n).ok())
                else {
                    self.refuse();
                    return;
                };
                // Reserve before decoding; even malformed events cannot grow an
                // unbudgeted replay queue. Failure disables only this proof.
                let Ok(budget) = memory.clone().try_acquire_many_owned(charge) else {
                    self.refuse();
                    return;
                };
                let Ok(mut bytes) = STANDARD.decode(encoded) else {
                    self.refuse();
                    return;
                };
                if STANDARD.encode(&bytes) != encoded {
                    bytes.zeroize();
                    self.refuse();
                    return;
                }
                self.chunks.push_back(Chunk {
                    seq,
                    stream,
                    bytes,
                    budget: Some(budget),
                });
            }
            "process/exited" => {
                let Some(code) = params
                    .get("exitCode")
                    .and_then(Value::as_i64)
                    .and_then(|n| i32::try_from(n).ok())
                else {
                    self.refuse();
                    return;
                };
                if self.exited.is_some() {
                    self.refuse();
                    return;
                }
                self.exited = Some((seq, code));
            }
            "process/closed" if self.exited.is_some() => self.closed = Some(seq),
            _ => {
                self.refuse();
                return;
            }
        }
        self.last_seq = seq;
    }
}
pub(super) struct Completed {
    pub(super) chunks: VecDeque<Chunk>,
    pub(super) exit: (u64, i32),
    pub(super) closed: u64,
}
pub(super) struct RetainedEvents {
    streams: HashMap<String, Option<Stream>>,
    memory: Arc<Semaphore>,
}
impl RetainedEvents {
    pub(super) fn new(bytes: usize) -> Self {
        Self {
            streams: HashMap::new(),
            memory: Arc::new(Semaphore::new(bytes)),
        }
    }
    pub(super) fn register(&mut self, id: &str) {
        self.streams.insert(id.into(), Some(Stream::default()));
    }
    pub(super) fn remove(&mut self, id: &str) {
        self.streams.remove(id);
    }
    pub(super) fn disable(&mut self, id: &str) {
        if let Some(stream) = self.streams.get_mut(id) {
            *stream = None;
        }
    }
    pub(super) fn observe(&mut self, id: &str, method: &str, params: &Value) {
        if let Some(Some(stream)) = self.streams.get_mut(id) {
            stream.observe(&self.memory, method, params);
        }
    }
    pub(super) fn take_completed(&mut self, id: &str, cursor: Option<u64>) -> Option<Completed> {
        let stream = self.streams.get_mut(id)?.as_mut()?;
        if stream.unavailable {
            return None;
        }
        let exit = stream.exited?;
        let closed = stream.closed?;
        if cursor.is_some_and(|seq| seq > closed) {
            return None;
        }
        let mut chunks = VecDeque::new();
        for chunk in std::mem::take(&mut stream.chunks) {
            if cursor.is_none_or(|seq| chunk.seq > seq) {
                chunks.push_back(chunk);
            }
        }
        Some(Completed {
            chunks,
            exit,
            closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn output(seq: u64) -> Value {
        json!({"seq":seq,"stream":"stdout","chunk":STANDARD.encode(b"private-output")})
    }
    fn finish(cache: &mut RetainedEvents, id: &str, exit: u64, closed: u64) {
        cache.observe(id, "process/exited", &json!({"seq":exit,"exitCode":0}));
        cache.observe(id, "process/closed", &json!({"seq":closed}));
    }
    #[test]
    fn only_an_exact_complete_original_stream_can_supply_delayed_output() {
        let mut cache = RetainedEvents::new(8192);
        cache.register("original");
        cache.register("other");
        cache.observe("original", "process/output", &output(1));
        assert!(cache.take_completed("original", None).is_none());
        cache.observe("original", "process/exited", &json!({"seq":2,"exitCode":0}));
        assert!(cache.take_completed("original", None).is_none());
        cache.observe("original", "process/closed", &json!({"seq":3}));
        assert!(cache.take_completed("other", None).is_none());
        let proof = cache.take_completed("original", None).unwrap();
        assert_eq!(proof.exit, (2, 0));
        assert_eq!(proof.closed, 3);
        assert_eq!(proof.chunks.front().unwrap().bytes, b"private-output");
        drop(proof);
        assert_eq!(cache.memory.available_permits(), 8192);
        cache.remove("original");
        assert!(cache.take_completed("original", None).is_none());
    }
    #[test]
    fn gaps_duplicates_malformed_events_and_memory_loss_cannot_fabricate_eof() {
        for bad in [
            json!({"seq":2,"stream":"stdout","chunk":"YQ=="}),
            json!({"seq":1,"stream":"unknown","chunk":"YQ=="}),
            json!({"seq":1,"stream":"stdout","chunk":"YQ==\n"}),
        ] {
            let mut cache = RetainedEvents::new(8192);
            cache.register("p");
            cache.observe("p", "process/output", &bad);
            finish(&mut cache, "p", 3, 4);
            assert!(cache.take_completed("p", None).is_none());
        }
        let mut cache = RetainedEvents::new(8192);
        cache.register("p");
        cache.observe("p", "process/output", &output(1));
        cache.observe("p", "process/output", &output(1));
        finish(&mut cache, "p", 2, 3);
        assert!(cache.take_completed("p", None).is_none());
        assert_eq!(cache.memory.available_permits(), 8192);
        let mut cache = RetainedEvents::new(600);
        cache.register("p");
        cache.observe("p", "process/output", &output(1));
        cache.observe("p", "process/output", &output(2));
        finish(&mut cache, "p", 3, 4);
        assert!(cache.take_completed("p", None).is_none());
        assert_eq!(cache.memory.available_permits(), 600);
        cache.register("raw");
        cache.observe("raw", "process/output", &output(1));
        cache.disable("raw");
        finish(&mut cache, "raw", 2, 3);
        assert!(cache.take_completed("raw", None).is_none());
        assert_eq!(cache.memory.available_permits(), 600);
    }
}
