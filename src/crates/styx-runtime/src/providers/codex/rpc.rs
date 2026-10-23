use super::ExecError;
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt, sync::oneshot};
use tokio_util::codec::{FramedRead, LinesCodec};

// Reserve maximum request + response wire frames per in-flight RPC, plus
// one reader frame. Derive concurrency from the frozen 16MiB peer budget.
const MAX_INFLIGHT: usize = (styx_contracts::OPERATION_METADATA_BYTES
    - styx_contracts::EXEC_FRAME_BYTES)
    / (2 * styx_contracts::EXEC_FRAME_BYTES);
struct BudgetedReply {
    result: Result<Value, ExecError>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
struct Pending {
    reply: oneshot::Sender<BudgetedReply>,
    read_process: Option<String>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[derive(Clone, Debug, Default)]
pub(super) struct Observation {
    pub exited: Option<(u64, i32)>,
    pub closed: Option<u64>,
    pub invalid: bool,
    pub lost: bool,
}
impl Observation {
    fn notice(&mut self, method: &str, params: &Value) {
        let Some(seq) = params.get("seq").and_then(Value::as_u64).filter(|s| *s > 0) else {
            self.invalid = true;
            return;
        };
        if method == "process/exited" {
            let Some(code) = params
                .get("exitCode")
                .and_then(Value::as_i64)
                .and_then(|v| i32::try_from(v).ok())
            else {
                self.invalid = true;
                return;
            };
            if self.exited.replace((seq, code)).is_some() {
                self.invalid = true;
            }
        } else if self.closed.replace(seq).is_some() {
            self.invalid = true;
        }
        if let (Some((exit, _)), Some(close)) = (self.exited, self.closed)
            && close <= exit
        {
            self.invalid = true;
        }
    }
}
pub(super) struct Rpc {
    stdin: tokio::sync::Mutex<Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>>,
    pending: Mutex<HashMap<u64, Pending>>,
    observations: Mutex<HashMap<String, Observation>>,
    sequence: AtomicU64,
    closed: AtomicBool,
    timeout: Duration,
    permits: Arc<tokio::sync::Semaphore>,
    observation_limit: usize,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Rpc {
    pub fn new<
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    >(
        stdin: W,
        stdout: R,
        timeout: Duration,
        observation_limit: usize,
    ) -> Arc<Self> {
        let rpc = Arc::new(Self {
            stdin: tokio::sync::Mutex::new(Some(Box::new(stdin))),
            pending: Mutex::new(HashMap::new()),
            observations: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            timeout,
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT)),
            observation_limit,
            reader_task: Mutex::new(None),
        });
        let weak = Arc::downgrade(&rpc);
        let reader_task = tokio::spawn(async move {
            let mut frames = FramedRead::new(
                stdout,
                LinesCodec::new_with_max_length(styx_contracts::EXEC_FRAME_BYTES),
            );
            while let Some(frame) = frames.next().await {
                let Some(rpc) = weak.upgrade() else { break };
                match frame {
                    Ok(line) => {
                        if rpc.route(&line).is_err() {
                            rpc.fail(ExecError::InvalidFrame);
                            break;
                        }
                    }
                    Err(_) => {
                        rpc.fail(ExecError::InvalidFrame);
                        break;
                    }
                }
            }
            if let Some(rpc) = weak.upgrade() {
                rpc.fail(ExecError::TransportLost);
            }
        });
        *rpc.reader_task.lock().expect("reader task mutex") = Some(reader_task);
        rpc
    }
    fn route(&self, line: &str) -> Result<(), ExecError> {
        let message: Value = serde_json::from_str(line).map_err(|_| ExecError::InvalidFrame)?;
        if !message.is_object() {
            return Err(ExecError::InvalidFrame);
        }
        if message.get("id").is_none() {
            let method = message
                .get("method")
                .and_then(Value::as_str)
                .ok_or(ExecError::InvalidFrame)?;
            if matches!(method, "process/exited" | "process/closed") {
                let params = message.get("params").ok_or(ExecError::InvalidFrame)?;
                let id = params
                    .get("processId")
                    .and_then(Value::as_str)
                    .ok_or(ExecError::InvalidFrame)?;
                if let Some(observation) = self
                    .observations
                    .lock()
                    .expect("observation mutex")
                    .get_mut(id)
                {
                    observation.notice(method, params);
                }
            }
            return Ok(());
        }
        let id = message["id"].as_u64().ok_or(ExecError::InvalidFrame)?;
        if message.get("result").is_some() == message.get("error").is_some() {
            return Err(ExecError::InvalidFrame);
        }
        let Some(pending) = self.pending.lock().expect("pending mutex").remove(&id) else {
            return Ok(());
        };
        let result = if let Some(error) = message.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(ExecError::InvalidFrame)?;
            if code == -32600
                && pending.read_process.as_ref().is_some_and(|p| {
                    error.get("message").and_then(Value::as_str)
                        == Some(format!("unknown process id {p}").as_str())
                })
            {
                Err(ExecError::ProcessLost)
            } else {
                Err(ExecError::Rejected(code))
            }
        } else {
            Ok(message["result"].clone())
        };
        let _ = pending.reply.send(BudgetedReply {
            result,
            _permit: pending._permit,
        });
        Ok(())
    }
    pub fn register(&self, id: &str) -> Result<(), ExecError> {
        let mut observations = self.observations.lock().expect("observation mutex");
        if observations.len() >= self.observation_limit || observations.contains_key(id) {
            return Err(ExecError::Capacity);
        }
        observations.insert(id.to_owned(), Observation::default());
        Ok(())
    }
    pub fn observation(&self, id: &str) -> Option<Observation> {
        self.observations
            .lock()
            .expect("observation mutex")
            .get(id)
            .cloned()
    }
    pub fn unregister(&self, id: &str) {
        self.observations
            .lock()
            .expect("observation mutex")
            .remove(id);
    }
    pub fn fail(&self, error: ExecError) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.permits.close();
        for (_, pending) in self.pending.lock().expect("pending mutex").drain() {
            let _ = pending.reply.send(BudgetedReply {
                result: Err(error.clone()),
                _permit: pending._permit,
            });
        }
        for observation in self
            .observations
            .lock()
            .expect("observation mutex")
            .values_mut()
        {
            observation.lost = true;
        }
    }
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, ExecError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ExecError::NotSent);
        }
        let id = self
            .sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| ExecError::Capacity)?
            + 1;
        // Reject saturated work before serializing a wire buffer; queued
        // callers do not accumulate maximum-size request strings here.
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ExecError::Capacity)?;
        #[derive(serde::Serialize)]
        struct WireRequest<'a> {
            id: u64,
            method: &'a str,
            params: &'a Value,
        }
        let text = serde_json::to_string(&WireRequest {
            id,
            method,
            params: &params,
        })
        .map_err(|_| ExecError::InvalidRequest)?;
        if text.len() > styx_contracts::EXEC_FRAME_BYTES {
            return Err(ExecError::InvalidRequest);
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(ExecError::NotSent);
        }
        let (reply, receiver) = oneshot::channel();
        self.pending.lock().expect("pending mutex").insert(
            id,
            Pending {
                reply,
                read_process: (method == "process/read")
                    .then(|| params["processId"].as_str().unwrap_or_default().to_owned()),
                _permit: permit,
            },
        );
        let mut guard = PendingGuard {
            rpc: self,
            id,
            sending: false,
        };
        // A cancelled/failed partial write corrupts stream framing, so only a
        // send failure fences the whole transport. A response wait timeout does
        // not stop the executor or unrelated processes and never causes replay.
        match tokio::time::timeout(self.timeout, self.send_request(&text, &mut guard)).await {
            Ok(Ok(())) => {
                guard.sending = false;
            }
            Ok(Err(error)) => {
                if guard.sending {
                    self.fail(error.clone());
                }
                return Err(error);
            }
            Err(_) => {
                if guard.sending {
                    self.fail(ExecError::TimeoutUnknown);
                }
                return Err(if guard.sending {
                    ExecError::TimeoutUnknown
                } else {
                    ExecError::NotSent
                });
            }
        }
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(reply)) => reply.result,
            Ok(Err(_)) => Err(ExecError::TransportLost),
            Err(_) => {
                self.pending.lock().expect("pending mutex").remove(&id);
                Err(ExecError::TimeoutUnknown)
            }
        }
    }
    async fn send_request(
        &self,
        text: &str,
        dispatch: &mut PendingGuard<'_>,
    ) -> Result<(), ExecError> {
        let mut writer = self.stdin.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(ExecError::NotSent);
        }
        let stdin = writer.as_mut().ok_or(ExecError::NotSent)?;
        // Waiting for the writer mutex has not emitted a byte and cannot
        // corrupt framing if cancelled; only fence once sending can begin.
        dispatch.sending = true;
        stdin
            .write_all(text.as_bytes())
            .await
            .map_err(|_| ExecError::TransportLost)?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|_| ExecError::TransportLost)?;
        stdin.flush().await.map_err(|_| ExecError::TransportLost)?;
        dispatch.sending = false;
        Ok(())
    }
    async fn send(&self, text: &str) -> Result<(), ExecError> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or(ExecError::TransportLost)?;
        stdin
            .write_all(text.as_bytes())
            .await
            .map_err(|_| ExecError::TransportLost)?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|_| ExecError::TransportLost)?;
        stdin.flush().await.map_err(|_| ExecError::TransportLost)
    }
    pub async fn notify(&self, method: &str) -> Result<(), ExecError> {
        let text = json!({"method":method,"params":{}}).to_string();
        self.send(&text).await
    }
    pub async fn finish_reader(&self, until: tokio::time::Instant) -> bool {
        let task = self.reader_task.lock().expect("reader task mutex").take();
        if let Some(mut task) = task {
            match tokio::time::timeout_at(until, &mut task).await {
                Ok(result) => result.is_ok(),
                Err(_) => {
                    task.abort();
                    if task.is_finished() {
                        task.await.is_err_and(|e| e.is_cancelled())
                    } else {
                        *self.reader_task.lock().expect("reader task mutex") = Some(task);
                        false
                    }
                }
            }
        } else {
            true
        }
    }
    pub async fn close(&self) {
        self.fail(ExecError::TransportLost);
        if let Some(mut stdin) = self.stdin.lock().await.take() {
            let _ = stdin.shutdown().await;
        }
    }
}

// Dropping a call while waiting for a reply removes only that waiter. Dropping
// during a possible partial frame send fences framing for the whole transport.
struct PendingGuard<'a> {
    rpc: &'a Rpc,
    id: u64,
    sending: bool,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.rpc
            .pending
            .lock()
            .expect("pending mutex")
            .remove(&self.id);
        if self.sending {
            self.rpc.fail(ExecError::TransportLost);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    fn pair(timeout: Duration) -> (Arc<Rpc>, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client);
        (Rpc::new(writer, reader, timeout, 2), server)
    }
    #[tokio::test]
    async fn reply_timeout_is_local_and_late_reply_does_not_replay_or_dispose_executor() {
        let (rpc, server) = pair(Duration::from_millis(60));
        let (r, mut w) = tokio::io::split(server);
        let observer = tokio::spawn(async move {
            let mut lines = BufReader::new(r).lines();
            let first: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            tokio::time::sleep(Duration::from_millis(90)).await;
            w.write_all(
                format!("{}\n", json!({"id":first["id"],"result":{"late":true}})).as_bytes(),
            )
            .await
            .unwrap();
            let second: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(second["method"], "healthy");
            w.write_all(
                format!("{}\n", json!({"id":second["id"],"result":{"ok":true}})).as_bytes(),
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        assert_eq!(
            rpc.request("hold", json!({})).await.unwrap_err(),
            ExecError::TimeoutUnknown
        );
        assert!(!rpc.closed.load(Ordering::SeqCst));
        assert_eq!(rpc.request("healthy", json!({})).await.unwrap()["ok"], true);
        observer.await.unwrap();
    }
    #[tokio::test]
    async fn rpc_ids_never_wrap_and_observations_are_bounded() {
        let (rpc, _server) = pair(Duration::from_millis(50));
        rpc.sequence.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(
            rpc.request("unreachable", json!({})).await.unwrap_err(),
            ExecError::Capacity
        );
        assert_eq!(rpc.sequence.load(Ordering::SeqCst), u64::MAX);
        rpc.register("a").unwrap();
        rpc.register("b").unwrap();
        assert_eq!(rpc.register("c"), Err(ExecError::Capacity));
        rpc.unregister("a");
        rpc.register("c").unwrap();
    }
}
#[cfg(test)]
mod budget_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    #[tokio::test]
    async fn delivered_unconsumed_replies_keep_wire_budget_reserved() {
        let (client, server) = tokio::io::duplex(4096);
        let (r, w) = tokio::io::split(client);
        let rpc = Rpc::new(w, r, Duration::from_millis(200), 4);
        let (r, mut w) = tokio::io::split(server);
        let worker = tokio::spawn(async move {
            let mut lines = BufReader::new(r).lines();
            for _ in 0..MAX_INFLIGHT {
                let q: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                w.write_all(format!("{}\n", json!({"id":q["id"],"result":{"ok":true}})).as_bytes())
                    .await
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let mut calls = (0..MAX_INFLIGHT)
            .map(|_| Box::pin(rpc.request("parked", json!({}))))
            .collect::<Vec<_>>();
        for call in &mut calls {
            assert!(futures_util::poll!(call.as_mut()).is_pending());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(rpc.permits.available_permits(), 0);
        assert_eq!(
            rpc.request("saturated", json!({})).await.unwrap_err(),
            ExecError::Capacity
        );
        drop(calls);
        assert_eq!(rpc.permits.available_permits(), MAX_INFLIGHT);
        worker.await.unwrap();
    }
    #[tokio::test]
    async fn oversized_frame_and_partial_send_have_bounded_explicit_transport_failure() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (r, w) = tokio::io::split(client);
        let rpc = Rpc::new(w, r, Duration::from_millis(100), 4);
        let worker = tokio::spawn(async move {
            let _ = server
                .write_all(&vec![b'x'; styx_contracts::EXEC_FRAME_BYTES + 1])
                .await;
        });
        assert_eq!(
            rpc.request("frame-test", json!({})).await.unwrap_err(),
            ExecError::InvalidFrame
        );
        worker.await.unwrap();
        let (client, _server) = tokio::io::duplex(64);
        let (r, w) = tokio::io::split(client);
        let rpc = Rpc::new(w, r, Duration::from_millis(20), 4);
        assert_eq!(
            rpc.request("partial-send", json!({"data":"x".repeat(8192)}))
                .await
                .unwrap_err(),
            ExecError::TimeoutUnknown
        );
        assert!(rpc.closed.load(Ordering::SeqCst));
        assert_eq!(
            rpc.request("never-replayed", json!({})).await.unwrap_err(),
            ExecError::NotSent
        );
    }
}
