//! Parent-only bounded watch transport. The actual zbus watcher runs exclusively
//! inside the pinned same-image resource-limited worker. Any terminal report or
//! worker EOF is a full-source fence, never a Ready/registration assertion.
use super::*;
use crate::platform::linux::LinuxCandidate;
pub use crate::platform::linux::watch::{
    CandidateKey, Invalidation, InvalidationReason, WatchChange, WatchEvent, WatchShutdown,
    WatchStop,
};
use crate::store::ProcessIdentity;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use styx_contracts::identity::AgentInstanceId;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, LinesCodec};
// A long-lived watch must not occupy the short probe partition: the desktop
// supervisor intentionally owns one watch AND one fresh association probe.
// Dedicated single slots bound each kind, without allowing two watchers to
// starve discovery/association or allowing unbounded worker fan-out.
static WATCH_SLOT: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(1)));
const QUEUE: usize = 8;
const IDLE: Duration = Duration::from_secs(35);
const END_GRACE: Duration = Duration::from_secs(2);

/// One JSON object per line. No additional wrapper/decoder authority is added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Wire {
    Event(WatchEvent),
    Shutdown(WatchShutdown),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentStop {
    Cancelled,
    Busy,
    Spawn,
    Entropy,
    InvalidFrame,
    OutputTooLarge,
    Overflow,
    ConsumerGone,
    Deadline,
    WorkerLost,
    CleanupUnconfirmed,
    WorkerShutdown(WatchStop),
}
#[derive(Debug, Clone, Serialize)]
pub struct WatchReport {
    pub stream_instance: Option<AgentInstanceId>,
    pub owned_worker_identity: Option<ProcessIdentity>,
    pub fenced: bool,
    pub reason: ParentStop,
    pub child_reaped: bool,
    pub worker_exit_success: Option<bool>,
    pub stdout_eof: bool,
    /// Inline FramedRead loop has ended/dropped; no detached reader task exists.
    pub stdout_joined: bool,
    pub worker_shutdown: Option<WatchShutdown>,
    /// This never becomes true merely because the parent killed/reaped a child.
    pub final_invalidation_delivered: bool,
}
fn report(
    reason: ParentStop,
    reaped: bool,
    status: Option<bool>,
    eof: bool,
    shutdown: Option<WatchShutdown>,
) -> WatchReport {
    WatchReport {
        stream_instance: None,
        owned_worker_identity: None,
        fenced: true,
        reason,
        child_reaped: reaped,
        worker_exit_success: status,
        stdout_eof: eof,
        stdout_joined: true,
        final_invalidation_delivered: shutdown.is_some_and(|s| s.final_invalidation_delivered),
        worker_shutdown: shutdown,
    }
}
/// Fixed worker-only CLI port. The Linux implementation refuses normal Host
/// resource limits; hidden CLI calls prepare_worker_limits before its runtime.
/// Neither this wrapper nor the watcher accepts an alternate UID/socket/path.
pub async fn worker_watch(
    events: mpsc::Sender<WatchEvent>,
    cancel: CancellationToken,
) -> WatchShutdown {
    crate::platform::linux::watch::watch_current_user(events, cancel).await
}
/// Parent-minted stream identity, never supplied in worker wire frames. This
/// type intentionally cannot be deserialized into a trusted observation.
#[derive(Debug, Clone, Serialize)]
pub struct WatchObservation {
    pub stream_instance: AgentInstanceId,
    pub event: WatchEvent,
}
fn new_instance() -> Result<AgentInstanceId, ParentStop> {
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| ParentStop::Entropy)?;
    let mut text = String::from("linux-watch-");
    use std::fmt::Write;
    for byte in entropy {
        write!(&mut text, "{byte:02x}").map_err(|_| ParentStop::Entropy)?;
    }
    AgentInstanceId::try_from(text).map_err(|_| ParentStop::Entropy)
}
/// The caller supplies only a bounded event sink and cancellation. It must
/// invalidate all previously associated desktop facts on this terminal report,
/// on channel/worker EOF, or on a dropped watch waiter. There is no auto-restart.
pub async fn watch_current_user(
    events: mpsc::Sender<WatchObservation>,
    cancel: CancellationToken,
) -> WatchReport {
    let instance = match new_instance() {
        Ok(i) => i,
        Err(reason) => return report(reason, false, None, false, None),
    };
    let fail = |reason| {
        let mut value = report(reason, false, None, false, None);
        value.stream_instance = Some(instance.clone());
        value
    };
    if events.max_capacity() != QUEUE {
        return fail(ParentStop::InvalidFrame);
    }
    if cancel.is_cancelled() {
        return fail(ParentStop::Cancelled);
    }
    let mut image = match PinnedWorker::current() {
        Ok(image) => image,
        Err(_) => return fail(ParentStop::Spawn),
    };
    image.args = vec!["__linux-desktop-watch".into()];
    run(
        image,
        nix::unistd::geteuid().as_raw(),
        events,
        cancel,
        instance,
    )
    .await
}
struct Validator {
    uid: u32,
    next: u64,
    owner: Option<String>,
    previous: BTreeMap<String, LinuxCandidate>,
    invalidated: BTreeSet<CandidateKey>,
}
fn key_valid(key: &CandidateKey, uid: u32) -> bool {
    key.uid == uid
        && !key.session_id.is_empty()
        && field(&key.session_id)
        && key.leader_pid != 0
        && key.leader_birth != 0
        && key.login_timestamp_monotonic != 0
        && matches!(key.backend.as_str(), "wayland" | "x11")
        && key.seat.as_ref().is_none_or(|s| !s.is_empty() && field(s))
}
impl Validator {
    fn new(uid: u32) -> Self {
        Self {
            uid,
            next: 1,
            owner: None,
            previous: BTreeMap::new(),
            invalidated: BTreeSet::new(),
        }
    }
    fn event(&mut self, event: &WatchEvent) -> Result<(), ParentStop> {
        if event.schema != 1 || event.sequence != self.next {
            return Err(ParentStop::InvalidFrame);
        }
        let next = self.next.checked_add(1).ok_or(ParentStop::InvalidFrame)?;
        match &event.change {
            WatchChange::Snapshot {
                login_unique_owner,
                candidates,
            } => {
                if !login_unique_owner.starts_with(':')
                    || !field(login_unique_owner)
                    || zbus::names::UniqueName::try_from(login_unique_owner.as_str()).is_err()
                    || self
                        .owner
                        .as_ref()
                        .is_some_and(|old| old != login_unique_owner)
                    || candidates.len() > 32
                {
                    return Err(ParentStop::InvalidFrame);
                }
                let mut replacement = BTreeMap::new();
                for c in candidates {
                    if !key_valid(&c.into(), self.uid)
                        || c.state.is_empty()
                        || !field(&c.state)
                        || c.agent_association != Association::Unknown
                        || c.compositor_association != Association::Unknown
                        || replacement
                            .insert(c.session_id.clone(), c.clone())
                            .is_some()
                    {
                        return Err(ParentStop::InvalidFrame);
                    }
                }
                // A changed/removed candidate cannot silently replace a
                // previously published instance without its prior invalidation.
                for old in self.previous.values() {
                    if replacement.get(&old.session_id) != Some(old)
                        && !self.invalidated.contains(&old.into())
                    {
                        return Err(ParentStop::InvalidFrame);
                    }
                }
                self.previous = replacement;
                self.owner = Some(login_unique_owner.clone());
                self.invalidated.clear();
            }
            WatchChange::Invalidations { items } => {
                if items.is_empty() || items.len() > 32 {
                    return Err(ParentStop::InvalidFrame);
                }
                let mut keys = BTreeSet::new();
                for item in items {
                    if !key_valid(&item.key, self.uid)
                        || !keys.insert(item.key.clone())
                        || self
                            .previous
                            .get(&item.key.session_id)
                            .is_none_or(|c| CandidateKey::from(c) != item.key)
                    {
                        return Err(ParentStop::InvalidFrame);
                    }
                }
                self.invalidated.extend(keys);
            }
        }
        self.next = next;
        Ok(())
    }
}
async fn run(
    image: PinnedWorker,
    uid: u32,
    events: mpsc::Sender<WatchObservation>,
    cancel: CancellationToken,
    instance: AgentInstanceId,
) -> WatchReport {
    let permit = match WATCH_SLOT.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let mut value = report(ParentStop::Busy, false, None, false, None);
            value.stream_instance = Some(instance);
            return value;
        }
    };
    let dropped = CancellationToken::new();
    let guard = dropped.clone().drop_guard();
    let (tx, rx) = oneshot::channel();
    let waiter_instance = instance.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let _pin = &image;
        let mut reply = Reply {
            tx: Some(tx),
            instance,
            identity: None,
        };
        if dropped.is_cancelled() || cancel.is_cancelled() {
            send(
                &mut reply,
                report(ParentStop::Cancelled, false, None, false, None),
            );
            return;
        }
        let parent = match crate::store::ProcessIdentity::current() {
            Ok(p) => p,
            Err(_) => {
                send(
                    &mut reply,
                    report(ParentStop::Spawn, false, None, false, None),
                );
                return;
            }
        };
        let crate::store::ProcessIdentity::Linux {
            pid, start_ticks, ..
        } = parent;
        let mut command = Command::new(&image.launch);
        command
            .args(&image.args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .env("STYX_INTERNAL_PROBE_PARENT_PID", pid.to_string())
            .env("STYX_INTERNAL_PROBE_PARENT_BIRTH", start_ticks.to_string());
        #[cfg(test)]
        command.envs(&image.environment);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                send(
                    &mut reply,
                    report(ParentStop::Spawn, false, None, false, None),
                );
                return;
            }
        };
        reply.identity = child
            .id()
            .and_then(|pid| ProcessIdentity::observe(pid).ok());
        if reply.identity.is_none() || !matches!(child.try_wait(), Ok(None)) {
            let _ = child.start_kill();
            if let Ok(Ok(status)) = timeout_at(Instant::now() + CLEANUP_TIME, child.wait()).await {
                send(
                    &mut reply,
                    report(
                        ParentStop::WorkerLost,
                        true,
                        Some(status.success()),
                        false,
                        None,
                    ),
                );
            } else {
                send(
                    &mut reply,
                    report(ParentStop::CleanupUnconfirmed, false, None, false, None),
                );
                loop {
                    let _ = child.start_kill();
                    if child.wait().await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            return;
        }
        let mut eof = false;
        let mut shutdown = None;
        let reason = if let Some(stdout) = child.stdout.take() {
            let mut framed = FramedRead::new(stdout, LinesCodec::new_with_max_length(MAX_OUTPUT));
            let mut validator = Validator::new(uid);
            let mut deadline = Instant::now() + IDLE;
            let reason = loop {
                let item = tokio::select! {
                    biased;
                    _=dropped.cancelled()=>break ParentStop::Cancelled,
                    _=cancel.cancelled()=>break ParentStop::Cancelled,
                    item=timeout_at(deadline,framed.next())=>match item {Ok(v)=>v,Err(_)=>break ParentStop::Deadline},
                };
                match item {
                    None => {
                        eof = true;
                        break shutdown
                            .map(|s: WatchShutdown| ParentStop::WorkerShutdown(s.reason))
                            .unwrap_or(ParentStop::WorkerLost);
                    }
                    Some(Err(tokio_util::codec::LinesCodecError::MaxLineLengthExceeded)) => {
                        break ParentStop::OutputTooLarge;
                    }
                    Some(Err(tokio_util::codec::LinesCodecError::Io(error))) => {
                        break if error.kind() == std::io::ErrorKind::InvalidData {
                            ParentStop::InvalidFrame
                        } else {
                            ParentStop::WorkerLost
                        };
                    }
                    Some(Ok(line)) => {
                        if shutdown.is_some() {
                            break ParentStop::InvalidFrame;
                        }
                        let wire = match serde_json::from_str::<Wire>(&line) {
                            Ok(w) => w,
                            Err(_) => break ParentStop::InvalidFrame,
                        };
                        match wire {
                            Wire::Event(event) => {
                                if let Err(reason) = validator.event(&event) {
                                    break reason;
                                }
                                if let Err(error) = events.try_send(WatchObservation {
                                    stream_instance: reply.instance.clone(),
                                    event,
                                }) {
                                    break match error {
                                        mpsc::error::TrySendError::Full(_) => ParentStop::Overflow,
                                        mpsc::error::TrySendError::Closed(_) => {
                                            ParentStop::ConsumerGone
                                        }
                                    };
                                }
                                deadline = Instant::now() + IDLE;
                            }
                            Wire::Shutdown(value) => {
                                if !value.fenced
                                    || value.sdk_tasks_joined
                                    || value.final_invalidation_delivered
                                        && validator
                                            .previous
                                            .values()
                                            .any(|c| !validator.invalidated.contains(&c.into()))
                                {
                                    break ParentStop::InvalidFrame;
                                }
                                shutdown = Some(value);
                                deadline = Instant::now() + END_GRACE;
                            }
                        }
                    }
                }
            };
            drop(framed);
            reason
        } else {
            ParentStop::WorkerLost
        };
        if !eof || shutdown.is_none() {
            let _ = child.start_kill();
        }
        match timeout_at(Instant::now() + CLEANUP_TIME, child.wait()).await {
            Ok(Ok(status)) => send(
                &mut reply,
                report(reason, true, Some(status.success()), eof, shutdown),
            ),
            _ => {
                // Caller budget ends, not physical ownership. This job retains
                // pin, slot and exact Child until the kernel confirms wait.
                send(
                    &mut reply,
                    report(ParentStop::CleanupUnconfirmed, false, None, eof, shutdown),
                );
                loop {
                    let _ = child.start_kill();
                    if child.wait().await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        drop(image);
    });
    let value = rx.await.unwrap_or_else(|_| {
        let mut r = report(ParentStop::CleanupUnconfirmed, false, None, false, None);
        r.stdout_joined = false;
        r.stream_instance = Some(waiter_instance);
        r
    });
    guard.disarm();
    value
}
struct Reply {
    tx: Option<oneshot::Sender<WatchReport>>,
    instance: AgentInstanceId,
    identity: Option<ProcessIdentity>,
}
fn send(reply: &mut Reply, mut value: WatchReport) {
    value.stream_instance = Some(reply.instance.clone());
    value.owned_worker_identity = reply.identity.clone();
    if let Some(tx) = reply.tx.take() {
        let _ = tx.send(value);
    }
}
