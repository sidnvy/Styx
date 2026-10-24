//! Isolated-worker logind watch. Signals invalidate; they never authorize a
//! Desktop, compositor, Agent, or provider. The parent must fence all bindings
//! on worker EOF/termination, including when the final event cannot be queued.
//!
//! Official zbus 5.14 MessageStream::for_match_rule owns bus subscription setup;
//! max_queued bounds messages, not SDK allocation. Run only in the existing
//! same-image memory-limited worker, never in the Host address space.
//! https://docs.rs/zbus/5.14.0/zbus/struct.MessageStream.html
use super::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock},
};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use zbus::{MatchRule, Message, MessageStream, message::Type};
const QUEUE: usize = 8;
const RECONCILE: Duration = Duration::from_secs(30);
const DEBOUNCE: Duration = Duration::from_millis(100);
const WORK: Duration = Duration::from_millis(1800);
const CLOSE: Duration = Duration::from_millis(200);
static SLOT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

/// Full known login instance, not a Desktop binding. Backend/seat are not
/// evidence for a compositor association, and PID alone is never this key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateKey {
    pub session_id: String,
    pub uid: u32,
    pub seat: Option<String>,
    pub backend: String,
    pub leader_pid: u32,
    pub leader_birth: u64,
    pub login_timestamp_monotonic: u64,
}
impl From<&LinuxCandidate> for CandidateKey {
    fn from(c: &LinuxCandidate) -> Self {
        Self {
            session_id: c.session_id.clone(),
            uid: c.uid,
            seat: c.seat.clone(),
            backend: c.backend.clone(),
            leader_pid: c.leader_pid,
            leader_birth: c.leader_birth,
            login_timestamp_monotonic: c.login_timestamp_monotonic,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    Removed,
    IdentityChanged,
    PropertiesChanged,
    LockBoundary,
    TopologyChanged,
    SourceLost,
    LoginOwnerChanged,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invalidation {
    pub key: CandidateKey,
    pub reason: InvalidationReason,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatchChange {
    /// These candidates retain Unknown compositor/Agent association. A live
    /// watch socket is not reported as a closed discovery connection.
    Snapshot {
        login_unique_owner: String,
        candidates: Vec<LinuxCandidate>,
    },
    Invalidations {
        items: Vec<Invalidation>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchEvent {
    pub schema: u16,
    pub sequence: u64,
    pub change: WatchChange,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchStop {
    Cancelled,
    Overflow,
    ConsumerGone,
    SequenceExhausted,
    NotIsolated,
    Busy,
    SourceChanged,
    SourceEnded,
    Discovery(DiscoveryError),
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchShutdown {
    pub fenced: bool,
    pub reason: WatchStop,
    pub final_invalidation_delivered: bool,
    pub connection_closed: bool,
    /// Connection::close is not evidence for joining the SDK's internal tasks.
    pub sdk_tasks_joined: bool,
}
struct State {
    owner: String,
    previous: Vec<LinuxCandidate>,
    sequence: u64,
}
impl State {
    fn send(
        &mut self,
        events: &mpsc::Sender<WatchEvent>,
        change: WatchChange,
    ) -> Result<(), WatchStop> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(WatchStop::SequenceExhausted)?;
        let event = WatchEvent {
            schema: 1,
            sequence: self.sequence,
            change,
        };
        // Bound the serialized protocol before sending, without allocating a
        // second whole frame. The SDK's incoming frame boundary is isolated.
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(b.len())
                    .filter(|n| *n <= MAX_FACTS)
                    .ok_or_else(|| std::io::Error::other("watch frame budget"))?;
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(&mut Count(0), &event)
            .map_err(|_| WatchStop::Discovery(DiscoveryError::Capacity))?;
        events.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => WatchStop::Overflow,
            mpsc::error::TrySendError::Closed(_) => WatchStop::ConsumerGone,
        })
    }
    fn invalidate(
        &mut self,
        events: &mpsc::Sender<WatchEvent>,
        reason: InvalidationReason,
    ) -> Result<(), WatchStop> {
        if self.previous.is_empty() {
            return Ok(());
        }
        self.send(
            events,
            WatchChange::Invalidations {
                items: self
                    .previous
                    .iter()
                    .map(|c| Invalidation {
                        key: c.into(),
                        reason,
                    })
                    .collect(),
            },
        )
    }
    fn reconcile(
        &mut self,
        events: &mpsc::Sender<WatchEvent>,
        snapshot: LinuxDiscoverySnapshot,
        uid: u32,
    ) -> Result<(), WatchStop> {
        validate_snapshot(&snapshot, uid)?;
        if snapshot.login_unique_owner != self.owner {
            return Err(WatchStop::SourceChanged);
        }
        let invalidations = changes(&self.previous, &snapshot.candidates);
        if !invalidations.is_empty() {
            self.send(
                events,
                WatchChange::Invalidations {
                    items: invalidations,
                },
            )?;
        }
        self.send(
            events,
            WatchChange::Snapshot {
                login_unique_owner: self.owner.clone(),
                candidates: snapshot.candidates.clone(),
            },
        )?;
        self.previous = snapshot.candidates;
        Ok(())
    }
}
fn validate_snapshot(snapshot: &LinuxDiscoverySnapshot, uid: u32) -> Result<(), WatchStop> {
    if snapshot.schema != 1
        || snapshot.candidates.len() > MAX_SESSIONS
        || snapshot.login_unique_owner.len() > MAX_FIELD
    {
        return Err(WatchStop::Discovery(DiscoveryError::InvalidFacts));
    }
    let mut ids = BTreeSet::new();
    for c in &snapshot.candidates {
        if c.uid != uid
            || c.leader_pid == 0
            || c.leader_birth == 0
            || !ids.insert(&c.session_id)
            || c.compositor_association != Association::Unknown
            || c.agent_association != Association::Unknown
            || !matches!(c.backend.as_str(), "wayland" | "x11")
        {
            return Err(WatchStop::Discovery(DiscoveryError::InvalidFacts));
        }
        for s in [&c.session_id, &c.backend, &c.state] {
            bounded(s).map_err(WatchStop::Discovery)?;
        }
        if let Some(seat) = &c.seat {
            bounded(seat).map_err(WatchStop::Discovery)?;
        }
    }
    Ok(())
}
fn changes(previous: &[LinuxCandidate], next: &[LinuxCandidate]) -> Vec<Invalidation> {
    let by_id: BTreeMap<_, _> = next.iter().map(|c| (&c.session_id, c)).collect();
    previous
        .iter()
        .filter_map(|old| {
            let reason = match by_id.get(&old.session_id) {
                None => InvalidationReason::Removed,
                Some(new) if CandidateKey::from(old) != CandidateKey::from(*new) => {
                    InvalidationReason::IdentityChanged
                }
                Some(new) if old.locked_hint != new.locked_hint => InvalidationReason::LockBoundary,
                Some(new) if old != *new => InvalidationReason::PropertiesChanged,
                _ => return None,
            };
            Some(Invalidation {
                key: old.into(),
                reason,
            })
        })
        .collect()
}
fn signal_reason(message: &Message, owner: &str) -> Result<Option<InvalidationReason>, WatchStop> {
    if message.data().len() > MAX_FACTS {
        return Err(WatchStop::Discovery(DiscoveryError::Capacity));
    }
    let header = message.header();
    if header.sender().map(|s| s.as_str()) != Some(owner) || header.message_type() != Type::Signal {
        return Ok(None);
    }
    let interface = header.interface().map(|s| s.as_str());
    let member = header.member().map(|s| s.as_str());
    let path = header.path().map(|s| s.as_str());
    if interface == Some("org.freedesktop.login1.Manager")
        && path == Some("/org/freedesktop/login1")
        && matches!(member, Some("SessionNew" | "SessionRemoved"))
    {
        let (id, path): (String, OwnedObjectPath) = message
            .body()
            .deserialize()
            .map_err(|_| WatchStop::Discovery(DiscoveryError::InvalidFacts))?;
        bounded(&id).map_err(WatchStop::Discovery)?;
        bounded(path.as_str()).map_err(WatchStop::Discovery)?;
        // This is a topology hint. Only the subsequent stable snapshot can
        // say which exact known instance disappeared; never label all sessions
        // Removed because one root-owned Manager signal was observed.
        return Ok(Some(InvalidationReason::TopologyChanged));
    }
    if !path.is_some_and(|p| p.starts_with("/org/freedesktop/login1/session/")) {
        return Ok(None);
    }
    if interface == Some(SESSION_INTERFACE) && matches!(member, Some("Lock" | "Unlock")) {
        return Ok(Some(InvalidationReason::LockBoundary));
    }
    if interface == Some("org.freedesktop.DBus.Properties") && member == Some("PropertiesChanged") {
        let (name, changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
            message
                .body()
                .deserialize()
                .map_err(|_| WatchStop::Discovery(DiscoveryError::InvalidFacts))?;
        if name != SESSION_INTERFACE {
            return Ok(None);
        }
        if changed.len() > 32 || invalidated.len() > 32 {
            return Err(WatchStop::Discovery(DiscoveryError::Capacity));
        }
        for key in changed.keys().chain(invalidated.iter()) {
            bounded(key).map_err(WatchStop::Discovery)?;
        }
        return Ok(Some(
            if changed.contains_key("LockedHint") || invalidated.iter().any(|p| p == "LockedHint") {
                InvalidationReason::LockBoundary
            } else {
                InvalidationReason::PropertiesChanged
            },
        ));
    }
    Ok(None)
}
fn owner_changed(message: &Message, current: &str) -> Result<bool, WatchStop> {
    if message.data().len() > MAX_FACTS {
        return Err(WatchStop::Discovery(DiscoveryError::Capacity));
    }
    let h = message.header();
    if h.message_type() != Type::Signal
        || h.path().map(|p| p.as_str()) != Some("/org/freedesktop/DBus")
        || h.sender().map(|s| s.as_str()) != Some("org.freedesktop.DBus")
        || h.interface().map(|s| s.as_str()) != Some("org.freedesktop.DBus")
        || h.member().map(|s| s.as_str()) != Some("NameOwnerChanged")
    {
        return Ok(false);
    }
    let (name, old, new): (String, String, String) = message
        .body()
        .deserialize()
        .map_err(|_| WatchStop::Discovery(DiscoveryError::InvalidFacts))?;
    for field in [&name, &old, &new] {
        bounded(field).map_err(WatchStop::Discovery)?;
    }
    Ok(name == LOGIN && (old != current || new != current))
}
fn isolated() -> bool {
    use nix::sys::resource::{Resource, getrlimit};
    matches!((getrlimit(Resource::RLIMIT_AS),getrlimit(Resource::RLIMIT_DATA)),(Ok((_,as_hard)),Ok((_,data_hard))) if as_hard<=512*1024*1024&&data_hard<=96*1024*1024)
}
/// Worker-only entry. No supplied UID, bus address, session selector or provider
/// authority. Queue is exactly eight bounded <=64KiB events. Any terminal return
/// or worker EOF is a source fence; the Host must invalidate its old bindings.
/// Cancellation drops subscriptions, awaits official close and retains the
/// physical SocketFence. It does not claim to join internal SDK tasks.
pub(crate) async fn watch_current_user(
    events: mpsc::Sender<WatchEvent>,
    cancel: CancellationToken,
) -> WatchShutdown {
    let stop = |reason, delivered, closed| WatchShutdown {
        fenced: true,
        reason,
        final_invalidation_delivered: delivered,
        connection_closed: closed,
        sdk_tasks_joined: false,
    };
    if cancel.is_cancelled() {
        return stop(WatchStop::Cancelled, true, false);
    }
    if events.max_capacity() != QUEUE || !isolated() {
        return stop(WatchStop::NotIsolated, false, false);
    }
    let Ok(_slot) = SLOT.clone().try_acquire_owned() else {
        return stop(WatchStop::Busy, false, false);
    };
    let uid = nix::unistd::geteuid().as_raw();
    let end = Instant::now() + Duration::from_secs(2);
    let stream = match timeout_at(end, UnixStream::connect(SYSTEM_BUS)).await {
        Ok(Ok(s)) => s,
        _ => {
            return stop(
                WatchStop::Discovery(DiscoveryError::Unavailable),
                false,
                false,
            );
        }
    };
    if stream.peer_cred().map(|c| c.uid()).ok() != Some(0) {
        return stop(
            WatchStop::Discovery(DiscoveryError::UntrustedPeer),
            false,
            false,
        );
    }
    let stream = match stream.into_std() {
        Ok(s) => s,
        Err(_) => {
            return stop(
                WatchStop::Discovery(DiscoveryError::Unavailable),
                false,
                false,
            );
        }
    };
    let fence = match stream.try_clone() {
        Ok(s) => SocketFence(s),
        Err(_) => {
            return stop(
                WatchStop::Discovery(DiscoveryError::Unavailable),
                false,
                false,
            );
        }
    };
    let connection = match timeout_at(end, async {
        let stream = UnixStream::from_std(stream).map_err(|_| DiscoveryError::Unavailable)?;
        zbus::connection::Builder::unix_stream(stream)
            .max_queued(4)
            .method_timeout(WORK)
            .build()
            .await
            .map_err(|_| DiscoveryError::Unavailable)
    })
    .await
    {
        Ok(Ok(c)) => c,
        _ => {
            return stop(
                WatchStop::Discovery(DiscoveryError::Unavailable),
                false,
                false,
            );
        }
    };
    let mut state = State {
        owner: String::new(),
        previous: vec![],
        sequence: 0,
    };
    let setup = async {
        // Subscribe to driver ownership changes before resolving login1. A new
        // owner requires a fresh worker/authority observation, never auto-adopt.
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")
            .map_err(|_| WatchStop::SourceEnded)?
            .interface("org.freedesktop.DBus")
            .map_err(|_| WatchStop::SourceEnded)?
            .member("NameOwnerChanged")
            .map_err(|_| WatchStop::SourceEnded)?
            .path("/org/freedesktop/DBus")
            .map_err(|_| WatchStop::SourceEnded)?
            .arg(0, LOGIN)
            .map_err(|_| WatchStop::SourceEnded)?
            .build();
        let ownership = MessageStream::for_match_rule(rule, &connection, Some(4))
            .await
            .map_err(|_| WatchStop::SourceEnded)?;
        let bus = DBusProxy::new(&connection)
            .await
            .map_err(|_| WatchStop::SourceEnded)?;
        let owner = bus
            .get_name_owner(LOGIN.try_into().map_err(|_| WatchStop::SourceEnded)?)
            .await
            .map_err(|_| WatchStop::SourceEnded)?;
        let user = bus
            .get_connection_unix_user(owner.as_ref().into())
            .await
            .map_err(|_| WatchStop::SourceEnded)?;
        stable_owner(owner.as_str(), owner.as_str(), user).map_err(WatchStop::Discovery)?;
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(owner.as_str())
            .map_err(|_| WatchStop::SourceEnded)?
            .path_namespace("/org/freedesktop/login1")
            .map_err(|_| WatchStop::SourceEnded)?
            .build();
        let signals = MessageStream::for_match_rule(rule, &connection, Some(4))
            .await
            .map_err(|_| WatchStop::SourceEnded)?;
        Ok::<_, WatchStop>((ownership, signals, owner.to_string()))
    };
    let setup = tokio::select! {
        _=cancel.cancelled()=>Err(WatchStop::Cancelled),
        result=timeout_at(end,setup)=>result.unwrap_or(Err(WatchStop::Discovery(DiscoveryError::Deadline))),
    };
    let (mut ownership, mut signals, owner) = match setup {
        Ok(value) => value,
        Err(reason) => {
            let closed = matches!(
                timeout_at(Instant::now() + CLOSE, connection.close()).await,
                Ok(Ok(()))
            );
            drop(fence);
            return stop(reason, true, closed);
        }
    };
    state.owner = owner;
    let work = async {
        let mut due = Instant::now();
        loop {
            tokio::select! {
                biased;
                _=cancel.cancelled()=>return Err(WatchStop::Cancelled),
                notice=ownership.next()=>match notice {
                    Some(Ok(message))=>if owner_changed(&message,&state.owner)?{return Err(WatchStop::SourceChanged);},
                    _=>return Err(WatchStop::SourceEnded),
                },
                notice=signals.next()=>match notice {
                    Some(Ok(message))=>if let Some(reason)=signal_reason(&message,&state.owner)? {
                        state.invalidate(&events,reason)?;due=Instant::now()+DEBOUNCE;
                    },
                    _=>return Err(WatchStop::SourceEnded),
                },
                result=async {tokio::time::sleep_until(due).await;before_deadline(Instant::now()+WORK,collect(&connection,uid)).await}=>{
                    state.reconcile(&events,result.map_err(WatchStop::Discovery)?,uid)?;
                    due=Instant::now()+RECONCILE;
                }
            }
        }
    };
    // Setup (bus auth/subscription/owner proof) is bounded too. The ongoing loop
    // has per-reconcile deadlines and cancellation, not a fixed total lifetime.
    let reason = match work.await {
        Err(reason) => reason,
        Ok(()) => WatchStop::SourceEnded,
    };
    drop(ownership);
    drop(signals);
    let why = match reason {
        WatchStop::Cancelled => InvalidationReason::Cancelled,
        WatchStop::SourceChanged | WatchStop::Discovery(DiscoveryError::OwnerChanged) => {
            InvalidationReason::LoginOwnerChanged
        }
        _ => InvalidationReason::SourceLost,
    };
    let delivered = state.invalidate(&events, why).is_ok();
    let closed = matches!(
        timeout_at(Instant::now() + CLOSE, connection.close()).await,
        Ok(Ok(()))
    );
    drop(fence);
    stop(reason, delivered, closed)
}
#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;
