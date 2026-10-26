//! Linux adapters: read-only login candidates and explicit user-manager actions.
//! This first slice has no watcher, agent authentication, attachment or input API.
//! The owned session_probe worker isolates SDK allocations; MAX_FACTS only
//! bounds retained/serialized facts, not upstream DBus frame allocation.
pub(crate) mod association;
pub mod manager;
#[cfg(target_env = "gnu")]
pub(crate) use manager::persistent as native_service;

use futures_util::{StreamExt, TryStreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
    net::Shutdown,
    time::Duration,
};
use tokio::{
    net::UnixStream,
    time::{Instant, timeout_at},
};
use zbus::{
    Connection,
    fdo::{DBusProxy, PropertiesProxy},
    zvariant::{OwnedObjectPath, OwnedValue},
};

const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";
const LOGIN: &str = "org.freedesktop.login1";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const MAX_SESSIONS: usize = 32;
const MAX_FIELD: usize = 256;
const MAX_FACTS: usize = 64 * 1024;
type ListedSession = (String, u32, String, String, OwnedObjectPath);

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_path = "/org/freedesktop/login1"
)]
trait LoginManager {
    fn list_sessions(&self) -> zbus::Result<Vec<ListedSession>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryError {
    #[error("discovery_deadline")]
    Deadline,
    #[error("system_bus_unavailable")]
    Unavailable,
    #[error("untrusted_system_bus_peer")]
    UntrustedPeer,
    #[error("login_owner_changed")]
    OwnerChanged,
    #[error("session_changed_during_snapshot")]
    SessionChanged,
    #[error("invalid_login_facts")]
    InvalidFacts,
    #[error("discovery_capacity")]
    Capacity,
    #[error("system_bus_close_unconfirmed")]
    CloseUnconfirmed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Association {
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCandidate {
    pub session_id: String,
    pub uid: u32,
    pub seat: Option<String>,
    pub leader_pid: u32,
    pub leader_birth: u64,
    pub login_timestamp_monotonic: u64,
    pub backend: String,
    pub active: bool,
    pub state: String,
    pub locked_hint: bool,
    pub compositor_association: Association,
    pub agent_association: Association,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxDiscoverySnapshot {
    pub schema: u16,
    pub login_unique_owner: String,
    pub candidates: Vec<LinuxCandidate>,
    /// Official socket close was awaited. This does not attest SDK task joins.
    pub connection_closed: bool,
}

// A duplicate socket handle makes cancellation during authentication/close shut
// the physical socket. No detached Styx task or child process is spawned.
struct SocketFence(std::os::unix::net::UnixStream);
impl Drop for SocketFence {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
fn bounded(s: &str) -> Result<(), DiscoveryError> {
    if s.len() > MAX_FIELD {
        Err(DiscoveryError::Capacity)
    } else if s.contains(['\0', '\r', '\n']) {
        Err(DiscoveryError::InvalidFacts)
    } else {
        Ok(())
    }
}
fn checked_list(list: &[ListedSession]) -> Result<BTreeSet<(String, u32, String)>, DiscoveryError> {
    if list.len() > MAX_SESSIONS {
        return Err(DiscoveryError::Capacity);
    }
    let mut set = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for (id, uid, username, seat, path) in list {
        for s in [id.as_str(), username.as_str(), seat.as_str(), path.as_str()] {
            bounded(s)?;
        }
        if id.is_empty() || !ids.insert(id.clone()) {
            return Err(DiscoveryError::InvalidFacts);
        }
        set.insert((id.clone(), *uid, path.as_str().to_owned()));
    }
    Ok(set)
}
fn take<T: TryFrom<OwnedValue>>(
    map: &mut HashMap<String, OwnedValue>,
    key: &str,
) -> Result<T, DiscoveryError> {
    map.remove(key)
        .ok_or(DiscoveryError::InvalidFacts)?
        .try_into()
        .map_err(|_| DiscoveryError::InvalidFacts)
}
fn birth(pid: u32) -> Result<u64, DiscoveryError> {
    let mut text = String::new();
    std::fs::File::open(format!("/proc/{pid}/stat"))
        .map_err(|_| DiscoveryError::SessionChanged)?
        .take(8193)
        .read_to_string(&mut text)
        .map_err(|_| DiscoveryError::SessionChanged)?;
    if text.len() > 8192 {
        return Err(DiscoveryError::Capacity);
    }
    text.rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|x| x.parse().ok())
        .ok_or(DiscoveryError::SessionChanged)
}
// Internal complete sample: equality covers fields used to filter candidates too.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionFacts {
    id: String,
    user: u32,
    user_path: OwnedObjectPath,
    seat: String,
    seat_path: OwnedObjectPath,
    backend: String,
    class: String,
    state: String,
    remote: bool,
    leader_pid: u32,
    leader_birth: Option<u64>,
    timestamp: u64,
    active: bool,
    locked: bool,
}
fn decode_facts(
    row: &ListedSession,
    mut p: HashMap<String, OwnedValue>,
) -> Result<SessionFacts, DiscoveryError> {
    let id: String = take(&mut p, "Id")?;
    let (user, user_path): (u32, OwnedObjectPath) = take(&mut p, "User")?;
    let (seat, seat_path): (String, OwnedObjectPath) = take(&mut p, "Seat")?;
    let backend: String = take(&mut p, "Type")?;
    let class: String = take(&mut p, "Class")?;
    let state: String = take(&mut p, "State")?;
    bounded(user_path.as_str())?;
    bounded(seat_path.as_str())?;
    for s in [&id, &seat, &backend, &class, &state] {
        bounded(s)?;
    }
    if id != row.0 || user != row.1 || seat != row.3 {
        return Err(DiscoveryError::SessionChanged);
    }
    let leader_pid: u32 = take(&mut p, "Leader")?;
    let remote: bool = take(&mut p, "Remote")?;
    let graphical = !remote && class == "user" && matches!(backend.as_str(), "wayland" | "x11");
    let leader_birth = if graphical {
        if leader_pid == 0 {
            return Err(DiscoveryError::InvalidFacts);
        }
        Some(birth(leader_pid)?)
    } else {
        // Remote/manager rows confer no candidate; an already-ended unrelated
        // SSH leader must not block discovery of the graphical session.
        None
    };
    Ok(SessionFacts {
        id,
        user,
        user_path,
        seat,
        seat_path,
        backend,
        class,
        state,
        remote,
        leader_pid,
        leader_birth,
        timestamp: take(&mut p, "TimestampMonotonic")?,
        active: take(&mut p, "Active")?,
        locked: take(&mut p, "LockedHint")?,
    })
}
fn candidate(facts: &SessionFacts, uid: u32) -> Option<LinuxCandidate> {
    if facts.user != uid
        || facts.remote
        || facts.class != "user"
        || !matches!(facts.backend.as_str(), "wayland" | "x11")
    {
        return None;
    }
    Some(LinuxCandidate {
        session_id: facts.id.clone(),
        uid: facts.user,
        seat: if facts.seat.is_empty() {
            None
        } else {
            Some(facts.seat.clone())
        },
        leader_pid: facts.leader_pid,
        leader_birth: facts.leader_birth?,
        login_timestamp_monotonic: facts.timestamp,
        backend: facts.backend.clone(),
        active: facts.active,
        state: facts.state.clone(),
        locked_hint: facts.locked,
        compositor_association: Association::Unknown,
        agent_association: Association::Unknown,
    })
}
fn stable_facts(first: &SessionFacts, second: &SessionFacts) -> Result<(), DiscoveryError> {
    if first == second {
        Ok(())
    } else {
        Err(DiscoveryError::SessionChanged)
    }
}
async fn sample(
    connection: &Connection,
    owner: &str,
    row: &ListedSession,
) -> Result<SessionFacts, DiscoveryError> {
    let properties = PropertiesProxy::builder(connection)
        .destination(owner)
        .map_err(|_| DiscoveryError::InvalidFacts)?
        .path(row.4.as_str())
        .map_err(|_| DiscoveryError::InvalidFacts)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    let mut facts = HashMap::with_capacity(11);
    // Official Properties.Get requests only needed fields. This deliberately
    // never requests GetAll (which can include unrelated large properties).
    for key in [
        "Id",
        "User",
        "Seat",
        "Type",
        "Class",
        "State",
        "Remote",
        "Leader",
        "TimestampMonotonic",
        "Active",
        "LockedHint",
    ] {
        let value = properties
            .get(
                SESSION_INTERFACE
                    .try_into()
                    .map_err(|_| DiscoveryError::InvalidFacts)?,
                key,
            )
            .await
            .map_err(|_| DiscoveryError::SessionChanged)?;
        facts.insert(key.to_owned(), value);
    }
    decode_facts(row, facts)
}
fn stable_owner(before: &str, after: &str, user: u32) -> Result<(), DiscoveryError> {
    if user != 0 {
        Err(DiscoveryError::UntrustedPeer)
    } else if before != after {
        Err(DiscoveryError::OwnerChanged)
    } else {
        bounded(before)
    }
}
async fn before_deadline<T>(
    deadline: Instant,
    work: impl std::future::Future<Output = Result<T, DiscoveryError>>,
) -> Result<T, DiscoveryError> {
    timeout_at(deadline, work)
        .await
        .map_err(|_| DiscoveryError::Deadline)?
}
async fn collect(
    connection: &Connection,
    uid: u32,
) -> Result<LinuxDiscoverySnapshot, DiscoveryError> {
    let bus = DBusProxy::new(connection)
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    let name = LOGIN.try_into().map_err(|_| DiscoveryError::InvalidFacts)?;
    let owner = bus
        .get_name_owner(name)
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    let owner_user = bus
        .get_connection_unix_user(owner.as_ref().into())
        .await
        .map_err(|_| DiscoveryError::UntrustedPeer)?;
    stable_owner(owner.as_str(), owner.as_str(), owner_user)?;
    let manager = LoginManagerProxy::builder(connection)
        .destination(owner.as_str())
        .map_err(|_| DiscoveryError::InvalidFacts)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    let rows = manager
        .list_sessions()
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    let listed = checked_list(&rows)?;
    let relevant: Vec<_> = rows.iter().filter(|r| r.1 == uid).collect();
    let first: Vec<SessionFacts> = stream::iter(
        relevant
            .iter()
            .map(|row| sample(connection, owner.as_str(), row)),
    )
    .buffered(4)
    .try_collect()
    .await?;
    let again = manager
        .list_sessions()
        .await
        .map_err(|_| DiscoveryError::Unavailable)?;
    if listed != checked_list(&again)? {
        return Err(DiscoveryError::SessionChanged);
    }
    let second: Vec<SessionFacts> = stream::iter(
        relevant
            .iter()
            .map(|row| sample(connection, owner.as_str(), row)),
    )
    .buffered(4)
    .try_collect()
    .await?;
    for (before, after) in first.iter().zip(&second) {
        stable_facts(before, after)?;
    }
    let after = bus
        .get_name_owner(LOGIN.try_into().map_err(|_| DiscoveryError::InvalidFacts)?)
        .await
        .map_err(|_| DiscoveryError::OwnerChanged)?;
    let after_user = bus
        .get_connection_unix_user(after.as_ref().into())
        .await
        .map_err(|_| DiscoveryError::UntrustedPeer)?;
    stable_owner(owner.as_str(), after.as_str(), after_user)?;
    let mut result = LinuxDiscoverySnapshot {
        schema: 1,
        login_unique_owner: owner.to_string(),
        candidates: second
            .iter()
            .filter_map(|facts| candidate(facts, uid))
            .collect(),
        connection_closed: false,
    };
    result
        .candidates
        .sort_by(|a, b| a.session_id.cmp(&b.session_id));
    for c in &result.candidates {
        if birth(c.leader_pid)? != c.leader_birth {
            return Err(DiscoveryError::SessionChanged);
        }
    }
    if serde_json::to_vec(&result)
        .map_err(|_| DiscoveryError::InvalidFacts)?
        .len()
        > MAX_FACTS
    {
        return Err(DiscoveryError::Capacity);
    }
    Ok(result)
}

/// Fixed root-owned system bus only. Caller environment and arbitrary sockets
/// cannot select the authority. Candidate availability confers no desktop grant.
pub async fn discover_candidates(uid: u32) -> Result<LinuxDiscoverySnapshot, DiscoveryError> {
    let end = Instant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_millis(200);
    let stream = timeout_at(work_end, UnixStream::connect(SYSTEM_BUS))
        .await
        .map_err(|_| DiscoveryError::Deadline)?
        .map_err(|_| DiscoveryError::Unavailable)?;
    if stream
        .peer_cred()
        .map_err(|_| DiscoveryError::UntrustedPeer)?
        .uid()
        != 0
    {
        return Err(DiscoveryError::UntrustedPeer);
    }
    let stream = stream.into_std().map_err(|_| DiscoveryError::Unavailable)?;
    let _fence = SocketFence(
        stream
            .try_clone()
            .map_err(|_| DiscoveryError::Unavailable)?,
    );
    let connection = timeout_at(
        work_end,
        zbus::connection::Builder::unix_stream(
            UnixStream::from_std(stream).map_err(|_| DiscoveryError::Unavailable)?,
        )
        .max_queued(4)
        .method_timeout(Duration::from_millis(1800))
        .build(),
    )
    .await
    .map_err(|_| DiscoveryError::Deadline)?
    .map_err(|_| DiscoveryError::Unavailable)?;
    let result = before_deadline(work_end, collect(&connection, uid)).await;
    let closed = timeout_at(end, connection.close()).await;
    if !matches!(closed, Ok(Ok(()))) {
        return Err(DiscoveryError::CloseUnconfirmed);
    }
    result.map(|mut facts| {
        facts.connection_closed = true;
        facts
    })
}

#[cfg(test)]
mod tests;

pub(crate) mod watch;
