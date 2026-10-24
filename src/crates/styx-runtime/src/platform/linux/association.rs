//! Exact Arch/UWSM association, not Desktop readiness or a Gateway grant.
//!
//! `collect_uwsm` runs ONLY inside the existing same-image bounded probe child:
//! official zbus can allocate a frame before our retained-fact limits. The
//! parent consumes facts only after that ORIGINAL owned collector's bounded
//! output, successful wait and source/budget checks. Deserialization alone is
//! never authorization. No environment, arbitrary bus address, old Cua process
//! or a same-UID/unique-candidate shortcut establishes this association.
use super::{LinuxCandidate, LoginManagerProxy, PropertiesProxy, SYSTEM_BUS};
use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::Mode,
    unistd::Uid,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    net::Shutdown,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use styx_contracts::{
    identity::{AgentInstanceId, SessionId, Sha256Digest},
    session::SessionIdentity,
};
use styx_core::session::RegistrationFacts;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Instant, timeout_at},
};
use zbus::{
    Connection,
    fdo::DBusProxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const MANAGER: &str = "org.freedesktop.systemd1";
const LOGIN: &str = "org.freedesktop.login1";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const MAX_ROWS: usize = 32;
const MAX_FIELD: usize = 256;
// Leave room for the schema/facts envelope and final newline in the64KiB pipe.
const MAX_FACTS: usize = 64 * 1024 - 64;
const MAX_PROC: usize = 8192;
// systemd Manager.ListUnitsByPatterns: a(ssssssouso), including Following.
type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);
type Result<T> = std::result::Result<T, AssociationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AssociationError {
    #[error("desktop association unavailable")]
    Unavailable,
    #[error("desktop association deadline")]
    Deadline,
    #[error("desktop association ambiguous")]
    Ambiguous,
    #[error("desktop association changed")]
    Changed,
    #[error("desktop association untrusted source")]
    Untrusted,
    #[error("desktop association unsupported launch form")]
    Unsupported,
    #[error("desktop association capacity")]
    Capacity,
    #[error("desktop association locked or inactive")]
    Inactive,
    #[error("desktop association source close unconfirmed")]
    CloseUnconfirmed,
}
impl AssociationError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "desktop_association_unavailable",
            Self::Deadline => "desktop_association_deadline",
            Self::Ambiguous => "desktop_association_ambiguous",
            Self::Changed => "desktop_association_changed",
            Self::Untrusted => "desktop_association_untrusted_source",
            Self::Unsupported => "desktop_association_unsupported_launch_form",
            Self::Capacity => "desktop_association_capacity",
            Self::Inactive => "desktop_association_locked_or_inactive",
            Self::CloseUnconfirmed => "desktop_association_close_unconfirmed",
        }
    }
}
#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_path = "/org/freedesktop/login1"
)]
trait AssociationLogin {
    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<OwnedObjectPath>;
}
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_path = "/org/freedesktop/systemd1"
)]
trait AssociationManager {
    fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> zbus::Result<Vec<UnitRow>>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessFact {
    pid: u32,
    birth: u64,
    uid: u32,
    proc_device: u64,
    proc_inode: u64,
    cgroup: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitFact {
    name: String,
    path: OwnedObjectPath,
    invocation: Vec<u8>,
    cgroup: String,
    main_pid: Option<u32>,
    binds: Vec<String>,
    wants: Vec<String>,
    on_success: Vec<String>,
    on_failure: Vec<String>,
    conflicts: Vec<String>,
    restart: Option<String>,
    service_type: Option<String>,
    // Service.ExecStart: a(sasbttttuii), four real/monotonic start/end timestamps.
    bind_start: Option<Vec<(String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32)>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointFact {
    path: PathBuf,
    device: u64,
    inode: u64,
    peer: ProcessFact,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFact {
    path: PathBuf,
    device: u64,
    inode: u64,
    digest: Sha256Digest,
}
/// Concrete OS observations only. Fields intentionally private; root's dedicated
/// worker-completion port owns decoding. Never accept this from management/MCP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssociationFacts {
    schema: u16,
    boot: String,
    uid: u32,
    candidate: LinuxCandidate,
    login_owner: String,
    manager_owner: String,
    manager_process: ProcessFact,
    leader: ProcessFact,
    anchor: ProcessFact,
    anchor_argv: Vec<String>,
    bind: UnitFact,
    envelope: UnitFact,
    wm: UnitFact,
    wm_env: UnitFact,
    bind_process: ProcessFact,
    wm_main: ProcessFact,
    wayland: EndpointFact,
    hyprland: EndpointFact,
    hyprland_events: EndpointFact,
    window_read: WindowReadEvidence,
    sources: Vec<SourceFact>,
}
impl AssociationFacts {
    // A fresh collector may observe different window contents without changing
    // the original session authority. All source/lifecycle identities stay exact.
    fn same_source(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.boot == other.boot
            && self.uid == other.uid
            && self.candidate == other.candidate
            && self.login_owner == other.login_owner
            && self.manager_owner == other.manager_owner
            && self.manager_process == other.manager_process
            && self.leader == other.leader
            && self.anchor == other.anchor
            && self.anchor_argv == other.anchor_argv
            && self.bind == other.bind
            && self.envelope == other.envelope
            && self.wm == other.wm
            && self.wm_env == other.wm_env
            && self.bind_process == other.bind_process
            && self.wm_main == other.wm_main
            && self.wayland == other.wayland
            && self.hyprland == other.hyprland
            && self.hyprland_events == other.hyprland_events
            && self.sources == other.sources
    }
}
const MONITORS_REPLY: usize = 64 * 1024;
const CLIENTS_REPLY: usize = 256 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WindowQuery {
    Monitors,
    Clients,
}
impl WindowQuery {
    fn command(self) -> &'static [u8] {
        match self {
            Self::Monitors => b"j/monitors",
            Self::Clients => b"j/clients",
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Monitors => MONITORS_REPLY,
            Self::Clients => CLIENTS_REPLY,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryReadEvidence {
    query: WindowQuery,
    object_count: usize,
    raw_bytes: usize,
    raw_sha256: Sha256Digest,
}
/// Only successful, typed, EOF-complete reads from the attested compositor
/// construct this evidence. No titles/classes/window content are retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowReadEvidence {
    schema: u16,
    peer: ProcessFact,
    socket_device: u64,
    socket_inode: u64,
    monitors: QueryReadEvidence,
    clients: QueryReadEvidence,
}
impl WindowReadEvidence {
    pub(crate) fn source_peer(&self) -> (u32, u64) {
        (self.peer.pid, self.peer.birth)
    }
    pub(crate) fn socket_identity(&self) -> (u64, u64) {
        (self.socket_device, self.socket_inode)
    }
    pub(crate) fn query_counts(&self) -> (usize, usize) {
        (self.monitors.object_count, self.clients.object_count)
    }
    pub(crate) fn response_sha256(&self) -> (Sha256Digest, Sha256Digest) {
        (self.monitors.raw_sha256, self.clients.raw_sha256)
    }
}
#[derive(Deserialize)]
struct ReadWorkspace {
    id: i64,
}
#[derive(Deserialize)]
struct ReadMonitor {
    id: i64,
    name: String,
    width: u32,
    height: u32,
    scale: f64,
    #[serde(rename = "activeWorkspace")]
    active_workspace: ReadWorkspace,
    #[serde(rename = "specialWorkspace")]
    special_workspace: ReadWorkspace,
}
#[derive(Deserialize)]
struct ReadClient {
    address: String,
    mapped: bool,
    hidden: bool,
    pid: i64,
    at: [i32; 2],
    size: [i32; 2],
    workspace: ReadWorkspace,
}
fn decode_window_reply(query: WindowQuery, bytes: &[u8]) -> Result<QueryReadEvidence> {
    if bytes.len() > query.limit() {
        return Err(AssociationError::Capacity);
    }
    let mut identities = std::collections::BTreeSet::new();
    let object_count = match query {
        WindowQuery::Monitors => {
            let monitors: Vec<ReadMonitor> =
                serde_json::from_slice(bytes).map_err(|_| AssociationError::Untrusted)?;
            if monitors.is_empty() || monitors.len() > 32 {
                return Err(AssociationError::Untrusted);
            }
            for m in &monitors {
                if m.id < 0
                    || !identities.insert(m.id)
                    || m.name.is_empty()
                    || m.name.len() > MAX_FIELD
                    || m.name.chars().any(char::is_control)
                    || m.width == 0
                    || m.height == 0
                    || u64::from(m.width) * u64::from(m.height) > 64 * 1024 * 1024
                    || !m.scale.is_finite()
                    || m.scale <= 0.0
                {
                    return Err(AssociationError::Untrusted);
                }
                // Typed workspace IDs are observed, not interpreted as grants.
                let _ = (m.active_workspace.id, m.special_workspace.id);
            }
            monitors.len()
        }
        WindowQuery::Clients => {
            let clients: Vec<ReadClient> =
                serde_json::from_slice(bytes).map_err(|_| AssociationError::Untrusted)?;
            if clients.len() > 512 {
                return Err(AssociationError::Capacity);
            }
            let mut addresses = std::collections::BTreeSet::new();
            for c in &clients {
                let address = c
                    .address
                    .strip_prefix("0x")
                    .ok_or(AssociationError::Untrusted)?;
                if address.is_empty()
                    || address.len() > 16
                    || !address.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(AssociationError::Untrusted);
                }
                let address =
                    u64::from_str_radix(address, 16).map_err(|_| AssociationError::Untrusted)?;
                if address == 0
                    || !addresses.insert(address)
                    || c.pid < 0
                    || c.pid > u32::MAX as i64
                    || c.size.iter().any(|v| *v < 0)
                    || (c.mapped && (c.pid == 0 || c.size.contains(&0)))
                {
                    return Err(AssociationError::Untrusted);
                }
                let _ = (c.hidden, c.at, c.workspace.id);
            }
            clients.len()
        }
    };
    Ok(QueryReadEvidence {
        query,
        object_count,
        raw_bytes: bytes.len(),
        raw_sha256: Sha256Digest::of_bytes(bytes),
    })
}
fn validate_window_evidence(e: &WindowReadEvidence, endpoint: &EndpointFact) -> Result<()> {
    if e.schema != 1
        || e.peer != endpoint.peer
        || e.socket_device != endpoint.device
        || e.socket_inode != endpoint.inode
        || e.monitors.query != WindowQuery::Monitors
        || !(1..=32).contains(&e.monitors.object_count)
        || e.clients.query != WindowQuery::Clients
        || e.clients.object_count > 512
    {
        return Err(AssociationError::Untrusted);
    }
    for q in [&e.monitors, &e.clients] {
        if q.raw_bytes < 2 || q.raw_bytes > q.query.limit() {
            return Err(AssociationError::Untrusted);
        }
    }
    Ok(())
}
async fn read_window_reply<R: tokio::io::AsyncRead + Unpin>(
    query: WindowQuery,
    reader: &mut R,
) -> Result<QueryReadEvidence> {
    let mut bytes = Vec::with_capacity(8192);
    // A response at/below the cap is accepted only after read_to_end sees EOF.
    reader
        .take(query.limit() as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    decode_window_reply(query, &bytes)
}
async fn query_windows(
    wayland: &EndpointFact,
    hyprland: &EndpointFact,
    uid: u32,
    end: Instant,
) -> Result<WindowReadEvidence> {
    // Same wire shape as pinned Cua0.36 hyprland.rs:304-328,396-418:
    // exact command bytes, no newline/extra shutdown, then real EOF + JSON.
    // Unlike its optional readonly retry policy, Styx does not retry this probe.
    let monitors = query_window_once(WindowQuery::Monitors, wayland, hyprland, uid, end).await?;
    let clients = query_window_once(WindowQuery::Clients, wayland, hyprland, uid, end).await?;
    Ok(WindowReadEvidence {
        schema: 1,
        peer: hyprland.peer.clone(),
        socket_device: hyprland.device,
        socket_inode: hyprland.inode,
        monitors,
        clients,
    })
}
async fn query_window_once(
    query: WindowQuery,
    wayland: &EndpointFact,
    hyprland: &EndpointFact,
    uid: u32,
    end: Instant,
) -> Result<QueryReadEvidence> {
    let expected = hyprland.peer.clone();
    let (pin, observed) = tokio::task::spawn_blocking(move || proc_read(expected.pid))
        .await
        .map_err(|_| AssociationError::Unavailable)??;
    same(&observed, &hyprland.peer)?;
    let (_display, display_fact) = endpoint(&wayland.path, uid, end).await?;
    same(wayland, &display_fact)?;
    let (mut socket, actual) = endpoint(&hyprland.path, uid, end).await?;
    same(hyprland, &actual)?;
    same(&display_fact.peer, &actual.peer)?;
    let result = timeout_at(end, async {
        socket
            .write_all(query.command())
            .await
            .map_err(|_| AssociationError::Unavailable)?;
        // No read retry: a timeout with a valid JSON prefix is still failure.
        read_window_reply(query, &mut socket).await
    })
    .await
    .map_err(|_| AssociationError::Deadline)??;
    // Same original descriptor, process birth/cgroup and named inode after I/O.
    let peer = socket.peer_cred().map_err(|_| AssociationError::Changed)?;
    if peer.uid() != uid
        || peer.pid().and_then(|v| u32::try_from(v).ok()) != Some(hyprland.peer.pid)
    {
        return Err(AssociationError::Changed);
    }
    let expected = hyprland.clone();
    tokio::task::spawn_blocking(move || {
        if parse_stat(&proc_file(&pin, "stat")?)? != expected.peer.birth {
            return Err(AssociationError::Changed);
        }
        same(&expected.peer, &proc_read(expected.peer.pid)?.1)?;
        let m = std::fs::symlink_metadata(&expected.path).map_err(|_| AssociationError::Changed)?;
        if !m.file_type().is_socket()
            || m.uid() != uid
            || m.dev() != expected.device
            || m.ino() != expected.inode
        {
            return Err(AssociationError::Changed);
        }
        Ok(())
    })
    .await
    .map_err(|_| AssociationError::Unavailable)??;
    if Instant::now() >= end {
        return Err(AssociationError::Deadline);
    }
    Ok(result)
}
impl AssociationFacts {
    pub(crate) fn matches_candidate(&self, candidate: &LinuxCandidate) -> bool {
        self.schema == 1 && self.uid == candidate.uid && &self.candidate == candidate
    }
}
struct Bus {
    connection: Connection,
    fence: std::os::unix::net::UnixStream,
}
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.fence.shutdown(Shutdown::Both);
    }
}
async fn bus(path: &Path, uid: u32, end: Instant) -> Result<Bus> {
    let stream = timeout_at(end, UnixStream::connect(path))
        .await
        .map_err(|_| AssociationError::Deadline)?
        .map_err(|_| AssociationError::Unavailable)?;
    if stream
        .peer_cred()
        .map_err(|_| AssociationError::Untrusted)?
        .uid()
        != uid
    {
        return Err(AssociationError::Untrusted);
    }
    let raw = stream
        .into_std()
        .map_err(|_| AssociationError::Unavailable)?;
    let fence = raw.try_clone().map_err(|_| AssociationError::Unavailable)?;
    let connection = timeout_at(
        end,
        zbus::connection::Builder::unix_stream(
            UnixStream::from_std(raw).map_err(|_| AssociationError::Unavailable)?,
        )
        .max_queued(4)
        .method_timeout(Duration::from_millis(1800))
        .build(),
    )
    .await
    .map_err(|_| AssociationError::Deadline)?
    .map_err(|_| AssociationError::Unavailable)?;
    Ok(Bus { connection, fence })
}
async fn owner(connection: &Connection, name: &str, uid: u32) -> Result<(String, u32)> {
    let bus = DBusProxy::new(connection)
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let owner = bus
        .get_name_owner(name.try_into().map_err(|_| AssociationError::Untrusted)?)
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let actual = bus
        .get_connection_unix_user(owner.as_ref().into())
        .await
        .map_err(|_| AssociationError::Untrusted)?;
    let pid = bus
        .get_connection_unix_process_id(owner.as_ref().into())
        .await
        .map_err(|_| AssociationError::Untrusted)?;
    if actual != uid || pid == 0 {
        return Err(AssociationError::Untrusted);
    }
    field(owner.as_str())?;
    Ok((owner.to_string(), pid))
}
fn field(value: &str) -> Result<()> {
    if value.len() > MAX_FIELD {
        Err(AssociationError::Capacity)
    } else if value.is_empty() || value.contains(['\0', '\n', '\r']) {
        Err(AssociationError::Untrusted)
    } else {
        Ok(())
    }
}
fn limited(mut file: File, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AssociationError::Changed)?;
    if bytes.len() > limit {
        return Err(AssociationError::Capacity);
    }
    Ok(bytes)
}
fn proc_file(dir: &File, name: &str) -> Result<Vec<u8>> {
    let fd = openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| AssociationError::Changed)?;
    limited(File::from(fd), MAX_PROC)
}
fn parse_stat(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| AssociationError::Changed)?;
    let rest = text.rsplit_once(')').ok_or(AssociationError::Changed)?.1;
    if matches!(rest.split_whitespace().next(), Some("Z" | "X" | "x") | None) {
        return Err(AssociationError::Changed);
    }
    rest.split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .ok_or(AssociationError::Changed)
}
fn proc_read(pid: u32) -> Result<(File, ProcessFact)> {
    if pid == 0 {
        return Err(AssociationError::Untrusted);
    }
    let file = File::from(
        open(
            Path::new(&format!("/proc/{pid}")),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AssociationError::Changed)?,
    );
    let metadata = file.metadata().map_err(|_| AssociationError::Changed)?;
    let uid = metadata.uid();
    let before = parse_stat(&proc_file(&file, "stat")?)?;
    let cgroup =
        String::from_utf8(proc_file(&file, "cgroup")?).map_err(|_| AssociationError::Changed)?;
    let rows: Vec<_> = cgroup.lines().collect();
    if rows.len() != 1 {
        return Err(AssociationError::Unsupported);
    }
    let path = rows[0]
        .strip_prefix("0::")
        .ok_or(AssociationError::Unsupported)?
        .to_owned();
    field(&path)?;
    if !path.starts_with('/') || path.contains("/../") {
        return Err(AssociationError::Untrusted);
    }
    if parse_stat(&proc_file(&file, "stat")?)? != before {
        return Err(AssociationError::Changed);
    }
    Ok((
        file,
        ProcessFact {
            pid,
            birth: before,
            uid,
            proc_device: metadata.dev(),
            proc_inode: metadata.ino(),
            cgroup: path,
        },
    ))
}
fn boot() -> Result<String> {
    let bytes = limited(
        File::open("/proc/sys/kernel/random/boot_id").map_err(|_| AssociationError::Unavailable)?,
        64,
    )?;
    let text = String::from_utf8(bytes)
        .map_err(|_| AssociationError::Untrusted)?
        .trim()
        .to_owned();
    if text.len() != 36 || !text.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(AssociationError::Untrusted);
    }
    Ok(text)
}
fn private_dir(path: &Path, uid: u32) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|_| AssociationError::Unavailable)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(AssociationError::Untrusted);
    }
    Ok(())
}
fn bounded_entries(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|_| AssociationError::Unavailable)? {
        if paths.len() >= 128 {
            return Err(AssociationError::Capacity);
        }
        paths.push(entry.map_err(|_| AssociationError::Changed)?.path());
    }
    paths.sort();
    Ok(paths)
}
fn belongs(process: &ProcessFact, unit: &UnitFact, uid: u32) -> bool {
    process.uid == uid
        && !unit.cgroup.is_empty()
        && (process.cgroup == unit.cgroup
            || process
                .cgroup
                .strip_prefix(&unit.cgroup)
                .is_some_and(|s| s.starts_with('/')))
}
fn anchor_envelope(argv: &[String]) -> Result<String> {
    if argv.len() != 3
        || !matches!(
            argv[0].as_str(),
            "/bin/sh" | "/usr/bin/sh" | "/usr/bin/bash"
        )
        || argv[1] != "/usr/lib/uwsm/signal-handler.sh"
    {
        return Err(AssociationError::Unsupported);
    }
    let instance = argv[2]
        .strip_prefix("wayland-session-envelope@")
        .and_then(|s| s.strip_suffix(".target"))
        .ok_or(AssociationError::Unsupported)?;
    if instance.is_empty()
        || instance.len() > 128
        || !instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.\\".contains(&b))
    {
        return Err(AssociationError::Unsupported);
    }
    Ok(instance.to_owned())
}
fn command(pid: u32) -> Result<Vec<String>> {
    let (dir, _) = proc_read(pid)?;
    let bytes = proc_file(&dir, "cmdline")?;
    if bytes.last() != Some(&0) {
        return Err(AssociationError::Changed);
    }
    bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .map(|v| String::from_utf8(v.to_vec()).map_err(|_| AssociationError::Unsupported))
        .collect()
}
async fn property<T: TryFrom<OwnedValue>>(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
    key: &str,
) -> Result<T> {
    let p = PropertiesProxy::builder(connection)
        .destination(owner)
        .map_err(|_| AssociationError::Untrusted)?
        .path(path)
        .map_err(|_| AssociationError::Untrusted)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    p.get(
        interface
            .try_into()
            .map_err(|_| AssociationError::Untrusted)?,
        key,
    )
    .await
    .map_err(|_| AssociationError::Changed)?
    .try_into()
    .map_err(|_| AssociationError::Untrusted)
}
async fn unit(connection: &Connection, owner: &str, name: &str, service: bool) -> Result<UnitFact> {
    field(name)?;
    let manager = AssociationManagerProxy::builder(connection)
        .destination(owner)
        .map_err(|_| AssociationError::Untrusted)?
        .build()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let path = manager
        .get_unit(name)
        .await
        .map_err(|_| AssociationError::Changed)?;
    let id: String = property(connection, owner, path.as_str(), UNIT, "Id").await?;
    let active: String = property(connection, owner, path.as_str(), UNIT, "ActiveState").await?;
    let invocation: Vec<u8> =
        property(connection, owner, path.as_str(), UNIT, "InvocationID").await?;
    if id != name
        || active != "active"
        || invocation.len() != 16
        || invocation.iter().all(|b| *b == 0)
    {
        return Err(AssociationError::Changed);
    }
    let binds = property(connection, owner, path.as_str(), UNIT, "BindsTo").await?;
    let wants = property(connection, owner, path.as_str(), UNIT, "Wants").await?;
    let on_success = property(connection, owner, path.as_str(), UNIT, "OnSuccess").await?;
    let on_failure = property(connection, owner, path.as_str(), UNIT, "OnFailure").await?;
    let conflicts = property(connection, owner, path.as_str(), UNIT, "Conflicts").await?;
    let (main_pid, cgroup, restart, service_type) = if service {
        (
            Some(property(connection, owner, path.as_str(), SERVICE, "MainPID").await?),
            property(connection, owner, path.as_str(), SERVICE, "ControlGroup").await?,
            Some(property(connection, owner, path.as_str(), SERVICE, "Restart").await?),
            Some(property(connection, owner, path.as_str(), SERVICE, "Type").await?),
        )
    } else {
        (None, String::new(), None, None)
    };
    let bind_start = if name.starts_with("wayland-session-bindpid@") {
        Some(property(connection, owner, path.as_str(), SERVICE, "ExecStart").await?)
    } else {
        None
    };
    let result = UnitFact {
        name: id,
        path,
        invocation,
        cgroup,
        main_pid,
        binds,
        wants,
        on_success,
        on_failure,
        conflicts,
        restart,
        service_type,
        bind_start,
    };
    for values in [
        &result.binds,
        &result.wants,
        &result.on_success,
        &result.on_failure,
        &result.conflicts,
    ] {
        if values.len() > 64 {
            return Err(AssociationError::Capacity);
        }
        for s in values {
            field(s)?;
        }
    }
    if !result.cgroup.is_empty() {
        field(&result.cgroup)?;
    }
    Ok(result)
}
fn check_units(
    bind: &UnitFact,
    envelope: &UnitFact,
    wm: &UnitFact,
    env: &UnitFact,
    instance: &str,
) -> Result<()> {
    let pid = bind
        .name
        .strip_prefix("wayland-session-bindpid@")
        .and_then(|v| v.strip_suffix(".service"))
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(AssociationError::Unsupported)?;
    let expected = format!(
        "if command -v waitpid >/dev/null; then exec waitpid -e {pid}; else exec /usr/bin/uwsm aux waitpid {pid}; fi"
    );
    let starts = bind
        .bind_start
        .as_ref()
        .ok_or(AssociationError::Unsupported)?;
    let expected_argv: Vec<String> = ["/bin/sh", "-c", expected.as_str(), "waitpid"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if starts.len() != 1 || starts[0].0 != "/bin/sh" || starts[0].1 != expected_argv || starts[0].2
    {
        return Err(AssociationError::Unsupported);
    }
    let shutdown = "wayland-session-shutdown.target";
    let has = |v: &Vec<String>, s: &str| v.iter().any(|x| x == s);
    if bind.restart.as_deref() != Some("no")
        || bind.service_type.as_deref() != Some("exec")
        || !has(&bind.on_success, shutdown)
        || !has(&bind.on_failure, shutdown)
        || !has(&bind.conflicts, shutdown)
        || !has(&envelope.binds, &wm.name)
        || !has(&envelope.binds, &env.name)
        || !has(&envelope.conflicts, shutdown)
        || wm.restart.as_deref() != Some("no")
        || wm.service_type.as_deref() != Some("notify")
        || !has(&wm.binds, &format!("wayland-session@{instance}.target"))
        || !has(&wm.wants, &envelope.name)
        || !has(&wm.on_success, shutdown)
        || !has(&wm.on_failure, shutdown)
        || env.restart.as_deref() != Some("no")
        || env.service_type.as_deref() != Some("oneshot")
        || !has(
            &env.binds,
            &format!("wayland-session-pre@{instance}.target"),
        )
    {
        return Err(AssociationError::Unsupported);
    }
    Ok(())
}
const SOURCES: [(&str, &str); 6] = [
    (
        "/usr/share/uwsm/modules/uwsm/main.py",
        "2e706425343da602cb1e9c5f227252788913c67cd5c16de678cbce196f08fe79",
    ),
    (
        "/usr/lib/uwsm/signal-handler.sh",
        "c086816ed7764335f9188ee63c0e9a18c35e162d62d51df74b796aa9fc22d10a",
    ),
    (
        "/usr/lib/systemd/user/wayland-session-envelope@.target",
        "f26987268ac51bc5970248ce1d420c604b1030e7049999f3461af8b2b9bc0596",
    ),
    (
        "/usr/lib/systemd/user/wayland-wm@.service",
        "4772c8dcdf1d8e72b793d649a707e58bc636dd3bf35e87bc4f1b029fa39f257d",
    ),
    (
        "/usr/lib/systemd/user/wayland-wm-env@.service",
        "b80e45b22e0ca051439d62e959ba135468c885784212d108d5b809dcf774d566",
    ),
    (
        "/usr/lib/systemd/user/wayland-session-bindpid@.service",
        "b135a2ebe7c591213e75e9860077afedbc8a9ac5baa9604312c629cdb837bb4a",
    ),
];
fn sources() -> Result<Vec<SourceFact>> {
    SOURCES
        .iter()
        .map(|(path, expected)| {
            let file = File::from(
                open(
                    Path::new(path),
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| AssociationError::Unavailable)?,
            );
            let meta = file.metadata().map_err(|_| AssociationError::Unavailable)?;
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(AssociationError::Untrusted);
            }
            let bytes = limited(file, 1024 * 1024)?;
            let digest = Sha256Digest::of_bytes(&bytes);
            if digest.to_hex() != *expected {
                return Err(AssociationError::Unsupported);
            }
            Ok(SourceFact {
                path: PathBuf::from(path),
                device: meta.dev(),
                inode: meta.ino(),
                digest,
            })
        })
        .collect()
}
async fn endpoint(path: &Path, uid: u32, end: Instant) -> Result<(UnixStream, EndpointFact)> {
    let selected = path.to_path_buf();
    let before = tokio::task::spawn_blocking(move || std::fs::symlink_metadata(selected))
        .await
        .map_err(|_| AssociationError::Unavailable)?
        .map_err(|_| AssociationError::Changed)?;
    if !before.file_type().is_socket() || before.uid() != uid {
        return Err(AssociationError::Untrusted);
    }
    let socket = timeout_at(end, UnixStream::connect(path))
        .await
        .map_err(|_| AssociationError::Deadline)?
        .map_err(|_| AssociationError::Changed)?;
    let peer = socket
        .peer_cred()
        .map_err(|_| AssociationError::Untrusted)?;
    if peer.uid() != uid {
        return Err(AssociationError::Untrusted);
    }
    let pid = peer
        .pid()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or(AssociationError::Untrusted)?;
    let process = tokio::task::spawn_blocking(move || proc_read(pid).map(|(_, facts)| facts))
        .await
        .map_err(|_| AssociationError::Unavailable)??;
    let selected = path.to_path_buf();
    let after = tokio::task::spawn_blocking(move || std::fs::symlink_metadata(selected))
        .await
        .map_err(|_| AssociationError::Unavailable)?
        .map_err(|_| AssociationError::Changed)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || !after.file_type().is_socket()
    {
        return Err(AssociationError::Changed);
    }
    Ok((
        socket,
        EndpointFact {
            path: path.to_path_buf(),
            device: before.dev(),
            inode: before.ino(),
            peer: process,
        },
    ))
}
fn check_candidate(candidate: &LinuxCandidate, uid: u32) -> Result<()> {
    if candidate.uid != uid
        || candidate.backend != "wayland"
        || candidate.seat.as_ref().is_none_or(|s| s.is_empty())
    {
        return Err(AssociationError::Unsupported);
    }
    if !candidate.active || candidate.locked_hint || candidate.state != "active" {
        return Err(AssociationError::Inactive);
    }
    Ok(())
}
fn same<T: PartialEq>(before: &T, after: &T) -> Result<()> {
    if before == after {
        Ok(())
    } else {
        Err(AssociationError::Changed)
    }
}
fn one<T>(mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        return Err(if values.is_empty() {
            AssociationError::Unavailable
        } else {
            AssociationError::Ambiguous
        });
    }
    Ok(values.remove(0))
}

/// Read-only actual collector. Call in the existing bounded native worker only.
/// Only bounded read-only Hyprland monitors/clients IPC is sent. No Wayland
/// protocol, input, capture, Agent registration or whole-capability Ready is claimed.
/// 1.1s work + 0.2s close fits the parent runner's 1.5s output/wait
/// and 0.5s revalidation/cleanup within the same 2s absolute request budget.
pub(crate) async fn collect_uwsm(candidate: &LinuxCandidate) -> Result<AssociationFacts> {
    let end = Instant::now() + Duration::from_millis(1300);
    let work = end - Duration::from_millis(200);
    let uid = Uid::current().as_raw();
    check_candidate(candidate, uid)?;
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    private_dir(&runtime, uid)?;
    let system = bus(Path::new(SYSTEM_BUS), 0, work).await?;
    let user = match bus(&runtime.join("bus"), uid, work).await {
        Ok(v) => v,
        Err(e) => {
            let _ = timeout_at(end, system.connection.clone().close()).await;
            return Err(e);
        }
    };
    let mut result = timeout_at(
        work,
        collect(
            &system.connection,
            &user.connection,
            candidate,
            &runtime,
            work,
        ),
    )
    .await
    .map_err(|_| AssociationError::Deadline)
    .and_then(|v| v);
    // Bounded proc/source reads are synchronous inside the isolated child;
    // do not publish a late result merely because one poll crossed the timer.
    if Instant::now() >= work {
        result = Err(AssociationError::Deadline);
    }
    let (a, b) = tokio::join!(
        timeout_at(end, system.connection.clone().close()),
        timeout_at(end, user.connection.clone().close())
    );
    if !matches!(a, Ok(Ok(()))) || !matches!(b, Ok(Ok(()))) {
        return Err(AssociationError::CloseUnconfirmed);
    }
    result
}
async fn collect(
    system: &Connection,
    user: &Connection,
    candidate: &LinuxCandidate,
    runtime: &Path,
    end: Instant,
) -> Result<AssociationFacts> {
    let uid = Uid::current().as_raw();
    let boot_before = boot()?;
    let (login_owner, _) = owner(system, LOGIN, 0).await?;
    let (manager_owner, manager_pid) = owner(user, MANAGER, uid).await?;
    let (_, manager_process) = proc_read(manager_pid)?;
    if manager_process.uid != uid {
        return Err(AssociationError::Untrusted);
    }
    let login = LoginManagerProxy::builder(system)
        .destination(login_owner.as_str())
        .map_err(|_| AssociationError::Untrusted)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let rows = login
        .list_sessions()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    super::checked_list(&rows).map_err(|_| AssociationError::Capacity)?;
    let row = rows
        .iter()
        .find(|r| r.0 == candidate.session_id)
        .ok_or(AssociationError::Changed)?;
    let session = super::sample(system, &login_owner, row)
        .await
        .map_err(|_| AssociationError::Changed)?;
    same(&Some(candidate.clone()), &super::candidate(&session, uid))?;
    let (_, leader) = proc_read(candidate.leader_pid)?;
    if leader.birth != candidate.leader_birth || ![0, uid].contains(&leader.uid) {
        return Err(AssociationError::Changed);
    }
    let by_pid = AssociationLoginProxy::builder(system)
        .destination(login_owner.as_str())
        .map_err(|_| AssociationError::Untrusted)?
        .build()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let manager = AssociationManagerProxy::builder(user)
        .destination(manager_owner.as_str())
        .map_err(|_| AssociationError::Untrusted)?
        .build()
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    let units = manager
        .list_units_by_patterns(&["active"], &["wayland-session-bindpid@*.service"])
        .await
        .map_err(|_| AssociationError::Unavailable)?;
    if units.len() > MAX_ROWS {
        return Err(AssociationError::Capacity);
    }
    let mut matches = Vec::new();
    for row_unit in units {
        let anchor_pid = row_unit
            .0
            .strip_prefix("wayland-session-bindpid@")
            .and_then(|s| s.strip_suffix(".service"))
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|p| *p > 0)
            .ok_or(AssociationError::Untrusted)?;
        // Other real logins are not fallback targets. Every anchor of THIS
        // login must verify; a broken one cannot be silently skipped.
        let path = by_pid
            .get_session_by_pid(anchor_pid)
            .await
            .map_err(|_| AssociationError::Changed)?;
        if path != row.4 {
            continue;
        }
        let (_, anchor) = proc_read(anchor_pid)?;
        if anchor.uid != uid {
            return Err(AssociationError::Untrusted);
        }
        let argv = command(anchor_pid)?;
        let instance = anchor_envelope(&argv)?;
        let bind = unit(user, &manager_owner, &row_unit.0, true).await?;
        let envelope = unit(
            user,
            &manager_owner,
            &format!("wayland-session-envelope@{instance}.target"),
            false,
        )
        .await?;
        let wm = unit(
            user,
            &manager_owner,
            &format!("wayland-wm@{instance}.service"),
            true,
        )
        .await?;
        let wm_env = unit(
            user,
            &manager_owner,
            &format!("wayland-wm-env@{instance}.service"),
            true,
        )
        .await?;
        check_units(&bind, &envelope, &wm, &wm_env, &instance)?;
        let (_, bind_process) = proc_read(bind.main_pid.ok_or(AssociationError::Changed)?)?;
        let (_, wm_main) = proc_read(wm.main_pid.ok_or(AssociationError::Changed)?)?;
        if !belongs(&bind_process, &bind, uid) || !belongs(&wm_main, &wm, uid) {
            return Err(AssociationError::Changed);
        }
        matches.push((
            anchor,
            argv,
            bind,
            envelope,
            wm,
            wm_env,
            bind_process,
            wm_main,
        ));
    }
    let (anchor, anchor_argv, bind, envelope, wm, wm_env, bind_process, wm_main) = one(matches)?;
    let mut displays = Vec::new();
    for path in bounded_entries(runtime)? {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name
            .strip_prefix("wayland-")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let (_socket, fact) = endpoint(&path, uid, end).await?;
        if belongs(&fact.peer, &wm, uid) {
            displays.push(fact)
        }
    }
    let wayland = one(displays)?;
    private_dir(&runtime.join("hypr"), uid)?;
    let mut ipc = Vec::new();
    for dir in bounded_entries(&runtime.join("hypr"))? {
        private_dir(&dir, uid)?;
        let (_a, a) = endpoint(&dir.join(".socket.sock"), uid, end).await?;
        let (_b, b) = endpoint(&dir.join(".socket2.sock"), uid, end).await?;
        if a.peer == wayland.peer && b.peer == wayland.peer {
            ipc.push((a, b))
        }
    }
    let (hyprland, hyprland_events) = one(ipc)?;
    let window_read = query_windows(&wayland, &hyprland, uid, end).await?;
    let facts = AssociationFacts {
        schema: 1,
        boot: boot_before,
        uid,
        candidate: candidate.clone(),
        login_owner: login_owner.clone(),
        manager_owner,
        manager_process,
        leader,
        anchor,
        anchor_argv,
        bind,
        envelope,
        wm,
        wm_env,
        bind_process,
        wm_main,
        wayland,
        hyprland,
        hyprland_events,
        window_read,
        sources: sources()?,
    };
    // Same unique owners, typed properties and kernel facts in the second pass.
    same(&facts.login_owner, &owner(system, LOGIN, 0).await?.0)?;
    same(
        &(facts.manager_owner.clone(), facts.manager_process.pid),
        &owner(user, MANAGER, uid).await?,
    )?;
    same(
        &session,
        &super::sample(system, &facts.login_owner, row)
            .await
            .map_err(|_| AssociationError::Changed)?,
    )?;
    same(
        &row.4,
        &by_pid
            .get_session_by_pid(facts.anchor.pid)
            .await
            .map_err(|_| AssociationError::Changed)?,
    )?;
    for old in [&facts.bind, &facts.envelope, &facts.wm, &facts.wm_env] {
        same(
            old,
            &unit(
                user,
                &facts.manager_owner,
                &old.name,
                old.main_pid.is_some(),
            )
            .await?,
        )?;
    }
    validate_kernel(&facts)?;
    if serde_json::to_vec(&facts)
        .map_err(|_| AssociationError::Untrusted)?
        .len()
        > MAX_FACTS
    {
        return Err(AssociationError::Capacity);
    }
    Ok(facts)
}
fn validate_kernel(facts: &AssociationFacts) -> Result<Vec<File>> {
    validate_window_evidence(&facts.window_read, &facts.hyprland)?;
    if facts.schema != 1 || facts.uid != Uid::current().as_raw() {
        return Err(AssociationError::Untrusted);
    }
    check_candidate(&facts.candidate, facts.uid)?;
    same(&facts.boot, &boot()?)?;
    let runtime = PathBuf::from(format!("/run/user/{}", facts.uid));
    private_dir(&runtime, facts.uid)?;
    private_dir(&runtime.join("hypr"), facts.uid)?;
    private_dir(
        facts
            .hyprland
            .path
            .parent()
            .ok_or(AssociationError::Untrusted)?,
        facts.uid,
    )?;
    let mut pins = Vec::new();
    for old in [
        &facts.manager_process,
        &facts.leader,
        &facts.anchor,
        &facts.bind_process,
        &facts.wm_main,
        &facts.wayland.peer,
    ] {
        let (file, now) = proc_read(old.pid)?;
        same(old, &now)?;
        pins.push(file);
    }
    same(&facts.anchor_argv, &command(facts.anchor.pid)?)?;
    let executable = File::open(format!("/proc/{}/exe", facts.anchor.pid))
        .map_err(|_| AssociationError::Changed)?;
    let actual = executable
        .metadata()
        .map_err(|_| AssociationError::Changed)?;
    let shell = File::open(&facts.anchor_argv[0])
        .map_err(|_| AssociationError::Changed)?
        .metadata()
        .map_err(|_| AssociationError::Changed)?;
    if !actual.is_file()
        || actual.uid() != 0
        || actual.mode() & 0o022 != 0
        || actual.dev() != shell.dev()
        || actual.ino() != shell.ino()
    {
        return Err(AssociationError::Untrusted);
    }
    same(&facts.sources, &sources()?)?;
    for old in [&facts.wayland, &facts.hyprland, &facts.hyprland_events] {
        let m = std::fs::symlink_metadata(&old.path).map_err(|_| AssociationError::Changed)?;
        if !m.file_type().is_socket()
            || m.uid() != facts.uid
            || m.dev() != old.device
            || m.ino() != old.inode
        {
            return Err(AssociationError::Changed);
        }
    }
    Ok(pins)
}
/// Read-only projection. It is not an Agent registration or capability grant.
#[derive(Serialize)]
pub struct AssociationInspection {
    schema: u16,
    source_session_id: String,
    user_uid: u32,
    compositor_pid: u32,
    compositor_birth: u64,
    wayland_basename: String,
    hyprland_instance: String,
    native_agent_registered: bool,
    capability_readiness: &'static str,
    window_read_query_observed: bool,
    window_read_monitors_count: usize,
    window_read_monitors_sha256: Sha256Digest,
    window_read_clients_count: usize,
    window_read_clients_sha256: Sha256Digest,
}
/// Held kernel identities; no Clone/Serde, no candidate→Ready conversion.
/// Parent must fence on existing watch EOF/overflow/owner/unit/lock events BEFORE
/// another Desktop dispatch. Revalidation is not an atomic OS action lock.
pub(crate) struct LinuxAssociationLease {
    facts: AssociationFacts,
    _processes: Vec<File>,
    _endpoints: Vec<UnixStream>,
}
impl LinuxAssociationLease {
    /// Compare fresh original-owned-worker observations without rebinding or
    /// granting authority. Window response content is intentionally excluded.
    pub(crate) fn same_source(&self, other: &Self) -> bool {
        self.facts.same_source(&other.facts)
    }

    /// ONLY root's private original-owned-worker completion may call this.
    /// It must check exact worker image, normal wait, bounded frame and budgets.
    /// Do not expose an arbitrary AssociationFacts constructor on network IPC.
    pub(crate) async fn from_owned_collector(
        facts: AssociationFacts,
        end: Instant,
    ) -> Result<Self> {
        if Instant::now() >= end {
            return Err(AssociationError::Deadline);
        }
        let initial = facts.clone();
        let pins = tokio::task::spawn_blocking(move || validate_kernel(&initial))
            .await
            .map_err(|_| AssociationError::Unavailable)??;
        let mut endpoints = Vec::new();
        for original in [&facts.wayland, &facts.hyprland, &facts.hyprland_events] {
            let (socket, actual) = endpoint(&original.path, facts.uid, end).await?;
            same(original, &actual)?;
            endpoints.push(socket);
        }
        let final_facts = facts.clone();
        tokio::task::spawn_blocking(move || validate_kernel(&final_facts))
            .await
            .map_err(|_| AssociationError::Unavailable)??;
        if Instant::now() >= end {
            return Err(AssociationError::Deadline);
        }
        Ok(Self {
            facts,
            _processes: pins,
            _endpoints: endpoints,
        })
    }
    pub(crate) fn inspection(&self) -> AssociationInspection {
        AssociationInspection {
            schema: 1,
            source_session_id: self.facts.candidate.session_id.clone(),
            user_uid: self.facts.uid,
            compositor_pid: self.facts.wayland.peer.pid,
            compositor_birth: self.facts.wayland.peer.birth,
            wayland_basename: self.wayland_display().to_owned(),
            hyprland_instance: self.hyprland_instance().to_owned(),
            native_agent_registered: false,
            capability_readiness: "NOT_ATTESTED",
            window_read_query_observed: true,
            window_read_monitors_count: self.facts.window_read.monitors.object_count,
            window_read_monitors_sha256: self.facts.window_read.monitors.raw_sha256,
            window_read_clients_count: self.facts.window_read.clients.object_count,
            window_read_clients_sha256: self.facts.window_read.clients.raw_sha256,
        }
    }
    pub(crate) fn window_read_evidence(&self) -> &WindowReadEvidence {
        &self.facts.window_read
    }
    /// Cheap native identity check; DOES NOT renew bus/unit/lock observations.
    /// Parent combines it with a fresh supervised collector/watch generation.
    pub(crate) fn revalidate_kernel(&self) -> Result<()> {
        validate_kernel(&self.facts).map(|_| ())
    }
    pub(crate) fn wayland_display(&self) -> &str {
        self.facts
            .wayland
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("collected named display")
    }
    pub(crate) fn hyprland_instance(&self) -> &str {
        self.facts
            .hyprland
            .path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .expect("collected named Hyprland instance")
    }
    pub(crate) fn login_unique_owner(&self) -> &str {
        &self.facts.login_owner
    }
    pub(crate) fn runtime_dir(&self) -> PathBuf {
        PathBuf::from(format!("/run/user/{}", self.facts.uid))
    }
    /// Agent instance identifies the actually owned, supervised per-session Rust
    /// Desktop supervisor holding this lease. Cua is its operation backend and
    /// need not exist before registration. A random ID/candidate alone is not an
    /// Agent. Registration remains separate from capture/input/grant evidence.
    pub(crate) fn registration_facts(
        &self,
        agent_instance: AgentInstanceId,
    ) -> Result<RegistrationFacts> {
        self.revalidate_kernel()?;
        let hash = |v: &[u8]| Sha256Digest::of_bytes(v).to_hex();
        let login = format!(
            "{}:{}:{}:{}",
            self.facts.boot,
            self.facts.candidate.session_id,
            self.facts.leader.birth,
            self.facts.candidate.login_timestamp_monotonic
        );
        let compositor = format!(
            "{}:{}:{}:{}",
            self.facts.boot,
            self.facts.wayland.peer.pid,
            self.facts.wayland.peer.birth,
            hex::encode(&self.facts.wm.invocation)
        );
        let display = format!(
            "{}:{}:{}:{}",
            self.facts.wayland.device,
            self.facts.wayland.inode,
            self.facts.hyprland.device,
            self.facts.hyprland.inode
        );
        Ok(RegistrationFacts {
            id: SessionId::try_from(format!("linux-{}", hash(login.as_bytes())))
                .map_err(|_| AssociationError::Untrusted)?,
            identity: SessionIdentity::Linux {
                uid: self.facts.uid,
                login_instance: login,
                seat: self.facts.candidate.seat.clone(),
                compositor_instance: hash(compositor.as_bytes()),
                display_identity: hash(display.as_bytes()),
            },
            agent_instance,
            protocol_version: 1,
            provenance:
                "kernel/logind+UWSM0.26.6 exact lifecycle bridge; owned per-session Rust Desktop supervisor required".into(),
        })
    }
}
#[cfg(test)]
#[path = "association_tests.rs"]
mod tests;
