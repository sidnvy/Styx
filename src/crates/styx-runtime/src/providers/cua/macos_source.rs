//! Draft platform-local source binding. No Core registration or capability grant.
//! Uses the separate fixed read-only SignedAppMembers factory in signed-app-pin/.
//! All filesystem/Security calls run on the caller's existing blocking boundary.

use super::probe_diagnostic::{ProbeCause, ProbeDiagnostic, ProbeStage};
use crate::store::{PrivateRoot, ProcessIdentity, SignedAppMember, SignedAppMembers, StoreError};
use core_foundation::{base::TCFType, data::CFData};
use nix::{
    sys::socket::{
        MsgFlags, audit_token_t, getsockopt, recv,
        sockopt::{LocalPeerPid, LocalPeerToken},
    },
    unistd::{geteuid, getpeereid, getuid},
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use serde::Deserialize;
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

#[path = "macos_native_observation.rs"]
mod native_observation;
pub(crate) use native_observation::{
    NativeObservation, ObservedConsoleIdentity, WindowReadEvidence,
};

const APP: &str = "/Applications/Styx.app";
const APP_IMAGE: &str = "/Applications/Styx.app/Contents/MacOS/Styx";
const DAEMON_IMAGE: &str = "/Applications/Styx.app/Contents/MacOS/cua-driver";
const ORIGINAL_CERT: &str = "9a4c8c7e15d006f9d0a576b137c7696f143f46d8";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BindingError {
    #[error("fixed Mac desktop source not yet published")]
    NotPublished,
    #[error("fixed Mac desktop source unavailable")]
    Unavailable,
    #[error("fixed Mac native observation protocol incomplete or refused")]
    NativeProtocol,
    #[error("fixed Mac source discovery hint invalid")]
    InvalidHint,
    #[error("fixed Mac source image pin unavailable or changed")]
    ImagePin,
    #[error("fixed Mac source signature refused")]
    Signature,
    #[error("fixed Mac socket peer identity refused")]
    Peer,
    #[error("fixed Mac source changed; replacement not adopted")]
    Fenced,
}
type Result<T> = std::result::Result<T, BindingError>;
impl BindingError {
    pub(super) fn probe_cause(self) -> ProbeCause {
        match self {
            Self::NotPublished => ProbeCause::NotPublished,
            Self::Unavailable => ProbeCause::Unavailable,
            Self::NativeProtocol => ProbeCause::NativeProtocol,
            Self::InvalidHint => ProbeCause::InvalidHint,
            Self::ImagePin => ProbeCause::ImagePin,
            Self::Signature => ProbeCause::Signature,
            Self::Peer => ProbeCause::Peer,
            Self::Fenced => ProbeCause::Fenced,
        }
    }
}

/// Fixed read-only App pins have no configuration or process-launch authority.
pub(crate) struct MacAppImages {
    members: SignedAppMembers,
    app_cdhash: Vec<u8>,
    daemon_cdhash: Vec<u8>,
}
impl MacAppImages {
    pub(crate) fn open_fixed() -> Result<Self> {
        let members = SignedAppMembers::open_fixed().map_err(|_| BindingError::ImagePin)?;
        require_image(&members.app, APP_IMAGE)?;
        require_image(&members.daemon, DAEMON_IMAGE)?;
        let app_cdhash = members
            .app
            .expected_cdhash()
            .map_err(|_| BindingError::ImagePin)?;
        let daemon_cdhash = members
            .daemon
            .expected_cdhash()
            .map_err(|_| BindingError::ImagePin)?;
        let images = Self {
            members,
            app_cdhash,
            daemon_cdhash,
        };
        images.revalidate()?;
        Ok(images)
    }
    fn revalidate(&self) -> Result<()> {
        self.members
            .revalidate()
            .map_err(|_| BindingError::ImagePin)
    }
}
fn require_image(image: &SignedAppMember, expected: &str) -> Result<()> {
    // The read-only factory hashed and signature-verified the original FD.
    // This checks its retained identity, not a generic spawn locator.
    image.revalidate().map_err(|_| BindingError::ImagePin)?;
    if image
        .source_path_for_image_attestation()
        .map_err(|_| BindingError::ImagePin)?
        != Path::new(expected)
    {
        return Err(BindingError::ImagePin);
    }
    image.retained_file().map_err(|_| BindingError::ImagePin)?;
    Ok(())
}
fn requirement(value: &str) -> Result<SecRequirement> {
    value.parse().map_err(|_| BindingError::Signature)
}

#[derive(Deserialize, Eq, PartialEq)]
struct Hint {
    schema: u32,
    generation: String,
    owner_pid: u32,
    daemon_pid: u32,
    bundle_id: String,
    // Console availability is published by this same signed App owner. TCC
    // still comes from the original daemon's standard check_permissions.
    host_on_console: bool,
    host_session_locked: bool,
}
fn missing_publication(error: StoreError) -> BindingError {
    match error {
        StoreError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            BindingError::NotPublished
        }
        _ => BindingError::Unavailable,
    }
}
fn hint(root: &PrivateRoot) -> Result<Hint> {
    let raw = root
        .read_raw("connection.json", 16 * 1024)
        .map_err(missing_publication)?;
    let value: Hint = serde_json::from_slice(raw.bytes()).map_err(|_| BindingError::InvalidHint)?;
    if value.schema != 1
        || value.bundle_id != "app.styx.host"
        || value.generation.len() != 36
        || Uuid::parse_str(&value.generation).is_err()
        || value.owner_pid == value.daemon_pid
        || value.owner_pid == 0
        || value.owner_pid > i32::MAX as u32
        || value.daemon_pid == 0
        || value.daemon_pid > i32::MAX as u32
    {
        return Err(BindingError::InvalidHint);
    }
    Ok(value)
}
fn birth(pid: u32, uid: u32) -> Result<ProcessIdentity> {
    let value = ProcessIdentity::observe(pid).map_err(|_| BindingError::Peer)?;
    if !matches!(&value, ProcessIdentity::Macos { uid: actual, .. } if *actual == uid) {
        return Err(BindingError::Peer);
    }
    Ok(value)
}

fn original_daemon_parent(candidate: &MacSourceCandidate) -> Result<()> {
    if !crate::platform::macos_spawn::original_parent_matches(
        &candidate.daemon,
        candidate.hint.owner_pid,
    ) {
        return Err(BindingError::Peer);
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    changed: (i64, i64),
}
fn socket_identity(path: &Path, uid: u32) -> Result<SocketIdentity> {
    // Fixed locator only. PrivateRoot read before/after detects ancestry
    // replacement; the actual connected peer is independently authenticated.
    // This path observation alone is never used to authorize a connection.
    let metadata =
        fs::symlink_metadata(path).map_err(|error| missing_publication(StoreError::Io(error)))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o7077 != 0
        || metadata.nlink() != 1
    {
        return Err(BindingError::Peer);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid,
        mode: metadata.mode(),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

/// Discovery owns no process and is never Ready. It retains the original root,
/// original image descriptors, and births before the only fixed-path connect.
pub(crate) struct MacSourceCandidate {
    images: MacAppImages,
    root: PrivateRoot,
    socket_path: PathBuf,
    uid: u32,
    hint: Hint,
    owner: ProcessIdentity,
    daemon: ProcessIdentity,
    socket: SocketIdentity,
}
impl MacSourceCandidate {
    /// Denial-only headless/stale-endpoint prefilter. These cheap protected
    /// observations never authorize a source or replace full image/peer checks.
    pub(crate) fn check_discovery_presence() -> Result<()> {
        let uid = getuid().as_raw();
        if geteuid().as_raw() != uid {
            return Err(BindingError::Peer);
        }
        let directory = PathBuf::from(format!("/private/tmp/styx-cua-{uid}"));
        let root = PrivateRoot::open(&directory).map_err(missing_publication)?;
        let original = hint(&root)?;
        birth(original.owner_pid, uid)?;
        birth(original.daemon_pid, uid)?;
        socket_identity(&directory.join("cua.sock"), uid)?;
        Ok(())
    }
    pub(crate) fn discover(images: MacAppImages) -> Result<Self> {
        let uid = getuid().as_raw();
        if geteuid().as_raw() != uid {
            return Err(BindingError::Peer);
        }
        images.revalidate()?;
        let directory = PathBuf::from(format!("/private/tmp/styx-cua-{uid}"));
        let root = PrivateRoot::open(&directory).map_err(|_| BindingError::Unavailable)?;
        let original = hint(&root)?;
        let owner = birth(original.owner_pid, uid)?;
        let daemon = birth(original.daemon_pid, uid)?;
        let socket_path = directory.join("cua.sock");
        let socket = socket_identity(&socket_path, uid)?;
        if hint(&root)? != original {
            return Err(BindingError::Fenced);
        }
        Ok(Self {
            images,
            root,
            socket_path,
            uid,
            hint: original,
            owner,
            daemon,
            socket,
        })
    }

    /// Returns a connected-but-unbound transport. Its fields stay private; no
    /// caller can use it for actions before finish_binding on the blocking pool.
    /// Uses the caller's existing acquisition deadline, no hidden retry/backoff.
    pub(crate) async fn connect(
        self,
        deadline: tokio::time::Instant,
    ) -> Result<ConnectedCandidate> {
        let stream =
            tokio::time::timeout_at(deadline, tokio::net::UnixStream::connect(&self.socket_path))
                .await
                .map_err(|_| BindingError::Unavailable)?
                .map_err(|_| BindingError::Unavailable)?;
        let stream = stream.into_std().map_err(|_| BindingError::Unavailable)?;
        Ok(ConnectedCandidate {
            candidate: Arc::new(self),
            stream,
        })
    }
}
pub(crate) struct ConnectedCandidate {
    candidate: Arc<MacSourceCandidate>,
    stream: UnixStream,
}
impl ConnectedCandidate {
    pub(crate) fn finish_binding(self) -> Result<BoundMacSource> {
        let (uid, _) = getpeereid(&self.stream).map_err(|_| BindingError::Peer)?;
        let pid = getsockopt(&self.stream, LocalPeerPid).map_err(|_| BindingError::Peer)?;
        if uid.as_raw() != self.candidate.uid
            || pid <= 0
            || pid as u32 != self.candidate.hint.daemon_pid
        {
            return Err(BindingError::Peer);
        }
        let peer_token =
            getsockopt(&self.stream, LocalPeerToken).map_err(|_| BindingError::Peer)?;
        let mut bound = BoundMacSource {
            candidate: self.candidate,
            stream: self.stream,
            peer_token,
            fenced: false,
            protocol_clean: true,
            native_console: None,
            probe_session: None,
            probe_drained: false,
            probe_failure: None,
            initial_provisional: false,
        };
        bound.fresh_binding()?;
        Ok(bound)
    }
}

pub(crate) struct BoundMacSource {
    candidate: Arc<MacSourceCandidate>,
    stream: UnixStream,
    peer_token: audit_token_t,
    fenced: bool,
    // Frame integrity is independent of authorization/session fencing.
    protocol_clean: bool,
    native_console: Option<ObservedConsoleIdentity>,
    probe_session: Option<String>,
    probe_drained: bool,
    // First closed fault facts only; never consulted for source authority.
    probe_failure: Option<ProbeDiagnostic>,
    // A protocol-complete qualification sample exists on this original FD.
    // Executor admission is separately blocked by MacProxySource's lifecycle.
    initial_provisional: bool,
}
impl BoundMacSource {
    pub(crate) fn probe_diagnostic(&self) -> Option<ProbeDiagnostic> {
        self.probe_failure
    }
    fn remember_probe_failure(&mut self, diagnostic: ProbeDiagnostic) {
        self.probe_failure.get_or_insert(diagnostic);
    }
    pub(super) fn fence_initial_native(&mut self) {
        self.fenced = true;
        self.initial_provisional = false;
    }
    /// Snapshot the original authenticated source solely to authenticate a NEW
    /// resource's control connection. Never used to retry/replace an existing
    /// resource's control after dispatch or a lost drain acknowledgement.
    pub(crate) fn duplicate_binding(&mut self) -> Result<Self> {
        self.fresh_binding()?;
        let stream = self
            .stream
            .try_clone()
            .map_err(|_| BindingError::Unavailable)?;
        let next = Self {
            candidate: self.candidate.clone(),
            stream,
            peer_token: self.peer_token,
            fenced: false,
            protocol_clean: true,
            native_console: self.native_console.clone(),
            probe_session: None,
            probe_drained: false,
            probe_failure: None,
            initial_provisional: false,
        };
        self.fresh_binding()?;
        Ok(next)
    }
    /// A second observation connection is authenticated against the retained
    /// source. The official proxy independently uses its private-path service
    /// connections; this observation is not an attestation of those call FDs.
    pub(crate) async fn connect_same_peer(&mut self, until: tokio::time::Instant) -> Result<Self> {
        self.fresh_binding()?;
        let stream = tokio::time::timeout_at(
            until,
            tokio::net::UnixStream::connect(&self.candidate.socket_path),
        )
        .await
        .map_err(|_| BindingError::Unavailable)?
        .map_err(|_| BindingError::Unavailable)?;
        let connected = ConnectedCandidate {
            candidate: self.candidate.clone(),
            stream: stream.into_std().map_err(|_| BindingError::Unavailable)?,
        };
        let mut next = connected.finish_binding()?;
        if next.peer_token != self.peer_token {
            return Err(BindingError::Peer);
        }
        next.native_console = self.native_console.clone();
        self.fresh_binding()?;
        Ok(next)
    }
    pub(crate) fn proxy_parts(&mut self) -> Result<(Arc<SignedAppMember>, PathBuf)> {
        self.fresh_binding()?;
        self.fresh_binding()?;
        Ok((
            self.candidate.images.members.daemon.clone(),
            self.candidate.socket_path.clone(),
        ))
    }
    pub(crate) fn binding_digest(&self) -> Result<styx_contracts::identity::Sha256Digest> {
        let bytes=serde_json::to_vec(&serde_json::json!({
            "schema":1,"uid":self.candidate.uid,"owner":self.candidate.owner,"daemon":self.candidate.daemon,
            "hint_generation":self.candidate.hint.generation,"socket_device":self.candidate.socket.device,
            "socket_inode":self.candidate.socket.inode,"proxy_sha256":self.candidate.images.members.daemon.expected_sha256().map_err(|_|BindingError::ImagePin)?
        })).map_err(|_|BindingError::InvalidHint)?;
        Ok(styx_contracts::identity::Sha256Digest::of_bytes(&bytes))
    }
    /// Revalidates the same source and same FD. Never reconnects/adopts a new
    /// descriptor, generation, owner, daemon, inode, image, or socket peer.
    pub(crate) fn fresh_binding(&mut self) -> Result<()> {
        if self.fenced {
            return Err(BindingError::Fenced);
        }
        let result = self.check_binding();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    fn check_binding(&self) -> Result<()> {
        self.check_original_peer(true)
    }
    // Discovery withdrawal fences new observations/actions, not cleanup on
    // the original authenticated FD. Process, socket and image pins still apply.
    fn check_cleanup_binding(&self) -> Result<()> {
        self.check_original_peer(false)
    }
    fn check_original_peer(&self, require_publication: bool) -> Result<()> {
        let candidate = &self.candidate;
        let mut byte = [0u8; 1];
        match recv(
            self.stream.as_raw_fd(),
            &mut byte,
            MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => return Err(BindingError::Fenced),
            Ok(_) | Err(nix::errno::Errno::EAGAIN) => {}
            Err(_) => return Err(BindingError::Peer),
        }
        if getuid().as_raw() != candidate.uid
            || geteuid().as_raw() != candidate.uid
            || (require_publication && hint(&candidate.root)? != candidate.hint)
            || socket_identity(&candidate.socket_path, candidate.uid)? != candidate.socket
            || birth(candidate.hint.owner_pid, candidate.uid)? != candidate.owner
            || birth(candidate.hint.daemon_pid, candidate.uid)? != candidate.daemon
        {
            return Err(BindingError::Fenced);
        }
        let (uid, _) = getpeereid(&self.stream).map_err(|_| BindingError::Peer)?;
        if uid.as_raw() != candidate.uid
            || getsockopt(&self.stream, LocalPeerPid).map_err(|_| BindingError::Peer)? as u32
                != candidate.hint.daemon_pid
            || getsockopt(&self.stream, LocalPeerToken).map_err(|_| BindingError::Peer)?
                != self.peer_token
        {
            return Err(BindingError::Peer);
        }
        candidate.images.revalidate()?;
        original_daemon_parent(candidate)?;
        verify_guest(
            candidate.hint.owner_pid,
            None,
            APP,
            &candidate.images.app_cdhash,
            true,
        )?;
        verify_guest(
            candidate.hint.daemon_pid,
            Some(self.peer_token),
            DAEMON_IMAGE,
            &candidate.images.daemon_cdhash,
            false,
        )?;
        candidate.images.revalidate()?;
        if birth(candidate.hint.owner_pid, candidate.uid)? != candidate.owner
            || birth(candidate.hint.daemon_pid, candidate.uid)? != candidate.daemon
            || (require_publication && hint(&candidate.root)? != candidate.hint)
            || socket_identity(&candidate.socket_path, candidate.uid)? != candidate.socket
        {
            return Err(BindingError::Fenced);
        }
        original_daemon_parent(candidate)?;
        Ok(())
    }
}

fn verify_guest(
    pid: u32,
    token: Option<audit_token_t>,
    path: &str,
    cdhash: &[u8],
    app: bool,
) -> Result<()> {
    if !matches!(cdhash.len(), 20 | 32) {
        return Err(BindingError::Signature);
    }
    let mut attributes = GuestAttributes::new();
    // Preserve the opaque native representation, without decoding/reinterpreting
    // audit fields. SecCode consumes the authenticated original peer token.
    let token_data = token.map(|token| {
        CFData::from_buffer(
            &token
                .val
                .into_iter()
                .flat_map(u32::to_ne_bytes)
                .collect::<Vec<_>>(),
        )
    });
    if let Some(token) = &token_data {
        attributes.set_audit_token(token.as_concrete_TypeRef());
    } else {
        attributes.set_pid(pid as i32);
    }
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| BindingError::Signature)?;
    let identifier = if app {
        " and identifier \"app.styx.host\""
    } else {
        ""
    };
    let requirement = requirement(&format!(
        "certificate leaf = H\"{ORIGINAL_CERT}\" and cdhash H\"{}\"{identifier}",
        hex::encode(cdhash)
    ))?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| BindingError::Signature)?;
    if code
        .path(Flags::NONE)
        .map_err(|_| BindingError::Signature)?
        .to_path()
        .as_deref()
        != Some(Path::new(path))
    {
        return Err(BindingError::Signature);
    }
    Ok(())
}
