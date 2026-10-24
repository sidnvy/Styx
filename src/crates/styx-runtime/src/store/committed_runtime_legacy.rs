//! Read-only original owner bindings. These observations grant no physical
//! settlement, migration commit, writer exception or ordinary admission.
use super::CommittedRuntimeSnapshot;
use crate::store::secure_journal::{JournalError, JournalResult};
use crate::store::{FileObservation, PrivateRoot, RootIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use styx_contracts::{identity::Sha256Digest, native_management::NativeRootIdentity};
use zeroize::Zeroizing;

const MAX: usize = 1024 * 1024;
const STATE: &[&str] = &[
    "foreground.lock",
    "foreground-recovery.lock",
    "background.lock",
    "advance.lock",
    "capabilities.lock",
    "gateway-runtime-recovery.lock",
    "host-payload-migration-recovery.lock",
    "host-update-recovery.lock",
    "account-acceptance.lock",
    "onboarding-plugin.lock",
    "tunnel/owner.lock",
    "host-payload-migration.json",
];
const HOST: &[&str] = &[
    "service.json",
    "install/.health-update-lock",
    "install/.health-operation-lock",
    "install/.health-recovery-guard",
];
const GATEWAY: &[&str] = &[
    "service.json",
    "runtime-change.json",
    "foreground.lock",
    "background.lock",
    "install/.health-update-lock",
    "install/.health-operation-lock",
    "install/.health-recovery-guard",
];
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Observation {
    device: u64,
    inode: u64,
    byte_len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}
impl From<&FileObservation> for Observation {
    fn from(o: &FileObservation) -> Self {
        Self {
            device: o.device,
            inode: o.inode,
            byte_len: o.byte_len,
            modified_seconds: o.modified_seconds,
            modified_nanoseconds: o.modified_nanoseconds,
            changed_seconds: o.changed_seconds,
            changed_nanoseconds: o.changed_nanoseconds,
        }
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Present {
    observation: Observation,
    sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnerFile {
    relative: String,
    present: Option<Present>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnerRoot {
    path: PathBuf,
    identity: NativeRootIdentity,
    files: Vec<OwnerFile>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bindings {
    schema: u16,
    state: OwnerRoot,
    host: OwnerRoot,
    gateway: OwnerRoot,
    gateway_runtime: Option<OwnerRoot>,
}
#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    host: HostLocator,
    gateway: GatewayLocator,
}
#[derive(Deserialize)]
struct HostLocator {
    #[serde(rename = "baseDir")]
    base: PathBuf,
}
#[derive(Deserialize)]
struct GatewayLocator {
    runtime: Option<RuntimeLocator>,
}
#[derive(Deserialize)]
struct RuntimeLocator {
    #[serde(rename = "baseDir")]
    base: PathBuf,
}
fn path_valid(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
}
fn identity(root: &PrivateRoot) -> NativeRootIdentity {
    let RootIdentity::Linux { device, inode, uid } = root.identity();
    NativeRootIdentity::Linux { device, inode, uid }
}
fn observe(root: &PrivateRoot, relative: &str) -> JournalResult<Option<Present>> {
    // Only a descriptor-relative ENOENT is absence. Any other failure must
    // instead produce a successful protected read or fail the observation.
    if root.ensure_absent(relative).is_ok() {
        return Ok(None);
    }
    let raw = root
        .read_raw(relative, MAX)
        .map_err(|_| JournalError::Unknown)?;
    Ok(Some(Present {
        observation: raw.observation().into(),
        sha256: Sha256Digest::of_bytes(raw.bytes()),
    }))
}
fn capture_root(path: &Path, names: &[&str]) -> JournalResult<OwnerRoot> {
    if !path_valid(path) {
        return Err(JournalError::InvalidInput);
    }
    let root = PrivateRoot::open(path).map_err(|_| JournalError::Unknown)?;
    let initial = identity(&root);
    let files = names
        .iter()
        .map(|name| {
            Ok(OwnerFile {
                relative: (*name).to_owned(),
                present: observe(&root, name)?,
            })
        })
        .collect::<JournalResult<Vec<_>>>()?;
    for file in &files {
        if observe(&root, &file.relative)? != file.present {
            return Err(JournalError::Unknown);
        }
    }
    if identity(&PrivateRoot::open(path).map_err(|_| JournalError::Unknown)?) != initial {
        return Err(JournalError::Unknown);
    }
    Ok(OwnerRoot {
        path: path.to_owned(),
        identity: initial,
        files,
    })
}
fn deployment(state: &PrivateRoot) -> JournalResult<(Deployment, Present)> {
    let raw = state
        .read_raw("deployment.json", MAX)
        .map_err(|_| JournalError::Unknown)?;
    let parsed: Deployment =
        serde_json::from_slice(raw.bytes()).map_err(|_| JournalError::Conflict)?;
    if parsed.schema != 1
        || !path_valid(&parsed.host.base)
        || parsed
            .gateway
            .runtime
            .as_ref()
            .is_some_and(|r| !path_valid(&r.base))
    {
        return Err(JournalError::Conflict);
    }
    Ok((
        parsed,
        Present {
            observation: raw.observation().into(),
            sha256: Sha256Digest::of_bytes(raw.bytes()),
        },
    ))
}
/// Capture only after the caller validated original fences/scopes. This function
/// neither interprets owner-file contents nor attests that their owners stopped.
pub(crate) fn capture_legacy_owners(
    state_dir: &Path,
    host_dir: &Path,
    gateway_runtime: Option<&Path>,
) -> JournalResult<Box<serde_json::value::RawValue>> {
    let state = PrivateRoot::open(state_dir).map_err(|_| JournalError::Unknown)?;
    let (selected, before) = deployment(&state)?;
    if selected.host.base != host_dir
        || selected.gateway.runtime.as_ref().map(|r| r.base.as_path()) != gateway_runtime
    {
        return Err(JournalError::Conflict);
    }
    let bindings = Bindings {
        schema: 1,
        state: capture_root(state_dir, STATE)?,
        host: capture_root(host_dir, HOST)?,
        gateway: capture_root(&state_dir.join("gateway"), GATEWAY)?,
        gateway_runtime: gateway_runtime
            .map(|p| capture_root(p, GATEWAY))
            .transpose()?,
    };
    if deployment(&state)?.1 != before {
        return Err(JournalError::Unknown);
    }
    // Recheck all roots once more across the complete capture, not just within
    // each root. Root callers retain their actual maintenance custody around it.
    validate_bindings(
        &bindings,
        &state,
        &PrivateRoot::open(host_dir).map_err(|_| JournalError::Unknown)?,
        state_dir,
    )?;
    serde_json::value::to_raw_value(&bindings).map_err(|_| JournalError::InvalidInput)
}
fn validate_root(
    saved: &OwnerRoot,
    root: &PrivateRoot,
    expected_path: &Path,
    names: &[&str],
) -> JournalResult<()> {
    if saved.path != expected_path
        || saved.identity != identity(root)
        || saved.files.len() != names.len()
    {
        return Err(JournalError::Conflict);
    }
    let reopened = PrivateRoot::open(expected_path).map_err(|_| JournalError::Unknown)?;
    if identity(&reopened) != saved.identity {
        return Err(JournalError::Conflict);
    }
    for (file, name) in saved.files.iter().zip(names) {
        if file.relative != *name
            || observe(root, name)? != file.present
            || observe(&reopened, name)? != file.present
        {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}
fn validate_bindings(
    b: &Bindings,
    state: &PrivateRoot,
    host: &PrivateRoot,
    state_path: &Path,
) -> JournalResult<()> {
    if b.schema != 1 || !path_valid(state_path) {
        return Err(JournalError::Conflict);
    }
    let (selected, before) = deployment(state)?;
    validate_root(&b.state, state, state_path, STATE)?;
    validate_root(&b.host, host, &selected.host.base, HOST)?;
    let gateway = state_path.join("gateway");
    validate_root(
        &b.gateway,
        &PrivateRoot::open(&gateway).map_err(|_| JournalError::Unknown)?,
        &gateway,
        GATEWAY,
    )?;
    match (&b.gateway_runtime, &selected.gateway.runtime) {
        (None, None) => {}
        (Some(saved), Some(runtime)) => validate_root(
            saved,
            &PrivateRoot::open(&runtime.base).map_err(|_| JournalError::Unknown)?,
            &runtime.base,
            GATEWAY,
        )?,
        _ => return Err(JournalError::Conflict),
    }
    if deployment(state)?.1 != before {
        return Err(JournalError::Unknown);
    }
    Ok(())
}
impl CommittedRuntimeSnapshot {
    pub(crate) fn validate_legacy_owners(
        &self,
        state: &PrivateRoot,
        host: &PrivateRoot,
    ) -> JournalResult<()> {
        self.revalidate()?;
        let retired = self.retirement().original();
        if state.identity() != self.root_identity()
            || identity(host)
                != (NativeRootIdentity::Linux {
                    device: retired.intent.host_root.device,
                    inode: retired.intent.host_root.inode,
                    uid: retired.intent.host_root.uid,
                })
        {
            return Err(JournalError::Conflict);
        }
        let raw = self
            .state()
            .extensions
            .get("legacy_owner_bindings_v1")
            .ok_or(JournalError::Conflict)?;
        let bindings: Bindings =
            serde_json::from_str(raw.get()).map_err(|_| JournalError::Conflict)?;
        validate_bindings(&bindings, state, host, &bindings.state.path)?;
        let service = bindings
            .host
            .files
            .first()
            .and_then(|f| f.present.as_ref())
            .ok_or(JournalError::Conflict)?;
        if service.sha256 != retired.intent.service_descriptor_sha256 {
            return Err(JournalError::Conflict);
        }
        self.revalidate()
    }
    pub(crate) fn read_retired_token(
        &self,
        host: &PrivateRoot,
    ) -> JournalResult<Zeroizing<Vec<u8>>> {
        self.revalidate()?;
        let retired = self.retirement().original();
        if identity(host)
            != (NativeRootIdentity::Linux {
                device: retired.intent.host_root.device,
                inode: retired.intent.host_root.inode,
                uid: retired.intent.host_root.uid,
            })
        {
            return Err(JournalError::Conflict);
        }
        host.ensure_absent(retired.intent.token_source())
            .map_err(|_| JournalError::Conflict)?;
        let stamp = retired.post_stamp.as_ref().ok_or(JournalError::Conflict)?;
        let raw = host
            .read_raw(retired.intent.token_destination(), 4096)
            .map_err(|_| JournalError::Unknown)?;
        let o = raw.observation();
        if stamp.mode != (libc::S_IFREG | 0o600)
            || stamp.nlink != 1
            || stamp.uid != retired.intent.host_root.uid
            || o.device != stamp.device
            || o.inode != stamp.inode
            || o.byte_len != stamp.byte_len
            || o.modified_seconds != stamp.modified_seconds
            || o.modified_nanoseconds != stamp.modified_nanoseconds
            || o.changed_seconds != stamp.changed_seconds
            || o.changed_nanoseconds != stamp.changed_nanoseconds
            || Sha256Digest::of_bytes(raw.bytes()) != stamp.sha256
        {
            return Err(JournalError::Conflict);
        }
        // Protected read already checks actual UID/private regular mode/nlink;
        // exact ctime+inode also refuses a chmod/chown/relink since retirement.
        let token = Zeroizing::new(raw.bytes().to_vec());
        let after = host
            .read_raw(retired.intent.token_destination(), 4096)
            .map_err(|_| JournalError::Unknown)?;
        if after.observation() != o || Sha256Digest::of_bytes(after.bytes()) != stamp.sha256 {
            return Err(JournalError::Unknown);
        }
        host.ensure_absent(retired.intent.token_source())
            .map_err(|_| JournalError::Conflict)?;
        self.revalidate()?;
        Ok(token)
    }
}
