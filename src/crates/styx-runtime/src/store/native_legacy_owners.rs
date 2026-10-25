//! Read-only original owner bindings. These observations grant no physical
//! settlement, migration commit, writer exception or ordinary admission.
use crate::store::secure_journal::{JournalError, JournalResult};
use crate::store::{FileObservation, PrivateRoot, RootIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use styx_contracts::{identity::Sha256Digest, native_management::NativeRootIdentity};

const MAX: usize = 1024 * 1024;
const STATE: &[&str] = &[
    "foreground.lock",
    "foreground-owner.json",
    "foreground-observer.json",
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
    gateway: Option<OwnerRoot>,
    deployment: Present,
    gateway_runtime: Option<OwnerRoot>,
}
#[derive(Deserialize)]
struct Deployment {
    schema: u32,
    mode: String,
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
        && path.components().all(|p| match p {
            Component::RootDir | Component::Normal(_) => true,
            #[cfg(target_os = "windows")]
            Component::Prefix(value) => matches!(
                value.kind(),
                std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
            ),
            _ => false,
        })
}
fn identity(root: &PrivateRoot) -> NativeRootIdentity {
    match root.identity() {
        RootIdentity::Linux { device, inode, uid } => {
            NativeRootIdentity::Linux { device, inode, uid }
        }
        #[cfg(target_os = "macos")]
        RootIdentity::Macos { device, inode, uid } => {
            NativeRootIdentity::Macos { device, inode, uid }
        }
        #[cfg(target_os = "windows")]
        RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } => NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        },
    }
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
        || !matches!(parsed.mode.as_str(), "create-local" | "join-existing")
        || (parsed.mode == "join-existing" && parsed.gateway.runtime.is_some())
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
pub(crate) fn capture_native_legacy_owners(
    state: &PrivateRoot,
    state_dir: &Path,
) -> JournalResult<Box<serde_json::value::RawValue>> {
    if !path_valid(state_dir) {
        return Err(JournalError::InvalidInput);
    }
    let reopened = PrivateRoot::open(state_dir).map_err(|_| JournalError::Unknown)?;
    if identity(&reopened) != identity(state) {
        return Err(JournalError::Conflict);
    }
    let (selected, before) = deployment(state)?;
    let host = PrivateRoot::open(&selected.host.base).map_err(|_| JournalError::Unknown)?;
    let bindings = Bindings {
        schema: 2,
        state: capture_root(state_dir, STATE)?,
        host: capture_root(&selected.host.base, HOST)?,
        gateway: if selected.mode == "create-local" {
            Some(capture_root(&state_dir.join("gateway"), GATEWAY)?)
        } else {
            None
        },
        gateway_runtime: selected
            .gateway
            .runtime
            .as_ref()
            .map(|p| capture_root(&p.base, GATEWAY))
            .transpose()?,
        deployment: before,
    };
    validate_bindings(&bindings, state, &host, state_dir)?;
    let raw = serde_json::value::to_raw_value(&bindings).map_err(|_| JournalError::InvalidInput)?;
    if raw.get().len() > MAX {
        return Err(JournalError::InvalidInput);
    }
    Ok(raw)
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
    if b.schema != 2 || !path_valid(state_path) {
        return Err(JournalError::Conflict);
    }
    let (selected, before) = deployment(state)?;
    validate_root(&b.state, state, state_path, STATE)?;
    validate_root(&b.host, host, &selected.host.base, HOST)?;
    match (&b.gateway, selected.mode.as_str()) {
        (None, "join-existing") => {}
        (Some(saved), "create-local") => {
            let gateway = state_path.join("gateway");
            validate_root(
                saved,
                &PrivateRoot::open(&gateway).map_err(|_| JournalError::Unknown)?,
                &gateway,
                GATEWAY,
            )?;
        }
        _ => return Err(JournalError::Conflict),
    }
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
    if before != b.deployment || deployment(state)?.1 != b.deployment {
        return Err(JournalError::Unknown);
    }
    Ok(())
}
/// Original closed file observations only. Caller separately validates the
/// committed same-journal chain/retirement and, when present, C GuardsHeld posts.
/// No owner liveness, scope settlement, writer or admission authority is minted.
pub(crate) fn validate_native_legacy_owners(
    raw: &serde_json::value::RawValue,
    state: &PrivateRoot,
    host: &PrivateRoot,
    state_dir: &Path,
    expected_service_sha256: Sha256Digest,
) -> JournalResult<()> {
    if raw.get().len() > MAX {
        return Err(JournalError::InvalidInput);
    }
    let bindings: Bindings = serde_json::from_str(raw.get()).map_err(|_| JournalError::Conflict)?;
    validate_bindings(&bindings, state, host, state_dir)?;
    let service = bindings
        .host
        .files
        .first()
        .and_then(|v| v.present.as_ref())
        .ok_or(JournalError::Conflict)?;
    if service.sha256 != expected_service_sha256 {
        return Err(JournalError::Conflict);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    fn directory(path: &Path) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    fn file(path: &Path, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
    #[test]
    fn native_owner_bindings_host_only_actual_files_refuse_replacement_and_new_owner() {
        let top = std::env::temp_dir().join(format!(
            "styx-native-owner-bindings-{}",
            uuid::Uuid::new_v4().simple()
        ));
        directory(&top);
        let state = top.join("state");
        let host = top.join("host");
        directory(&state);
        directory(&host);
        let deployment=serde_json::to_vec(&serde_json::json!({"schema":1,"mode":"join-existing","host":{"baseDir":host},"gateway":{"url":"https://127.0.0.1:443"}})).unwrap();
        file(&state.join("deployment.json"), &deployment);
        file(&state.join("foreground.lock"), b"original retained guard");
        file(&host.join("service.json"), b"original descriptor");
        let state_root = PrivateRoot::open(&state).unwrap();
        let host_root = PrivateRoot::open(&host).unwrap();
        let expected = Sha256Digest::of_bytes(b"original descriptor");
        let raw = capture_native_legacy_owners(&state_root, &state).unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.get()).unwrap();
        assert_eq!(value["schema"], 2);
        assert!(value["gateway"].is_null());
        assert!(value["gateway_runtime"].is_null());
        assert!(!state.join("gateway").exists());
        validate_native_legacy_owners(&raw, &state_root, &host_root, &state, expected).unwrap();
        fs::rename(
            state.join("foreground.lock"),
            state.join("retained-original.guard"),
        )
        .unwrap();
        file(&state.join("foreground.lock"), b"original retained guard");
        assert!(
            validate_native_legacy_owners(&raw, &state_root, &host_root, &state, expected).is_err()
        );
        let current = capture_native_legacy_owners(&state_root, &state).unwrap();
        file(&state.join("capabilities.lock"), b"new owner");
        assert!(
            validate_native_legacy_owners(&current, &state_root, &host_root, &state, expected)
                .is_err()
        );
        fs::remove_dir_all(&top).unwrap();
    }
}
