//! Original committed App input, preserving Host-only or original shared root. No Join/Claim, identity creation,
//! manager conversion or fresh-seed imitation occurs on this read path.
use super::*;
use crate::store::{committed_runtime_native::NativeCommittedRuntimeSnapshot, native_state};
use styx_contracts::{
    management::ReaderContract,
    native_management::{NativeDeploymentMode, NativeMigrationHistory},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Topology {
    HostOnly,
    SharedLocal,
}
pub(super) struct Inspection {
    pub enrollment: Value,
    pub topology: Topology,
}
pub(super) fn inspect(scope: Arc<HostScope>) -> Result<Option<Inspection>, AppError> {
    scope.validate()?;
    let root =
        PrivateRoot::open(scope.state_dir()).map_err(|_| AppError("app_migrated_input_refused"))?;
    let raw = root
        .read_raw("state.json", 1024 * 1024)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    // Selection only; all authority/material checks are the formal snapshot.
    let marker = root
        .read_raw(".styx-native-root-v1.json", 4096)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let marker = native_state::decode_marker(marker.bytes())
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let state = native_state::decode_state(raw.bytes(), &marker)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    if state.state().reader_contract != ReaderContract::NativeMigratedStateV2 {
        return Ok(None);
    }
    let snapshot = NativeCommittedRuntimeSnapshot::open(scope.state_dir())
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let state = snapshot.state();
    let binding = state
        .migration_v2()
        .map_err(|_| AppError("app_migrated_input_refused"))?
        .ok_or(AppError("app_migrated_input_refused"))?;
    let app_role = |r: styx_contracts::native_management::NativeComponentDesired| {
        r.manager == NativeManager::AppManaged && r.autostart == NativeAutostartDesired::Disabled
    };
    if !state.desired.host.is_some_and(app_role)
        || state.desired.gateway.is_some_and(|g| !app_role(g))
    {
        return Err(AppError("app_manager_refused"));
    }
    let topology = match (
        state.mode,
        state.desired.gateway.is_some(),
        &binding.history,
    ) {
        (
            NativeDeploymentMode::JoinExisting,
            false,
            NativeMigrationHistory::PreservedHostPair { .. },
        ) => Topology::HostOnly,
        (
            NativeDeploymentMode::CreateLocal,
            true,
            NativeMigrationHistory::ImportedLocalGateway { .. },
        ) => Topology::SharedLocal,
        _ => return Err(AppError("app_migrated_topology_unsupported")),
    };
    let deployment = root
        .read_raw("deployment.json", 1024 * 1024)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let d: Value = serde_json::from_slice(deployment.bytes())
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let base = PathBuf::from(
        d.pointer("/host/baseDir")
            .and_then(Value::as_str)
            .ok_or(AppError("app_migrated_input_refused"))?,
    );
    let host = PrivateRoot::open(&base).map_err(|_| AppError("app_migrated_input_refused"))?;
    snapshot
        .validate_legacy_owners(&root, &host)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    let identity = host
        .read_raw("device/identity.json", 1024 * 1024)
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    #[derive(Deserialize)]
    struct Identity {
        device_id: styx_contracts::identity::DeviceId,
        fingerprint: styx_contracts::identity::Sha256Digest,
    }
    let identity: Identity = serde_json::from_slice(identity.bytes())
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    snapshot
        .revalidate()
        .map_err(|_| AppError("app_migrated_input_refused"))?;
    scope.validate()?;
    Ok(Some(Inspection {
        topology,
        enrollment: json!({"schema":1,"operation":"inspect_committed_migration","status":"ready_to_connect","source":"committed_original_pair","state_dir":scope.state_dir(),"device_id":identity.device_id,"fingerprint":identity.fingerprint,"service_started":false,"runtime_health":"not_started"}),
    }))
}

/// Retains the original input selected at actual role start. UI status never
/// acquires a replacement profile or promotes local intent to remote authority.
#[derive(Clone)]
pub(super) enum DesktopIntent {
    Fresh(Arc<crate::store::native_host_snapshot::NativeHostSnapshot>),
    Migrated(Arc<foreground::profile::LoadedLegacyProfile>),
}
impl DesktopIntent {
    pub(super) fn open(scope: Arc<HostScope>, migrated: bool) -> Result<Self, AppError> {
        if migrated {
            foreground::profile::load_for_app(scope)
                .map(|p| Self::Migrated(Arc::new(p)))
                .map_err(|_| AppError("app_migrated_input_refused"))
        } else {
            crate::store::native_host_snapshot::NativeHostSnapshot::open_for_app(
                scope.state_dir(),
                scope.clone(),
            )
            .map(|p| Self::Fresh(Arc::new(p)))
            .map_err(|_| AppError("app_scope_changed"))
        }
    }
    pub(super) fn requested(&self) -> bool {
        match self {
            Self::Fresh(p) => {
                p.seed().computer_requested && p.ready().computer_approved && p.revalidate().is_ok()
            }
            // Local configuration intent only; the actual Host/Core session performs
            // current remote capability and OS-session/permission checks separately.
            Self::Migrated(p) => p.computer_enabled().unwrap_or(false),
        }
    }
}
