//! Explicit stopped-profile selection. The original C07 writer and verified
//! release objects remain in custody until the actual transaction settles.
use super::*;

#[derive(Serialize)]
pub struct RuntimeSelectionReport {
    pub schema: u16,
    pub operation: &'static str,
    pub configuration: NativeManagementReport,
    pub selected_manifest_sha256: Sha256Digest,
    pub previous_manifest_sha256: Sha256Digest,
    pub runtime_launched: bool,
    pub operations_replayed: bool,
}
pub async fn select_runtime(
    state_dir: &Path,
    selection_file: &Path,
    transaction_id: &str,
    sequence: u64,
) -> Result<RuntimeSelectionReport> {
    let id = parse_transaction_id(transaction_id)?;
    if sequence == 0 {
        return Err(NativeManagementError::new(ErrorKind::Invalid));
    }
    let path = state_dir.to_owned();
    let selection_file = selection_file.to_owned();
    blocking(move || {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        ))]
        {
            let raw = platform::private_file(&selection_file, NATIVE_STATE_BYTES)?;
            let selected: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
                .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
            platform::use_managed_transactions(&path, None, |transactions| {
                platform::reconcile_complete_tip(transactions, false)?;
                let state = transactions
                    .readstate()
                    .map_err(NativeManagementError::transaction)?;
                let initialized = require_initialized_profile(&path, transactions, &state)?;
                let previous = state
                    .state()
                    .runtime_selection()
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
                if previous.publisher_spki_sha256 != selected.publisher_spki_sha256 {
                    return Err(NativeManagementError::new(ErrorKind::Conflict));
                }
                let old_release = crate::release::verify_selected(&previous)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                let new_release = crate::release::verify_selected(&selected)
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
                initialized.validate()?;
                let committed = transactions
                    .update_runtime(old_release, new_release, id, sequence)
                    .map_err(NativeManagementError::transaction)?;
                initialized.validate()?;
                let transaction = NativeTransactionReport {
                    transaction_id: committed.transaction_id,
                    sequence: committed.committed.sequence,
                    observed_stage: Some(DurableStage::Committed),
                    receipt: Some(committed.committed),
                    recovered: committed.recovered,
                };
                Ok(RuntimeSelectionReport {
                    schema: 1,
                    operation: "runtime_select",
                    configuration: platform::report(
                        transactions,
                        "runtime_select",
                        Some(transaction),
                    )?,
                    selected_manifest_sha256: selected.manifest_sha256,
                    previous_manifest_sha256: previous.manifest_sha256,
                    runtime_launched: false,
                    operations_replayed: false,
                })
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "macos",
            target_os = "windows"
        )))]
        {
            let _ = (path, selection_file, id, sequence);
            Err(NativeManagementError::new(ErrorKind::Unsupported))
        }
    })
    .await
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
struct InitializedProfile {
    root: crate::store::PrivateRoot,
    files: Vec<crate::store::RawFile>,
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
impl InitializedProfile {
    fn capture(&mut self, name: &str, limit: usize) -> Result<usize> {
        let raw = self
            .root
            .read_raw(name, limit)
            .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
        if raw.bytes().is_empty() {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
        self.files.push(raw);
        Ok(self.files.len() - 1)
    }
    fn validate(&self) -> Result<()> {
        for before in &self.files {
            let after = self
                .root
                .read_raw(before.relative_path(), NATIVE_STATE_BYTES)
                .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
            if after.observation() != before.observation() || after.bytes() != before.bytes() {
                return Err(NativeManagementError::new(ErrorKind::Unknown));
            }
        }
        Ok(())
    }
}
/// Business precondition under the already retained original writer. This is
/// read-only completed-enrollment evidence, not a second writer, a claim, or a
/// substitute for update_runtime's original C07/execution-lease checks.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
fn require_initialized_profile(
    path: &Path,
    transactions: &NativeTransactions,
    canonical: &crate::store::native_state::ValidatedNativeState,
) -> Result<InitializedProfile> {
    use serde::Deserialize;
    use styx_contracts::native_host::{NativeHostJoinSeed, NativeHostReady};
    let invalid = || NativeManagementError::new(ErrorKind::Invalid);
    let conflict = || NativeManagementError::new(ErrorKind::Conflict);
    let state = canonical.state();
    if state.has_migration_binding() {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    let root = crate::store::PrivateRoot::open(path).map_err(|_| invalid())?;
    if root.identity()
        != transactions
            .configuration_root()
            .identity()
            .map_err(|_| conflict())?
    {
        return Err(conflict());
    }
    let current = crate::store::native_host_snapshot::validated_runtime_selection(
        &root,
        canonical,
        transactions.marker(),
    )
    .map_err(|_| conflict())?;
    let bootstrap = state
        .runtime_update()
        .map_err(|_| invalid())?
        .map_or(current, |update| update.bootstrap_runtime);
    let stopped = |d: &NativeComponentDesired| {
        d.manager == NativeManager::ForegroundCli
            && d.run == NativeRunDesired::Stopped
            && d.autostart == NativeAutostartDesired::Disabled
    };
    let mut held = InitializedProfile {
        root,
        files: Vec::new(),
    };
    held.capture(".styx-native-root-v1.json", NATIVE_MARKER_BYTES)?;
    let deployment = held.capture("deployment.json", NATIVE_STATE_BYTES)?;
    if Sha256Digest::of_bytes(held.files[deployment].bytes()) != state.deployment_raw_sha256 {
        return Err(conflict());
    }
    match (&state.desired.host, &state.desired.gateway, state.mode) {
        (Some(host), None, NativeDeploymentMode::JoinExisting) if stopped(host) => {
            // Require the same completed prefix as native_join::inspect, using
            // the original recorded comparison and confirmation codec. No HTTP.
            let seed_file = held.capture("host-join-seed-v1.json", NATIVE_STATE_BYTES)?;
            let ready_file = held.capture("host-ready-v1.json", NATIVE_STATE_BYTES)?;
            let credential_file = held.capture("host-credential.token", 4096)?;
            held.capture("host-join-dispatched-v1.json", NATIVE_STATE_BYTES)?;
            let reply_file = held.capture("host-join-reply-v1.json", NATIVE_STATE_BYTES)?;
            let confirm_file =
                held.capture("host-confirm-dispatched-v1.json", NATIVE_STATE_BYTES)?;
            held.capture("host-identity.pem", 16 * 1024)?;
            held.capture("host-ca.pem", 128 * 1024)?;
            let seed: NativeHostJoinSeed =
                serde_json::from_slice(held.files[seed_file].bytes()).map_err(|_| invalid())?;
            let ready: NativeHostReady =
                serde_json::from_slice(held.files[ready_file].bytes()).map_err(|_| invalid())?;
            let seed_hash = Sha256Digest::of_bytes(held.files[seed_file].bytes());
            let expected: Sha256Digest = serde_json::from_str(
                state
                    .extensions
                    .get("fresh_host_seed_v1")
                    .ok_or_else(invalid)?
                    .get(),
            )
            .map_err(|_| invalid())?;
            let credential = held.files[credential_file].bytes();
            if seed.schema != 1
                || ready.schema != 1
                || seed_hash != expected
                || seed.root_identity != transactions.marker().root_identity
                || seed.scope_generation != state.scope_generation
                || seed.deployment_raw_sha256 != state.deployment_raw_sha256
                || seed.runtime != bootstrap
                || ready.seed_sha256 != seed_hash
                || ready.device_id != seed.device_id
                || ready.fingerprint != seed.fingerprint
                || ready.credential_sha256 != Sha256Digest::of_bytes(credential)
                || ready.request_id.is_empty()
                || ready.generation.is_empty()
                || ready.generation.len() > 128
                || !(32..=4096).contains(&credential.len())
                || !credential
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
                || (ready.computer_approved && !seed.computer_requested)
                || (ready.browser_approved && !seed.browser_requested)
            {
                return Err(conflict());
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct RecordedReply<'a> {
                schema: u16,
                peer_leaf_sha256: Sha256Digest,
                #[serde(borrow)]
                body: &'a serde_json::value::RawValue,
            }
            let reply: RecordedReply<'_> =
                serde_json::from_slice(held.files[reply_file].bytes()).map_err(|_| invalid())?;
            if reply.schema != 1 {
                return Err(conflict());
            }
            let leaf = crate::tls::GatewayLeafPin::parse_hex(&reply.peer_leaf_sha256.to_hex())
                .map_err(|_| invalid())?;
            let pending = crate::management::native_join_protocol::validate_recorded_pending(
                &seed,
                reply.body.get().as_bytes(),
                &leaf,
            )
            .map_err(|_| conflict())?;
            let confirm =
                crate::management::native_join_protocol::confirm_request(&pending, credential)
                    .map_err(|_| conflict())?;
            if pending.request_id != ready.request_id
                || confirm.as_slice() != held.files[confirm_file].bytes()
            {
                return Err(conflict());
            }
        }
        (None, Some(gateway), NativeDeploymentMode::CreateLocal) if stopped(gateway) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct GatewayReady {
                schema: u16,
                root_identity: NativeRootIdentity,
                scope_generation: Sha256Digest,
                deployment_raw_sha256: Sha256Digest,
                runtime: NativeRuntimeSelection,
                origin: String,
                not_before_unix: i64,
                not_after_unix: i64,
                files: std::collections::BTreeMap<String, Sha256Digest>,
            }
            let ready_file = held.capture("gateway-ready-v1.json", NATIVE_STATE_BYTES)?;
            let ready: GatewayReady =
                serde_json::from_slice(held.files[ready_file].bytes()).map_err(|_| invalid())?;
            let binding: Sha256Digest = serde_json::from_str(
                state
                    .extensions
                    .get("fresh_gateway_binding_v1")
                    .ok_or_else(invalid)?
                    .get(),
            )
            .map_err(|_| invalid())?;
            let names = [
                "gateway-ca.pem",
                "gateway-ca-key.pem",
                "gateway-chain.pem",
                "gateway-key.pem",
                "gateway-admin.token",
                "gateway-model.token",
            ];
            let origin = url::Url::parse(&ready.origin).map_err(|_| invalid())?;
            let deployment: serde_json::Value =
                serde_json::from_slice(held.files[deployment].bytes()).map_err(|_| invalid())?;
            let deployment_origin = deployment
                .get("gateway")
                .and_then(|v| v.get("url"))
                .and_then(|v| v.as_str())
                .ok_or_else(invalid)?;
            let deployment_origin = url::Url::parse(deployment_origin).map_err(|_| invalid())?;
            if ready.schema != 1
                || binding != Sha256Digest::of_bytes(held.files[ready_file].bytes())
                || ready.root_identity != transactions.marker().root_identity
                || ready.scope_generation != state.scope_generation
                || ready.deployment_raw_sha256 != state.deployment_raw_sha256
                || ready.runtime != bootstrap
                || ready.not_before_unix < 0
                || ready.not_after_unix <= ready.not_before_unix
                || origin.scheme() != "https"
                || origin.origin().ascii_serialization() != ready.origin
                || deployment_origin.origin().ascii_serialization() != ready.origin
                || ready.files.len() != names.len()
                || names.iter().any(|name| !ready.files.contains_key(*name))
            {
                return Err(conflict());
            }
            for name in names {
                let file = held.capture(name, NATIVE_STATE_BYTES)?;
                if ready.files[name] != Sha256Digest::of_bytes(held.files[file].bytes()) {
                    return Err(conflict());
                }
            }
        }
        _ => return Err(NativeManagementError::new(ErrorKind::Unsupported)),
    }
    held.validate()?;
    Ok(held)
}
