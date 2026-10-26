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
            select_in_scope(&path, &selection_file, id, sequence, None)
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
fn select_in_scope(
    path: &Path,
    selection_file: &Path,
    id: TransactionId,
    sequence: u64,
    scope: Option<&Arc<crate::app::HostScope>>,
) -> Result<RuntimeSelectionReport> {
    let raw = platform::private_file(selection_file, NATIVE_STATE_BYTES)?;
    let selected: NativeRuntimeSelection = serde_json::from_slice(raw.bytes())
        .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?;
    platform::use_managed_transactions(path, scope, |transactions| {
        platform::reconcile_complete_tip(transactions, scope.is_some())?;
        let state = transactions
            .readstate()
            .map_err(NativeManagementError::transaction)?;
        let initialized = require_initialized_profile(path, transactions, &state, scope)?;
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
        let committed = match scope {
            Some(scope) => transactions.update_runtime_for_app(
                old_release,
                new_release,
                id,
                sequence,
                scope.clone(),
            ),
            None => transactions.update_runtime(old_release, new_release, id, sequence),
        }
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
            configuration: platform::report(transactions, "runtime_select", Some(transaction))?,
            selected_manifest_sha256: selected.manifest_sha256,
            previous_manifest_sha256: previous.manifest_sha256,
            runtime_launched: false,
            operations_replayed: false,
        })
    })
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
    scope: Option<&Arc<crate::app::HostScope>>,
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
    platform::require_scope(path, scope)?;
    let manager = if scope.is_some() {
        NativeManager::AppManaged
    } else {
        NativeManager::ForegroundCli
    };
    let stopped = |d: &NativeComponentDesired| {
        d.manager == manager
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

/// The App's retained scope is required; no caller-selected manager or role.
pub(crate) async fn select_runtime_for_app(
    scope: Arc<crate::app::HostScope>,
    selection_file: &Path,
    transaction_id: &str,
    sequence: u64,
) -> Result<RuntimeSelectionReport> {
    let selection_file = selection_file.to_owned();
    let transaction_id = transaction_id.to_owned();
    let report_id = parse_transaction_id(&transaction_id).ok();
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    return app_blocking(scope, move |scope| {
        let id = parse_transaction_id(&transaction_id)?;
        if sequence == 0 {
            return Err(NativeManagementError::new(ErrorKind::Invalid));
        }
        select_in_scope(
            scope.state_dir(),
            &selection_file,
            id,
            sequence,
            Some(scope),
        )
    })
    .await
    .map_err(|mut error| {
        error.runtime_update_transaction = report_id;
        error
    });
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = (selection_file, transaction_id, sequence);
        Err(NativeManagementError::new(ErrorKind::Unsupported).with_app_scope(scope))
    }
}

#[derive(Serialize)]
pub(crate) struct AppRuntimeStatus {
    pub configuration: NativeManagementReport,
    pub current_selection: NativeRuntimeSelection,
    pub next_sequence: u64,
    pub pending_transaction: Option<NativeTransactionReport>,
}
/// Data projection only. A retained error is borrowed: never dropped or reopened.
pub(crate) fn runtime_status_for_app(
    scope: &Arc<crate::app::HostScope>,
    transaction_id: Option<&str>,
    retained: Option<&NativeManagementError>,
) -> Result<AppRuntimeStatus> {
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        let id = transaction_id.map(parse_transaction_id).transpose()?;
        let project = |transactions: &NativeTransactions| -> Result<AppRuntimeStatus> {
            platform::require_scope(scope.state_dir(), Some(scope))?;
            let state = transactions
                .readstate()
                .map_err(NativeManagementError::transaction)?;
            platform::require_state(state.state(), true)?;
            if state.state().has_migration_binding()
                || state
                    .state()
                    .desired
                    .host
                    .iter()
                    .chain(state.state().desired.gateway.iter())
                    .count()
                    != 1
            {
                return Err(NativeManagementError::new(ErrorKind::Unsupported));
            }
            let pending = transactions
                .pending_app_transaction()
                .map_err(NativeManagementError::transaction)?;
            let pending_transaction = pending
                .as_ref()
                .map(|id| platform::observed(transactions, id))
                .transpose()?;
            let transaction = match id.as_ref() {
                Some(id)
                    if transactions
                        .query(id)
                        .map_err(NativeManagementError::transaction)?
                        .is_some() =>
                {
                    Some(platform::observed(transactions, id)?)
                }
                _ => None,
            };
            Ok(AppRuntimeStatus {
                configuration: platform::report(transactions, "app_runtime_status", transaction)?,
                current_selection: state
                    .state()
                    .runtime_selection()
                    .map_err(|_| NativeManagementError::new(ErrorKind::Invalid))?
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
                pending_transaction,
                next_sequence: transactions
                    .runtime_update_high_water()
                    .map_err(NativeManagementError::transaction)?
                    .checked_add(1)
                    .ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?,
            })
        };
        if let Some(error) = retained {
            if error
                ._app_scope
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, scope))
            {
                return Err(NativeManagementError::new(ErrorKind::Conflict));
            }
            return match error._retained.as_ref() {
                Some(Retained::Transactions { _owner }) => project(_owner),
                _ => Err(NativeManagementError::new(ErrorKind::Conflict)),
            };
        }
        platform::use_managed_transactions(scope.state_dir(), Some(scope), |tx| {
            if let Some(id) = tx
                .pending_app_transaction()
                .map_err(NativeManagementError::transaction)?
            {
                let mut error = NativeManagementError::new(ErrorKind::Unknown);
                error.runtime_update_transaction = Some(id);
                return Err(error);
            }
            platform::reconcile_complete_tip(tx, true)?;
            project(tx)
        })
        .map_err(|e| e.with_app_scope(scope.clone()))
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = (transaction_id, retained);
        Err(NativeManagementError::new(ErrorKind::Unsupported).with_app_scope(scope.clone()))
    }
}

/// Only the exact original error/coordinator is consumed. Invalid inputs return
/// it still owning the writer, scope and any RuntimeUpdateCustody.
pub(crate) async fn recover_runtime_for_app(
    scope: Arc<crate::app::HostScope>,
    transaction_id: &str,
    retained: Option<NativeManagementError>,
) -> Result<NativeManagementReport> {
    recover_app_transaction(scope, transaction_id, retained, true).await
}
/// Original App desired/update C07 only. The App supplies the exact ID from its
/// immutable approved update input; no public command or migration fallback.
pub(crate) async fn recover_transaction_for_app(
    scope: Arc<crate::app::HostScope>,
    transaction_id: &str,
    retained: Option<NativeManagementError>,
) -> Result<NativeManagementReport> {
    recover_app_transaction(scope, transaction_id, retained, false).await
}
async fn recover_app_transaction(
    scope: Arc<crate::app::HostScope>,
    transaction_id: &str,
    retained: Option<NativeManagementError>,
    runtime_only: bool,
) -> Result<NativeManagementReport> {
    let id = match parse_transaction_id(transaction_id) {
        Ok(id) => id,
        Err(e) => return Err(retained.unwrap_or(e)),
    };
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        // Acquire before moving a retained error into a cancellable waiter. A
        // Busy response must not drop its original coordinator with the closure.
        let permit = match WORKERS.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                return Err(retained.unwrap_or_else(|| {
                    NativeManagementError::new(ErrorKind::Busy).with_app_scope(scope.clone())
                }));
            }
        };
        let output_scope = scope.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Some(mut error) = retained {
                if error
                    ._app_scope
                    .as_ref()
                    .is_none_or(|s| !Arc::ptr_eq(s, &scope))
                {
                    error.kind = ErrorKind::Conflict;
                    return Err(error);
                }
                if let Err(next) = platform::require_scope(scope.state_dir(), Some(&scope)) {
                    error.kind = next.kind;
                    return Err(error);
                }
                let mut _owner = match error._retained.take() {
                    Some(Retained::Transactions { _owner }) => _owner,
                    other => {
                        error._retained = other;
                        error.kind = ErrorKind::Conflict;
                        return Err(error);
                    }
                };
                let result = recover_app_in_place(&scope, &id, &mut _owner, runtime_only);
                return result.map_err(|mut next| {
                    next.runtime_update_transaction = error.runtime_update_transaction;
                    next.keep(*_owner).with_app_scope(scope)
                });
            }
            platform::use_managed_transactions(scope.state_dir(), Some(&scope), |tx| {
                recover_app_in_place(&scope, &id, tx, runtime_only)
            })
            .map_err(|mut e| {
                e.runtime_update_transaction = Some(id);
                e.with_app_scope(scope)
            })
        })
        .await
        .map_err(|_| NativeManagementError::new(ErrorKind::Unknown).with_app_scope(output_scope))?
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = (id, runtime_only);
        Err(retained.unwrap_or_else(|| {
            NativeManagementError::new(ErrorKind::Unsupported).with_app_scope(scope)
        }))
    }
}
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "windows"
))]
fn recover_app_in_place(
    scope: &Arc<crate::app::HostScope>,
    id: &TransactionId,
    tx: &mut NativeTransactions,
    runtime_only: bool,
) -> Result<NativeManagementReport> {
    platform::require_scope(scope.state_dir(), Some(scope))?;
    let state = tx.readstate().map_err(NativeManagementError::transaction)?;
    platform::require_state(state.state(), true)?;
    if state.state().has_migration_binding() {
        return Err(NativeManagementError::new(ErrorKind::Unsupported));
    }
    let (before, target) = tx
        .original_desired(id)
        .map_err(NativeManagementError::transaction)?;
    for desired in [&before, &target] {
        let roles: Vec<_> = desired.host.iter().chain(desired.gateway.iter()).collect();
        if roles.len() != 1
            || roles[0].manager != NativeManager::AppManaged
            || roles[0].autostart != NativeAutostartDesired::Disabled
        {
            return Err(NativeManagementError::new(ErrorKind::Unsupported));
        }
    }
    let update_selections = tx
        .runtime_update_selections(id)
        .map_err(NativeManagementError::transaction)?;
    let committed = if update_selections.is_none() {
        if runtime_only || tx.has_runtime_update_custody() {
            return Err(NativeManagementError::new(ErrorKind::Conflict));
        }
        tx.recover_original(id)
    } else if tx.has_runtime_update_custody() {
        tx.recover_retained_runtime_update_for_app(scope, id)
    } else {
        let (before, target) =
            update_selections.ok_or_else(|| NativeManagementError::new(ErrorKind::Invalid))?;
        let previous = crate::release::verify_selected(&before)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        let selected = crate::release::verify_selected(&target)
            .map_err(|_| NativeManagementError::new(ErrorKind::Unknown))?;
        tx.recover_runtime_update_for_app(previous, selected, id, scope.clone())
    }
    .map_err(NativeManagementError::transaction)?;
    platform::require_scope(scope.state_dir(), Some(scope))?;
    platform::report(
        tx,
        "app_runtime_recover",
        Some(NativeTransactionReport {
            transaction_id: committed.transaction_id,
            sequence: committed.committed.sequence,
            observed_stage: Some(DurableStage::Committed),
            receipt: Some(committed.committed),
            recovered: committed.recovered,
        }),
    )
}
