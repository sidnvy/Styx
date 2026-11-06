//! Current read-only startup observation. Recovery and mutations keep their
//! original coordinators; a historical observation never resumes a transaction.
use super::runtime_update::{OriginalInput, SelectionPin, root_digest, same_file};
use super::*;
use crate::store::{management::ManagementInventory, native_host_snapshot::NativeHostSnapshot};
use std::collections::BTreeSet;
use styx_contracts::{identity::TransactionId, management::DurableStage};

fn committed(inventory: &ManagementInventory, id: &TransactionId, sequence: u64) -> bool {
    inventory.orphans.is_empty()
        && inventory.transactions.iter().any(|transaction| {
            transaction.intent.transaction_id == *id
                && transaction.intent.sequence == sequence
                && transaction
                    .phase_receipts
                    .last()
                    .is_some_and(|receipt| receipt.stage == DurableStage::Committed)
        })
}
fn names(path: &Path) -> Result<BTreeSet<std::ffi::OsString>, AppError> {
    let mut names = BTreeSet::new();
    for entry in
        std::fs::read_dir(path).map_err(|_| AppError("app_runtime_original_input_invalid"))?
    {
        if names.len() >= 64 {
            return Err(AppError("app_runtime_input_budget"));
        }
        names.insert(
            entry
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?
                .file_name(),
        );
    }
    Ok(names)
}
impl HostApp {
    fn completed_runtime_history(&self, profile: &NativeHostSnapshot) -> Result<bool, AppError> {
        if self
            .scope
            .container
            .parent
            .ensure_absent("runtime-updates")
            .is_ok()
        {
            return Ok(true);
        }
        let directory = self.scope.container.parent_path.join("runtime-updates");
        let held = PrivateRoot::open(&directory)
            .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
        let original_names = names(&directory)?;
        let inventory = profile
            .management_inventory()
            .map_err(|_| AppError("app_startup_observation_changed"))?;
        let container = root_digest(&self.scope.container.parent)?;
        let root = root_digest(
            self.scope
                .root
                .get()
                .ok_or(AppError("app_not_configured"))?,
        )?;
        let mut inputs = Vec::new();
        let mut selections = Vec::new();
        for name in &original_names {
            let name = name
                .to_str()
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            let id = name
                .strip_suffix(".json")
                .and_then(|id| TransactionId::try_from(id).ok())
                .ok_or(AppError("app_runtime_original_input_invalid"))?;
            let raw = held
                .read_raw(name, 65536)
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            let input: OriginalInput = serde_json::from_slice(raw.bytes())
                .map_err(|_| AppError("app_runtime_original_input_invalid"))?;
            input.validate_shape(&id)?;
            // Split local Gateway updates retain the old, original recovery
            // path. This current-state shortcut handles the single-Host App.
            if input.roles.len() != 1 {
                return Ok(false);
            }
            let role = &input.roles[0];
            if input.container_sha256 != container || role.root_sha256 != root || role.gateway {
                return Err(AppError("app_runtime_original_input_changed"));
            }
            let selection = SelectionPin::open(
                &self
                    .scope
                    .container
                    .parent_path
                    .join("runtime-versions")
                    .join(&input.selection_file),
            )?;
            if selection.selection != input.selection
                || styx_contracts::identity::Sha256Digest::of_bytes(selection.file.bytes())
                    != input.selection_sha256
            {
                return Err(AppError("app_runtime_original_input_changed"));
            }
            if !committed(&inventory, &role.select_transaction, role.select_sequence) {
                return Ok(false);
            }
            inputs.push(raw);
            selections.push(selection);
        }
        // The one validated journal observation is DATA. Detect any change to
        // its namespace, original inputs or original selection files before use.
        if names(&directory)? != original_names
            || PrivateRoot::open(&directory)
                .map_err(|_| AppError("app_runtime_original_input_changed"))?
                .identity()
                != held.identity()
        {
            return Err(AppError("app_runtime_original_input_changed"));
        }
        for input in &inputs {
            same_file(&held, input)?;
        }
        for selection in &selections {
            selection.validate()?;
        }
        profile
            .revalidate()
            .map_err(|_| AppError("app_startup_observation_changed"))?;
        self.scope.validate()?;
        Ok(true)
    }
    pub(super) async fn try_ready_startup(&mut self) -> Result<bool, AppError> {
        // Existing service clients and split local Gateway composition keep
        // their original path. No sibling is created or paired here.
        if self.scope.gateway_sibling()?.root.get().is_some() {
            return Ok(false);
        }
        if let Some(d) = &self.startup_diagnostic {
            d.report("app_current_observation_begin");
        }
        let scope = self.scope.clone();
        let profile = match tokio::task::spawn_blocking(move || {
            NativeHostSnapshot::observe_for_app(scope.state_dir(), scope.clone())
        })
        .await
        {
            Ok(Ok(profile)) => Arc::new(profile),
            // Incomplete/pending roots enter the original full inspector and
            // original recovery/fencing path; no cached success substitutes it.
            _ => return Ok(false),
        };
        if !self.completed_runtime_history(&profile)? {
            return Ok(false);
        }
        let state = profile.canonical();
        self.configuration = Some(native::NativeManagementReport {
            schema: 1,
            configuration_only: true,
            operation: "app_current_observation",
            runtime_health: "not_observed",
            revision: state.state().revision,
            canonical_state_sha256: state.raw_sha256(),
            desired: state.state().desired.clone(),
            // observe_for_app requires the entire completed canonical C07 chain.
            admission_fenced: false,
            transaction: None,
        });
        match native_join::inspect_for_app_retained(self.scope.clone(), profile.verified_release())
            .await
        {
            Ok(report) => {
                if profile.revalidate().is_err() {
                    self.unknown = true;
                    self.enrollment = Some(
                        json!({"status":"incomplete","error":"app_startup_observation_changed"}),
                    );
                    return Ok(true);
                }
                self.native_computer_requested = Some(report.computer_requested);
                self.native_runtime = Some(report.verified_runtime.clone());
                self.enrollment = Some(
                    serde_json::to_value(report).map_err(|_| AppError("app_response_invalid"))?,
                );
                self.startup_profile = Some(profile);
            }
            Err(error) => {
                let code = self.join_error(error).code();
                self.unknown = true;
                self.enrollment = Some(json!({"status":"incomplete","error":code}));
            }
        }
        if let Some(d) = &self.startup_diagnostic {
            d.report("app_current_observation_ready");
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::management::ManagementTransactionObservation;
    use styx_contracts::{
        identity::Sha256Digest,
        management::{DesiredStateCommit, JournalReceipt, ReaderContract},
    };

    #[test]
    fn history_observation_never_treats_pending_unknown_or_another_assignment_as_complete() {
        let id: TransactionId = "startup-history-host-select".try_into().unwrap();
        let other: TransactionId = "other-host-select".try_into().unwrap();
        let mut inventory = ManagementInventory {
            high_water: 7,
            transactions: vec![ManagementTransactionObservation {
                intent: DesiredStateCommit {
                    transaction_id: id.clone(),
                    sequence: 7,
                    deployment_raw_sha256: Sha256Digest::of_bytes(b"deployment"),
                    before_state_sha256: Sha256Digest::of_bytes(b"before"),
                    target_state_sha256: Sha256Digest::of_bytes(b"after"),
                    reader: ReaderContract::NativeAppRuntimeSelectedStateV1,
                },
                prepared: None,
                phase_receipts: Vec::new(),
            }],
            orphans: Vec::new(),
        };
        for stage in [
            DurableStage::Prepared,
            DurableStage::Applied,
            DurableStage::Verified,
        ] {
            inventory.transactions[0].phase_receipts = vec![JournalReceipt {
                transaction_id: id.clone(),
                sequence: 7,
                stage,
                previous: None,
                record_sha256: Sha256Digest::of_bytes(b"observed"),
            }];
            assert!(!committed(&inventory, &id, 7));
        }
        inventory.transactions[0].phase_receipts[0].stage = DurableStage::Committed;
        assert!(committed(&inventory, &id, 7));
        assert!(!committed(&inventory, &id, 8));
        assert!(!committed(&inventory, &other, 7));
        inventory.orphans.push("unsettled-original.tmp".into());
        assert!(!committed(&inventory, &id, 7));
    }

    #[cfg(unix)]
    #[test]
    fn history_original_pin_rejects_same_content_replacement_and_namespace_growth_is_bounded() {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        };
        let path =
            std::env::temp_dir().join(format!("styx-startup-observe-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let create = |name: &str| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))
                .unwrap();
            f.write_all(b"original read-only input").unwrap();
        };
        create("original.json");
        let held = PrivateRoot::open(&path).unwrap();
        let raw = held.read_raw("original.json", 65536).unwrap();
        assert!(same_file(&held, &raw).is_ok());
        fs::rename(path.join("original.json"), path.join("retained.json")).unwrap();
        create("original.json");
        assert!(same_file(&held, &raw).is_err());
        let before = names(&path).unwrap();
        create("added.json");
        assert_ne!(names(&path).unwrap(), before);
        for index in 0..61 {
            create(&format!("entry-{index}.json"));
        }
        assert_eq!(names(&path).unwrap().len(), 64);
        create("over-budget.json");
        assert!(names(&path).is_err());
        drop(raw);
        drop(held);
        fs::remove_dir_all(path).unwrap();
    }
}
