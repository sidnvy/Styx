//! Read-only App startup projection. No writer, namespace creation or recovery
//! capability is acquired; a transaction id is only an observed original id.
use super::secure_journal::JournalResult;
use std::sync::Arc;

pub(crate) enum AppMigrationObservation {
    NotMigration,
    #[cfg(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    ))]
    Required,
    #[cfg(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    ))]
    Pending {
        transaction_id: String,
    },
    #[cfg(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    ))]
    Blocked {
        code: &'static str,
    },
}

pub(crate) fn observe(scope: Arc<crate::app::HostScope>) -> JournalResult<AppMigrationObservation> {
    #[cfg(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    ))]
    {
        platform::observe(&scope)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(test, target_os = "linux", target_env = "gnu")
    )))]
    {
        let _ = scope;
        Ok(AppMigrationObservation::NotMigration)
    }
}

#[cfg(any(
    target_os = "macos",
    all(test, target_os = "linux", target_env = "gnu")
))]
mod platform {
    use super::*;
    use crate::store::{
        PrivateRoot, RawFile, StoreError, management,
        native_root::NATIVE_MARKER_FILE,
        secure_journal::{JournalBudget, JournalError, JournalObservation, files},
    };
    use std::{collections::BTreeSet, fs::File, os::unix::fs::MetadataExt};
    use styx_core::management::transaction::DurableStage;

    const NAMESPACE: &str = ".styx-management-journal-v1";
    const LIMIT: usize = 1024 * 1024;
    fn blocked(code: &'static str) -> AppMigrationObservation {
        AppMigrationObservation::Blocked { code }
    }
    fn optional(root: &PrivateRoot, name: &str) -> JournalResult<Option<RawFile>> {
        if root.ensure_absent(name).is_ok() {
            return Ok(None);
        }
        root.read_raw(name, LIMIT)
            .map(Some)
            .map_err(|_| JournalError::Unknown)
    }
    fn identity(file: &File) -> JournalResult<(u64, u64)> {
        let metadata = file.metadata().map_err(|_| JournalError::Unknown)?;
        Ok((metadata.dev(), metadata.ino()))
    }
    fn same_scan(a: &JournalObservation, b: &JournalObservation) -> bool {
        a.total_bytes == b.total_bytes
            && a.files.len() == b.files.len()
            && a.files
                .iter()
                .zip(&b.files)
                .all(|(a, b)| a.name == b.name && a.bytes() == b.bytes())
    }
    fn same_input(a: &Option<RawFile>, b: &Option<RawFile>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => a.bytes() == b.bytes() && a.observation() == b.observation(),
            _ => false,
        }
    }
    pub(super) fn observe(scope: &crate::app::HostScope) -> JournalResult<AppMigrationObservation> {
        scope.validate().map_err(|_| JournalError::Unknown)?;
        let root = match PrivateRoot::open(scope.state_dir()) {
            Ok(root) => root,
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                scope.validate().map_err(|_| JournalError::Unknown)?;
                return Ok(AppMigrationObservation::NotMigration);
            }
            Err(_) => return Ok(blocked("migration_root_invalid")),
        };
        let original_root = root.identity();
        let marker = optional(&root, NATIVE_MARKER_FILE)?;
        let deployment = optional(&root, "deployment.json")?;
        let state = optional(&root, "state.json")?;
        let namespace = if root.ensure_absent(NAMESPACE).is_ok() {
            None
        } else {
            Some(
                root.inner
                    .with_readonly_directory(|dir| Ok(files::directory(dir, NAMESPACE)))
                    .map_err(|_| JournalError::Unknown)??,
            )
        };
        let namespace_id = namespace.as_ref().map(identity).transpose()?;
        let scan = namespace
            .as_ref()
            .map(|dir| files::scan(dir, JournalBudget::default()))
            .transpose()?;
        let result = classify(
            marker.as_ref(),
            deployment.as_ref(),
            state.as_ref(),
            scan.as_ref(),
        );
        // Reopen named protected inputs and namespace, not just the held FDs.
        if root.identity() != original_root
            || PrivateRoot::open(scope.state_dir())
                .map_err(|_| JournalError::Unknown)?
                .identity()
                != original_root
            || !same_input(&marker, &optional(&root, NATIVE_MARKER_FILE)?)
            || !same_input(&deployment, &optional(&root, "deployment.json")?)
            || !same_input(&state, &optional(&root, "state.json")?)
        {
            return Err(JournalError::Unknown);
        }
        match (&namespace, &scan, namespace_id) {
            (Some(held), Some(before), Some(id)) => {
                let named = root
                    .inner
                    .with_readonly_directory(|dir| Ok(files::directory(dir, NAMESPACE)))
                    .map_err(|_| JournalError::Unknown)??;
                if identity(held)? != id
                    || identity(&named)? != id
                    || !same_scan(before, &files::scan(&named, JournalBudget::default())?)
                {
                    return Err(JournalError::Unknown);
                }
            }
            (None, None, None) => root
                .ensure_absent(NAMESPACE)
                .map_err(|_| JournalError::Unknown)?,
            _ => return Err(JournalError::Unknown),
        }
        root.inner
            .with_readonly_directory(|_| Ok(()))
            .map_err(|_| JournalError::Unknown)?;
        scope.validate().map_err(|_| JournalError::Unknown)?;
        result
    }
    fn native_transaction(
        raw: &[u8],
        marker: &crate::store::native_state::NativeRootMarker,
    ) -> JournalResult<String> {
        let canonical = crate::store::native_state::decode_state(raw, marker)
            .map_err(|_| JournalError::Conflict)?;
        let state = canonical.state();
        match state.migration_v2().map_err(|_| JournalError::Conflict)? {
            Some(binding) => Ok(binding.transaction_id.as_str().to_owned()),
            None => state
                .migration
                .as_ref()
                .map(|binding| binding.transaction_id.as_str().to_owned())
                .ok_or(JournalError::Conflict),
        }
    }
    fn classify(
        marker: Option<&RawFile>,
        deployment: Option<&RawFile>,
        state: Option<&RawFile>,
        scan: Option<&JournalObservation>,
    ) -> JournalResult<AppMigrationObservation> {
        if let Some(raw) = marker
            && crate::store::native_state::decode_marker(raw.bytes()).is_err()
        {
            return Ok(blocked("migration_native_marker_invalid"));
        }
        let mut ids = BTreeSet::new();
        let mut committed = false;
        if let Some(scan) = scan {
            let inventory = match management::readonly_inventory(scan) {
                Ok(inventory) if inventory.orphans.is_empty() => inventory,
                _ => return Ok(blocked("migration_journal_invalid")),
            };
            for (id, _, _) in &inventory.migration_plans {
                ids.insert(id.as_str().to_owned());
            }
            for (id, _, _) in &inventory.owner_recoveries {
                ids.insert(id.as_str().to_owned());
            }
            for handoff in &inventory.handoffs {
                ids.insert(handoff.transaction_id.as_str().to_owned());
            }
            let cutovers = management::cutover::scan_cutovers(scan)?;
            for original in &cutovers.records {
                ids.insert(original.intent.transaction_id.as_str().to_owned());
            }
            for original in &cutovers.native_records {
                ids.insert(original.intent.transaction_id.as_str().to_owned());
            }
            committed = inventory.committed_cutover_anchor.is_some()
                && !inventory.has_unresolved_legacy_handoffs();
            if ids.len() > 1 {
                return Ok(blocked("migration_transaction_ambiguous"));
            }
            if ids.is_empty()
                && inventory.transactions.iter().any(|t| {
                    t.phase_receipts
                        .last()
                        .is_none_or(|p| p.stage != DurableStage::Committed)
                })
            {
                return Ok(blocked("migration_unrelated_transaction_pending"));
            }
        }
        if committed {
            return Ok(AppMigrationObservation::NotMigration);
        }
        if let Some(transaction_id) = ids.into_iter().next() {
            let (Some(deployment), Some(state)) = (deployment, state) else {
                return Ok(blocked("migration_original_inputs_incomplete"));
            };
            let deployment: serde_json::Value = match serde_json::from_slice(deployment.bytes()) {
                Ok(value) => value,
                Err(_) => return Ok(blocked("migration_original_format_invalid")),
            };
            if deployment.get("schema").and_then(|v| v.as_u64()) != Some(1) {
                return Ok(blocked("migration_original_format_invalid"));
            }
            if let Some(marker_raw) = marker {
                let marker = crate::store::native_state::decode_marker(marker_raw.bytes())
                    .map_err(|_| JournalError::Conflict)?;
                let current = native_transaction(state.bytes(), &marker);
                if !current.is_ok_and(|id| id == transaction_id) {
                    // Marker publication precedes canonical rename. Only the
                    // exact validated original Prepared before-image may still
                    // be legacy here; arbitrary schema1 bytes are not fallback.
                    let cutovers =
                        management::cutover::scan_cutovers(scan.ok_or(JournalError::Conflict)?)?;
                    let before_transition = cutovers.native_records.iter().any(|original| {
                        original.intent.transaction_id.as_str() == transaction_id
                            && matches!(
                                original.last_stage,
                                DurableStage::Planned | DurableStage::Prepared
                            )
                            && original.marker == marker_raw.bytes()
                            && original.before == state.bytes()
                            && native_transaction(&original.target, &marker)
                                .is_ok_and(|id| id == transaction_id)
                    });
                    if !before_transition {
                        return Ok(blocked("migration_native_binding_mismatch"));
                    }
                }
            } else {
                let state: serde_json::Value = match serde_json::from_slice(state.bytes()) {
                    Ok(value) => value,
                    Err(_) => return Ok(blocked("migration_original_format_invalid")),
                };
                if state.get("schema").and_then(|v| v.as_u64()) != Some(1)
                    || state.get("mode") != deployment.get("mode")
                {
                    return Ok(blocked("migration_original_format_invalid"));
                }
            }
            return Ok(AppMigrationObservation::Pending { transaction_id });
        }
        if let Some(raw) = marker {
            let marker = crate::store::native_state::decode_marker(raw.bytes())
                .map_err(|_| JournalError::Conflict)?;
            let Some(state) = state else {
                return Ok(blocked("migration_native_state_missing"));
            };
            let canonical = match crate::store::native_state::decode_state(state.bytes(), &marker) {
                Ok(canonical) => canonical,
                Err(_) => return Ok(blocked("migration_native_state_invalid")),
            };
            if canonical.state().has_migration_binding() {
                return Ok(blocked("migration_original_transaction_missing"));
            }
            // Fresh native format remains subject to its full ordinary reader;
            // this observer never grants ordinary admission.
            return Ok(AppMigrationObservation::NotMigration);
        }
        match (deployment, state) {
            (None, None) => Ok(AppMigrationObservation::NotMigration),
            (Some(deployment), Some(state)) => {
                let parse =
                    |raw: &RawFile| serde_json::from_slice::<serde_json::Value>(raw.bytes()).ok();
                match (parse(deployment), parse(state)) {
                    (Some(d), Some(s))
                        if d.get("schema").and_then(|v| v.as_u64()) == Some(1)
                            && s.get("schema").and_then(|v| v.as_u64()) == Some(1)
                            && matches!(
                                d.get("mode").and_then(|v| v.as_str()),
                                Some("join-existing" | "create-local")
                            )
                            && s.get("mode") == d.get("mode") =>
                    {
                        Ok(AppMigrationObservation::Required)
                    }
                    _ => Ok(blocked("migration_original_format_invalid")),
                }
            }
            _ => Ok(blocked("migration_original_inputs_incomplete")),
        }
    }
}
