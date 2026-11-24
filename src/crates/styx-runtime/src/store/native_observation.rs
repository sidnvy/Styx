//! Coherent existing-only C07 DATA. No lock acquisition, recovery or write.
use super::secure_journal::{JournalBudget, JournalError, JournalResult, files};
use super::{PrivateRoot, management, native_root, native_state};
use std::path::Path;
use styx_contracts::identity::Sha256Digest;

pub(crate) struct NativeObservation {
    pub(crate) canonical: native_state::ValidatedNativeState,
    pub(crate) inventory: management::ManagementInventory,
}
pub(crate) fn read(path: &Path) -> JournalResult<NativeObservation> {
    const NS: &str = ".styx-management-journal-v1";
    const MAX: usize = 1024 * 1024;
    let root = PrivateRoot::open(path).map_err(|_| JournalError::Unknown)?;
    let mut pins = Vec::new();
    for name in [
        ".styx-native-root-v1.json",
        "state.json",
        "deployment.json",
        ".styx-configuration-writer.lock",
    ] {
        pins.push(
            root.read_raw(name, MAX)
                .map_err(|_| JournalError::Unknown)?,
        );
    }
    let marker =
        native_state::decode_marker(pins[0].bytes()).map_err(|_| JournalError::Conflict)?;
    if !native_root::same_identity(&root.identity(), &marker) {
        return Err(JournalError::Conflict);
    }
    let canonical =
        native_state::decode_state(pins[1].bytes(), &marker).map_err(|_| JournalError::Conflict)?;
    if canonical.state().deployment_raw_sha256 != Sha256Digest::of_bytes(pins[2].bytes()) {
        return Err(JournalError::Conflict);
    }
    root.inner
        .with_readonly_directory(|directory| {
            let result = (|| {
                let namespace = files::directory(directory, NS)?;
                let identity = super::native_host_snapshot::directory_identity(&namespace)?;
                let scan = files::scan(&namespace, JournalBudget::default())?;
                let inventory = management::readonly_inventory(&scan)?;
                management::validate_observed_native_tip(&scan, &canonical, &marker, &inventory)?;
                for file in &scan.files {
                    let raw = root
                        .read_raw(format!("{NS}/{}", file.name), MAX)
                        .map_err(|_| JournalError::Unknown)?;
                    if raw.bytes() != file.bytes() {
                        return Err(JournalError::Unknown);
                    }
                    pins.push(raw);
                }
                let after = files::scan(&namespace, JournalBudget::default())?;
                let current_namespace = files::directory(directory, NS)?;
                if super::native_host_snapshot::directory_identity(&current_namespace)? != identity
                    || super::native_host_snapshot::directory_identity(&namespace)? != identity
                    || scan.files.len() != after.files.len()
                    || scan
                        .files
                        .iter()
                        .zip(&after.files)
                        .any(|(a, b)| a.name != b.name || a.bytes() != b.bytes())
                {
                    return Err(JournalError::Unknown);
                }
                for pin in &pins {
                    let after = root
                        .read_raw(pin.relative_path(), MAX)
                        .map_err(|_| JournalError::Unknown)?;
                    if after.observation() != pin.observation() || after.bytes() != pin.bytes() {
                        return Err(JournalError::Unknown);
                    }
                }
                if PrivateRoot::open(path)
                    .map_err(|_| JournalError::Unknown)?
                    .identity()
                    != root.identity()
                {
                    return Err(JournalError::Unknown);
                }
                Ok(NativeObservation {
                    canonical,
                    inventory,
                })
            })();
            Ok(result)
        })
        .map_err(|_| JournalError::Unknown)?
}
