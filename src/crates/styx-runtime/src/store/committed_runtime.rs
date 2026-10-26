//! Fresh-process, read-only committed runtime observation. This acquires no
//! writer, grants no admission, and cannot manufacture a live cutover proof.
use super::management::{cutover, handoff};
use super::secure_journal::{
    JournalBudget, JournalError, JournalObservation, JournalResult, files,
};
use super::{FileObservation, PrivateRoot, RootIdentity};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
use styx_contracts::{
    identity::Sha256Digest,
    native_management::{NativeRuntimeSelection, NativeState},
};
use styx_core::management::transaction::DurableStage;

const NAMESPACE: &str = ".styx-management-journal-v1";
const MAX: usize = 1024 * 1024;
struct Pin {
    path: String,
    observation: FileObservation,
    digest: Sha256Digest,
}
/// No Debug/Serde: original attachments can contain private material.
pub(crate) struct CommittedRuntimeSnapshot {
    root: PrivateRoot,
    namespace: File,
    namespace_identity: (u64, u64),
    pins: Vec<Pin>,
    original: cutover::OriginalCutover,
    retirement: handoff::ObservedRetirement,
    state: NativeState,
    canonical: Vec<u8>,
    selection: NativeRuntimeSelection,
}
impl CommittedRuntimeSnapshot {
    pub(crate) fn open(state_dir: &Path) -> JournalResult<Self> {
        if !state_dir.is_absolute() {
            return Err(JournalError::InvalidInput);
        }
        let root = PrivateRoot::open(state_dir).map_err(|_| JournalError::Unknown)?;
        let namespace = root
            .inner
            .with_readonly_directory(|directory| Ok(files::directory(directory, NAMESPACE)))
            .map_err(|_| JournalError::Unknown)??;
        let metadata = namespace.metadata().map_err(|_| JournalError::Unknown)?;
        let namespace_identity = (metadata.dev(), metadata.ino());
        let scan = files::scan(&namespace, JournalBudget::default())?;
        let parsed = cutover::scan_cutovers(&scan)?;
        let id = parsed
            .records
            .first()
            .ok_or(JournalError::Conflict)?
            .intent
            .transaction_id
            .clone();
        let original = cutover::original(&scan, &id)?;
        if original.intent.schema != 2
            || original.last_stage != DurableStage::Committed
            || original.validation_report().is_none()
            || original.paired_validation_report().is_none()
        {
            return Err(JournalError::Conflict);
        }
        cutover::check_committed_successor_root(&root, &original, &scan)?;
        let marker = super::native_state::decode_marker(&original.marker)
            .map_err(|_| JournalError::Conflict)?;
        let canonical = root
            .read_raw("state.json", MAX)
            .map_err(|_| JournalError::Unknown)?
            .bytes()
            .to_vec();
        let state = super::native_state::decode_state(&canonical, &marker)
            .map_err(|_| JournalError::Conflict)?;
        let state = state.state().clone();
        let migration = state.migration.as_ref().ok_or(JournalError::Conflict)?;
        let selection: NativeRuntimeSelection = serde_json::from_str(
            state
                .extensions
                .get("runtime_selection_v1")
                .ok_or(JournalError::Conflict)?
                .get(),
        )
        .map_err(|_| JournalError::Conflict)?;
        if selection.schema != 1
            || selection.manifest_sha256 != original.intent.candidate_manifest_sha256
            || selection.publisher_spki_sha256 != original.intent.publisher_spki_sha256
            || selection.manifest_sha256 != migration.candidate_manifest_sha256
            || selection.publisher_spki_sha256 != migration.publisher_spki_sha256
            || !absolute_locator(&selection.payload_path)
            || !absolute_locator(&selection.publisher_file)
        {
            return Err(JournalError::Conflict);
        }
        let baseline_raw = root
            .read_raw(
                ".styx-enrollment-journal-v1/historical-baseline.intent",
                MAX,
            )
            .map_err(|_| JournalError::Unknown)?;
        let baseline = styx_contracts::historical_enrollment::decode(baseline_raw.bytes())
            .map_err(|_| JournalError::Conflict)?;
        let journal_root = baseline
            .journal_root()
            .map_err(|_| JournalError::Conflict)?;
        let RootIdentity::Linux { device, inode, uid } = root.identity();
        if baseline.schema != 2
            || baseline.migration != id
            || journal_root
                != &(styx_contracts::historical_enrollment::SourceRoot::Linux {
                    device,
                    inode,
                    uid,
                })
        {
            return Err(JournalError::Conflict);
        }
        let mut retirements = handoff::scan_handoffs(&scan)?.records;
        if retirements.len() != 1 {
            return Err(JournalError::Conflict);
        }
        let retirement = retirements.pop().ok_or(JournalError::Conflict)?;
        let mut pins = capture_journal(&root, &scan)?;
        for path in [
            "deployment.json",
            "state.json",
            ".styx-native-root-v1.json",
            ".styx-enrollment-journal-v1/historical-baseline.intent",
            ".styx-enrollment-journal-v1/historical-baseline.committed",
        ] {
            let raw = root
                .read_raw(path, MAX)
                .map_err(|_| JournalError::Unknown)?;
            pins.push(Pin {
                path: path.into(),
                observation: raw.observation().clone(),
                digest: Sha256Digest::of_bytes(raw.bytes()),
            });
        }
        let snapshot = Self {
            root,
            namespace,
            namespace_identity,
            pins,
            original,
            retirement,
            state,
            canonical,
            selection,
        };
        snapshot.revalidate()?;
        Ok(snapshot)
    }
    pub(crate) fn revalidate(&self) -> JournalResult<()> {
        self.root
            .inner
            .with_readonly_directory(|directory| {
                let result = (|| {
                    let current = files::directory(directory, NAMESPACE)?;
                    let metadata = current.metadata().map_err(|_| JournalError::Unknown)?;
                    let held = self
                        .namespace
                        .metadata()
                        .map_err(|_| JournalError::Unknown)?;
                    if (metadata.dev(), metadata.ino()) != self.namespace_identity
                        || (held.dev(), held.ino()) != self.namespace_identity
                        || held.nlink() == 0
                    {
                        return Err(JournalError::Unknown);
                    }
                    let scan = files::scan(&self.namespace, JournalBudget::default())?;
                    if scan.files.len() != self.pins.len().saturating_sub(5) {
                        return Err(JournalError::Conflict);
                    }
                    for pin in &self.pins {
                        let raw = self
                            .root
                            .read_raw(&pin.path, MAX)
                            .map_err(|_| JournalError::Unknown)?;
                        if raw.observation() != &pin.observation
                            || Sha256Digest::of_bytes(raw.bytes()) != pin.digest
                        {
                            return Err(JournalError::Unknown);
                        }
                    }
                    for file in &scan.files {
                        let path = format!("{NAMESPACE}/{}", file.name);
                        if !self.pins.iter().any(|p| {
                            p.path == path && p.digest == Sha256Digest::of_bytes(file.bytes())
                        }) {
                            return Err(JournalError::Unknown);
                        }
                    }
                    cutover::check_committed_successor_root(&self.root, &self.original, &scan)?;
                    let after = files::scan(&self.namespace, JournalBudget::default())?;
                    if after.files.len() != scan.files.len()
                        || after
                            .files
                            .iter()
                            .zip(&scan.files)
                            .any(|(a, b)| a.name != b.name || a.bytes() != b.bytes())
                    {
                        return Err(JournalError::Unknown);
                    }
                    // A same-bytes file/namespace replacement is still a changed
                    // original observation, not an acceptable cached selection.
                    for pin in &self.pins {
                        let raw = self
                            .root
                            .read_raw(&pin.path, MAX)
                            .map_err(|_| JournalError::Unknown)?;
                        if raw.observation() != &pin.observation
                            || Sha256Digest::of_bytes(raw.bytes()) != pin.digest
                        {
                            return Err(JournalError::Unknown);
                        }
                    }
                    let final_directory = files::directory(directory, NAMESPACE)?;
                    let final_metadata = final_directory
                        .metadata()
                        .map_err(|_| JournalError::Unknown)?;
                    if (final_metadata.dev(), final_metadata.ino()) != self.namespace_identity {
                        return Err(JournalError::Unknown);
                    }
                    Ok(())
                })();
                Ok(result)
            })
            .map_err(|_| JournalError::Unknown)?
    }
    pub(crate) fn state(&self) -> &NativeState {
        &self.state
    }
    pub(crate) fn before(&self) -> &[u8] {
        &self.original.before
    }
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub(crate) fn committed_receipt(
        &self,
    ) -> JournalResult<&styx_core::management::transaction::JournalReceipt> {
        self.original
            .phases
            .last()
            .filter(|receipt| receipt.stage == DurableStage::Committed)
            .ok_or(JournalError::Conflict)
    }
    pub(crate) fn selection(&self) -> &NativeRuntimeSelection {
        &self.selection
    }
    pub(crate) fn root_identity(&self) -> RootIdentity {
        self.root.identity()
    }
    pub(crate) fn endpoint_binding(&self) -> Option<&[u8]> {
        self.original.endpoint_binding()
    }
    pub(crate) fn endpoint_chain(&self) -> Option<&[u8]> {
        self.original.endpoint_chain()
    }
    pub(crate) fn endpoint_key(&self) -> Option<&[u8]> {
        self.original.endpoint_key()
    }
    pub(super) fn retirement(&self) -> &handoff::ObservedRetirement {
        &self.retirement
    }
}
fn absolute_locator(value: &str) -> bool {
    let path = Path::new(value);
    value.len() <= 4096
        && !value.contains('\0')
        && path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
fn capture_journal(root: &PrivateRoot, scan: &JournalObservation) -> JournalResult<Vec<Pin>> {
    scan.files
        .iter()
        .map(|file| {
            let path = format!("{NAMESPACE}/{}", file.name);
            let raw = root
                .read_raw(&path, MAX)
                .map_err(|_| JournalError::Unknown)?;
            let digest = Sha256Digest::of_bytes(file.bytes());
            if Sha256Digest::of_bytes(raw.bytes()) != digest {
                return Err(JournalError::Unknown);
            }
            Ok(Pin {
                path,
                observation: raw.observation().clone(),
                digest,
            })
        })
        .collect()
}
#[path = "committed_runtime_legacy.rs"]
mod legacy;

pub(crate) use legacy::capture_legacy_owners;
#[path = "committed_runtime_owner.rs"]
mod owner;
pub(crate) use owner::RecoveredCommittedRuntime;
