//! OS-scoped service readers follow complete C07 autostart and run requests.
//! A stop for this role withdraws admission; it is never proof of actual exit.
//! This never selects a new deployment, runtime, identity or manager,
//! and never grants a writer or repairs/replays an incomplete transaction.
use super::{
    FileObservation, PrivateRoot, RawFile, management, native_state,
    secure_journal::{JournalBudget, JournalError, JournalObservation, JournalResult, files},
};
use crate::platform::linux::native_service::ServiceScope;
use std::{
    collections::BTreeMap,
    fs::File,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    management::DurableStage,
    native_management::{NativeManager, NativeRootMarker, NativeRunDesired},
};
use styx_core::management::state::{
    autostart_only_compatible, service_desired_compatible, validate_transition,
};
const NS: &str = ".styx-management-journal-v1";
const MAX: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveTipError {
    /// New journal material is not yet a fully committed, coherent observation.
    /// This fences new dispatch. It does not mean the old executor stopped.
    Pending,
    /// A committed request to stop this role. Cleanup is still outstanding.
    StopRequested,
    Changed,
}
impl From<JournalError> for LiveTipError {
    fn from(_: JournalError) -> Self {
        Self::Changed
    }
}
pub(crate) struct AutostartTip {
    marker: NativeRootMarker,
    baseline: native_state::ValidatedNativeState,
    files: BTreeMap<String, Sha256Digest>,
    follow_run: bool,
}
impl AutostartTip {
    pub(crate) fn capture(
        marker: &NativeRootMarker,
        canonical: &[u8],
        scan: &JournalObservation,
    ) -> JournalResult<Self> {
        let baseline =
            native_state::decode_state(canonical, marker).map_err(|_| JournalError::Conflict)?;
        management::validate_readonly_native_tip(scan, &baseline, marker)?;
        Ok(Self {
            marker: marker.clone(),
            baseline,
            follow_run: false,
            files: scan
                .files
                .iter()
                .map(|f| (f.name.clone(), Sha256Digest::of_bytes(f.bytes())))
                .collect(),
        })
    }
    // Only the OS-scoped ServiceTip below enables run-desired observation.
    // It translates its own Stopped request into withdrawal, never Ok/ready.
    fn follow_service_requests(mut self) -> Self {
        self.follow_run = true;
        self
    }
    pub(crate) fn validate(
        &self,
        scan: &JournalObservation,
        raw: &[u8],
    ) -> Result<(), LiveTipError> {
        let compatible = if self.follow_run {
            service_desired_compatible
        } else {
            autostart_only_compatible
        };
        let current: BTreeMap<_, _> = scan
            .files
            .iter()
            .map(|f| (f.name.as_str(), Sha256Digest::of_bytes(f.bytes())))
            .collect();
        if self
            .files
            .iter()
            .any(|(n, h)| current.get(n.as_str()) != Some(h))
        {
            return Err(LiveTipError::Changed);
        }
        let added = scan
            .files
            .iter()
            .filter(|f| !self.files.contains_key(&f.name))
            .collect::<Vec<_>>();
        if added.iter().any(|f| !c07_name(&f.name)) {
            return Err(LiveTipError::Changed);
        }
        if added.is_empty() {
            return if raw == self.baseline.raw_bytes() {
                Ok(())
            } else {
                Err(LiveTipError::Changed)
            };
        }
        // Partial append/write observations withdraw admission; they never admit
        // an operation or silently choose a new state while the writer settles.
        let canonical =
            native_state::decode_state(raw, &self.marker).map_err(|_| LiveTipError::Pending)?;
        if !compatible(self.baseline.state(), canonical.state()) {
            return Err(LiveTipError::Changed);
        }
        let inventory = management::readonly_inventory(scan).map_err(|_| LiveTipError::Pending)?;
        if !inventory.orphans.is_empty() {
            return Err(LiveTipError::Pending);
        }
        let floor = self
            .baseline
            .state()
            .last_transaction
            .as_ref()
            .map_or(0, |tx| tx.sequence);
        let mut previous = self.baseline.raw_bytes().to_vec();
        for tx in inventory
            .transactions
            .iter()
            .filter(|tx| tx.intent.sequence > floor)
        {
            if tx
                .phase_receipts
                .last()
                .is_none_or(|r| r.stage != DurableStage::Committed)
            {
                return Err(LiveTipError::Pending);
            }
            let original = management::readonly_original(scan, &tx.intent.transaction_id)?;
            if original.before != previous {
                return Err(LiveTipError::Changed);
            }
            let before = native_state::decode_state(&original.before, &self.marker)
                .map_err(|_| LiveTipError::Changed)?;
            let target = native_state::decode_state(&original.target, &self.marker)
                .map_err(|_| LiveTipError::Changed)?;
            validate_transition(
                before.state(),
                target.state(),
                &self.marker,
                &original.intent,
            )
            .map_err(|_| LiveTipError::Changed)?;
            if !compatible(before.state(), target.state()) {
                return Err(LiveTipError::Changed);
            }
            previous = original.target;
        }
        if previous != raw {
            return Err(LiveTipError::Pending);
        }
        management::validate_readonly_native_tip(scan, &canonical, &self.marker)
            .map_err(|_| LiveTipError::Pending)?;
        Ok(())
    }
}
fn c07_name(name: &str) -> bool {
    if let Some(tail) = name.strip_prefix("txn-") {
        return tail.rsplit_once('.').is_some_and(|(id, phase)| {
            TransactionId::try_from(id).is_ok()
                && matches!(
                    phase,
                    "intent" | "prepared" | "applied" | "verified" | "committed"
                )
        });
    }
    ["before-", "target-"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(".material"))
            .is_some_and(|h| {
                h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    })
}
/// Only ServiceTip can mint these exact current expectations after complete
/// chain validation under its original OS scope. No deserialization or caller
/// constructor is provided. Using this proof replaces an old expected state;
/// it never omits validation of the current canonical file or journal.
pub(crate) struct ServiceTipProof {
    canonical_pin: FileObservation,
    canonical_digest: Sha256Digest,
    journal: BTreeMap<String, Sha256Digest>,
}
impl ServiceTipProof {
    pub(crate) fn matches_state(&self, raw: &RawFile) -> bool {
        raw.observation() == &self.canonical_pin
            && Sha256Digest::of_bytes(raw.bytes()) == self.canonical_digest
    }
    pub(crate) fn matches_scan(&self, scan: &JournalObservation) -> bool {
        self.journal.len() == scan.files.len()
            && scan
                .files
                .iter()
                .all(|f| self.journal.get(&f.name) == Some(&Sha256Digest::of_bytes(f.bytes())))
    }
}
/// Original OS-authenticated service scope plus held namespace and marker.
/// Callers still revalidate every original identity, credential and payload pin.
pub(crate) struct ServiceTip {
    scope: Arc<ServiceScope>,
    root: PrivateRoot,
    namespace: File,
    namespace_identity: (u64, u64),
    marker_pin: FileObservation,
    marker_digest: Sha256Digest,
    accepted: Mutex<AcceptedTip>,
}
struct AcceptedTip {
    tip: AutostartTip,
    canonical_pin: FileObservation,
    pins: Vec<(String, FileObservation, Sha256Digest)>,
}
fn journal_pins(
    root: &PrivateRoot,
    scan: &JournalObservation,
) -> JournalResult<Vec<(String, FileObservation, Sha256Digest)>> {
    scan.files
        .iter()
        .map(|f| {
            let name = format!("{NS}/{}", f.name);
            let raw = root
                .read_raw(&name, MAX)
                .map_err(|_| JournalError::Unknown)?;
            if raw.bytes() != f.bytes() {
                return Err(JournalError::Unknown);
            }
            Ok((
                name,
                raw.observation().clone(),
                Sha256Digest::of_bytes(raw.bytes()),
            ))
        })
        .collect()
}
impl ServiceTip {
    pub(crate) fn open(scope: Arc<ServiceScope>) -> JournalResult<Self> {
        scope.validate().map_err(|_| JournalError::Conflict)?;
        let root = PrivateRoot::open(scope.state_dir()).map_err(|_| JournalError::Unknown)?;
        let marker_raw = root
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(|_| JournalError::Unknown)?;
        let marker =
            native_state::decode_marker(marker_raw.bytes()).map_err(|_| JournalError::Conflict)?;
        let canonical = root
            .read_raw("state.json", MAX)
            .map_err(|_| JournalError::Unknown)?;
        let state = native_state::decode_state(canonical.bytes(), &marker)
            .map_err(|_| JournalError::Conflict)?;
        if scope.role().desired(state.state()).is_none_or(|d| {
            d.manager != NativeManager::PersistentService || d.run != NativeRunDesired::Running
        }) {
            return Err(JournalError::Conflict);
        }
        let namespace = root
            .inner
            .with_readonly_directory(|d| Ok(files::directory(d, NS)))
            .map_err(|_| JournalError::Unknown)??;
        let m = namespace.metadata().map_err(|_| JournalError::Unknown)?;
        let scan = files::scan(&namespace, JournalBudget::default())?;
        let accepted = AcceptedTip {
            tip: AutostartTip::capture(&marker, canonical.bytes(), &scan)?
                .follow_service_requests(),
            canonical_pin: canonical.observation().clone(),
            pins: journal_pins(&root, &scan)?,
        };
        let result = Self {
            scope,
            root,
            namespace,
            namespace_identity: (m.dev(), m.ino()),
            marker_pin: marker_raw.observation().clone(),
            marker_digest: Sha256Digest::of_bytes(marker_raw.bytes()),
            accepted: Mutex::new(accepted),
        };
        result.revalidate().map_err(|_| JournalError::Conflict)?;
        Ok(result)
    }
    pub(crate) fn revalidate(&self) -> Result<(), LiveTipError> {
        self.revalidate_proof().map(|_| ())
    }
    pub(crate) fn revalidate_proof(&self) -> Result<ServiceTipProof, LiveTipError> {
        self.scope.validate().map_err(|_| LiveTipError::Changed)?;
        let current =
            PrivateRoot::open(self.scope.state_dir()).map_err(|_| LiveTipError::Changed)?;
        if current.identity() != self.root.identity() {
            return Err(LiveTipError::Changed);
        }
        let marker = current
            .read_raw(".styx-native-root-v1.json", 4096)
            .map_err(|_| LiveTipError::Changed)?;
        if marker.observation() != &self.marker_pin
            || Sha256Digest::of_bytes(marker.bytes()) != self.marker_digest
        {
            return Err(LiveTipError::Changed);
        }
        self.check_namespace()?;
        let mut accepted = self.accepted.lock().map_err(|_| LiveTipError::Changed)?;
        for (name, observation, digest) in &accepted.pins {
            let raw = current
                .read_raw(name, MAX)
                .map_err(|_| LiveTipError::Changed)?;
            if raw.observation() != observation || Sha256Digest::of_bytes(raw.bytes()) != *digest {
                return Err(LiveTipError::Changed);
            }
        }
        let before = files::scan(&self.namespace, JournalBudget::default())?;
        let raw = current
            .read_raw("state.json", MAX)
            .map_err(|_| LiveTipError::Pending)?;
        if raw.bytes() == accepted.tip.baseline.raw_bytes()
            && raw.observation() != &accepted.canonical_pin
        {
            return Err(LiveTipError::Changed);
        }
        let result = accepted.tip.validate(&before, raw.bytes());
        let after = files::scan(&self.namespace, JournalBudget::default())?;
        self.check_namespace()?;
        if before.files.len() != after.files.len()
            || before
                .files
                .iter()
                .zip(&after.files)
                .any(|(a, b)| a.name != b.name || a.bytes() != b.bytes())
        {
            return Err(LiveTipError::Pending);
        }
        let final_raw = current
            .read_raw("state.json", MAX)
            .map_err(|_| LiveTipError::Pending)?;
        if final_raw.observation() != raw.observation() || final_raw.bytes() != raw.bytes() {
            return Err(LiveTipError::Pending);
        }
        result?;
        // Advance only after a coherent committed read. Subsequent observations
        // must retain these exact files too: rollback/deletion cannot resurrect
        // the baseline merely because the initial process accepted it once.
        let pins = journal_pins(&current, &after)?;
        let next = AutostartTip::capture(&accepted.tip.marker, raw.bytes(), &after)?
            .follow_service_requests();
        let stopping = self
            .scope
            .role()
            .desired(next.baseline.state())
            .is_some_and(|d| d.run == NativeRunDesired::Stopped);
        let proof = ServiceTipProof {
            canonical_pin: raw.observation().clone(),
            canonical_digest: Sha256Digest::of_bytes(raw.bytes()),
            journal: next.files.clone(),
        };
        *accepted = AcceptedTip {
            tip: next,
            canonical_pin: raw.observation().clone(),
            pins,
        };
        if stopping {
            Err(LiveTipError::StopRequested)
        } else {
            Ok(proof)
        }
    }
    fn check_namespace(&self) -> Result<(), LiveTipError> {
        let current = self
            .root
            .inner
            .with_readonly_directory(|d| Ok(files::directory(d, NS)))
            .map_err(|_| LiveTipError::Changed)??;
        for file in [&current, &self.namespace] {
            let m = file.metadata().map_err(|_| LiveTipError::Changed)?;
            if (m.dev(), m.ino()) != self.namespace_identity || m.nlink() == 0 {
                return Err(LiveTipError::Changed);
            }
        }
        Ok(())
    }
}
