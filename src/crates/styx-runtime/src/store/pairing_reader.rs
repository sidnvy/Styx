//! Enrollment-format admission on the original protected configuration owner.
//! No new writer/namespace, activation, state upgrade or retry is performed.
use super::OwnedConfigurationRoot;
use super::secure_journal::{JournalError, JournalResult};
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
use super::{ConfigurationWriterGuard, PrivateRoot, RawFile};
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
use super::{native_host_snapshot, native_root, native_state};
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
use styx_contracts::{
    identity::Sha256Digest,
    management::ReaderContract,
    native_management::{NATIVE_MARKER_BYTES, NATIVE_STATE_BYTES},
};

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
fn revalidate_inputs(root: &PrivateRoot, pins: &[&RawFile]) -> JournalResult<()> {
    for before in pins {
        let after = root
            .read_raw(before.relative_path(), NATIVE_STATE_BYTES)
            .map_err(|_| JournalError::Unknown)?;
        if after.observation() != before.observation() || after.bytes() != before.bytes() {
            return Err(JournalError::Unknown);
        }
    }
    Ok(())
}

/// Called with the existing configuration mutex and writer already held.
/// EnrollmentJournal invokes this directly; it must not reacquire owner.state.
#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "windows",
    target_os = "macos"
))]
pub(super) fn require(root: &PrivateRoot, writer: &ConfigurationWriterGuard) -> JournalResult<()> {
    root.inner
        .with_configuration_writer_directory(writer, |_| {
            let result = (|| {
                // Generic enrollment journals deliberately lack this native
                // contract. Refuse them without poisoning ordinary operations.
                if root.ensure_absent(native_root::NATIVE_MARKER_FILE).is_ok() {
                    return Err(JournalError::Conflict);
                }
                let marker_raw = root
                    .read_raw(native_root::NATIVE_MARKER_FILE, NATIVE_MARKER_BYTES)
                    .map_err(|_| JournalError::Unknown)?;
                let state_raw = root
                    .read_raw("state.json", NATIVE_STATE_BYTES)
                    .map_err(|_| JournalError::Unknown)?;
                let deployment = root
                    .read_raw("deployment.json", NATIVE_STATE_BYTES)
                    .map_err(|_| JournalError::Unknown)?;
                let marker = native_state::decode_marker(marker_raw.bytes())
                    .map_err(|_| JournalError::Conflict)?;
                if !native_root::same_identity(&root.identity(), &marker) {
                    return Err(JournalError::Conflict);
                }
                let canonical = native_state::decode_state(state_raw.bytes(), &marker)
                    .map_err(|_| JournalError::Conflict)?;
                if canonical.state().schema != 7
                    || canonical.state().reader_contract
                        != ReaderContract::NativePairingLifecycleStateV1
                    || canonical.state().deployment_raw_sha256
                        != Sha256Digest::of_bytes(deployment.bytes())
                {
                    return Err(JournalError::Conflict);
                }
                // Reuse the complete existing C07 parser and protected
                // canonical/namespace pins. Pending, orphan and inconsistent
                // history cannot be mistaken for a completed reader upgrade.
                let selection =
                    native_host_snapshot::validated_runtime_selection(root, &canonical, &marker)?;
                let selected = crate::release::load_selected(&selection)
                    .map_err(|_| JournalError::Conflict)?;
                if !selected
                    .manifest()
                    .minimum_reader
                    .supports_state_reader(ReaderContract::NativePairingLifecycleStateV1)
                {
                    return Err(JournalError::Conflict);
                }
                if native_host_snapshot::validated_runtime_selection(root, &canonical, &marker)?
                    != selection
                {
                    return Err(JournalError::Unknown);
                }
                selected
                    .revalidate_matches_selection(&selection)
                    .map_err(|_| JournalError::Unknown)?;
                // Signature verification may take time. All original root
                // inputs, including deployment, must still be the exact files
                // captured before it, not same-value replacement files.
                revalidate_inputs(root, &[&marker_raw, &state_raw, &deployment])
            })();
            Ok(result)
        })
        .map_err(|_| JournalError::Unknown)?
}

impl OwnedConfigurationRoot {
    /// Service preflight only. The persistence boundary checks again while
    /// holding this same owner's mutex, without a second lock acquisition.
    pub(crate) fn require_pairing_lifecycle_reader(&self) -> JournalResult<()> {
        #[cfg(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        ))]
        {
            self.with_state(|state| {
                state.ordinary_admission()?;
                require(&state.root, &state.writer)
            })
        }
        #[cfg(not(any(
            all(target_os = "linux", target_env = "gnu"),
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            Err(JournalError::Unsupported)
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "pairing_reader_tests.rs"]
mod tests;
