//! Darwin-only physical credential locator effect. No process settlement,
//! migration admission or final-commit capability is manufactured here.
use super::*;
use crate::store::{
    configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
    management::handoff::NativeRetirementFileStamp,
    management::handoff::{NativePreparedRetirement, NativeRetiredRecord, NativeRetirementIntent},
    management::handoff::{ProofStamp, RetirementFileStamp},
    secure_journal::{JournalError, JournalResult},
};
use std::os::unix::fs::FileExt;
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::NativeRootIdentity,
};
use zeroize::Zeroizing;

/// Retain this SAME value on Unknown. Neither Drop nor a pathname is cleanup.
/// Its original owner and maintenance remain live through all OS/file effects.
pub(in crate::store) struct MacTokenRetirement {
    owner: OwnedConfigurationRoot,
    maintenance: Arc<ConfigurationMaintenance>,
    host: Root,
    device: File,
    device_identity: (u64, u64),
    token: File,
    original: RetirementFileStamp,
    original_bytes: Zeroizing<Vec<u8>>,
    destination: String,
    attempted: bool,
    retired: bool,
    retired_post: Option<RetirementFileStamp>,
}
fn unknown<T>(value: Result<T>) -> JournalResult<T> {
    value.map_err(|_| JournalError::Unknown)
}
pub(super) fn digest_file(file: &File, expected_len: usize) -> JournalResult<Zeroizing<Vec<u8>>> {
    if !(1..=4096).contains(&expected_len) {
        return Err(JournalError::InvalidInput);
    }
    let mut bytes = Zeroizing::new(vec![0u8; expected_len + 1]);
    let mut offset = 0;
    while offset < bytes.len() {
        let n = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| JournalError::Unknown)?;
        if n == 0 {
            break;
        }
        offset += n;
    }
    if offset != expected_len {
        return Err(JournalError::Unknown);
    }
    bytes.truncate(expected_len);
    Ok(bytes)
}
pub(super) fn stamp(file: &File) -> JournalResult<RetirementFileStamp> {
    let before = unknown(journal_private_file(file))?;
    let bytes = digest_file(file, before.len() as usize)?;
    let after = unknown(journal_private_file(file))?;
    if observation(&before) != observation(&after) {
        return Err(JournalError::Unknown);
    }
    Ok(RetirementFileStamp {
        device: after.dev(),
        inode: after.ino(),
        uid: after.uid(),
        mode: after.mode(),
        nlink: after.nlink(),
        byte_len: after.len(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        changed_seconds: after.ctime(),
        changed_nanoseconds: after.ctime_nsec(),
        sha256: Sha256Digest::of_bytes(&bytes),
    })
}
fn native_root(root: RootIdentity) -> JournalResult<NativeRootIdentity> {
    match root {
        RootIdentity::Macos { device, inode, uid } => {
            Ok(NativeRootIdentity::Macos { device, inode, uid })
        }
        _ => Err(JournalError::Conflict),
    }
}
impl MacTokenRetirement {
    /// Original private raw observation must come from the trusted legacy reader,
    /// not a client path or a serialized stamp. Only the fixed locator is opened.
    pub(in crate::store) fn prepare(
        host: &Root,
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        original: &RawFile,
    ) -> JournalResult<Self> {
        if !maintenance.matches(&owner)
            || original.relative_path != Path::new("device/host.token")
            || original.bytes().is_empty()
            || original.bytes().len() > 4096
        {
            return Err(JournalError::Conflict);
        }
        let destination = format!(
            ".styx-retired-host-token-{}",
            maintenance.transaction_id().as_str()
        );
        let held_host = host.clone();
        owner.with_maintenance(&maintenance, |state| {
            let before = state
                .root
                .read_raw("state.json", 1024 * 1024)
                .map_err(|_| JournalError::Unknown)?;
            crate::store::management::handoff::reject_migration_v2_collision(before.bytes())?;
            unknown(held_host.validate_root())?;
            let device = unknown(open_at(
                &held_host.directory,
                OsStr::new("device"),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty(),
            ))?;
            let meta = unknown(journal_private_directory(&device))?;
            let token = unknown(open_at(
                &device,
                OsStr::new("host.token"),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ))?;
            let original_stamp = stamp(&token)?;
            if observation(&unknown(journal_private_file(&token))?) != *original.observation()
                || original_stamp.sha256 != Sha256Digest::of_bytes(original.bytes())
            {
                return Err(JournalError::Conflict);
            }
            // Absence is checked before journal preparation; never replace an
            // older attempt. The later kernel RENAME_EXCL checks it again.
            match open_at(
                &device,
                OsStr::new(&destination),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ) {
                Err(StoreError::Io(ref error)) if error.raw_os_error() == Some(libc::ENOENT) => {}
                _ => return Err(JournalError::Conflict),
            }
            unknown(held_host.validate_root())?;
            Ok(Self {
                owner: owner.clone(),
                maintenance: maintenance.clone(),
                host: held_host.clone(),
                device,
                device_identity: (meta.dev(), meta.ino()),
                token,
                original: original_stamp,
                original_bytes: Zeroizing::new(original.bytes().to_vec()),
                destination: destination.clone(),
                attempted: false,
                retired: false,
                retired_post: None,
            })
        })
    }
    /// Reopen only an already recorded Retired effect from the original journal
    /// predecessor. This observes existing bytes; it never renames, re-records,
    /// repairs permissions, or manufactures a replacement post-effect stamp.
    pub(in crate::store) fn reopen_recorded_retired(
        host: &Root,
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        prepared: &NativePreparedRetirement,
        record: &NativeRetiredRecord,
    ) -> JournalResult<Self> {
        if !record.matches_prepared(prepared) {
            return Err(JournalError::Conflict);
        }
        Self::reopen_existing_retired(
            host,
            owner,
            maintenance,
            prepared,
            Some(record.post_stamp()),
        )
    }
    /// Recover the rename-before-receipt interruption by observation only.
    /// Both original C custody and the original Prepared journal must remain
    /// live. Missing/restored/replaced files are refused, never renamed again.
    pub(in crate::store) fn reopen_unrecorded_retired(
        host: &Root,
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        journal: &crate::store::management::OwnedManagementJournal,
        prepared: &NativePreparedRetirement,
        custody: &MacBootRecoveryEffects,
        held: &crate::store::management::handoff::LegacyGuardsHeld,
    ) -> JournalResult<Self> {
        Self::validate_recovery_binding(&owner, &maintenance, prepared, custody, held)?;
        journal.validate_native_prepared(&maintenance, prepared)?;
        let reopened = Self::reopen_existing_retired(host, owner, maintenance, prepared, None)?;
        custody.validate_retained(held)?;
        journal.validate_native_prepared(&reopened.maintenance, prepared)?;
        reopened.validate_retired()?;
        Ok(reopened)
    }
    fn validate_recovery_binding(
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        prepared: &NativePreparedRetirement,
        custody: &MacBootRecoveryEffects,
        held: &crate::store::management::handoff::LegacyGuardsHeld,
    ) -> JournalResult<()> {
        let original = held.prepared().intent();
        let intent = prepared.intent();
        if !maintenance.matches(owner)
            || !prepared.matches_owner(owner)
            || !custody.matches_owner(owner)
            || custody.maintenance().transaction_id() != maintenance.transaction_id()
            || original.transaction_id != intent.transaction_id
            || original.sequence != intent.sequence
            || original.config_root != intent.config_root
            || original.deployment_raw_sha256 != intent.deployment_raw_sha256
            || original.before_state_sha256 != intent.before_state_sha256
            || original.candidate_manifest_sha256 != intent.candidate_manifest_sha256
            || original.publisher_spki_sha256 != intent.publisher_spki_sha256
            || original.successor_retirement_intent_sha256 != prepared.raw_intent_sha256()
        {
            return Err(JournalError::Conflict);
        }
        custody.validate_retained(held)
    }
    /// Shared fixed-path observation. None means no post stamp was durably
    /// recorded: prove the original inode/content and sync the existing rename.
    fn reopen_existing_retired(
        host: &Root,
        owner: OwnedConfigurationRoot,
        maintenance: Arc<ConfigurationMaintenance>,
        prepared: &NativePreparedRetirement,
        expected_post: Option<&NativeRetirementFileStamp>,
    ) -> JournalResult<Self> {
        if !maintenance.matches(&owner) || !prepared.matches_owner(&owner) {
            return Err(JournalError::Conflict);
        }
        let intent = prepared.intent();
        let host_root = native_root(host.identity())?;
        let destination = format!(
            ".styx-retired-host-token-{}",
            maintenance.transaction_id().as_str()
        );
        if intent.transaction_id != *maintenance.transaction_id()
            || intent.config_root != native_root(owner.identity()?)?
            || intent.host_root != host_root
            || intent.token_destination() != Path::new("device").join(&destination)
            || !intent.original_token.valid_for(&host_root)
            || expected_post.is_some_and(|post| {
                !post.valid_for(&host_root) || !intent.original_token.same_file_after_rename(post)
            })
        {
            return Err(JournalError::Conflict);
        }
        let NativeRetirementFileStamp::Macos { stamp: original } = &intent.original_token else {
            return Err(JournalError::Conflict);
        };
        let held_host = host.clone();
        owner.with_maintenance(&maintenance, |_| {
            unknown(held_host.validate_root())?;
            let device = unknown(open_at(
                &held_host.directory,
                OsStr::new("device"),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty(),
            ))?;
            let meta = unknown(journal_private_directory(&device))?;
            // An absent retired destination or a restored source is not Done.
            match open_at(
                &device,
                OsStr::new("host.token"),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ) {
                Err(StoreError::Io(ref error)) if error.raw_os_error() == Some(libc::ENOENT) => {}
                _ => return Err(JournalError::Unknown),
            }
            let token = unknown(open_at(
                &device,
                OsStr::new(&destination),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ))?;
            let post = stamp(&token)?;
            let native_post = NativeRetirementFileStamp::Macos {
                stamp: post.clone(),
            };
            if !intent.original_token.same_file_after_rename(&native_post)
                || expected_post.is_some_and(|expected| expected != &native_post)
            {
                return Err(JournalError::Unknown);
            }
            let bytes = digest_file(&token, original.byte_len as usize)?;
            if Sha256Digest::of_bytes(&bytes) != original.sha256 || stamp(&token)? != post {
                return Err(JournalError::Unknown);
            }
            let reopened = Self {
                owner: owner.clone(),
                maintenance: maintenance.clone(),
                host: held_host.clone(),
                device,
                device_identity: (meta.dev(), meta.ino()),
                token,
                original: original.clone(),
                original_bytes: bytes,
                destination: destination.clone(),
                // Preserve the one-attempt boundary: retire() must reject this
                // value, including after a later validation failure.
                attempted: true,
                retired: true,
                retired_post: Some(post.clone()),
            };
            if reopened.validate_retired_locked()? != native_post {
                return Err(JournalError::Unknown);
            }
            if expected_post.is_none() {
                unknown(sync_private_file(&reopened.token))?;
                unknown(sync_private_directory(&reopened.device))?;
                unknown(reopened.host.sync_directory())?;
                if reopened.validate_retired_locked()? != native_post {
                    return Err(JournalError::Unknown);
                }
            }
            Ok(reopened)
        })
    }
    pub(in crate::store) fn matches_binding(
        &self,
        owner: &OwnedConfigurationRoot,
        host: &NativeRootIdentity,
        credential: Sha256Digest,
    ) -> bool {
        self.owner.same_authority(owner)
            && self.maintenance.matches(owner)
            && native_root(self.host.identity()).is_ok_and(|root| &root == host)
            && self.original.sha256 == credential
    }
    pub(in crate::store) fn pre_stamp(&self) -> NativeRetirementFileStamp {
        NativeRetirementFileStamp::Macos {
            stamp: self.original.clone(),
        }
    }
    fn validate_directories(&self) -> JournalResult<()> {
        unknown(self.host.validate_root())?;
        let original = unknown(journal_private_directory(&self.device))?;
        let now = unknown(open_at(
            &self.host.directory,
            OsStr::new("device"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::empty(),
        ))?;
        let current = unknown(journal_private_directory(&now))?;
        if (original.dev(), original.ino()) != self.device_identity
            || (current.dev(), current.ino()) != self.device_identity
        {
            return Err(JournalError::Unknown);
        }
        Ok(())
    }
    fn validate_intent(&self, intent: &NativeRetirementIntent) -> JournalResult<()> {
        if intent.transaction_id != *self.maintenance.transaction_id()
            || intent.host_root != native_root(self.host.identity())?
            || intent.config_root != native_root(self.owner.identity()?)?
            || intent.original_token != self.pre_stamp()
            || intent.token_destination() != Path::new("device").join(&self.destination)
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    /// The opaque journal predecessor is necessary but NOT sufficient for the
    /// higher coordinator to stop/adopt an old runtime. Call only after its
    /// original scope proof was consumed; this private OS bridge proves rename.
    pub(in crate::store) fn retire(
        &mut self,
        prepared: &NativePreparedRetirement,
    ) -> JournalResult<NativeRetirementFileStamp> {
        if self.attempted || !prepared.matches_owner(&self.owner) {
            return Err(JournalError::Conflict);
        }
        self.validate_intent(prepared.intent())?;
        let owner = self.owner.clone();
        let maintenance = self.maintenance.clone();
        owner.with_maintenance(&maintenance, |_| {
            self.validate_directories()?;
            let current = unknown(open_at(
                &self.device,
                OsStr::new("host.token"),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ))?;
            if stamp(&current)? != self.original
                || stamp(&self.token)? != self.original
                || digest_file(&self.token, self.original_bytes.len())?.as_slice()
                    != self.original_bytes.as_slice()
            {
                return Err(JournalError::Conflict);
            }
            // Latch BEFORE kernel effect. Failure/lost return never permits a
            // second rename; retain original handles and inspect the same ID.
            self.attempted = true;
            unknown(rename_exclusive(
                &self.device,
                "host.token",
                &self.device,
                &self.destination,
            ))?;
            unknown(sync_private_file(&self.token))?;
            unknown(sync_private_directory(&self.device))?;
            unknown(self.host.sync_directory())?;
            let post = stamp(&self.token)?;
            let native = NativeRetirementFileStamp::Macos {
                stamp: post.clone(),
            };
            if !self.pre_stamp().same_file_after_rename(&native) {
                return Err(JournalError::Unknown);
            }
            let published = unknown(open_at(
                &self.device,
                OsStr::new(&self.destination),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ))?;
            if stamp(&published)? != post
                || digest_file(&published, self.original_bytes.len())?.as_slice()
                    != self.original_bytes.as_slice()
            {
                return Err(JournalError::Unknown);
            }
            match open_at(
                &self.device,
                OsStr::new("host.token"),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                Mode::empty(),
            ) {
                Err(StoreError::Io(ref error)) if error.raw_os_error() == Some(libc::ENOENT) => {}
                _ => return Err(JournalError::Unknown),
            }
            self.validate_directories()?;
            self.retired_post = Some(post);
            self.retired = true;
            Ok(native)
        })
    }
    /// Revalidates the exact original file after retirement. No replay/restore,
    /// canonical replacement or new credentials; caller retains this pin.
    /// Journal preflight precedes the one OS attempt. On any error the caller
    /// retains this SAME value (including original owner/maintenance/pins).
    pub(in crate::store) fn retire_and_record(
        &mut self,
        journal: &mut crate::store::management::OwnedManagementJournal,
        prepared: &NativePreparedRetirement,
    ) -> JournalResult<crate::store::management::handoff::NativeRetiredRecord> {
        journal.validate_native_prepared(&self.maintenance, prepared)?;
        let post = self.retire(prepared)?;
        let record =
            journal.record_native_credential_retired(&self.maintenance, prepared, &post)?;
        if self.validate_retired()? != *record.post_stamp() {
            return Err(JournalError::Unknown);
        }
        Ok(record)
    }
    /// Record only a physically observed original rename. The caller retains
    /// this value and C custody on every error; there is no rename/retry path.
    pub(in crate::store) fn record_observed_retirement(
        &mut self,
        journal: &mut crate::store::management::OwnedManagementJournal,
        prepared: &NativePreparedRetirement,
        custody: &MacBootRecoveryEffects,
        held: &crate::store::management::handoff::LegacyGuardsHeld,
    ) -> JournalResult<NativeRetiredRecord> {
        Self::validate_recovery_binding(&self.owner, &self.maintenance, prepared, custody, held)?;
        self.validate_intent(prepared.intent())?;
        journal.validate_native_prepared(&self.maintenance, prepared)?;
        let post = self.validate_retired()?;
        let record =
            journal.record_native_credential_retired(&self.maintenance, prepared, &post)?;
        custody.validate_retained(held)?;
        if self.validate_retired()? != *record.post_stamp() {
            return Err(JournalError::Unknown);
        }
        Ok(record)
    }
    /// Exact post-effect observation, never a newly captured replacement stamp.
    pub(super) fn validate_retired_locked(&self) -> JournalResult<NativeRetirementFileStamp> {
        if !self.retired {
            return Err(JournalError::Unknown);
        }
        let expected = self.retired_post.as_ref().ok_or(JournalError::Unknown)?;
        self.validate_directories()?;
        let post = stamp(&self.token)?;
        let native = NativeRetirementFileStamp::Macos {
            stamp: post.clone(),
        };
        if &post != expected || !self.pre_stamp().same_file_after_rename(&native) {
            return Err(JournalError::Unknown);
        }
        let published = unknown(open_at(
            &self.device,
            OsStr::new(&self.destination),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        ))?;
        if stamp(&published)? != post {
            return Err(JournalError::Unknown);
        }
        match open_at(
            &self.device,
            OsStr::new("host.token"),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Err(StoreError::Io(ref error)) if error.raw_os_error() == Some(libc::ENOENT) => {}
            _ => return Err(JournalError::Unknown),
        }
        Ok(native)
    }
    pub(in crate::store) fn validate_retired(&self) -> JournalResult<NativeRetirementFileStamp> {
        self.owner
            .with_maintenance(&self.maintenance, |_| self.validate_retired_locked())
    }
    pub(in crate::store) fn retired_relative_path(&self) -> PathBuf {
        Path::new("device").join(&self.destination)
    }
    /// Only the ORIGINAL retained token descriptor is read, under the original
    /// live owner/fence. A caller's path, JSON hash, or another same-UID file
    /// cannot select a credential. Returned bytes have no execution authority.
    pub(in crate::store) fn read_retired(
        &self,
        host: &PrivateRoot,
    ) -> JournalResult<Zeroizing<Vec<u8>>> {
        self.owner.with_maintenance(&self.maintenance, |_| {
            if host.identity() != self.host.identity() {
                return Err(JournalError::Conflict);
            }
            let before = self.validate_retired_locked()?;
            let bytes = digest_file(&self.token, self.original_bytes.len())?;
            let named = host
                .read_raw(self.retired_relative_path(), 4096)
                .map_err(|_| JournalError::Unknown)?;
            if named.bytes() != bytes.as_slice()
                || Sha256Digest::of_bytes(&bytes) != self.original.sha256
                || named.observation() != &observation(&unknown(journal_private_file(&self.token))?)
            {
                return Err(JournalError::Unknown);
            }
            if self.validate_retired_locked()? != before {
                return Err(JournalError::Unknown);
            }
            Ok(bytes)
        })
    }
}
