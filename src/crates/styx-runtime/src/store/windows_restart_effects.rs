//! OS effect only, a child of store::windows. No ledger, admission or Deserialize.
//! The coordinator retains this object and original journal/maintenance on one
//! blocking worker; it validates the durable Prepared immediately before effects.
//! It must verify the original package/publisher against the same plan as well.
use super::*;
use crate::{
    platform::{
        windows_legacy_observation::{BootStamp, WindowsLegacyObservation},
        windows_restart_observation::{
            MAX_STARTUP_RECOVERY_RAW, current_startup_directory, link_fields,
        },
    },
    store::{
        configuration::{ConfigurationMaintenance, OwnedConfigurationRoot},
        management::handoff::{NativeRetirementFileStamp, ProofStamp},
        secure_journal::{JournalError, JournalResult},
    },
};
use std::os::windows::{fs::FileExt, io::FromRawHandle};
use styx_contracts::{
    identity::{Sha256Digest, TransactionId},
    native_management::NativeRootIdentity,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};
const NAME: &str = "Styx.lnk";
const ARCHIVE: &str = "windows-startup-original.lnk";
fn failed<T>(_: T) -> JournalError {
    JournalError::Unknown
}
/// Data from the SAME verified plan; never a settled-owner capability.
/// The journal also binds package+publisher SHA, candidate SHA and desiredEnabled.
pub(in crate::store) struct StartupOriginal {
    pub(in crate::store) transaction: TransactionId,
    pub(in crate::store) config_root: NativeRootIdentity,
    pub(in crate::store) startup_directory: PathBuf,
    pub(in crate::store) original: NativeRetirementFileStamp,
    pub(in crate::store) bytes: Vec<u8>,
    pub(in crate::store) target: String,
    pub(in crate::store) arguments: String,
    pub(in crate::store) working_directory: String,
    pub(in crate::store) checkpoint_boot: BootStamp,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::store) enum StartupLocation {
    Original,
    Archived,
}
/// Held OS pins, not a scope-settled proof. Generic JSON cannot construct it.
pub(in crate::store) struct StartupLinkCustody {
    owner: OwnedConfigurationRoot,
    original: StartupOriginal,
    archive: Root,
    startup: PathBuf,
    parents: Vec<File>,
    parent_facts: Vec<ffi::Facts>,
    file: File,
    location: StartupLocation,
    boot_this_attempt: BootStamp,
}
#[allow(unsafe_code)] // Exact CreateFileW/owned HANDLE boundary only.
fn open_link(path: &Path, writable: bool) -> Result<File> {
    let text: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if text.len() > 32768 || text[..text.len() - 1].contains(&0) {
        return Err(StoreError::InvalidRoot);
    }
    // Original writable handle denies write sharing. Read-only name checks share
    // the existing writer/delete access but never request either right themselves.
    let h = unsafe {
        CreateFileW(
            text.as_ptr(),
            GENERIC_READ | if writable { GENERIC_WRITE | DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_DELETE | if writable { 0 } else { FILE_SHARE_WRITE },
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(StoreError::Io(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_handle(h) };
    let facts = ffi::facts(&file)?;
    if facts.directory || facts.links != 1 {
        return Err(StoreError::NotRegularFile);
    }
    if ffi::local_executable_acl(&file)? != ffi::current_sid()? {
        return Err(StoreError::NotPrivate);
    }
    Ok(file)
}
fn optional(path: &Path, writable: bool) -> JournalResult<Option<File>> {
    match open_link(path, writable) {
        Ok(f) => Ok(Some(f)),
        Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(JournalError::Unknown),
    }
}
fn observe(file: &File, bytes: &[u8]) -> JournalResult<NativeRetirementFileStamp> {
    if bytes.len() > MAX_STARTUP_RECOVERY_RAW {
        return Err(JournalError::Unsupported);
    }
    if bytes.is_empty() {
        return Err(JournalError::InvalidInput);
    }
    let before = ffi::facts(file).map_err(failed)?;
    let sid = ffi::local_executable_acl(file).map_err(failed)?;
    if sid != ffi::current_sid().map_err(failed)?
        || before.directory
        || before.observation.byte_len != bytes.len() as u64
    {
        return Err(JournalError::Conflict);
    }
    let mut raw = vec![0u8; bytes.len() + 1];
    let mut used = 0;
    while used < raw.len() {
        let n = file
            .seek_read(&mut raw[used..], used as u64)
            .map_err(failed)?;
        if n == 0 {
            break;
        }
        used += n;
    }
    if used != bytes.len() || &raw[..used] != bytes || ffi::facts(file).map_err(failed)? != before {
        return Err(JournalError::Conflict);
    }
    let f = before.observation;
    Ok(NativeRetirementFileStamp::Windows {
        volume_serial: f.device,
        file_id: f.inode,
        owner_sid: sid,
        nlink: u64::from(before.links),
        byte_len: f.byte_len,
        modified_seconds: f.modified_seconds,
        modified_nanoseconds: f.modified_nanoseconds,
        changed_seconds: f.changed_seconds,
        changed_nanoseconds: f.changed_nanoseconds,
        sha256: Sha256Digest::of_bytes(bytes),
    })
}
/// Read-only plan material. Retains no-write/no-delete source and ancestry pins
/// until the shared journal has saved the actual raw attachment. Dropping it is
/// not a mutation; reopen rechecks the original file before any effect.
pub(in crate::store) struct StartupLinkRead {
    pub(in crate::store) directory: PathBuf,
    pub(in crate::store) original: NativeRetirementFileStamp,
    pub(in crate::store) bytes: Vec<u8>,
    pub(in crate::store) fields: crate::platform::windows_restart_observation::LinkFields,
    _file: File,
    _parents: Vec<File>,
}
pub(in crate::store) fn read_original_startup_link() -> JournalResult<StartupLinkRead> {
    let directory =
        normalized_root(&current_startup_directory().map_err(failed)?).map_err(failed)?;
    let (_, parents) = absolute_pins(&directory).map_err(failed)?;
    for parent in parents.iter().skip(1) {
        ffi::local_executable_acl(parent).map_err(failed)?;
    }
    let path = directory.join(NAME);
    let file = ffi::open(&path, false, false, false).map_err(failed)?;
    ffi::require_no_streams(&path).map_err(failed)?;
    let before = ffi::facts(&file).map_err(failed)?;
    if before.observation.byte_len > MAX_STARTUP_RECOVERY_RAW as u64 {
        return Err(JournalError::Unsupported);
    }
    if before.directory || before.observation.byte_len == 0 {
        return Err(JournalError::InvalidInput);
    }
    let mut bytes = vec![0u8; before.observation.byte_len as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(failed)?;
        if count == 0 {
            return Err(JournalError::Unknown);
        }
        offset += count;
    }
    let original = observe(&file, &bytes)?;
    let fields = link_fields(&bytes).map_err(failed)?;
    if ffi::facts(&file).map_err(failed)? != before
        || ffi::final_path(&file).map_err(failed)? != path
    {
        return Err(JournalError::Conflict);
    }
    Ok(StartupLinkRead {
        directory,
        original,
        bytes,
        fields,
        _file: file,
        _parents: parents,
    })
}
impl StartupLinkCustody {
    /// Reopen from original journal attachments, including after process/OS restart.
    /// archive is the existing fixed private directory belonging to this tx; no
    /// create/open-existing adoption occurs here. No bytes or ACLs are rewritten.
    pub(in crate::store) fn reopen(
        owner: OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        original: StartupOriginal,
        archive: Root,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<Self> {
        if maintenance.transaction_id() != &original.transaction
            || archive.path.file_name() != Some(OsStr::new(original.transaction.as_str()))
        {
            return Err(JournalError::Conflict);
        }
        let startup =
            normalized_root(&current_startup_directory().map_err(failed)?).map_err(failed)?;
        if startup != normalized_root(&original.startup_directory).map_err(failed)? {
            return Err(JournalError::Conflict);
        }
        if original.bytes.len() > MAX_STARTUP_RECOVERY_RAW {
            return Err(JournalError::Unsupported);
        }
        let fields = link_fields(&original.bytes).map_err(failed)?;
        if fields.target != original.target
            || fields.arguments != original.arguments
            || fields.working_directory != original.working_directory
        {
            return Err(JournalError::Conflict);
        }
        // Exact plan strings, fixed legacy basename and args shape. No environment
        // expansion, URL target, arbitrary arguments, Shell resolve or execution.
        let target = normalized_root(Path::new(&fields.target)).map_err(failed)?;
        let cwd = normalized_root(Path::new(&fields.working_directory)).map_err(failed)?;
        if target.file_name() != Some(OsStr::new("StyxPreview.exe"))
            || target.parent() != Some(cwd.as_path())
            || !fields.arguments.starts_with("--startup --state-dir \"")
            || !fields.arguments.ends_with('"')
        {
            return Err(JournalError::Conflict);
        }
        let (_, parents) = absolute_pins(&startup).map_err(failed)?;
        for p in parents.iter().skip(1) {
            ffi::local_executable_acl(p).map_err(failed)?;
        }
        let parent_facts = parents
            .iter()
            .map(ffi::facts)
            .collect::<Result<Vec<_>>>()
            .map_err(failed)?;
        archive.validate_root().map_err(failed)?;
        let folder = parents.last().ok_or(JournalError::Unknown)?;
        ffi::require_local_ntfs(&startup, folder).map_err(failed)?;
        if ffi::facts(folder).map_err(failed)?.observation.device
            != ffi::facts(&archive.directory)
                .map_err(failed)?
                .observation
                .device
        {
            return Err(JournalError::Conflict);
        }
        let source = optional(&startup.join(NAME), true)?;
        let dest = optional(&archive.path.join(ARCHIVE), true)?;
        let (file, location) = match (source, dest) {
            (Some(f), None) => (f, StartupLocation::Original),
            (None, Some(f)) => (f, StartupLocation::Archived),
            _ => return Err(JournalError::Conflict),
        };
        let stamp = observe(&file, &original.bytes)?;
        if !original.original.same_file_after_rename(&stamp) {
            return Err(JournalError::Conflict);
        }
        let now = os.checkpoint().map_err(failed)?;
        // Same-boot process recovery or actual later boot; earlier/ambiguous denied.
        if now != original.checkpoint_boot
            && !now.definitely_after_old_ms(original.checkpoint_boot.unix_micros / 1000)
        {
            return Err(JournalError::Conflict);
        }
        let value = Self {
            owner,
            original,
            archive,
            startup,
            parents,
            parent_facts,
            file,
            location,
            boot_this_attempt: now,
        };
        value.validate(maintenance, os)?;
        Ok(value)
    }
    pub(in crate::store) fn location(&self) -> StartupLocation {
        self.location
    }
    fn validate(
        &self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        self.owner.with_maintenance(maintenance, |state| {
            self.validate_binding_locked(state, &self.owner, maintenance)
        })?;
        self.validate_physical(os)
    }
    fn validate_binding_locked(
        &self,
        s: &crate::store::configuration::ConfigurationState,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
    ) -> JournalResult<()> {
        if !self.owner.same_authority(owner)
            || !maintenance.matches(owner)
            || maintenance.transaction_id() != &self.original.transaction
        {
            return Err(JournalError::Conflict);
        }
        s.require_native_maintenance(&self.original.transaction)?;
        let fixed_archive = s
            .root
            .inner
            .path
            .join("foreground-recovery")
            .join(self.original.transaction.as_str());
        let profile = s.root.inner.path.parent().ok_or(JournalError::Conflict)?;
        let expected_arguments = format!("--startup --state-dir \"{}\"", profile.display());
        if self.archive.path != fixed_archive || self.original.arguments != expected_arguments {
            return Err(JournalError::Conflict);
        }
        let RootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        } = s.root.identity()
        else {
            return Err(JournalError::Conflict);
        };
        if (NativeRootIdentity::Windows {
            volume_serial,
            file_id,
            owner_sid,
        }) != self.original.config_root
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    fn validate_physical(
        &self,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        self.archive.validate_root().map_err(failed)?;
        if normalized_root(&current_startup_directory().map_err(failed)?).map_err(failed)?
            != self.startup
            || os.checkpoint().map_err(failed)? != self.boot_this_attempt
        {
            return Err(JournalError::Conflict);
        }
        for (p, original) in self.parents.iter().zip(&self.parent_facts) {
            let now = ffi::facts(p).map_err(failed)?;
            // Directory timestamps change when entries move; identity must not.
            if now.observation.device != original.observation.device
                || now.observation.inode != original.observation.inode
            {
                return Err(JournalError::Conflict);
            }
        }
        for p in self.parents.iter().skip(1) {
            ffi::local_executable_acl(p).map_err(failed)?;
        }
        let (path, absent) = match self.location {
            StartupLocation::Original => (self.startup.join(NAME), self.archive.path.join(ARCHIVE)),
            StartupLocation::Archived => (self.archive.path.join(ARCHIVE), self.startup.join(NAME)),
        };
        if ffi::final_path(&self.file).map_err(failed)? != path
            || optional(&absent, false)?.is_some()
        {
            return Err(JournalError::Conflict);
        }
        ffi::require_no_streams(&path).map_err(failed)?;
        let held = observe(&self.file, &self.original.bytes)?;
        let named = optional(&path, false)?.ok_or(JournalError::Unknown)?;
        if observe(&named, &self.original.bytes)? != held
            || !self.original.original.same_file_after_rename(&held)
        {
            return Err(JournalError::Conflict);
        }
        Ok(held)
    }
    /// Held original named object, same owner/transaction and original post.
    /// This is callable by the C effect on every operation; it never renames.
    pub(in crate::store) fn validate_excluded(
        &self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        if self.location != StartupLocation::Archived {
            return Err(JournalError::Conflict);
        }
        self.validate(maintenance, os)
    }
    /// Same original binding/physical checks when the caller already holds the
    /// configuration mutex. Never recursively acquires that mutex.
    pub(in crate::store) fn validate_excluded_locked(
        &self,
        state: &crate::store::configuration::ConfigurationState,
        owner: &OwnedConfigurationRoot,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        if self.location != StartupLocation::Archived {
            return Err(JournalError::Conflict);
        }
        self.validate_binding_locked(state, owner, maintenance)?;
        self.validate_physical(os)
    }
    pub(in crate::store) fn matches_prepared(
        &self,
        prepared: &crate::store::management::handoff::PreparedLegacyOwnerRecovery,
    ) -> bool {
        let Some(checkpoint) = prepared.startup_checkpoint() else {
            return false;
        };
        prepared.matches_owner(&self.owner)
            && prepared.intent().transaction_id == self.original.transaction
            && prepared.intent().config_root == self.original.config_root
            && prepared.intent().current_boot.id
                == format!(
                    "wmi-lastboot-unix-micros:{}",
                    self.original.checkpoint_boot.unix_micros
                )
            && prepared.intent().current_boot.started_at_ms
                == self.original.checkpoint_boot.unix_micros / 1000
            && checkpoint.original_link == self.original.original
            && prepared.startup_raw() == Some(self.original.bytes.as_slice())
            && checkpoint.startup_directory == self.original.startup_directory.to_string_lossy()
            && checkpoint.target == self.original.target
            && checkpoint.arguments == self.original.arguments
            && checkpoint.working_directory == self.original.working_directory
    }
    fn flush(&self) -> JournalResult<()> {
        ffi::flush_file(&self.file).map_err(failed)?;
        let writable = ffi::open(&self.startup, true, true, false).map_err(failed)?;
        let now = ffi::facts(&writable).map_err(failed)?;
        let original = self.parent_facts.last().ok_or(JournalError::Unknown)?;
        if now.observation.device != original.observation.device
            || now.observation.inode != original.observation.inode
        {
            return Err(JournalError::Conflict);
        }
        ffi::local_executable_acl(&writable).map_err(failed)?;
        ffi::flush_file(&writable).map_err(failed)?;
        self.archive.sync_directory().map_err(failed)
    }
    /// Only after SAME-journal durable checkpoint. Returns actual stamp for its
    /// record_excluded call. A rename error retains this original HANDLE; caller
    /// must retain self and reopen/classify before another effect, never replay.
    pub(in crate::store) fn exclude(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        self.validate(maintenance, os)?;
        if self.location == StartupLocation::Original {
            if self.boot_this_attempt != self.original.checkpoint_boot {
                return Err(JournalError::Conflict);
            }
            ffi::rename_journal_file(&self.file, &self.archive.directory, ARCHIVE, false)
                .map_err(failed)?;
            self.location = StartupLocation::Archived;
        }
        self.flush()?;
        self.validate(maintenance, os)
    }
    /// Explicit rollback only, after same-journal authorization. Never call on
    /// successful Rust activation: that path restores the preference with a NEW
    /// Rust shortcut through the installer and must not reactivate this old App.
    pub(in crate::store) fn restore_original(
        &mut self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<NativeRetirementFileStamp> {
        self.validate(maintenance, os)?;
        if self.location == StartupLocation::Archived {
            let folder = self.parents.last().ok_or(JournalError::Unknown)?;
            ffi::rename_journal_file(&self.file, folder, NAME, false).map_err(failed)?;
            self.location = StartupLocation::Original;
        }
        self.flush()?;
        self.validate(maintenance, os)
    }
    /// Necessary physical fact only. NOT an old-scope admission proof: the
    /// coordinator must also revalidate other restart sources and journal phase.
    /// Business outcomes remain Unknown. No operation is marked Cancelled here.
    pub(in crate::store) fn observe_later_boot_while_excluded(
        &self,
        maintenance: &ConfigurationMaintenance,
        os: &WindowsLegacyObservation,
    ) -> JournalResult<BootStamp> {
        if self.location != StartupLocation::Archived
            || !self
                .boot_this_attempt
                .definitely_after_old_ms(self.original.checkpoint_boot.unix_micros / 1000)
        {
            return Err(JournalError::Conflict);
        }
        self.validate(maintenance, os)?;
        Ok(self.boot_this_attempt)
    }
}
